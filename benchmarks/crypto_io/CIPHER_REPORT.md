# Wave 1 Silicon Bake-Off — Part A: AEAD Cipher & Hardware Instruction Proof

- **Date:** 2026-11-17
- **Silicon Under Test:** AMD Ryzen 9 7950X3D (16C / 32T, Zen 4, 1 MiB private L2/core, 96 MiB + 32 MiB asymmetric L3, Windows 11 x64 `x86_64-pc-windows-msvc`)
- **Toolchain:** `rustc 1.94.1 (e408947bf 2026-03-25)` / `cargo 1.94.1`, `--release` (`opt-level = 3`, `lto = "thin"`, `codegen-units = 1`)
- **Payload & AEAD Contract:** Exact **2 GiB (`2,147,483,648` bytes)** deterministic SplitMix64 high-entropy buffer (`fingerprint = 0xC752F5004364C1B6`), **AES-256-GCM** (96-bit nonce, 128-bit tag) with authenticated **25-byte AAD** (`16B file_uuid || 8B chunk_idx_le || 1B is_final`), 3 timed passes per configuration after per-thread warmup + RAM page pre-faulting.
- **Artifacts:**
  - Benchmark crate: `<workspace>\benchmarks\crypto_io\cipher_bench`
  - Raw JSON telemetry: `<workspace>\benchmarks\crypto_io\cipher_results.json`
  - Isolated Cargo target dir: `<workspace>\target\swarm\bakeoff-crypto-io\cipher`

---

## 1. Executive Silicon Verdict & Major Empirical Findings

1. **`ring 0.17.14` is the undisputed AES-256-GCM throughput winner on `x86_64-pc-windows-msvc` (`1.87x` faster per core than `aws-lc-rs`, `3.86x–6.21x` faster than `aes-gcm`):**
   - **Pure L2 In-Place (1 Thread):** **`11.16 GiB/s` Encrypt (`0.350 cycles/byte`)** / **`10.70 GiB/s` Decrypt (`0.366 cycles/byte`)** (`10.62 GiB/s` / `0.368 cpb` even in baseline x86_64 without `-C target-cpu=native`).
   - **2 GiB Bounded-RAM Streaming (`1 MiB` chunks):**
     - **1 Thread:** `7.18 GiB/s` Enc / `7.10 GiB/s` Dec (baseline) and **`8.33 GiB/s` Enc (`240.16 ms`, `0.470 cpb`) / `9.27 GiB/s` Dec (`215.79 ms`, `0.422 cpb`)** (`target-cpu=native`).
     - **8 Threads:** `36.81 GiB/s` Enc / `37.25 GiB/s` Dec (baseline) and **`44.77 GiB/s` Enc (`44.67 ms`) / `52.07 GiB/s` Dec (`38.41 ms`)** (`target-cpu=native` — `55.9 GB/s`, saturating dual-channel DDR5 read bandwidth).

2. **Critical Windows MSVC Discovery in `aws-lc-rs 1.19.0` (`aws-lc-sys 0.47.0`, `features = ["prebuilt-nasm"]`):**
   - Theoretical conventional wisdom assumes `aws-lc-rs` beats `ring` on Zen 4 via AVX-512 `VAES + VPCLMULQDQ`. **Disassembly proves this is FALSE on `x86_64-pc-windows-msvc`:**
   - Although `aws_lc_0_47_0_crypto.lib` contains `aws_lc_0_47_0_aes_gcm_encrypt_avx512` from `prebuilt-nasm`, the C capability gate `aws_lc_0_47_0_crypto_gcm_avx512_enabled` is compiled unconditionally under `_MSC_VER` to **`33 C0 C3` (`xor eax, eax; ret` — hardcoded `0`)**!
   - Consequently, MSVC `link.exe` (`/OPT:REF`) dead-strips all 512-bit `zmm` AES-GCM kernels (`0` `zmm` `vaesenc`/`vpclmulqdq` instructions in the final `.exe`), forcing `aws-lc-rs` down to its 128-bit `xmm` kernel `aws_lc_0_47_0_aesni_gcm_encrypt` (`_aesni_ctr32_ghash_6x`) at **`5.66–5.97 GiB/s` L2 (`0.656–0.691 cpb`)**.
   - By contrast, **`ring 0.17.14`** ships and dispatches at runtime to a stitched **256-bit AVX2 `VAES + VPCLMULQDQ`** kernel (`ring_core_0_17_14__aes_gcm_enc_update_vaes_avx2` / `dec_update_vaes_avx2`) operating on `ymm12..ymm15` + `ymm1..ymm6`, utilizing Zen 4's full 256-bit crypto pipelines on Windows x64!

3. **`aes-gcm 0.10.3` (`RustCrypto`) uses runtime `cpufeatures` for baseline AES-NI, but STILL requires `RUSTFLAGS="-C target-cpu=native"` for a `+60.6%` to `+107.1%` speedup — and still trails `ring` by `3.8x`:**
   - In `baseline-x86_64`, `aes-gcm` does **not** fall back to software lookup tables (`cpufeatures 0.2.17` detects `aes` + `pclmulqdq` at runtime and reaches `1.56 GiB/s` 1T / `9.77 GiB/s` 8T). However, because its runtime-dispatched target feature scope only enables SSE2+AES-NI (`16` `xmm0..xmm15` registers), **8-block pipelined AES-256 spills round keys onto the stack (`[rsp+40h..60h]`) every round** and emits legacy 2-operand `aesenc` + `pclmulqdq` (`2.169 cpb` L2).
   - With `RUSTFLAGS="-C target-cpu=native"`, LLVM unlocks AVX-512VL's **32 vector registers (`xmm0..xmm31`)**, keeping all 15 AES-256 round keys and 8 CTR state blocks 100% register-resident with EVEX 3-operand `vaesenc`, `vpclmulqdq`, and `vpternlogq` (`1.353 cpb` L2 = `2.89 GiB/s`, `2.64 GiB/s` 1T / `20.23 GiB/s` 8T streaming). Even with `-C target-cpu=native`, `aes-gcm` executes non-stitched 128-bit CTR + 1-block POLYVAL, making `ring` **3.86x faster per core**.

4. **Chunk Size vs. Zen 4 Cache Hierarchy (`1 MiB` Private L2 Sweet Spot):**
   - Every Zen 4 core on the Ryzen 9 7950X3D has a **1 MiB private L2 cache**.
   - At **`1 MiB` chunks**, each worker thread's reusable `1 MiB + 16 B` buffer stays hot inside its core's private L2 cache: 8-thread `ring` hits **`36.81–44.77 GiB/s` Enc / `37.25–52.07 GiB/s` Dec** while adding only **`+7.1 MiB`** of RSS above the 2 GiB payload (`WorkingSet64 = 2061.7 MiB`).
   - At **`4 MiB` and `16 MiB` chunks**, per-thread working buffers spill out of private L2 into shared L3/DRAM, cutting 8-thread `ring` throughput to **`13.55–17.72 GiB/s`** while increasing RSS to `2085.7 MiB` (`4 MiB` chunks) and `2181.7 MiB` (`16 MiB` chunks) and increasing page fault deltas by `15.6x` (`193,216` vs `12,383`).

---

## 2. Runtime CPUID & Compile-Time Target Feature Proof

Queried directly from silicon via `__cpuid` and `std::arch::is_x86_feature_detected!` vs `cfg!(target_feature = ...)`:

- **CPU Brand String (`__cpuid` `0x80000002..=0x80000004`):** `AMD Ryzen 9 7950X3D 16-Core Processor`
- **Logical Processors:** `32`
- **Calibrated Invariant `_rdtsc` Reference Clock:** `4.1999 GHz` (`4.19987484 GHz` baseline / `4.19990710 GHz` native; Zen 4 cores boost dynamically to `5.25–5.70 GHz`, explaining sub-0.4 reference cycles/byte on wide VAES pipelines)

| Feature Flag | Runtime CPUID (`is_x86_feature_detected!`) | Compile-Time `baseline-x86_64` (`cfg!`) | Compile-Time `target-cpu=native` (`cfg!`) |
| :--- | :---: | :---: | :---: |
| `aes` | **`true`** | `false` | **`true`** |
| `pclmulqdq` | **`true`** | `false` | **`true`** |
| `sse2` | **`true`** | **`true`** | **`true`** |
| `sse4.1` | **`true`** | `false` | **`true`** |
| `avx` | **`true`** | `false` | **`true`** |
| `avx2` | **`true`** | `false` | **`true`** |
| `vaes` | **`true`** | `false` | **`true`** |
| `vpclmulqdq` | **`true`** | `false` | **`true`** |
| `avx512f` | **`true`** | `false` | **`true`** |
| `avx512bw` | **`true`** | `false` | **`true`** |
| `avx512vl` | **`true`** | `false` | **`true`** |

### Cross-Crate NIST AES-256-GCM & 25-Byte AAD Verification
Prior to timing, all builds executed deterministic cross-crate verification over a `1 MiB` (`1,048,576` B) pseudo-random chunk with `25-byte` AAD (`16B file_uuid || 8B chunk_idx || 1B is_final`):
- `ciphertexts_bit_identical`: **`true`** (`aws-lc-rs == ring == aes-gcm`)
- `tags_bit_identical`: **`true`** (all three 16-byte authentication tags identical)
- `cross_decrypt_ok`: **`true`** (`aws-lc-rs -> ring`, `ring -> aes-gcm`, `aes-gcm -> aws-lc-rs`)
- `aad_tamper_rejected_all_crates`: **`true`** (flipping `is_final` byte 24 in the 25-byte AAD caused immediate `Err` tag authentication failure in all three crates)

---

## 3. Pure L2 In-Place Silicon Diagnostic (1 Thread, Zero DRAM Traffic)

4,096 iterations over an L2-resident `256 KiB` buffer (`1.0 GiB` total processed per pass) isolating pure AES-256-GCM + 25B AAD instruction throughput:

| Crate | Build Profile | Encrypt `GiB/s` | Encrypt `cycles/byte` (`_rdtsc`) | Decrypt `GiB/s` | Decrypt `cycles/byte` (`_rdtsc`) | Active Hardware Kernel |
| :--- | :--- | ---: | ---: | ---: | ---: | :--- |
| **`ring 0.17.14`** | `baseline-x86_64` | **10.62** | **0.368** | **9.56** | **0.409** | Stitched 256-bit `ymm` `VAES + VPCLMULQDQ` (runtime CPUID) |
| **`ring 0.17.14`** | `target-cpu=native` | **11.16** | **0.350** | **10.70** | **0.366** | Stitched 256-bit `ymm` `VAES + VPCLMULQDQ` (runtime CPUID) |
| `aws-lc-rs 1.19.0` | `baseline-x86_64` | 5.66 | 0.691 | 5.26 | 0.744 | Stitched 128-bit `xmm` VEX `aesni_gcm_encrypt` (AVX512 gated off on MSVC) |
| `aws-lc-rs 1.19.0` | `target-cpu=native` | 5.97 | 0.656 | 4.71 | 0.830 | Stitched 128-bit `xmm` VEX `aesni_gcm_encrypt` (AVX512 gated off on MSVC) |
| `aes-gcm 0.10.3` | `baseline-x86_64` | 1.80 | 2.169 | 1.75 | 2.237 | Non-stitched 128-bit `xmm0..15` legacy `aesenc` (stack spills) + `pclmulqdq` |
| `aes-gcm 0.10.3` | `target-cpu=native` | **2.89** | **1.353** | **2.78** | **1.408** | Non-stitched 128-bit EVEX `xmm0..31` `vaesenc` (no spills) + `vpclmulqdq` |

---

## 4. Full 2 GiB Bounded-RAM Streaming Benchmark Matrix (54 Configurations)

Architecture: Single shared `2 GiB` (`2,147,483,648` B) source buffer in RAM; worker threads pull chunks dynamically via `AtomicUsize` into pre-allocated per-thread `chunk_size + 16` reusable buffers (`std::thread::scope`), authenticating 25-byte AAD and 16-byte GCM tags on every chunk. Median of `3` timed 2 GiB passes (`6 GiB` encrypted + `6 GiB` decrypted per row). Memory metrics sampled via Win32 `K32GetProcessMemoryInfo` while all worker buffers are live.

### 4.1 Profile 1: Default Target (`baseline-x86_64`, No `RUSTFLAGS`)

| Crate | Chunk Size | Threads | Encrypt `ms` | Encrypt `GiB/s` | Decrypt `ms` | Decrypt `GiB/s` | 1T Enc `cpb` | 1T Dec `cpb` | Live RSS `WorkingSet64` (`MiB`) | Peak RSS (`MiB`) | `PageFaultCount` Total | `PageFaultCount` Delta |
| :--- | :---: | :---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `aws-lc-rs` | `1 MiB` | 1 | 411.98 | 4.85 | 481.83 | 4.15 | 0.806 | 0.942 | 2054.6 | 2061.7 | 541,374 | 10,546 |
| `aws-lc-rs` | `1 MiB` | 4 | 206.07 | 9.71 | 185.51 | 10.78 | — | — | 2057.6 | 2061.7 | 542,424 | 11,332 |
| `aws-lc-rs` | `1 MiB` | 8 | 97.24 | 20.57 | 95.89 | 20.86 | — | — | 2061.7 | 2061.7 | 544,525 | 12,382 |
| **`ring`** | `1 MiB` | 1 | **278.63** | **7.18** | **281.63** | **7.10** | **0.545** | **0.551** | 2054.6 | 2061.7 | 544,788 | 10,546 |
| **`ring`** | `1 MiB` | 4 | **112.95** | **17.71** | **104.90** | **19.07** | — | — | 2057.6 | 2061.7 | 545,838 | 11,333 |
| **`ring`** | `1 MiB` | 8 | **54.33** | **36.81** | **53.69** | **37.25** | — | — | 2061.7 | 2061.7 | 547,939 | 12,383 |
| `aes-gcm` | `1 MiB` | 1 | 1281.50 | 1.56 | 1254.90 | 1.59 | 2.506 | 2.454 | 2054.6 | 2061.7 | 548,202 | 10,546 |
| `aes-gcm` | `1 MiB` | 4 | 408.73 | 4.89 | 394.71 | 5.07 | — | — | 2057.6 | 2061.7 | 549,253 | 11,334 |
| `aes-gcm` | `1 MiB` | 8 | 204.64 | 9.77 | 197.17 | 10.14 | — | — | 2061.7 | 2061.7 | 551,354 | 12,384 |
| `aws-lc-rs` | `4 MiB` | 1 | 516.04 | 3.88 | 568.57 | 3.52 | 1.009 | 1.112 | 2057.6 | 2085.7 | 594,938 | 41,326 |
| `aws-lc-rs` | `4 MiB` | 4 | 207.08 | 9.66 | 235.38 | 8.50 | — | — | 2069.6 | 2085.7 | 599,067 | 44,422 |
| `aws-lc-rs` | `4 MiB` | 8 | 134.57 | 14.86 | 131.64 | 15.19 | — | — | 2085.7 | 2085.7 | 607,324 | 48,550 |
| **`ring`** | `4 MiB` | 1 | **318.76** | **6.27** | **329.26** | **6.07** | **0.623** | **0.644** | 2057.6 | 2085.7 | 608,357 | 41,328 |
| **`ring`** | `4 MiB` | 4 | **150.22** | **13.31** | **156.35** | **12.79** | — | — | 2069.6 | 2085.7 | 612,485 | 44,423 |
| **`ring`** | `4 MiB` | 8 | **112.87** | **17.72** | **113.85** | **17.57** | — | — | 2085.7 | 2085.7 | 620,742 | 48,551 |
| `aes-gcm` | `4 MiB` | 1 | 1291.04 | 1.55 | 1324.54 | 1.51 | 2.525 | 2.590 | 2057.6 | 2085.7 | 621,775 | 41,327 |
| `aes-gcm` | `4 MiB` | 4 | 409.77 | 4.88 | 419.27 | 4.77 | — | — | 2069.6 | 2085.7 | 625,904 | 44,423 |
| `aes-gcm` | `4 MiB` | 8 | 221.04 | 9.05 | 216.96 | 9.22 | — | — | 2085.7 | 2085.7 | 634,163 | 48,554 |
| `aws-lc-rs` | `16 MiB` | 1 | 553.01 | 3.62 | 544.52 | 3.67 | 1.082 | 1.065 | 2069.5 | 2181.7 | 807,023 | 164,446 |
| `aws-lc-rs` | `16 MiB` | 4 | 228.39 | 8.76 | 215.34 | 9.29 | — | — | 2117.6 | 2181.7 | 823,463 | 176,775 |
| `aws-lc-rs` | `16 MiB` | 8 | 151.77 | 13.18 | 148.99 | 13.42 | — | — | 2181.7 | 2181.7 | 856,343 | 193,214 |
| **`ring`** | `16 MiB` | 1 | **337.01** | **5.93** | **313.16** | **6.39** | **0.659** | **0.612** | 2069.5 | 2181.7 | 860,454 | 164,445 |
| **`ring`** | `16 MiB` | 4 | **170.87** | **11.70** | **148.79** | **13.44** | — | — | 2117.6 | 2181.7 | 876,895 | 176,776 |
| **`ring`** | `16 MiB` | 8 | **146.07** | **13.69** | **130.88** | **15.28** | — | — | 2181.7 | 2181.7 | 909,776 | 193,216 |
| `aes-gcm` | `16 MiB` | 1 | 1375.47 | 1.45 | 1152.32 | 1.74 | 2.690 | 2.254 | 2069.5 | 2181.7 | 913,887 | 164,448 |
| `aes-gcm` | `16 MiB` | 4 | 411.08 | 4.87 | 348.41 | 5.74 | — | — | 2117.6 | 2181.7 | 930,327 | 176,777 |
| `aes-gcm` | `16 MiB` | 8 | 228.91 | 8.74 | 214.70 | 9.32 | — | — | 2181.7 | 2181.7 | 963,207 | 193,216 |

### 4.2 Profile 2: Zen 4 Native (`RUSTFLAGS="-C target-cpu=native"`)

| Crate | Chunk Size | Threads | Encrypt `ms` | Encrypt `GiB/s` | Decrypt `ms` | Decrypt `GiB/s` | 1T Enc `cpb` | 1T Dec `cpb` | Live RSS `WorkingSet64` (`MiB`) | Peak RSS (`MiB`) | `PageFaultCount` Total | `PageFaultCount` Delta |
| :--- | :---: | :---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `aws-lc-rs` | `1 MiB` | 1 | 414.06 | 4.83 | 404.73 | 4.94 | 0.810 | 0.792 | 2054.6 | 2061.7 | 541,375 | 10,557 |
| `aws-lc-rs` | `1 MiB` | 4 | 107.93 | 18.53 | 99.85 | 20.03 | — | — | 2057.6 | 2061.7 | 542,429 | 11,344 |
| `aws-lc-rs` | `1 MiB` | 8 | 54.75 | 36.53 | 52.65 | 37.99 | — | — | 2061.7 | 2061.7 | 544,530 | 12,394 |
| **`ring`** | `1 MiB` | 1 | **240.16** | **8.33** | **215.79** | **9.27** | **0.470** | **0.422** | 2054.6 | 2061.7 | 544,794 | 10,557 |
| **`ring`** | `1 MiB` | 4 | **61.69** | **32.42** | **58.25** | **34.34** | — | — | 2057.6 | 2061.7 | 545,845 | 11,344 |
| **`ring`** | `1 MiB` | 8 | **44.67** | **44.77** | **38.41** | **52.07** | — | — | 2061.7 | 2061.7 | 547,947 | 12,394 |
| `aes-gcm` | `1 MiB` | 1 | 756.34 | 2.64 | 798.94 | 2.50 | 1.479 | 1.563 | 2054.6 | 2061.7 | 548,211 | 10,557 |
| `aes-gcm` | `1 MiB` | 4 | 191.58 | 10.44 | 234.57 | 8.53 | — | — | 2057.6 | 2061.7 | 549,262 | 11,344 |
| `aes-gcm` | `1 MiB` | 8 | 98.88 | 20.23 | 140.50 | 14.23 | — | — | 2061.7 | 2061.7 | 551,364 | 12,394 |
| `aws-lc-rs` | `4 MiB` | 1 | 604.06 | 3.31 | 760.45 | 2.63 | 1.181 | 1.487 | 2057.6 | 2085.7 | 594,961 | 41,338 |
| `aws-lc-rs` | `4 MiB` | 4 | 193.76 | 10.32 | 204.11 | 9.80 | — | — | 2069.6 | 2085.7 | 599,090 | 44,433 |
| `aws-lc-rs` | `4 MiB` | 8 | 138.66 | 14.42 | 133.35 | 15.00 | — | — | 2085.7 | 2085.7 | 607,349 | 48,562 |
| **`ring`** | `4 MiB` | 1 | **358.70** | **5.58** | **420.60** | **4.76** | **0.702** | **0.823** | 2057.6 | 2085.7 | 608,383 | 41,338 |
| **`ring`** | `4 MiB` | 4 | **155.40** | **12.87** | **183.14** | **10.92** | — | — | 2069.6 | 2085.7 | 612,513 | 44,434 |
| **`ring`** | `4 MiB` | 8 | **145.53** | **13.74** | **138.13** | **14.48** | — | — | 2085.7 | 2085.7 | 620,770 | 48,561 |
| `aes-gcm` | `4 MiB` | 1 | 886.33 | 2.26 | 894.93 | 2.23 | 1.733 | 1.750 | 2057.6 | 2085.7 | 621,804 | 41,338 |
| `aes-gcm` | `4 MiB` | 4 | 270.32 | 7.40 | 254.92 | 7.85 | — | — | 2069.6 | 2085.7 | 625,934 | 44,434 |
| `aes-gcm` | `4 MiB` | 8 | 195.41 | 10.23 | 159.10 | 12.57 | — | — | 2085.7 | 2085.7 | 634,191 | 48,561 |
| `aws-lc-rs` | `16 MiB` | 1 | 617.15 | 3.24 | 608.24 | 3.29 | 1.207 | 1.190 | 2069.5 | 2181.7 | 807,061 | 164,456 |
| `aws-lc-rs` | `16 MiB` | 4 | 179.12 | 11.17 | 182.32 | 10.97 | — | — | 2117.6 | 2181.7 | 823,503 | 176,786 |
| `aws-lc-rs` | `16 MiB` | 8 | 143.67 | 13.92 | 146.91 | 13.61 | — | — | 2181.7 | 2181.7 | 856,384 | 193,225 |
| **`ring`** | `16 MiB` | 1 | **334.56** | **5.98** | **331.79** | **6.03** | **0.654** | **0.649** | 2069.5 | 2181.7 | 860,496 | 164,455 |
| **`ring`** | `16 MiB` | 4 | **154.19** | **12.97** | **152.14** | **13.15** | — | — | 2117.6 | 2181.7 | 876,938 | 176,785 |
| **`ring`** | `16 MiB` | 8 | **147.63** | **13.55** | **139.84** | **14.30** | — | — | 2181.7 | 2181.7 | 909,819 | 193,224 |
| `aes-gcm` | `16 MiB` | 1 | 784.96 | 2.55 | 795.32 | 2.51 | 1.535 | 1.555 | 2069.5 | 2181.7 | 913,931 | 164,454 |
| `aes-gcm` | `16 MiB` | 4 | 262.79 | 7.61 | 260.96 | 7.66 | — | — | 2117.6 | 2181.7 | 930,373 | 176,784 |
| `aes-gcm` | `16 MiB` | 8 | 177.18 | 11.29 | 188.22 | 10.63 | — | — | 2181.7 | 2181.7 | 963,255 | 193,226 |

---

## 5. Hardware Disassembly Proof (`dumpbin.exe /disasm`)

Disassembled using `"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\dumpbin.exe" /disasm` against the linked executables (`cipher_bench_baseline.exe`, `cipher_bench_native.exe`) and static C/ASM archives (`ring_core_0_17_14_.lib`, `aws_lc_0_47_0_crypto.lib`).

### 5.1 Whole-Binary Hardware Instruction Histogram

| Hardware Instruction Form | `cipher_bench_baseline.exe` | `cipher_bench_native.exe` (`-C target-cpu=native`) | Delta & Architectural Origin |
| :--- | ---: | ---: | :--- |
| `aesenc` (legacy 2-op SSE) | `668` | `447` | **`-221`** (`aes-gcm` upgraded from legacy SSE `aesenc` to EVEX `vaesenc`) |
| `aesenclast` (legacy 2-op SSE) | `119` | `102` | **`-17`** (`aes-gcm` upgraded to EVEX `vaesenclast`) |
| `vaesenc` (`128-bit xmm`) | `180` | `414` | **`+234`** (`180` in `aws-lc-rs`/`ring` 128b kernels + `234` emitted by `aes-gcm` native) |
| **`vaesenc` (`256-bit ymm`)** | **`116`** | **`116`** | **100% from `ring 0.17.14` (`aes_gcm_enc/dec_update_vaes_avx2`) in BOTH builds** |
| `vaesenc` (`512-bit zmm`) | `0` | `0` | Dead-stripped by MSVC `/OPT:REF` because `aws-lc-sys` disables AVX-512 GCM on `_MSC_VER` |
| `vaesenclast` (`128-bit xmm`) | `24` | `42` | **`+18`** (`aes-gcm` native EVEX `vaesenclast`) |
| **`vaesenclast` (`256-bit ymm`)** | **`20`** | **`20`** | **100% from `ring 0.17.14` (`aes_gcm_enc/dec_update_vaes_avx2`) in BOTH builds** |
| `vaesenclast` (`512-bit zmm`) | `0` | `0` | Dead-stripped (`aws-lc-sys` `_MSC_VER` gate = `0`) |
| `pclmulqdq` (legacy 2-op SSE) | `102` | `99` | **`-3`** (`polyval` upgraded from `pclmulqdq` to VEX `vpclmulqdq`) |
| `vpclmulqdq` (`128-bit xmm`) | `304` | `346` | **`+42`** (`aws-lc-rs`/`ring` 128b GHASH + `polyval` native inlined calls) |
| **`vpclmulqdq` (`256-bit ymm`)** | **`88`** | **`88`** | **100% from `ring 0.17.14` (`aes_gcm_enc/dec_update_vaes_avx2`) in BOTH builds** |
| `vpclmulqdq` (`512-bit zmm`) | `0` | `0` | Dead-stripped (`aws-lc-sys` `_MSC_VER` gate = `0`) |

---

### 5.2 `ring 0.17.14` — Stitched 256-Bit `ymm` `VAES + VPCLMULQDQ` Proof (`ring_core_0_17_14_.lib`)

`ring` dispatches at runtime via CPUID (`vaes` + `vpclmulqdq` + `avx2`) to `ring_core_0_17_14__aes_gcm_enc_update_vaes_avx2`, encrypting **8 AES blocks (`4 × 256-bit ymm12..ymm15`)** while simultaneously computing **256-bit `vpclmulqdq` GHASH (`ymm1..ymm6`)** in the same loop:

```asm
ring_core_0_17_14__aes_gcm_enc_update_vaes_avx2 (L$crypt_loop_4x__func1):
  0000000000000430: C4 C2 7D 5A 93 30 FF FF FF  vbroadcasti128 ymm2,oword ptr [r11-0D0h]
  0000000000000439: C4 62 1D DC E2              vaesenc     ymm12,ymm12,ymm2
  000000000000043E: C4 62 15 DC EA              vaesenc     ymm13,ymm13,ymm2
  0000000000000443: C4 62 0D DC F2              vaesenc     ymm14,ymm14,ymm2
  0000000000000448: C4 62 05 DC FA              vaesenc     ymm15,ymm15,ymm2
  ...
  00000000000004B2: C5 FE 6F 1A                 vmovdqu     ymm3,ymmword ptr [rdx]
  00000000000004B6: C4 E2 65 00 D8              vpshufb     ymm3,ymm3,ymm0
  00000000000004BB: C5 FE 6F 27                 vmovdqu     ymm4,ymmword ptr [rdi]
  00000000000004BF: C5 E5 EF D9                 vpxor       ymm3,ymm3,ymm1
  00000000000004C3: C4 E3 65 44 EC 00           vpclmulqdq  ymm5,ymm3,ymm4,0
  00000000000004C9: C4 E3 65 44 CC 11           vpclmulqdq  ymm1,ymm3,ymm4,11h
  00000000000004CF: C5 E5 6D D3                 vpunpckhqdq ymm2,ymm3,ymm3
  00000000000004D3: C5 ED EF D3                 vpxor       ymm2,ymm2,ymm3
  00000000000004D7: C4 E3 6D 44 F7 00           vpclmulqdq  ymm6,ymm2,ymm7,0
  00000000000004DD: C4 C2 7D 5A 93 70 FF FF FF  vbroadcasti128 ymm2,oword ptr [r11-90h]
  00000000000004E6: C4 62 1D DC E2              vaesenc     ymm12,ymm12,ymm2
  00000000000004EB: C4 62 15 DC EA              vaesenc     ymm13,ymm13,ymm2
  00000000000004F0: C4 62 0D DC F2              vaesenc     ymm14,ymm14,ymm2
  00000000000004F5: C4 62 05 DC FA              vaesenc     ymm15,ymm15,ymm2
  ...
  000000000000039E: C4 62 1D DD E2              vaesenclast ymm12,ymm12,ymm2
  00000000000003A3: C4 62 15 DD EB              vaesenclast ymm13,ymm13,ymm3
  00000000000003A8: C4 62 0D DD F5              vaesenclast ymm14,ymm14,ymm5
  00000000000003AD: C4 62 05 DD FE              vaesenclast ymm15,ymm15,ymm6
```

---

### 5.3 `aws-lc-rs 1.19.0` — Windows MSVC AVX-512 Gate Smoking Gun & 128-Bit `xmm` Fallback (`aws_lc_0_47_0_crypto.lib`)

Disassembly of `aws_lc_0_47_0_crypto_gcm_avx512_enabled` in `aws_lc_0_47_0_crypto.lib` proves why `aws-lc-rs` fails to use Zen 4's `VAES + VPCLMULQDQ` wide vectors on Windows MSVC:

```asm
aws_lc_0_47_0_crypto_gcm_avx512_enabled:
  0000000000000000: 33 C0              xor         eax,eax
  0000000000000002: C3                 ret
```

Because `crypto_gcm_avx512_enabled()` unconditionally returns `0`, `CRYPTO_ghash_init` falls back to `aws_lc_0_47_0_aesni_gcm_encrypt` (`_aesni_ctr32_ghash_6x`), which uses VEX-encoded **128-bit `xmm` hardware instructions** (`vaesenc xmm` + `vpclmulqdq xmm`) — still hardware-accelerated (no software lookup tables), but half the vector width of `ring`'s 256-bit `ymm` kernel:

```asm
aws_lc_0_47_0_aesni_gcm_encrypt (_aesni_ctr32_ghash_6x):
  0000000000000A37: E8 C4 F5 FF FF     call        _aesni_ctr32_ghash_6x
  ...
  0000000000000AA9: C4 E3 41 44 EB 00  vpclmulqdq  xmm5,xmm7,xmm3,0
  0000000000000AAF: C5 E9 EF D6        vpxor       xmm2,xmm2,xmm6
  0000000000000AB3: C4 E3 41 44 FB 11  vpclmulqdq  xmm7,xmm7,xmm3,11h
  0000000000000AB9: C4 C3 71 44 CF 00  vpclmulqdq  xmm1,xmm1,xmm15,0
  0000000000000AC5: C4 E3 49 44 E0 00  vpclmulqdq  xmm4,xmm6,xmm0,0
```

---

### 5.4 `aes-gcm 0.10.3` — `baseline-x86_64` (SSE `xmm0..15` Stack Spills) vs. `-C target-cpu=native` (EVEX `xmm0..31` Register-Pinned)

**In `cipher_bench_baseline.exe` (no `RUSTFLAGS`):** `cpufeatures` jumps into an `#[target_feature(enable = "aes")]` routine restricted to `xmm0..xmm15`, forcing round-key reloads from `[rsp+40h..60h]` and legacy 2-operand `aesenc` / `pclmulqdq`:

```asm
; cipher_bench_baseline.exe — aes-gcm 0.10.3 (aes 0.8.4 + polyval 0.6.2)
  000000014001F85F: 66 44 0F 6F 64 24 60  movdqa      xmm12,xmmword ptr [rsp+60h] ; round key stack spill reload!
  000000014001F866: 66 45 0F 38 DC CC     aesenc      xmm9,xmm12
  000000014001F874: 66 41 0F 38 DC FC     aesenc      xmm7,xmm12
  000000014001F87F: 66 45 0F 38 DC FC     aesenc      xmm15,xmm12
  ...
  000000014001F8BF: 66 44 0F 6F 6C 24 50  movdqa      xmm13,xmmword ptr [rsp+50h] ; round key stack spill reload!
  000000014001F8C6: 66 45 0F 38 DC CD     aesenc      xmm9,xmm13
  ...
  000000014003CD22: 66 0F 3A 44 DA 00     pclmulqdq   xmm3,xmm2,0
  000000014003CD2C: 66 0F 3A 44 E9 00     pclmulqdq   xmm5,xmm1,0
  000000014003CD32: 66 0F 3A 44 C1 11     pclmulqdq   xmm0,xmm1,11h
```

**In `cipher_bench_native.exe` (`RUSTFLAGS="-C target-cpu=native"`):** LLVM allocates across AVX-512VL extended registers `xmm16..xmm31`, eliminating all round-key stack spills and emitting EVEX 3-operand `vaesenc`, `vpclmulqdq`, and AVX-512 `vpternlogq` (`0x96` 3-way XOR):

```asm
; cipher_bench_native.exe — aes-gcm 0.10.3 with -C target-cpu=native
  000000014001B7D0: 62 B2 45 08 DC F8  vaesenc     xmm7,xmm7,xmm16
  000000014001B7D6: 62 62 0D 00 DC F3  vaesenc     xmm30,xmm30,xmm3
  000000014001B7DC: 62 22 2D 00 DC D0  vaesenc     xmm26,xmm26,xmm16
  000000014001B7F9: 62 22 25 00 DC D8  vaesenc     xmm27,xmm27,xmm16
  000000014001B7FF: 62 B2 45 08 DC F9  vaesenc     xmm7,xmm7,xmm17
  000000014001B80B: 62 22 2D 00 DC D1  vaesenc     xmm26,xmm26,xmm17
  000000014001B828: 62 22 25 00 DC D9  vaesenc     xmm27,xmm27,xmm17
  000000014001B82E: 62 B2 45 08 DC FA  vaesenc     xmm7,xmm7,xmm18
  ...
  000000014001C572: C4 E3 71 44 DF 00  vpclmulqdq  xmm3,xmm1,xmm7,0
  000000014001C578: C4 E3 71 44 E7 11  vpclmulqdq  xmm4,xmm1,xmm7,11h
  000000014001C5AF: 62 A3 FD 00 25 D1  vpternlogq  xmm18,xmm16,xmm17,96h
                    96
```

---

## 6. Merger Architecture Recommendations

1. **Select `ring = "0.17"` (`0.17.14`) as the Primary Windows x64 AEAD Engine (or Dual-Backend Trait Defaulting to `ring` on Windows):**
   - On `x86_64-pc-windows-msvc`, `ring 0.17.14` delivers **`10.62–11.16 GiB/s` single-core L2 (`0.350–0.368 cpb`)** and **`36.81–52.07 GiB/s` 8-thread 2 GiB streaming** WITHOUT needing `-C target-cpu=native` to unlock its 256-bit `VAES + VPCLMULQDQ` assembly kernel, making portable binary distribution safe while still achieving peak Zen 4 / Ice Lake+ silicon speed.
   - Do **not** blindly assume `aws-lc-rs` uses AVX-512 GCM on Windows MSVC: `aws-lc-sys 0.47.0` compiles `crypto_gcm_avx512_enabled()` to `xor eax, eax; ret` on `_MSC_VER`, leaving `1.87x` per-core throughput on the table (`5.66–5.97 GiB/s`).
   - Do **not** use RustCrypto `aes-gcm 0.10` for multi-GiB bulk payload encryption: even with `-C target-cpu=native` (`2.89 GiB/s` L2), it lacks stitched multi-block VAES+VPCLMULQDQ (`3.86x` slower per core than `ring`, and `5.89x` slower in portable baseline builds).
2. **Standardize Streaming Chunk Buffers at `1 MiB` (or Sub-L2 Tile Reuse if Larger Logical Chunks Are Used):**
   - `1 MiB` chunks fit inside Zen 4's `1 MiB` private L2 cache per core, delivering **`2.1x–3.6x` higher 8-thread throughput** (`36.8–52.1 GiB/s` vs `13.6–17.7 GiB/s`) and **`120 MiB` lower Peak RSS** (`2061.7 MiB` vs `2181.7 MiB`) than `16 MiB` chunks.
