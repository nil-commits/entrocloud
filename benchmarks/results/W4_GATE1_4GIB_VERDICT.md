# Wave 4 Gate 1 Adversarial Verification Verdict (`Bit-Exact 4 GiB Multi-Cloud Roundtrip & Bounded RSS Proof`)

- **Gate:** Wave 4 Gate 1 — Bit-Exact `4 GiB` (`4,294,967,296` B) Multi-Cloud Streaming Roundtrip, `QuotaPooled` Spillover, `Mirrored` RAID-1 Tamper Failover, `O(1)` Video-Scrub Hydration & Bounded Win32 RSS Proof
- **Auditor:** `Agent-Judge` (Adversarial Red-Team & Proof Verifier)
- **Audit Timestamp (UTC):** `2026-11-17T21:08:54Z`
- **Host Hardware:** Windows 11 (`x86_64-pc-windows-msvc`), Hardware `VAES` + `VPCLMULQDQ` + `AVX2` + `AES-NI` active (`ring-0.17-aes256gcm-vaes-avx2`)
- **Test Harness Source:** [w4_gate1_4gib_roundtrip.rs](tests/e2e/tests/w4_gate1_4gib_roundtrip.rs)
- **Isolated Target Dir:** `<workspace>\target\swarm\judge\w4-4gib`
- **Read-Only Source Baseline Integrity:** **PASS (`0` mutations across `184` files / `298,766,349` bytes)** — verified bit-for-bit against [READONLY_BASELINE.txt](audit/READONLY_BASELINE.txt).

---

## Executive Gate 1 Decision: **PASS (`0` Vetoes Exercised — All Cryptographic, Multi-Cloud & Bounded-RSS Invariants Proven on Silicon)**

Using **100% real production workspace crates** (`RingHybridCryptoEngine`, `SqliteMetadataStore` in `WAL` + `secure_delete=1` mode, `StorageRouter` with `QuotaPooled` + `OrderedSpillover` across two `OpenDalBackend` `LocalFs` clouds and `Mirrored` RAID-1 across two `LocalFs` clouds, `SyncEngine` with default `zerovaultd` config `max_ram_cache_bytes = 32 MiB` / `max_concurrent_transfers = 8`, and `MockDrive` / `VfsBackend`), the system passed every Wave 4 Gate 1 torture invariant in `--release` mode (`EXIT=0`):

| Gate 1 Requirement | Target / Invariant | Empirical Measurement | Status |
| :--- | :--- | :--- | :---: |
| **4 GiB Stream Payload & Entropy** | `4,294,967,296` B (`1,024 × 4 MiB`), non-compressible | Keyed `BLAKE3` XOF stream, Shannon entropy **`7.999958 bits/byte`** | **PASS** |
| **Bit-Exact 4 GiB `SHA-256` Match** | `actual_full_sha256 == expected_full_sha256` | `9ff6bcaeee6e664cd84126fc759b6dfe27412760787d6c605e7e6703103fec48` (both) | **PASS** |
| **`QuotaPooled` Multi-Cloud Spillover** | Backend A capped at `2.5 GiB` (`16 MiB` reserve) spills into Backend B (`4.0 GiB`) | Backend A: **`635` `.zv` blobs (`2,540.03 MiB`)**; Backend B: **`389` `.zv` blobs (`1,556.02 MiB`)**; Total = **`1,024 / 1,024`** (`0` plaintext key leaks) | **PASS** |
| **Complete Local Cache Purge** | `0` chunks in RAM LRU, `0` files in `staging_dir`, `OnlineOnly` in SQLite | `RAM_LRU = 0 B`, `StagingFiles = 0`, `SQLiteHydrated = 0/1,024`, locked `read_range` -> `VaultLocked`, RSS dropped to **`14.79 MiB`** (`3.95 MiB` Private) | **PASS** |
| **Arbitrary `4 MiB` Video Scrub (`O(1)`)** | Bit-exact `SHA-256` on unaligned + cross-cloud seeks; `chunks_hydrated << 1,024` | `6 / 6` `4 MiB` scrubs matched `SHA-256` in **`9.86–18.15 ms`** each (`137.63 ms` total), including exact A->B spillover straddle; **`chunks_hydrated = 10 / 1,024` (`0.98%`)** | **PASS** |
| **Bounded RSS During 4 GiB Upload & Download** | `<= 128 MiB` delta / target ceiling (`<< 256 MiB`, independent of `4,096 MiB` file) | Max Sampled `WorkingSetSize`: **`93.76 MiB`** (`+83.57 MiB` delta vs start, `+81.11 MiB` vs mounted); Win32 Kernel `PeakWorkingSetSize`: **`97.77 MiB`** across entire `4 GiB` upload + `4 GiB` download + `64 MiB` Argon2id (`100.23 MiB` process lifetime incl. RAID-1 test) | **PASS** |
| **Post-Stream Memory Reclamation** | Reclaim buffers & pages to OS after 4 GiB roundtrip | Post-download `dehydrate` + `reclaim_process_memory()` dropped RSS from `55.55 MiB` to **`19.33 MiB`** (`8.59 MiB` Private) | **PASS** |
| **`Mirrored` (`RAID-1`) & Tamper Failover** | `min_ack=2` replication, automatic 1-replica bit-flip recovery, dual-tamper fail-closed | `16 / 16` blobs on both mirrors (`0.986 s`); 1-bit flip on chunks `0` & `9` on `mirror-cloud-1` seamlessly failed over to `mirror-cloud-2` (`SHA-256` match); dual-mirror tamper returned `CryptoTamperDetected` | **PASS** |

---

## 1. Read-Only Source Tree Baseline Integrity (`0` Mutations)

- **Command Executed (`EXIT=0`, Wall-Clock `626.33 ms`):**
  ```powershell
  Get-ExactBaseline "cloudbridge"       "<donor-root>\cloudbridge"
  Get-ExactBaseline "cloudbridge linux" "<donor-root>\cloudbridge linux"
  Get-ExactBaseline "zerovault"         "<donor-root>\zerovault"
  ```
- **Verbatim Output:**
  ```text
  cloudbridge | files=37 | bytes=89165156 | tree_sha256=43ADD08E502AC76DF469BDCEF9C8DC11914880DB8288C28C204345E69AE5B05F
  cloudbridge linux | files=65 | bytes=178010385 | tree_sha256=32DB719E53848B03BBDAC67B33423DE9D4161F660FBFF91A1B005126CE31554F
  zerovault | files=82 | bytes=31590808 | tree_sha256=383752380A143E34B124F1CA365BD6D5F9F43C570DE0E8D89D00C0632FB4D51D
  ELAPSED_MS=626,33
  ```

---

## 2. Exact Command Executed, Throughput & Latency Breakdown

### Exact Execution Command (`EXIT=0`)
```powershell
$env:CARGO_TARGET_DIR = "<workspace>\target\swarm\judge\w4-4gib"
cargo test --manifest-path "<workspace>\Cargo.toml" --release -p zerovault-e2e --test w4_gate1_4gib_roundtrip --locked -- --nocapture
```
- **Exit Code:** `0` (`1 passed; 0 failed; 0 compiler warnings`)
- **Total Suite Wall-Clock:** `60.757 s` (`62.27 s` Cargo test harness wall-clock)

### Phase-by-Phase Throughput, Latency & RSS Summary

| Pipeline Phase | Payload Size | Wall-Clock (`s`) | Throughput (`MiB/s`) | Active `WorkingSetSize` (`MiB`) | `PrivateUsage` (`MiB`) | Notes |
| :--- | ---: | ---: | ---: | ---: | ---: | :--- |
| **0. Process Baseline** | `0 MiB` | — | — | `10.19 MiB` | `2.05 MiB` | Fresh `--release` test binary start |
| **1. `Argon2id` Vault Init (`64 MiB`, `t=3, p=4`)** | `64 MiB` KDF | — | — | `10.76 MiB` post-reclaim | `2.43 MiB` | Kernel `PeakRSS` touched `74.46 MiB` (`10.19 + ~64 MiB`), immediately reclaimed |
| **2. VFS Stream Write + AEAD `.zvpart` Staging** | `4,096.00 MiB` | **`12.316 s`** | **`332.58 MiB/s`** | **`17.04 – 17.07 MiB`** | `6.75 – 6.77 MiB` | Flat `17.06 MiB` across all `32` samples (`128..4,096 MiB`); `1,024` `.zvpart` files staged |
| **3. Multi-Cloud `QuotaPooled` `flush` + Wipe** | `4,096.00 MiB` | **`33.405 s`** | **`122.62 MiB/s`** | **`77.59 – 93.76 MiB`** | `67.29 – 85.72 MiB` | Includes `.zvpart` AEAD open + `BLAKE3` + `VAES` `AES-256-GCM` seal + 2-cloud upload + `1,024`× zero-wipe & `FlushFileBuffers` (`sync_all`); `1,319` watchdog samples @ `25 ms` |
| **Combined End-to-End 4 GiB Upload (`Write + Flush`)** | `4,096.00 MiB` | **`45.724 s`** | **`89.58 MiB/s`** | **`93.76 MiB` max** | `85.72 MiB` max | `635` blobs (`2,540.03 MiB`) on Backend A + `389` blobs (`1,556.02 MiB`) on Backend B |
| **4. Dehydrate + `lock_and_purge_cache`** | `0 MiB` | — | — | **`14.79 MiB`** | `3.95 MiB` | `0 B` RAM LRU, `0` staging files, `0 / 1,024` hydrated in SQLite, `VaultLocked` enforced |
| **5. `6 × 4 MiB` Arbitrary Video Scrubs (`O(1)`)** | `24.00 MiB` | **`0.138 s`** | **`174.38 MiB/s`** | `55.17 MiB` | `44.27 MiB` | `9.86 – 18.15 ms` per `4 MiB` scrub; only **`10 / 1,024` chunks** hydrated |
| **6. Full Cold Sequential `4 GiB` Hydration + `SHA-256`** | `4,096.00 MiB` | **`13.363 s`** | **`306.52 MiB/s`** | **`55.22 – 55.55 MiB`** | `44.30 – 44.84 MiB` | Flat `~55.3 MiB` across all `32` samples (`128..4,096 MiB`); `1,024 / 1,024` cold chunks AEAD+BLAKE3+SHA256 verified |
| **7. Post-Download `dehydrate` + `reclaim_process_memory`** | `0 MiB` | — | — | **`19.33 MiB`** | `8.59 MiB` | Kernel `PeakRSS` across entire `8 GiB` I/O roundtrip: **`97.77 MiB`** (`41.9x` smaller than `4 GiB` file) |
| **8. `Mirrored` (`RAID-1`) `64 MiB` + Tamper Failover** | `64.00 MiB` × 2 | **`0.986 s`** | — | `28.06 MiB` post-lock | `17.04 MiB` | `16` blobs × 2 mirrors; 2 corrupted chunks on `mirror-cloud-1` recovered via `mirror-cloud-2`; dual-mirror corruption rejected via `CryptoTamperDetected` |

---

## 3. Arbitrary `4 MiB` Byte-Range Video-Scrub Proof (`O(1)` Hydration)

Starting from a completely cold, dehydrated state (`chunks_hydrated = 0`, `RAM_LRU = 0 B`, `StagingFiles = 0`), `6` `4 MiB` (`4,194,304` B) `VfsBackend::read_range` calls were executed across aligned, unaligned cross-chunk, and cross-cloud spillover boundaries:

| Scrub Case | Byte Offset | Length (`B`) | Touched Chunks | Backend Residence | Chunks Hydrated | Latency (`ms`) | Ground-Truth vs Hydrated `SHA-256` Prefix |
| :--- | ---: | ---: | :---: | :---: | :---: | ---: | :--- |
| `scrub_0_head_aligned_cloudA` | `0` | `4,194,304` | `0..=0` | `cloud-pool-a` | `+1` | `16.12 ms` | `fbf25970ab98a23c...` (**MATCH**) |
| `scrub_1_1gib_unaligned_cloudA` | `1,073,865,280` (`1 GiB + 123,456`) | `4,194,304` | `256..=257` | `cloud-pool-a` | `+2` | `15.54 ms` | `eef1848dadaf04aa...` (**MATCH**) |
| `scrub_2_cross_backend_spillover_straddle_A_to_B` | `2,661,285,888` (`634 * 4 MiB + 2 MiB`) | `4,194,304` | `634..=635` | **`cloud-pool-a` + `cloud-pool-b`** | `+2` | `18.15 ms` | `2dfdfe5af7ab07ab...` (**MATCH**) |
| `scrub_3_2_5gib_unaligned_cloudB` | `2,688,354,560` (`2.5 GiB + 4,000,000`) | `4,194,304` | `640..=641` | `cloud-pool-b` | `+2` | `16.56 ms` | `1afc3eca031baaef...` (**MATCH**) |
| `scrub_4_3_5gib_unaligned_cloudB` | `3,758,097,161` (`3.5 GiB + 777`) | `4,194,304` | `896..=897` | `cloud-pool-b` | `+2` | `16.58 ms` | `f7dbd0b185b0c195...` (**MATCH**) |
| `scrub_5_4gib_tail_final_chunk_cloudB` | `4,290,772,992` (`4 GiB - 4 MiB`) | `4,194,304` | `1023..=1023` | `cloud-pool-b` | `+1` | `9.86 ms` | `a075031f11fa821d...` (**MATCH**) |
| **Total Across All 6 Scrubs** | — | **`25,165,824`** | `10` distinct | Both Clouds | **`10 / 1,024` (`0.98%`)** | **`137.63 ms`** | **`6 / 6` BIT-EXACT `SHA-256` MATCHES** |

---

## 4. Full Verbatim Raw `stdout` / `stderr` & Win32 RSS Timeline (`EXIT=0`)

```text
Command exited with code 0.

Command output:
   Compiling zerovault-e2e v0.2.0 (<workspace>\tests\e2e)
    Finished `release` profile [optimized] target(s) in 28.33s
     Running tests\w4_gate1_4gib_roundtrip.rs (entrocloud merge\target\swarm\judge\w4-4gib\release\deps\w4_gate1_4gib_roundtrip-7d44eb49fd2fe916.exe)

running 1 test
================================================================================
WAVE 4 GATE 1 ADVERSARIAL TORTURE TEST: 4 GiB MULTI-CLOUD ROUNDTRIP & BOUNDED RSS
================================================================================
[MEM] Baseline Process Start : RSS=10.19 MiB | PeakRSS=10.19 MiB | Private=2.05 MiB
[HW ] Crypto Engine          : backend=ring-0.17-aes256gcm-vaes-avx2 | arch=x86_64 | aes_hw=true | pclmul_hw=true | vaes_hw=true | avx2_hw=true
[MEM] Post-Argon2id (64 MiB) : RSS=10.76 MiB | PeakRSS=74.46 MiB | Private=2.43 MiB
[CFG] SyncEngine             : max_ram_cache_bytes=32 MiB | max_concurrent_transfers=8
[MEM] Engine Mounted Idle    : RSS=12.65 MiB | PeakRSS=74.46 MiB | Private=2.70 MiB
[INGEST] 4,096 MiB Staged    : 12.316 s (332.58 MiB/s) | entropy=7.999958 bits/B | .zvpart=1024 | RSS=13.15 MiB
[HASH] Expected 4 GiB SHA-256: 9ff6bcaeee6e664cd84126fc759b6dfe27412760787d6c605e7e6703103fec48
[FLUSH] 4,096 MiB Cloud Sync : 33.405 s (122.62 MiB/s) | Combined Ingest+Flush: 45.724 s (89.58 MiB/s)
[MEM] Flush 25ms Watchdog    : samples=1319 | MaxRSS=93.76 MiB | MaxPrivate=85.72 MiB | PostFlushRSS=78.68 MiB
[CLOUD] Backend A (2.5 GiB)  : blobs=635 | blob_bytes=2663413520 (2540.03 MiB) | tracked_used=2663563494 (2540.17 MiB)
[CLOUD] Backend B (4.0 GiB)  : blobs=389 | blob_bytes=1631602928 (1556.02 MiB) | tracked_used=1631602928 (1556.02 MiB)
[CLOUD] Total Pooled Blobs   : 1024 / 1024 | Pooled Used=4096.19 MiB / 6656.00 MiB
[PURGE] Cache Purged & Locked: RAM_LRU=0 B | StagingFiles=0 | SQLiteHydrated=0/1024 | RSS=14.79 MiB
[SCRUB] scrub_0_head_aligned_cloudA                     | off=            0 | chunks=   0..=0    | +1 chunks |  16.12 ms | SHA256=fbf25970ab98a23c (MATCH)
[SCRUB] scrub_1_1gib_unaligned_cloudA                   | off=   1073865280 | chunks= 256..=257  | +2 chunks |  15.54 ms | SHA256=eef1848dadaf04aa (MATCH)
[SCRUB] scrub_2_cross_backend_spillover_straddle_A_to_B | off=   2661285888 | chunks= 634..=635  | +2 chunks |  18.15 ms | SHA256=2dfdfe5af7ab07ab (MATCH)
[SCRUB] scrub_3_2_5gib_unaligned_cloudB                 | off=   2688354560 | chunks= 640..=641  | +2 chunks |  16.56 ms | SHA256=1afc3eca031baaef (MATCH)
[SCRUB] scrub_4_3_5gib_unaligned_cloudB                 | off=   3758097161 | chunks= 896..=897  | +2 chunks |  16.58 ms | SHA256=f7dbd0b185b0c195 (MATCH)
[SCRUB] scrub_5_4gib_tail_final_chunk_cloudB            | off=   4290772992 | chunks=1023..=1023 | +1 chunks |   9.86 ms | SHA256=a075031f11fa821d (MATCH)
[SCRUB] Summary              : 6 arbitrary 4 MiB ranges verified in 137.63 ms | chunks_hydrated=10 / 1024 (O(1) PROVEN) | RSS=55.17 MiB
[HASH] Actual   4 GiB SHA-256: 9ff6bcaeee6e664cd84126fc759b6dfe27412760787d6c605e7e6703103fec48
[READ] 4,096 MiB Hydrated    : 13.363 s (306.52 MiB/s) | cold_chunks_hydrated=1024 / 1024
[MEM] Post-Reclaim Idle      : RSS=19.33 MiB | PeakRSS=97.77 MiB | Private=8.59 MiB
test w4_gate1_bit_exact_4gib_multicloud_roundtrip_and_bounded_rss has been running for over 60 seconds
[MIRROR] RAID-1 64 MiB Check : 0.986 s | m1_blobs=16, m2_blobs=16 | 1-Replica Bit-Flip Failover SHA256=1e61fb7ad3fb02c7 (MATCH) | Dual-Replica Tamper -> CryptoTamperDetected (FAIL-CLOSED)

--------------------------------------------------------------------------------
PHASE                              | STREAM MiB |  RSS (MiB) |  PEAK (MiB) |  PRIV (MiB)
--------------------------------------------------------------------------------
00_process_start_baseline          |          0 |      10.19 |       10.19 |        2.05
01_post_argon2id_init              |          0 |      10.76 |       74.46 |        2.43
02_engine_mounted_idle             |          0 |      12.65 |       74.46 |        2.70
03_vfs_write_stage                 |        128 |      17.04 |       74.46 |        6.75
03_vfs_write_stage                 |        256 |      17.05 |       74.46 |        6.75
03_vfs_write_stage                 |        384 |      17.05 |       74.46 |        6.75
03_vfs_write_stage                 |        512 |      17.05 |       74.46 |        6.75
03_vfs_write_stage                 |        640 |      17.05 |       74.46 |        6.75
03_vfs_write_stage                 |        768 |      17.05 |       74.46 |        6.75
03_vfs_write_stage                 |        896 |      17.05 |       74.46 |        6.75
03_vfs_write_stage                 |       1024 |      17.05 |       74.46 |        6.75
03_vfs_write_stage                 |       1152 |      17.05 |       74.46 |        6.75
03_vfs_write_stage                 |       1280 |      17.05 |       74.46 |        6.75
03_vfs_write_stage                 |       1408 |      17.06 |       74.46 |        6.75
03_vfs_write_stage                 |       1536 |      17.06 |       74.46 |        6.75
03_vfs_write_stage                 |       1664 |      17.06 |       74.46 |        6.75
03_vfs_write_stage                 |       1792 |      17.06 |       74.46 |        6.75
03_vfs_write_stage                 |       1920 |      17.06 |       74.46 |        6.75
03_vfs_write_stage                 |       2048 |      17.06 |       74.46 |        6.75
03_vfs_write_stage                 |       2176 |      17.06 |       74.46 |        6.75
03_vfs_write_stage                 |       2304 |      17.06 |       74.46 |        6.75
03_vfs_write_stage                 |       2432 |      17.06 |       74.46 |        6.75
03_vfs_write_stage                 |       2560 |      17.06 |       74.46 |        6.75
03_vfs_write_stage                 |       2688 |      17.06 |       74.46 |        6.75
03_vfs_write_stage                 |       2816 |      17.06 |       74.46 |        6.75
03_vfs_write_stage                 |       2944 |      17.06 |       74.46 |        6.75
03_vfs_write_stage                 |       3072 |      17.06 |       74.46 |        6.75
03_vfs_write_stage                 |       3200 |      17.06 |       74.46 |        6.75
03_vfs_write_stage                 |       3328 |      17.06 |       74.46 |        6.75
03_vfs_write_stage                 |       3456 |      17.06 |       74.46 |        6.75
03_vfs_write_stage                 |       3584 |      17.06 |       74.46 |        6.75
03_vfs_write_stage                 |       3712 |      17.07 |       74.46 |        6.76
03_vfs_write_stage                 |       3840 |      17.07 |       74.46 |        6.76
03_vfs_write_stage                 |       3968 |      17.07 |       74.46 |        6.76
03_vfs_write_stage                 |       4096 |      17.07 |       74.46 |        6.77
04_multicloud_flush_500ms_00       |       4096 |      13.28 |       74.46 |        2.94
04_multicloud_flush_500ms_01       |       4096 |      85.54 |       89.51 |       77.23
04_multicloud_flush_500ms_02       |       4096 |      85.54 |       89.54 |       75.23
04_multicloud_flush_500ms_03       |       4096 |      85.58 |       89.55 |       77.25
04_multicloud_flush_500ms_04       |       4096 |      85.57 |       89.57 |       75.27
04_multicloud_flush_500ms_05       |       4096 |      77.59 |       89.61 |       67.29
04_multicloud_flush_500ms_06       |       4096 |      87.62 |       89.61 |       77.32
04_multicloud_flush_500ms_07       |       4096 |      87.63 |       89.62 |       77.34
04_multicloud_flush_500ms_08       |       4096 |      77.64 |       89.64 |       67.33
04_multicloud_flush_500ms_09       |       4096 |      87.70 |       89.70 |       77.42
04_multicloud_flush_500ms_10       |       4096 |      87.70 |       91.70 |       77.42
04_multicloud_flush_500ms_11       |       4096 |      87.72 |       91.70 |       77.44
04_multicloud_flush_500ms_12       |       4096 |      87.73 |       91.70 |       77.44
04_multicloud_flush_500ms_13       |       4096 |      87.73 |       91.70 |       77.45
04_multicloud_flush_500ms_14       |       4096 |      93.76 |       97.77 |       83.48
04_multicloud_flush_500ms_15       |       4096 |      85.84 |       97.77 |       77.49
04_multicloud_flush_500ms_16       |       4096 |      83.95 |       97.77 |       77.49
04_multicloud_flush_500ms_17       |       4096 |      77.79 |       97.77 |       67.48
04_multicloud_flush_500ms_18       |       4096 |      87.80 |       97.77 |       77.50
04_multicloud_flush_500ms_19       |       4096 |      83.30 |       97.77 |       73.62
04_multicloud_flush_500ms_20       |       4096 |      87.88 |       97.77 |       77.63
04_multicloud_flush_500ms_21       |       4096 |      85.94 |       97.77 |       77.64
04_multicloud_flush_500ms_22       |       4096 |      85.89 |       97.77 |       75.64
04_multicloud_flush_500ms_23       |       4096 |      85.96 |       97.77 |       77.70
04_multicloud_flush_500ms_24       |       4096 |      91.16 |       97.77 |       81.71
04_multicloud_flush_500ms_25       |       4096 |      91.96 |       97.77 |       85.72
04_multicloud_flush_500ms_26       |       4096 |      91.96 |       97.77 |       85.72
04_multicloud_flush_500ms_27       |       4096 |      91.96 |       97.77 |       85.72
04_multicloud_flush_500ms_28       |       4096 |      91.96 |       97.77 |       85.72
04_multicloud_flush_500ms_29       |       4096 |      91.96 |       97.77 |       85.72
04_multicloud_flush_500ms_30       |       4096 |      89.97 |       97.77 |       81.71
04_multicloud_flush_500ms_31       |       4096 |      85.96 |       97.77 |       75.69
04_multicloud_flush_500ms_32       |       4096 |      85.97 |       97.77 |       75.70
04_multicloud_flush_500ms_33       |       4096 |      87.98 |       97.77 |       77.71
04_multicloud_flush_500ms_34       |       4096 |      83.61 |       97.77 |       75.70
04_multicloud_flush_500ms_35       |       4096 |      85.96 |       97.77 |       77.62
04_multicloud_flush_500ms_36       |       4096 |      89.93 |       97.77 |       79.62
04_multicloud_flush_500ms_37       |       4096 |      89.93 |       97.77 |       79.62
04_multicloud_flush_500ms_38       |       4096 |      85.96 |       97.77 |       77.62
04_multicloud_flush_500ms_39       |       4096 |      85.96 |       97.77 |       77.64
04_multicloud_flush_500ms_40       |       4096 |      86.03 |       97.77 |       77.66
04_multicloud_flush_500ms_41       |       4096 |      82.74 |       97.77 |       77.67
04_multicloud_flush_500ms_42       |       4096 |      86.00 |       97.77 |       75.67
04_multicloud_flush_500ms_43       |       4096 |      88.02 |       97.77 |       77.69
04_multicloud_flush_500ms_44       |       4096 |      78.01 |       97.77 |       67.66
04_multicloud_flush_500ms_45       |       4096 |      86.04 |       97.77 |       75.70
04_multicloud_flush_500ms_46       |       4096 |      82.07 |       97.77 |       71.74
04_multicloud_flush_500ms_47       |       4096 |      78.32 |       97.77 |       71.74
04_multicloud_flush_500ms_48       |       4096 |      78.92 |       97.77 |       68.54
04_multicloud_flush_500ms_49       |       4096 |      78.92 |       97.77 |       68.54
04_multicloud_flush_500ms_50       |       4096 |      78.92 |       97.77 |       68.54
04_multicloud_flush_500ms_51       |       4096 |      78.92 |       97.77 |       68.54
04_multicloud_flush_500ms_52       |       4096 |      78.92 |       97.77 |       68.54
04_multicloud_flush_500ms_53       |       4096 |      78.92 |       97.77 |       68.54
04_multicloud_flush_500ms_54       |       4096 |      78.92 |       97.77 |       68.54
04_multicloud_flush_500ms_55       |       4096 |      78.88 |       97.77 |       68.46
04_multicloud_flush_500ms_56       |       4096 |      78.88 |       97.77 |       68.46
04_multicloud_flush_500ms_57       |       4096 |      78.88 |       97.77 |       68.46
04_multicloud_flush_500ms_58       |       4096 |      78.88 |       97.77 |       68.46
04_multicloud_flush_500ms_59       |       4096 |      78.88 |       97.77 |       68.46
04_multicloud_flush_500ms_60       |       4096 |      78.88 |       97.77 |       68.46
04_multicloud_flush_500ms_61       |       4096 |      78.88 |       97.77 |       68.46
04_multicloud_flush_500ms_62       |       4096 |      78.82 |       97.77 |       68.40
04_multicloud_flush_500ms_63       |       4096 |      78.82 |       97.77 |       68.40
04_multicloud_flush_500ms_64       |       4096 |      78.82 |       97.77 |       68.40
04_multicloud_flush_500ms_65       |       4096 |      78.82 |       97.77 |       68.40
05_post_multicloud_flush           |       4096 |      78.68 |       97.77 |       68.06
06_purged_and_locked               |          0 |      14.79 |       97.77 |        3.95
07_reunlocked_cold_cache           |          0 |      14.80 |       97.77 |        3.95
08_post_6x_video_scrub             |         24 |      55.17 |       97.77 |       44.27
09_seq_4gib_download               |        128 |      55.22 |       97.77 |       44.30
09_seq_4gib_download               |        256 |      55.27 |       97.77 |       44.35
09_seq_4gib_download               |        384 |      55.25 |       97.77 |       44.32
09_seq_4gib_download               |        512 |      55.31 |       97.77 |       44.38
09_seq_4gib_download               |        640 |      55.27 |       97.77 |       44.33
09_seq_4gib_download               |        768 |      55.25 |       97.77 |       44.31
09_seq_4gib_download               |        896 |      55.30 |       97.77 |       44.37
09_seq_4gib_download               |       1024 |      55.24 |       97.77 |       44.31
09_seq_4gib_download               |       1152 |      55.27 |       97.77 |       44.34
09_seq_4gib_download               |       1280 |      55.29 |       97.77 |       44.36
09_seq_4gib_download               |       1408 |      55.29 |       97.77 |       44.35
09_seq_4gib_download               |       1536 |      55.26 |       97.77 |       44.32
09_seq_4gib_download               |       1664 |      55.29 |       97.77 |       44.36
09_seq_4gib_download               |       1792 |      55.30 |       97.77 |       44.38
09_seq_4gib_download               |       1920 |      55.26 |       97.77 |       44.32
09_seq_4gib_download               |       2048 |      55.27 |       97.77 |       44.33
09_seq_4gib_download               |       2176 |      55.49 |       97.77 |       44.84
09_seq_4gib_download               |       2304 |      55.29 |       97.77 |       44.36
09_seq_4gib_download               |       2432 |      55.25 |       97.77 |       44.31
09_seq_4gib_download               |       2560 |      55.31 |       97.77 |       44.38
09_seq_4gib_download               |       2688 |      55.29 |       97.77 |       44.36
09_seq_4gib_download               |       2816 |      55.46 |       97.77 |       44.84
09_seq_4gib_download               |       2944 |      55.49 |       97.77 |       44.84
09_seq_4gib_download               |       3072 |      55.48 |       97.77 |       44.83
09_seq_4gib_download               |       3200 |      55.25 |       97.77 |       44.31
09_seq_4gib_download               |       3328 |      55.48 |       97.77 |       44.83
09_seq_4gib_download               |       3456 |      55.47 |       97.77 |       44.83
09_seq_4gib_download               |       3584 |      55.48 |       97.77 |       44.82
09_seq_4gib_download               |       3712 |      55.47 |       97.77 |       44.82
09_seq_4gib_download               |       3840 |      55.41 |       97.77 |       44.79
09_seq_4gib_download               |       3968 |      55.48 |       97.77 |       44.83
09_seq_4gib_download               |       4096 |      55.55 |       97.77 |       44.84
10_post_4gib_reclaim_idle          |       4096 |      19.33 |       97.77 |        8.59
11_final_locked_reclaimed          |          0 |      28.06 |      100.23 |       17.04
--------------------------------------------------------------------------------
[SUMMARY] Total Suite Wall-Clock : 60.757 s
[SUMMARY] 4 GiB SHA-256 Digest   : 9ff6bcaeee6e664cd84126fc759b6dfe27412760787d6c605e7e6703103fec48 (BIT-EXACT MATCH)
[SUMMARY] Max Sampled RSS        : 93.76 MiB (Delta vs Start: +83.57 MiB | Delta vs Mounted: +81.11 MiB)
[SUMMARY] Win32 Kernel PeakRSS   : 100.23 MiB (Across entire 4,096 MiB Upload + 4,096 MiB Download + 64 MiB Argon2id)
test w4_gate1_bit_exact_4gib_multicloud_roundtrip_and_bounded_rss ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 62.27s
```
