# Adversarial Gate 2A Verification Verdict (`JUDGE_GATE2A_VERDICT.md`)

- **Auditor:** `Agent-Judge` (Adversarial Red-Team & Proof Verifier — Zero-Trust Empirical Merger Swarm)
- **Audit Scope:** Wave 2 Foundation Crates (Part A):
  - [`crates/zerovault-types`](crates/zerovault-types)
  - [`crates/zerovault-crypto`](crates/zerovault-crypto)
  - [`crates/zerovault-storage`](crates/zerovault-storage)
  - [`crates/zerovault-vfs`](crates/zerovault-vfs)
- **Isolated Build Artifact Root:** `<workspace>\target\swarm\judge\gate2a`
- **Host Hardware & Toolchain:** AMD Ryzen 9 7950X3D (16C/32T, `VAES` + `VPCLMULQDQ` + `AVX2` + `AES-NI`), Windows 11 x64 (`10.0.26300`), `rustc 1.94.1 (e408947bf 2026-03-25)` (`edition = "2024"`), targets `x86_64-pc-windows-msvc` + `x86_64-unknown-linux-musl`
- **Gate 2A Final Verdict:** **`PASS (ZERO VETOES — ALL STATIC, CRYPTOGRAPHIC, STORAGE, VFS & CROSS-TARGET PROOFS EMPIRICALLY VERIFIED)`**

---

## 1. Read-Only Donor Source Tree Integrity Attestation (`0` Mutations)

Verified against [`audit/READONLY_BASELINE.txt`](audit/READONLY_BASELINE.txt) after all Gate 2A compilations and test runs:

- **Exact Command Executed:**
  ```powershell
  Get-ExactBaseline "cloudbridge"       "<donor-root>\cloudbridge"
  Get-ExactBaseline "cloudbridge linux" "<donor-root>\cloudbridge linux"
  Get-ExactBaseline "zerovault"         "<donor-root>\zerovault"
  Compare-Object -ReferenceObject (Get-Content "<workspace>\audit\READONLY_BASELINE.txt") -DifferenceObject @($r1, $r2, $r3)
  ```
- **Exit Code:** `0`
- **Wall-Clock Latency:** `613.54 ms` (`298,766,349` bytes hashed across `184` files -> **`464.42 MiB/s`** SHA-256 verification throughput)
- **Judge Process Physical RSS (`WorkingSet64` / `PeakWorkingSet64`):** `120,012,800 B` (`114.45 MiB`) / `120,201,216 B` (`114.63 MiB`)
- **Verbatim Stdout:**
  ```text
  cloudbridge | files=37 | bytes=89165156 | tree_sha256=43ADD08E502AC76DF469BDCEF9C8DC11914880DB8288C28C204345E69AE5B05F
  cloudbridge linux | files=65 | bytes=178010385 | tree_sha256=32DB719E53848B03BBDAC67B33423DE9D4161F660FBFF91A1B005126CE31554F
  zerovault | files=82 | bytes=31590808 | tree_sha256=383752380A143E34B124F1CA365BD6D5F9F43C570DE0E8D89D00C0632FB4D51D
  EXACT_DIFF_COUNT=0 | ELAPSED_MS=613.54 | RSS_BYTES=120012800 (114.45 MiB) | PEAK_RSS_BYTES=120201216 (114.63 MiB)
  ```

---

## 2. Static Red-Team Audit (`crates/{zerovault-types, zerovault-crypto, zerovault-storage, zerovault-vfs}/src/**`)

### 2.1 Zero Production `.unwrap()`, `.expect()`, `panic!()`, `todo!()`, `unimplemented!()`, `dbg!()`, & `unsafe`

1. **Full Source Regex Scan (`Select-String` across all `24` `.rs` files in `src/**`):**
   - **Command Executed:**
     ```powershell
     Select-String -Path "crates\{zerovault-types,zerovault-crypto,zerovault-storage,zerovault-vfs}\src\**\*.rs" `
       -Pattern "\.unwrap\s*\(|\.expect\s*\(|panic!\s*\(|todo!\s*\(|unimplemented!\s*\(|\bunsafe\b|dbg!\s*\("
     ```
   - **Findings:**
     - `zerovault-crypto/src/**`: **`0` matches** (`0` in prod, `0` in `src/`).
     - `zerovault-storage/src/**`: **`0` matches** (`#![forbid(unsafe_code)]` and `#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::todo, clippy::unimplemented)]` enforced at crate root [`crates/zerovault-storage/src/lib.rs:4-11`](crates/zerovault-storage/src/lib.rs#L4-L11)).
     - `zerovault-types/src/**`: **`0` production matches** (`23` matches in [`crates/zerovault-types/src/lib.rs:67-252`](crates/zerovault-types/src/lib.rs#L49-L260) are 100% inside `#[cfg(test)] mod tests`; even [`crates/zerovault-types/src/mocks.rs`](crates/zerovault-types/src/mocks.rs) has `0` `.unwrap()`/`.expect()`/`panic!()`/`unsafe`).
     - `zerovault-vfs/src/**`: **`0` production matches** (`8` matches in [`crates/zerovault-vfs/src/lib.rs:135-153`](crates/zerovault-vfs/src/lib.rs#L120-L156) are 100% inside `#[cfg(test)] mod tests`).

2. **Compiler AST/HIR Proof Across Both Windows (`msvc`) and Linux (`musl`) Production Targets:**
   - **Windows Host AST Proof Command:**
     ```powershell
     $env:CARGO_TARGET_DIR = "<workspace>\target\swarm\judge\gate2a"
     cargo clippy --manifest-path "<workspace>\Cargo.toml" `
       -p zerovault-types -p zerovault-crypto -p zerovault-storage -p zerovault-vfs --lib --locked `
       -- -D warnings -D unsafe_code -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic -D clippy::todo -D clippy::unimplemented -D clippy::dbg_macro
     ```
     - **Result:** **`EXIT_CODE=0`** | **Wall-Clock:** `10,959.18 ms` | **`0` warnings / `0` errors**
   - **Linux `x86_64-unknown-linux-musl` AST Proof Command (`fuser v0.18` + `nix v0.31` paths active):**
     ```powershell
     $env:CARGO_TARGET_DIR = "<workspace>\target\swarm\judge\gate2a"
     cargo clippy --manifest-path "<workspace>\Cargo.toml" `
       -p zerovault-vfs --lib --locked --target x86_64-unknown-linux-musl `
       -- -D warnings -D unsafe_code -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic -D clippy::todo -D clippy::unimplemented -D clippy::dbg_macro
     ```
     - **Result:** **`EXIT_CODE=0`** | **Wall-Clock:** `5,277.77 ms` | **`0` warnings / `0` errors**

3. **`unsafe` Audit Summary:**
   - `zerovault-types/src/**`: **`0` `unsafe` blocks**
   - `zerovault-crypto/src/**`: **`0` `unsafe` blocks**
   - `zerovault-storage/src/**`: **`0` `unsafe` blocks** (`#![forbid(unsafe_code)]`)
   - `zerovault-vfs/src/linux/**`: **`0` `unsafe` blocks**
   - `zerovault-vfs/src/windows/**`: **`0` `unsafe` blocks** — [`drive.rs`](crates/zerovault-vfs/src/windows/drive.rs), [`filter.rs`](crates/zerovault-vfs/src/windows/filter.rs), and [`placeholder.rs`](crates/zerovault-vfs/src/windows/placeholder.rs) interact with Win32 `CfApi` exclusively via safe `cloud-filter v0.0.7` abstractions (`Session`, `Connection`, `Placeholder`, `SyncRootIdBuilder`, `ticket::FetchData::write_at`) and typed `windows v0.62` constants/HRESULT mappings.

---

### 2.2 Cryptographic Engine & Post-Quantum Sharing Audit (`zerovault-crypto`)

| Audit Requirement | Source File & Line References | Verification Result |
| :--- | :--- | :---: |
| **`Zeroizing` on all 7 subkeys + seeds + DEKs + `RecipientPrivateIdentity`** | - [`engine.rs:43-153`](crates/zerovault-crypto/src/engine.rs#L43-L153): `MasterSeed` + all 7 `HKDF-SHA256` subkeys (`MasterKek`, `ManifestKey`, `TokenWrapKey`, `HeaderVerifierKey`, `MetadataKey`, `BlindIndexKey`, `StagingKey`) wrap `Zeroizing<[u8; 32]>` and derive `Zeroize, ZeroizeOnDrop`, with `[REDACTED]` `Debug` impls. `KeyRingState` derives `Zeroize, ZeroizeOnDrop` and is scrubbed on `install_keyring` (`L263-269`) and `lock_vault` (`L464-470`).<br>- [`engine.rs:311-317`](crates/zerovault-crypto/src/engine.rs#L311-L317) & [`aead_ring.rs:23-42`](crates/zerovault-crypto/src/aead_ring.rs#L23-L42): Argon2id output, CSPRNG secret buffers, and HKDF outputs write directly into `Zeroizing<[u8; 32]>`.<br>- [`wire.rs:87-119`](crates/zerovault-types/src/wire.rs#L87-L119) & [`engine.rs:590-633`](crates/zerovault-crypto/src/engine.rs#L590-L633): `DekBytes(Zeroizing<[u8; 32]>)` derives `Zeroize, ZeroizeOnDrop`.<br>- [`zerovault-types/src/sharing.rs:337-357`](crates/zerovault-types/src/sharing.rs#L337-L357): `RecipientPrivateIdentity` derives `Zeroize, ZeroizeOnDrop` and wraps `ed25519_seed: Zeroizing<[u8; 32]>`, `x25519_private: Zeroizing<[u8; 32]>`, and `mlkem768_decaps_key: Zeroizing<Vec<u8>>` (`2,400 B`). `CapabilityUri` (`L43-59`) wraps `share_root_key: Zeroizing<[u8; 32]>`. | **`PASS`** |
| **Real `ring 0.17` `AES_256_GCM` + real `aws-lc-rs` `ML_KEM_768` + `X25519` + `Ed25519` (zero mocks in prod)** | - [`aead_ring.rs:4-5, 46-121`](crates/zerovault-crypto/src/aead_ring.rs#L4-L121): Real `ring::aead::{AES_256_GCM, LessSafeKey, UnboundKey}` + `ring::rand::SystemRandom`, gated by CPUID `AES-NI + PCLMULQDQ` / `VAES + AVX2` (`hw.rs:32-53, 144-160`).<br>- [`sharing.rs:4-7, 97-410`](crates/zerovault-crypto/src/sharing.rs#L4-L410): Real `aws_lc_rs::kem::{ML_KEM_768, DecapsulationKey, EncapsulationKey, Ciphertext}` (FIPS 203 `1184 B` encaps / `2400 B` decaps / `1088 B` ct), `aws_lc_rs::agreement::{X25519, EphemeralPrivateKey, PrivateKey}`, and `aws_lc_rs::signature::{ED25519, Ed25519KeyPair, UnparsedPublicKey}`.<br>- Zero imports or references to `zerovault_types::mocks` anywhere in `zerovault-crypto/src/**`. | **`PASS`** |
| **`ZVS2` keyring session encryption (`NEW-M03` fix — no raw `master_seed`)** | - [`engine.rs:37-40, 472-588`](crates/zerovault-crypto/src/engine.rs#L472-L588): `persist_session` generates/retrieves a 32-byte CSPRNG `wrap_key` under `{vault_id}:wrap-key` and seals `root_key` in-place under `AES-256-GCM` (`aad = b"ZVS2" \|\| vault_id`, 12B CSPRNG nonce, 32B ciphertext, 16B tag = `80 B` `ZVS2` blob) under `{vault_id}:session`. Raw `master_seed`/`root_key` never appears in keyring blobs. | **`PASS`** |
| **`out_plaintext.zeroize()` on AEAD failure** | - [`aead_ring.rs:81-121`](crates/zerovault-crypto/src/aead_ring.rs#L81-L121): `open_in_place_detached` calls `in_out.zeroize()` on key schedule error, tag length error, and GCM authentication tag mismatch.<br>- [`engine.rs:346-351, 685-752`](crates/zerovault-crypto/src/engine.rs#L685-L752): `decrypt_chunk_into` calls `scrub_and_clear(out_plaintext)` (`buf.as_mut().zeroize(); buf.clear();`) on every header/index/wire-length error AND calls `out_plaintext.as_mut().zeroize(); out_plaintext.clear();` on AEAD failure (`L746-748`). | **`PASS`** |
| **Pre-allocation Argon2id KDF floor & anti-OOM DoS ceiling** | - [`wire.rs:44-55, 185-201, 287`](crates/zerovault-types/src/wire.rs#L185-L201) & [`engine.rs:296-302, 416`](crates/zerovault-crypto/src/engine.rs#L296-L302): Enforces `m_cost_kib in 65_536..=262_144` (64–256 MiB), `t_cost in 3..=10`, `p_cost in 4..=16` strictly *before* `Argon2` memory allocation. | **`PASS`** |

---

### 2.3 Multi-Cloud Storage Router, Hardened OAuth2 & Chaos Layer Audit (`zerovault-storage`)

| Audit Requirement | Source File & Line References | Verification Result |
| :--- | :--- | :---: |
| **Zero unbounded `operator.read()` calls** | - Verified `0` `operator.read(...)` calls across `crates/zerovault-storage/src/*.rs`.<br>- [`backend.rs:43-60, 583-631`](crates/zerovault-storage/src/backend.rs#L583-L631): `CloudBackend::get_object` resolves strict per-class wire ceilings (`112 B` header, `4 MiB` keybox/share, `4 MiB + 48 B` chunk, `64 MiB` manifest), opens `operator.reader(object_key).await?.into_stream(..).await?`, and aborts immediately with `InvalidWireFormat` if `out.len().saturating_add(chunk.len()) > max_bytes`.<br>- [`backend.rs:635-702`](crates/zerovault-storage/src/backend.rs#L635-L702): `get_object_range` validates `len <= max_bytes` and `offset.checked_add(len)` before issuing bounded `reader.read(offset..end).await`. | **`PASS`** |
| **`5s` per-socket OAuth timeout + non-aborting invalid `state` handling (`NEW-L01` fix)** | - [`oauth.rs:36, 689-859`](crates/zerovault-storage/src/oauth.rs#L689-L859): `PER_SOCKET_READ_TIMEOUT = Duration::from_secs(5)` (`L36`). Every accepted TCP socket in `accept_callback_code` is wrapped in `tokio::time::timeout(per_socket_read_timeout, read_http_request(&mut stream))` (`L700`); slowloris timeouts, malformed requests, non-`/callback` paths, missing `state`, mismatched `state` (`constant_time_csrf_eq` via `subtle::ConstantTimeEq`), forged `error` with wrong `state`, and missing `code` all return `400 Bad Request` / `404` and **`continue` listening** without aborting user login.<br>- [`oauth.rs:313-321`](crates/zerovault-storage/src/oauth.rs#L313-L321): `reqwest::redirect::Policy::none()` blocks 302 SSRF token-endpoint redirects. | **`PASS`** |
| **`Mirrored` AEAD bit-rot failover (`NEW-M02` fix)** | - [`router.rs:153-271`](crates/zerovault-storage/src/router.rs#L153-L271): `StorageRouter::get_blob_verified` races healthy primary mirrors via `select_ok`; when the fastest responder fails caller cryptographic `verify(&bytes)`, marks that mirror unhealthy (`bad.set_healthy(false, ...)`) and automatically iterates remaining `candidate_backends` via `get_blob_from_backend` until an intact replica passes `verify`, or fails closed with `CryptoTamperDetected` if all replicas fail.<br>- [`chaos.rs:136-375`](crates/zerovault-storage/src/chaos.rs#L136-L375): Lock-free SplitMix64 `ChaosStorageRouter` provides deterministic basis-point packet drops and targeted `BitFlipRule` replica corruption with verified failover. | **`PASS`** |

---

### 2.4 Cross-Platform Virtual Filesystem Audit (`zerovault-vfs`)

| Audit Requirement | Source File & Line References | Verification Result |
| :--- | :--- | :---: |
| **Windows `CfApi` calls `backend.unpin` *before* `backend.dehydrate` (`NEW-H02` / `VFS-1` & `VFS-3` fix)** | - [`windows/filter.rs:445-461`](crates/zerovault-vfs/src/windows/filter.rs#L445-L461): `WindowsCfFilter::dehydrate` inspects `FILE_ATTRIBUTE_UNPINNED` on user-initiated dehydration (`!info.background()`) and calls `self.backend.unpin(rec.inode).await?` *before* `guard_dehydrate_inode(&*self.backend, rec.inode).await?`.<br>- [`windows/filter.rs:782-788, 821-827`](crates/zerovault-vfs/src/windows/filter.rs#L821-L827): `process_state_change_path` executes `backend.unpin(rec.inode).await?; backend.dehydrate(rec.inode).await?;` on `wants_unpin` for both directories and files.<br>- [`windows/drive.rs:508-521`](crates/zerovault-vfs/src/windows/drive.rs#L508-L521): Implements `VirtualDrive::unpin_path`. | **`PASS`** |
| **Linux `FUSE` calls `backend.unpin` *before* `backend.dehydrate` (`NEW-H02` / `VFS-2` & `VFS-3` fix)** | - [`linux/portable.rs:1818-1837`](crates/zerovault-vfs/src/linux/portable.rs#L1818-L1837) (wired into `ZeroVaultFuseFs::setxattr` at [`linux/fs.rs:508-521, 829-843`](crates/zerovault-vfs/src/linux/fs.rs#L508-L521)): Setting `user.zerovault.pin` to `0`/`false`/`unpin` flushes dirty handles, invokes `self.backend.unpin(ino).await?` (`L1829-1832`), and then invokes `self.backend.dehydrate(ino).await` (`L1833-1836`).<br>- [`linux/drive.rs:287-293`](crates/zerovault-vfs/src/linux/drive.rs#L287-L293): Implements `VirtualDrive::unpin_path`. | **`PASS`** |
| **`DirtyWriteBuffer` wipes `0..capacity` (`NEW-M04` fix)** | - [`linux/portable.rs:514-541, 550-598, 931-950`](crates/zerovault-vfs/src/linux/portable.rs#L514-L598): Payload is stored in `Zeroizing<Vec<u8>>` capped at `PLAINTEXT_CHUNK_SIZE` (`4 MiB`). `scrub_zeroize_vec` executes `buf.resize(cap, 0); buf.zeroize();` across full `0..capacity` on `zeroize_and_clear`, `Drop`, auto-flush, error rollback (`scrub_truncate_vec`), partial short-write drain (`scrub_drain_prefix`), and growth reallocation (`reserve_bounded` scrubs prior heap buffer before drop). | **`PASS`** |

---

## 3. Independent Empirical Execution & Telemetry Matrix

All Cargo executions used `$env:CARGO_TARGET_DIR = "<workspace>\target\swarm\judge\gate2a"`.

### 3.1 Mandatory Cargo Suite & Cross-Target Clippy Commands

| Gate Check | Exact Command Executed | Exit Code | Result / Warnings | Wall-Clock Latency | Idle / Min Active RSS (`WorkingSet64`) | Peak Physical RSS (`WorkingSet64`) |
| :--- | :--- | :---: | :--- | ---: | ---: | ---: |
| **1a. `cargo test` (Cold Build + Full Run)** | `cargo test --manifest-path "<workspace>\Cargo.toml" -p zerovault-types -p zerovault-crypto -p zerovault-storage -p zerovault-vfs --locked` | **`0`** | **`76 passed, 0 failed, 1 ignored`** (`0` doc-tests) | `61,845.19 ms` (`41.03 s` compile + `~20.8 s` test) | `44,728,320 B` (`42.66 MiB` tree) | `2,963,550,208 B` (`2,826.26 MiB` parallel `rustc` tree) |
| **1b. `cargo test` (Warm Execution Only)** | `cargo test --manifest-path "<workspace>\Cargo.toml" -p zerovault-types -p zerovault-crypto -p zerovault-storage -p zerovault-vfs --locked` | **`0`** | **`76 passed, 0 failed, 1 ignored`** (`0` doc-tests) | **`21,669.91 ms`** (`21.670 s`) | `2,699,264 B` (`2.57 MiB` binary idle) | `77,426,688 B` (`73.84 MiB` max single test binary) |
| **2. Host Windows `cargo clippy --all-targets`** | `cargo clippy --manifest-path "<workspace>\Cargo.toml" -p zerovault-types -p zerovault-crypto -p zerovault-storage -p zerovault-vfs --all-targets --locked -- -D warnings` | **`0`** | **`0` warnings / `0` errors** | **`33,315.09 ms`** (`33.315 s`) | `34,918,400 B` (`33.30 MiB`) | `46,723,072 B` (`44.56 MiB`) |
| **3. Cross-Target Linux `musl` `cargo clippy --all-targets`** | `cargo clippy --manifest-path "<workspace>\Cargo.toml" -p zerovault-vfs --all-targets --locked --target x86_64-unknown-linux-musl -- -D warnings` | **`0`** | **`0` warnings / `0` errors** (`fuser v0.18.0`, `nix v0.31.4`) | **`16,120.84 ms`** (`16.121 s`) | `60,723,200 B` (`57.91 MiB`) | `60,723,200 B` (`57.91 MiB`) |

### 3.2 Per-Binary NT Kernel `WorkingSet64` / `PeakWorkingSet64` & Hardware Throughput Telemetry

| Crate & Target Binary | Passed | Failed | Ignored | Exit Code | Wall-Clock Latency | Idle `WorkingSet64` | Peak `PeakWorkingSet64` | Empirical Throughput / Notes |
| :--- | ---: | ---: | ---: | :---: | ---: | ---: | ---: | :--- |
| `zerovault-types` (`lib` unittests) | `7` | `0` | `0` | `0` | `46.92 ms` | `2,703,360 B` (`2.58 MiB`) | `6,578,176 B` (`6.27 MiB`) | Wire headers, KDF DoS bounds, `zv://` & mock keybox epoch floor, `proptest` `ChunkRangeSpan` |
| `zerovault-crypto` (`lib` unittests) | `0` | `0` | `0` | `0` | `0.00 ms` | — | — | Tested comprehensively via `tests/crypto_suite.rs` |
| `zerovault-crypto` (`tests/crypto_suite.rs`, debug `--test-threads=1`) | `18` | `0` | `0` | `0` | `9,905.57 ms` (`6.94 s` parallel) | `2,711,552 B` (`2.59 MiB`) | `77,426,688 B` (`73.84 MiB`) | Single `64 MiB` Argon2id arena + `~9.8 MiB` process overhead; includes live Windows Credential Manager `ZVS2` roundtrip & 6 `proptest` tamper suites |
| `zerovault-crypto` (`tests/crypto_suite.rs`, `--release` `64 MiB` `4 MiB`-chunk bench) | `1` | `0` | `0` | `0` | `51.28 ms` (`20 ms` bench) | `2,707,456 B` (`2.58 MiB`) | `13,987,840 B` (`13.34 MiB`) | **`7,875.66 MiB/s` (`7.69 GiB/s`) encrypt / `9,093.36 MiB/s` (`8.88 GiB/s`) decrypt** (`ring-0.17-aes256gcm-vaes-avx2`) |
| `zerovault-storage` (`lib` unittests) | `5` | `0` | `0` | `0` | `43.28 ms` | `2,715,648 B` (`2.59 MiB`) | `6,062,080 B` (`5.78 MiB`) | Wire ceilings, streaming/range roundtrip, SplitMix64 bit-flip determinism |
| `zerovault-storage` (`tests/storage_integration.rs`) | `11` | `0` | `0` | `0` | `5,075.73 ms` | `2,711,552 B` (`2.59 MiB`) | `24,109,056 B` (`22.99 MiB`) | Includes live `5.0s` slowloris socket timeout proof (`4.8s..8.0s` verified), SSRF 302 trap, RAID-1 bit-rot failover, `min_ack` rollback |
| `zerovault-storage` (`tests/storage_proptest.rs`) | `6` | `0` | `0` | `0` | `100.81 ms` | `2,711,552 B` (`2.59 MiB`) | `20,480,000 B` (`19.53 MiB`) | `30%` chaos packet-loss convergence, RAID-1 bit-rot `proptest`, quota conservation |
| `zerovault-vfs` (`lib` unittests) | `1` | `0` | `0` | `0` | `< 10.00 ms` | — | — | `MockDrive` `pin -> unpin -> dehydrate` lifecycle |
| `zerovault-vfs` (`tests/linux_vfs_tests.rs`) | `8` | `0` | `0` | `0` | `6,274.42 ms` | `2,703,360 B` (`2.58 MiB`) | `47,927,296 B` (`45.71 MiB`) | Portable FUSE state-machine, `DirtyWriteBuffer` `0..capacity` pointer zeroization proof, `xattr` `unpin -> dehydrate`, `Makefile`/`makefile` POSIX siblings |
| `zerovault-vfs` (`tests/windows_vfs_tests.rs`) | `20` | `0` | `1` | `0` | `111.19 ms` | `2,699,264 B` (`2.57 MiB`) | `48,652,288 B` (`46.40 MiB`) | `NEW-H02` (`VFS-1`/`VFS-3`) unpin->dehydrate regressions, `5.01 MiB` streaming hydration/upload, `512`-case `CfApi` 4 KiB alignment `proptest` *(1 ignored: `live_cfapi_sync_root_mount_and_unmount_integration` requiring interactive Explorer Shell SyncRoot session)* |
| **TOTAL GATE 2A TEST SUITE** | **`76`** | **`0`** | **`1`** | **`0`** | **`21.670 s` warm** | **`2.57 MiB` min** | **`73.84 MiB` max** | **100% pass rate (`0` failures)** |

---

## 4. Verbatim Raw Stdout / Stderr Excerpts

### 4.1 `cargo test -p zerovault-types -p zerovault-crypto -p zerovault-storage -p zerovault-vfs --locked`
```text
    Finished `test` profile [unoptimized + debuginfo] target(s) in 41.03s
     Running unittests src\lib.rs (entrocloud merge\target\swarm\judge\gate2a\debug\deps\zerovault_crypto-848210a16413cbbe.exe)
running 0 tests
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running tests\crypto_suite.rs (entrocloud merge\target\swarm\judge\gate2a\debug\deps\crypto_suite-4cd70a06a5ad24bd.exe)
running 18 tests
test all_eight_key_wrappers_redact_debug_zeroize_and_separate_7_hkdf_domains ... ok
test hardware_acceleration_verified_and_fail_closed_when_absent ... ok
test metadata_blind_index_staging_and_manifest_operations_roundtrip_and_reject_tamper ... ok
test ring_and_aws_lc_aes256_gcm_produce_bit_identical_wire_ciphertext_and_tags ... ok
test prop_kdf_out_of_bounds_floor_and_oom_ceiling_rejected_pre_alloc ... ok
test os_keyring_secret_store_windows_zvs2_roundtrip_and_cleanup ... ok
test edge_cases_exact_4mib_is_final_truncation_dek_wrap_and_zero_epoch_revisions ... ok
test capability_share_zv_uri_roundtrip_without_vault_unlock_and_tamper_checks ... ok
test prop_metadata_and_staging_chunk_tamper_rejected ... ok
test multi_chunk_4mib_streaming_buffer_reuse_and_tamper_scrubbing ... ok
test benchmark_aes256_gcm_4mib_reports_high_hardware_throughput ... ok
test prop_chunk_swap_file_swap_and_is_final_flip_rejected ... ok
test prop_chunk_1bit_flip_always_rejected_and_zeroizes_out_buf ... ok
test prop_zv_capability_share_tamper_rejected ... ok
test prop_keybox_epoch_replay_forged_sig_and_mlkem_tamper_rejected ... ok
test zvs2_wrapped_session_remediates_new_m03_never_persisting_raw_seed ... ok
test pq_keybox_mlkem768_x25519_ed25519_sharing_and_revocation_epoch_floor ... ok
test init_lock_unlock_lifecycle_and_kdf_floor_plus_oom_ceiling ... ok
test result: ok. 18 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 6.94s

     Running unittests src\lib.rs (entrocloud merge\target\swarm\judge\gate2a\debug\deps\zerovault_storage-cf7a946ad2d3fcb1.exe)
running 5 tests
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s

     Running tests\storage_integration.rs (entrocloud merge\target\swarm\judge\gate2a\debug\deps\storage_integration-0c24d110ed47bc56.exe)
running 11 tests
test new_m02_get_blob_verified_marks_bitrotted_fast_mirror_unhealthy_and_fails_over ... ok
test oauth_new_l01_survives_slowloris_and_malicious_probes_until_valid_state_arrives ... ok
test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 5.02s

     Running tests\storage_proptest.rs (entrocloud merge\target\swarm\judge\gate2a\debug\deps\storage_proptest-2a82064ddae92071.exe)
running 6 tests
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.07s

     Running unittests src\lib.rs (entrocloud merge\target\swarm\judge\gate2a\debug\deps\zerovault_types-5dd37ffdb5c93b83.exe)
running 7 tests
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s

     Running unittests src\lib.rs (entrocloud merge\target\swarm\judge\gate2a\debug\deps\zerovault_vfs-b552329471c60f69.exe)
running 1 test
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running tests\linux_vfs_tests.rs (entrocloud merge\target\swarm\judge\gate2a\debug\deps\linux_vfs_tests-ae512b6e4ef84049.exe)
running 8 tests
test dirty_write_buffer_coalesces_and_zeroizes_spare_capacity ... ok
test portable_xattr_engine_pin_unpin_dehydrate_and_file_id ... ok
test prop_dirty_write_buffer_coalescing_matches_oracle_and_zeroizes ... ok
test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 6.48s

     Running tests\windows_vfs_tests.rs (entrocloud merge\target\swarm\judge\gate2a\debug\deps\windows_vfs_tests-a3646b1672aa7a9e.exe)
running 21 tests
test live_cfapi_sync_root_mount_and_unmount_integration ... ignored, requires live Windows Explorer / Shell SyncRoot registration context
test regression_new_h02_vfs1_pinned_file_unpin_attribute_transition_unpins_and_dehydrates_online_only ... ok
test regression_new_h02_vfs3_windows_cf_drive_unpin_path_clears_pin_and_enables_dehydration ... ok
test result: ok. 20 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.08s
```

### 4.2 Release Hardware AES-256-GCM Throughput Verification (`ring 0.17` Stitched `VAES` + `AVX2`)
```text
BIN=zerovault-crypto (crypto_suite release bench) | EXIT=0 | MS=51.28 | IDLE_RSS=2707456 (2.58 MiB) | PEAK_RSS=13987840 (13.34 MiB)
BENCHMARK_REPORT backend=ring-0.17-aes256gcm-vaes-avx2 enc_mib_s=7875.66 dec_mib_s=9093.36
test benchmark_aes256_gcm_4mib_reports_high_hardware_throughput ... ok
```

### 4.3 Host Windows & Cross-Target Linux `musl` Clippy (`-D warnings`)
```text
HOST_CLIPPY: EXIT_CODE=0 | ELAPSED_MS=33315.09 | PEAK_RSS_BYTES=46723072 (44.56 MiB) | IDLE_RSS_BYTES=34918400 (33.30 MiB)
    Checking zerovault-types v0.2.0 (<workspace>\crates\zerovault-types)
    Checking zerovault-vfs v0.2.0 (<workspace>\crates\zerovault-vfs)
    Checking zerovault-crypto v0.2.0 (<workspace>\crates\zerovault-crypto)
    Checking zerovault-storage v0.2.0 (<workspace>\crates\zerovault-storage)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 32.97s

MUSL_CLIPPY: EXIT_CODE=0 | ELAPSED_MS=16120.84 | PEAK_RSS_BYTES=60723200 (57.91 MiB) | IDLE_RSS_BYTES=60723200 (57.91 MiB)
   Compiling fuser v0.18.0
    Checking zerovault-types v0.2.0 (<workspace>\crates\zerovault-types)
    Checking zerovault-vfs v0.2.0 (<workspace>\crates\zerovault-vfs)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 15.96s
```

---

## 5. Judicial Sign-Off

Gate 2A (`zerovault-types`, `zerovault-crypto`, `zerovault-storage`, `zerovault-vfs`) is **APPROVED (`PASS`)** with zero vetoes and zero open defects. Downstream integration crates (`zerovault-core`, `zerovault-daemon`, `zerovault-cli`, `zerovault-ui`) are cleared to build atop these verified foundations.
