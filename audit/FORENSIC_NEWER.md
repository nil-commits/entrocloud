# Wave 0 Forensic Archaeology Report — Newer `zerovault` Codebase

- **Target Repository (Read-Only):** `<donor-root>\zerovault`
- **Auditor:** `Agent-Forensics-B` (Zero-Trust Empirical Merger Swarm)
- **Audit Date:** `2026-11-17`
- **HEAD Commit:** `46c9e77` (`feat(ui): human-oriented desktop UX, native OS dialogs, and standalone Zerovault.exe`)
- **Workspace Scale:** `9` Cargo workspace members (`8` crates under `crates/` + `tests/e2e`), `46` `.rs` files (`29,969` lines of Rust), plus `4,352` lines of Tauri frontend (`HTML`/`CSS`/`JS`) and `5` OS packaging manifests/scripts.
- **Source Tree Mutation Check:** `0` modified, untracked, or deleted files (`git status --short` verified empty before and after all operations; all Cargo artifacts isolated inside `<workspace>\target\swarm\forensics-b`).

---

## 1. Executive Summary & High-Impact Verdicts

1. **Workspace Compiles & Passes All Tests/Clippy Cleanly:**
   - `cargo test --workspace --locked` exits `0` in `120.809s` (`85 passed, 0 failed, 1 ignored, 0 doc-tests`).
   - `cargo clippy --workspace --all-targets --locked -- -D warnings` exits `0` in `57.742s` with **`0` warnings**.
   - Cross-target Linux verification (`cargo clippy -p zerovault-vfs --all-targets --locked --target x86_64-unknown-linux-musl -- -D warnings`) also exits `0` in `21.104s` with **`0` warnings**, proving the Linux `fuser` VFS compiles cleanly without platform syntax/type rot.
2. **Hard Iron Law #2 Violation (`Zerovault.exe` Uses Tauri v2 + WebView2):**
   - `Zerovault.exe` (`29,826,048` bytes / `28.44 MiB`, internal PE export name `zerovault_ui.exe`) links `tauri v2.12.6`, `tauri-runtime-wry v2.12.4`, `wry v0.57.2`, and `webview2-com-sys v0.39.1` (`WebView2LoaderStatic.lib`), dynamically loading `EBWebView\x64\EmbeddedBrowserWebView.dll` at runtime. Its UX workflows must be ported to a zero-WebView native Rust UI; `tauri`/`wry`/`webview2` must be excised completely.
3. **Symmetric Envelope Crypto Is Real & High-Assurance (`aws-lc-rs`), But Post-Quantum / Asymmetric Sharing (`keybox.zv`, `ML-KEM-768`, `Ed25519`, `X25519`, `zv://`) Is 100% Absent:**
   - `zerovault-crypto` genuinely uses **`aws-lc-rs v1.19`** (`AES_256_GCM`, scatter/gather AEAD, CSPRNG nonces), runtime CPUID hardware gating (`AES-NI` + `PCLMULQDQ` on x86_64; `AES` + `PMULL` on AArch64), `Argon2id` (`>= 64 MiB`, `t >= 3`, `p >= 4`), and `HKDF-SHA256` 4-subkey derivation. Meanwhile, `aes-gcm = "0.10"` in root `Cargo.toml:55` is dead/unused.
   - **Zero occurrences** (`PROD=0, TEST=0`) exist anywhere in `zerovault` for `ML-KEM-768` (`aws_lc_rs::kem`), `Ed25519`, `X25519`, `keybox.zv`, or `zv://` capability URIs. Those primitives must be sourced from the sibling `cloudbridge` codebase or freshly engineered.
4. **Major Newly Uncovered Architectural & Security Defects (Missed by `SECURITY_AUDIT.md`):**
   - **[CRITICAL] Multi-Device Cloud Bootstrap Is Broken in `DaemonRuntime`:** `DaemonRuntime::init_vault` (`crates/zerovault-daemon/src/service.rs:773-825`) writes `vault.zvh` only to local `state_dir` and **never calls `SyncEngine::publish_vault_header`**. `DaemonRuntime::unlock_vault` (`service.rs:827-888`) reads only local `state_dir/vault.zvh` and **never calls `SyncEngine::fetch_vault_header`**. A second computer cannot join an existing cloud vault via `zerovaultd`, `zv`, or `zerovault-ui`!
   - **[HIGH] Zero Periodic Background Sync Loop in `zerovaultd`:** Despite documentation claiming `zerovaultd` is a background sync daemon, neither `crates/zerovault-daemon/src/main.rs` nor `service.rs` spawns any periodic sync timer/worker. `sync_once()` only runs on manual `SyncNow` RPCs or explicit file `flush()`.
   - **[HIGH] VFS Unpin Broken on Both Windows Explorer & Linux FUSE:** Both `crates/zerovault-vfs/src/windows/filter.rs:694-698, 727-731` and `crates/zerovault-vfs/src/linux/fs.rs:1042-1046` handle OS unpin events by calling `backend.dehydrate(inode)` directly *without* calling `backend.unpin(inode)` first—which deterministically fails with `PinnedDehydrationDenied` (`EBUSY` on Linux; silently swallowed on Windows) whenever the file was previously pinned! Furthermore, `VirtualDrive` (`crates/zerovault-types/src/traits.rs:730-754`) has no `unpin_path` method at all.
   - **[HIGH] Local Disk Staging Writes Unencrypted Plaintext `.part` Chunks:** `ChunkCache` (`crates/zerovault-core/src/cache.rs:212-304`) writes dirty 4 MiB chunks as **plaintext** under `staging_dir/dirty/<inode>/<chunk_index>.part` (with default NTFS DACLs on Windows) and leaves unflushed `.part` plaintext files on disk across `LockVault` (`engine.rs:1245-1282`).
   - **[MEDIUM] `SECURITY_AUDIT.md` Claim of "0 `unsafe` Blocks" Is Stale/False:** Commit `46c9e77` introduced **12 production `unsafe` blocks** in `crates/zerovault-ui/src/dialogs.rs:126-312` for Win32 COM `IFileOpenDialog`/`IFileSaveDialog`/`ShellExecuteW` without updating `SECURITY_AUDIT.md`.
   - **[MEDIUM] Dead & Plaintext-Bearing Keyring Session Blob (`ZVS1`):** `AwsLcCryptoEngine::persist_session` (`crates/zerovault-crypto/src/engine.rs:406-445`) stores the **unencrypted 32-byte `master_seed`** at bytes `53..85` of its `ZVS1` blob (using AES-GCM only as a zero-byte tag verifier), and neither `zerovault-daemon` nor `zerovault-ui` ever invokes `persist_session` or `restore_session`.

---

## 2. Empirical Build, Test, Clippy & Binary Forensics

### 2.1 Git Commit Lineage (`<donor-root>\zerovault`)
```text
46c9e77 feat(ui): human-oriented desktop UX, native OS dialogs, and standalone Zerovault.exe
6c1d5ad feat(ui): replace hidden tray stub with full standalone Tauri v2 desktop GUI
35895c2 feat(wave-3): e2e zero-knowledge security suite, audit remediations, and docs
fa243da feat(wave-2): sync engine, daemon IPC, zv CLI, Tauri tray UI, and OS packaging
084c248 feat(wave-1): crypto, multi-cloud storage router, and cross-platform VFS
```

### 2.2 Isolated `cargo test --workspace --locked` Execution
- **Command:**
  ```powershell
  $env:CARGO_TARGET_DIR = "<workspace>\target\swarm\forensics-b"
  cargo test --workspace --locked --manifest-path "<donor-root>\zerovault\Cargo.toml"
  ```
- **Exit Code:** `0`
- **Wall-Clock Duration (Cold Compile + Full Test Suite):** `120.809s` (`120,809 ms`; `rustc` compile `68s` + test execution `~48.3s`)
- **Raw Log Artifact:** [cargo_test_raw.log](target/swarm/forensics-b/cargo_test_raw.log)

| Crate / Target | Passed | Failed | Ignored | Doc-Tests | Execution Time | Notes |
|---|---:|---:|---:|---:|---:|---|
| `zerovault-cli` (`lib`) | `3` | `0` | `0` | `0` | `0.10s` | Subcommand parser, live 8 MiB `bench-crypto`, TCP loopback daemon RPC |
| `zerovault-cli` (`bin zv`) | `0` | `0` | `0` | — | `0.00s` | Thin wrapper around `zerovault_cli::run_from_env()` |
| `zerovault-core` (`lib`) | `10` | `0` | `0` | `0` | `3.50s` | Pool, LRU + `.part` staging, SQLite WAL, conflict formatting, 9.5 MiB seek, offline retry |
| `zerovault-crypto` (`lib`) | `9` | `0` | `0` | `0` | `6.13s` | CPUID, zeroize/redaction, `aws-lc-rs` scatter/gather, Argon2id 64 MiB, Windows Credential Manager roundtrip |
| `zerovault-daemon` (`lib`) | `6` | `0` | `0` | `0` | `23.78s` | Named Pipe DACL lifecycle, TCP loopback, frame DoS bounds, GUI file/policy/conflict RPCs |
| `zerovault-daemon` (`bin zerovaultd`) | `0` | `0` | `0` | — | `0.00s` | CLI + signal handler wrapper |
| `zerovault-e2e` (`e2e_multicloud_zero_knowledge`) | `6` | `0` | `0` | `0` | `7.52s` | Zero-knowledge blob audit, O(1) boundary read, tamper fail-closed, RAID-1 failover, quota spillover, 2-device conflict |
| `zerovault-e2e` (`redteam_security_audit`) | `6` | `0` | `0` | — | `5.43s` | DEK/chunk transplant, 4 MiB final-flag bitflip, path traversal, OAuth SSRF/CSRF, IPC frame bounds, rollback & lock purge |
| `zerovault-storage` (`lib`) | `20` | `0` | `0` | `0` | `0.06s` | All 7 OpenDAL builders, OAuth PKCE loopback + token refresh, Targeted/Mirrored/QuotaPooled + CAS concurrency |
| `zerovault-types` (`lib`) | `6` | `0` | `0` | `0` | `0.01s` | Wire headers, KDF floor, `ChunkSpan` math, key validation, redaction, mocks |
| `zerovault-ui` (`lib` + `bin`) | `5` | `0` | `0` | `0` | `1.71s` | View models, policy builder, embedded standalone `DaemonRuntime`, notes, session scrub |
| `zerovault-vfs` (`lib`) | `1` | `0` | `0` | `0` | `0.00s` | `MockDrive` lifecycle |
| `zerovault-vfs` (`tests/windows_vfs_tests.rs`) | `13` | `0` | `1` | — | `0.08s` | Ignored: `live_cfapi_sync_root_mount_and_unmount_integration` (requires Explorer Shell SyncRoot registration) |
| `zerovault-vfs` (`tests/linux_vfs_tests.rs`) | `0` | `0` | `0` | — | `0.00s` | `#![cfg(target_os = "linux")]` (`12` `#[test]` functions compiled & checked via musl target below) |
| **TOTAL** | **`85`** | **`0`** | **`1`** | **`0`** | **`120.81s` wall** | **100% pass rate** |

### 2.3 Isolated `cargo clippy` Executions (Host Windows MSVC + Cross-Target Linux musl)
1. **Windows Host Workspace Clippy:**
   - **Command:** `cargo clippy --workspace --all-targets --locked --manifest-path "<donor-root>\zerovault\Cargo.toml" -- -D warnings`
   - **Exit Code:** `0` (`0` warnings, `0` errors)
   - **Wall-Clock Duration:** `57.742s` (`57,741 ms`, `Finished dev profile in 57.51s`)
   - **Raw Log:** [cargo_clippy_raw.log](target/swarm/forensics-b/cargo_clippy_raw.log)
2. **Linux `x86_64-unknown-linux-musl` Cross-Target VFS Clippy:**
   - **Command:** `cargo clippy -p zerovault-vfs --all-targets --locked --target x86_64-unknown-linux-musl --manifest-path "<donor-root>\zerovault\Cargo.toml" -- -D warnings`
   - **Exit Code:** `0` (`0` warnings, `0` errors across `fuser v0.18.0`, `src/linux/*`, and `tests/linux_vfs_tests.rs`)
   - **Wall-Clock Duration:** `21.104s` (`21,104 ms`, `Finished dev profile in 20.81s`)
   - **Raw Log:** [linux_vfs_clippy.log](target/swarm/forensics-b/linux_vfs_clippy.log)

### 2.4 Binary Forensics on `<donor-root>\zerovault\Zerovault.exe`
- **File Size:** `29,826,048` bytes (`28.44 MiB`)
- **SHA-256:** `D2F046F53355675AF81E318652092B75A23C3C76DD149412A97329C63B06322A`
- **PE32+ Header Metadata (`dumpbin /headers`):**
  - Machine: `8664 (x64)`, Linker `14.50`, Subsystem: `2 (Windows GUI)`, DLL Characteristics: `0x8160` (`HIGH_ENTROPY_VA`, `DYNAMIC_BASE`, `NX_COMPAT`, `TERMINAL_SERVER_AWARE`).
  - PE Sections: `.text` (`0x14A2000` = `20.63 MiB`), `.rdata` (`0x6CF000` = `6.81 MiB`), `.pdata` (`0xE8000`), `.reloc` (`0x13000`), `.data` (`0xE000`), `.rsrc` (`0x1000`).
- **Verbatim `dumpbin /dependents /exports Zerovault.exe` Output:**
  ```text
  Dump of file <donor-root>\zerovault\Zerovault.exe

  File Type: EXECUTABLE IMAGE

    Image has the following dependencies:

      kernel32.dll
      bcryptprimitives.dll
      ntdll.dll
      api-ms-win-core-synch-l1-2-0.dll
      oleaut32.dll
      cldapi.dll
      advapi32.dll
      api-ms-win-core-winrt-l1-1-0.dll
      combase.dll
      shell32.dll
      gdi32.dll
      comctl32.dll
      user32.dll
      ole32.dll
      imm32.dll
      dwmapi.dll
      api-ms-win-core-winrt-error-l1-1-0.dll
      shlwapi.dll
      bcrypt.dll
      ws2_32.dll
      crypt32.dll
      api-ms-win-crt-string-l1-1-0.dll
      api-ms-win-crt-math-l1-1-0.dll
      api-ms-win-crt-heap-l1-1-0.dll
      api-ms-win-crt-utility-l1-1-0.dll
      api-ms-win-crt-time-l1-1-0.dll
      api-ms-win-crt-runtime-l1-1-0.dll
      api-ms-win-crt-convert-l1-1-0.dll
      api-ms-win-crt-environment-l1-1-0.dll
      api-ms-win-crt-stdio-l1-1-0.dll
      api-ms-win-crt-locale-l1-1-0.dll

    Section contains the following exports for zerovault_ui.exe

      ordinal hint RVA      name
            1    0 01437F50 aws_lc_0_47_0_jent_entropy_collector_alloc
            2    1 01437FD0 aws_lc_0_47_0_jent_entropy_collector_free
            3    2 01438050 aws_lc_0_47_0_jent_entropy_init
            4    3 01438090 aws_lc_0_47_0_jent_entropy_init_ex
            5    4 01438120 aws_lc_0_47_0_jent_entropy_switch_notime_impl
            6    5 01437A90 aws_lc_0_47_0_jent_read_entropy
            7    6 01437C40 aws_lc_0_47_0_jent_read_entropy_safe
            8    7 014380F0 aws_lc_0_47_0_jent_set_fips_failure_callback
            9    8 01438110 aws_lc_0_47_0_jent_version
  ```
- **Empirical Proof of Tauri v2 / WebView2 Dependency (Iron Law #2 Violation):**
  - `Zerovault.exe` is simply `target/release/zerovault-ui.exe` copied to the repo root by [bundle-portable.ps1](../zerovault/packaging/windows/bundle-portable.ps1#L76-L82) (proven by the PE export directory header `exports for zerovault_ui.exe`).
  - Why `WebView2Loader.dll` is not in the static PE import table: `webview2-com-sys v0.39.1` statically links Microsoft's `WebView2LoaderStatic.lib` directly into `.text`/`.rdata`, which resolves Edge WebView2 via registry queries and `LoadLibraryW` at runtime.
  - Extracted ASCII & UTF-16LE strings inside `Zerovault.exe` confirm:
    - `EBWebView\x64\EmbeddedBrowserWebView.dll` (`x86` and `arm64` paths also embedded)
    - `Software\Policies\Microsoft\Edge\WebView2\` and `Microsoft.WebView2Runtime.Stable_8wekyb3d8bbwe` (`Beta`, `Dev`, `Canary`)
    - `tauri_runtime_wryCould not find the WebView2 Runtime`
    - `window.__TAURI_INTERNALS__`, `tauri v2.12.6`, `wry v0.57.2`, `webview2-com-sys v0.39.1`.
  - It also links `cldapi.dll` directly because `zerovault-ui` embeds `zerovault-daemon` -> `zerovault-vfs` (`cloud-filter v0.0.7`) in-process for standalone operation!

---

## 3. Complete Crate-by-Crate Source Dissection

### 3.1 Workspace Configuration ([Cargo.toml](../zerovault/Cargo.toml))
- **Rust Toolchain Floor:** `edition = "2024"`, `rust-version = "1.90"` (`Cargo.toml:14-17`), release profile `lto = "thin"`, `codegen-units = 1`, `panic = "abort"`, `strip = "symbols"` (`Cargo.toml:116-122`), and Windows `.cargo/config.toml` sets `-C target-feature=+crt-static`? No—[.cargo/config.toml](../zerovault/.cargo/config.toml#L1-L6) sets `RUSTDOCFLAGS = "-D warnings"` and `aws_lc_sys` CMake/NASM friendliness (`env` empty, standard dynamic UCRT).
- **Unused / Duplicate Dependencies Detected in Graph:**
  1. `aes-gcm = "0.10"` ([Cargo.toml](../zerovault/Cargo.toml#L55)): **0 crates in the workspace depend on it.**
  2. `rand = "0.8"` ([Cargo.toml](../zerovault/Cargo.toml#L63)): **0 workspace crates import it directly** (CSPRNG uses `aws_lc_rs::rand::fill`).
  3. `interprocess = "2.4"` ([Cargo.toml](../zerovault/Cargo.toml#L96), [crates/zerovault-daemon/Cargo.toml](../zerovault/crates/zerovault-daemon/Cargo.toml#L19)): **compiled (`cargo_test_raw.log:370`), but never imported anywhere** (`daemon/src/ipc.rs` uses `tokio::net::windows::named_pipe` and `tokio::net::UnixListener` directly).
  4. **Duplicate HTTP Stacks:** `Cargo.lock` compiles **both** `reqwest v0.12.28` (via `opendal v0.59.5`) and `reqwest v0.13.5` (`Cargo.toml:73`, used by `zerovault-storage` OAuth), plus **both** `aws-lc-sys v0.47.0` and `ring v0.17.14` (`cargo_test_raw.log:195-196`).

---

### 3.2 `zerovault-types` (`crates/zerovault-types`)
Shared zero-IO contract crate defining domain models, binary wire headers, routing policies, IPC protocol frames, errors, traits, and deterministic unit-test mocks.

1. **Domain Primitives & Constants ([src/lib.rs](../zerovault/crates/zerovault-types/src/lib.rs#L22-L252)):**
   - `VaultId(pub Uuid)` (`L31`), `InodeId = u64` with `ROOT_INODE = 1` (`L57-L59`).
   - `RedactedSecret(String)` (`L66-L102`) & `DekBytes([u8; 32])` (`L108-L143`): derive `Zeroize` + `ZeroizeOnDrop`; manual `fmt::Debug` prints `"[REDACTED]"` without length leakage.
   - `HydrationState` (`L147-L169`): `OnlineOnly`, `PartiallyHydrated`, `Hydrated`, `Pinned`, `DirtyLocal` (`xattr_value()` returns `"online_only"`, `"partial"`, `"hydrated"`, `"pinned"`, `"dirty"`).
   - `EntryKind` (`File`, `Directory`, `Symlink`), `EntryMetadata` (`L183-L202`: `inode`, `parent_inode`, `name`, `kind`, `size`, `mode`, `created_at`, `modified_at`, `hydration`, `pinned`, `file_id`, `wrapped_dek`, `version`), `ChunkMeta` (`L206-L216`: `chunk_index`, `blob_id: Uuid`, `plaintext_len`, `wire_len`, `backends: Vec<String>`, `sha256_ciphertext: Option<[u8; 32]>`, `locally_hydrated: bool`).
   - `RoutingPolicy` (`L226-L252`):
     - `Targeted { prefix_routes: Vec<PrefixRoute>, default_backend: String }`
     - `Mirrored { backends: Vec<String>, min_ack: usize }`
     - `QuotaPooled { pool_backends: Vec<String> }`

2. **Binary Wire Formats & Key Validators ([src/wire.rs](../zerovault/crates/zerovault-types/src/wire.rs#L1-L794)):**
   - **Chunk Geometry (`L12-L35`):** `PLAINTEXT_CHUNK_SIZE = 4 * 1024 * 1024` (`4,194,304` B), `CHUNK_HEADER_LEN = 32`, `GCM_TAG_LEN = 16`, `GCM_NONCE_LEN = 12`, `MAX_WIRE_CHUNK_SIZE = 4,194,352` B.
   - **`KdfParams` (`L45-L96`):** Enforces floor `MIN_ARGON2_MEMORY_KIB = 65_536` (64 MiB), `MIN_ARGON2_TIME_COST = 3`, `MIN_ARGON2_PARALLELISM = 4` (`validate()`, `L77-L95`).
   - **`VaultHeader` (`ZVH1`, fixed `112` bytes, `L149-L285`):**
     `magic = b"ZVH1" [4] || version = 1 [2 LE] || kdf_alg = 1 [1] || flags = 0 [1] || vault_id [16] || argon2_salt [32] || m_cost_kib [4 LE] || t_cost [4 LE] || p_cost [4 LE] || verifier_nonce [12] || verifier_tag [16] || reserved_zero [16]`. Rejects non-zero reserved bytes or KDF downgrade on `decode()`.
   - **`WrappedDek` (`L289-L315`):** `nonce: [u8; 12]` + `ciphertext_and_tag: Vec<u8>` (`48` bytes = `32B` DEK + `16B` GCM tag). `aad_for_file(file_id)` (`L297-L305`) constructs `25` bytes: `b"ZV-DEK-V1" [9B] || file_id [16B]`.
   - **`ChunkAad` (`L319-L330`):** Canonical `25`-byte chunk AAD:
     `file_id [16B] || chunk_index.to_le_bytes() [8B] || u8::from(is_final_chunk) [1B]`.
   - **`ChunkHeader` (`ZVC1`, fixed `32` bytes, `L336-L447`):**
     `magic = b"ZVC1" [4] || version = 1 [1] || flags [1: bit 0 = FLAG_FINAL_CHUNK, bits 1..7 must be 0] || reserved_zero [2] || chunk_index [8 LE] || plaintext_len [4 LE] || nonce [12]`. Non-final chunks MUST have `plaintext_len == 4_194_304`; final chunks MUST have `plaintext_len <= 4_194_304` (`validate_invariants()`, `L370-L398`).
   - **`ManifestWireHeader` (`ZVM1`, fixed `44` bytes, `L454-L523`):**
     `magic = b"ZVM1" [4] || version = 1 [1] || reserved_zero [3] || vault_id [16] || revision [8 LE, must be >= 1] || nonce [12]`. First `32` bytes (`0..32`) serve as the AEAD AAD (`aad_slice`, `L514-L516`) over the `postcard`-serialized `VaultManifest` (`L527-L567`).
   - **Zero-Knowledge Remote Key Whitelist (`validate_remote_object_key`, `L607-L686`):** Rejects any remote key unless it is literally `"vault/header.zvh"`, `"manifests/head.zvm"`, `"manifests/<32-lower-hex-uuid>.zvm"`, or `"blobs/<2-hex>/<2-hex>/<canonical-lowercase-uuid>.zv"` where the 2-char shards match the UUID prefix (`L645-L654`).
   - **`ChunkSpan::slices_for_range` (`L702-L735`):** Pure O(1) arithmetic mapping arbitrary `(offset, len)` byte reads across `4 MiB` chunk boundaries.

3. **IPC Protocol & Error Taxonomy ([src/ipc.rs](../zerovault/crates/zerovault-types/src/ipc.rs#L1-L398), [src/error.rs](../zerovault/crates/zerovault-types/src/error.rs#L1-L138)):**
   - `MAX_IPC_FRAME_BYTES = 1_048_576` (`1 MiB`, `ipc.rs:14`). Note: `ipc.rs:8` doc-comment claims *"framed with a 4-byte little-endian length prefix (`Postcard` or `JSON`)"*, whereas `daemon/src/ipc.rs:5-6, 179, 200` actually uses **4-byte BIG-ENDIAN length prefix + `serde_json` UTF-8**!
   - `DaemonRequest` (`ipc.rs:18-137`, 22 variants): `Ping`, `InitVault`, `UnlockVault`, `LockVault`, `AddRemote`, `RemoveRemote`, `ListRemotes`, `SetRoutingPolicy`, `Mount`, `Unmount`, `Pin`, `Unpin`, `Dehydrate`, `SyncNow`, `Status`, `ListDirectory`, `CreateDirectory`, `ImportLocalFile`, `ExportFileToLocal`, `DeleteEntry`, `RenameEntry`, `ListConflicts`, `BenchCrypto`, `Shutdown`. Custom `Debug` redacts `InitVault.passphrase`, `UnlockVault.passphrase`, and `AddRemote.secret` (`ipc.rs:94-137`).
   - `ZeroVaultError` (`error.rs:9-96`, 20 variants): Explicit `HardwareAccelerationUnavailable`, `KdfPolicyViolation`, `InvalidPassphrase`, `VaultLocked`, `CryptoTamperDetected`, `InvalidWireFormat`, `PinnedDehydrationDenied`, `QuotaExhausted`, `StorageConflict`, `EntryNotFound`, `AlreadyExists`, `DirectoryNotEmpty`, `NotADirectory`, `IsADirectory`, `InvalidPath`, `BackendError`, `OAuthError`, `KeyringError`, `VfsError`, `DatabaseError`, `IpcError`, `Internal`.

---

### 3.3 `zerovault-crypto` (`crates/zerovault-crypto`)
1. **Actual AEAD Implementation ([src/engine.rs](../zerovault/crates/zerovault-crypto/src/engine.rs#L13-L20,L245-L292)):**
   - Uses **`aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey}`** (`aws-lc-rs v1.19.0` with `prebuilt-nasm`).
   - `seal_detached` (`engine.rs:245-268`) calls `LessSafeKey::seal_out_of_place_scatter(nonce, Aad::from(aad), plaintext, out_ciphertext, &mut tag_buf)`.
   - `open_detached` (`engine.rs:270-292`) calls `LessSafeKey::open_separate_gather(nonce, Aad::from(aad), in_ciphertext, tag, out_plaintext)` and **immediately calls `out_plaintext.zeroize()` on error** (`L289`, plus `out.clear()` at `L662`) before returning `ZeroVaultError::CryptoTamperDetected`.
2. **Hardware Acceleration CPUID Gate ([src/hw.rs](../zerovault/crates/zerovault-crypto/src/hw.rs#L13-L135)):**
   - On `x86`/`x86_64` (`hw.rs:46-75`): uses `cpufeatures::new!(cpuid_aes_pclmul, "aes", "pclmulqdq")`, `cpufeatures::new!(cpuid_avx2, "avx2")`, and `std::arch::is_x86_feature_detected!("vaes")`. Requires `has_aes && has_pclmul` (`accelerated = true`); reports `"AES-NI + VAES + VPCLMULQDQ/PCLMULQDQ (AVX2)"` or `"AES-NI + PCLMULQDQ"`.
   - On `aarch64` (`hw.rs:78-97`): `cpufeatures::new!(cpuid_arm_crypto, "aes", "pmull")`.
   - Any other architecture returns `accelerated = false` (`hw.rs:100-112`), causing `AwsLcCryptoEngine::new()` (`engine.rs:163-166`) and every crypto operation (`ensure_hardware_ready()`, `engine.rs:180-188`) to fail closed with `ZeroVaultError::HardwareAccelerationUnavailable`.
3. **KDF & Envelope Key Hierarchy ([src/engine.rs](../zerovault/crates/zerovault-crypto/src/engine.rs#L29-L125,L216-L243)):**
   - `derive_master_seed` (`engine.rs:216-243`): validates `KdfParams` floor (`m >= 65536 KiB`, `t >= 3`, `p >= 4`), clones passphrase into `Zeroizing<Vec<u8>>`, runs `argon2::Argon2::new(Algorithm::Argon2id, Version::V0x13, params).hash_password_into` inside `tokio::task::spawn_blocking`, returning `MasterSeed([u8; 32])` (`Zeroize` + `ZeroizeOnDrop`).
   - `VaultKeyring::derive_from_seed(vault_id, master_seed, argon2_salt)` (`engine.rs:94-119`): runs `Hkdf::<Sha256>::new(Some(&argon2_salt), &master_seed.0)` and expands four domain-separated 256-bit keys:
     - `"zerovault.v1.kek"` -> `master_kek` (wraps per-file 256-bit DEKs with AAD `b"ZV-DEK-V1" || file_id`)
     - `"zerovault.v1.manifest"` -> `manifest_key` (seals `postcard`-encoded `VaultManifest` inside `ZVM1` with 32-byte header AAD)
     - `"zerovault.v1.token-wrap"` -> `token_wrap_key` (seals OAuth2 JSON bundles / remote credentials with AAD `b"ZV-TOKEN-V1:" || vault_id`)
     - `"zerovault.v1.verifier"` -> `header_verifier_key` (seals 0-byte payload with 84-byte `ZVH1` prefix AAD to authenticate passphrase + KDF params on unlock; mismatch maps to `ZeroVaultError::InvalidPassphrase`, `engine.rs:368-373`).
4. **Chunk Encryption & Reuse-Buffer Discipline ([src/engine.rs](../zerovault/crates/zerovault-crypto/src/engine.rs#L571-L668)):**
   - `encrypt_chunk_into`: enforces `1 <= plaintext.len() <= 4 MiB` (except 0-byte empty final chunk index 0), generates fresh 12-byte CSPRNG nonce (`fill_random`), builds 32-byte `ZVC1` header + 25-byte `ChunkAad` (`file_id || chunk_index || is_final_chunk`), resizes caller's `out: &mut Vec<u8>` in place without shrinking capacity (`CHUNK_HEADER_LEN + plaintext.len() + GCM_TAG_LEN`), and seals scatter-mode.
   - `decrypt_chunk_into`: parses `ZVC1` header, verifies `is_final_chunk` matches caller expectation (`L634-L639`) and wire length equals `32 + header.plaintext_len + 16` (`L641-L648`), opens with `ChunkAad`, and zeroes `out` on tag failure.
5. **OS Keyring (`keyring_store.rs`) & Session Blob Defect (`engine.rs:406-509`):**
   - `OsKeyringSecretStore` ([src/keyring_store.rs](../zerovault/crates/zerovault-crypto/src/keyring_store.rs#L18-L94)) wraps `keyring::Entry::new(service, account)` (`set_secret`, `get_secret`, `delete_credential`) serialized under `parking_lot::Mutex<()>` inside `spawn_blocking`.
   - **Defect in `ZVS1` Session Persistence (`engine.rs:406-509`):** `persist_session` constructs a `129`-byte `ZVS1` payload where `blob[53..85]` is the **raw, unencrypted `master_seed.0`** (`blob.extend_from_slice(&state.master_seed.0)`, `L429`), followed by a 12B nonce + 16B GCM tag over empty plaintext (`L432-L438`). While stored inside OS Credential Manager/Secret Service, the `master_seed` itself is unencrypted inside the blob—and **neither `zerovault-daemon` nor `zerovault-ui` ever calls `persist_session` or `restore_session`** (only unit tests do!).
6. **Empirical Verification of `zv://` Capability URI & `keybox.zv` (`Ed25519` + `X25519` + `ML-KEM-768`):**
   - Full-repo regex scan for `(zv://|keybox\.zv|ML-KEM|ml_kem|mlkem|Ed25519|ed25519|X25519|x25519|aws_lc_rs::kem)`: **`0` matches in production code, `0` matches in tests**.
   - **Verdict:** Completely unimplemented in `zerovault`. `zerovault` is purely passphrase -> `Argon2id` -> `HKDF-SHA256` symmetric single-custodian encryption.

---

### 3.4 `zerovault-storage` (`crates/zerovault-storage`)
1. **Apache OpenDAL `0.59` Multi-Cloud Backends ([src/backend.rs](../zerovault/crates/zerovault-storage/src/backend.rs#L729-L951)):**
   - Supports 7 `BackendKind`s via `opendal::services`: `GoogleDrive` (`Gdrive`), `OneDrive` (`Onedrive`), `Dropbox` (`Dropbox`), `S3` (`S3`), `WebDav` (`Webdav`), `LocalFs` (`Fs`), and `Memory` (`Memory`).
   - Every `Operator` is wrapped in `apply_resilience_layers` (`backend.rs:924-951`):
     - `ConcurrentLimitLayer::new(16)` (`DEFAULT_BACKEND_CONCURRENCY = 16`)
     - `TimeoutLayer::new().with_timeout(30s).with_io_timeout(60s)`
     - `RetryLayer::new().with_jitter().with_min_delay(100ms).with_max_delay(2s).with_max_times(3)`.
   - All remote paths pass `validate_remote_object_key(key)` *before* touching OpenDAL (`backend.rs:429, 440, 502, 520, 535`).
2. **Chunk Streaming vs. Whole-File Buffering ([src/backend.rs](../zerovault/crates/zerovault-storage/src/backend.rs#L437-L497,L684-L695)):**
   - `get_object` never calls unbounded `operator.read(key)`. Instead, it obtains `reader = self.operator.reader(key).await` -> `reader.into_stream(..)` and reads chunks incrementally into a `BytesMut` capped strictly by `max_wire_bytes_for_object_key(key)`:
     - `vault/header.zvh`: max **`112` bytes**
     - `blobs/<aa>/<bb>/<uuid>.zv`: max **`4,194,352` bytes** (`4 MiB + 48 B`)
     - `manifests/*.zvm`: max **`67,108,864` bytes** (`64 MiB`).
   - Because `SyncEngine` splits files into `4 MiB` `.zv` chunk objects before calling `StorageRouterTrait::put_blob`, **whole multi-chunk files are never buffered in RAM inside `zerovault-storage`**.
   - **Caveat on LocalFS/Cloud Fallback CAS (`backend.rs:546-594`):** When OpenDAL returns `Unsupported` for `put_with().if_match(...)`/`if_none_match("*")` (which happens on `Fs` and providers lacking conditional HTTP headers!), `put_object_cas` falls back to serialized `cas_fallback_lock: tokio::sync::Mutex<()>` + `stat()` + synthetic ETag (`"{content_length:x}-{mtime_ns:x}"`, `backend.rs:703-717`). This protects single-process concurrency, **not** multi-device race conditions on backends without native HTTP `If-Match` (e.g., shared `LocalFs` folders, Google Drive/Dropbox if OpenDAL doesn't support `if_match` on them!).
3. **OAuth2 PKCE Loopback & Token Persistence ([src/oauth.rs](../zerovault/crates/zerovault-storage/src/oauth.rs#L307-L928)):**
   - Uses `oauth2 v5.0` Authorization Code Grant + mandatory `PkceCodeChallenge::new_random_sha256()`, binding an ephemeral `127.0.0.1:0` (or caller-specified loopback port) `TcpListener`.
   - Uses `reqwest::Client::builder().redirect(Policy::none())` (`oauth.rs:285-296`) to block SSRF open-redirect attacks, and `subtle::ConstantTimeEq` (`constant_time_csrf_eq`, `oauth.rs:299-305`) for CSRF state verification.
   - Persists `OAuthTokenBundle` JSON encrypted via `CryptoEngine::wrap_token_payload` (`TokenWrapKey` + `vault_id` AAD) into `SecretStore` (`persist_wrapped_tokens`, `oauth.rs:584-605`), and preserves existing `refresh_token` when providers omit a new one during refresh (`oauth.rs:550-564`).
   - **Residual Loopback DoS Weakness (`oauth.rs:642-818`):** `accept_callback_code` loops over `/favicon.ico` (`404`), **but** any single local request to `/callback` with a wrong `state` or missing `code` immediately returns `Err(OAuthError)` and aborts the listener (`L741-L760`), allowing any unprivileged local webpage/process probing `127.0.0.1:<port>/callback?state=x` to abort an in-flight login. Also `read_http_request` (`L768-L818`) caps buffer size at `16 KiB` (`MAX_CALLBACK_REQUEST_BYTES`) but lacks a per-socket `tokio::time::timeout`, so a local process opening a raw TCP connection and sending `1` byte stalls the entire OAuth login until `callback_timeout` (`180s`) expires.
4. **Multi-Cloud Router Policies ([src/router.rs](../zerovault/crates/zerovault-storage/src/router.rs#L240-L850)):**
   - **`Targeted` (`router.rs:631-670`):** Normalizes `virtual_hint_path` locally (never transmitted over the wire) and selects the `PrefixRoute` with the longest segment-aware prefix match, falling back to `default_backend`.
   - **`Mirrored` (`router.rs:277-314, 344-421, 474-592, 828-850`):**
     - **Writes:** Dispatches `put_object` concurrently across all mirror backends via `join_all`; succeeds if `acks.len() >= min_ack` (`L290-L310`), rolling back partial writes if quorum fails (`L297-L303`).
     - **Reads (Fastest-Read RAID-1):** Splits candidates into healthy (`backend.is_healthy()`) and unhealthy tiers; races healthy mirrors concurrently via `futures::future::select_ok` (`race_get_backends`, `L828-L850`), falling back to racing unhealthy mirrors only if all healthy mirrors fail I/O (`L395-L420`).
     - **Mirrored Integrity Defect:** `race_get_backends` operates at the raw byte transport layer *before* `CryptoEngine::decrypt_chunk_into`! If Mirror A is faster than Mirror B, and Mirror A returns bit-rotted or tampered bytes (`HTTP 200`), `select_ok` immediately returns Mirror A's corrupt bytes and cancels Mirror B; `SyncEngine` then fails closed with `CryptoTamperDetected` **without retrying healthy Mirror B**!
     - **Mirrored Manifest CAS (`L494-L591`):** Uses composite JSON ETag `"zv-mirror-cas:{\"a\":\"etag1\",\"b\":\"etag2\"}"` (`encode_mirror_cas_token`, `L925-L953`) so multi-revision CAS updates (`rev 1 -> 2 -> 3`) work across mirrors.
   - **`QuotaPooled` (`router.rs:315-340, 745-788`, `backend.rs:373-414`):**
     - Uses lock-free `AtomicU64::compare_exchange_weak` (`try_reserve_quota`) against `quota_limit_bytes.saturating_sub(min_free_reserve_bytes)` *before* network upload, rolling back via `release_quota` if `put_object` fails (`router.rs:328-331`). Supports `OrderedSpillover` (default: fills account 1, spills to account 2) and `MaxAvailable` (picks account with largest `available_bytes()`).

---

### 3.5 `zerovault-vfs` (`crates/zerovault-vfs`)
1. **Cross-Platform Surface ([src/lib.rs](../zerovault/crates/zerovault-vfs/src/lib.rs#L1-L150)):**
   - Exposes `MockDrive` unconditionally, `WindowsCfDrive` on `#[cfg(target_os = "windows")]`, and `LinuxFuseDrive` on `#[cfg(target_os = "linux")]`.
2. **Windows `CfApi` Implementation (`src/windows/{drive.rs, filter.rs, placeholder.rs}`):**
   - Built on `cloud-filter = "0.0.7"` + `windows = "0.62"`.
   - **SyncRoot Registration (`drive.rs:195-232`):** Registers `SyncRootIdBuilder::new("cloud.entropy.Zerovault")` (`HydrationType::Progressive`, `HydrationPolicy::StreamingAllowed | AutoDehydrationAllowed`, `PopulationType::Full`) and connects via `Session::new().block_implicit_hydration().connect_async(...)` (`drive.rs:261-265`).
   - **Placeholder Identity (`placeholder.rs:42-119, 179-247`):** Encodes 28-byte `FileIdentity` (`b"ZVID" [4B] || inode [8B LE] || file_id [16B]`) into every NTFS reparse placeholder (`PlaceholderCreateInfo::blob`), verified against `VfsBackend::stat` in `resolve_inode` (`filter.rs:212-265`).
   - **Progressive Range Hydration (`filter.rs:94-205, 314-366`):** `align_cfapi_transfer_range` aligns requested byte offsets outward to `4096`-byte (`CFAPI_ALIGNMENT`) sector boundaries (clamped to EOF for tail blocks). `stream_chunked_hydration` loops in `<= 4 MiB` (`PLAINTEXT_CHUNK_SIZE`) slices, checking `ActiveFetchGuard` cancellation (`AtomicBool` in `DashMap<u64, Arc<AtomicBool>>`, triggered by `cancel_fetch_data`) before and after every `VfsBackend::read_range` call, and writes directly into kernel `ticket::FetchData::write_at`—**zero whole-file buffering**.
   - **Local Write & Attribute Reconciliation (`filter.rs:607-758`):** `state_changed` pushes modified paths into an unbounded channel drained by a single background worker (`run_state_watcher_worker`, `filter.rs:582-605`). Local file writes stream from NTFS in `4 MiB` slices via `sync_local_file_contents_streaming` (`filter.rs:737-765`) -> `backend.write_range` + `backend.truncate` + `backend.flush(inode)`.
3. **Linux FUSE3 Implementation (`src/linux/{drive.rs, fs.rs}`):**
   - Built on `fuser = "0.18"` (`default-features = false` — pure Rust `/dev/fuse` + `fusermount3`, no C `libfuse3.so` runtime linkage required unless distro `fusermount3` setuid helper is missing).
   - **Mount Options (`drive.rs:146-163`):** `MountOption::FSName("zerovault")`, `Subtype("zerovault")`, `NoAtime`, `DefaultPermissions`, `AutoUnmount`, and `SessionACL::Owner` (strictly blocking root/other UIDs unless kernel allows owner only — zero `allow_other`).
   - **Async Bridge (`fs.rs:34-77`):** `RuntimeBridge::block_on` checks `tokio::runtime::Handle::try_current()`: because `fuser::spawn_mount2` runs its own dedicated OS thread outside Tokio (`Err(_)`), it calls `self.handle.block_on(fut)` directly without nesting. If invoked from a multi-thread Tokio worker (`RuntimeFlavor::MultiThread`), it uses `tokio::task::block_in_place`; on `CurrentThread` it spawns a scoped OS thread.
   - **POSIX Operations & Streaming (`fs.rs:479-1114`):** Implements `init`, `lookup` (`TTL = 1s`), `getattr`, `setattr` (`chmod`, `truncate`, `utimens`), `open`, `read` (calls `backend.read_range(ino, offset, size)` directly), `write` (per-handle `DirtyWriteBuffer` coalescing contiguous writes up to `MAX_WRITE_BUFFER_BYTES = 4 MiB` before flushing to `backend.write_range`, `fs.rs:101-190`), `flush`, `fsync`, `release` (captures final flush errors for POSIX `close(2)` semantics via `take_handle_error`), `opendir`, `readdir` (snapshot cached per `fh`), `releasedir`, `create`, `mkdir`, `unlink`, `rmdir`, `rename` (`RENAME_NOREPLACE` supported; `RENAME_EXCHANGE` returns `EINVAL`), `statfs` (`bsize = 4 MiB`, `frsize = 4 KiB`), and `getxattr`/`listxattr`/`setxattr`/`removexattr` (`user.zerovault.state`, `user.zerovault.pin`, `user.zerovault.file_id`).
4. **Three Newly Discovered VFS Pin/Unpin Bugs:**
   - **Bug VFS-1 (Windows Explorer Unpin Fails on Pinned Files — [filter.rs](../zerovault/crates/zerovault-vfs/src/windows/filter.rs#L694-L698) & [L727-L731](../zerovault/crates/zerovault-vfs/src/windows/filter.rs#L727-L731)):** When a user clicks *"Free up space"* (`FILE_ATTRIBUTE_UNPINNED`, `wants_unpin == true`) on a file that was previously marked *"Always keep on this device"* (`rec.pinned == true`), `process_state_change_path` calls `backend.dehydrate(rec.inode).await?` **without calling `backend.unpin(rec.inode).await?` first**! Because `SyncEngine::dehydrate` (`core/src/engine.rs:1557-1561`) rejects `meta.pinned == true` with `PinnedDehydrationDenied`, `process_state_change_path` errors out, `run_state_watcher_worker` logs a warning (`filter.rs:593-599`), and the file can NEVER be unpinned/dehydrated from Windows Explorer! (Unit test `windows_vfs_tests.rs:715-732` missed this because it set `FILE_ATTRIBUTE_UNPINNED` on a file that had never been pinned!)
   - **Bug VFS-2 (Linux `setxattr(user.zerovault.pin, "0")` Fails with `EBUSY` on Pinned Files — [fs.rs](../zerovault/crates/zerovault-vfs/src/linux/fs.rs#L1042-L1046)):** Identical logic bug: `b"0" | b"false" | b"unpin"` calls `self.backend.dehydrate(ino)` directly without `self.backend.unpin(ino)` first! Setting `user.zerovault.pin="1"` followed by `user.zerovault.pin="0"` deterministically returns `EBUSY` (`PinnedDehydrationDenied`).
   - **Bug VFS-3 (`VirtualDrive` Trait Lacks `unpin_path` — [traits.rs](../zerovault/crates/zerovault-types/src/traits.rs#L730-L754), [service.rs](../zerovault/crates/zerovault-daemon/src/service.rs#L1421-L1437)):** `DaemonRuntime::unpin_path` only calls `sync.unpin(meta.inode)` in SQLite and never calls `Placeholder::mark_pin(PinState::Unpinned)` on the mounted `WindowsCfDrive`, leaving NTFS `FILE_ATTRIBUTE_PINNED` out of sync with SQLite!

---

### 3.6 `zerovault-core` (`crates/zerovault-core`)
1. **SQLite WAL Metadata Store ([src/db.rs](../zerovault/crates/zerovault-core/src/db.rs#L17-L135)):**
   - Uses `rusqlite v0.32` (`features = ["bundled"]`), single `Arc<parking_lot::Mutex<Connection>>` dispatched via `tokio::task::spawn_blocking`.
   - Pragmas (`db.rs:108-115`): `PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA foreign_keys = ON; PRAGMA temp_store = MEMORY; PRAGMA busy_timeout = 5000;`.
   - **Schema (`SCHEMA_SQL`, `db.rs:17-82`, 6 tables):**
     - `sequences(name PRIMARY KEY, next_val INTEGER)` (`next_inode` seeded to `2`)
     - `inodes(inode PK, parent_inode, name, kind, size, mode, created_at_ns, modified_at_ns, hydration, pinned, file_id, wrapped_dek BLOB, version, UNIQUE(parent_inode, name))` (seeded with `ROOT_INODE = 1`)
     - `chunks(inode FK ON DELETE CASCADE, chunk_index, blob_id, plaintext_len, wire_len, backends_json, sha256_ciphertext BLOB, locally_hydrated, PRIMARY KEY(inode, chunk_index))`
     - `dirty_ops(op_id PK AUTOINCREMENT, inode, op_kind, target_path_hint, payload_json, created_at_ns, attempts, last_error)`
     - `manifest_cursor(singleton_id CHECK(=1), revision INTEGER, etag TEXT)`
     - `conflicts(conflict_id PK, original_path, conflict_path, winning_device, losing_device, detected_at_ns)`.
2. **Epoch / Monotonic Rollback Enforcement ([src/engine.rs](../zerovault/crates/zerovault-core/src/engine.rs#L332-L355,L854-L866)):**
   - On `sync_once()`, `SyncEngine` reads `(local_rev, local_etag)` from `manifest_cursor`, fetches remote `manifests/head.zvm`, opens it via `CryptoEngine::open_manifest` (verifying `ZVM1` AAD binding `vault_id` + `revision`), checks `manifest.vault_id == current_vault_id` (`L335-L340`), and enforces:
     ```rust
     if local_rev > 0 && manifest.revision < local_rev {
         return Err(ZeroVaultError::CryptoTamperDetected(format!(
             "remote manifest rollback detected: remote revision {} < local cursor revision {}",
             manifest.revision, local_rev
         )));
     }
     ```
   - **Rollback & Fork Gaps Found:**
     1. **New-Device Bootstrap Rollback (`local_rev == 0`):** Because `VaultHeader` (`ZVH1`) is static and stores no monotonic epoch, a brand-new device (`local_rev == 0`) has no out-of-band floor and will accept an old valid `rev 1` manifest replayed by a compromised cloud server in place of `rev 50`.
     2. **`parent_manifest_id` Is Volatile & Unchecked (`engine.rs:858`):** `VaultManifest.parent_manifest_id` is populated from `self.last_manifest_id: Mutex<Option<Uuid>>`—which is **never persisted in SQLite** (resets to `None` on every daemon restart!) and **never verified** during `sync_once()`.
3. **Bounded Buffer Pool & Local Cache ([src/pool.rs](../zerovault/crates/zerovault-core/src/pool.rs#L58-L227), [src/cache.rs](../zerovault/crates/zerovault-core/src/cache.rs#L73-L388)):**
   - `BoundedBufferPool` uses `tokio::sync::Semaphore` (`min 2` permits even if `max_concurrent_transfers == 1` so `acquire_pair` via `acquire_many_owned(2)` never self-deadlocks, `pool.rs:64, 108-127`). Default `8` slots * `~4 MiB` = `~32 MiB` pool cap.
   - **Buffer Zeroization Gap (`pool.rs:208-226`):** `PooledBuffer::drop` calls `buf.as_mut().zeroize(); buf.clear();`—if a caller called `buf.truncate(0)` or `buf.clear()` before dropping, `Vec::as_mut()` has length `0`, so **`zeroize()` zeroes `0` bytes while up to `4 MiB` of plaintext remains in `buf`'s spare capacity**!
   - `ChunkCache` (`cache.rs:73-210`): byte-bounded `lru::LruCache<(InodeId, u64), Arc<Zeroizing<Vec<u8>>>>` (default `32 MiB`), purged on `SyncEngine::lock_and_purge_cache` (`engine.rs:202-205`) and checked fail-closed via `ensure_vault_unlocked()` at the top of `read_range`/`write_range` (`engine.rs:1203, 1246`).
   - **Plaintext Disk Staging Vulnerability (`cache.rs:212-304`):** `write_dirty_slice` writes **unencrypted plaintext** to `staging_dir/dirty/<inode>/<chunk_index>.part`! On Unix it sets `0o700` dir / `0o600` file modes (`cache.rs:367-388`), on Windows it uses default inherited directory ACLs, and **`LockVault` does NOT wipe unflushed `.part` files** (`remove_dirty_chunk` uses plain `tokio::fs::remove_file` only after cloud upload succeeds!).
4. **Conflict Resolution & Crash Recovery ([src/conflict.rs](../zerovault/crates/zerovault-core/src/conflict.rs#L54-L166), [src/engine.rs](../zerovault/crates/zerovault-core/src/engine.rs#L300-L600)):**
   - Non-destructive sibling fork: when `sync_once()` pulls a remote revision where an inode's chunk blob IDs or size changed concurrently while `local_inode.hydration == DirtyLocal` (or has pending `dirty_ops`), the remote version wins the canonical path and the local dirty inode is forked under a fresh `InodeId`, fresh `Uuid`, and fresh `WrappedDek` named `<stem> (conflict-<device_id>-<YYYYMMDD-HHMMSS>).<ext>`, uploaded in the same sync cycle, and logged in SQLite `conflicts`.
   - Crash/offline recovery: `write_range`/`unlink`/`rename`/`mkdir` append `DirtyOp` rows to SQLite WAL *before* upload; if cloud upload fails during `flush()`, `DirtyLocal` state + `.part` files + `dirty_ops` persist across restarts and retry on next `sync_once()` (`MAX_CAS_RETRIES = 5`). Note: there is **zero remote blob garbage collection** (`delete_blob` is never called by `SyncEngine` when overwriting or deleting files!).

---

### 3.7 `zerovault-daemon` (`crates/zerovault-daemon`)
1. **IPC Framing, Permissions & DoS Bounds ([src/ipc.rs](../zerovault/crates/zerovault-daemon/src/ipc.rs#L29-L649)):**
   - **Framing (`ipc.rs:163-214`):** 4-byte **big-endian** `u32` length header + UTF-8 `serde_json` payload. `validate_frame_len` (`L165-L176`) rejects `len == 0` or `len > 1_048_576` (`1 MiB`) **before** allocating `vec![0u8; len]`.
   - **DoS Guards (`ipc.rs:34-39, 344-420`):** `MAX_CONCURRENT_IPC_CONNECTIONS = 64` (`tokio::sync::Semaphore`) + `IPC_FRAME_IO_TIMEOUT = 30s` (`tokio::time::timeout` around `read_frame` and `write_frame`).
   - **Transport Security:**
     - **Windows Named Pipe (`ipc.rs:505-649`):** Default `\\.\pipe\zerovaultd`. Constructs a custom Win32 `SECURITY_DESCRIPTOR` via `ConvertStringSecurityDescriptorToSecurityDescriptorW` with SDDL **`D:P(A;;GA;;;SY)(A;;GA;;;OW)`** (`PROTECTED_DACL`: `LocalSystem` + `Creator Owner` ONLY, blocking `Everyone` and other local users!), passes `first_pipe_instance(true)` on the initial listener (`FILE_FLAG_FIRST_PIPE_INSTANCE` anti-squatting), `reject_remote_clients(true)` (blocks SMB remote pipe access), and `PipeMode::Byte`.
     - **Unix Domain Socket (`ipc.rs:285-315`):** Default `$XDG_RUNTIME_DIR/zerovault/zerovaultd.sock` (fallback `/tmp/zerovault-<uid>/zerovaultd.sock`). Sets parent directory `0o700` before `UnixListener::bind`, then socket `0o600` (minor `bind` -> `set_permissions` umask window; also unconditionally calls `std::fs::remove_file(&path)` if `path.exists()` without checking `symlink_metadata().file_type().is_socket()` or checking whether a live daemon already owns the socket!).
     - **TCP Fallback (`ipc.rs:124-137, 317-327`):** Rejects any `!addr.ip().is_loopback()` fail-closed (`ZeroVaultError::IpcError`). Note: TCP loopback (`--ipc tcp://127.0.0.1:<port>`) has no bearer token if explicitly enabled by user/tests.
2. **Critical `DaemonRuntime` Defects ([src/service.rs](../zerovault/crates/zerovault-daemon/src/service.rs), [src/main.rs](../zerovault/crates/zerovault-daemon/src/main.rs)):**
   - **Defect DAEMON-1 (Multi-Device Cloud Header Never Published or Fetched):**
     - `DaemonRuntime::init_vault` (`service.rs:773-825`) writes `header.encode()` only to local `state_dir/vault.zvh` (`write_private_file(&self.vault_header_path(), ...)`, `L800`) and **never calls `SyncEngine::publish_vault_header(&header)`**—nor does `add_remote` (`service.rs:924-1037`) or `sync_now` (`service.rs:1464-1474`) ever upload `vault/header.zvh`!
     - `DaemonRuntime::unlock_vault` (`service.rs:827-888`) reads `std::fs::read(&header_path)` locally (`L835-L841`) and fails immediately with `"Vault is not initialized"` if local `vault.zvh` is missing—**never calling `SyncEngine::fetch_vault_header`** from configured cloud remotes!
     - *Impact:* Multi-device sharing worked in `e2e_concurrent_device_conflict_preservation` ONLY because the test bypassed `DaemonRuntime` and called `dev_win.publish_vault_header(&header)` + `SyncEngine::fetch_vault_header(...)` directly (`tests/e2e/tests/e2e_multicloud_zero_knowledge.rs:706-714`)! Through the actual daemon, CLI, or UI, a second device cannot join a cloud vault!
   - **Defect DAEMON-2 (Zero Background Sync Loop):** `zerovaultd` (`daemon/src/main.rs:1-92`) only runs `IpcServer::serve_with_shutdown(..., shutdown_signal())`. No `tokio::time::interval` or remote poll loop exists anywhere in the workspace!
   - **Defect DAEMON-3 (`import_local_file` Follows Symlinks & Overwrites Silently):** `DaemonRuntime::import_local_file` (`service.rs:1619-1748`) checks `local_meta = tokio::fs::metadata(&src).await` (which follows symlinks, unlike `zerovault-ui`'s folder importer which checks `symlink_metadata`) and truncates/overwrites any existing file at `virtual_dest_path` (`L1677-L1681`) without prompt.

---

### 3.8 `zerovault-cli` (`crates/zerovault-cli`)
- `clap` v4 derive CLI (`zv`) in [src/cli.rs](../zerovault/crates/zerovault-cli/src/cli.rs#L1-L748) supporting: `init`, `unlock`, `lock`, `remote {add, list, remove}`, `mount`, `unmount`, `pin`, `dehydrate`, `sync`, `status`, `bench-crypto`, `shutdown`, plus global `--ipc` and `--json`.
- **CLI Gaps:**
  1. Missing subcommands for `unpin`, `remote set-policy`, `ls`/`mkdir`/`import`/`export`/`rm`/`mv`, `conflicts`, and OAuth2 login (all of those exist in `DaemonRequest` / `zerovault-ui`, not in `zv`).
  2. `resolve_passphrase` (`cli.rs:150-189`) reads `--passphrase-stdin` or `ZV_PASSPHRASE` into an ordinary `String` (never wrapped in `Zeroizing<String>`), leaving the passphrase unzeroized on the CLI heap until process exit. Also lacks interactive hidden TTY prompt (`rpassword`).

---

### 3.9 `zerovault-ui` (`crates/zerovault-ui`) — Tauri v2 Violation & UX Porting Blueprint
- **Architecture ([src/lib.rs](../zerovault/crates/zerovault-ui/src/lib.rs#L1-L2581), [src/dialogs.rs](../zerovault/crates/zerovault-ui/src/dialogs.rs#L1-L406), `dist/{index.html, app.js, styles.css}`):**
  - Tauri v2 (`2.12.6`) desktop app (`1180x780`, min `940x620`) exposing **22 `#[tauri::command]` handlers** (`ui_bootstrap`, `ui_init_vault`, `ui_unlock_vault`, `ui_lock_vault`, `ui_add_remote`, `ui_remove_remote`, `ui_set_routing_policy`, `ui_mount_drive`, `ui_unmount_drive`, `ui_sync_now`, `ui_list_dir`, `ui_create_dir`, `ui_import_paths`, `ui_open_entry_in_os`, `ui_read_text_entry`, `ui_save_text_entry`, `ui_free_up_space`, `ui_export_file`, `ui_delete_entry`, `ui_rename_entry`, `ui_pin_entry`, `ui_unpin_entry`, `ui_dehydrate_entry`, `ui_list_conflicts`, `ui_bench_crypto`, `ui_detect_installed_clouds`, `ui_start_oauth_remote`, `ui_browse_local_fs`, `ui_create_local_dir`, `ui_pick_local_files`, `ui_pick_local_folder`, `ui_pick_save_file`, `ui_quit` — 33 commands total registered at `lib.rs:2268-2303`!).
  - **CSP Weakness ([tauri.conf.json](../zerovault/crates/zerovault-ui/tauri.conf.json#L26)):** Retains `'unsafe-inline'` in `style-src` (`"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; ..."`).
  - **12 Undocumented `unsafe` Blocks ([src/dialogs.rs](../zerovault/crates/zerovault-ui/src/dialogs.rs#L126-L312)):** Spawns dedicated STA threads calling Win32 COM `CoInitializeEx`, `CoCreateInstance(&FileOpenDialog / &FileSaveDialog)`, `IShellItem::GetDisplayName`, `CoTaskMemFree`, `CoUninitialize`, and `ShellExecuteW` (Linux falls back to `zenity` / `kdialog` / `xdg-open`, then an HTML in-app directory browser).
- **High-Value UX Workflows Worth Porting to Our Zero-WebView Native UI (`cloudbridge` Merger Target):**
  1. **Zero-CLI Standalone Mode (`UiAppState::dispatch`, `lib.rs:344-455`):** Attempts IPC connection to external `zerovaultd` (`500ms` ping); if absent, transparently boots an in-process `DaemonRuntime` + `CoreSyncEngineFactory` + `OsKeyringSecretStore` so end-users never touch a terminal.
  2. **Secure Temp-Preview File Scrubber (`ui_open_entry_in_os` + `wipe_and_remove_file`, `lib.rs:1174-1267, 1791-1838`):** Exports decrypted files to a `0o700` `ui_session/<subdir>/` folder for default OS viewer preview and **overwrites every temp file with `64 KiB` zero blocks + `sync_all()` before unlinking** on Vault Lock and Quit! (Note: on Windows, `ui_session` currently lacks a restricted NTFS DACL—we should apply `D:P(A;;GA;;;SY)(A;;GA;;;OW)` when porting!).
  3. **1-Click Local Cloud Sync Folder Detector (`detect_installed_clouds_sync`, `lib.rs:1443-1595`):** Auto-discovers installed OneDrive (`OneDriveCommercial`/`OneDriveConsumer`/`OneDrive`), Google Drive (`G:\My Drive`..`Z:\My Drive` + `~/Google Drive`), Dropbox (`%LOCALAPPDATA%\Dropbox\info.json` + `~/.dropbox/info.json`), iCloud Drive, and Local Documents Backup for instant zero-OAuth onboarding.
  4. **Recursive Drag-and-Drop Folder Importer (`import_path_recursive`, `lib.rs:1012-1172`):** Uses `tokio::fs::symlink_metadata` to **skip symlinks**, recursively creates virtual directories (`MAX_RECURSIVE_IMPORT_DEPTH = 32`), imports files, and triggers a single batch `SyncNow` at the end.
  5. **Built-in Encrypted UTF-8 Note Editor (`ui_read_text_entry` / `ui_save_text_entry`, `lib.rs:1269-1399`):** Direct in-memory `<= 2 MiB` (`MAX_TEXT_NOTE_BYTES`) encrypted note creation/editing without touching host temp files unless `SyncEngine` stages dirty chunks.
  6. **1-Click "Free Up Space" Workflow (`ui_free_up_space`, `lib.rs:1401-1441`):** Explicitly chains `DaemonRequest::Unpin` (ignoring benign errors) **followed by** `DaemonRequest::Dehydrate`—working around the VFS unpin bug when invoked from inside the app!
  7. **Live Multi-Cloud Routing Studio (`build_routing_policy_from_input`, `lib.rs:640-733`):** Interactive switcher between **Pool Storage Together** (`QuotaPooled`), **Mirror Backup (RAID-1)** (`Mirrored` + `min_ack`), and **Folder Rules** (`Targeted` prefix table), plus live CPUID pills + 64 MiB AES-256-GCM speed bar chart and Conflict History viewer.

---

### 3.10 `packaging/` & `tests/e2e`
1. **OS Packaging Discrepancies (`packaging/`):**
   - **Arch Linux ([PKGBUILD](../zerovault/packaging/arch/PKGBUILD#L1-L59), [zerovaultd.service](../zerovault/packaging/arch/zerovaultd.service#L1-L23), [zerovault.desktop](../zerovault/packaging/arch/zerovault.desktop#L1-L12)):**
     - **CRITICAL PACKAGING BUG:** `PKGBUILD:27` runs `cargo build --release --locked --workspace` (without excluding `zerovault-ui` or adding `webkit2gtk-4.1` to `depends`! `depends` at `L11` only lists `fuse3`, `gcc-libs`, `glibc`, `libsecret` — Tauri v2 on Linux will fail to compile without `webkit2gtk-4.1` / `gtk3` / `libayatana-appindicator`!).
     - Even worse: `PKGBUILD:45` renames `zerovault-ui` to `/usr/bin/zerovault-tray` (`zerovault.desktop:5` also sets `Exec=zerovault-tray`), whereas Windows `install.ps1:28,67` and `zerovault.wxs:65,81` install `zerovault-ui.exe`, and `bundle-portable.ps1:49,77` renames it to `Zerovault.exe`!
     - `zerovaultd.service` (`systemd --user`) has strong sandboxing (`NoNewPrivileges=true`, `PrivateTmp=true`, `ProtectSystem=strict`, `ProtectHome=read-only`, `ReadWritePaths=%h %t`, `LockPersonality=true`, `MemoryDenyWriteExecute=true`), **but** `ProtectHome=read-only` followed by `ReadWritePaths=%h %t` (`L16-L17`) re-grants read-write access to the **entire `$HOME` directory (`%h`)**, largely negating `ProtectHome=read-only`!
   - **Windows Packaging ([install.ps1](../zerovault/packaging/windows/install.ps1#L1-L84), [zerovault.wxs](../zerovault/packaging/windows/zerovault.wxs#L1-L99), [bundle-portable.ps1](../zerovault/packaging/windows/bundle-portable.ps1#L1-L94)):**
     - WiX v4 `zerovault.wxs` builds a clean per-user MSI (`%LOCALAPPDATA%\Zerovault\bin`), sets `HKCU` PATH, and creates a Start Menu shortcut—**but** omits `InstallAutoStart` logon task registration (only `install.ps1:74-82` registers Scheduled Task `ZerovaultDaemon`).
2. **`tests/e2e` — Empirical Reality vs. Mocks ([e2e_multicloud_zero_knowledge.rs](../zerovault/tests/e2e/tests/e2e_multicloud_zero_knowledge.rs#L1-L1018), [redteam_security_audit.rs](../zerovault/tests/e2e/tests/redteam_security_audit.rs#L1-L671)):**
   - **What Is Genuinely Tested End-to-End (`12` tests, `0` crypto/SQLite/router mocks):**
     - Real `AwsLcCryptoEngine` (`Argon2id` 64 MiB + `HKDF-SHA256` + `AES-256-GCM`), real on-disk `SqliteMetadataStore` (`WAL`), real `StorageRouter` + `CloudBackend` (`opendal::services::Fs`), real `SyncEngine`, and real `DaemonRuntime` over both OS Named Pipes (`\\.\pipe\zerovaultd-rt-*`) and loopback TCP.
     - Proves zero plaintext filename/path/content leakage in remote `.zv`/`.zvm`/`.zvh` files (`L148-L339`), O(1) cross-chunk hydration across `4 MiB` boundary without downloading chunk 2 (`L304-L336`), fail-closed `CryptoTamperDetected` on 1-bit `.zv` flip / chunk 0<->1 swap / 1-byte `head.zvm` corruption / cross-file `WrappedDek` & chunk transplant / exact `4 MiB` `is_final_chunk` flag bitflip (`0x01 -> 0x00`), RAID-1 outage failover, `QuotaPooled` 9 MiB spillover + reassembly, 2-device concurrent conflict preservation, OAuth SSRF `302` non-following + constant-time CSRF, IPC `1 MiB` frame DoS rejection, and `Mirrored` `rev 1 -> 2 -> 3` CAS + rollback rejection + post-lock cache fail-closed.
   - **What Remains Mocked / Untested in `tests/e2e`:**
     1. Uses `MockDrive` (`with_mock_vfs(true)`) instead of live Windows `CfApi` (`live_cfapi_sync_root_mount_and_unmount_integration` is `#[ignore]`) or live Linux `/dev/fuse` mount (`linux_vfs_tests.rs` tests `ZeroVaultFuseFs` handler methods via mock structs rather than mounting `/dev/fuse`).
     2. Uses `InMemorySecretStore` in E2E daemon tests (`OsKeyringSecretStore` is tested separately in `zerovault-crypto/src/tests.rs:675-715`).
     3. Uses `BackendKind::LocalFs` (which hits the in-process `cas_fallback_lock` rather than real HTTP `If-Match`/`If-None-Match` conditional headers on S3/GDrive/OneDrive/Dropbox/WebDAV).

---

## 4. Static Code Quality & Red-Team Audit Ledger

### 4.1 Exhaustive Workspace Grep Summary (`46` `.rs` Files, `29,969` Lines)
Raw audit output saved at: [static_audit_grep.txt](target/swarm/forensics-b/static_audit_grep.txt)

| Pattern | Production (`PROD`) | Tests / Mocks (`TEST`) | Exact Production Locations |
|---|---:|---:|---|
| `.unwrap()` | **`0`** | `17` | None (`100%` clean in production code) |
| `.expect()` | **`0`** | `839` | None (`100%` clean in production code) |
| `todo!()` | **`0`** | `0` | None |
| `unimplemented!()` | **`0`** | `0` | None |
| `unreachable!()` | **`0`** | `0` | None |
| `panic!()` | **`0`** | `15` | None (`100%` clean in production code) |
| `unsafe` | **`12`** | `2` | **ALL 12 in [crates/zerovault-ui/src/dialogs.rs](../zerovault/crates/zerovault-ui/src/dialogs.rs#L126-L312):** lines `126` (`CoInitializeEx`), `137` (`CoUninitialize`), `147` (`GetDisplayName`), `149` (`PWSTR::to_string`), `151` (`CoTaskMemFree`), `173` (`CoCreateInstance` Open), `179` (`IFileOpenDialog` file picker block), `222` (`CoCreateInstance` Folder), `228` (`IFileOpenDialog` folder picker block), `264` (`CoCreateInstance` Save), `270` (`IFileSaveDialog` block), `303` (`ShellExecuteW`). Test blocks: `windows_vfs_tests.rs:195`, `linux_vfs_tests.rs:924`. |

### 4.2 Documentation vs. Source Code Discrepancy Matrix

| Document & Claim | Empirical `.rs` Reality | Verdict |
|---|---|---|
| `SECURITY_AUDIT.md:50, 200` — *"0 hand-written `unsafe` blocks in production crate sources"* | `crates/zerovault-ui/src/dialogs.rs` contains **12 hand-written `unsafe` blocks** (`L126-L312`) added in commit `46c9e77`. | **FALSE (Stale Audit)** |
| `README.md:14, 21` & `ARCHITECTURE.md:45` — *"Background sync & IPC daemon (`zerovaultd`)"* | `zerovaultd` (`daemon/src/main.rs` & `service.rs`) spawns **zero** periodic sync timers or background cloud pollers; sync only runs on manual `SyncNow` RPCs or file `flush()`. | **FALSE / UNIMPLEMENTED** |
| `README.md:31` — *"Zero WebView GUI? Tauri v2 Desktop App (`zerovault-ui`)"* | Uses Tauri v2 + Microsoft Edge WebView2 (`Zerovault.exe` = `28.44 MiB` `zerovault_ui.exe`). Directly violates Swarm Iron Law #2. | **VIOLATES IRON LAW #2** |
| `ARCHITECTURE.md:19, 86` — *"4-byte little-endian length-prefixed JSON IPC"* & `types/src/ipc.rs:8` (*"4-byte little-endian length prefix (`Postcard` or `JSON`)"*) | `daemon/src/ipc.rs:5-6, 179, 200` uses **4-byte BIG-ENDIAN (`u32::from_be_bytes` / `to_be_bytes`)** + `serde_json` only (`postcard` is used exclusively for `VaultManifest`, not IPC). | **DOC MISMATCH** |
| `SPEC_CRYPTO.md:81` (§4.2) — *"Each file entry receives an independent random 256-bit DEK per file creation / full overwrite"* | `SyncEngine::upload_dirty_inode_blobs` (`core/src/engine.rs:606-613`) **reuses the existing `wrapped_dek`** across all overwrites and partial edits for the lifetime of an inode (`if let Some(existing) = &inode_meta.wrapped_dek { crypto.unwrap_dek(...) }`). | **PARTIAL DISCREPANCY** |
| `ARCHITECTURE.md:42` & `README.md:11` — *"Zero plaintext on disk or in the cloud"* | Cloud storage is 100% zero-knowledge encrypted, **but local disk staging** (`core/src/cache.rs:212-304`) writes **unencrypted plaintext** to `staging_dir/dirty/<inode>/<chunk_index>.part`, and `zerovault-ui` (`ui/src/lib.rs:1174-1267`) writes decrypted preview files to `ui_session/` while unlocked. | **FALSE FOR LOCAL DISK** |
| Swarm Prompt Checklist — *"`zv://` Capability URI & `keybox.zv` (`Ed25519` + `X25519` + `ML-KEM-768`)"* | **0 lines of code** anywhere in `zerovault`. Neither `SPEC_CRYPTO.md` nor `zerovault-crypto` implements asymmetric keys, post-quantum KEM, `keybox.zv`, or `zv://` sharing URIs. | **100% ABSENT IN NEWER REPO** |

### 4.3 Ranked Security & Correctness Vulnerability Catalog

| ID | Severity | Location (`file:line`) | Technical Finding & Impact |
|---|---|---|---|
| **NEW-C01** | **CRITICAL** | `crates/zerovault-daemon/src/service.rs:773-888` | **`DaemonRuntime` Never Publishes or Fetches `vault/header.zvh`:** `init_vault` only writes local `state_dir/vault.zvh`; `unlock_vault` only reads local `state_dir/vault.zvh`. Second devices cannot join/unlock a cloud vault via `zerovaultd`, `zv`, or `zerovault-ui`. |
| **NEW-H01** | **HIGH** | `crates/zerovault-core/src/cache.rs:212-304`, `engine.rs:1245-1282` | **Unencrypted Plaintext `.part` Staging on Local Disk:** Dirty chunks are written in plaintext to `staging_dir/dirty/<inode>/<idx>.part` (without restricted NTFS DACLs on Windows), unlinked without zero-wipe after sync, and left behind in plaintext if `LockVault` occurs before `SyncNow` succeeds. |
| **NEW-H02** | **HIGH** | `crates/zerovault-vfs/src/windows/filter.rs:694-698, 727-731` & `src/linux/fs.rs:1042-1046` & `types/src/traits.rs:730-754` | **Broken VFS Unpin on Windows (`CfApi`) & Linux (`FUSE`):** Both OS unpin handlers call `backend.dehydrate(inode)` without calling `backend.unpin(inode)` first, always failing with `PinnedDehydrationDenied` on pinned files. `VirtualDrive` also lacks `unpin_path` to clear NTFS `PinState::Pinned`. |
| **NEW-H03** | **HIGH** | `crates/zerovault-daemon/src/main.rs:1-92`, `service.rs` | **Missing Background Sync Loop:** `zerovaultd` has no background sync scheduler or remote manifest watcher. |
| **NEW-M01** | **MEDIUM** | `crates/zerovault-core/src/engine.rs:341-346, 858` | **First-Sync (`local_rev == 0`) Rollback & Unchecked `parent_manifest_id`:** A fresh device (`local_rev == 0`) accepts any historical `ZVM1` snapshot (`rev 1` instead of `rev 50`), and `parent_manifest_id` is volatile in RAM (`Mutex<Option<Uuid>>`) and never validated on pull. |
| **NEW-M02** | **MEDIUM** | `crates/zerovault-storage/src/router.rs:386-421, 828-850` | **Mirrored Fastest-Read Does Not Fail Over on AEAD Tamper/Bit-Rot:** `race_get_backends` returns the fastest mirror's raw bytes before AEAD verification; if Mirror A has silent bit-rot (`HTTP 200`), `SyncEngine` aborts with `CryptoTamperDetected` instead of falling back to healthy Mirror B. |
| **NEW-M03** | **MEDIUM** | `crates/zerovault-crypto/src/engine.rs:406-509` | **Unencrypted `master_seed` Inside Unused `ZVS1` Keyring Blob:** `persist_session` embeds raw `master_seed` at `blob[53..85]` (only authenticating it with an empty-plaintext AES-GCM tag), and is dead code across daemon/UI. |
| **NEW-M04** | **MEDIUM** | `crates/zerovault-core/src/pool.rs:208-226`, `vfs/src/linux/fs.rs:116-144`, `cli/src/cli.rs:150-189` | **Unzeroized Plaintext Memory Residuals & Unpinned Secrets:** `PooledBuffer::drop` only zeroes `0..len` (leaving `len..capacity` unzeroized if cleared); Linux `DirtyWriteBuffer.data: Vec<u8>` (4 MiB) is not wrapped in `Zeroizing`; `zv` CLI passphrase `String` and `DaemonRequest::InitVault/UnlockVault` `String` fields are not `Zeroize`d; no `VirtualLock`/`mlock` page-pinning is used on `MasterSeed`/`VaultKeyring`. |
| **NEW-M05** | **MEDIUM** | `crates/zerovault-storage/src/backend.rs:546-594` | **Synthetic CAS Fallback on Non-Conditional Backends:** When OpenDAL returns `Unsupported` for `if_match`/`if_none_match`, `CloudBackend` falls back to process-local `Mutex` + `stat()` ETag check, leaving a TOCTOU race window between two concurrent devices sharing a non-CAS backend. |
| **NEW-L01** | **LOW** | `crates/zerovault-storage/src/oauth.rs:642-818` | **OAuth Loopback Single-Shot Callback Abort & Socket Stall:** One forged local `/callback` request aborts OAuth login, and `read_http_request` lacks a per-connection timeout. |
| **NEW-L02** | **LOW** | `crates/zerovault-daemon/src/ipc.rs:297-313` | **Unix Socket Unconditional `remove_file` & `bind`->`chmod` Window:** Removes existing path before checking if it is a socket or owned by an active `zerovaultd` instance, and calls `set_permissions(0o600)` after `bind()`. |
| **NEW-L03** | **LOW** | `crates/zerovault-core/src/engine.rs` (all overwrite/unlink paths) | **Zero Remote Orphan Blob / Snapshot Manifest Garbage Collection:** Overwriting or deleting files never deletes superseded `blobs/<aa>/<bb>/<uuid>.zv` objects or old `manifests/<uuid>.zvm` snapshots, causing unbounded remote quota consumption over time. |
| **NEW-L04** | **LOW** | `packaging/arch/PKGBUILD:11,27,45`, `zerovaultd.service:16-17` | **Arch Packaging Build Failure & Binary Naming Drift:** `PKGBUILD` builds `--workspace` (pulling Tauri `zerovault-ui`) without `webkit2gtk-4.1` in `depends`, renames UI binary to `zerovault-tray` (vs `Zerovault.exe` / `zerovault-ui.exe`), and `ReadWritePaths=%h %t` undermines `ProtectHome=read-only`. |

---

## 5. Strategic Salvage Recommendations for the Unified Merger

1. **ADOPT & HARDEN from `zerovault`:**
   - **`zerovault-crypto` symmetric core (`aws-lc-rs` scatter/gather AEAD + CPUID gate + `Argon2id` 64 MiB + `HKDF-SHA256` + `ZVH1`/`ZVC1`/`ZVM1` wire formats + `OsKeyringSecretStore`)**, removing the dead `ZVS1` plaintext-seed blob and merging `ML-KEM-768` + `Ed25519` + `X25519` + `keybox.zv` + `zv://` capability URIs on top of `aws-lc-rs`.
   - **`zerovault-storage` (`opendal v0.59` 7-backend abstraction + bounded `into_stream` reader + OAuth2 S256 PKCE loopback + `Targeted` / `Mirrored` / `QuotaPooled` router + composite mirror CAS)**, fixing Mirror AEAD failover, OAuth per-socket timeouts, and orphan blob GC.
   - **`zerovault-vfs` (`WindowsCfDrive` 4 KiB-aligned streaming `CfApi` + `LinuxFuseDrive` pure-Rust `fuser v0.18`)**, fixing **NEW-H02** (`unpin` before `dehydrate` + `VirtualDrive::unpin_path`) and wrapping `DirtyWriteBuffer` in `Zeroizing`.
   - **`zerovault-core` (`SqliteMetadataStore` WAL + `BoundedBufferPool` + `ChunkCache` + non-destructive conflict resolution)**, encrypting local `.part` staging chunks under an ephemeral/session key (**NEW-H01**) and zeroizing full `Vec` spare capacity (`0..capacity`) in `PooledBuffer::drop`.
   - **`zerovault-daemon` Named Pipe `D:P(A;;GA;;;SY)(A;;GA;;;OW)` SDDL DACL + `1 MiB` pre-allocation framing**, wiring `publish_vault_header`/`fetch_vault_header` (**NEW-C01**) and a configurable background sync loop (**NEW-H03**).
   - **`tests/e2e` 12-test adversarial & zero-knowledge integration suite** as a baseline regression gate.
2. **EXCISE COMPLETELY from `zerovault`:**
   - All of `tauri`, `tauri-build`, `wry`, `webview2-com*`, `dist/{index.html, app.js, styles.css}`, unused `aes-gcm`, `rand`, `interprocess`, and duplicate `reqwest` versions—porting the 7 high-value UX workflows from `zerovault-ui` (§3.9) into our zero-WebView native Rust GUI.

---

## 6. Read-Only Source Preservation Attestation

Verified via `git status --short` across all source repositories:
- `git -C "<donor-root>\zerovault" status --short` -> **`0` lines (clean)**
- `Test-Path "<donor-root>\zerovault\target"` -> **`False` (never created)**
