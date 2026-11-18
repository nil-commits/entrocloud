# Wave 0 Gate Output: Empirical Merger Plan (`MERGER_PLAN.md`)

- **Orchestrator:** `Lead-Orchestrator` (Principal Systems Architect & Chief Verification Officer)
- **Merged Workspace Root:** `<workspace>`
- **Source Forensic Inputs (Strictly Read-Only, SHA-256 Verified):**
  1. **Legacy Codebases (`Agent-Forensics-A`):** [FORENSIC_LEGACY.md](audit/FORENSIC_LEGACY.md) — `cloudbridge` (`v0.4.0` Windows WPF, `37` files, tree SHA-256 `43ADD08E...`) and `cloudbridge linux` (`v0.5.0` `.NET 9` + Avalonia `11.3.22`, `65` files, tree SHA-256 `32DB719E...`).
  2. **Newer Codebase (`Agent-Forensics-B`):** [FORENSIC_NEWER.md](audit/FORENSIC_NEWER.md) — `zerovault` (`v0.1.0` Rust 2024 + Tauri v2, `82` files, HEAD `46c9e77`, tree SHA-256 `38375238...`).
  3. **Read-Only Integrity Baseline:** [READONLY_BASELINE.txt](audit/READONLY_BASELINE.txt) (`0` mutations across all three input directories).

---

## 1. Comparative Empirical Baseline (Measured on Host AMD Ryzen 9 7950X3D)

| Dimension | Legacy `cloudbridge` (`v0.4.0` / `v0.5.0`) | Newer `zerovault` (`v0.1.0`, HEAD `46c9e77`) | Merged Target (`entrocloud merge`) |
|---|---|---|---|
| **Core Runtime** | `.NET 9.0` GC + `libsodium` P/Invoke + `rclone v1.75.1` (`81.25 MiB` Go CLI subprocess) | Pure Rust 2024 (`rustc 1.94.1`), `tokio`, `opendal v0.59`, `rusqlite v0.32` | Pure Rust 2024 (`zerovaultd` + `zv`), Wave-1-proven global allocator, zero GC |
| **Test Suite Verdict** | `138/138` (`cb_win`, `85.69s`) & `146/146` (`cb_linux`, `54.86s`) + `4/4` PyNaCl | `85/85` passed (`120.81s`), `0` clippy warnings (Windows MSVC + Linux `musl`) | Full unit + `proptest` tamper/fuzz + `criterion` benches + 6-gate E2E torture suite |
| **Measured Peak RSS** | **`622.34 MiB`** (`cb_win`) / **`517.52 MiB`** (`cb_linux`) due to LOH + Argon2 arenas | Bounded `32 MiB` `BoundedBufferPool` + `32 MiB` `ChunkCache` in daemon | Strictly bounded `<= 128 MiB` RSS under 4 GiB multi-cloud streaming |
| **Desktop UI Stack & Footprint** | WPF (`85.22 MiB` dir) / Avalonia `11.3.22` (**`212.01 MiB`** framework-dependent dir; **P0 UI deadlock `ExitCode=42`**) | **Tauri v2 + Edge WebView2** (`Zerovault.exe` = `28.44 MiB`, **violates Iron Law #2**) | **Wave 1 Silicon Winner** (zero WebView2, decoupled IPC, **`0 B` background UI RAM** when window closed) |
| **Symmetric Crypto** | `libsodium` `XChaCha20-Poly1305` (`1 MiB` frames, non-standard empty `TAG_FINAL`) | `aws-lc-rs v1.19` `AES-256-GCM` (`4 MiB` `ZVC1` chunks, 25B `ChunkAad`, CPUID `AES-NI`/`VAES` gate) | Wave 1 Cipher Winner (`AES-256-GCM` `4 MiB` streaming + CPUID `AES-NI`/`VAES`/`ARMv8` enforcement) |
| **Serverless E2E Sharing** | **0% Implemented** | **0% Implemented** (`0` lines of `zv://`, `keybox.zv`, `Ed25519`, `X25519`, `ML-KEM-768`) | **`zv://` Capability URIs** + **`keybox.zv`** (`Ed25519` + Hybrid `X25519 + ML-KEM-768` + monotonic `epoch`) |
| **Multi-Cloud Routing** | **0% Implemented** (`1 job = 1 rclone remote`; zero HTTP `Range` reads) | `Targeted`, `Mirrored` (RAID-1 `select_ok`), `QuotaPooled` (atomic CAS) | Hardened `Targeted`, **AEAD-verified `Mirrored` failover**, `QuotaPooled`, + HTTP `Range` slices |
| **On-Demand VFS** | **0% Implemented** (batch backup/restore only) | Windows `CfApi` (`cloud-filter`) + Linux `fuser v0.18` (`xattr`) — **unpin broken (`NEW-H02`)** | Fixed Windows `CfApi` + Arch Linux `fuser` (`unpin` -> `dehydrate`, portable path sanitizer) |
| **Local Disk & SQLite Zero-Knowledge** | Leaks plaintext `connections.key` on Linux (`CB-04`) & CLI secrets (`CB-02`) | **Leaks plaintext `.part` chunks (`NEW-H01`) & plaintext filenames in SQLite `inodes.name`!** | **100% Encrypted:** `MetadataKey` + `BLAKE3` blind-indexed SQLite columns & AEAD-sealed `.zvpart` staging |

---

## 2. Subsystem-by-Subsystem Merger & Remediation Matrix

### 2.1 Cryptography & Serverless Post-Quantum Sharing (`crates/zerovault-crypto`)

| Action | Source / Origin | Exact Specification |
|---|---|---|
| **PORT** | `zerovault` (`crypto/src/{engine.rs, hw.rs, keyring_store.rs}`) | `aws-lc-rs` scatter/gather `AES-256-GCM`, runtime CPUID enforcement (`AES-NI + PCLMULQDQ` + `VAES` detection on `x86_64`; `AES + PMULL` on `aarch64`), `4 MiB` `ZVC1` chunk framing with 25-byte `ChunkAad` (`file_id [16B] \|\| chunk_idx [8B LE] \|\| is_final [1B]`), `ZVH1` header, `WrappedDek` (`b"ZV-DEK-V1" \|\| file_id`), and `OsKeyringSecretStore`. |
| **PORT** | `cloudbridge linux` (`Sodium.cs:102`, `VaultService.cs:12`) | **Pre-Allocation KDF DoS Bounds:** Enforce upper ceilings (`m_cost_kib <= 262_144` [256 MiB], `t_cost <= 10`, `p_cost <= 16`) alongside minimum floors (`m >= 65_536`, `t >= 3`, `p >= 4`) *before* `Argon2` memory allocation so a malicious remote `header.zvh` cannot OOM-kill `zerovaultd`. Port strict domain-separated AAD context strings across all wire objects. |
| **FIX** | Remediate `NEW-M03` (`engine.rs:406-509`) | Replace raw `master_seed` inside `ZVS1` session blobs: generate a random 256-bit OS-keyring-resident wrapping key (`zv-keyring-wrap`) and AEAD-seal `master_seed` (`ZVS2`) with `vault_id` AAD so `master_seed` never sits unencrypted even inside credential blobs. |
| **EXPAND** | Zero-Knowledge Local Subkeys | Expand `HKDF-SHA256` key schedule with `"zerovault.v2.meta-aead"` (`MetadataKey` for encrypting SQLite inode/conflict/dirty-op names), `"zerovault.v2.meta-blind"` (`BlindIndexKey` for `BLAKE3::keyed_hash(parent_inode \|\| utf8_name)` O(1) directory lookups), and ephemeral CSPRNG `StagingKey` (`Zeroizing<[u8; 32]>`) for encrypting local dirty `.zvpart` chunks. |
| **BUILD CLEAN** | **Capability URIs (`zv://`)** | Implement `zv://share/v1/<provider_locator>?id=<uuid>&size=<len>&chunks=<n>#<base64url(SRK_32B \|\| Ed25519_PubKey_32B)>`. Fragment `#...` never leaves client (`RFC 3986 §3.5`). `HKDF-SHA256(SRK)` derives read-only `ShareManifestKey` + `ShareChunkKey`; manifest signature verified under `Ed25519_PubKey` before any chunk decryption. |
| **BUILD CLEAN** | **Cloud Keyboxes (`keybox.zv`, `ZVK1`)** | Implement serverless multi-recipient folder sharing:<li>**Signing:** Owner `Ed25519` keypair (`aws_lc_rs::signature::Ed25519KeyPair`) signs canonical `ZVK1` header + recipient stanzas + `epoch: u64` + `vault_id`.</li><li>**Hybrid PQ Recipient Stanzas:** Combine classical **`X25519`** (`aws_lc_rs::agreement::X25519`) + NIST FIPS 203 **`ML-KEM-768`** (`aws_lc_rs::kem::ML_KEM_768`) via `HKDF-SHA256(ikm = x25519_shared \|\| mlkem768_shared, salt = stanza_nonce, info = "zerovault.v2.pq-keybox" \|\| vault_id \|\| epoch_le \|\| recipient_fingerprint)` to AEAD-wrap the 256-bit `FolderRootKey` (`FRK`).</li><li>**Revocation & Anti-Rollback:** Removing a recipient increments `epoch -> epoch + 1`, rotates `FRK'`, omits the revoked recipient stanza, re-signs `keybox.zv`, and updates SQLite `epoch_floor` so replaying `epoch = 1` after `epoch = 2` deterministically fails closed (`CryptoTamperDetected`).</li> |
| **EXCISE** | `cloudbridge` (`Sodium.cs`, `SodiumStream.cs`) & `zerovault` (`Cargo.toml:55,63`) | Retire `libsodium.dll`/`.so.23` P/Invoke, `CBSOD002` signed-length framing, managed `string`/`byte[]` keys (`CB-05`, `CB-06`), and unused `aes-gcm` / `rand` workspace dependencies. |

---

### 2.2 Multi-Cloud Storage Router & OAuth2 (`crates/zerovault-storage`)

| Action | Source / Origin | Exact Specification |
|---|---|---|
| **PORT** | `zerovault` (`storage/src/{backend.rs, oauth.rs, router.rs}`) | OpenDAL `0.59` 7-backend engine (`GoogleDrive`, `OneDrive`, `Dropbox`, `S3`, `WebDav`, `LocalFs`, `Memory`), strict `validate_remote_object_key` whitelist (extended to permit `"vault/keybox.zv"` and `"shares/<32-hex>.zvs"`), bounded `into_stream` readers, S256 PKCE loopback OAuth2 (`redirect::Policy::none()`, constant-time CSRF, `TokenWrapKey`), and `Targeted` / `Mirrored` / `QuotaPooled` policies. |
| **PORT** | `cloudbridge` (`ConnectionWindow.cs:63-107`, `BackupEngine.cs:96-112`) | Least-privilege provider scopes (Google Drive `https://www.googleapis.com/auth/drive.file`, OneDrive `Files.ReadWrite.AppFolder offline_access`, Dropbox `files.content.write files.content.read`), automatic cleanup of half-configured remotes on aborted OAuth flow, and strict immutable-blob-before-manifest two-phase upload ordering. |
| **FIX** | Remediate `NEW-M02` (`router.rs:386-421, 828-850`) | **Cryptographically Verified RAID-1 Failover:** Add `get_blob_verified` / ordered candidate fallback on `Mirrored` reads: race healthy mirrors via `select_ok` for lowest latency, **and** if the winning mirror's payload fails caller verification (AEAD tag / header check), mark that mirror degraded and transparently retry remaining healthy/standby mirrors before returning `CryptoTamperDetected`. |
| **FIX** | Remediate `NEW-L01` (`oauth.rs:642-818`) | Harden loopback OAuth callback server: wrap every accepted TCP socket in a `5s` `tokio::time::timeout` (blocking 1-byte slowloris stalls) and respond `400 Bad Request` on invalid/missing `state` **without** aborting the listener loop until the authentic CSRF `state` arrives or overall timeout expires. |
| **BUILD CLEAN** | **Chaos Fault Injector (`ChaosStorageLayer`)** | Built-in deterministic/probabilistic fault injection wrapper (configurable packet drop %, truncated stream, corrupted byte, latency spike) for Wave 4 Gate 4 (`30%` packet failure resilience proof). |
| **EXCISE** | `cloudbridge` (`RcloneClient.cs`, `TransferSession.cs`) | Retire `81.25 MiB` `rclone` binary, CLI secret passing (`CB-02`), and double full-tree hashing (`CB-09`). |

---

### 2.3 Cross-Platform Native On-Demand VFS (`crates/zerovault-vfs`)

| Action | Source / Origin | Exact Specification |
|---|---|---|
| **PORT** | `zerovault` (`vfs/src/windows/*`, `vfs/src/linux/*`) | Windows native `CfApi` (`cloud-filter v0.0.7`: `HydrationType::Progressive`, 4 KiB sector alignment, `<= 4 MiB` streaming `FetchData`, `ActiveFetchGuard` cancellation, 28B `ZVID` placeholder identity) and Arch Linux `fuser v0.18` (`SessionACL::Owner`, `RuntimeBridge`, `DirtyWriteBuffer`, `user.zerovault.{state,pin,file_id}` xattrs). |
| **PORT** | `cloudbridge linux` (`BackupEngine.cs:185-226`, `Platform.cs`) | **Cross-OS Path Sanitizer (`sanitize_virtual_component`):** Reject NULs, path traversal (`..`), ADS colons (`:`), control chars, and optionally warn/sanitize Windows reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1..9`, `LPT1..9`, trailing dots/spaces) on cross-OS sync while **strictly preserving case-sensitive POSIX filenames (`Ordinal`)** in manifests and Linux FUSE (remediating `CB-03` silent data loss!). |
| **FIX** | Remediate `NEW-H02` (`VFS-1`, `VFS-2`, `VFS-3`) | 1. Add `async fn unpin_path(&self, relative_path: &str) -> ZeroVaultResult<()>` to `VirtualDrive` (`zerovault-types`), calling `Placeholder::mark_pin(PinState::Unpinned)` on Windows.<br>2. In both `vfs/src/windows/filter.rs` (`wants_unpin`) and `vfs/src/linux/fs.rs` (`setxattr` `"user.zerovault.pin" = "0"`), execute `backend.unpin(inode)` **before** `backend.dehydrate(inode)` so previously pinned files unpin and dehydrate cleanly. |
| **FIX** | Remediate `NEW-M04` (`linux/fs.rs:116-144`) | Wrap `DirtyWriteBuffer` payload in `Zeroizing` and wipe full `0..capacity` before freeing. |
| **EXPAND** | Portable Linux FUSE State-Machine Tests | Decouple portable inode/xattr/buffer logic in `src/linux/` from Linux-only `fuser` kernel mount calls where appropriate so unit + `proptest` suites execute natively on Windows host **in addition** to `cargo clippy --target x86_64-unknown-linux-musl`. |

---

### 2.4 Zero-Knowledge SQLite WAL & Bounded Streaming Core (`crates/zerovault-core`)

| Action | Source / Origin | Exact Specification |
|---|---|---|
| **PORT** | `zerovault` (`core/src/{db.rs, engine.rs, pool.rs, cache.rs, conflict.rs}`) | SQLite WAL store, deadlock-safe `BoundedBufferPool`, `32 MiB` LRU `ChunkCache`, O(1) `ChunkSpan` range hydration across 4 MiB boundaries, and non-destructive sibling conflict preservation (`<stem> (conflict-<dev>-<ts>).<ext>`). |
| **PORT** | `cloudbridge` (`PackedBackup.cs:216-229`, `BackupEngine.cs:145-158`) | Crash-resumable encrypted upload chunk journal + `.partial` exclusive-locked atomic local file export promotion (verifying AEAD + length + symlink/reparse absence before rename) + configurable OS noise exclusion filter (`Thumbs.db`, `.DS_Store`, `desktop.ini`, `~$*`). |
| **CRITICAL FIX** | **Zero-Knowledge SQLite Schema (`Wave 4 Gate 2` Compliance)** | Eliminate ALL plaintext file/directory names from SQLite (`inodes.name`, `dirty_ops.target_path_hint`/`payload_json`, `conflicts.original_path`/`conflict_path`):<li>Store `name_blind_idx BLOB NOT NULL` = `BLAKE3::keyed_hash(BlindIndexKey, parent_inode_le \|\| utf8_name)` with `UNIQUE(parent_inode, name_blind_idx)` for O(1) indexed lookups.</li><li>Store `enc_name BLOB NOT NULL` = `AES-256-GCM(MetadataKey, nonce, aad = b"ZV-META-NAME-V2" \|\| inode_le \|\| parent_inode_le, utf8_name)`.</li><li>Encrypt `dirty_ops.enc_payload BLOB` and `conflicts.enc_record BLOB` under `MetadataKey`, Enable `PRAGMA secure_delete = ON;`. Result: **0 plaintext canary strings** in SQLite columns, B-tree pages, or WAL frames!</li> |
| **FIX** | Remediate `NEW-H01` (`cache.rs:212-304`) | **Encrypted `.zvpart` Local Disk Staging:** Seal every staged dirty chunk on disk with ephemeral session `StagingKey` (`AES-256-GCM`, `aad = b"ZV-STAGE-V2" \|\| inode_le \|\| chunk_idx_le`), apply owner-only NTFS DACL (`D:P(A;;GA;;;SY)(A;;GA;;;OW)`) / Unix `0o700`, and cryptographically wipe + unlink staging files on `LockVault` and daemon startup crash recovery. |
| **FIX** | Remediate `NEW-M01` & Rollback Defense | Add `security_epochs(scope_id PK, min_epoch INTEGER NOT NULL, last_manifest_id BLOB, min_revision INTEGER NOT NULL)` table in SQLite WAL. Persist `parent_manifest_id` and `keybox.zv` `epoch`; reject any remote manifest or keybox whose `revision < min_revision` or `epoch < min_epoch` with `ZeroVaultError::CryptoTamperDetected`. |
| **FIX** | Remediate `NEW-M04` & `NEW-L03` | Fix `PooledBuffer::drop` to zeroize full `0..capacity` (including spare capacity beyond `len`); implement deferred remote orphan `.zv` blob garbage collection after manifest CAS commit succeeds. |

---

### 2.5 Daemon, CLI, Zero-WebView Native UI & Packaging (`zerovault-daemon`, `zerovault-cli`, `zerovault-ui`, `packaging/`)

| Action | Source / Origin | Exact Specification |
|---|---|---|
| **PORT & FIX** | `zerovault-daemon` (`ipc.rs`, `service.rs`, `main.rs`) | Keep Windows Named Pipe owner-only `PROTECTED_DACL` (`D:P(A;;GA;;;SY)(A;;GA;;;OW)`) + `1 MiB` pre-allocation framing.<br><li>**Fix `NEW-C01`:** Wire `publish_vault_header` on `InitVault`/`AddRemote` and `fetch_vault_header` fallback on `UnlockVault` so multi-device cloud vaults work out-of-the-box.</li><li>**Fix `NEW-H03`:** Spawn configurable periodic background sync worker (`tokio::time::interval` + `tokio::sync::Notify` immediate trigger) in `zerovaultd`.</li><li>**Fix `NEW-L02`:** Probe existing Unix Domain Socket (`$XDG_RUNTIME_DIR/zerovault/zerovaultd.sock`) before unlinking stale socket, and bind inside `0o700` parent directory so zero race window exists.</li><li>Add RPC endpoints for `CreateShareUri`, `ImportShareUri`, `InitSharedFolderKeybox`, `AddKeyboxRecipient`, `RevokeKeyboxRecipient`, and live transfer telemetry (`bytes_up_per_sec`, `bytes_down_per_sec`, `active_chunks`, `rss_bytes`).</li> |
| **PORT & FIX** | `zerovault-cli` (`zv`) | Wrap all CLI passphrases in `Zeroizing<String>`; add full subcommands for `unpin`, `policy`, `share create-uri`, `share open-uri`, `keybox {init, grant, revoke, status}`, `ls`, `import`, `export`, `conflicts`, and `oauth`. |
| **BUILD CLEAN** | **`zerovault-ui` (Wave 1 Bake-Off Winner — Zero WebView2!)** | Implement production UI using the **empirically proven Wave 1 winner** (`.NET NativeAOT + Avalonia` vs Pure Rust `iced` vs Pure Rust `eframe`/`egui`).<br><li>**Zero Background UI Surface RAM:** Closing the UI window completely terminates the UI window process (leaving **`0 bytes`** of UI surface RAM/VRAM resident while `zerovaultd` stays resident in the background; optional ultra-minimal tray launcher or `--tray` mode spawns the window process on demand via IPC).</li><li>Port high-value UX workflows: auto-daemon bootstrap, 1-click local cloud folder detector, recursive symlink-safe import, encrypted note editor, 1-click Free Up Space (`Unpin` + `Dehydrate`), Multi-Cloud Routing Studio, Serverless Sharing (`zv://` & `keybox.zv` PQ recipient manager), and Emergency Recovery Kit export.</li><li>Register OS `zv://` custom URI scheme handler (`HKCU\Software\Classes\zv` on Windows; `x-scheme-handler/zv` in Arch `.desktop`).</li> |
| **FIX** | `packaging/arch/*` & `packaging/windows/*` | Fix `PKGBUILD` (`NEW-L04`: zero `webkit2gtk` dependency, consistent binary names `zerovaultd`, `zv`, `zerovault-ui`), tighten `zerovaultd.service` (`ProtectHome=read-only` with scoped `ReadWritePaths=%h/.local/share/zerovault %h/ZeroVault %t` instead of all of `%h`!), and align Windows `install.ps1` / `zerovault.wxs` / `bundle-portable.ps1` with `zv://` URI registration + logon daemon startup. |

---

## 3. Gate 0 Verification Checklist

- [x] `cloudbridge` (`v0.4.0`) and `cloudbridge linux` (`v0.5.0`) compiled and executed empirically (`138/138` and `146/146` tests passed; raw Peak RSS & deadlock proof recorded in [FORENSIC_LEGACY.md](audit/FORENSIC_LEGACY.md)).
- [x] `zerovault` (`v0.1.0`) compiled, tested, clippy-checked (Windows + Linux `musl`), and PE-inspected empirically (`85/85` tests passed; `Zerovault.exe` WebView2 static loader & 12 defects documented in [FORENSIC_NEWER.md](audit/FORENSIC_NEWER.md)).
- [x] Zero files added, modified, or deleted in `cloudbridge`, `cloudbridge linux`, or `zerovault`.
- [x] Subsystem-by-subsystem merger plan locked in `MERGER_PLAN.md`, pending **Wave 1 Silicon Bake-Off** empirical stack selection (`Agent-Judge` Gate 1).
