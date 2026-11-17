# Zerovault System Architecture (`ARCHITECTURE.md`)

**Project:** `cloud.entropy.rs / Zerovault`  
**Edition:** Rust `2024` (`tokio` async runtime)  
**Target OSes:** Windows 10/11 (`x86_64-pc-windows-msvc`), Arch Linux (`x86_64-unknown-linux-gnu` / `aarch64-unknown-linux-gnu`)

---

## 1. Crate Dependency DAG

```text
                       ┌──────────────────────┐
                       │   zerovault-types    │  ◄── Frozen Wave-0 Contracts
                       │ (traits, wire, mocks)│      Owned by Lead-Architect
                       └──────────┬───────────┘
          ┌───────────────────────┼───────────────────────┐
          ▼                       ▼                       ▼
┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐
│ zerovault-crypto │    │zerovault-storage │    │  zerovault-vfs   │
│  aws-lc-rs AES   │    │ OpenDAL + PKCE   │    │ Win CfApi / FUSE │
│  Argon2id/HKDF   │    │ Targeted/RAID1/  │    │   + MockDrive    │
│  OS Keyring      │    │ Quota Pooling    │    └────────┬─────────┘
└────────┬─────────┘    └────────┬─────────┘             │
         └───────────────┬───────┘                       │
                         ▼                               │
                ┌──────────────────┐                     │
                │  zerovault-core  │ ◄───────────────────┘
                │ SQLite WAL, LRU, │   implements VfsBackend
                │ Bounded BytesMut │
                │ Sync + Conflicts │
                └────────┬─────────┘
                         │
          ┌──────────────┴──────────────┐
          ▼                             ▼
┌──────────────────┐          ┌──────────────────┐
│ zerovault-daemon │◄────────►│  zerovault-cli   │ (zv)
│ Named Pipes/UDS  │          ├──────────────────┤
└──────────────────┘          │  zerovault-ui    │ (Tauri v2 tray)
                              └──────────────────┘
```

---

## 2. Subsystems & Responsibilities

### 2.1 `zerovault-types` (Shared Contract Crate)
- **Async Traits (`#[async_trait]`):** `CryptoEngine`, `SecretStore`, `StorageRouterTrait`, `MetadataStore`, `VfsBackend`, `VirtualDrive`.
- **Wire & Domain Types:** `ChunkHeader`, `ChunkAad`, `VaultHeader`, `WrappedDek`, `VaultManifest`, `ManifestNode`, `BlobObjectKey`, `ManifestObjectKey`, `RoutingPolicy`, `DaemonRequest`/`DaemonResponse`, `ZeroVaultError`.
- **Test Doubles (`zerovault-types::mocks`):** Thread-safe in-memory mocks (`MockCryptoEngine`, `InMemorySecretStore`, `MockStorageRouter`, `MockMetadataStore`, `MockVfsBackend`) allowing every Wave 1/2 crate to compile and test independently.

### 2.2 `zerovault-crypto`
- `AwsLcCryptoEngine`: Hardware-accelerated `AES-256-GCM` via `aws-lc-rs`, runtime CPUID enforcement (`AES-NI` + `PCLMULQDQ` on x86_64; `AES` + `PMULL` on aarch64), Argon2id + HKDF-SHA256 key hierarchy, `Zeroizing` memory hygiene, and 4 MiB chunk streaming benchmark.
- `OsKeyringSecretStore`: OS credential manager persistence (`keyring` crate) with AES-256-GCM token wrapping.

### 2.3 `zerovault-storage`
- `OpenDalBackend`: Apache `opendal` v0.59 adapters for Google Drive, OneDrive, Dropbox, S3-compatible object stores, WebDAV, local `Fs`, and `Memory` wrapped with retry, timeout, and concurrency layers.
- `OAuthPkceAuthenticator`: `oauth2` v5.0 Authorization Code + S256 PKCE loopback listener (`127.0.0.1:<ephemeral>`) with SSRF redirect protection (`Policy::none()`) and constant-time CSRF state validation.
- `StorageRouter`:
  1. **Targeted Routing:** Longest virtual path prefix pins subtrees to a specific cloud backend.
  2. **Mirrored Redundancy (RAID-1):** Parallel upload across 2+ backends; `get_blob` races healthy mirrors with `futures::future::select_ok` and returns the fastest valid response.
  3. **Quota Pooling:** Automatically spills blobs across multiple free-tier cloud accounts ranked by remaining free capacity while preserving reserve headroom.

### 2.4 `zerovault-vfs`
- **Windows 10/11 (`src/windows/`):** Native Cloud Files API (`cloud-filter` / `CfApi`), zero kernel drivers, NTFS sparse placeholders, Explorer sync badges & progress reporting, 4 KiB-aligned partial range hydration (`fetch_data`), Storage Sense `dehydrate`, and local change/pin watcher.
- **Arch Linux (`src/linux/`):** Unprivileged `fuser` (`fuse3` protocol) filesystem mapping SQLite inodes, hydrating needed 4 MiB chunks on `read()`, streaming dirty writes cleanly on `write()`/`flush()`/`fsync()`, and exposing `user.zerovault.state` and `user.zerovault.pin` xattrs.
- **Cross-Platform Harness:** `MockDrive` exercising `VfsBackend` directly on any OS without elevated privileges or FUSE kernel mounts.

### 2.5 `zerovault-core`
- **SQLite WAL Store:** `rusqlite` (`journal_mode=WAL`, `synchronous=NORMAL`, `foreign_keys=ON`) tracking virtual inodes, hydration states (`OnlineOnly`, `PartiallyHydrated`, `LocallyCached`, `Pinned`, `DirtyLocal`), wrapped DEKs, chunk maps, dirty queue, and manifest ETags.
- **Bounded Memory Pipeline (< 80 MB idle RAM):**
  - `BoundedBufferPool`: `tokio::sync::Semaphore`-gated pool of reusable 4 MiB `BytesMut` chunk buffers. Files are always streamed chunk-by-chunk—never loaded wholly in RAM.
  - `ChunkCache`: Byte-bounded LRU cache (`lru::LruCache`) holding decrypted verified chunks up to a configurable memory budget (default 32 MiB) plus optional encrypted disk cache.
- **Conflict Resolution:** Optimistic concurrency against manifest revisions; concurrent remote + local modifications never overwrite silently—the local or conflicting copy is preserved deterministically as `<stem> (conflict-<device>-<YYYYMMDD-HHMMSS>).<ext>`.

### 2.6 `zerovault-daemon`, `zerovault-cli`, `zerovault-ui` & `packaging/`
- **`zerovaultd`:** Background sync daemon exposing length-prefixed JSON IPC over Windows Named Pipes (`\\.\pipe\zerovaultd`) or Linux Unix Domain Sockets (`$XDG_RUNTIME_DIR/zerovault/zerovaultd.sock`, mode `0600`).
- **`zv`:** `clap` CLI for `init`, `unlock`, `lock`, `remote add/list`, `mount`, `unmount`, `pin`, `dehydrate`, `status`, and `bench-crypto`.
- **`zerovault-ui`:** Lightweight Tauri v2 tray popup polling daemon throughput, pooled cloud quotas, sync health, and one-click vault lock.
- **`packaging/`:** Arch Linux `PKGBUILD` + `systemd --user` unit (`zerovaultd.service`), and Windows portable/WiX bundle scripts.

---

## 3. Swarm File-Ownership Matrix

| Role | Exclusive Write Scope |
|---|---|
| `Lead-Architect` | Root `Cargo.toml`, `.cargo/config.toml`, `ARCHITECTURE.md`, `SPEC_CRYPTO.md`, `README.md`, `crates/zerovault-types/**`, `crates/zerovault-vfs/Cargo.toml`, `crates/zerovault-vfs/src/lib.rs`, final binary wiring |
| `Agent-Crypto` | `crates/zerovault-crypto/**` |
| `Agent-Storage` | `crates/zerovault-storage/**` |
| `Agent-VFS-Linux` | `crates/zerovault-vfs/src/linux/**`, `crates/zerovault-vfs/tests/linux_*` |
| `Agent-VFS-Windows` | `crates/zerovault-vfs/src/windows/**`, `crates/zerovault-vfs/tests/windows_*` |
| `Agent-Core` | `crates/zerovault-core/**` |
| `Agent-UX-Pkg` | `crates/zerovault-daemon/**`, `crates/zerovault-cli/**`, `crates/zerovault-ui/**`, `packaging/**` |
| `Agent-SecQA` | `tests/e2e/**`, `SECURITY_AUDIT.md` |
