# cloud.entropy.rs / Zerovault

High-performance, **zero-knowledge encrypted virtual filesystem** and **multi-cloud sync client** written in Rust (`edition = "2024"`, `tokio`), providing Windows OneDrive "Files On-Demand" (`CfApi`) and Arch Linux user-space FUSE3 (`fuser`) mounts backed simultaneously by Google Drive, Microsoft OneDrive, Dropbox, S3-compatible object storage, and WebDAV.

---

## Security & Architecture Highlights

1. **Strict Zero-Knowledge Encryption ([`SPEC_CRYPTO.md`](SPEC_CRYPTO.md)):**
   - Cloud storage providers NEVER receive plaintext file bytes, plaintext filenames, file extensions, or directory structures.
   - Remote objects follow a strict obfuscated UUID schema enforced fail-closed before I/O:
     - `vault/header.zvh` (112-byte Argon2id salt/params + AES-GCM verifier)
     - `manifests/head.zvm` & `manifests/<2-hex>/<2-hex>/<uuid>.zvm` (encrypted `ZVM1` directory snapshots)
     - `blobs/<2-hex>/<2-hex>/<uuid>.zv` (encrypted `ZVC1` 4 MiB chunks)
2. **Hardware-Accelerated Cryptography (`crates/zerovault-crypto`):**
   - **AEAD:** `AES-256-GCM` via `aws-lc-rs` (`prebuilt-nasm` on Windows). Mandatory runtime CPUID check verifies `AES-NI` + `PCLMULQDQ` (plus `VAES`/`AVX2` detection) on `x86_64` and `AES` + `PMULL` on `aarch64`, failing closed if absent.
   - **Envelope Keys:** `Argon2id` (`m >= 64 MiB`, `t >= 3`, `p >= 4`) + 256-bit CSPRNG salt -> `HKDF-SHA256` domain-separated `MasterKek`, `ManifestKey`, `TokenWrapKey`, and `HeaderVerifierKey`.
   - **Anti-Tamper 25-Byte Chunk AAD:** `file_uuid (16B) || chunk_index (u64 LE) || is_final_chunk (u8)` prevents chunk swapping, cross-file splicing, and tail truncation.
   - **Memory Hygiene:** `Zeroizing` / `ZeroizeOnDrop` key and RAM chunk wrappers, redacted `Debug`, and native OS credential storage (`keyring`: Windows Credential Manager / Linux Secret Service & `keyutils`).
3. **Multi-Cloud Storage Router (`crates/zerovault-storage`):**
   - Powered by Apache `opendal` v0.59 (`Gdrive`, `Onedrive`, `Dropbox`, `S3`, `Webdav`, `Fs`, `Memory`) + `oauth2` v5.0 PKCE S256 loopback login (SSRF `redirect::Policy::none()` + constant-time CSRF check).
   - **Policies:** `Targeted` (virtual prefix pinning), `Mirrored` (RAID-1 parallel writes + fastest-responder `select_ok` reads), and `QuotaPooled` (automatic spillover across multiple free-tier cloud accounts).
4. **Cross-Platform Virtual Filesystem (`crates/zerovault-vfs`) & Bounded Core (`crates/zerovault-core`):**
   - **Windows 10/11:** Native `cloud-filter` (`CfApi`) sparse NTFS placeholders, 4 KiB-aligned partial range hydration, Storage Sense dehydration guard, and Explorer pin/unpin sync watcher—zero kernel drivers.
   - **Arch Linux:** Unprivileged `fuser` FUSE3 mount (`NoAtime`, `DefaultPermissions`), O(1) 4 MiB chunk hydration on `read()`, bounded dirty chunk streaming, and `user.zerovault.state` / `user.zerovault.pin` xattrs.
   - **SQLite WAL & Bounded Memory:** `rusqlite` WAL metadata DB, `Semaphore`-gated `BoundedBufferPool` + `BytesMut`, byte-bounded LRU `ChunkCache` (32 MiB default), and deterministic non-destructive conflict naming (`<stem> (conflict-<device>-<ts>).<ext>`).

---

## Workspace Crates

| Crate | Purpose |
|---|---|
| `crates/zerovault-types` | Shared async trait contracts (`CryptoEngine`, `StorageRouterTrait`, `MetadataStore`, `VfsBackend`, `VirtualDrive`), 4 MiB wire codecs, errors, IPC structs, and test mocks |
| `crates/zerovault-crypto` | Hardware-checked `aws-lc-rs` AES-256-GCM, Argon2id/HKDF key hierarchy, `OsKeyringSecretStore`, throughput benchmark |
| `crates/zerovault-storage` | `opendal` cloud connectors, OAuth2 PKCE loopback flow, `StorageRouter` (Targeted / Mirrored / Quota-Pooled) |
| `crates/zerovault-vfs` | Native Windows `CfApi` (`windows/`), Arch Linux FUSE3 (`linux/`), and cross-platform `MockDrive` |
| `crates/zerovault-core` | SQLite WAL store, `BoundedBufferPool`, `ChunkCache`, `ConflictResolver`, and streaming `SyncEngine` |
| `crates/zerovault-daemon` | `zerovaultd` background daemon & length-prefixed local IPC (Windows Named Pipes / `0600` Unix Domain Sockets) |
| `crates/zerovault-cli` | `zv` CLI (`init`, `unlock`, `lock`, `remote add/list`, `mount`, `unmount`, `pin`, `dehydrate`, `sync`, `status`, `bench-crypto`) |
| `crates/zerovault-ui` | Tauri v2 system tray popup displaying live throughput, pooled cloud quotas, and one-click vault lock |
| `tests/e2e` | Real-stack zero-knowledge end-to-end integration and adversarial security test suite |

---

## Building, Testing & Running

### Prerequisites
- **Rust toolchain:** `rustc >= 1.90` (`edition = "2024"`).
- **Windows 10/11 (`x86_64-pc-windows-msvc`):** Visual Studio C++ Build Tools + CMake + Windows 10/11 SDK (`rc.exe`). Note: `aws-lc-rs` uses the `prebuilt-nasm` feature so `nasm.exe` is not required.
- **Arch Linux (`x86_64-unknown-linux-gnu` / `aarch64-unknown-linux-gnu`):**
  ```bash
  sudo pacman -S base-devel cmake nasm fuse3 webkit2gtk-4.1 libayatana-appindicator pkgconf attr
  ```

### Build & Verify From Source

```bash
# Check full workspace
cargo check --workspace

# Run unit + E2E zero-knowledge test suite
cargo test --workspace

# Strict workspace lint check
cargo clippy --workspace --all-targets -- -D warnings

# Run hardware-accelerated AES-256-GCM 4 MiB benchmark
cargo run --release -p zerovault-cli -- bench-crypto --mib 64
```

### Quickstart CLI Workflow

1. **Start the background daemon:**
   ```bash
   cargo run --release --bin zerovaultd
   # Or pass --mock-vfs for headless / unprivileged environments
   ```
2. **Initialize vault, add pooled/mirrored clouds, and mount:**
   ```bash
   zv init
   zv remote add cloud-a --kind fs --root ~/.local/share/zerovault-cloud-a --quota-mib 10240 --policy pooled
   zv remote add cloud-b --kind s3 --bucket my-zv-bucket --region us-east-1 --quota-mib 51200 --policy pooled
   zv mount ~/Zerovault   # Windows: C:\Users\<user>\Zerovault
   zv status
   ```
3. **On-demand hydration & Arch Linux xattrs:**
   ```bash
   zv pin /Finance/Taxes.pdf
   zv dehydrate /Finance/Taxes.pdf

   # Arch Linux FUSE3 extended attribute inspection & pinning:
   getfattr -n user.zerovault.state ~/Zerovault/Finance/Taxes.pdf
   setfattr -n user.zerovault.pin -v "1" ~/Zerovault/Finance/Taxes.pdf
   ```
4. **Lock vault immediately (zeroizes in-memory keys & unmounts VFS):**
   ```bash
   zv lock
   ```

---

## OS Packaging

### Arch Linux (`packaging/arch/`)
```bash
cd packaging/arch
makepkg -si
systemctl --user enable --now zerovaultd.service
```

### Windows 10/11 (`packaging/windows/`)
- **Portable Bundle:** `.\packaging\windows\bundle-portable.ps1` (builds release `zerovaultd.exe`, `zv.exe`, and `zerovault-ui.exe` into a versioned portable `.zip`).
- **User-Local Install:** `.\packaging\windows\install.ps1` (installs under `%LOCALAPPDATA%\Zerovault\bin` and optionally registers user logon startup).
- **MSI Installer (WiX v4):** `wix build packaging\windows\zerovault.wxs`.

---

## Security Audit

See [`SECURITY_AUDIT.md`](SECURITY_AUDIT.md) for the full red-team static/dynamic audit findings, positive control matrix, and remediation verification log.
