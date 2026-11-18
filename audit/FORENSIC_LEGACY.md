# Wave 0 Forensic Archaeology: Legacy CloudBridge (`v0.4.0` Windows WPF & `v0.5.0` Cross-Platform / Avalonia)

**Auditor:** `Agent-Forensics-A` (Zero-Trust Empirical Merger Swarm)  
**Audit Date:** `2026-11-17`  
**Toolchain:** `.NET SDK 9.0.320` (`win-x64`), `PyNaCl 1.6.2` (independent wire-format verification), Win32 `psapi!GetProcessMemoryInfo` (`PROCESS_MEMORY_COUNTERS`)  
**Targets Audited (Strictly Read-Only):**
1. **CloudBridge v0.4.0 (`cb_win`):** [`<donor-root>/cloudbridge`](../cloudbridge) — 37 files, `89,165,156` bytes (`net9.0-windows` WPF + WinForms tray)
2. **CloudBridge v0.5.0 (`cb_linux`):** [`<donor-root>/cloudbridge linux`](../cloudbridge%20linux) — 65 files, `178,010,385` bytes (`CloudBridge.Core` `net9.0` + `CloudBridge.Desktop` Avalonia `11.3.22` + `CloudBridge` `net9.0-windows` WPF)

---

## 1. Zero-Mutation Sandbox Build, Execution & Memory Telemetry

Both legacy trees were mirrored via `robocopy /E` into isolated sandboxes under [`target/swarm/forensics-a/sandbox/cb_win`](target/swarm/forensics-a/sandbox/cb_win) and [`target/swarm/forensics-a/sandbox/cb_linux`](target/swarm/forensics-a/sandbox/cb_linux) prior to invoking `dotnet build` or running any binaries.

### 1.1 Release Build Matrix & Compiled Artifact Sizes

All five project targets compiled cleanly under `.NET SDK 9.0.320` (`-c Release`) with **0 warnings, 0 errors, ExitCode = `0`**:

| Sandbox Target | Project File | TFM / Type | Build Wall-Clock | Managed App Binary Size | Output Dir Files | Total Output Dir Bytes |
|---|---|---|---:|---:|---:|---:|
| `cb_win` WPF App | [`src/CloudBridge/CloudBridge.csproj`](../cloudbridge/src/CloudBridge/CloudBridge.csproj) | `net9.0-windows` (`WinExe`) | `5,682.5 ms` | `CloudBridge.dll`: `187,904` B<br>`CloudBridge.exe`: `156,160` B | 10 | `89,360,694` B (`85.22 MiB`) |
| `cb_win` Test Suite | [`tests/CloudBridge.Tests/CloudBridge.Tests.csproj`](../cloudbridge/tests/CloudBridge.Tests/CloudBridge.Tests.csproj) | `net9.0-windows` (`Exe`) | `1,816.6 ms` | `CloudBridge.Tests.dll`: `57,856` B<br>`CloudBridge.Tests.exe`: `156,160` B | 15 | `89,597,522` B (`85.45 MiB`) |
| `cb_linux` Core Engine | [`src/CloudBridge.Core/CloudBridge.Core.csproj`](../cloudbridge%20linux/src/CloudBridge.Core/CloudBridge.Core.csproj) | `net9.0` (`Library`) | *(built w/ dependents)* | `CloudBridge.Core.dll`: `131,584` B | 3 | `169,525` B (`0.16 MiB`) |
| `cb_linux` WPF App | [`src/CloudBridge/CloudBridge.csproj`](../cloudbridge%20linux/src/CloudBridge/CloudBridge.csproj) | `net9.0-windows` (`WinExe`) | `2,197.8 ms` | `CloudBridge.dll`: `73,728` B<br>`CloudBridge.Core.dll`: `131,584` B<br>`CloudBridge.exe`: `156,160` B | 12 | `89,392,363` B (`85.25 MiB`) |
| `cb_linux` Avalonia Desktop | [`src/CloudBridge.Desktop/CloudBridge.Desktop.csproj`](../cloudbridge%20linux/src/CloudBridge.Desktop/CloudBridge.Desktop.csproj) | `net9.0` (`WinExe`, Avalonia `11.3.22`) | `3,799.4 ms` | `CloudBridge.dll`: `232,960` B<br>`CloudBridge.Core.dll`: `131,584` B<br>`CloudBridge.exe`: `197,632` B | **67** | **`222,304,167` B (`212.01 MiB`)** |
| `cb_linux` Test Suite | [`tests/CloudBridge.Tests/CloudBridge.Tests.csproj`](../cloudbridge%20linux/tests/CloudBridge.Tests/CloudBridge.Tests.csproj) | `net9.0` (`Exe`) | `3,086.0 ms` | `CloudBridge.Tests.dll`: `60,416` B<br>`CloudBridge.Tests.exe`: `156,160` B | 9 | `1,153,792` B (`1.10 MiB`) |

**Bundled Third-Party Native Binary Inventory (Verified SHA-256):**
- `tools/libsodium.dll` (Windows x64, `libsodium 1.0.22`): `709,505` B — SHA-256 `32A6F89659284A4D85447CD0C25C406B26C66C363A2F7B3A106D9BE463565FBE` (identical across v0.4.0 and v0.5.0).
- `tools/libsodium.so.23` (Linux x64, v0.5.0 only): `367,408` B — SHA-256 `F9FDC530581D9C0978097C3838D12E33B12D7496106699C796635E97A0407421`.
- `tools/rclone.exe` (Windows x64, `v1.75.1`): `85,192,704` B (`81.25 MiB`) — SHA-256 `033EEE51C9AD47C2DE2624B6674D355274BCD6CF0027A5F85DB4437BA24AE81C` (identical across v0.4.0 and v0.5.0).
- `tools/rclone` (Linux x64, `v1.75.1`, v0.5.0 only): `85,360,802` B (`81.41 MiB`) — SHA-256 `F66D8C1D552AD90296A11BC8B46D56A7FA5DA1A7FA05E7CA522D95DF92C4A4C0`.
- **Avalonia UI Footprint Bloat:** Framework-dependent `CloudBridge.Desktop` output is **212.01 MiB** before self-contained `.NET` runtime packaging (`~130 MiB` of multi-RID `libSkiaSharp`, `libHarfBuzzSharp`, `av_libglesv2.dll`, `Avalonia.Fonts.Inter.dll`, and `Avalonia.*` assemblies) alongside an `81.25 MiB` `rclone` binary.

### 1.2 Empirical Test Suite Execution & Peak RSS (`WorkingSet64`)

Executed via [`run_tests_telemetry.ps1`](target/swarm/forensics-a/run_tests_telemetry.ps1) (full raw logs captured in [`test_telemetry_output.txt`](target/swarm/forensics-a/test_telemetry_output.txt)):

| Executable | Exit Code | Checks Passed / Failed | Wall-Clock Execution | Peak RSS (`WorkingSet64` / `PeakWorkingSetSize`) | Peak Commit (`PeakPagefileUsage`) |
|---|---:|---:|---:|---:|---:|
| `cb_win` `CloudBridge.Tests.exe` (`net9.0-windows`) | `0` | **138 / 0** | **`85,691.85 ms` (`85.692 s`)** | **`652,566,528` B (`622.34 MiB`)** | `630,132,736` B (`600.94 MiB`) |
| `cb_linux` `CloudBridge.Tests.exe` (`net9.0`) | `0` | **146 / 0** *(+4 Linux-only guarded by `IsLinux()`)* | **`54,860.05 ms` (`54.860 s`)** | **`542,658,560` B (`517.52 MiB`)** | `509,440,000` B (`485.84 MiB`) |
| `interop.py` + `--interop-only` (`cb_win` fixture) | `0` | **4 / 0** (`PyNaCl 1.6.2` ↔ C#) | `< 2.0 s` | — | — |
| `interop.py` + `--interop-only` (`cb_linux` fixture) | `0` | **4 / 0** (`PyNaCl 1.6.2` ↔ C#) | `< 2.0 s` | — | — |

#### Raw Build & Test Telemetry Excerpt
```text
=== BUILD SUMMARY ===
cb_win   CloudBridge.csproj         -> ExitCode=0 ElapsedMs=5682.5 (0 Warn, 0 Err)
cb_win   CloudBridge.Tests.csproj   -> ExitCode=0 ElapsedMs=1816.6 (0 Warn, 0 Err)
cb_linux CloudBridge.csproj         -> ExitCode=0 ElapsedMs=2197.8 (0 Warn, 0 Err)
cb_linux CloudBridge.Desktop.csproj -> ExitCode=0 ElapsedMs=3799.4 (0 Warn, 0 Err)
cb_linux CloudBridge.Tests.csproj   -> ExitCode=0 ElapsedMs=3086.0 (0 Warn, 0 Err)

=== TEST EXECUTION 1: cb_win CloudBridge.Tests (net9.0-windows) ===
ExitCode: 0
WallClockMs: 85691.85 (85.692 s)
SampledMaxWorkingSet64: 652566528 bytes (622.34 MiB)
KernelPeakWorkingSetSize: 652566528 bytes (622.34 MiB)
KernelPeakCommitBytes: 630132736 bytes (600.94 MiB)
138 checks passed. Test artifacts: ...\sandbox\cb_win\work\sodium-test-889c91109ccb49f1ac93429669487a4c

=== TEST EXECUTION 2: cb_linux CloudBridge.Tests (net9.0) ===
ExitCode: 0
WallClockMs: 54860.05 (54.860 s)
SampledMaxWorkingSet64: 542658560 bytes (517.52 MiB)
KernelPeakWorkingSetSize: 542658560 bytes (517.52 MiB)
KernelPeakCommitBytes: 509440000 bytes (485.84 MiB)
146 checks passed. Test artifacts: ...\sandbox\cb_linux\work\sodium-test-88a93686199a42c49bc3eca2e1d8e21e

=== PYNACL 1.6.2 INTEROP ===
PASS: PyNaCl decrypts C# secretstream with independently parsed framing
PASS: PyNaCl independently derives Argon2id key and unwraps C# vault envelope
Created independently encrypted Python fixture with variable chunk sizes
PASS: PyNaCl independently restores all packed files, including a file spanning multiple packs
PASS: C# decrypts independently generated PyNaCl secretstream
```

**Root Cause of 517–622 MiB Peak RSS:**
1. Repeated `64 MiB` native `Argon2id` arena allocations (`crypto_pwhash`) across ~14 unlock/unwrap checks.
2. Uncompacted `.NET` Large Object Heap (LOH) allocations in both test and production paths: e.g., `File.ReadAllBytes` + `DecryptBytes` `MemoryStream` buffering up to `64 MiB` for snapshot manifests ([`BackupEngine.cs:177`](../cloudbridge%20linux/src/CloudBridge.Core/BackupEngine.cs#L177)), `SodiumStream.Decrypt` allocating `new byte[ChunkSize]` (`1 MiB`) + `new byte[ChunkSize + 17]` on the LOH **on every single decrypted file/record** in v0.4.0 ([`SodiumStream.cs:50`](../cloudbridge/src/CloudBridge/SodiumStream.cs#L50), fixed with `ArrayPool` in v0.5.0 [`SodiumStream.cs:52`](../cloudbridge%20linux/src/CloudBridge.Core/SodiumStream.cs#L52)), and 40 MiB / 96 MiB whole-array allocations in `CloudBridge.Tests/Program.cs`.

---

## 2. Cryptography, Wire Format & Secret Hygiene Dissection

### 2.1 Cipher Suite & Native P/Invoke Architecture
- **AEAD Stream Primitive:** `libsodium` `crypto_secretstream_xchacha20poly1305` (XChaCha20 stream cipher + Poly1305 MAC + per-chunk state ratcheting), called via Cdecl `[DllImport("libsodium")]` in [`Sodium.cs:62-72`](../cloudbridge/src/CloudBridge/Sodium.cs#L62-L72) (v0.4.0) and [`Sodium.cs:109-119`](../cloudbridge%20linux/src/CloudBridge.Core/Sodium.cs#L109-L119) (v0.5.0). No `.NET` AES/ChaCha cipher is used anywhere.
- **`.NET` Crypto Primitives Used:**
  - `SHA256` / `IncrementalHash(HashAlgorithmName.SHA256)` for plaintext file digests, `.cbp` pack digests, `PackJournal` target binding, and `SingleInstance` lock hashing.
  - `RandomNumberGenerator.GetBytes` for 16-byte KDF salts ([`VaultService.cs:15`](../cloudbridge%20linux/src/CloudBridge.Core/VaultService.cs#L15)), 32-byte `connections.key` ([`ConfigKeyStore.cs:24`](../cloudbridge%20linux/src/CloudBridge.Core/ConfigKeyStore.cs#L24)), and 32-byte `RCLONE_RC_PASS` ([`TransferSession.cs:31`](../cloudbridge%20linux/src/CloudBridge.Core/TransferSession.cs#L31)). Vault keys (`32` B) use `libsodium` `randombytes_buf` ([`Sodium.cs:98`](../cloudbridge%20linux/src/CloudBridge.Core/Sodium.cs#L98)).
  - `ProtectedData.Protect` / `Unprotect` (`DataProtectionScope.CurrentUser`, `optionalEntropy: null`) for Windows DPAPI protection of `connections.key` ([`RcloneClient.cs:39-41`](../cloudbridge/src/CloudBridge/RcloneClient.cs#L39-L41), [`ConfigKeyStore.cs:51,64`](../cloudbridge%20linux/src/CloudBridge.Core/ConfigKeyStore.cs#L51-L64)).

### 2.2 Stream Framing (`.cbs`), Packed Containers (`.cbp`) & `FORMAT.md` Discrepancies
1. **`.cbs` Stream Framing ([`SodiumStream.cs`](../cloudbridge%20linux/src/CloudBridge.Core/SodiumStream.cs#L13-L88)):**
   - **Header (`32` bytes):** `8`-byte ASCII magic `CBSOD002` + `24`-byte `crypto_secretstream_xchacha20poly1305` stream header (internally generated CSPRNG nonce/HChaCha20 input via `init_push`).
   - **Chunk Records:** `ChunkSize = 1,048,576` (`1 MiB`). Each record prefixes a **signed** 4-byte little-endian `Int32` (`BinaryPrimitives.WriteInt32LittleEndian` / `ReadInt32LittleEndian`, lines `39, 60`) — whereas [`FORMAT.md:11`](../cloudbridge/FORMAT.md#L11) describes it as an *"unsigned little-endian integer"*. Because `Decrypt` validates `if (size < 17 || size > ChunkSize + 17)` (line `61`), negative `Int32` values (`>= 0x80000000` unsigned) are safely rejected before allocation.
   - **Non-Standard Mandatory Empty `TAG_FINAL` Frame:** `Encrypt` loops `int count = input.Read(plain, 0, bufferSize); byte tag = count == 0 ? (byte)3 : (byte)0;` (lines `36-37`). Consequently, `TAG_FINAL (3)` is **never** attached to the final non-empty plaintext chunk; every stream (including non-empty ones) appends a trailing 0-byte plaintext `TAG_FINAL` frame (`4`-byte length `17` + `17`-byte tag = `21` extra bytes). Furthermore, `Decrypt` (line `65`) explicitly rejects `(tag == 3 && count != 0)`, rejecting standard `libsodium` streams that fold `TAG_FINAL` onto the final data chunk.
   - **Short-Read Sensitivity:** `Encrypt` performs a single `input.Read(plain, 0, bufferSize)` per frame rather than `ReadAtLeast` / full-chunk loop, so slow/pipe streams emit variable-sized ciphertext frames leaking read boundaries.

2. **`.cbp` Pack Container Framing ([`PackedBackup.cs`](../cloudbridge%20linux/src/CloudBridge.Core/PackedBackup.cs#L82-L215)):**
   - Begins with `8`-byte unauthenticated ASCII magic `CBPACK03` (`PackedBackup.cs:86`), followed by up to `4,096` concatenated `CBSOD002` record streams (`SegmentSize = 4 MiB` max plaintext per record; pack cap `16`, `64` [default], or `128 MiB`).
   - Container-level integrity relies on the encrypted `VaultSnapshot` index storing `(PackId, Offset, EncryptedLength, PlainLength, RecordId, PackSize, PackSha256)` per `VaultPart` ([`BackupEngine.cs:228-230`](../cloudbridge%20linux/src/CloudBridge.Core/BackupEngine.cs#L228-L230), [`PackRestore.cs:51`](../cloudbridge%20linux/src/CloudBridge.Core/PackRestore.cs#L51)).

3. **PROVEN `FORMAT.md` / `TEST-RESULTS.md` Discrepancy in `v0.5.0` (`PendingChunk` Schema Drift):**
   - [`cloudbridge linux/FORMAT.md:72`](../cloudbridge%20linux/FORMAT.md#L72) (byte-identical SHA-256 `E60D8D76...` to v0.4.0) states: *"JSON fields are `Format` (3)... Each chunk stores `Path`, `FileSize`, `FileSha256`, `Modified`, `Index`, `ChunkSha256`, and `Part`"*.
   - [`cloudbridge linux/TEST-RESULTS.md:12`](../cloudbridge%20linux/TEST-RESULTS.md#L12) claims: *"The Windows build is unchanged in format: the same vault layout, contexts, and checkpoints are used on both platforms"*.
   - **Actual Code Reality:** In v0.4.0 ([`cloudbridge/src/CloudBridge/PackedBackup.cs:16`](../cloudbridge/src/CloudBridge/PackedBackup.cs#L16)), `PendingChunk` includes `string ChunkSha256`. In v0.5.0 ([`cloudbridge linux/src/CloudBridge.Core/PackedBackup.cs:16`](../cloudbridge%20linux/src/CloudBridge.Core/PackedBackup.cs#L16)), `ChunkSha256` was **deleted** without incrementing `PendingPack.Format` (still `3` at lines `34, 58`). Any v0.5.0 `.resume` checkpoint cannot be read by v0.4.0 (`!Regex.IsMatch(chunk.ChunkSha256 ...)` / null failure).

### 2.3 Domain-Separated AAD Context Hierarchy
Every chunk in every `CBSOD002` stream authenticates a UTF-8 AAD string:
- **Vault Key Envelope (`vault.json` & `sodium-profile.json`):** `wrap|2|<VaultId>|<SaltBase64>|<Operations>|<MemoryBytes>` ([`VaultService.cs:12`](../cloudbridge%20linux/src/CloudBridge.Core/VaultService.cs#L12))
- **Legacy v0.3 Object (`objects/<id>.cbs`):** `object|2|<jobId>|<objectId>` ([`BackupEngine.cs:23`](../cloudbridge%20linux/src/CloudBridge.Core/BackupEngine.cs#L23))
- **Snapshot Manifest (`snapshots/<id>.cbs`):** `snapshot|2|<jobId>|<snapshotId>` ([`BackupEngine.cs:24`](../cloudbridge%20linux/src/CloudBridge.Core/BackupEngine.cs#L24)) *(retains `2` in AAD even for `VaultSnapshot.Format = 3`)*
- **Packed Record (`packs/<id>.cbp` slice):** `record|3|<jobId>|<recordId>` ([`BackupEngine.cs:25`](../cloudbridge%20linux/src/CloudBridge.Core/BackupEngine.cs#L25))
- **Local Resume Checkpoint (`pending/<jobId>/<packId>.resume`):** `resume|3|<jobId>|<SHA256(FullSource|VaultRoot)>|<packId>` ([`PackedBackup.cs:28,33`](../cloudbridge%20linux/src/CloudBridge.Core/PackedBackup.cs#L28-L33))

### 2.4 KDF, Key Wrapping & Metadata Leakage
- **KDF (`Sodium.Derive`, [`Sodium.cs:100-108`](../cloudbridge%20linux/src/CloudBridge.Core/Sodium.cs#L100-L108)):** `crypto_pwhash` with `ALG_ARGON2ID13 (2)`, `opslimit = 3`, `memlimit = 64 MiB` (`67,108,864` B), `16`-byte CSPRNG salt, `32`-byte derived key. Reader enforces `operations ∈ [2, 6]` and `memoryBytes ∈ [64 MiB, 256 MiB]` prior to native allocation.
- **No Password Policy:** Accepts `""` (0-byte empty string) and 1-char passwords ([`Program.cs:92`](../cloudbridge%20linux/tests/CloudBridge.Tests/Program.cs#L92)).
- **Canary-Only Local Profile:** `sodium-profile.json` wraps a discarded random key under `VaultId = "local-profile"` ([`VaultService.cs:64-68`](../cloudbridge%20linux/src/CloudBridge.Core/VaultService.cs#L64-L68)). Each job independently wraps its own 32-byte random key in cloud `vault.json` using the session password. There is no master key hierarchy: if a user initializes a second PC with a different password, existing cloud jobs and new local jobs become mutually incompatible within the same session.
- **Filename & Traffic-Analysis Leakage:**
  - Plaintext directory hierarchy and filenames are hidden inside the encrypted monolithic `snapshots/<id>.cbs` JSON index (capped at `64 MiB` uncompressed JSON, [`BackupEngine.cs:19,104`](../cloudbridge%20linux/src/CloudBridge.Core/BackupEngine.cs#L19)).
  - **Zero ciphertext padding:** Small incremental edits produce small `.cbp` packs whose exact plaintext size (`PackSize - 61` for `<= 1 MiB` single-file edits) is exposed directly to the storage provider.
  - **Plaintext snapshot timestamps:** Cloud snapshot filenames `snapshots/yyyyMMddTHHmmssfffZ_<guid>.cbs` ([`BackupEngine.cs:95`](../cloudbridge%20linux/src/CloudBridge.Core/BackupEngine.cs#L95)) leak exact backup activity schedules to millisecond resolution.

### 2.5 Secret Zeroization & GC Pinning Failures
Despite wrapping `sodium_malloc` / `sodium_free` in `SecureMemory` ([`Sodium.cs:11-40`](../cloudbridge%20linux/src/CloudBridge.Core/Sodium.cs#L11-L40)), secret hygiene is undermined across the `.NET` managed boundary:
1. **Immutable `System.String` Passphrases on Managed Heap:**
   - `VaultService.UnlockAsync(string text, ...)` ([`VaultService.cs:52`](../cloudbridge%20linux/src/CloudBridge.Core/VaultService.cs#L52)), WPF `password.Password` ([`UnlockWindow.cs:31`](../cloudbridge/src/CloudBridge/UnlockWindow.cs#L31)), and Avalonia `TextBox { PasswordChar = '•' }` ([`UnlockWindow.cs:21,41`](../cloudbridge%20linux/src/CloudBridge.Desktop/UnlockWindow.cs#L21-L41)) allocate immutable UTF-16 `string` objects on the GC heap that cannot be zeroed and survive until arbitrary GC compaction/collection or crash dump. Avalonia `UnlockWindow` does not even clear `password.Text` on `Closed`.
2. **Unpinned `byte[]` Exports of Raw 256-Bit Vault Keys:**
   - `SecureMemory.Export()` ([`Sodium.cs:27-31`](../cloudbridge%20linux/src/CloudBridge.Core/Sodium.cs#L27-L31)) copies guarded `sodium_malloc` key material into an **unpinned** `new byte[Length]` on the GC heap!
   - Called on **every wrap** ([`VaultService.cs:19`](../cloudbridge%20linux/src/CloudBridge.Core/VaultService.cs#L19)), **every unwrap** via `SodiumStream.DecryptBytes` → `MemoryStream.ToArray()` ([`VaultService.cs:27`](../cloudbridge%20linux/src/CloudBridge.Core/VaultService.cs#L27)), and **every cached vault key clone** in `SecureMemory.Clone()` ([`Sodium.cs:33-38`](../cloudbridge%20linux/src/CloudBridge.Core/Sodium.cs#L33-L38)) instead of copying native-to-native between `sodium_malloc` pointers!
3. **Unzeroed `MemoryStream` Resize Buffers (`SodiumStream.DecryptBytes`):**
   - [`SodiumStream.cs:83-88`](../cloudbridge%20linux/src/CloudBridge.Core/SodiumStream.cs#L83-L88) writes decrypted vault keys, snapshot JSON indexes, and `.resume` journals into `new MemoryStream()` with default capacity `0`. Every capacity doubling allocates a new `byte[]` and abandons the prior smaller `byte[]` **unzeroed** on the GC heap; `finally { ZeroMemory(output.GetBuffer()); }` zeroes only the final buffer!
4. **Permanent Plaintext `RcloneClient.password` & Unzeroed `ConfigKeyStore` Buffers:**
   - [`RcloneClient.cs:25,35`](../cloudbridge%20linux/src/CloudBridge.Core/RcloneClient.cs#L25-L35) holds the Base64-encoded 32-byte `connections.key` in `private string password` for the entire lifetime of the process and injects `RCLONE_CONFIG_PASS` into every child environment ([`RcloneClient.cs:66`](../cloudbridge%20linux/src/CloudBridge.Core/RcloneClient.cs#L66)).
   - [`ConfigKeyStore.cs:24,32,38,60-78`](../cloudbridge%20linux/src/CloudBridge.Core/ConfigKeyStore.cs#L24-L78) allocates `byte[] key`, `file`, `payload`, and `content` without zeroing any of them on success paths.

---

## 3. Multi-Cloud Storage & Sync Engine Dissection

### 3.1 Subprocess & Loopback RC Daemon Architecture
CloudBridge implements **zero** native HTTP/REST cloud provider clients in C#; all storage operations shell out to `rclone v1.75.1`:
1. **Persistent Loopback HTTP Daemon (`TransferSession`, [`TransferSession.cs`](../cloudbridge%20linux/src/CloudBridge.Core/TransferSession.cs#L18-L101)):**
   - Spawns `rclone rcd --rc-addr 127.0.0.1:0 --rc-server-write-timeout 0 --immutable ...` authenticated via HTTP Basic Auth (`RCLONE_RC_USER=cloudbridge`, random 32-byte Base64 `RCLONE_RC_PASS` passed via environment variable).
   - Scrapes `stderr` with regex `http://127\.0\.0\.1:(\d+)/` (15s startup timeout) to find the bound loopback port, then issues JSON POSTs to `operations/copyfile` (for concurrent `.cbp` pack uploads), `operations/list` (for resume check), and `core/stats` (polled every `750 ms` by `PackedBackup.Monitor`).
2. **High-Overhead One-Shot CLI Subprocesses (`RcloneClient.RunAsync`, [`BackupEngine.cs`](../cloudbridge%20linux/src/CloudBridge.Core/BackupEngine.cs)):**
   - Metadata checks (`backend features`, `lsf`), `vault.json` upload, `snapshots/<id>.cbs` upload, local directory scanning (`lsjson --hash`), and **all restore downloads** bypass `TransferSession` and spawn fresh `rclone` processes!
   - **Double Local Full-Tree Hashing Overhead:** [`BackupEngine.cs:55`](../cloudbridge%20linux/src/CloudBridge.Core/BackupEngine.cs#L55) runs `rclone lsjson <job.Source> --recursive --hash --hash-type SHA-256`, forcing `rclone` to read and SHA-256 hash **every byte of every file in the source folder on every scheduled run** (ignoring unchanged size+mtime!), buffering the entire JSON output into a single C# `string`. Then, for every new/modified file, `PackedBackup.AddFile` ([`PackedBackup.cs:172-183`](../cloudbridge%20linux/src/CloudBridge.Core/PackedBackup.cs#L172-L183)) reads and SHA-256 hashes the file **a second time** during encryption!
   - **Restore Subprocess Multiplication:** [`BackupEngine.Download`](../cloudbridge%20linux/src/CloudBridge.Core/BackupEngine.cs#L247-L255) spawns **two sequential `rclone` processes per pack/object** (`rclone lsjson --stat` followed by `rclone copyto --max-transfer ... --cutoff-mode hard`), incurring repeated Go runtime init + OAuth/TLS handshakes.

### 3.2 OAuth, Rate-Limiting, Quota Pooling & Sync Capabilities Matrix

| Capability | Actual Source Implementation | Evidence |
|---|---|---|
| **Config Encryption** | `rclone` native `RCLONE_ENCRYPT_V0` (`connections.conf`), unlocked via `RCLONE_CONFIG_PASS` env var | [`RcloneClient.cs:36-41,66`](../cloudbridge%20linux/src/CloudBridge.Core/RcloneClient.cs#L36-L66) |
| **OAuth Setup State Machine** | Wraps `rclone config create/update --non-interactive` (8-min timeout); requires user-owned Desktop OAuth `client_id` + `client_secret` for Google Drive (`scope = drive.file`); deletes unfinished remote on dialog close | [`ConnectionWindow.cs:63-107`](../cloudbridge%20linux/src/CloudBridge.Desktop/ConnectionWindow.cs#L63-L107) |
| **Rate-Limit / Retry** | CLI: `--retries 3 --contimeout 20s --timeout 2m`; `rcd`: `--low-level-retries 5` + 3 attempts (`1s`, `2s` backoff) in `TransferSession.CopyAsync`. **Zero HTTP 429 `Retry-After` parsing or adaptive concurrency throttling.** | [`TransferSession.cs:33,76-88`](../cloudbridge%20linux/src/CloudBridge.Core/TransferSession.cs#L76-L88) |
| **Multi-Cloud Quota Pooling / Sharding** | **0% Implemented.** Each `BackupJob` maps 1:1 to a single `string Remote`. No `rclone about` quota queries, no cross-cloud striping, no sharding, no multi-cloud failover. | [`Models.cs:18,29`](../cloudbridge%20linux/src/CloudBridge.Core/Models.cs#L18-L29) |
| **Two-Way Sync & Conflict Resolution** | **0% Implemented.** Strictly one-way, single-writer append-only backup. Concurrent multi-PC writes to one vault are uncoordinated. | [`BackupEngine.cs:33-113`](../cloudbridge%20linux/src/CloudBridge.Core/BackupEngine.cs#L33-L113) |
| **Deletion & Retention Semantics** | **"Retain Everything Forever" Trap:** `BackupCore` clones `previous.Files` (`BackupEngine.cs:52`) and never removes locally deleted files! Restoring "Latest backup" resurrects all historically deleted files; zero snapshot pruning or unreferenced pack GC exists. | [`BackupEngine.cs:52,72-88`](../cloudbridge%20linux/src/CloudBridge.Core/BackupEngine.cs#L52-L88) |
| **Delta / Block Deduplication** | **Whole-File Only:** Unchanged `(Path, Size, Sha256)` reuses prior `VaultPart` metadata; a 1-byte edit to a 10 GiB file re-encrypts and re-uploads all 10 GiB. Identical files at different paths are NOT deduplicated. | [`BackupEngine.cs:80-84`](../cloudbridge%20linux/src/CloudBridge.Core/BackupEngine.cs#L80-L84) |
| **Partial / HTTP Range Reads** | **0% Implemented (Full-Pack Buffering):** Despite storing exact `Offset` and `EncryptedLength` per 4 MiB record, [`PackRestore.cs:48`](../cloudbridge%20linux/src/CloudBridge.Core/PackRestore.cs#L48) downloads the **entire 16–128 MiB `.cbp` pack** to local disk (4-pack LRU cache) before seeking locally. | [`PackRestore.cs:38-57`](../cloudbridge%20linux/src/CloudBridge.Core/PackRestore.cs#L38-L57) |
| **VFS / FUSE / Cloud Mount** | **0% Implemented** in both v0.4.0 and v0.5.0. | Confirmed across all `.cs` files |

---

## 4. Evolution Analysis: `v0.4.0` (`cloudbridge`) vs `v0.5.0` (`cloudbridge linux`)

1. **Architecture & Project Split:**
   - Extracted backend into `CloudBridge.Core` (`net9.0`).
   - Kept legacy WPF app in `src/CloudBridge/` — **all 9 `.cs`/`.xaml`/`.manifest` files in `cloudbridge linux/src/CloudBridge/` are 100% SHA-256 byte-identical to `cloudbridge/src/CloudBridge/`** (even `<Version>0.4.0</Version>` in `CloudBridge.csproj:10` was left unbumped).
   - Added `CloudBridge.Desktop` (`net9.0`, Avalonia `11.3.22`) targeting Windows and Linux x64.
2. **Cross-Platform Additions in `v0.5.0`:**
   - [`Platform.cs`](../cloudbridge%20linux/src/CloudBridge.Core/Platform.cs): OS-aware `PathComparison` (`OrdinalIgnoreCase` on Windows, `Ordinal` on Unix) and boundary-safe `IsWithin`.
   - [`BackupEngine.cs:218-226`](../cloudbridge%20linux/src/CloudBridge.Core/BackupEngine.cs#L218-L226): Replaced host-dependent `Path.GetInvalidFileNameChars()` with hardcoded Windows-strict `InvalidNameCharacters` so Linux backups remain restorable on Windows.
   - [`ConfigKeyStore.cs`](../cloudbridge%20linux/src/CloudBridge.Core/ConfigKeyStore.cs): Added 4-byte header `CBK\x01` (Windows DPAPI) vs `CBK\x02` (Unix raw plaintext `0600` file; **no Linux Secret Service / `libsecret` keyring**).
   - [`LinuxAutostart.cs`](../cloudbridge%20linux/src/CloudBridge.Core/LinuxAutostart.cs) & [`StartupIntegration.cs`](../cloudbridge%20linux/src/CloudBridge.Desktop/StartupIntegration.cs): XDG `~/.config/autostart/cloudbridge.desktop` generator.
   - [`RcloneLocator.cs`](../cloudbridge%20linux/src/CloudBridge.Core/RcloneLocator.cs) & [`Sodium.cs:54-88`](../cloudbridge%20linux/src/CloudBridge.Core/Sodium.cs#L54-L88): Multi-OS native binary/library search (`PATH` fallback for `rclone`; `libsodium.so.23/.26/.18/.so` + `CLOUDBRIDGE_LIBSODIUM` override).
   - [`SingleInstance.cs`](../cloudbridge%20linux/src/CloudBridge.Desktop/SingleInstance.cs): Replaced Windows named `Mutex` with `FileShare.None` lockfile in `Path.GetTempPath()`.
   - [`TrayIcon.cs`](../cloudbridge%20linux/src/CloudBridge.Desktop/TrayIcon.cs) & [`OpenPath.cs`](../cloudbridge%20linux/src/CloudBridge.Desktop/OpenPath.cs): Avalonia `StatusNotifierItem`/AppIndicator tray + `notify-send` + `xdg-open`.
3. **Engine Throughput Optimizations in `v0.5.0` (Measured 36% Test Suite Speedup: `85.69s` → `54.86s`):**
   - Cached unwrapped 32-byte vault keys per `job.Id` in `VaultService.vaultKeys` ([`VaultService.cs:46,85-93`](../cloudbridge%20linux/src/CloudBridge.Core/VaultService.cs#L85-L93)).
   - Removed unused plaintext `IncrementalHash` inside `SodiumStream.Encrypt` ([`SodiumStream.cs:22`](../cloudbridge%20linux/src/CloudBridge.Core/SodiumStream.cs#L22)).
   - Pooled `1 MiB` buffers via `ArrayPool<byte>.Shared` in `SodiumStream.Decrypt` ([`SodiumStream.cs:52,76`](../cloudbridge%20linux/src/CloudBridge.Core/SodiumStream.cs#L52)).
   - Eliminated per-chunk `ChunkSha256` computation and added incremental `HashingStream` during `.cbp` pack creation so `Seal()` no longer re-reads sealed 64 MiB packs from disk ([`PackedBackup.cs:197-198,221-224,299-313`](../cloudbridge%20linux/src/CloudBridge.Core/PackedBackup.cs#L299-L313)).
   - Added `--transfers 8 --checkers 8 --buffer-size 16M --drive-chunk-size 16M --drive-upload-cutoff 16M` to `rclone rcd` ([`TransferSession.cs:33`](../cloudbridge%20linux/src/CloudBridge.Core/TransferSession.cs#L33)).

---

## 5. UI & UX Dissection: WPF vs `CloudBridge.Desktop` (Avalonia `11.3.22`)

### 5.1 CRITICAL SHOWSTOPPER: UI-Thread Sync-Over-Async Deadlock in `CloudBridge.Desktop`
In [`cloudbridge linux/src/CloudBridge.Desktop/MainWindow.axaml.cs:272-278`](../cloudbridge%20linux/src/CloudBridge.Desktop/MainWindow.axaml.cs#L272-L278), the port from WPF replaced `new UnlockWindow(vault) { Owner = this }.ShowDialog() == true` with:
```csharp
private bool EnsureUnlocked()
{
    if (vault.IsUnlocked) return true;
    bool result = new UnlockWindow(vault).ShowDialog<bool>(this).GetAwaiter().GetResult();
    foreach (var job in jobs.Where(j => j.EncryptionVersion == 2)) job.Status = result ? "Unlocked" : "Locked";
    RefreshView(); return result;
}
```
- **Why It Deadlocks 100% of the Time:** Unlike WPF's `Window.ShowDialog()` (which pushes a nested Win32 `DispatcherFrame` message pump), Avalonia `11.3.22`'s `Window.ShowDialog<TResult>(Window owner)` is strictly asynchronous and requires the calling UI `Dispatcher` thread to return to the main event loop to render the dialog and pump input/close events. Blocking the UI thread with `.GetAwaiter().GetResult()` **permanently freezes the entire Avalonia UI** before `UnlockWindow` can even paint or receive input!
- **Empirical Verification (`DialogProbe` against Avalonia `11.3.22`):** Executed [`target/swarm/forensics-a/dialog_probe/Program.cs`](target/swarm/forensics-a/dialog_probe/Program.cs):
  ```text
  Calling dlg.ShowDialog<bool>(owner).GetAwaiter().GetResult() on Avalonia UI thread...
  EMPIRICAL_RESULT: UI_THREAD_DEADLOCK_CONFIRMED (ShowDialog<bool>.GetAwaiter().GetResult() blocked UI message pump; dialog Opened/Close could never pump)
  ExitCode=42
  ```
- **Blast Radius:** Freezes **every encrypted workflow** in `CloudBridge.Desktop`: startup auto-unlock when jobs exist (`line 56`), `RunJobs` / Back up / Preview (`line 132`), `+ Add folder` (`line 197`), `Edit` (`line 214`), `Restore…` (`line 252`), `Set encryption password` / `Unlock backups` (`line 284`), and `Recover encrypted backup` (`line 291`). The original author's smoke test in `TEST-RESULTS.md:9` only launched the app with an empty `settings.json` (`jobs.Count == 0`) and never clicked any unlock-gated button!

### 5.2 Binding, Rendering & UX Deficiencies
- **Untyped Reflection Bindings:** [`CloudBridge.Desktop.csproj:13`](../cloudbridge%20linux/src/CloudBridge.Desktop/CloudBridge.Desktop.csproj#L13) explicitly sets `<AvaloniaUseCompiledBindingsByDefault>false</AvaloniaUseCompiledBindingsByDefault>` and [`MainWindow.axaml:19,72`](../cloudbridge%20linux/src/CloudBridge.Desktop/MainWindow.axaml#L19-L88) omits `x:DataType`, forcing runtime reflection property lookups across `ConnectionsList` and `JobList` templates.
- **`WindowNotificationManager` Leak:** [`TrayIcon.cs:100-101`](../cloudbridge%20linux/src/CloudBridge.Desktop/TrayIcon.cs#L100-L101) allocates `new WindowNotificationManager(window)` on **every** Windows notification call, stacking visual overlay managers onto `MainWindow` without disposal.
- **WPF Software-Only Rasterization:** [`App.xaml.cs:14`](../cloudbridge/src/CloudBridge/App.xaml.cs#L14) forces `RenderOptions.ProcessRenderMode = RenderMode.SoftwareOnly`, disabling GPU composition across all windows.
- **Vanilla GNOME Hidden-Window Lockout:** On GNOME desktops without AppIndicator (`tray.Warning != null`), [`MainWindow.axaml.cs:325-328`](../cloudbridge%20linux/src/CloudBridge.Desktop/MainWindow.axaml.cs#L325-L328) (`OnClosing`) still cancels window close and calls `Hide()`, leaving the process invisible with **no tray icon** and **no IPC activation in `SingleInstance`** to reopen the window!
- **Coarse All-or-Nothing Restore UX:** [`RestoreWindow.cs`](../cloudbridge%20linux/src/CloudBridge.Desktop/RestoreWindow.cs) only allows restoring an **entire snapshot** into a brand-new timestamped directory; users cannot inspect snapshot contents or restore a single file/subfolder.

---

## 6. Master Vulnerability, Race Condition & Bottleneck Ledger

| ID | Severity | Category | Exact Location(s) | Empirical Finding & Exploit / Failure Mechanism |
|---|---|---|---|---|
| **CB-01** | **CRITICAL** | UI Deadlock | [`CloudBridge.Desktop/MainWindow.axaml.cs:275`](../cloudbridge%20linux/src/CloudBridge.Desktop/MainWindow.axaml.cs#L275) *(called at lines 56, 132, 197, 214, 252, 284, 291)* | Synchronous `.ShowDialog<bool>(this).GetAwaiter().GetResult()` on Avalonia UI thread deadlocks 100% of password setup/unlock/backup/restore flows (`ExitCode=42` empirically verified). |
| **CB-02** | **HIGH** | Secret Leak (CLI Args) | [`CloudBridge/ConnectionWindow.cs:82,88`](../cloudbridge/src/CloudBridge/ConnectionWindow.cs#L82-L88)<br>[`CloudBridge.Desktop/ConnectionWindow.cs:87,93`](../cloudbridge%20linux/src/CloudBridge.Desktop/ConnectionWindow.cs#L87-L93) | Passes OAuth `client_secret` and provider secrets (`--result <password/secret_key>`) as plaintext OS command-line arguments to `rclone`, exposing them via world-readable `/proc/<pid>/cmdline` on Linux and Event ID 4688 / WMI on Windows. |
| **CB-03** | **HIGH** | Silent Data Loss (Linux) | [`CloudBridge.Core/BackupEngine.cs:52-53,80-87`](../cloudbridge%20linux/src/CloudBridge.Core/BackupEngine.cs#L52-L87) | Uses `StringComparer.OrdinalIgnoreCase` for `files` and `directories` dictionaries on case-sensitive Linux filesystems. Sibling files differing only in case (e.g., `Makefile` and `makefile`, or `a.txt` and `A.txt`) **silently overwrite each other in `files[path]` during backup without error**, permanently omitting one file from the snapshot! |
| **CB-04** | **HIGH** | Key Storage + TOCTOU | [`CloudBridge.Core/ConfigKeyStore.cs:70-82`](../cloudbridge%20linux/src/CloudBridge.Core/ConfigKeyStore.cs#L70-L82) | Stores 32-byte `connections.key` in **raw plaintext** (`CBK\x02` + key) on Linux (zero OS keyring/Secret Service integration) AND writes `connections.key.tmp` via `File.WriteAllBytes` (default `umask` `0644` world-readable) **before** calling `File.SetUnixFileMode(..., 0600)`. |
| **CB-05** | **HIGH** | Library Injection | [`CloudBridge.Core/Sodium.cs:66-70`](../cloudbridge%20linux/src/CloudBridge.Core/Sodium.cs#L66-L70) | Loads arbitrary native binary path from `CLOUDBRIDGE_LIBSODIUM` env var prior to bundled `libsodium` without path/signature validation. |
| **CB-06** | **MEDIUM-HIGH** | Heap Secret Persistence | [`Sodium.cs:29,35`](../cloudbridge%20linux/src/CloudBridge.Core/Sodium.cs#L29-L35), [`SodiumStream.cs:83-88`](../cloudbridge%20linux/src/CloudBridge.Core/SodiumStream.cs#L83-L88), [`VaultService.cs:19,27,52`](../cloudbridge%20linux/src/CloudBridge.Core/VaultService.cs#L19-L52), [`RcloneClient.cs:25,35`](../cloudbridge%20linux/src/CloudBridge.Core/RcloneClient.cs#L25-L35) | Passwords, `RCLONE_CONFIG_PASS`, exported 256-bit vault keys, and `MemoryStream` growth buffers reside in unpinned/unzeroed managed GC memory (`string` and `byte[]`). |
| **CB-07** | **MEDIUM** | Data Race & Auth Bypass | [`CloudBridge.Core/VaultService.cs:46,74,79,85-98`](../cloudbridge%20linux/src/CloudBridge.Core/VaultService.cs#L85-L98) | Unsynchronized `Dictionary<string, SecureMemory> vaultKeys` accessed concurrently from ThreadPool (`BackupCore`/`RestoreCore`) and UI thread (`Lock`/`UnlockAsync`), risking `Use-After-Free` / dictionary corruption; furthermore, cached `Open(id, envelope)` ignores `envelope` entirely on cache hit instead of verifying header authenticity. |
| **CB-08** | **MEDIUM** | Local DoS & Process Leak | [`SingleInstance.cs:27-32`](../cloudbridge%20linux/src/CloudBridge.Desktop/SingleInstance.cs#L27-L32)<br>[`CloudBridge.Core/ProcessLease.cs:23`](../cloudbridge%20linux/src/CloudBridge.Core/ProcessLease.cs#L23) | Deterministic `/tmp/cloudbridge-<hash>.lock` in world-writable `/tmp` allows any local user to block app startup; `ProcessLease` is a no-op on Linux (missing `PR_SET_PDEATHSIG`), leaving `rclone rcd` running on crash. |
| **CB-09** | **MEDIUM** | I/O & Memory Bottlenecks | [`BackupEngine.cs:55,177,247`](../cloudbridge%20linux/src/CloudBridge.Core/BackupEngine.cs#L55)<br>[`PackRestore.cs:48`](../cloudbridge%20linux/src/CloudBridge.Core/PackRestore.cs#L48) | Full-tree SHA-256 disk read on every 15-min scan + second full read of changed files during encrypt; full 16–128 MiB pack download on restore (no HTTP Range reads); 2 subprocess spawns per restored pack; unbounded cloud storage growth due to immortal deleted files. |

---

## 7. Reusable Architectural Gems Worth Porting to Rust ZeroVault

While the `.NET`/Avalonia/WPF runtime, `string`/`byte[]` memory handling, and one-shot `rclone` CLI wrappers should be retired completely, **seven battle-tested design patterns** in CloudBridge are genuinely well-engineered and directly strengthen the merged Rust architecture:

1. **Strict Domain-Separated Context AAD Binding (`wrap|`, `snapshot|`, `record|`, `resume|`):**
   - Binding every AEAD chunk's Associated Data to `(domain, format_version, vault_id, object_or_record_id, kdf_metadata)` ([`VaultService.cs:12`](../cloudbridge%20linux/src/CloudBridge.Core/VaultService.cs#L12), [`BackupEngine.cs:23-25`](../cloudbridge%20linux/src/CloudBridge.Core/BackupEngine.cs#L23-L25)) cleanly prevents cross-vault transplant, chunk splicing, and KDF parameter tampering.
2. **Bounded Pack Aggregation (`CBPACK03` Concept) Upgraded with HTTP Range Reads:**
   - Packing small files and 4 MiB segments into 16–64 MiB immutable `.cbp` containers while keeping each record independently AEAD-framed with explicit `(PackId, Offset, EncryptedLength, PlainLength, RecordId)` cut small-file local transfer time by **17.1×** (`21.79s` → `1.27s`). In Rust, pairing this exact offset-indexed pack layout with **HTTP `Range: bytes=Offset..(Offset+EncryptedLength-1)`** eliminates CloudBridge's whole-pack restore amplification while preserving small-file upload batching!
3. **AEAD-Authenticated Local Upload Resume Checkpoints (`PackJournal`):**
   - Persisting encrypted `.resume` checkpoints bound to `SHA256(Source|Destination)` after `fsync`-sealing each pack ([`PackedBackup.cs:216-229`](../cloudbridge%20linux/src/CloudBridge.Core/PackedBackup.cs#L216-L229)) and reconciling against remote pack listings + current exclusion rules on restart provides crash-resilient multi-gigabyte upload resumption without corrupting cloud state.
4. **Two-Phase Immutable Snapshot Publication & `.partial` Atomic Restore Commit:**
   - Uploading immutable packs first (`--immutable`) and publishing the snapshot manifest last ([`BackupEngine.cs:96-112`](../cloudbridge%20linux/src/CloudBridge.Core/BackupEngine.cs#L96-L112)), paired with restoring into `<file>.<uuid>.partial` with exclusive lock, verifying AEAD + exact size + whole-file digest + reparse-point absence before atomic rename ([`BackupEngine.cs:145-158`](../cloudbridge%20linux/src/CloudBridge.Core/BackupEngine.cs#L145-L158)), guarantees incomplete or tampered plaintext is never exposed at target paths.
5. **Cross-OS Portable Path Validation & Ancestor Collision Checks:**
   - Validating paths against Windows reserved names (`CON`, `AUX`, `COM1`, superscript `COM¹`–`COM³`), ADS colons, trailing dots/spaces, symlinks/reparse points, and file-vs-ancestor-directory collisions ([`BackupEngine.cs:185-226`](../cloudbridge%20linux/src/CloudBridge.Core/BackupEngine.cs#L185-L226)) prevents malicious cloud manifests from escaping restore roots on Windows or Linux (fixing **CB-03** by keeping Linux case-sensitivity in snapshots while warning/disambiguating on Windows restore).
6. **Pre-Allocation KDF Parameter Bounds Checking:**
   - Rejecting untrusted `vault.json` headers whose `MemoryBytes` or `Operations` fall outside `[64 MiB..256 MiB]` / `[2..6]` *before* allocating Argon2id arenas ([`Sodium.cs:102`](../cloudbridge%20linux/src/CloudBridge.Core/Sodium.cs#L102)) prevents trivial OOM DoS from tampered cloud headers.
7. **Persistent Loopback Transport + Kernel-Enforced Child Process Leases:**
   - Using Win32 `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` ([`ProcessLease.cs:17`](../cloudbridge/src/CloudBridge/ProcessLease.cs#L17)) (extended on Linux in Rust via `prctl(PR_SET_PDEATHSIG, SIGKILL)`) ensures external transport helpers never outlive a crashed parent process, while Google Drive's `drive.file` least-privilege OAuth scope ([`GOOGLE-DRIVE-SETUP.md:7`](../cloudbridge/GOOGLE-DRIVE-SETUP.md#L7)) avoids Google's restricted-scope verification wall for personal Desktop OAuth clients.

---

## 8. Read-Only Legacy Integrity Verification

Post-execution verification against [`audit/READONLY_BASELINE.txt`](audit/READONLY_BASELINE.txt) confirms **zero files created, modified, or deleted** in either legacy codebase:

| Legacy Directory | Baseline Files | Post-Audit Files | Baseline Bytes | Post-Audit Bytes | `bin`/`obj`/`work` Dirs | Newest File `LastWriteTimeUtc` | Status |
|---|---:|---:|---:|---:|---:|---|---|
| `<donor-root>\cloudbridge` | `37` | `37` | `89,165,156` | `89,165,156` | `0` | `2026-09-19T16:46:48.6086090Z` | **UNTOUCHED (`100%` INTACT)** |
| `<donor-root>\cloudbridge linux` | `65` | `65` | `178,010,385` | `178,010,385` | `0` | `2026-09-19T20:07:18.7421674Z` | **UNTOUCHED (`100%` INTACT)** |
