# Zerovault Cryptographic Specification (`SPEC_CRYPTO.md`)

**Protocol Version:** `1` (`ZVH1` / `ZVC1` / `ZVM1`)  
**Workspace:** `cloud.entropy.rs / Zerovault`  
**Mandatory Cipher:** `AES-256-GCM` via `aws-lc-rs` (hardware-accelerated `AES-NI`/`VAES`/`PCLMULQDQ` on `x86_64`, ARMv8 Crypto Extensions on `aarch64`)

---

## 1. Security Model & Zero-Knowledge Invariants

1. **Untrusted Cloud Backends:** Cloud providers (Google Drive, OneDrive, Dropbox, S3, WebDAV) are treated as honest-but-curious and actively tamper-capable adversaries.
2. **Zero Plaintext Exposure:** Cloud storage NEVER receives:
   - Plaintext file bytes
   - Plaintext file names, directory names, or file extensions
   - Plaintext directory hierarchy or file sizes beyond 4 MiB chunk quantization + padding/header framing
3. **Fail-Closed Verification:** Every remote chunk, wrapped DEK, vault header verifier, and encrypted manifest MUST pass `AES-256-GCM` tag verification before any decrypted byte is written to disk cache, returned to VFS callers, or applied to metadata state.
4. **Memory Hygiene:**
   - All key material (`MasterSeed`, `MasterKek`, `ManifestKey`, `TokenWrapKey`, `HeaderVerifierKey`, `DekBytes`, passphrases, OAuth tokens) MUST be wrapped in `zeroize::Zeroizing` or implement `ZeroizeOnDrop`.
   - `Debug` implementations on all secret-bearing structs MUST emit `"[REDACTED]"`.
   - No secret bytes, passphrases, OAuth tokens, or plaintext paths may be emitted in `INFO` or `DEBUG` logs.

---

## 2. Hardware Acceleration Mandate

Before performing production encryption or decryption, `CryptoEngine::verify_hardware_acceleration()` executes runtime CPUID / feature register verification:

- **`x86_64`:** Mandatory `aes` (`AES-NI`) **AND** `pclmulqdq` (`PCLMULQDQ`). Optionally detects `vaes`, `avx2`, `avx512f` for vectorized GHASH/AES execution in `aws-lc-rs`.
- **`aarch64`:** Mandatory `aes` **AND** `pmull` (ARMv8 Crypto Extensions).
- **Failure Behavior:** If mandatory hardware instructions are absent at runtime, fail closed with `ZeroVaultError::HardwareAccelerationUnavailable`.

---

## 3. Envelope Key Hierarchy

```text
Passphrase (Zeroizing<String>) + argon2_salt ([u8; 32], CSPRNG)
   │
   ▼ Argon2id (version 0x13, m_cost >= 65536 KiB [64 MiB], t_cost >= 3, p_cost >= 4)
MasterSeed ([u8; 32], Zeroizing)
   │
   ├──► HKDF-SHA256(salt = argon2_salt, info = "zerovault.v1.kek")       ──► MasterKek (256-bit)
   ├──► HKDF-SHA256(salt = argon2_salt, info = "zerovault.v1.manifest")  ──► ManifestKey (256-bit)
   ├──► HKDF-SHA256(salt = argon2_salt, info = "zerovault.v1.token-wrap")──► TokenWrapKey (256-bit)
   └──► HKDF-SHA256(salt = argon2_salt, info = "zerovault.v1.verifier")  ──► HeaderVerifierKey (256-bit)
```

### Policy Floor
`KdfParams::validate_production()` rejects any vault creation or unlock attempt with:
- `m_cost_kib < 65_536` (64 MiB)
- `t_cost < 3`
- `p_cost < 4`

### OS Secret Storage (`keyring`)
- Session unlock credentials and OAuth2 token bundles (encrypted under `TokenWrapKey` with AES-256-GCM before persisting) are stored in the native OS credential vault:
  - Windows 10/11: Windows Credential Manager
  - Arch Linux: Secret Service D-Bus (`libsecret` / GNOME Keyring / KWallet) or kernel `keyutils`

---

## 4. Wire Formats (Exact Byte Layouts)

All multi-byte integers in wire headers and AADs use **Little Endian (`LE`)** encoding.

### 4.1 Vault Bootstrap Header (`vault/header.zvh`)

| Offset | Size | Field | Description |
|---:|---:|---|---|
| `0` | `4` | `magic` | `b"ZVH1"` |
| `4` | `1` | `version` | `1u8` |
| `5` | `3` | `reserved` | `[0, 0, 0]` |
| `8` | `16` | `vault_id` | UUID v4/v7 bytes (big-endian UUID wire order) |
| `24` | `32` | `argon2_salt` | CSPRNG 256-bit salt |
| `56` | `4` | `m_cost_kib` | Argon2id memory in KiB (`>= 65536`) |
| `60` | `4` | `t_cost` | Argon2id iterations (`>= 3`) |
| `64` | `4` | `p_cost` | Argon2id parallelism (`>= 4`) |
| `68` | `12` | `verifier_nonce` | CSPRNG 96-bit nonce |
| `80` | `32` | `verifier_tag` | AES-256-GCM(`HeaderVerifierKey`, `verifier_nonce`, plaintext = `vault_id (16B)`, AAD = `b"ZVH1" \|\| vault_id (16B)`) |

Total fixed size: **112 bytes**.

### 4.2 Per-File DEK Wrapping (`WrappedDek`)

Each file revision receives a freshly generated random 256-bit `DEK` via `aws_lc_rs::rand::fill`:
- **Cipher:** AES-256-GCM under `MasterKek`
- **Nonce:** 96-bit CSPRNG (`[u8; 12]`)
- **AAD (25 bytes):** `b"ZV-DEK-V1" (9B) || file_id.as_bytes() (16B)`
- **Ciphertext:** `DEK (32B) || GCM_TAG (16B)` = **48 bytes**

### 4.3 4 MiB Chunk Blob (`blobs/<2-hex>/<2-hex>/<blob_uuid>.zv`)

Files are partitioned into fixed `PLAINTEXT_CHUNK_SIZE = 4_194_304` (4 MiB) chunks (`chunk_index = 0, 1, 2, ...`):
- Non-final chunks (`is_final_chunk = false`) MUST have `plaintext_len == 4_194_304`.
- Final chunk (`is_final_chunk = true`) MUST have `1 <= plaintext_len <= 4_194_304` unless `chunk_index == 0`, in which case `plaintext_len == 0` is permitted for zero-byte empty files.

#### 32-Byte Chunk Wire Header

| Offset | Size | Field | Description |
|---:|---:|---|---|
| `0` | `4` | `magic` | `b"ZVC1"` |
| `4` | `1` | `version` | `1u8` |
| `5` | `1` | `flags` | Bit `0` (`0x01`): `is_final_chunk`; bits `1..7` MUST be `0` |
| `6` | `2` | `reserved` | `[0, 0]` |
| `8` | `8` | `chunk_index` | `u64` LE (`0..`) |
| `16` | `4` | `plaintext_len` | `u32` LE (`0..=4_194_304`) |
| `20` | `12` | `nonce` | CSPRNG 96-bit nonce (fresh per encryption!) |
| `32` | `N + 16` | `ciphertext \|\| tag` | AES-256-GCM(`DEK`, `nonce`, plaintext, AAD) |

Total maximum encrypted chunk wire length: `32 + 4_194_304 + 16 = 4_194_352` bytes.

#### Canonical 25-Byte Chunk AAD (`ChunkAad`)

| Offset | Size | Field | Description |
|---:|---:|---|---|
| `0` | `16` | `file_id` | UUID bytes of the owning encrypted file |
| `16` | `8` | `chunk_index` | `u64` LE zero-based chunk index |
| `24` | `1` | `is_final_chunk` | `1u8` if last chunk of file, `0u8` otherwise |

**Attacks Prevented by `ChunkAad` + `ChunkHeader`:**
1. **Cross-file chunk transplant:** `file_id` mismatch causes GCM tag rejection.
2. **Intra-file chunk reordering:** `chunk_index` mismatch causes GCM tag rejection.
3. **Tail truncation / extension:** `is_final_chunk` mismatch causes GCM tag rejection.
4. **Header tampering:** `plaintext_len` and `flags` mismatches fail payload length checks or AAD checks.

### 4.4 Encrypted Directory & Snapshot Manifest (`manifests/<2-hex>/<2-hex>/<manifest_uuid>.zvm` & `manifests/head.zvm`)

| Offset | Size | Field | Description |
|---:|---:|---|---|
| `0` | `4` | `magic` | `b"ZVM1"` |
| `4` | `1` | `version` | `1u8` |
| `5` | `3` | `reserved` | `[0, 0, 0]` |
| `8` | `16` | `vault_id` | Vault UUID |
| `24` | `8` | `revision` | Monotonic manifest revision (`u64` LE) |
| `32` | `12` | `nonce` | CSPRNG 96-bit nonce |
| `44` | `M + 16` | `ciphertext \|\| tag` | AES-256-GCM(`ManifestKey`, `nonce`, `postcard(VaultManifest)`, AAD) |

- **Manifest AAD (28 bytes):** `b"ZVM1" (4B) || vault_id (16B) || revision (8B LE)`.

---

## 5. Remote Path Obfuscation Grammar

Every remote object key transmitted through `StorageRouterTrait` MUST validate against one of:
- `vault/header.zvh`
- `manifests/head.zvm`
- `manifests/<2-hex>/<2-hex>/<uuid>.zvm`
- `blobs/<2-hex>/<2-hex>/<uuid>.zv`

Any object key outside this strict grammar (e.g., containing plaintext filenames, extensions, or `..`) MUST be rejected client-side before invoking any cloud backend.
