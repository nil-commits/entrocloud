# EntroCloud v1.0 — Cryptographic & Wire Protocol Specification (`SPEC_CRYPTO.md`)

## 1. Threat Model & Non-Negotiable Invariants

1. **Untrusted Cloud Storage:** Remote storage backends (Google Drive, Microsoft OneDrive, Dropbox, S3 / Cloudflare R2 / Backblaze B2 / MinIO, Nextcloud / WebDAV, and synced local folders) are treated as active Byzantine adversaries capable of reading all stored objects/filenames, flipping bits, swapping chunks, truncating streams, injecting unsigned manifests, and replaying historical manifests or revoked `keybox.zv` epochs.
2. **Zero Plaintext Leakage (Remote, SQLite & Staging):**
   - Remote object keys follow a strict whitelist (`vault/header.zvh`, `vault/keybox.zv`, `manifests/head.zvm`, `manifests/<aa>/<bb>/<uuid>.zvm`, `shares/<aa>/<bb>/<uuid>.zvs`, `blobs/<aa>/<bb>/<uuid>.zv`). Both Virtual Drive files and Automatic PC Folder Backup trees (`/Backups/<JobName>/...`) compile into the same encrypted inode/chunk graph so remote object stores never observe plaintext folder names or extensions.
   - Local SQLite WAL columns encrypt all entry names, virtual paths, dirty-op hints, and conflict paths under `MetadataKey` (`AES-256-GCM`) paired with `BLAKE3` keyed blind indexes (`BlindIndexKey`).
   - Local dirty staging chunks (`staging_dir/dirty/<inode>/<idx>.zvpart`) are AEAD-encrypted on disk under `StagingKey` (`AES-256-GCM`) and cryptographically wiped on `LockVault`.
3. **Mandatory Silicon Hardware Acceleration:**
   - `x86_64`: Requires CPUID `AES-NI` + `PCLMULQDQ` (automatically dispatching 256-bit `VAES + VPCLMULQDQ` via `ring 0.17.14` when `VAES` + `AVX2` are present).
   - `aarch64`: Requires ARMv8 `AES` + `PMULL` instructions.
   - Absence of hardware acceleration causes `CryptoEngine` (`entrocloud-crypto`) to fail closed with `EntroCloudError::HardwareAccelerationUnavailable` (`ZeroVaultError::HardwareAccelerationUnavailable`).
4. **Deterministic Secret Zeroization:** All keys, seeds, DEKs, passphrases, OAuth2 secrets, and staging buffers implement `zeroize::Zeroize` / `ZeroizeOnDrop`; pooled `Vec<u8>`/`BytesMut` buffers zeroize full `0..capacity` before release.

---

## 2. Key Derivation & Subkey Hierarchy

### 2.1 Passphrase KDF (`Argon2id` v0x13 — RFC 9106)
Given passphrase $P$ and 256-bit CSPRNG salt $S \in \{0,1\}^{256}$ from `VaultHeader` (`ZVH1`):
- **Policy Floor (Anti-Weakness):** $m \ge 65{,}536\text{ KiB}$ ($64\text{ MiB}$), $t \ge 3$, $p \ge 4$.
- **Policy Ceiling (Pre-Allocation Anti-OOM DoS, ported from CloudBridge):** $m \le 262{,}144\text{ KiB}$ ($256\text{ MiB}$), $t \le 10$, $p \le 16$. Any header outside bounds is rejected *before* memory allocation with `KdfPolicyViolation`.
- **Master Seed:** $\text{MS} = \text{Argon2id}(P, S, m, t, p) \in \{0,1\}^{256}$.

### 2.2 Domain-Separated `HKDF-SHA256` Subkeys
From $\text{PRK} = \text{HKDF-Extract}(\text{salt} = S, \text{ikm} = \text{MS})$, seven independent 256-bit keys are expanded via $\text{HKDF-Expand}(\text{PRK}, \text{info}, 32)$.

> **Wire Compatibility Note:** EntroCloud v1.0 preserves canonical `ZVH1` / `ZVC1` / `ZVM1` / `ZVK1` / `ZVS1` wire magics, AAD prefixes, and `zerovault.v1.*` / `zerovault.v2.*` HKDF domain-separation labels byte-for-byte so existing encrypted vaults unlock seamlessly without re-encryption.

| Subkey | HKDF `info` Context String | Purpose & AAD Binding |
|---|---|---|
| `MasterKek` | `"zerovault.v1.kek"` | Wraps per-file 256-bit `DEK`s (`AAD = "ZV-DEK-V1" \|\| file_id`). |
| `ManifestKey` | `"zerovault.v1.manifest"` | Seals/opens `ZVM1` `VaultManifest` snapshots (`AAD = "ZVM1" \|\| vault_id \|\| revision_le`). |
| `TokenWrapKey` | `"zerovault.v1.token-wrap"` | Wraps OAuth2/API credentials in OS Keyring (`AAD = "ZV-TOKEN-V1:" \|\| vault_id`). |
| `HeaderVerifierKey` | `"zerovault.v1.verifier"` | Authenticates `vault_id` inside `ZVH1` (`AAD = "ZVH1" \|\| vault_id`). |
| `MetadataKey` | `"zerovault.v2.meta-aead"` | Encrypts SQLite inode names, conflict paths & dirty ops (`AAD = domain \|\| row_context`). |
| `BlindIndexKey` | `"zerovault.v2.meta-blind"` | Keyed `BLAKE3` blind index `H(BlindIndexKey, parent_inode_le \|\| utf8_name)` for O(1) lookup. |
| `StagingKey` | `"zerovault.v2.staging"` | Encrypts local dirty `.zvpart` chunks (`AAD = "ZV-STAGE-V2" \|\| inode_le \|\| chunk_idx_le`). |

---

## 3. Binary Wire Formats

### 3.1 Vault Bootstrap Header (`vault/header.zvh` — Fixed `112` Bytes)
```text
Offset  Size  Field
0..4    4B    Magic = b"ZVH1"
4       1B    Version = 1
5..8    3B    Reserved = [0, 0, 0] (rejected if non-zero)
8..24   16B   vault_id (UUID bytes)
24..56  32B   argon2_salt
56..60  4B    m_cost_kib (u32 LE, 65_536..=262_144)
60..64  4B    t_cost (u32 LE, 3..=10)
64..68  4B    p_cost (u32 LE, 4..=16)
68..80  12B   verifier_nonce (96-bit CSPRNG)
80..112 32B   verifier_tag = AES-256-GCM(HeaderVerifierKey, verifier_nonce, AAD="ZVH1"||vault_id, pt=vault_id)
```

### 3.2 Streaming File Chunk (`blobs/<aa>/<bb>/<uuid>.zv` — `ZVC1`)
- **Plaintext Chunk Size:** Fixed `4,194,304` bytes (`4 MiB`) for all non-final chunks (`chunk_index < N - 1`); `0..=4,194,304` bytes for the final chunk (`CHUNK_FLAG_FINAL = 0x01`; `0` bytes permitted only when `chunk_index == 0`).
- **Wire Header (`32` Bytes):**
  `b"ZVC1" [4B] || version=1 [1B] || flags [1B] || reserved=[0,0] [2B] || chunk_index [8B LE] || plaintext_len [4B LE] || nonce [12B CSPRNG]`.
- **Canonical 25-Byte Chunk AAD:**
  $$\text{AAD}_{\text{chunk}} = \text{file\_id}_{16\text{B}} \,\|\, \text{chunk\_index}_{8\text{B LE}} \,\|\, \text{is\_final}_{1\text{B}}$$
- **Defeats:** Bit-flips (GCM tag), chunk `3 <-> 4` reordering (`chunk_index` in AAD), cross-file chunk transplant (`file_id` in AAD), and EOF truncation (`is_final` bit in AAD).

### 3.3 Encrypted Vault Manifest (`manifests/head.zvm` — `ZVM1`)
- **44-Byte Prefix:** `b"ZVM1" [4B] || version=1 [1B] || reserved=[0,0,0] [3B] || vault_id [16B] || revision [8B LE] || nonce [12B]`.
- **Ciphertext:** `AES-256-GCM(ManifestKey, nonce, AAD = "ZVM1" || vault_id || revision_le, postcard(VaultManifest))`.
- **Anti-Rollback:** SQLite `security_epochs` persists `(min_revision, last_manifest_id)`; any remote manifest with `revision < min_revision` is rejected fail-closed with `CryptoTamperDetected`.

---

## 4. Serverless Zero-Knowledge E2E Sharing

### 4.1 Read-Only Capability URIs (`ec://` Primary + `zv://` Legacy Compatibility)
Primary format (`CAPABILITY_URI_SCHEME = "ec"`):
```text
ec://share/v1/<backend_kind>?root=<url_encoded_root>&share=<share_uuid>#<base64url_nopad(SRK_32B || Ed25519_PubKey_32B)>
```
Legacy backward-compatible format (`LEGACY_CAPABILITY_URI_SCHEME = "zv"`, also accepted by `CapabilityUri::parse`, `EntroCloud.exe`, and `ec`):
```text
zv://share/v1/<backend_kind>?root=<url_encoded_root>&share=<share_uuid>#<base64url_nopad(SRK_32B || Ed25519_PubKey_32B)>
```
- Per `RFC 3986 §3.5`, the URI fragment (`#<64B secret+pubkey>`) is never transmitted to any server or cloud provider.
- From the 256-bit `ShareRootKey` ($\text{SRK}$):
  - `ShareKey = HKDF-SHA256(SRK, info = "zerovault.v2.share-manifest" || share_uuid)` decrypts the remote `shares/<aa>/<bb>/<share_uuid>.zvs` (`ZVS1`) manifest.
  - Before trusting chunk pointers or unwrapping the shared file `DEK`, the client verifies the **64-byte `Ed25519` signature** over `b"ZV-SHARE-SIG-V1" || share_uuid || ciphertext` using the `Ed25519_PubKey` pinned in the URI fragment. Unsigned or re-signed manifests fail closed (`CryptoTamperDetected`).

### 4.2 Revocable Multi-Recipient Post-Quantum Cloud Keyboxes (`vault/keybox.zv` — `ZVK1`)
Supports serverless read/write shared folders using **Hybrid Classical + Post-Quantum KEM (`X25519 + ML-KEM-768`)** and **`Ed25519`** sender authentication via `aws-lc-rs`:

1. **Recipient Identity Keys:**
   - `Ed25519` signing keypair (`32B` seed, `32B` public key).
   - Static `X25519` agreement keypair (`32B` private, `32B` public key).
   - Static NIST FIPS 203 `ML-KEM-768` KEM keypair (`2,400B` decapsulation key + `1,184B` encapsulation key).
   - `recipient_id` = lowercase hex of `BLAKE3("ZV-RCPT-ID-V1" || ed25519_pub || x25519_pub || mlkem768_encaps)[0..16]`.
2. **Hybrid Encapsulation per Recipient Stanza:**
   - Generate fresh ephemeral `X25519` keypair $(esk, epk)$ and compute $ss_{\text{x25519}} = \text{X25519}(esk, pk_{\text{x25519}}) \in \{0,1\}^{256}$.
   - Encapsulate $(ct_{\text{mlkem}}, ss_{\text{mlkem}}) = \text{ML-KEM-768.Encaps}(pk_{\text{mlkem}})$ where $|ct_{\text{mlkem}}| = 1{,}088\text{ B}$ and $ss_{\text{mlkem}} \in \{0,1\}^{256}$.
   - Combine both shared secrets via `HKDF-SHA256`:
     $$K_{\text{wrap}} = \text{HKDF}(\text{salt} = \text{stanza\_nonce}_{12\text{B}},\; \text{ikm} = ss_{\text{x25519}} \,\|\, ss_{\text{mlkem}} \,\|\, epk \,\|\, pk_{\text{x25519}},\; \text{info} = \text{"zerovault.v2.pq-stanza"} \,\|\, \text{vault\_id} \,\|\, \text{epoch}_{\text{LE}} \,\|\, \text{recipient\_id})$$
   - Wrap the 256-bit `FolderRootKey` ($\text{FRK}$) with `AES-256-GCM` under $K_{\text{wrap}}$ (`AAD = "ZV-KEYBOX-STANZA-V1" || vault_id || epoch_le || recipient_id`).
3. **Owner Signature & Monotonic Epoch Rollback Protection:**
   - The entire `ZVK1` payload (`version || vault_id || epoch_le || owner_ed25519_pubkey || created_at || stanzas`) is signed with the owner's `Ed25519` private key (`64B` signature) and prefixed with `b"ZVK1"`.
   - **Revocation:** Revoking any recipient increments `epoch = prev_epoch + 1`, generates a fresh CSPRNG `FRK'`, re-encapsulates `FRK'` only for remaining authorized recipients, re-signs `keybox.zv`, and advances SQLite `security_epochs.min_epoch = epoch`.
   - **Replay Rejection:** Any attempt by a compromised cloud server or revoked user to replay `keybox.zv` with `epoch < min_epoch` (e.g. replaying `epoch = 1` after advancing to `epoch = 2`) or with a forged/missing `Ed25519` signature deterministically fails closed with `CryptoTamperDetected`.
