# Cloud Provider & Google Drive Setup Guide (`EntroCloud v1.0`)

EntroCloud connects directly to your cloud storage without any middleman servers or bundled third-party binaries. Every file, filename, directory tree, and backup snapshot is encrypted locally with hardware-accelerated **AES-256-GCM** before a single byte leaves your PC. Cloud credentials and OAuth2 refresh tokens are wrapped with your vault key and stored in your native OS keyring (**Windows Credential Manager** or **Linux Secret Service**).

Choose whichever setup path fits you best:

- **Fastest (Zero OAuth Console Needed):** [Section 6 — 1-Click Local / Synced Cloud Folders](#6-1-click-local--synced-cloud-folders-zero-oauth-setup) *(uses an existing OneDrive, Google Drive, Dropbox, iCloud, NAS, or USB folder on your PC in 10 seconds)*
- **Direct Cloud APIs (No Official Provider App Required):**
  1. [Google Drive (Desktop OAuth — `drive.file`)](#1-google-drive-desktop-oauth--drivefile)
  2. [Microsoft OneDrive (Microsoft Entra)](#2-microsoft-onedrive-microsoft-entra)
  3. [Dropbox (Dropbox App Console)](#3-dropbox-dropbox-app-console)
  4. [Cloudflare R2 / Amazon S3 / Backblaze B2 / MinIO](#4-cloudflare-r2--amazon-s3--backblaze-b2--minio)
  5. [Nextcloud / OwnCloud / WebDAV](#5-nextcloud--owncloud--webdav)

---

## 1. Google Drive (Desktop OAuth — `drive.file`)

EntroCloud uses your own **Google Desktop app** OAuth client with RFC 8252 loopback sign-in (`127.0.0.1`) and S256 PKCE. Shared public OAuth clients (such as legacy shared rclone credentials) are being retired and rate-limited in 2026; creating your own personal Desktop client takes about three minutes, gives you dedicated API quota, and restricts access strictly to `drive.file` (EntroCloud can manage only the encrypted vault files it creates and **cannot** read your personal Google Docs, Photos, or other Drive files).

### Step-by-Step Google Cloud Console Setup

1. **Enable the Google Drive API:**
   - Open the [Google Cloud Console](https://console.cloud.google.com/), sign in, and create a new project (for example, `EntroCloud Personal`) or select an existing project.
   - Go to **APIs & Services -> Library**, search for **Google Drive API**, and click **Enable**.

2. **Configure Google Auth Platform (OAuth Consent Screen):**
   - Open **Google Auth Platform -> Branding / Overview** (or **APIs & Services -> OAuth consent screen**).
   - Enter an **App name** (e.g., `EntroCloud`), choose your email for **User support email** and **Developer contact information**, and select the **Audience** appropriate for your account (**External** for personal `@gmail.com` accounts; **Internal** if restricted to your own Google Workspace organization).

3. **Add the Least-Privilege `drive.file` Scope:**
   - Open **Google Auth Platform -> Data Access** (Scopes) and click **Add or remove scopes**.
   - Add **only** the narrow per-file scope:
     ```text
     https://www.googleapis.com/auth/drive.file
     ```
   - Save your changes. Because EntroCloud requests only `drive.file`, it never asks for broad access to the rest of your Google Drive.

4. **Configure Test Users / Publishing Status:**
   - Open **Google Auth Platform -> Audience**.
   - While Publishing status is **Testing**, add your Google email address under **Test users**.
   - **Important for ongoing automatic backups:** Google expires `Testing`-mode refresh tokens after **7 days**. For uninterrupted long-term personal backups, review Google's publishing requirements on the **Audience** page and switch Publishing status to **In production** when eligible (personal apps using only `drive.file` typically do not require restricted-scope security verification, though Google may display an unverified-app confirmation screen during your own sign-in).

5. **Create Your Desktop OAuth Client ID:**
   - Open **Google Auth Platform -> Clients** (or **APIs & Services -> Credentials -> Create Credentials -> OAuth client ID**).
   - Set **Application type** to **Desktop app** and give it a name such as `EntroCloud Desktop`.
   - Click **Create**, then copy your **Client ID** (`...apps.googleusercontent.com`) and **Client Secret**. Enter the secret **only** inside EntroCloud.

6. **Sign In from EntroCloud:**
   - **Desktop App (`EntroCloud.exe` / `entrocloud`):**
     1. Unlock or initialize your vault password first.
     2. Open **Cloud Accounts -> Guided Cloud Setup -> Google Drive**.
     3. Set a connection ID (e.g., `gdrive-main`), keep the cloud root folder as `/EntroCloud`, paste your **Client ID** and **Client Secret**, and click **Sign in with Browser**.
     4. Complete Google sign-in and grant the `drive.file` permission in your browser. Once finished, click **Test Connection** to verify latency and Drive quota.
   - **CLI (`ec`):**
     ```bash
     printf '%s\n' "$GDRIVE_CLIENT_SECRET" | ec remote oauth gdrive-main \
       --kind gdrive \
       --root /EntroCloud \
       --client-id "$GDRIVE_CLIENT_ID" \
       --client-secret-stdin \
       --policy pooled \
       --quota-mib 15360
     ```

> **Important `drive.file` Rule:** Do **not** manually pre-create the `/EntroCloud` folder in the Google Drive web UI beforehand. Under the `drive.file` security scope, Google Drive allows an app to see only folders and files created by **that exact OAuth Client ID**. Keep your Client ID and Client Secret saved (for example, in your password manager) so that if you set up a new PC later, reconnecting with the **same Google account and OAuth Client ID** immediately sees your existing encrypted vault.

---

## 2. Microsoft OneDrive (Microsoft Entra)

EntroCloud authenticates with Personal OneDrive and OneDrive for Business / SharePoint via Microsoft Graph OAuth2 v2.0 + S256 PKCE.

1. Open the [Microsoft Entra admin center — App registrations](https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade) (or Azure Portal -> **App registrations**) and click **New registration**.
2. Enter **Name**: `EntroCloud`.
3. Under **Supported account types**, choose **Accounts in any organizational directory (Any Microsoft Entra ID tenant - Multitenant) and personal Microsoft accounts (e.g. Skype, Xbox)**.
4. Under **Redirect URI**:
   - Select platform **Mobile and desktop applications**.
   - Enter `http://127.0.0.1` *(Microsoft Entra automatically permits dynamic ephemeral ports `http://127.0.0.1:<port>` for native loopback desktop clients under RFC 8252)*.
   - Click **Register**.
5. Copy the **Application (client) ID** shown on the Overview page.
6. Open **Authentication** in the left menu -> scroll to **Advanced settings -> Allow public client flows** -> set **Enable the following mobile and desktop flows** to **Yes**, and click **Save** *(no client secret is required for public desktop PKCE apps)*.
7. Open **API permissions -> Add a permission -> Microsoft Graph -> Delegated permissions**, enable:
   - `Files.ReadWrite.AppFolder` *(least-privilege default used by EntroCloud)*
   - `offline_access` *(required for background sync & automatic folder backups)*
   Click **Add permissions**.
8. Connect in **EntroCloud Desktop** (**Cloud Accounts -> OneDrive**, paste your **Application (client) ID**, root `/EntroCloud`, and click **Sign in with Browser**) or via CLI:
   ```bash
   ec remote oauth onedrive-main \
     --kind onedrive \
     --root /EntroCloud \
     --client-id "$ONEDRIVE_CLIENT_ID" \
     --policy pooled \
     --quota-mib 5120
   ```

---

## 3. Dropbox (Dropbox App Console)

EntroCloud supports Dropbox Scoped Apps with S256 PKCE and offline refresh tokens.

1. Open the [Dropbox App Console](https://www.dropbox.com/developers/apps) and click **Create app**.
2. Choose **Scoped access** -> select **App folder** *(recommended least-privilege isolation)* -> enter a unique app name such as `EntroCloud-Vault-<yourname>` -> click **Create app**.
3. Open the **Permissions** tab FIRST (before signing in!), check:
   - `files.content.write`
   - `files.content.read`
   - `files.metadata.read`
   Click **Submit** at the bottom bar to activate the scopes.
4. Open the **Settings** tab:
   - Copy your **App key** (Client ID) and, if using confidential client mode, your **App secret**.
   - Note: EntroCloud uses a dynamic loopback port by default via PKCE, or if Dropbox requires an explicit Redirect URI on your account tier, add `http://127.0.0.1:53682/callback` or paste your App key + App secret in EntroCloud's Guided Setup.
5. Connect in **EntroCloud Desktop** (**Cloud Accounts -> Dropbox**) or via CLI:
   ```bash
   ec remote oauth dropbox-main \
     --kind dropbox \
     --root /EntroCloud \
     --client-id "$DROPBOX_APP_KEY" \
     --policy pooled \
     --quota-mib 2048
   ```

---

## 4. Cloudflare R2 / Amazon S3 / Backblaze B2 / MinIO

S3-compatible object stores require **zero browser OAuth setup** — simply create a private bucket and a bucket-scoped API keypair.

### Provider Quick-Reference Settings

| Provider | Endpoint URL Format | Region | Credentials |
| :--- | :--- | :--- | :--- |
| **Cloudflare R2** | `https://<ACCOUNT_ID>.r2.cloudflarestorage.com` | `auto` | R2 API Token -> **Access Key ID** & **Secret Access Key** (*Object Read & Write* on your bucket) |
| **Backblaze B2** | `https://s3.<region>.backblazeb2.com` *(e.g. `us-west-004`)* | `<region>` *(e.g. `us-west-004`)* | B2 **Application Key** (`keyID` + `applicationKey`) restricted to your private bucket |
| **Amazon S3** | *(leave blank for AWS default, or `https://s3.<region>.amazonaws.com`)* | e.g. `us-east-1`, `eu-central-1` | IAM Access Key scoped to `s3:GetObject`, `s3:PutObject`, `s3:DeleteObject`, `s3:ListBucket` |
| **MinIO / Garage / Wasabi** | `https://minio.example.com:9000` *(or `https://s3.wasabisys.com`)* | e.g. `us-east-1` | Bucket-scoped Access Key & Secret Key |

### Connect in EntroCloud

- **Desktop App (`EntroCloud.exe`):** Open **Cloud Accounts -> S3 / Cloudflare R2 / Backblaze B2**, enter your Connection ID (e.g., `r2-backup`), Bucket Name, Region, Endpoint URL, Access Key ID, and Secret Access Key, click **Add Account**, then click **Test Connection**.
- **CLI (`ec`):**
  ```bash
  printf '%s\n' "$R2_SECRET_ACCESS_KEY" | ec remote add r2-backup \
    --kind s3 \
    --bucket my-entrocloud-vault \
    --region auto \
    --endpoint "https://<ACCOUNT_ID>.r2.cloudflarestorage.com" \
    --root /vault \
    --username "$R2_ACCESS_KEY_ID" \
    --secret-stdin \
    --policy pooled \
    --quota-mib 10240
  ```

---

## 5. Nextcloud / OwnCloud / WebDAV

Connect any self-hosted Nextcloud, OwnCloud, Fastmail Files, Hetzner Storage Box, or RFC 4918 HTTPS WebDAV server:

1. **Create a Dedicated App Password (Recommended):**
   - In **Nextcloud**, open **Personal Settings -> Security -> Devices & sessions**, type `EntroCloud`, and click **Create new app password**. Copy the generated token *(do not use your primary Nextcloud login password when 2FA is enabled)*.
2. **Find Your WebDAV Endpoint URL:**
   - **Nextcloud / OwnCloud:** `https://cloud.example.com/remote.php/dav/files/<your-username>`
   - **Hetzner Storage Box:** `https://<uXXXXXX>.your-storagebox.de`
3. **Connect in EntroCloud:**
   - **Desktop App (`EntroCloud.exe`):** Open **Cloud Accounts -> Nextcloud / WebDAV**, enter the Endpoint URL, Root folder `/EntroCloud`, Username, and App Password, then click **Test Connection**.
   - **CLI (`ec`):**
     ```bash
     printf '%s\n' "$WEBDAV_APP_PASSWORD" | ec remote add nextcloud-home \
       --kind webdav \
       --endpoint "https://cloud.example.com/remote.php/dav/files/alice" \
       --root /EntroCloud \
       --username "alice" \
       --secret-stdin \
       --policy mirrored
     ```

---

## 6. 1-Click Local / Synced Cloud Folders (Zero-OAuth Setup)

If you already have **OneDrive**, **Google Drive for Desktop**, **Dropbox**, **iCloud Drive**, a **Synology/TrueNAS SMB network share**, or an **external NVMe/USB drive** mounted on your computer, you can skip API keys and OAuth consoles altogether:

1. Open **`EntroCloud.exe`** -> **Cloud Accounts -> 1-Click Local / Synced Folders** (or run `ec remote detect-clouds`).
2. EntroCloud automatically scans your PC for installed cloud sync directories and offers 1-click setup into a dedicated encrypted vault subfolder (for example, `C:\Users\<You>\OneDrive\EntroCloudVault`).
3. EntroCloud writes **only** authenticated zero-knowledge ciphertext (`vault/header.zvh`, `manifests/*.zvm`, `blobs/<aa>/<bb>/<uuid>.zv`) into that folder, and your existing desktop sync app uploads the encrypted blobs in the background.

```bash
# Inspect auto-detected cloud sync folders via CLI
ec remote detect-clouds

# Attach a synced folder or NAS share directly
ec remote add onedrive-local --kind fs --root "$HOME/OneDrive/EntroCloudVault" --policy mirrored
```

---

## 7. Automatic Folder Backups & Multi-PC Recovery Tips

- **Preview Before Uploading:** When adding an **Automatic PC Folder Backup Job** (e.g., backing up `Documents` -> `/Backups/Documents` every 15 minutes), you can run **Preview** (dry-run) first to inspect the exact file count and byte total before any cloud upload occurs, or uncheck *Automatic schedule* while configuring exclusion globs (`Thumbs.db`, `desktop.ini`, `~$*`, `node_modules`).
- **Safe Non-Destructive Restore:** Clicking **Restore** decrypts, authenticates every 4 MiB AES-256-GCM chunk, and writes into a brand-new subfolder inside your chosen destination parent so existing local files are never silently overwritten.
- **Recovering on a Brand-New PC:** All vault bootstrap parameters (`vault/header.zvh`), shared folder keyboxes (`vault/keybox.zv`), and encrypted manifests (`manifests/head.zvm`) live inside your cloud storage. On a new computer:
  1. Install EntroCloud and connect the same cloud account (for Google Drive `drive.file`, use the **same Google account and OAuth Client ID**).
  2. Click **Unlock Existing Vault** (or `ec unlock`) and enter your original vault passphrase — EntroCloud automatically fetches `vault/header.zvh` from your cloud and restores full access to your Virtual Drive and Backups without needing old local Windows DPAPI or SQLite files.
- **Canceling a Hung Browser Sign-In:** If you close the browser tab mid-login, click **Cancel Sign-In** in EntroCloud (or let the loopback listener time out cleanly) and retry.

---

### References

- [Google Workspace: Choose Google Drive API scopes (`drive.file`)](https://developers.google.com/workspace/drive/api/guides/api-specific-auth)
- [Google Identity: OAuth 2.0 for Mobile & Desktop Apps (RFC 8252 Loopback)](https://developers.google.com/identity/protocols/oauth2/native-app)
- [Microsoft Identity Platform: Public client & desktop app redirect URIs](https://learn.microsoft.com/en-us/entra/identity-platform/reply-url)
- [Dropbox Developers: OAuth Guide & Scoped Apps](https://developers.dropbox.com/oauth-guide)
