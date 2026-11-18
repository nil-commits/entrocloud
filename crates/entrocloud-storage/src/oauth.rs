//! Hardened OAuth2 Authorization Code + S256 PKCE loopback authentication and encrypted token storage.
//!
//! Implements RFC 8252 native-app loopback redirection (`127.0.0.1:<port>`), SSRF-safe HTTP
//! client configuration (`reqwest::redirect::Policy::none()`), constant-time CSRF `state`
//! validation (`subtle::ConstantTimeEq`), slowloris `5s` per-socket timeout + probe survival
//! (`NEW-L01`), least-privilege CloudBridge scopes, and AEAD-wrapped token persistence via
//! [`CryptoEngine`] + [`SecretStore`].

use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use oauth2::basic::BasicClient;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointNotSet, EndpointSet,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, RefreshToken, Scope, TokenResponse, TokenUrl,
};
use reqwest::redirect::Policy;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use url::Url;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use entrocloud_types::{
    BackendKind, CryptoEngine, RedactedSecret, SecretStore, ZeroVaultError, ZeroVaultResult,
};

/// Default [`SecretStore`] service namespace used when persisting wrapped OAuth2 token bundles.
pub const DEFAULT_TOKEN_SECRET_SERVICE: &str = "zerovault.oauth2";

/// Mandatory per-socket HTTP header read timeout defeating 1-byte slowloris hangs (`NEW-L01`).
pub const PER_SOCKET_READ_TIMEOUT: Duration = Duration::from_secs(5);

const PER_SOCKET_WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CALLBACK_HTTP_BYTES: usize = 16 * 1024;
const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_secs(30);

type ConfiguredOAuthClient =
    BasicClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointSet>;

/// Supported cloud storage OAuth2 provider presets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OAuthProviderPreset {
    /// Google Drive OAuth2 v2 endpoints (`accounts.google.com` / `oauth2.googleapis.com`).
    GoogleDrive,
    /// Microsoft OneDrive / Graph API OAuth2 v2.0 endpoints (`login.microsoftonline.com`).
    OneDrive,
    /// Dropbox OAuth2 endpoints (`www.dropbox.com` / `api.dropboxapi.com`).
    Dropbox,
}

impl OAuthProviderPreset {
    /// Canonical human-readable provider label (never sensitive).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GoogleDrive => "google-drive",
            Self::OneDrive => "onedrive",
            Self::Dropbox => "dropbox",
        }
    }

    /// Default OAuth2 authorization endpoint URL.
    #[must_use]
    pub const fn default_auth_url(self) -> &'static str {
        match self {
            Self::GoogleDrive => "https://accounts.google.com/o/oauth2/v2/auth",
            Self::OneDrive => "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
            Self::Dropbox => "https://www.dropbox.com/oauth2/authorize",
        }
    }

    /// Default OAuth2 token exchange / refresh endpoint URL.
    #[must_use]
    pub const fn default_token_url(self) -> &'static str {
        match self {
            Self::GoogleDrive => "https://oauth2.googleapis.com/token",
            Self::OneDrive => "https://login.microsoftonline.com/common/oauth2/v2.0/token",
            Self::Dropbox => "https://api.dropboxapi.com/oauth2/token",
        }
    }

    /// Least-privilege default scopes required for ZeroVault app/file encrypted blob storage.
    #[must_use]
    pub fn default_scopes(self) -> Vec<String> {
        match self {
            Self::GoogleDrive => vec!["https://www.googleapis.com/auth/drive.file".to_owned()],
            Self::OneDrive => vec![
                "Files.ReadWrite.AppFolder".to_owned(),
                "offline_access".to_owned(),
            ],
            Self::Dropbox => vec![
                "files.content.write".to_owned(),
                "files.content.read".to_owned(),
            ],
        }
    }
}

impl TryFrom<&BackendKind> for OAuthProviderPreset {
    type Error = ZeroVaultError;

    fn try_from(kind: &BackendKind) -> Result<Self, Self::Error> {
        match kind {
            BackendKind::GoogleDrive => Ok(Self::GoogleDrive),
            BackendKind::OneDrive => Ok(Self::OneDrive),
            BackendKind::Dropbox => Ok(Self::Dropbox),
            other => Err(ZeroVaultError::ConfigError(format!(
                "backend kind {other:?} does not use OAuth2"
            ))),
        }
    }
}

impl From<OAuthProviderPreset> for BackendKind {
    fn from(preset: OAuthProviderPreset) -> Self {
        match preset {
            OAuthProviderPreset::GoogleDrive => Self::GoogleDrive,
            OAuthProviderPreset::OneDrive => Self::OneDrive,
            OAuthProviderPreset::Dropbox => Self::Dropbox,
        }
    }
}

/// OAuth2 client configuration for a provider preset or custom local/enterprise endpoints.
#[derive(Clone, Serialize, Deserialize)]
pub struct OAuthProviderConfig {
    /// Provider preset identifier.
    pub preset: OAuthProviderPreset,
    /// Registered OAuth2 client ID.
    pub client_id: String,
    /// Optional OAuth2 client secret (redacted in `Debug`, never serialized unencrypted).
    #[serde(skip)]
    pub client_secret: Option<RedactedSecret>,
    /// Authorization endpoint URL.
    pub auth_url: String,
    /// Token exchange / refresh endpoint URL.
    pub token_url: String,
    /// Requested OAuth2 scopes.
    pub scopes: Vec<String>,
}

impl fmt::Debug for OAuthProviderConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthProviderConfig")
            .field("preset", &self.preset)
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field("auth_url", &self.auth_url)
            .field("token_url", &self.token_url)
            .field("scopes", &self.scopes)
            .finish()
    }
}

impl OAuthProviderConfig {
    /// Builds a configuration using a provider preset's canonical endpoints and least-privilege scopes.
    #[must_use]
    pub fn for_preset(
        preset: OAuthProviderPreset,
        client_id: impl Into<String>,
        client_secret: Option<RedactedSecret>,
    ) -> Self {
        Self {
            preset,
            client_id: client_id.into(),
            client_secret,
            auth_url: preset.default_auth_url().to_owned(),
            token_url: preset.default_token_url().to_owned(),
            scopes: preset.default_scopes(),
        }
    }

    /// Overrides the authorization and token endpoint URLs (useful for tenant endpoints or tests).
    #[must_use]
    pub fn with_endpoints(
        mut self,
        auth_url: impl Into<String>,
        token_url: impl Into<String>,
    ) -> Self {
        self.auth_url = auth_url.into();
        self.token_url = token_url.into();
        self
    }

    /// Overrides the requested OAuth2 scopes.
    #[must_use]
    pub fn with_scopes(mut self, scopes: Vec<String>) -> Self {
        self.scopes = scopes;
        self
    }
}

/// Redacted OAuth2 token bundle with automatic memory zeroization on drop.
#[derive(Clone)]
pub struct OAuthTokenBundle {
    /// Owning cloud provider preset.
    pub provider: OAuthProviderPreset,
    /// Bearer access token.
    pub access_token: RedactedSecret,
    /// Long-lived refresh token for automatic renewal, if issued.
    pub refresh_token: Option<RedactedSecret>,
    /// OAuth2 token type (typically `"bearer"`).
    pub token_type: String,
    /// Calculated UTC expiration instant when `expires_in` was provided.
    pub expires_at: Option<DateTime<Utc>>,
    /// Granted or requested scopes.
    pub scopes: Vec<String>,
    /// Client ID associated with this grant (used when configuring OpenDAL token refresh).
    pub client_id: Option<String>,
    /// Optional client secret associated with this grant (used when configuring OpenDAL token refresh).
    pub client_secret: Option<RedactedSecret>,
}

impl OAuthTokenBundle {
    /// Returns `true` when `expires_at` is known and within `leeway_secs` of expiring.
    #[must_use]
    pub fn is_expired(&self, leeway_secs: i64) -> bool {
        let Some(expires_at) = self.expires_at else {
            return false;
        };
        Utc::now() + ChronoDuration::seconds(leeway_secs) >= expires_at
    }
}

impl Zeroize for OAuthTokenBundle {
    fn zeroize(&mut self) {
        self.access_token.zeroize();
        self.refresh_token.zeroize();
        self.token_type.zeroize();
        for scope in &mut self.scopes {
            scope.zeroize();
        }
        self.scopes.clear();
        self.client_id.zeroize();
        self.client_secret.zeroize();
        self.expires_at = None;
    }
}

impl Drop for OAuthTokenBundle {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for OAuthTokenBundle {}

impl fmt::Debug for OAuthTokenBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthTokenBundle")
            .field("provider", &self.provider)
            .field("access_token", &"[REDACTED]")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("token_type", &self.token_type)
            .field("expires_at", &self.expires_at)
            .field("scopes", &self.scopes)
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

/// Internal wire payload serialized into `Zeroizing<Vec<u8>>` immediately before AEAD wrapping.
#[derive(Serialize, Deserialize)]
struct StoredTokenPayload {
    provider: OAuthProviderPreset,
    access_token: String,
    refresh_token: Option<String>,
    token_type: String,
    expires_at: Option<DateTime<Utc>>,
    scopes: Vec<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
}

impl Zeroize for StoredTokenPayload {
    fn zeroize(&mut self) {
        self.access_token.zeroize();
        self.refresh_token.zeroize();
        self.token_type.zeroize();
        for scope in &mut self.scopes {
            scope.zeroize();
        }
        self.scopes.clear();
        self.client_id.zeroize();
        self.client_secret.zeroize();
        self.expires_at = None;
    }
}

impl Drop for StoredTokenPayload {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Constructs an SSRF-safe asynchronous `reqwest` (`0.12`) HTTP client with `Policy::none()`
/// so token endpoints can never redirect requests onto internal hosts.
pub fn build_ssrf_safe_http_client() -> ZeroVaultResult<reqwest::Client> {
    reqwest::Client::builder()
        .redirect(Policy::none())
        .timeout(DEFAULT_HTTP_TIMEOUT)
        .build()
        .map_err(|err| {
            ZeroVaultError::OAuthError(format!("failed to build SSRF-safe OAuth2 client: {err}"))
        })
}

/// Constant-time comparison helper for OAuth2 CSRF `state` parameters using [`subtle::ConstantTimeEq`].
#[must_use]
pub fn constant_time_csrf_eq(expected: &str, received: &str) -> bool {
    let expected_bytes = expected.as_bytes();
    let received_bytes = received.as_bytes();
    bool::from(expected_bytes.ct_eq(received_bytes))
}

fn build_configured_client(
    config: &OAuthProviderConfig,
    redirect_uri: Option<&str>,
) -> ZeroVaultResult<ConfiguredOAuthClient> {
    if config.client_id.trim().is_empty() {
        return Err(ZeroVaultError::ConfigError(
            "OAuth2 client_id must not be empty".into(),
        ));
    }
    let auth_url = AuthUrl::new(config.auth_url.clone())
        .map_err(|err| ZeroVaultError::ConfigError(format!("invalid OAuth2 auth_url: {err}")))?;
    let token_url = TokenUrl::new(config.token_url.clone())
        .map_err(|err| ZeroVaultError::ConfigError(format!("invalid OAuth2 token_url: {err}")))?;

    let mut client = BasicClient::new(ClientId::new(config.client_id.clone()))
        .set_auth_uri(auth_url)
        .set_token_uri(token_url);

    if let Some(secret) = &config.client_secret {
        client = client.set_client_secret(ClientSecret::new(secret.as_str().to_owned()));
    }
    if let Some(redirect) = redirect_uri {
        let parsed_redirect = RedirectUrl::new(redirect.to_owned()).map_err(|err| {
            ZeroVaultError::ConfigError(format!("invalid OAuth2 redirect_uri: {err}"))
        })?;
        client = client.set_redirect_uri(parsed_redirect);
    }

    Ok(client)
}

/// Active loopback HTTP callback listener holding a single-use S256 PKCE verifier and CSRF state token.
pub struct LoopbackOAuthListener {
    listener: TcpListener,
    local_addr: SocketAddr,
    redirect_uri: String,
    authorize_url: Url,
    csrf_token: CsrfToken,
    pkce_verifier: PkceCodeVerifier,
    client: ConfiguredOAuthClient,
    http_client: reqwest::Client,
    config: OAuthProviderConfig,
    per_socket_read_timeout: Duration,
}

impl fmt::Debug for LoopbackOAuthListener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoopbackOAuthListener")
            .field("local_addr", &self.local_addr)
            .field("redirect_uri", &self.redirect_uri)
            .field("provider", &self.config.preset)
            .field("csrf_token", &"[REDACTED]")
            .field("pkce_verifier", &"[REDACTED]")
            .field("per_socket_read_timeout", &self.per_socket_read_timeout)
            .finish_non_exhaustive()
    }
}

impl LoopbackOAuthListener {
    /// Binds `127.0.0.1:<port>` (or an ephemeral port when `port` is `None` or `0`),
    /// generates an S256 PKCE challenge + random CSRF token, and constructs the authorization URL.
    pub async fn bind(config: OAuthProviderConfig, port: Option<u16>) -> ZeroVaultResult<Self> {
        let http_client = build_ssrf_safe_http_client()?;
        Self::bind_with_http_client(config, port, http_client).await
    }

    /// Binds an ephemeral loopback port (`127.0.0.1:0`).
    pub async fn bind_ephemeral(config: OAuthProviderConfig) -> ZeroVaultResult<Self> {
        Self::bind(config, None).await
    }

    async fn bind_with_http_client(
        config: OAuthProviderConfig,
        port: Option<u16>,
        http_client: reqwest::Client,
    ) -> ZeroVaultResult<Self> {
        let bind_port = port.unwrap_or(0);
        let listener = TcpListener::bind(("127.0.0.1", bind_port))
            .await
            .map_err(|err| {
                ZeroVaultError::OAuthError(format!("failed to bind loopback OAuth listener: {err}"))
            })?;
        let local_addr = listener.local_addr().map_err(|err| {
            ZeroVaultError::OAuthError(format!(
                "failed to inspect loopback listener address: {err}"
            ))
        })?;
        let redirect_uri = format!("http://127.0.0.1:{}/callback", local_addr.port());
        let client = build_configured_client(&config, Some(&redirect_uri))?;

        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        let mut auth_req = client
            .authorize_url(CsrfToken::new_random)
            .set_pkce_challenge(pkce_challenge);
        for scope in &config.scopes {
            auth_req = auth_req.add_scope(Scope::new(scope.clone()));
        }
        match config.preset {
            OAuthProviderPreset::GoogleDrive => {
                auth_req = auth_req
                    .add_extra_param("access_type", "offline")
                    .add_extra_param("prompt", "consent");
            }
            OAuthProviderPreset::Dropbox => {
                auth_req = auth_req.add_extra_param("token_access_type", "offline");
            }
            OAuthProviderPreset::OneDrive => {}
        }
        let (authorize_url, csrf_token) = auth_req.url();

        tracing::info!(
            provider = config.preset.as_str(),
            port = local_addr.port(),
            "bound loopback OAuth2 PKCE listener"
        );

        Ok(Self {
            listener,
            local_addr,
            redirect_uri,
            authorize_url,
            csrf_token,
            pkce_verifier,
            client,
            http_client,
            config,
            per_socket_read_timeout: PER_SOCKET_READ_TIMEOUT,
        })
    }

    /// Overrides the per-socket read timeout (defaults strictly to [`PER_SOCKET_READ_TIMEOUT`] = `5s`).
    #[must_use]
    pub fn with_per_socket_read_timeout(mut self, timeout: Duration) -> Self {
        self.per_socket_read_timeout = timeout;
        self
    }

    /// Returns the bound loopback socket address (`127.0.0.1:<port>`).
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Returns the exact loopback callback redirect URI registered with the OAuth2 request.
    #[must_use]
    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    /// Returns the authorization URL (including `code_challenge`, `code_challenge_method=S256`,
    /// `state`, and `redirect_uri`) that the user should open in a browser.
    #[must_use]
    pub fn authorize_url(&self) -> &Url {
        &self.authorize_url
    }

    /// Waits up to `timeout` for a verified loopback HTTP GET `/callback`, rejecting slowloris
    /// sockets (5s per-socket timeout) and unauthenticated/malformed probes (`400 Bad Request`)
    /// while continuing to listen until the genuine CSRF `state` arrives or `timeout` expires.
    pub async fn wait_for_callback(
        self,
        timeout: Duration,
    ) -> ZeroVaultResult<(
        AuthorizationCode,
        PkceCodeVerifier,
        ConfiguredOAuthClient,
        OAuthProviderConfig,
        reqwest::Client,
    )> {
        let code = tokio::time::timeout(
            timeout,
            accept_callback_code(
                &self.listener,
                self.csrf_token.secret(),
                self.per_socket_read_timeout,
            ),
        )
        .await
        .map_err(|_| {
            ZeroVaultError::OAuthError("timed out waiting for OAuth2 loopback callback".into())
        })??;

        Ok((
            code,
            self.pkce_verifier,
            self.client,
            self.config,
            self.http_client,
        ))
    }

    /// Waits for the loopback callback up to `timeout` and exchanges the authorization code +
    /// PKCE verifier at the token endpoint for an [`OAuthTokenBundle`].
    pub async fn wait_for_callback_and_exchange(
        self,
        timeout: Duration,
    ) -> ZeroVaultResult<OAuthTokenBundle> {
        let (code, pkce_verifier, client, config, http_client) =
            self.wait_for_callback(timeout).await?;
        exchange_authorization_code(&client, &http_client, &config, code, pkce_verifier).await
    }
}

/// High-level OAuth2 + S256 PKCE authenticator using an SSRF-safe `reqwest` (`0.12`) client.
#[derive(Clone)]
pub struct OAuthPkceAuthenticator {
    config: OAuthProviderConfig,
    http_client: reqwest::Client,
}

impl fmt::Debug for OAuthPkceAuthenticator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthPkceAuthenticator")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl OAuthPkceAuthenticator {
    /// Creates an authenticator for `config` with a redirect-disabled (`Policy::none()`) HTTP client.
    pub fn new(config: OAuthProviderConfig) -> ZeroVaultResult<Self> {
        let http_client = build_ssrf_safe_http_client()?;
        Ok(Self {
            config,
            http_client,
        })
    }

    /// Returns the provider configuration.
    #[must_use]
    pub fn config(&self) -> &OAuthProviderConfig {
        &self.config
    }

    /// Binds a single-use loopback listener on `127.0.0.1:<port>` (or ephemeral port if `None`).
    pub async fn bind_listener(&self, port: Option<u16>) -> ZeroVaultResult<LoopbackOAuthListener> {
        LoopbackOAuthListener::bind_with_http_client(
            self.config.clone(),
            port,
            self.http_client.clone(),
        )
        .await
    }

    /// Executes the full interactive PKCE loopback flow, passing the authorization URL to
    /// `launch_browser` (or test driver) before waiting up to `timeout` for the callback and
    /// exchanging the code for tokens.
    pub async fn authenticate_with<F, Fut>(
        &self,
        timeout: Duration,
        launch_browser: F,
    ) -> ZeroVaultResult<OAuthTokenBundle>
    where
        F: FnOnce(Url) -> Fut,
        Fut: Future<Output = ZeroVaultResult<()>>,
    {
        let listener = self.bind_listener(None).await?;
        let auth_url = listener.authorize_url().clone();
        launch_browser(auth_url).await?;
        listener.wait_for_callback_and_exchange(timeout).await
    }

    /// Exchanges a stored refresh token for a fresh access token using the SSRF-safe HTTP client,
    /// preserving the prior `refresh_token` if the provider omits a rotated refresh token.
    pub async fn refresh_tokens(
        &self,
        refresh_token: &RedactedSecret,
    ) -> ZeroVaultResult<OAuthTokenBundle> {
        let client = build_configured_client(&self.config, None)?;
        let rt = RefreshToken::new(refresh_token.as_str().to_owned());
        let response = client
            .exchange_refresh_token(&rt)
            .request_async(&self.http_client)
            .await
            .map_err(|err| {
                ZeroVaultError::OAuthError(format!("OAuth2 refresh token exchange failed: {err}"))
            })?;

        Ok(token_response_to_bundle(
            &self.config,
            &response,
            Some(refresh_token.clone()),
        ))
    }

    /// Refreshes the stored token bundle in `store` under `(service, account)`, preserving the
    /// prior `refresh_token` and persisting the newly wrapped bundle via `CryptoEngine`.
    pub async fn refresh_and_persist_tokens(
        &self,
        store: &dyn SecretStore,
        crypto: &dyn CryptoEngine,
        service: &str,
        account: &str,
    ) -> ZeroVaultResult<OAuthTokenBundle> {
        let existing = load_tokens(store, crypto, service, account)
            .await?
            .ok_or_else(|| {
                ZeroVaultError::OAuthError(format!(
                    "no stored OAuth2 token bundle found for account '{account}'"
                ))
            })?;
        let refresh = existing.refresh_token.as_ref().ok_or_else(|| {
            ZeroVaultError::OAuthError(format!(
                "stored OAuth2 token bundle for account '{account}' has no refresh_token"
            ))
        })?;
        let refreshed = self.refresh_tokens(refresh).await?;
        persist_tokens(&refreshed, store, crypto, service, account).await?;
        Ok(refreshed)
    }
}

async fn exchange_authorization_code(
    client: &ConfiguredOAuthClient,
    http_client: &reqwest::Client,
    config: &OAuthProviderConfig,
    code: AuthorizationCode,
    pkce_verifier: PkceCodeVerifier,
) -> ZeroVaultResult<OAuthTokenBundle> {
    let response = client
        .exchange_code(code)
        .set_pkce_verifier(pkce_verifier)
        .request_async(http_client)
        .await
        .map_err(|err| {
            ZeroVaultError::OAuthError(format!("OAuth2 authorization code exchange failed: {err}"))
        })?;

    tracing::info!(
        provider = config.preset.as_str(),
        has_refresh_token = response.refresh_token().is_some(),
        "completed OAuth2 PKCE token exchange"
    );

    Ok(token_response_to_bundle(config, &response, None))
}

fn token_response_to_bundle<TR: TokenResponse>(
    config: &OAuthProviderConfig,
    response: &TR,
    fallback_refresh_token: Option<RedactedSecret>,
) -> OAuthTokenBundle {
    let access_token = RedactedSecret::new(response.access_token().secret().clone());
    let refresh_token = response
        .refresh_token()
        .map(|rt| RedactedSecret::new(rt.secret().clone()))
        .or(fallback_refresh_token);
    let expires_at = response.expires_in().and_then(|dur| {
        ChronoDuration::from_std(dur)
            .ok()
            .map(|delta| Utc::now() + delta)
    });
    let scopes = response
        .scopes()
        .map(|list| list.iter().map(|s| s.as_str().to_owned()).collect())
        .unwrap_or_else(|| config.scopes.clone());

    OAuthTokenBundle {
        provider: config.preset,
        access_token,
        refresh_token,
        token_type: format!("{:?}", response.token_type()).to_ascii_lowercase(),
        expires_at,
        scopes,
        client_id: Some(config.client_id.clone()),
        client_secret: config.client_secret.clone(),
    }
}

async fn accept_callback_code(
    listener: &TcpListener,
    expected_state: &str,
    per_socket_read_timeout: Duration,
) -> ZeroVaultResult<AuthorizationCode> {
    loop {
        let (mut stream, _peer) = listener.accept().await.map_err(|err| {
            ZeroVaultError::OAuthError(format!("failed accepting loopback connection: {err}"))
        })?;

        let raw_request =
            match tokio::time::timeout(per_socket_read_timeout, read_http_request(&mut stream))
                .await
            {
                Ok(Ok(req)) if !req.trim().is_empty() => req,
                Ok(Ok(_empty)) => {
                    let _ = respond_with_timeout(
                        &mut stream,
                        "400 Bad Request",
                        error_html("Empty OAuth2 callback request."),
                    )
                    .await;
                    continue;
                }
                Ok(Err(err)) => {
                    tracing::warn!(
                        error = %err,
                        "malformed loopback HTTP request; continuing to accept callbacks"
                    );
                    let _ = respond_with_timeout(
                        &mut stream,
                        "400 Bad Request",
                        error_html("Malformed OAuth2 callback request."),
                    )
                    .await;
                    continue;
                }
                Err(_elapsed) => {
                    tracing::warn!(
                        timeout_ms = per_socket_read_timeout.as_millis(),
                        "loopback OAuth socket read timed out (slowloris defense); continuing"
                    );
                    let _ = respond_with_timeout(
                        &mut stream,
                        "400 Bad Request",
                        error_html("Loopback callback socket timed out."),
                    )
                    .await;
                    continue;
                }
            };

        let request_line = raw_request.lines().next().unwrap_or_default();
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or_default();
        let target = parts.next().unwrap_or_default();

        if !target.starts_with('/') {
            let _ = respond_with_timeout(
                &mut stream,
                "400 Bad Request",
                error_html("Invalid request target."),
            )
            .await;
            continue;
        }

        let Ok(parsed_url) = Url::parse(&format!("http://127.0.0.1{target}")) else {
            let _ = respond_with_timeout(
                &mut stream,
                "400 Bad Request",
                error_html("Invalid callback URL."),
            )
            .await;
            continue;
        };

        if parsed_url.path() != "/callback" {
            let _ = respond_with_timeout(
                &mut stream,
                "404 Not Found",
                error_html("Not Found. Waiting for OAuth2 /callback."),
            )
            .await;
            continue;
        }

        if method != "GET" {
            let _ = respond_with_timeout(
                &mut stream,
                "400 Bad Request",
                error_html("Expected HTTP GET for OAuth2 callback."),
            )
            .await;
            continue;
        }

        let mut code: Option<String> = None;
        let mut state: Option<String> = None;
        let mut oauth_error: Option<String> = None;
        let mut oauth_error_desc: Option<String> = None;

        for (k, v) in parsed_url.query_pairs() {
            match k.as_ref() {
                "code" => code = Some(v.into_owned()),
                "state" => state = Some(v.into_owned()),
                "error" => oauth_error = Some(v.into_owned()),
                "error_description" => oauth_error_desc = Some(v.into_owned()),
                _ => {}
            }
        }

        // NEW-L01 remediation: missing or mismatched CSRF `state` responds 400 Bad Request
        // and continues accepting connections so local port probes cannot abort user login.
        let Some(received_state) = state.filter(|s| !s.is_empty()) else {
            tracing::warn!(
                "loopback /callback missing state parameter; rejecting probe and continuing"
            );
            let _ = respond_with_timeout(
                &mut stream,
                "400 Bad Request",
                error_html("Missing CSRF state parameter in OAuth2 callback."),
            )
            .await;
            continue;
        };

        if !constant_time_csrf_eq(expected_state, &received_state) {
            tracing::warn!(
                "loopback /callback CSRF state mismatch; rejecting probe and continuing"
            );
            let _ = respond_with_timeout(
                &mut stream,
                "400 Bad Request",
                error_html("CSRF state validation failed."),
            )
            .await;
            continue;
        }

        // Only honour an OAuth2 `error` parameter once constant-time CSRF `state` has matched
        // (RFC 6749 §4.1.2.1 requires `state` on genuine authorization error redirects).
        if let Some(err_code) = oauth_error {
            let _ = respond_with_timeout(
                &mut stream,
                "400 Bad Request",
                error_html("Authorization was denied or cancelled by the OAuth2 provider."),
            )
            .await;
            let detail = oauth_error_desc.unwrap_or_else(|| "no description".to_owned());
            return Err(ZeroVaultError::OAuthError(format!(
                "provider returned authorization error '{err_code}': {detail}"
            )));
        }

        // NEW-L01 remediation: missing `code` responds 400 Bad Request and continues listening.
        let Some(auth_code) = code.filter(|c| !c.is_empty()) else {
            tracing::warn!("loopback /callback missing authorization code; continuing to listen");
            let _ = respond_with_timeout(
                &mut stream,
                "400 Bad Request",
                error_html("Missing authorization code in OAuth2 callback."),
            )
            .await;
            continue;
        };

        respond_with_timeout(&mut stream, "200 OK", success_html()).await?;
        return Ok(AuthorizationCode::new(auth_code));
    }
}

async fn read_http_request(stream: &mut TcpStream) -> ZeroVaultResult<String> {
    let mut buf = vec![0u8; MAX_CALLBACK_HTTP_BYTES];
    let mut total = 0usize;

    loop {
        if total == buf.len() {
            return Err(ZeroVaultError::OAuthError(
                "OAuth2 loopback HTTP request exceeded maximum header size".into(),
            ));
        }
        let n = stream.read(&mut buf[total..]).await.map_err(|err| {
            ZeroVaultError::OAuthError(format!("failed reading loopback HTTP request: {err}"))
        })?;
        if n == 0 {
            break;
        }
        total += n;
        if buf[..total].windows(4).any(|w| w == b"\r\n\r\n")
            || buf[..total].windows(2).any(|w| w == b"\n\n")
        {
            break;
        }
    }

    String::from_utf8(buf[..total].to_vec()).map_err(|_| {
        ZeroVaultError::OAuthError("non-UTF-8 bytes in OAuth2 loopback callback request".into())
    })
}

async fn respond_with_timeout(
    stream: &mut TcpStream,
    status: &str,
    body: &str,
) -> ZeroVaultResult<()> {
    tokio::time::timeout(
        PER_SOCKET_WRITE_TIMEOUT,
        write_http_response(stream, status, body),
    )
    .await
    .map_err(|_| ZeroVaultError::OAuthError("timed out writing loopback HTTP response".into()))?
}

async fn write_http_response(
    stream: &mut TcpStream,
    status: &str,
    body: &str,
) -> ZeroVaultResult<()> {
    let response = format!(
        "HTTP/1.1 {status}\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Cache-Control: no-store\r\n\
         X-Content-Type-Options: nosniff\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .await
        .map_err(|err| {
            ZeroVaultError::OAuthError(format!("failed writing loopback HTTP response: {err}"))
        })?;
    stream.flush().await.map_err(|err| {
        ZeroVaultError::OAuthError(format!("failed flushing loopback HTTP response: {err}"))
    })?;
    let _ = stream.shutdown().await;
    Ok(())
}

fn success_html() -> &'static str {
    "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
     <title>ZeroVault Authentication Complete</title></head>\
     <body style=\"font-family:sans-serif;max-width:34rem;margin:4rem auto;text-align:center\">\
     <h1>ZeroVault Connected</h1>\
     <p>OAuth2 authentication succeeded. You may close this browser tab and return to ZeroVault.</p>\
     </body></html>"
}

fn error_html(message: &str) -> &'static str {
    let _ = message;
    "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
     <title>ZeroVault Authentication Error</title></head>\
     <body style=\"font-family:sans-serif;max-width:34rem;margin:4rem auto;text-align:center\">\
     <h1>Authentication Failed</h1>\
     <p>The OAuth2 callback could not be verified. Please return to ZeroVault and try again.</p>\
     </body></html>"
}

/// Encrypts `bundle` under `CryptoEngine::wrap_token_payload` (`TokenWrapKey`) and stores it in
/// `SecretStore` under `(service, account)`.
pub async fn persist_tokens(
    bundle: &OAuthTokenBundle,
    store: &dyn SecretStore,
    crypto: &dyn CryptoEngine,
    service: &str,
    account: &str,
) -> ZeroVaultResult<()> {
    let payload = StoredTokenPayload {
        provider: bundle.provider,
        access_token: bundle.access_token.as_str().to_owned(),
        refresh_token: bundle
            .refresh_token
            .as_ref()
            .map(|s| s.as_str().to_owned()),
        token_type: bundle.token_type.clone(),
        expires_at: bundle.expires_at,
        scopes: bundle.scopes.clone(),
        client_id: bundle.client_id.clone(),
        client_secret: bundle
            .client_secret
            .as_ref()
            .map(|s| s.as_str().to_owned()),
    };

    let json_bytes = Zeroizing::new(serde_json::to_vec(&payload).map_err(|err| {
        ZeroVaultError::OAuthError(format!("failed serializing OAuth2 token payload: {err}"))
    })?);
    drop(payload);

    let wrapped = crypto.wrap_token_payload(json_bytes.as_slice())?;
    store.set_secret(service, account, &wrapped).await?;

    tracing::info!(
        service = service,
        account = account,
        provider = bundle.provider.as_str(),
        "persisted encrypted OAuth2 token bundle"
    );
    Ok(())
}

/// Loads and decrypts an [`OAuthTokenBundle`] from `SecretStore` using
/// `CryptoEngine::unwrap_token_payload`. Returns `Ok(None)` if no entry exists.
pub async fn load_tokens(
    store: &dyn SecretStore,
    crypto: &dyn CryptoEngine,
    service: &str,
    account: &str,
) -> ZeroVaultResult<Option<OAuthTokenBundle>> {
    let Some(wrapped) = store.get_secret(service, account).await? else {
        return Ok(None);
    };

    let plaintext = crypto.unwrap_token_payload(wrapped.as_slice())?;
    let payload: StoredTokenPayload =
        serde_json::from_slice(plaintext.as_slice()).map_err(|err| {
            ZeroVaultError::InvalidWireFormat(format!(
                "corrupted OAuth2 token payload in secret store: {err}"
            ))
        })?;

    Ok(Some(OAuthTokenBundle {
        provider: payload.provider,
        access_token: RedactedSecret::new(payload.access_token.clone()),
        refresh_token: payload.refresh_token.as_deref().map(RedactedSecret::new),
        token_type: payload.token_type.clone(),
        expires_at: payload.expires_at,
        scopes: payload.scopes.clone(),
        client_id: payload.client_id.clone(),
        client_secret: payload.client_secret.as_deref().map(RedactedSecret::new),
    }))
}

/// Deletes a persisted OAuth2 token bundle from `SecretStore`.
pub async fn delete_tokens(
    store: &dyn SecretStore,
    service: &str,
    account: &str,
) -> ZeroVaultResult<()> {
    store.delete_secret(service, account).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_provider_least_privilege_scopes_and_csrf() -> ZeroVaultResult<()> {
        assert_eq!(
            OAuthProviderPreset::GoogleDrive.default_scopes(),
            vec!["https://www.googleapis.com/auth/drive.file".to_owned()]
        );
        assert_eq!(
            OAuthProviderPreset::OneDrive.default_scopes(),
            vec![
                "Files.ReadWrite.AppFolder".to_owned(),
                "offline_access".to_owned(),
            ]
        );
        assert_eq!(
            OAuthProviderPreset::Dropbox.default_scopes(),
            vec![
                "files.content.write".to_owned(),
                "files.content.read".to_owned(),
            ]
        );
        assert!(constant_time_csrf_eq("alpha-state", "alpha-state"));
        assert!(!constant_time_csrf_eq("alpha-state", "alpha-statE"));
        assert!(!constant_time_csrf_eq("alpha-state", "short"));
        let _client = build_ssrf_safe_http_client()?;
        Ok(())
    }

    #[tokio::test]
    async fn unit_oauth_offline_refresh_params_for_gdrive_and_dropbox() -> ZeroVaultResult<()> {
        let gdrive = LoopbackOAuthListener::bind_ephemeral(OAuthProviderConfig::for_preset(
            OAuthProviderPreset::GoogleDrive,
            "test-client-id",
            None,
        ))
        .await?;
        let gdrive_params: std::collections::HashMap<String, String> = gdrive
            .authorize_url()
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        assert_eq!(
            gdrive_params.get("access_type").map(String::as_str),
            Some("offline")
        );
        assert_eq!(
            gdrive_params.get("prompt").map(String::as_str),
            Some("consent")
        );

        let dropbox = LoopbackOAuthListener::bind_ephemeral(OAuthProviderConfig::for_preset(
            OAuthProviderPreset::Dropbox,
            "test-client-id",
            None,
        ))
        .await?;
        let dropbox_params: std::collections::HashMap<String, String> = dropbox
            .authorize_url()
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        assert_eq!(
            dropbox_params.get("token_access_type").map(String::as_str),
            Some("offline")
        );

        Ok(())
    }
}

