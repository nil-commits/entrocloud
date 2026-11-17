//! OAuth2 Authorization Code + S256 PKCE loopback authentication and encrypted token storage.
//!
//! Implements RFC 8252 native-app loopback redirection (`127.0.0.1:<port>`), SSRF-safe HTTP
//! client configuration (`redirect::Policy::none()`), constant-time CSRF state validation
//! (`subtle::ConstantTimeEq`), and AEAD-wrapped token persistence via `CryptoEngine` + `SecretStore`.

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
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use url::Url;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use zerovault_types::{
    BackendKind, CryptoEngine, RedactedSecret, SecretStore, ZeroVaultError, ZeroVaultResult,
};

/// Default [`SecretStore`] service namespace used when persisting wrapped OAuth2 token bundles.
pub const DEFAULT_TOKEN_SECRET_SERVICE: &str = "zerovault.oauth2";

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

    /// Recommended minimal scopes required for encrypted blob & manifest storage.
    #[must_use]
    pub fn default_scopes(self) -> Vec<String> {
        match self {
            Self::GoogleDrive => vec!["https://www.googleapis.com/auth/drive.file".to_owned()],
            Self::OneDrive => vec![
                "Files.ReadWrite.All".to_owned(),
                "offline_access".to_owned(),
            ],
            Self::Dropbox => vec![
                "files.content.read".to_owned(),
                "files.content.write".to_owned(),
                "files.metadata.read".to_owned(),
                "files.metadata.write".to_owned(),
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
    /// Builds a configuration using a provider preset's canonical endpoints and default scopes.
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

/// Constructs an SSRF-safe asynchronous HTTP client that never follows HTTP redirects.
pub fn build_ssrf_safe_http_client() -> ZeroVaultResult<oauth2::reqwest::Client> {
    oauth2::reqwest::ClientBuilder::new()
        .redirect(oauth2::reqwest::redirect::Policy::none())
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

/// Active loopback HTTP callback listener holding a single-use PKCE verifier and CSRF state token.
pub struct LoopbackOAuthListener {
    listener: TcpListener,
    local_addr: SocketAddr,
    redirect_uri: String,
    authorize_url: Url,
    csrf_token: CsrfToken,
    pkce_verifier: PkceCodeVerifier,
    client: ConfiguredOAuthClient,
    http_client: oauth2::reqwest::Client,
    config: OAuthProviderConfig,
}

impl fmt::Debug for LoopbackOAuthListener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoopbackOAuthListener")
            .field("local_addr", &self.local_addr)
            .field("redirect_uri", &self.redirect_uri)
            .field("provider", &self.config.preset)
            .field("csrf_token", &"[REDACTED]")
            .field("pkce_verifier", &"[REDACTED]")
            .finish()
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
        http_client: oauth2::reqwest::Client,
    ) -> ZeroVaultResult<Self> {
        let bind_port = port.unwrap_or(0);
        let listener = TcpListener::bind(("127.0.0.1", bind_port))
            .await
            .map_err(|err| {
                ZeroVaultError::OAuthError(format!("failed to bind loopback OAuth listener: {err}"))
            })?;
        let local_addr = listener.local_addr().map_err(|err| {
            ZeroVaultError::OAuthError(format!("failed to inspect loopback listener address: {err}"))
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
        })
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

    /// Waits up to `timeout` for the loopback HTTP GET `/callback`, validates the CSRF `state`
    /// in constant time, serves a clean HTML response, and returns the authorization code.
    pub async fn wait_for_callback(
        self,
        timeout: Duration,
    ) -> ZeroVaultResult<(AuthorizationCode, PkceCodeVerifier, ConfiguredOAuthClient, OAuthProviderConfig, oauth2::reqwest::Client)> {
        let code = tokio::time::timeout(
            timeout,
            accept_callback_code(&self.listener, self.csrf_token.secret()),
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

/// High-level OAuth2 + S256 PKCE authenticator using an SSRF-safe `reqwest` client.
#[derive(Clone)]
pub struct OAuthPkceAuthenticator {
    config: OAuthProviderConfig,
    http_client: oauth2::reqwest::Client,
}

impl fmt::Debug for OAuthPkceAuthenticator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthPkceAuthenticator")
            .field("config", &self.config)
            .finish()
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

    /// Exchanges a stored refresh token for a fresh access token using the SSRF-safe HTTP client.
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
}

async fn exchange_authorization_code(
    client: &ConfiguredOAuthClient,
    http_client: &oauth2::reqwest::Client,
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
        .map(|list| list.iter().map(|s| s.to_string()).collect())
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
) -> ZeroVaultResult<AuthorizationCode> {
    loop {
        let (mut stream, _peer) = listener.accept().await.map_err(|err| {
            ZeroVaultError::OAuthError(format!("failed accepting loopback connection: {err}"))
        })?;

        let raw_request = match read_http_request(&mut stream).await {
            Ok(req) => req,
            Err(err) => {
                let _ = write_http_response(
                    &mut stream,
                    "400 Bad Request",
                    error_html("Malformed OAuth2 callback request."),
                )
                .await;
                return Err(err);
            }
        };

        let request_line = raw_request.lines().next().unwrap_or_default();
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or_default();
        let target = parts.next().unwrap_or_default();

        if !target.starts_with('/') {
            let _ = write_http_response(
                &mut stream,
                "400 Bad Request",
                error_html("Invalid request target."),
            )
            .await;
            return Err(ZeroVaultError::OAuthError(
                "invalid HTTP request target on loopback callback".into(),
            ));
        }

        let parsed_url = Url::parse(&format!("http://127.0.0.1{target}")).map_err(|err| {
            ZeroVaultError::OAuthError(format!("failed parsing callback URL query: {err}"))
        })?;

        // Ignore stray browser requests such as `/favicon.ico` and keep listening.
        if parsed_url.path() != "/callback" {
            let _ = write_http_response(
                &mut stream,
                "404 Not Found",
                error_html("Not Found. Waiting for OAuth2 /callback."),
            )
            .await;
            continue;
        }

        if method != "GET" {
            let _ = write_http_response(
                &mut stream,
                "405 Method Not Allowed",
                error_html("Expected HTTP GET for OAuth2 callback."),
            )
            .await;
            return Err(ZeroVaultError::OAuthError(
                "expected HTTP GET on OAuth2 loopback /callback".into(),
            ));
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

        if let Some(err_code) = oauth_error {
            let _ = write_http_response(
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

        let Some(received_state) = state else {
            let _ = write_http_response(
                &mut stream,
                "400 Bad Request",
                error_html("Missing CSRF state parameter in OAuth2 callback."),
            )
            .await;
            return Err(ZeroVaultError::OAuthError(
                "missing state parameter in OAuth2 callback".into(),
            ));
        };

        if !constant_time_csrf_eq(expected_state, &received_state) {
            let _ = write_http_response(
                &mut stream,
                "400 Bad Request",
                error_html("CSRF state validation failed. Authentication aborted."),
            )
            .await;
            return Err(ZeroVaultError::OAuthError(
                "OAuth2 CSRF state mismatch (constant-time check failed)".into(),
            ));
        }

        let Some(auth_code) = code.filter(|c| !c.is_empty()) else {
            let _ = write_http_response(
                &mut stream,
                "400 Bad Request",
                error_html("Missing authorization code in OAuth2 callback."),
            )
            .await;
            return Err(ZeroVaultError::OAuthError(
                "missing authorization code in OAuth2 callback".into(),
            ));
        };

        write_http_response(&mut stream, "200 OK", success_html()).await?;
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
     <title>Zerovault Authentication Complete</title></head>\
     <body style=\"font-family:sans-serif;max-width:34rem;margin:4rem auto;text-align:center\">\
     <h1>Zerovault Connected</h1>\
     <p>OAuth2 authentication succeeded. You may close this browser tab and return to Zerovault.</p>\
     </body></html>"
}

fn error_html(message: &str) -> &'static str {
    let _ = message;
    "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
     <title>Zerovault Authentication Error</title></head>\
     <body style=\"font-family:sans-serif;max-width:34rem;margin:4rem auto;text-align:center\">\
     <h1>Authentication Failed</h1>\
     <p>The OAuth2 callback could not be verified. Please return to Zerovault and try again.</p>\
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
    use std::sync::Arc;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;
    use zerovault_types::mocks::{InMemorySecretStore, MockCryptoEngine};

    use super::*;

    #[derive(Debug, Default)]
    struct MockTokenServerCapture {
        grant_type: Option<String>,
        code: Option<String>,
        code_verifier: Option<String>,
        redirect_uri: Option<String>,
    }

    async fn spawn_mock_oauth_token_server(
        capture: Arc<Mutex<MockTokenServerCapture>>,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind mock oauth token server");
        let addr = listener.local_addr().expect("mock server local_addr");

        let handle = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept token request");
            let mut raw = Vec::new();
            let mut tmp = [0u8; 4096];
            loop {
                let n = sock.read(&mut tmp).await.expect("read request");
                if n == 0 {
                    break;
                }
                raw.extend_from_slice(&tmp[..n]);
                if let Some(hdr_end) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                    let hdr_str = String::from_utf8_lossy(&raw[..hdr_end]);
                    let content_len = hdr_str
                        .lines()
                        .find_map(|line| {
                            let (k, v) = line.split_once(':')?;
                            if k.eq_ignore_ascii_case("content-length") {
                                v.trim().parse::<usize>().ok()
                            } else {
                                None
                            }
                        })
                        .unwrap_or(0);
                    let body_start = hdr_end + 4;
                    while raw.len() < body_start + content_len {
                        let m = sock.read(&mut tmp).await.expect("read body");
                        if m == 0 {
                            break;
                        }
                        raw.extend_from_slice(&tmp[..m]);
                    }
                    let body = String::from_utf8_lossy(&raw[body_start..]).into_owned();
                    let mut guard = capture.lock().await;
                    for (k, v) in url::form_urlencoded::parse(body.as_bytes()) {
                        match k.as_ref() {
                            "grant_type" => guard.grant_type = Some(v.into_owned()),
                            "code" => guard.code = Some(v.into_owned()),
                            "code_verifier" => guard.code_verifier = Some(v.into_owned()),
                            "redirect_uri" => guard.redirect_uri = Some(v.into_owned()),
                            _ => {}
                        }
                    }
                    break;
                }
            }

            let resp_body = r#"{
                "access_token": "mock-access-token-secret-xyz",
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "mock-refresh-token-secret-abc",
                "scope": "https://www.googleapis.com/auth/drive.file"
            }"#;
            let http_resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{resp_body}",
                resp_body.len()
            );
            sock.write_all(http_resp.as_bytes())
                .await
                .expect("write token response");
            let _ = sock.shutdown().await;
        });

        (addr, handle)
    }

    #[test]
    fn token_bundle_and_config_redact_debug_output() {
        let cfg = OAuthProviderConfig::for_preset(
            OAuthProviderPreset::GoogleDrive,
            "pub-client-id",
            Some(RedactedSecret::new("super-secret-client-secret")),
        );
        let cfg_dbg = format!("{cfg:?}");
        assert!(!cfg_dbg.contains("super-secret-client-secret"));
        assert!(cfg_dbg.contains("[REDACTED]"));

        let bundle = OAuthTokenBundle {
            provider: OAuthProviderPreset::Dropbox,
            access_token: RedactedSecret::new("secret-access-token-value"),
            refresh_token: Some(RedactedSecret::new("secret-refresh-token-value")),
            token_type: "bearer".to_owned(),
            expires_at: Some(Utc::now() + ChronoDuration::hours(1)),
            scopes: vec!["files.content.read".to_owned()],
            client_id: Some("cid".to_owned()),
            client_secret: Some(RedactedSecret::new("secret-client-secret-value")),
        };
        let bundle_dbg = format!("{bundle:?}");
        assert!(!bundle_dbg.contains("secret-access-token-value"));
        assert!(!bundle_dbg.contains("secret-refresh-token-value"));
        assert!(!bundle_dbg.contains("secret-client-secret-value"));
        assert!(bundle_dbg.contains("[REDACTED]"));
    }

    #[test]
    fn constant_time_csrf_check_rejects_mismatches() {
        assert!(constant_time_csrf_eq("abc123token", "abc123token"));
        assert!(!constant_time_csrf_eq("abc123token", "abc123tokEn"));
        assert!(!constant_time_csrf_eq("abc123token", "abc123"));
    }

    #[tokio::test]
    async fn oauth2_pkce_loopback_flow_exchanges_and_persists_wrapped_tokens() {
        let capture = Arc::new(Mutex::new(MockTokenServerCapture::default()));
        let (token_addr, server_task) = spawn_mock_oauth_token_server(capture.clone()).await;

        let config = OAuthProviderConfig::for_preset(
            OAuthProviderPreset::GoogleDrive,
            "zerovault-desktop-client",
            Some(RedactedSecret::new("desktop-client-secret")),
        )
        .with_endpoints(
            "https://accounts.google.com/o/oauth2/v2/auth",
            format!("http://{token_addr}/token"),
        );

        let listener = LoopbackOAuthListener::bind_ephemeral(config)
            .await
            .expect("bind loopback listener");

        let auth_url = listener.authorize_url().clone();
        let redirect_uri = listener.redirect_uri().to_owned();
        let port = listener.local_addr().port();

        let query: std::collections::HashMap<String, String> = auth_url
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        assert_eq!(
            query.get("code_challenge_method").map(String::as_str),
            Some("S256")
        );
        let code_challenge = query
            .get("code_challenge")
            .expect("PKCE code_challenge present")
            .clone();
        assert!(!code_challenge.is_empty());
        let state = query.get("state").expect("CSRF state present").clone();
        assert_eq!(
            query.get("redirect_uri").map(String::as_str),
            Some(redirect_uri.as_str())
        );

        let flow_handle = tokio::spawn(async move {
            listener
                .wait_for_callback_and_exchange(Duration::from_secs(5))
                .await
        });

        // Simulate browser redirect to 127.0.0.1:<port>/callback?code=...&state=...
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("reqwest client");
        let callback_url = format!(
            "http://127.0.0.1:{port}/callback?code=auth-code-42&state={}",
            url::form_urlencoded::byte_serialize(state.as_bytes()).collect::<String>()
        );
        let cb_resp = client
            .get(callback_url)
            .send()
            .await
            .expect("send loopback callback");
        assert_eq!(cb_resp.status(), reqwest::StatusCode::OK);
        let html = cb_resp.text().await.expect("html body");
        assert!(html.contains("Zerovault Connected"));

        let bundle = flow_handle
            .await
            .expect("join flow")
            .expect("exchange succeeds");
        server_task.await.expect("mock token server completes");

        assert_eq!(bundle.access_token.as_str(), "mock-access-token-secret-xyz");
        assert_eq!(
            bundle.refresh_token.as_ref().map(RedactedSecret::as_str),
            Some("mock-refresh-token-secret-abc")
        );

        let captured = capture.lock().await;
        assert_eq!(captured.grant_type.as_deref(), Some("authorization_code"));
        assert_eq!(captured.code.as_deref(), Some("auth-code-42"));
        assert_eq!(
            captured.redirect_uri.as_deref(),
            Some(redirect_uri.as_str())
        );
        let verifier_str = captured
            .code_verifier
            .as_deref()
            .expect("PKCE code_verifier sent to token endpoint");
        let expected_challenge = PkceCodeChallenge::from_code_verifier_sha256(
            &PkceCodeVerifier::new(verifier_str.to_owned()),
        );
        assert_eq!(expected_challenge.as_str(), code_challenge);

        // Verify encrypted SecretStore persistence via CryptoEngine::wrap_token_payload.
        let crypto = MockCryptoEngine::default();
        let secrets = InMemorySecretStore::default();
        persist_tokens(
            &bundle,
            &secrets,
            &crypto,
            DEFAULT_TOKEN_SECRET_SERVICE,
            "gdrive-personal",
        )
        .await
        .expect("persist wrapped tokens");

        // SecretStore raw bytes MUST NOT contain plaintext token strings.
        let raw_stored = secrets
            .get_secret(DEFAULT_TOKEN_SECRET_SERVICE, "gdrive-personal")
            .await
            .expect("get raw secret")
            .expect("secret exists");
        assert!(
            !String::from_utf8_lossy(raw_stored.as_slice())
                .contains("mock-access-token-secret-xyz")
        );
        assert!(
            !String::from_utf8_lossy(raw_stored.as_slice())
                .contains("mock-refresh-token-secret-abc")
        );

        let loaded = load_tokens(
            &secrets,
            &crypto,
            DEFAULT_TOKEN_SECRET_SERVICE,
            "gdrive-personal",
        )
        .await
        .expect("load tokens")
        .expect("tokens present");
        assert_eq!(loaded.access_token.as_str(), "mock-access-token-secret-xyz");
        assert_eq!(
            loaded.refresh_token.as_ref().map(RedactedSecret::as_str),
            Some("mock-refresh-token-secret-abc")
        );
    }

    #[tokio::test]
    async fn oauth2_loopback_rejects_mismatched_csrf_state() {
        let config = OAuthProviderConfig::for_preset(
            OAuthProviderPreset::OneDrive,
            "client-id",
            None,
        )
        .with_endpoints(
            "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
            "http://127.0.0.1:9/unused-token",
        );

        let listener = LoopbackOAuthListener::bind_ephemeral(config)
            .await
            .expect("bind loopback");
        let port = listener.local_addr().port();

        let task = tokio::spawn(async move {
            listener
                .wait_for_callback_and_exchange(Duration::from_secs(5))
                .await
        });

        let client = reqwest::Client::new();
        let resp = client
            .get(format!(
                "http://127.0.0.1:{port}/callback?code=evil-code&state=forged-csrf-state"
            ))
            .send()
            .await
            .expect("send forged callback");
        assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);

        let err = task
            .await
            .expect("join task")
            .expect_err("CSRF mismatch must fail closed");
        assert!(matches!(err, ZeroVaultError::OAuthError(_)));
    }

    #[tokio::test]
    async fn oauth2_ssrf_redirect_policy_none_blocks_redirects() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let trap_hit = Arc::new(AtomicBool::new(false));
        let trap_hit_clone = trap_hit.clone();
        let trap_listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind trap");
        let trap_addr = trap_listener.local_addr().expect("trap addr");
        let _trap_handle = tokio::spawn(async move {
            if let Ok((mut s, _)) = trap_listener.accept().await {
                trap_hit_clone.store(true, Ordering::SeqCst);
                let _ = s
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                    .await;
            }
        });

        let redirect_listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind redirect server");
        let redirect_addr = redirect_listener.local_addr().expect("redirect addr");
        let redir_handle = tokio::spawn(async move {
            let (mut s, _) = redirect_listener.accept().await.expect("accept");
            let mut buf = [0u8; 2048];
            let _ = s.read(&mut buf).await;
            let resp = format!(
                "HTTP/1.1 302 Found\r\nLocation: http://{trap_addr}/ssrf-target\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            s.write_all(resp.as_bytes()).await.expect("write 302");
            let _ = s.shutdown().await;
        });

        let config = OAuthProviderConfig::for_preset(
            OAuthProviderPreset::Dropbox,
            "client-id",
            Some(RedactedSecret::new("client-secret")),
        )
        .with_endpoints(
            "https://www.dropbox.com/oauth2/authorize",
            format!("http://{redirect_addr}/token"),
        );

        let listener = LoopbackOAuthListener::bind_ephemeral(config)
            .await
            .expect("bind");
        let port = listener.local_addr().port();
        let state = listener
            .authorize_url()
            .query_pairs()
            .find(|(k, _)| k == "state")
            .expect("state")
            .1
            .into_owned();

        let flow_handle = tokio::spawn(async move {
            listener
                .wait_for_callback_and_exchange(Duration::from_secs(5))
                .await
        });

        let client = reqwest::Client::new();
        let resp = client
            .get(format!(
                "http://127.0.0.1:{port}/callback?code=c123&state={}",
                url::form_urlencoded::byte_serialize(state.as_bytes()).collect::<String>()
            ))
            .send()
            .await
            .expect("callback");
        assert_eq!(resp.status(), reqwest::StatusCode::OK);

        let err = flow_handle
            .await
            .expect("join")
            .expect_err("302 redirect at token endpoint must fail closed");
        assert!(matches!(err, ZeroVaultError::OAuthError(_)));
        redir_handle.await.expect("redir server");
        assert!(
            !trap_hit.load(Ordering::SeqCst),
            "SSRF redirect target must NEVER be contacted"
        );
    }

    #[tokio::test]
    async fn oauth2_loopback_ignores_favicon_and_refreshes_preserving_refresh_token() {
        let refresh_listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind refresh server");
        let refresh_addr = refresh_listener.local_addr().expect("refresh addr");
        let server_task = tokio::spawn(async move {
            // 1. Initial auth code exchange
            let (mut s1, _) = refresh_listener.accept().await.expect("accept 1");
            let mut buf = [0u8; 4096];
            let _ = s1.read(&mut buf).await;
            let body1 = r#"{"access_token":"tok-1","token_type":"Bearer","expires_in":3600,"refresh_token":"rt-keep"}"#;
            let r1 = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body1}",
                body1.len()
            );
            s1.write_all(r1.as_bytes()).await.expect("write 1");
            let _ = s1.shutdown().await;

            // 2. Refresh exchange omitting refresh_token per RFC 6749 §6
            let (mut s2, _) = refresh_listener.accept().await.expect("accept 2");
            let _ = s2.read(&mut buf).await;
            let body2 = r#"{"access_token":"tok-2","token_type":"Bearer","expires_in":7200}"#;
            let r2 = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body2}",
                body2.len()
            );
            s2.write_all(r2.as_bytes()).await.expect("write 2");
            let _ = s2.shutdown().await;
        });

        let config = OAuthProviderConfig::for_preset(
            OAuthProviderPreset::GoogleDrive,
            "client-id",
            Some(RedactedSecret::new("client-secret")),
        )
        .with_endpoints(
            "https://accounts.google.com/o/oauth2/v2/auth",
            format!("http://{refresh_addr}/token"),
        );

        let auth = OAuthPkceAuthenticator::new(config).expect("auth");
        let listener = auth.bind_listener(None).await.expect("bind");
        let port = listener.local_addr().port();
        let state = listener
            .authorize_url()
            .query_pairs()
            .find(|(k, _)| k == "state")
            .expect("state")
            .1
            .into_owned();

        let flow = tokio::spawn(async move {
            listener
                .wait_for_callback_and_exchange(Duration::from_secs(5))
                .await
        });

        let client = reqwest::Client::new();
        // Browser sends stray /favicon.ico first -> gets 404, listener keeps waiting.
        let fav = client
            .get(format!("http://127.0.0.1:{port}/favicon.ico"))
            .send()
            .await
            .expect("favicon");
        assert_eq!(fav.status(), reqwest::StatusCode::NOT_FOUND);

        let cb = client
            .get(format!(
                "http://127.0.0.1:{port}/callback?code=code-1&state={}",
                url::form_urlencoded::byte_serialize(state.as_bytes()).collect::<String>()
            ))
            .send()
            .await
            .expect("callback");
        assert_eq!(cb.status(), reqwest::StatusCode::OK);

        let bundle1 = flow.await.expect("join").expect("exchange");
        assert_eq!(bundle1.access_token.as_str(), "tok-1");
        let rt = bundle1.refresh_token.as_ref().expect("rt present");
        let bundle2 = auth.refresh_tokens(rt).await.expect("refresh tokens");
        assert_eq!(bundle2.access_token.as_str(), "tok-2");
        assert_eq!(
            bundle2.refresh_token.as_ref().map(RedactedSecret::as_str),
            Some("rt-keep")
        );
        server_task.await.expect("server completes");
    }

    #[tokio::test]
    async fn oauth2_loopback_handles_provider_access_denied_error() {
        let config = OAuthProviderConfig::for_preset(
            OAuthProviderPreset::OneDrive,
            "client-id",
            None,
        );
        let listener = LoopbackOAuthListener::bind_ephemeral(config)
            .await
            .expect("bind");
        let port = listener.local_addr().port();

        let flow = tokio::spawn(async move {
            listener
                .wait_for_callback_and_exchange(Duration::from_secs(5))
                .await
        });

        let client = reqwest::Client::new();
        let resp = client
            .get(format!(
                "http://127.0.0.1:{port}/callback?error=access_denied&error_description=user_cancelled"
            ))
            .send()
            .await
            .expect("callback");
        assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);

        let err = flow.await.expect("join").expect_err("provider error");
        assert!(matches!(err, ZeroVaultError::OAuthError(_)));
    }
}
