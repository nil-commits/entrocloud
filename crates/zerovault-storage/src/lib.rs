//! Multi-cloud OpenDAL storage router & OAuth2 + PKCE connector for Zerovault.
//!
//! Provides:
//! - [`CloudBackend`] (and alias [`OpenDalBackend`]) wrapping Apache `opendal` v0.59 adapters
//!   across Google Drive, OneDrive, Dropbox, S3, WebDAV, LocalFs, and Memory with retry, timeout,
//!   and concurrency-limit layers plus atomic quota accounting and health tracking.
//! - [`LoopbackOAuthListener`] and [`OAuthPkceAuthenticator`] using `oauth2` v5.0 Authorization
//!   Code + S256 PKCE, SSRF-safe `redirect::Policy::none()`, constant-time CSRF state validation,
//!   and AEAD-wrapped `SecretStore` token persistence (`persist_tokens` / `load_tokens`).
//! - [`StorageRouter`] implementing [`zerovault_types::StorageRouterTrait`] with strict
//!   `validate_remote_object_key` enforcement and Targeted, Mirrored RAID-1, and Quota-Pooled
//!   policies plus optimistic manifest CAS.

pub mod backend;
pub mod oauth;
pub mod router;

pub use backend::{BackendLayerConfig, CloudBackend, DEFAULT_UNBOUNDED_QUOTA_BYTES, OpenDalBackend};
pub use oauth::{
    DEFAULT_TOKEN_SECRET_SERVICE, LoopbackOAuthListener, OAuthPkceAuthenticator,
    OAuthProviderConfig, OAuthProviderPreset, OAuthTokenBundle, build_ssrf_safe_http_client,
    constant_time_csrf_eq, delete_tokens, load_tokens, persist_tokens,
};
pub use router::{QuotaSelectionStrategy, StorageRouter};
pub use zerovault_types;
