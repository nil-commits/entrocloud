//! Multi-cloud OpenDAL `0.59` storage router, hardened OAuth2 + S256 PKCE loopback authenticator,
//! verified RAID-1 failover, and deterministic SplitMix64 network chaos fault injector.

#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented
)]

pub mod backend;
pub mod chaos;
pub mod oauth;
pub mod router;

pub use backend::{
    BackendLayerConfig, CloudBackend, DEFAULT_UNBOUNDED_QUOTA_BYTES, MAX_KEYBOX_BYTES,
    MAX_SEALED_MANIFEST_BYTES, MAX_SHARE_OBJECT_BYTES, OpenDalBackend,
    max_wire_bytes_for_object_key,
};
pub use chaos::{
    BitFlipRule, ChaosConfig, ChaosStats, ChaosStorageRouter, MAX_FAILURE_RATE_BPS,
    retry_transient,
};
pub use oauth::{
    DEFAULT_TOKEN_SECRET_SERVICE, LoopbackOAuthListener, OAuthPkceAuthenticator,
    OAuthProviderConfig, OAuthProviderPreset, OAuthTokenBundle, PER_SOCKET_READ_TIMEOUT,
    build_ssrf_safe_http_client, constant_time_csrf_eq, delete_tokens, load_tokens, persist_tokens,
};
pub use router::{MIRROR_CAS_PREFIX, QuotaSelectionStrategy, StorageRouter};
pub use entrocloud_types;
