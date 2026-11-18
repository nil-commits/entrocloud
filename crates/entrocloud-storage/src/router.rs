//! Multi-cloud [`StorageRouter`] implementing [`StorageRouterTrait`] across Targeted,
//! Mirrored (RAID-1 with `min_ack` rollback and AEAD-verified failover), and Quota-Pooled policies.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use futures::future::{BoxFuture, join_all, select_ok};
use tokio::sync::Mutex;

use entrocloud_types::{
    BackendConfig, BackendHealth, BackendId, BackendQuota, BlobPlacement, CryptoEngine,
    RemoteVersion, RoutingPolicy, SecretStore, StorageRouterTrait, ZeroVaultError, ZeroVaultResult,
    validate_remote_object_key,
};

use crate::backend::CloudBackend;

/// Prefix identifying composite per-replica ETag JSON maps for `Mirrored` manifest CAS.
pub const MIRROR_CAS_PREFIX: &str = "zv-mirror-cas:";

fn encode_mirrored_etag(map: &BTreeMap<BackendId, String>) -> String {
    let json = serde_json::to_string(map).unwrap_or_else(|_| "{}".to_owned());
    format!("{MIRROR_CAS_PREFIX}{json}")
}

fn decode_mirrored_etag(etag: &str) -> Option<BTreeMap<BackendId, String>> {
    let raw = etag.strip_prefix(MIRROR_CAS_PREFIX)?;
    serde_json::from_str::<BTreeMap<BackendId, String>>(raw).ok()
}

/// Strategy used by [`RoutingPolicy::QuotaPooled`] when choosing among eligible healthy accounts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum QuotaSelectionStrategy {
    /// Fills `pool_backends` in configured order, automatically spilling over to later accounts
    /// as earlier accounts reach `quota_limit_bytes - min_free_reserve_bytes`.
    #[default]
    OrderedSpillover,
    /// Selects the healthy pool backend with the highest `available_bytes` satisfying reserve
    /// headroom requirements.
    MaxAvailable,
}

/// Multi-cloud storage router enforcing strict zero-knowledge remote object keys and routing
/// encrypted blobs and manifests across heterogeneous OpenDAL backends.
#[derive(Debug)]
pub struct StorageRouter {
    backends: HashMap<BackendId, Arc<CloudBackend>>,
    backend_order: Vec<BackendId>,
    policy: RoutingPolicy,
    quota_strategy: QuotaSelectionStrategy,
    manifest_cas_lock: Mutex<()>,
}

impl StorageRouter {
    /// Constructs a [`StorageRouter`] from configured [`CloudBackend`] instances and validates
    /// that all backend IDs referenced by `policy` exist.
    pub fn new(
        backends: impl IntoIterator<Item = CloudBackend>,
        policy: RoutingPolicy,
    ) -> ZeroVaultResult<Self> {
        Self::from_shared(backends.into_iter().map(Arc::new), policy)
    }

    /// Constructs a [`StorageRouter`] from pre-shared `Arc<CloudBackend>` handles.
    pub fn from_shared(
        backends: impl IntoIterator<Item = Arc<CloudBackend>>,
        policy: RoutingPolicy,
    ) -> ZeroVaultResult<Self> {
        let mut map = HashMap::new();
        let mut order = Vec::new();
        for backend in backends {
            let id = backend.config().id.clone();
            if map.contains_key(&id) {
                return Err(ZeroVaultError::ConfigError(format!(
                    "duplicate backend id '{id}' in StorageRouter"
                )));
            }
            order.push(id.clone());
            map.insert(id, backend);
        }

        if map.is_empty() {
            return Err(ZeroVaultError::ConfigError(
                "StorageRouter requires at least one backend".into(),
            ));
        }

        validate_policy(&map, &policy)?;

        Ok(Self {
            backends: map,
            backend_order: order,
            policy,
            quota_strategy: QuotaSelectionStrategy::default(),
            manifest_cas_lock: Mutex::new(()),
        })
    }

    /// Convenience async constructor building all backends from [`BackendConfig`] slices and
    /// resolving wrapped OAuth2 secrets from [`SecretStore`].
    pub async fn from_configs_with_secrets(
        configs: &[BackendConfig],
        policy: RoutingPolicy,
        secret_store: Option<&dyn SecretStore>,
        crypto: Option<&dyn CryptoEngine>,
    ) -> ZeroVaultResult<Self> {
        let mut built = Vec::with_capacity(configs.len());
        for cfg in configs {
            built.push(CloudBackend::from_config_with_secrets(cfg, secret_store, crypto).await?);
        }
        Self::new(built, policy)
    }

    /// Configures the quota spillover selection strategy for [`RoutingPolicy::QuotaPooled`].
    #[must_use]
    pub fn with_quota_strategy(mut self, strategy: QuotaSelectionStrategy) -> Self {
        self.quota_strategy = strategy;
        self
    }

    /// Returns a handle to a registered backend by ID.
    #[must_use]
    pub fn backend(&self, id: &str) -> Option<&Arc<CloudBackend>> {
        self.backends.get(id)
    }

    /// Returns all registered backends in registration order.
    #[must_use]
    pub fn backends(&self) -> Vec<Arc<CloudBackend>> {
        self.backend_order
            .iter()
            .filter_map(|id| self.backends.get(id).cloned())
            .collect()
    }

    /// Actively probes all backends via OpenDAL `check()` and returns refreshed health reports.
    pub async fn probe_all_health(&self) -> ZeroVaultResult<Vec<BackendHealth>> {
        let futs = self
            .backends()
            .into_iter()
            .map(|b| async move { b.probe_health().await });
        Ok(join_all(futs).await)
    }

    /// Downloads an encrypted object and verifies its integrity/authenticity via `verify`
    /// (`NEW-M02` remediation).
    ///
    /// Races healthy primary replicas via `select_ok`; if the fastest responder returns corrupt
    /// or bit-rotted bytes that fail `verify`, immediately marks that replica unhealthy/degraded
    /// and automatically retries remaining candidate replicas until an intact copy passes `verify`.
    pub async fn get_blob_verified<F>(
        &self,
        object_key: &str,
        preferred_backends: &[BackendId],
        verify: F,
    ) -> ZeroVaultResult<Bytes>
    where
        F: Fn(&[u8]) -> bool,
    {
        validate_remote_object_key(object_key)?;

        let mut primary_tier = Vec::new();
        let mut primary_seen = HashSet::new();

        if !preferred_backends.is_empty() {
            for id in preferred_backends {
                if primary_seen.insert(id.clone())
                    && let Some(b) = self.backends.get(id)
                    && b.is_healthy()
                {
                    primary_tier.push(b.clone());
                }
            }
        }
        if primary_tier.is_empty() {
            for b in self.policy_read_order() {
                if b.is_healthy() && primary_seen.insert(b.config().id.clone()) {
                    primary_tier.push(b);
                }
            }
        }

        let mut tried: HashSet<BackendId> = HashSet::new();
        let mut saw_tamper = false;
        let mut all_not_found = true;
        let mut last_err: Option<ZeroVaultError> = None;

        if !primary_tier.is_empty() {
            match race_get_backends_with_id(&primary_tier, object_key).await {
                Ok((winner_id, bytes)) => {
                    if verify(&bytes) {
                        return Ok(bytes);
                    }
                    saw_tamper = true;
                    all_not_found = false;
                    tried.insert(winner_id.clone());
                    if let Some(bad) = self.backends.get(&winner_id) {
                        tracing::warn!(
                            backend_id = %winner_id,
                            object_key = %object_key,
                            "fastest replica failed cryptographic verification; marking degraded and failing over"
                        );
                        bad.set_healthy(
                            false,
                            Some(format!(
                                "cryptographic verification failed on object '{object_key}'"
                            )),
                        );
                    }
                }
                Err(err) => {
                    for b in &primary_tier {
                        tried.insert(b.config().id.clone());
                    }
                    if !matches!(err, ZeroVaultError::StorageNotFound(_)) {
                        all_not_found = false;
                    }
                    last_err = Some(err);
                }
            }
        }

        for candidate_id in self.candidate_backends(preferred_backends) {
            if !tried.insert(candidate_id.clone()) {
                continue;
            }
            match self.get_blob_from_backend(&candidate_id, object_key).await {
                Ok(bytes) => {
                    if verify(&bytes) {
                        return Ok(bytes);
                    }
                    saw_tamper = true;
                    all_not_found = false;
                    if let Some(bad) = self.backends.get(&candidate_id) {
                        tracing::warn!(
                            backend_id = %candidate_id,
                            object_key = %object_key,
                            "fallback replica failed cryptographic verification; marking degraded"
                        );
                        bad.set_healthy(
                            false,
                            Some(format!(
                                "cryptographic verification failed on object '{object_key}'"
                            )),
                        );
                    }
                }
                Err(ZeroVaultError::StorageNotFound(_)) => {}
                Err(err) => {
                    all_not_found = false;
                    last_err = Some(err);
                }
            }
        }

        if saw_tamper {
            Err(ZeroVaultError::CryptoTamperDetected(format!(
                "all candidate replicas failed cryptographic verification for '{object_key}'"
            )))
        } else if all_not_found {
            Err(ZeroVaultError::StorageNotFound(object_key.to_owned()))
        } else {
            Err(last_err.unwrap_or_else(|| {
                ZeroVaultError::StorageBackendError(format!(
                    "failed to retrieve verified object '{object_key}'"
                ))
            }))
        }
    }

    /// Downloads a bounded byte range `[offset, offset + len)` across candidate backends.
    pub async fn get_blob_range(
        &self,
        object_key: &str,
        offset: u64,
        len: usize,
        preferred_backends: &[BackendId],
    ) -> ZeroVaultResult<Bytes> {
        validate_remote_object_key(object_key)?;
        let candidates = self.candidate_backends(preferred_backends);
        let mut all_not_found = true;
        let mut last_err: Option<ZeroVaultError> = None;

        for id in candidates {
            let Some(backend) = self.backends.get(&id) else {
                continue;
            };
            match backend.get_object_range(object_key, offset, len).await {
                Ok(bytes) => return Ok(bytes),
                Err(err @ ZeroVaultError::InvalidRange { .. })
                | Err(err @ ZeroVaultError::InvalidWireFormat(_)) => return Err(err),
                Err(ZeroVaultError::StorageNotFound(_)) => {}
                Err(err) => {
                    all_not_found = false;
                    last_err = Some(err);
                }
            }
        }

        if all_not_found {
            Err(ZeroVaultError::StorageNotFound(object_key.to_owned()))
        } else {
            Err(last_err.unwrap_or_else(|| {
                ZeroVaultError::StorageBackendError(format!(
                    "failed byte-range read on '{object_key}'"
                ))
            }))
        }
    }

    fn resolve_targeted_backend(
        &self,
        virtual_hint_path: &str,
    ) -> ZeroVaultResult<Arc<CloudBackend>> {
        let RoutingPolicy::Targeted {
            prefix_routes,
            default_backend,
        } = &self.policy
        else {
            return Err(ZeroVaultError::ConfigError(
                "resolve_targeted_backend called on non-Targeted policy".into(),
            ));
        };

        let norm_hint = normalize_local_hint_path(virtual_hint_path);
        let mut best_match: Option<(usize, &BackendId)> = None;

        for (prefix, backend_id) in prefix_routes {
            let norm_prefix = normalize_local_hint_path(prefix);
            if let Some(match_len) = virtual_prefix_match_len(&norm_hint, &norm_prefix)
                && best_match.is_none_or(|(best_len, _)| match_len > best_len)
            {
                best_match = Some((match_len, backend_id));
            }
        }

        let chosen_id = best_match.map_or(default_backend, |(_, id)| id);
        self.backends.get(chosen_id).cloned().ok_or_else(|| {
            ZeroVaultError::ConfigError(format!("targeted backend '{chosen_id}' is not registered"))
        })
    }

    fn policy_read_order(&self) -> Vec<Arc<CloudBackend>> {
        match &self.policy {
            RoutingPolicy::Mirrored { backends, .. } => {
                let mut healthy = Vec::new();
                let mut unhealthy = Vec::new();
                for id in backends {
                    if let Some(b) = self.backends.get(id) {
                        if b.is_healthy() {
                            healthy.push(b.clone());
                        } else {
                            unhealthy.push(b.clone());
                        }
                    }
                }
                healthy.extend(unhealthy);
                healthy
            }
            RoutingPolicy::QuotaPooled { pool_backends } => pool_backends
                .iter()
                .filter_map(|id| self.backends.get(id).cloned())
                .collect(),
            RoutingPolicy::Targeted {
                default_backend, ..
            } => {
                let mut out = Vec::with_capacity(self.backend_order.len());
                if let Some(def) = self.backends.get(default_backend) {
                    out.push(def.clone());
                }
                for id in &self.backend_order {
                    if id != default_backend
                        && let Some(b) = self.backends.get(id)
                    {
                        out.push(b.clone());
                    }
                }
                out
            }
        }
    }

    fn ordered_quota_candidates(
        &self,
        pool_backends: &[BackendId],
        payload_len: u64,
    ) -> (Vec<Arc<CloudBackend>>, bool) {
        let mut healthy_any = false;
        let mut eligible = Vec::new();

        for id in pool_backends {
            let Some(backend) = self.backends.get(id) else {
                continue;
            };
            if !backend.is_healthy() {
                continue;
            }
            healthy_any = true;
            let needed = payload_len.saturating_add(backend.config().min_free_reserve_bytes);
            if backend.available_bytes() >= needed {
                eligible.push(backend.clone());
            }
        }

        if self.quota_strategy == QuotaSelectionStrategy::MaxAvailable {
            eligible.sort_by_key(|b| std::cmp::Reverse(b.available_bytes()));
        }

        (eligible, healthy_any)
    }

    async fn put_mirrored(
        &self,
        backends: &[BackendId],
        min_ack: usize,
        object_key: &str,
        ciphertext: Bytes,
    ) -> ZeroVaultResult<BlobPlacement> {
        let len = ciphertext.len();
        let handles: Vec<(Arc<CloudBackend>, bool)> = backends
            .iter()
            .map(|id| {
                let backend = self.backends.get(id).cloned().ok_or_else(|| {
                    ZeroVaultError::ConfigError(format!("unknown mirror backend '{id}'"))
                })?;
                let had_prior = backend.has_known_object(object_key);
                Ok((backend, had_prior))
            })
            .collect::<ZeroVaultResult<Vec<_>>>()?;

        let futs = handles.into_iter().map(|(backend, had_prior)| {
            let key = object_key.to_owned();
            let payload = ciphertext.clone();
            async move {
                let res = backend.put_object(&key, payload, false).await;
                (backend, had_prior, res)
            }
        });

        let results = join_all(futs).await;
        let mut replicas = Vec::new();
        let mut rollback_backends = Vec::new();
        let mut first_err: Option<ZeroVaultError> = None;

        for (backend, had_prior, res) in results {
            match res {
                Ok(target) => {
                    if !had_prior {
                        rollback_backends.push(backend);
                    }
                    replicas.push(target);
                }
                Err(err) => {
                    tracing::warn!(error = %err, "mirror replica put_blob failed");
                    if first_err.is_none() {
                        first_err = Some(err);
                    }
                }
            }
        }

        if replicas.len() >= min_ack {
            Ok(BlobPlacement {
                object_key: object_key.to_owned(),
                replicas,
                bytes_written: len,
            })
        } else {
            // Roll back partial new writes so failed min_ack uploads never leak blobs or quota.
            if !rollback_backends.is_empty() {
                let rollback_futs = rollback_backends.into_iter().map(|backend| {
                    let key = object_key.to_owned();
                    async move {
                        let _ = backend.delete_object(&key).await;
                    }
                });
                join_all(rollback_futs).await;
            }

            Err(first_err.unwrap_or_else(|| {
                ZeroVaultError::StorageBackendError(format!(
                    "mirrored write failed to achieve min_ack={min_ack} for {object_key}"
                ))
            }))
        }
    }

    async fn put_quota_pooled(
        &self,
        pool_backends: &[BackendId],
        object_key: &str,
        ciphertext: Bytes,
    ) -> ZeroVaultResult<BlobPlacement> {
        let len = ciphertext.len();
        let (candidates, healthy_any) = self.ordered_quota_candidates(pool_backends, len as u64);

        if candidates.is_empty() {
            if !healthy_any {
                return Err(ZeroVaultError::StorageBackendError(
                    "no healthy backends available in QuotaPooled pool".into(),
                ));
            }
            return Err(ZeroVaultError::StorageQuotaExceeded(format!(
                "all QuotaPooled backends lack capacity for {len} bytes"
            )));
        }

        let mut last_transport_err: Option<ZeroVaultError> = None;
        for backend in candidates {
            match backend.put_object(object_key, ciphertext.clone(), true).await {
                Ok(target) => {
                    return Ok(BlobPlacement {
                        object_key: object_key.to_owned(),
                        replicas: vec![target],
                        bytes_written: len,
                    });
                }
                Err(ZeroVaultError::StorageQuotaExceeded(_)) => {}
                Err(err) => {
                    tracing::warn!(
                        backend_id = %backend.config().id,
                        error = %err,
                        "QuotaPooled candidate write failed; failing over to next account"
                    );
                    last_transport_err = Some(err);
                }
            }
        }

        Err(last_transport_err.unwrap_or_else(|| {
            ZeroVaultError::StorageQuotaExceeded(format!(
                "all QuotaPooled backends exhausted capacity for {len} bytes"
            ))
        }))
    }
}

#[async_trait]
impl StorageRouterTrait for StorageRouter {
    async fn put_blob(
        &self,
        virtual_hint_path: &str,
        object_key: &str,
        ciphertext: Bytes,
    ) -> ZeroVaultResult<BlobPlacement> {
        validate_remote_object_key(object_key)?;
        match &self.policy {
            RoutingPolicy::Targeted { .. } => {
                let backend = self.resolve_targeted_backend(virtual_hint_path)?;
                let len = ciphertext.len();
                let target = backend.put_object(object_key, ciphertext, false).await?;
                Ok(BlobPlacement {
                    object_key: object_key.to_owned(),
                    replicas: vec![target],
                    bytes_written: len,
                })
            }
            RoutingPolicy::Mirrored { backends, min_ack } => {
                self.put_mirrored(backends, *min_ack, object_key, ciphertext)
                    .await
            }
            RoutingPolicy::QuotaPooled { pool_backends } => {
                self.put_quota_pooled(pool_backends, object_key, ciphertext)
                    .await
            }
        }
    }

    async fn get_blob(
        &self,
        object_key: &str,
        preferred_backends: &[BackendId],
    ) -> ZeroVaultResult<Bytes> {
        validate_remote_object_key(object_key)?;

        let mut seen = HashSet::new();
        let mut healthy_preferred = Vec::new();
        let mut unhealthy_preferred = Vec::new();
        for id in preferred_backends {
            if seen.insert(id.clone())
                && let Some(b) = self.backends.get(id)
            {
                if b.is_healthy() {
                    healthy_preferred.push(b.clone());
                } else {
                    unhealthy_preferred.push(b.clone());
                }
            }
        }

        let mut fallback = Vec::new();
        for b in self.policy_read_order() {
            if seen.insert(b.config().id.clone()) {
                fallback.push(b);
            }
        }
        for id in &self.backend_order {
            if seen.insert(id.clone())
                && let Some(b) = self.backends.get(id)
            {
                fallback.push(b.clone());
            }
        }

        let primary_tier = if !healthy_preferred.is_empty() {
            let mut combined_fallback = Vec::with_capacity(fallback.len() + unhealthy_preferred.len());
            let mut healthy_fb = Vec::new();
            let mut unhealthy_fb = unhealthy_preferred;
            for b in fallback {
                if b.is_healthy() {
                    healthy_fb.push(b);
                } else {
                    unhealthy_fb.push(b);
                }
            }
            combined_fallback.extend(healthy_fb);
            combined_fallback.extend(unhealthy_fb);
            fallback = combined_fallback;
            healthy_preferred
        } else {
            let mut healthy_fallback = Vec::new();
            let mut unhealthy_fallback = unhealthy_preferred;
            for b in fallback.drain(..) {
                if b.is_healthy() {
                    healthy_fallback.push(b);
                } else {
                    unhealthy_fallback.push(b);
                }
            }
            fallback = unhealthy_fallback;
            healthy_fallback
        };

        let mut all_not_found = true;
        let mut last_err: Option<ZeroVaultError> = None;

        for tier in [primary_tier, fallback] {
            if tier.is_empty() {
                continue;
            }
            match race_get_backends_with_id(&tier, object_key).await {
                Ok((_, bytes)) => return Ok(bytes),
                Err(err) => {
                    if !matches!(err, ZeroVaultError::StorageNotFound(_)) {
                        all_not_found = false;
                    }
                    last_err = Some(err);
                }
            }
        }

        if all_not_found {
            Err(ZeroVaultError::StorageNotFound(object_key.to_owned()))
        } else {
            Err(last_err.unwrap_or_else(|| {
                ZeroVaultError::StorageBackendError(format!(
                    "failed to retrieve object {object_key}"
                ))
            }))
        }
    }

    async fn get_blob_from_backend(
        &self,
        backend_id: &str,
        object_key: &str,
    ) -> ZeroVaultResult<Bytes> {
        validate_remote_object_key(object_key)?;
        let backend = self.backends.get(backend_id).ok_or_else(|| {
            ZeroVaultError::ConfigError(format!(
                "unknown backend '{backend_id}' in get_blob_from_backend"
            ))
        })?;
        backend.get_object(object_key).await
    }

    fn candidate_backends(&self, preferred_backends: &[BackendId]) -> Vec<BackendId> {
        let mut seen = HashSet::new();
        let mut healthy_ids = Vec::new();
        let mut unhealthy_ids = Vec::new();

        for id in preferred_backends {
            if let Some(b) = self.backends.get(id)
                && seen.insert(id.clone())
            {
                if b.is_healthy() {
                    healthy_ids.push(id.clone());
                } else {
                    unhealthy_ids.push(id.clone());
                }
            }
        }

        for b in self.policy_read_order() {
            let id = b.config().id.clone();
            if seen.insert(id.clone()) {
                if b.is_healthy() {
                    healthy_ids.push(id);
                } else {
                    unhealthy_ids.push(id);
                }
            }
        }

        for id in &self.backend_order {
            if let Some(b) = self.backends.get(id)
                && seen.insert(id.clone())
            {
                if b.is_healthy() {
                    healthy_ids.push(id.clone());
                } else {
                    unhealthy_ids.push(id.clone());
                }
            }
        }

        healthy_ids.extend(unhealthy_ids);
        healthy_ids
    }

    async fn delete_blob(
        &self,
        object_key: &str,
        backends: &[BackendId],
    ) -> ZeroVaultResult<()> {
        validate_remote_object_key(object_key)?;

        let targets: Vec<Arc<CloudBackend>> = if backends.is_empty() {
            self.backends()
        } else {
            let mut list = Vec::with_capacity(backends.len());
            for id in backends {
                let backend = self.backends.get(id).cloned().ok_or_else(|| {
                    ZeroVaultError::ConfigError(format!("unknown backend '{id}' in delete_blob"))
                })?;
                list.push(backend);
            }
            list
        };

        let futs = targets.into_iter().map(|backend| {
            let key = object_key.to_owned();
            async move { backend.delete_object(&key).await }
        });

        let mut first_err: Option<ZeroVaultError> = None;
        for res in join_all(futs).await {
            if let Err(err) = res
                && first_err.is_none()
            {
                first_err = Some(err);
            }
        }

        match first_err {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    async fn stat_object(
        &self,
        object_key: &str,
        preferred_backends: &[BackendId],
    ) -> ZeroVaultResult<Option<RemoteVersion>> {
        validate_remote_object_key(object_key)?;

        if preferred_backends.is_empty()
            && let RoutingPolicy::Mirrored { backends, .. } = &self.policy
        {
            let mut handles = Vec::with_capacity(backends.len());
            for id in backends {
                if let Some(b) = self.backends.get(id) {
                    handles.push((id.clone(), b.clone()));
                }
            }
            let stat_futs = handles.into_iter().map(|(id, backend)| {
                let key = object_key.to_owned();
                async move { (id, backend.stat_object(&key).await) }
            });

            let mut etags = BTreeMap::new();
            let mut sample: Option<RemoteVersion> = None;
            let mut first_err: Option<ZeroVaultError> = None;
            for (id, res) in join_all(stat_futs).await {
                match res {
                    Ok(Some(ver)) => {
                        if let Some(ref etag) = ver.etag {
                            etags.insert(id, etag.clone());
                        }
                        if sample.is_none() {
                            sample = Some(ver);
                        }
                    }
                    Ok(None) => {}
                    Err(err) => {
                        if first_err.is_none() {
                            first_err = Some(err);
                        }
                    }
                }
            }
            if let Some(mut ver) = sample {
                if !etags.is_empty() {
                    ver.etag = Some(encode_mirrored_etag(&etags));
                }
                return Ok(Some(ver));
            }
            return match first_err {
                Some(err) => Err(err),
                None => Ok(None),
            };
        }

        let mut seen = HashSet::new();
        let mut candidates = Vec::new();
        for id in preferred_backends {
            if seen.insert(id.clone())
                && let Some(b) = self.backends.get(id)
            {
                candidates.push(b.clone());
            }
        }
        if candidates.is_empty() {
            for b in self.policy_read_order() {
                if seen.insert(b.config().id.clone()) {
                    candidates.push(b);
                }
            }
        }

        let futs = candidates.into_iter().map(|backend| {
            let key = object_key.to_owned();
            async move { backend.stat_object(&key).await }
        });

        let mut first_err: Option<ZeroVaultError> = None;
        for res in join_all(futs).await {
            match res {
                Ok(Some(version)) => return Ok(Some(version)),
                Ok(None) => {}
                Err(err) => {
                    if first_err.is_none() {
                        first_err = Some(err);
                    }
                }
            }
        }

        match first_err {
            Some(err) => Err(err),
            None => Ok(None),
        }
    }

    async fn put_manifest_cas(
        &self,
        object_key: &str,
        sealed_manifest: Bytes,
        expected_etag: Option<&str>,
    ) -> ZeroVaultResult<RemoteVersion> {
        validate_remote_object_key(object_key)?;
        let _cas_guard = self.manifest_cas_lock.lock().await;

        match &self.policy {
            RoutingPolicy::Targeted {
                default_backend, ..
            } => {
                let backend = self.backends.get(default_backend).ok_or_else(|| {
                    ZeroVaultError::ConfigError(format!(
                        "default backend '{default_backend}' is not registered"
                    ))
                })?;
                backend
                    .put_object_cas(object_key, sealed_manifest, expected_etag)
                    .await
            }
            RoutingPolicy::Mirrored { backends, min_ack } => {
                let handles: Vec<(BackendId, Arc<CloudBackend>)> = backends
                    .iter()
                    .map(|id| {
                        let b = self.backends.get(id).cloned().ok_or_else(|| {
                            ZeroVaultError::ConfigError(format!("unknown mirror backend '{id}'"))
                        })?;
                        Ok((id.clone(), b))
                    })
                    .collect::<ZeroVaultResult<Vec<_>>>()?;

                let expected_map = expected_etag.and_then(decode_mirrored_etag);

                if let Some(expected_raw) = expected_etag {
                    let stat_futs = handles.iter().map(|(id, b)| {
                        let key = object_key.to_owned();
                        let id = id.clone();
                        let backend = b.clone();
                        async move { (id, backend.stat_object(&key).await) }
                    });
                    let mut saw_present_match = false;
                    let mut saw_none = false;
                    for (id, res) in join_all(stat_futs).await {
                        let expected_for_mirror = match expected_map.as_ref() {
                            Some(map) => map.get(&id).map(String::as_str),
                            None => Some(expected_raw),
                        };
                        match res {
                            Ok(Some(ver)) => {
                                if let Some(exp) = expected_for_mirror
                                    && ver.etag.as_deref() != Some(exp)
                                {
                                    return Err(ZeroVaultError::StorageConflict(format!(
                                        "manifest ETag mismatch for {object_key} on mirror '{id}'"
                                    )));
                                }
                                saw_present_match = true;
                            }
                            Ok(None) => {
                                saw_none = true;
                            }
                            Err(err) => {
                                tracing::warn!(
                                    mirror = %id,
                                    error = %err,
                                    "mirror stat during manifest CAS failed"
                                );
                            }
                        }
                    }
                    if !saw_present_match && saw_none {
                        return Err(ZeroVaultError::StorageConflict(format!(
                            "manifest {object_key} does not exist for expected ETag"
                        )));
                    }
                }

                let write_futs = handles.into_iter().map(|(id, b)| {
                    let key = object_key.to_owned();
                    let payload = sealed_manifest.clone();
                    let per_mirror_expected =
                        expected_etag.and_then(|raw| match expected_map.as_ref() {
                            Some(map) => map.get(&id).cloned(),
                            None => Some(raw.to_owned()),
                        });
                    async move {
                        let res = b
                            .put_object_cas(&key, payload, per_mirror_expected.as_deref())
                            .await;
                        (id, res)
                    }
                });
                let results = join_all(write_futs).await;
                let mut versions = Vec::new();
                let mut new_etags = BTreeMap::new();
                let mut conflict_err: Option<ZeroVaultError> = None;
                let mut first_err: Option<ZeroVaultError> = None;

                for (id, res) in results {
                    match res {
                        Ok(ver) => {
                            if let Some(ref etag) = ver.etag {
                                new_etags.insert(id, etag.clone());
                            }
                            versions.push(ver);
                        }
                        Err(err @ ZeroVaultError::StorageConflict(_)) => {
                            if conflict_err.is_none() {
                                conflict_err = Some(err);
                            }
                        }
                        Err(err) => {
                            if first_err.is_none() {
                                first_err = Some(err);
                            }
                        }
                    }
                }

                if versions.len() >= *min_ack {
                    let mut chosen = versions.into_iter().next().unwrap_or(RemoteVersion {
                        object_key: object_key.to_owned(),
                        etag: None,
                        content_length: sealed_manifest.len() as u64,
                        last_modified: None,
                    });
                    if !new_etags.is_empty() {
                        chosen.etag = Some(encode_mirrored_etag(&new_etags));
                    }
                    Ok(chosen)
                } else if let Some(err) = conflict_err {
                    Err(err)
                } else {
                    Err(first_err.unwrap_or_else(|| {
                        ZeroVaultError::StorageBackendError(format!(
                            "mirrored manifest CAS failed to reach min_ack={min_ack}"
                        ))
                    }))
                }
            }
            RoutingPolicy::QuotaPooled { pool_backends } => {
                let mut existing_holder: Option<(Arc<CloudBackend>, RemoteVersion)> = None;
                for id in pool_backends {
                    if let Some(backend) = self.backends.get(id)
                        && let Ok(Some(ver)) = backend.stat_object(object_key).await
                    {
                        existing_holder = Some((backend.clone(), ver));
                        break;
                    }
                }

                if let Some(expected) = expected_etag {
                    match &existing_holder {
                        Some((_, ver)) if ver.etag.as_deref() == Some(expected) => {}
                        Some(_) => {
                            return Err(ZeroVaultError::StorageConflict(format!(
                                "manifest ETag mismatch for {object_key}"
                            )));
                        }
                        None => {
                            return Err(ZeroVaultError::StorageConflict(format!(
                                "manifest {object_key} does not exist for expected ETag"
                            )));
                        }
                    }
                }

                let manifest_len = sealed_manifest.len() as u64;
                if let Some((holder, ver)) = &existing_holder
                    && holder.is_healthy()
                    && holder.available_bytes().saturating_add(ver.content_length)
                        >= manifest_len.saturating_add(holder.config().min_free_reserve_bytes)
                {
                    return holder
                        .put_object_cas(object_key, sealed_manifest, expected_etag)
                        .await;
                }

                let (candidates, healthy_any) =
                    self.ordered_quota_candidates(pool_backends, manifest_len);
                let Some(target) = candidates.into_iter().next() else {
                    if !healthy_any {
                        return Err(ZeroVaultError::StorageBackendError(
                            "no healthy backends available for QuotaPooled manifest".into(),
                        ));
                    }
                    return Err(ZeroVaultError::StorageQuotaExceeded(format!(
                        "all QuotaPooled backends lack capacity for manifest ({manifest_len} bytes)"
                    )));
                };

                let new_ver = target
                    .put_object_cas(object_key, sealed_manifest, None)
                    .await?;
                if let Some((old_holder, _)) = existing_holder
                    && old_holder.config().id != target.config().id
                {
                    let _ = old_holder.delete_object(object_key).await;
                }
                Ok(new_ver)
            }
        }
    }

    async fn list_backend_health(&self) -> ZeroVaultResult<Vec<BackendHealth>> {
        Ok(self.backends().into_iter().map(|b| b.health()).collect())
    }

    async fn pooled_quota(&self) -> ZeroVaultResult<BackendQuota> {
        let mut total_bytes = 0u64;
        let mut used_bytes = 0u64;
        let mut available_bytes = 0u64;

        for backend in self.backends() {
            let q = backend.quota();
            total_bytes = total_bytes.saturating_add(q.total_bytes);
            used_bytes = used_bytes.saturating_add(q.used_bytes);
            available_bytes = available_bytes.saturating_add(q.available_bytes);
        }

        Ok(BackendQuota {
            backend_id: "pool-total".to_owned(),
            total_bytes,
            used_bytes,
            available_bytes,
        })
    }

    fn routing_policy(&self) -> RoutingPolicy {
        self.policy.clone()
    }
}

async fn race_get_backends_with_id(
    backends: &[Arc<CloudBackend>],
    object_key: &str,
) -> ZeroVaultResult<(BackendId, Bytes)> {
    if backends.len() == 1 {
        let id = backends[0].config().id.clone();
        let bytes = backends[0].get_object(object_key).await?;
        return Ok((id, bytes));
    }

    let futs: Vec<BoxFuture<'_, Result<(BackendId, Bytes), ZeroVaultError>>> = backends
        .iter()
        .map(|backend| {
            let key = object_key.to_owned();
            let b = backend.clone();
            Box::pin(async move {
                let id = b.config().id.clone();
                let bytes = b.get_object(&key).await?;
                Ok((id, bytes))
            }) as BoxFuture<'_, Result<(BackendId, Bytes), ZeroVaultError>>
        })
        .collect();

    match select_ok(futs).await {
        Ok((pair, _remaining)) => Ok(pair),
        Err(err) => Err(err),
    }
}

fn validate_policy(
    backends: &HashMap<BackendId, Arc<CloudBackend>>,
    policy: &RoutingPolicy,
) -> ZeroVaultResult<()> {
    match policy {
        RoutingPolicy::Targeted {
            prefix_routes,
            default_backend,
        } => {
            if !backends.contains_key(default_backend) {
                return Err(ZeroVaultError::ConfigError(format!(
                    "Targeted policy default_backend '{default_backend}' is not registered"
                )));
            }
            for (prefix, target) in prefix_routes {
                if !backends.contains_key(target) {
                    return Err(ZeroVaultError::ConfigError(format!(
                        "Targeted policy route '{prefix}' references unknown backend '{target}'"
                    )));
                }
            }
        }
        RoutingPolicy::Mirrored {
            backends: mirror_ids,
            min_ack,
        } => {
            if mirror_ids.is_empty() {
                return Err(ZeroVaultError::ConfigError(
                    "Mirrored policy requires at least one backend".into(),
                ));
            }
            if *min_ack == 0 || *min_ack > mirror_ids.len() {
                return Err(ZeroVaultError::ConfigError(format!(
                    "Mirrored policy min_ack ({min_ack}) must be within 1..={}",
                    mirror_ids.len()
                )));
            }
            let mut seen = HashSet::new();
            for id in mirror_ids {
                if !seen.insert(id) {
                    return Err(ZeroVaultError::ConfigError(format!(
                        "duplicate backend '{id}' in Mirrored policy"
                    )));
                }
                if !backends.contains_key(id) {
                    return Err(ZeroVaultError::ConfigError(format!(
                        "Mirrored policy references unknown backend '{id}'"
                    )));
                }
            }
        }
        RoutingPolicy::QuotaPooled { pool_backends } => {
            if pool_backends.is_empty() {
                return Err(ZeroVaultError::ConfigError(
                    "QuotaPooled policy requires at least one backend".into(),
                ));
            }
            let mut seen = HashSet::new();
            for id in pool_backends {
                if !seen.insert(id) {
                    return Err(ZeroVaultError::ConfigError(format!(
                        "duplicate backend '{id}' in QuotaPooled policy"
                    )));
                }
                if !backends.contains_key(id) {
                    return Err(ZeroVaultError::ConfigError(format!(
                        "QuotaPooled policy references unknown backend '{id}'"
                    )));
                }
            }
        }
    }
    Ok(())
}

fn normalize_local_hint_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len() + 1);
    out.push('/');
    for seg in path.split('/') {
        if !seg.is_empty() && seg != "." {
            if out.len() > 1 {
                out.push('/');
            }
            out.push_str(seg);
        }
    }
    out
}

fn virtual_prefix_match_len(norm_hint: &str, norm_prefix: &str) -> Option<usize> {
    if norm_prefix == "/" {
        return Some(1);
    }
    if norm_hint == norm_prefix {
        return Some(norm_prefix.len());
    }
    if norm_hint.starts_with(norm_prefix)
        && norm_hint.as_bytes().get(norm_prefix.len()) == Some(&b'/')
    {
        return Some(norm_prefix.len());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_prefix_matching_and_composite_etag_codec() {
        let hint = normalize_local_hint_path("Finance//2026/./taxes.pdf");
        assert_eq!(hint, "/Finance/2026/taxes.pdf");
        assert_eq!(virtual_prefix_match_len(&hint, "/Finance"), Some(8));
        assert_eq!(virtual_prefix_match_len(&hint, "/Finance/2026"), Some(13));
        assert_eq!(virtual_prefix_match_len("/FinanceBackup/x", "/Finance"), None);

        let mut map = BTreeMap::new();
        map.insert("m1".to_owned(), "\"e1\"".to_owned());
        map.insert("m2".to_owned(), "\"e2\"".to_owned());
        let encoded = encode_mirrored_etag(&map);
        assert!(encoded.starts_with(MIRROR_CAS_PREFIX));
        assert_eq!(decode_mirrored_etag(&encoded), Some(map));
    }
}

