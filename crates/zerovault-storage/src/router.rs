//! Multi-cloud [`StorageRouter`] implementing [`StorageRouterTrait`] across Targeted,
//! Mirrored (RAID-1), and Quota-Pooled storage policies.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use futures::future::{BoxFuture, join_all, select_ok};
use tokio::sync::Mutex;

use zerovault_types::{
    BackendConfig, BackendHealth, BackendId, BackendQuota, BlobPlacement, CryptoEngine,
    RemoteVersion, RoutingPolicy, SecretStore, StorageRouterTrait, ZeroVaultError,
    ZeroVaultResult, validate_remote_object_key,
};

use crate::backend::CloudBackend;

const MIRROR_CAS_PREFIX: &str = "zv-mirror-cas:";

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
        let futs = self.backends().into_iter().map(|b| async move { b.probe_health().await });
        Ok(join_all(futs).await)
    }

    fn resolve_targeted_backend(&self, virtual_hint_path: &str) -> ZeroVaultResult<Arc<CloudBackend>> {
        let RoutingPolicy::Targeted {
            prefix_routes,
            default_backend,
        } = &self.policy
        else {
            return Err(ZeroVaultError::ConfigError(
                "resolve_targeted_backend called on non-Targeted policy".into(),
            ));
        };

        let norm_hint = normalize_virtual_path(virtual_hint_path);
        let mut best_match: Option<(usize, &BackendId)> = None;

        for (prefix, backend_id) in prefix_routes {
            let norm_prefix = normalize_virtual_path(prefix);
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
            RoutingPolicy::Targeted { default_backend, .. } => {
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
            // Stable sort preserves `pool_backends` order on equal free capacity.
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
        let handles: Vec<Arc<CloudBackend>> = backends
            .iter()
            .map(|id| {
                self.backends.get(id).cloned().ok_or_else(|| {
                    ZeroVaultError::ConfigError(format!("unknown mirror backend '{id}'"))
                })
            })
            .collect::<ZeroVaultResult<Vec<_>>>()?;

        let futs = handles.into_iter().map(|backend| {
            let key = object_key.to_owned();
            let payload = ciphertext.clone();
            async move { backend.put_object(&key, payload, false).await }
        });

        let results = join_all(futs).await;
        let mut replicas = Vec::new();
        let mut first_err: Option<ZeroVaultError> = None;

        for res in results {
            match res {
                Ok(target) => replicas.push(target),
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
        let (candidates, healthy_any) =
            self.ordered_quota_candidates(pool_backends, len as u64);

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
            match backend
                .put_object(object_key, ciphertext.clone(), true)
                .await
            {
                Ok(target) => {
                    return Ok(BlobPlacement {
                        object_key: object_key.to_owned(),
                        replicas: vec![target],
                        bytes_written: len,
                    });
                }
                Err(ZeroVaultError::StorageQuotaExceeded(_)) => continue,
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
        // Never log `virtual_hint_path` at any verbosity level.
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
        let mut preferred = Vec::new();
        for id in preferred_backends {
            if seen.insert(id.clone())
                && let Some(b) = self.backends.get(id)
            {
                preferred.push(b.clone());
            }
        }

        let mut fallback = Vec::new();
        for b in self.policy_read_order() {
            if seen.insert(b.config().id.clone()) {
                fallback.push(b);
            }
        }
        // In Targeted or multi-backend configurations, also include any remaining backends as final fallback.
        for id in &self.backend_order {
            if seen.insert(id.clone())
                && let Some(b) = self.backends.get(id)
            {
                fallback.push(b.clone());
            }
        }

        let mut all_not_found = true;
        let mut last_err: Option<ZeroVaultError> = None;

        // First race preferred backends (or all healthy policy backends if preferred is empty).
        let primary_tier = if preferred.is_empty() {
            let mut healthy_fallback = Vec::new();
            let mut unhealthy_fallback = Vec::new();
            for b in fallback.drain(..) {
                if b.is_healthy() {
                    healthy_fallback.push(b);
                } else {
                    unhealthy_fallback.push(b);
                }
            }
            fallback = unhealthy_fallback;
            healthy_fallback
        } else {
            preferred
        };

        for tier in [primary_tier, fallback] {
            if tier.is_empty() {
                continue;
            }
            match race_get_backends(&tier, object_key).await {
                Ok(bytes) => return Ok(bytes),
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
                    let per_mirror_expected = expected_etag.and_then(|raw| match expected_map.as_ref() {
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

                // When spilling manifest to a new backend, check has already succeeded above under lock.
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

async fn race_get_backends(
    backends: &[Arc<CloudBackend>],
    object_key: &str,
) -> ZeroVaultResult<Bytes> {
    if backends.len() == 1 {
        return backends[0].get_object(object_key).await;
    }

    let futs: Vec<BoxFuture<'_, Result<Bytes, ZeroVaultError>>> = backends
        .iter()
        .map(|backend| {
            let key = object_key.to_owned();
            let b = backend.clone();
            Box::pin(async move { b.get_object(&key).await })
                as BoxFuture<'_, Result<Bytes, ZeroVaultError>>
        })
        .collect();

    match select_ok(futs).await {
        Ok((bytes, _remaining)) => Ok(bytes),
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

fn normalize_virtual_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len() + 1);
    out.push('/');
    for seg in path.split('/') {
        if !seg.is_empty() {
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
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use opendal::raw::{
        Layer, OpCompose, OpCopy, OpCreateDir, OpList, OpPresign, OpRead, OpRename, OpRestore,
        OpStat, OpWrite, RpCreateDir, RpPresign, RpRead, RpRename, RpRestore, RpStat, Service,
        ServiceInfo, Servicer, oio,
    };
    use opendal::{BytesRange, Capability, OperationContext, Operator, services};
    use tempfile::TempDir;
    use uuid::Uuid;
    use zerovault_types::{
        BackendKind, BlobObjectKey, MANIFEST_HEAD_OBJECT_KEY, ManifestObjectKey,
    };

    use super::*;

    fn local_fs_config(
        id: &str,
        dir: &std::path::Path,
        quota_limit_bytes: Option<u64>,
        min_free_reserve_bytes: u64,
    ) -> BackendConfig {
        BackendConfig {
            id: id.to_owned(),
            kind: BackendKind::LocalFs,
            root: dir.to_str().expect("utf8 path").to_owned(),
            endpoint: None,
            bucket: None,
            region: None,
            quota_limit_bytes,
            min_free_reserve_bytes,
            username: None,
            access_key_id: None,
            secret_access_key: None,
            secret_account_key: None,
        }
    }

    #[tokio::test]
    async fn rejects_plaintext_object_keys_fail_closed() {
        let tmp = TempDir::new().expect("tempdir");
        let b = CloudBackend::from_config(&local_fs_config("fs-1", tmp.path(), None, 0))
            .expect("fs backend");
        let router = StorageRouter::new(
            vec![b],
            RoutingPolicy::Targeted {
                prefix_routes: vec![],
                default_backend: "fs-1".to_owned(),
            },
        )
        .expect("router");

        for bad_key in [
            "Taxes/2026.pdf",
            "blobs/aa/bb/taxes.pdf",
            "../vault/header.zvh",
            "manifests/notes.txt",
        ] {
            let put_err = router
                .put_blob("/Taxes/2026.pdf", bad_key, Bytes::from_static(b"x"))
                .await
                .expect_err("put_blob must reject plaintext key");
            assert!(matches!(put_err, ZeroVaultError::InvalidPath(_)));

            let get_err = router
                .get_blob(bad_key, &[])
                .await
                .expect_err("get_blob must reject plaintext key");
            assert!(matches!(get_err, ZeroVaultError::InvalidPath(_)));

            let stat_err = router
                .stat_object(bad_key, &[])
                .await
                .expect_err("stat_object must reject plaintext key");
            assert!(matches!(stat_err, ZeroVaultError::InvalidPath(_)));

            let del_err = router
                .delete_blob(bad_key, &[])
                .await
                .expect_err("delete_blob must reject plaintext key");
            assert!(matches!(del_err, ZeroVaultError::InvalidPath(_)));

            let cas_err = router
                .put_manifest_cas(bad_key, Bytes::from_static(b"x"), None)
                .await
                .expect_err("put_manifest_cas must reject plaintext key");
            assert!(matches!(cas_err, ZeroVaultError::InvalidPath(_)));
        }
    }

    #[tokio::test]
    async fn targeted_routing_longest_prefix_wins_with_slash_normalization() {
        let tmp = TempDir::new().expect("tempdir");
        let dir_default = tmp.path().join("cloud_default");
        let dir_finance = tmp.path().join("cloud_finance");
        let dir_archive = tmp.path().join("cloud_archive");

        let b_default = CloudBackend::from_config(&local_fs_config("default", &dir_default, None, 0))
            .expect("default");
        let b_finance = CloudBackend::from_config(&local_fs_config("finance", &dir_finance, None, 0))
            .expect("finance");
        let b_archive = CloudBackend::from_config(&local_fs_config("archive", &dir_archive, None, 0))
            .expect("archive");

        let router = StorageRouter::new(
            vec![b_default, b_finance, b_archive],
            RoutingPolicy::Targeted {
                prefix_routes: vec![
                    ("/Finance/".to_owned(), "finance".to_owned()),
                    ("Finance/2026/".to_owned(), "archive".to_owned()),
                ],
                default_backend: "default".to_owned(),
            },
        )
        .expect("router");

        let k1 = BlobObjectKey::from_uuid(Uuid::new_v4());
        let p1 = router
            .put_blob(
                "/Finance/2026/tax_return.pdf",
                k1.as_str(),
                Bytes::from_static(b"enc-2026"),
            )
            .await
            .expect("put longest prefix");
        assert_eq!(p1.replicas[0].backend_id, "archive");
        assert!(dir_archive.join(k1.as_str()).exists());
        assert!(!dir_finance.join(k1.as_str()).exists());

        let k2 = BlobObjectKey::from_uuid(Uuid::new_v4());
        let p2 = router
            .put_blob(
                "/Finance/budgets/q1.xlsx",
                k2.as_str(),
                Bytes::from_static(b"enc-fin"),
            )
            .await
            .expect("put shorter prefix");
        assert_eq!(p2.replicas[0].backend_id, "finance");
        assert!(dir_finance.join(k2.as_str()).exists());

        // Segment boundary must NOT falsely match `/FinanceBackup/...` to `/Finance`
        let k3 = BlobObjectKey::from_uuid(Uuid::new_v4());
        let p3 = router
            .put_blob(
                "/FinanceBackup/old.zip",
                k3.as_str(),
                Bytes::from_static(b"enc-def"),
            )
            .await
            .expect("put default fallback");
        assert_eq!(p3.replicas[0].backend_id, "default");
        assert!(dir_default.join(k3.as_str()).exists());

        assert_eq!(
            router
                .get_blob(k1.as_str(), &[])
                .await
                .expect("read k1")
                .as_ref(),
            b"enc-2026"
        );
    }

    #[tokio::test]
    async fn mirrored_raid1_recovers_from_deleted_mirror_and_races_slow_mirror() {
        let tmp = TempDir::new().expect("tempdir");
        let dir_a = tmp.path().join("mirror_a");
        let dir_b = tmp.path().join("mirror_b");

        let ba = CloudBackend::from_config(&local_fs_config("mirror-a", &dir_a, None, 0))
            .expect("mirror a");
        let bb = CloudBackend::from_config(&local_fs_config("mirror-b", &dir_b, None, 0))
            .expect("mirror b");

        let router = StorageRouter::new(
            vec![ba, bb],
            RoutingPolicy::Mirrored {
                backends: vec!["mirror-a".to_owned(), "mirror-b".to_owned()],
                min_ack: 2,
            },
        )
        .expect("mirrored router");

        let key = BlobObjectKey::from_uuid(Uuid::new_v4());
        let payload = Bytes::from_static(b"raid1-encrypted-chunk-bytes");
        let placement = router
            .put_blob("/Docs/critical.docx", key.as_str(), payload.clone())
            .await
            .expect("mirrored put");
        assert_eq!(placement.replicas.len(), 2);
        assert!(dir_a.join(key.as_str()).exists());
        assert!(dir_b.join(key.as_str()).exists());

        // Delete mirror A's blob file on disk -> get_blob must seamlessly recover from mirror B.
        std::fs::remove_file(dir_a.join(key.as_str())).expect("delete mirror A blob");
        let got = router
            .get_blob(key.as_str(), &[])
            .await
            .expect("recover from mirror B");
        assert_eq!(got, payload);

        // Also verify replacing mirror A's file with an unreadable directory fails A and recovers from B.
        let corrupted_path = dir_a.join(key.as_str());
        std::fs::create_dir_all(&corrupted_path).expect("corrupt mirror A path as dir");
        let got2 = router
            .get_blob(key.as_str(), &["mirror-a".to_owned()])
            .await
            .expect("recover even when preferred mirror A fails");
        assert_eq!(got2, payload);

        // Now test slow mirror delay vs fast mirror using a custom delay OpenDAL Layer on mirror A.
        #[derive(Debug, Clone)]
        struct SlowReadLayer {
            delay: Duration,
        }
        impl Layer for SlowReadLayer {
            fn apply_service(&self, inner: Servicer) -> Servicer {
                Arc::new(SlowReadService {
                    inner,
                    delay: self.delay,
                })
            }
        }
        #[derive(Debug)]
        struct SlowReadService {
            inner: Servicer,
            delay: Duration,
        }
        impl Service for SlowReadService {
            type Reader = DelayedReader;
            type Writer = oio::Writer;
            type Lister = oio::Lister;
            type Deleter = oio::Deleter;
            type Copier = oio::Copier;
            type Composer = oio::Composer;

            fn info(&self) -> ServiceInfo {
                self.inner.info()
            }
            fn capability(&self) -> Capability {
                self.inner.capability()
            }
            async fn create_dir(
                &self,
                ctx: &OperationContext,
                path: &str,
                args: OpCreateDir,
            ) -> opendal::Result<RpCreateDir> {
                self.inner.create_dir(ctx, path, args).await
            }
            fn read(
                &self,
                ctx: &OperationContext,
                path: &str,
                args: OpRead,
            ) -> opendal::Result<Self::Reader> {
                let inner_reader = self.inner.read(ctx, path, args)?;
                Ok(DelayedReader {
                    inner: inner_reader,
                    delay: self.delay,
                })
            }
            fn write(
                &self,
                ctx: &OperationContext,
                path: &str,
                args: OpWrite,
            ) -> opendal::Result<Self::Writer> {
                self.inner.write(ctx, path, args)
            }
            fn copy(
                &self,
                ctx: &OperationContext,
                from: &str,
                to: &str,
                args: OpCopy,
            ) -> opendal::Result<Self::Copier> {
                self.inner.copy(ctx, from, to, args)
            }
            fn compose(
                &self,
                ctx: &OperationContext,
                to: &str,
                args: OpCompose,
            ) -> opendal::Result<Self::Composer> {
                self.inner.compose(ctx, to, args)
            }
            async fn rename(
                &self,
                ctx: &OperationContext,
                from: &str,
                to: &str,
                args: OpRename,
            ) -> opendal::Result<RpRename> {
                self.inner.rename(ctx, from, to, args).await
            }
            async fn restore(
                &self,
                ctx: &OperationContext,
                path: &str,
                args: OpRestore,
            ) -> opendal::Result<RpRestore> {
                self.inner.restore(ctx, path, args).await
            }
            async fn stat(
                &self,
                ctx: &OperationContext,
                path: &str,
                args: OpStat,
            ) -> opendal::Result<RpStat> {
                self.inner.stat(ctx, path, args).await
            }
            fn delete(&self, ctx: &OperationContext) -> opendal::Result<Self::Deleter> {
                self.inner.delete(ctx)
            }
            fn list(
                &self,
                ctx: &OperationContext,
                path: &str,
                args: OpList,
            ) -> opendal::Result<Self::Lister> {
                self.inner.list(ctx, path, args)
            }
            async fn presign(
                &self,
                ctx: &OperationContext,
                path: &str,
                args: OpPresign,
            ) -> opendal::Result<RpPresign> {
                self.inner.presign(ctx, path, args).await
            }
        }
        struct DelayedReader {
            inner: oio::Reader,
            delay: Duration,
        }
        impl oio::Read for DelayedReader {
            async fn open(
                &self,
                range: BytesRange,
            ) -> opendal::Result<(RpRead, Box<dyn oio::ReadStreamDyn>)> {
                tokio::time::sleep(self.delay).await;
                self.inner.open(range).await
            }
            async fn read(&self, range: BytesRange) -> opendal::Result<(RpRead, opendal::Buffer)> {
                tokio::time::sleep(self.delay).await;
                self.inner.read(range).await
            }
        }

        let dir_slow = tmp.path().join("mirror_slow");
        let dir_fast = tmp.path().join("mirror_fast");
        std::fs::create_dir_all(&dir_slow).expect("create slow dir");
        std::fs::create_dir_all(&dir_fast).expect("create fast dir");

        let slow_op = Operator::new(
            services::Fs::default().root(dir_slow.to_str().expect("utf8")),
        )
        .expect("slow op")
        .layer(SlowReadLayer {
            delay: Duration::from_millis(600),
        });
        let slow_backend = CloudBackend::from_operator(
            local_fs_config("slow", &dir_slow, None, 0),
            slow_op,
        );
        let fast_backend = CloudBackend::from_config(&local_fs_config("fast", &dir_fast, None, 0))
            .expect("fast backend");

        let race_router = StorageRouter::new(
            vec![slow_backend, fast_backend],
            RoutingPolicy::Mirrored {
                backends: vec!["slow".to_owned(), "fast".to_owned()],
                min_ack: 2,
            },
        )
        .expect("race router");

        let race_key = BlobObjectKey::from_uuid(Uuid::new_v4());
        race_router
            .put_blob("/race", race_key.as_str(), Bytes::from_static(b"fast-win"))
            .await
            .expect("put both mirrors");

        let started = Instant::now();
        let raced = race_router
            .get_blob(race_key.as_str(), &[])
            .await
            .expect("fastest mirror wins");
        let elapsed = started.elapsed();
        assert_eq!(raced.as_ref(), b"fast-win");
        assert!(
            elapsed < Duration::from_millis(300),
            "expected fast mirror to win quickly, took {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn quota_pooled_spills_from_account1_to_account2_and_respects_reserve() {
        let tmp = TempDir::new().expect("tempdir");
        let dir1 = tmp.path().join("acct1");
        let dir2 = tmp.path().join("acct2");

        // Account 1: 8 KiB cap + 1 KiB reserve; Account 2: 1 MiB cap.
        let b1 = CloudBackend::from_config(&local_fs_config(
            "acct-1",
            &dir1,
            Some(8 * 1024),
            1024,
        ))
        .expect("acct1");
        let b2 = CloudBackend::from_config(&local_fs_config(
            "acct-2",
            &dir2,
            Some(1024 * 1024),
            0,
        ))
        .expect("acct2");

        let router = StorageRouter::new(
            vec![b1, b2],
            RoutingPolicy::QuotaPooled {
                pool_backends: vec!["acct-1".to_owned(), "acct-2".to_owned()],
            },
        )
        .expect("quota pooled router");

        let blob1 = BlobObjectKey::from_uuid(Uuid::new_v4());
        let data1 = Bytes::from(vec![0xA1u8; 5 * 1024]);
        let p1 = router
            .put_blob("/pool/one.bin", blob1.as_str(), data1.clone())
            .await
            .expect("first 5 KiB blob fits on acct-1");
        assert_eq!(p1.replicas[0].backend_id, "acct-1");

        // Remaining on acct-1 is 3 KiB, which cannot fit 5 KiB + 1 KiB reserve -> spills to acct-2.
        let blob2 = BlobObjectKey::from_uuid(Uuid::new_v4());
        let data2 = Bytes::from(vec![0xB2u8; 5 * 1024]);
        let p2 = router
            .put_blob("/pool/two.bin", blob2.as_str(), data2.clone())
            .await
            .expect("second 5 KiB blob spills automatically to acct-2");
        assert_eq!(p2.replicas[0].backend_id, "acct-2");

        // Note: a small 2.5 KiB blob would also fail acct-1 because 3 KiB - 2.5 KiB = 512 B < 1 KiB reserve!
        let blob3 = BlobObjectKey::from_uuid(Uuid::new_v4());
        let data3 = Bytes::from(vec![0xC3u8; 2560]);
        let p3 = router
            .put_blob("/pool/three.bin", blob3.as_str(), data3.clone())
            .await
            .expect("reserve protects acct-1 headroom and spills to acct-2");
        assert_eq!(p3.replicas[0].backend_id, "acct-2");

        assert_eq!(
            router.get_blob(blob1.as_str(), &[]).await.expect("read1"),
            data1
        );
        assert_eq!(
            router.get_blob(blob2.as_str(), &[]).await.expect("read2"),
            data2
        );
        assert_eq!(
            router.get_blob(blob3.as_str(), &[]).await.expect("read3"),
            data3
        );

        // Exhaust total pool -> must return StorageQuotaExceeded
        let oversized = BlobObjectKey::from_uuid(Uuid::new_v4());
        let err = router
            .put_blob(
                "/pool/huge.bin",
                oversized.as_str(),
                Bytes::from(vec![0u8; 2 * 1024 * 1024]),
            )
            .await
            .expect_err("all accounts lack capacity");
        assert!(matches!(err, ZeroVaultError::StorageQuotaExceeded(_)));
    }

    #[tokio::test]
    async fn quota_pooled_max_available_strategy_balances_capacity() {
        let tmp = TempDir::new().expect("tempdir");
        let b1 = CloudBackend::from_config(&local_fs_config(
            "small",
            &tmp.path().join("small"),
            Some(10 * 1024),
            0,
        ))
        .expect("small");
        let b2 = CloudBackend::from_config(&local_fs_config(
            "large",
            &tmp.path().join("large"),
            Some(16 * 1024),
            0,
        ))
        .expect("large");

        let router = StorageRouter::new(
            vec![b1, b2],
            RoutingPolicy::QuotaPooled {
                pool_backends: vec!["small".to_owned(), "large".to_owned()],
            },
        )
        .expect("router")
        .with_quota_strategy(QuotaSelectionStrategy::MaxAvailable);

        let k1 = BlobObjectKey::from_uuid(Uuid::new_v4());
        let p1 = router
            .put_blob("/a", k1.as_str(), Bytes::from(vec![1u8; 8 * 1024]))
            .await
            .expect("put 1");
        assert_eq!(p1.replicas[0].backend_id, "large");

        // Now large has 8 KiB free while small has 10 KiB free -> next goes to small.
        let k2 = BlobObjectKey::from_uuid(Uuid::new_v4());
        let p2 = router
            .put_blob("/b", k2.as_str(), Bytes::from(vec![2u8; 8 * 1024]))
            .await
            .expect("put 2");
        assert_eq!(p2.replicas[0].backend_id, "small");
    }

    #[tokio::test]
    async fn manifest_cas_detects_etag_conflicts_on_local_fs_and_memory() {
        for kind in [BackendKind::LocalFs, BackendKind::Memory] {
            let tmp = TempDir::new().expect("tempdir");
            let cfg = BackendConfig {
                id: "cas-backend".to_owned(),
                kind: kind.clone(),
                root: tmp.path().to_str().expect("utf8").to_owned(),
                endpoint: None,
                bucket: None,
                region: None,
                quota_limit_bytes: None,
                min_free_reserve_bytes: 0,
                username: None,
                access_key_id: None,
                secret_access_key: None,
                secret_account_key: None,
            };
            let backend = CloudBackend::from_config(&cfg).expect("backend");
            let router = StorageRouter::new(
                vec![backend],
                RoutingPolicy::Targeted {
                    prefix_routes: vec![],
                    default_backend: "cas-backend".to_owned(),
                },
            )
            .expect("router");

            // Missing manifest + Some(etag) must conflict.
            let missing_err = router
                .put_manifest_cas(
                    MANIFEST_HEAD_OBJECT_KEY,
                    Bytes::from_static(b"ZVM1-rev1"),
                    Some("\"nonexistent\""),
                )
                .await
                .expect_err("expected conflict on missing manifest");
            assert!(matches!(missing_err, ZeroVaultError::StorageConflict(_)));

            // Initial publish
            let v1 = router
                .put_manifest_cas(
                    MANIFEST_HEAD_OBJECT_KEY,
                    Bytes::from_static(b"ZVM1-rev1"),
                    None,
                )
                .await
                .expect("initial manifest publish");
            let etag1 = v1.etag.clone().expect("etag1 present");

            let stat1 = router
                .stat_object(MANIFEST_HEAD_OBJECT_KEY, &[])
                .await
                .expect("stat1")
                .expect("manifest exists");
            assert_eq!(stat1.etag.as_deref(), Some(etag1.as_str()));

            // Valid CAS advance
            let v2 = router
                .put_manifest_cas(
                    MANIFEST_HEAD_OBJECT_KEY,
                    Bytes::from_static(b"ZVM1-rev2"),
                    Some(&etag1),
                )
                .await
                .expect("CAS advance succeeds");
            let etag2 = v2.etag.clone().expect("etag2 present");
            assert_ne!(etag1, etag2);

            // Stale writer using etag1 MUST fail with StorageConflict
            let conflict = router
                .put_manifest_cas(
                    MANIFEST_HEAD_OBJECT_KEY,
                    Bytes::from_static(b"ZVM1-stale"),
                    Some(&etag1),
                )
                .await
                .expect_err("stale ETag must conflict");
            assert!(matches!(conflict, ZeroVaultError::StorageConflict(_)));

            // Historical immutable snapshot key also validates & succeeds
            let snap_key = ManifestObjectKey::from_uuid(Uuid::new_v4());
            let snap_ver = router
                .put_manifest_cas(snap_key.as_str(), Bytes::from_static(b"ZVM1-snap"), None)
                .await
                .expect("snapshot publish");
            assert_eq!(snap_ver.content_length, 9);
        }
    }

    #[tokio::test]
    async fn mirrored_raid1_min_ack1_tolerates_write_outage_and_delete_reclaims_quota() {
        let tmp = TempDir::new().expect("tempdir");
        let b1 = CloudBackend::from_config(&local_fs_config(
            "m1",
            &tmp.path().join("m1"),
            Some(1024),
            0,
        ))
        .expect("m1");
        let b2 = CloudBackend::from_config(&local_fs_config(
            "m2",
            &tmp.path().join("m2"),
            Some(1024),
            0,
        ))
        .expect("m2");

        // Make m1 fail writes with quota exceeded (512B > 200B? Wait: give m1 tiny 10B cap).
        let b1_small = CloudBackend::from_config(&local_fs_config(
            "m1",
            &tmp.path().join("m1_small"),
            Some(10),
            0,
        ))
        .expect("m1_small");

        let router_ack1 = StorageRouter::new(
            vec![b1_small, b2],
            RoutingPolicy::Mirrored {
                backends: vec!["m1".to_owned(), "m2".to_owned()],
                min_ack: 1,
            },
        )
        .expect("ack1 router");

        let k = BlobObjectKey::from_uuid(Uuid::new_v4());
        let p = router_ack1
            .put_blob("/docs/a.bin", k.as_str(), Bytes::from(vec![7u8; 256]))
            .await
            .expect("min_ack=1 succeeds with 1 healthy replica");
        assert_eq!(p.replicas.len(), 1);
        assert_eq!(p.replicas[0].backend_id, "m2");
        assert_eq!(
            router_ack1
                .get_blob(k.as_str(), &[])
                .await
                .expect("read from m2")
                .len(),
            256
        );
        router_ack1
            .delete_blob(k.as_str(), &[])
            .await
            .expect("delete blob");
        assert_eq!(
            router_ack1
                .backend("m2")
                .expect("m2")
                .used_bytes(),
            0
        );
        drop(b1);
    }

    #[tokio::test]
    async fn quota_pooled_concurrent_writes_never_exceed_cap_or_reserve() {
        let tmp = TempDir::new().expect("tempdir");
        // Account 1: 8 KiB cap + 1 KiB reserve => max usable 7168 B (at most two 3 KiB blobs).
        let b1 = CloudBackend::from_config(&local_fs_config(
            "acct-1",
            &tmp.path().join("acct1"),
            Some(8 * 1024),
            1024,
        ))
        .expect("acct1");
        let b2 = CloudBackend::from_config(&local_fs_config(
            "acct-2",
            &tmp.path().join("acct2"),
            Some(1024 * 1024),
            0,
        ))
        .expect("acct2");

        let router = Arc::new(
            StorageRouter::new(
                vec![b1, b2],
                RoutingPolicy::QuotaPooled {
                    pool_backends: vec!["acct-1".to_owned(), "acct-2".to_owned()],
                },
            )
            .expect("router"),
        );

        let mut handles = Vec::new();
        let mut expected_items = Vec::new();
        for i in 0u8..8 {
            let key = BlobObjectKey::from_uuid(Uuid::new_v4());
            let data = Bytes::from(vec![i + 1; 3 * 1024]);
            expected_items.push((key.as_str().to_owned(), data.clone()));
            let r = router.clone();
            let k_str = key.as_str().to_owned();
            handles.push(tokio::spawn(async move {
                r.put_blob("/concurrent", &k_str, data).await
            }));
        }

        let mut acct1_count = 0usize;
        let mut acct2_count = 0usize;
        for h in handles {
            let placement = h.await.expect("join").expect("put succeeds");
            match placement.replicas[0].backend_id.as_str() {
                "acct-1" => acct1_count += 1,
                "acct-2" => acct2_count += 1,
                other => panic!("unexpected backend {other}"),
            }
        }

        let acct1_used = router.backend("acct-1").expect("acct1").used_bytes();
        let acct2_used = router.backend("acct-2").expect("acct2").used_bytes();
        assert_eq!(acct1_count, 2);
        assert_eq!(acct2_count, 6);
        assert_eq!(acct1_used, 6 * 1024);
        assert!(acct1_used + 1024 <= 8 * 1024);
        assert_eq!(acct2_used, 18 * 1024);

        for (key, data) in expected_items {
            assert_eq!(router.get_blob(&key, &[]).await.expect("read back"), data);
        }
    }

    #[tokio::test]
    async fn manifest_cas_concurrent_race_allows_exactly_one_winner() {
        let tmp = TempDir::new().expect("tempdir");
        let b = CloudBackend::from_config(&local_fs_config("cas", tmp.path(), None, 0)).expect("fs");
        let router = Arc::new(
            StorageRouter::new(
                vec![b],
                RoutingPolicy::Targeted {
                    prefix_routes: vec![],
                    default_backend: "cas".to_owned(),
                },
            )
            .expect("router"),
        );

        let v1 = router
            .put_manifest_cas(
                MANIFEST_HEAD_OBJECT_KEY,
                Bytes::from_static(b"ZVM1-base"),
                None,
            )
            .await
            .expect("base manifest");
        let etag1 = v1.etag.expect("etag1");

        let mut tasks = Vec::new();
        for i in 0u8..6 {
            let r = router.clone();
            let e = etag1.clone();
            tasks.push(tokio::spawn(async move {
                r.put_manifest_cas(
                    MANIFEST_HEAD_OBJECT_KEY,
                    Bytes::from(format!("ZVM1-race-{i}")),
                    Some(&e),
                )
                .await
            }));
        }

        let mut ok_count = 0usize;
        let mut conflict_count = 0usize;
        for t in tasks {
            match t.await.expect("join") {
                Ok(_) => ok_count += 1,
                Err(ZeroVaultError::StorageConflict(_)) => conflict_count += 1,
                Err(other) => panic!("unexpected error: {other}"),
            }
        }

        assert_eq!(ok_count, 1);
        assert_eq!(conflict_count, 5);
    }
}
