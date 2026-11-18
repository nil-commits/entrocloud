//! Deterministic SplitMix64 network fault and targeted replica bit-flip injector (`ChaosStorageRouter`).
//!
//! Wraps any `Arc<dyn StorageRouterTrait>` to inject configurable basis-point transient
//! [`ZeroVaultError::StorageBackendError`] packet drops across `put_blob`, `get_blob`,
//! `get_blob_from_backend`, and `put_manifest_cas`, as well as deterministic byte/bit corruption
//! on individual replicas to verify RAID-1 AEAD failover (`NEW-M02` and Wave 4 Gate 4).

use std::fmt;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use dashmap::DashMap;

use entrocloud_types::{
    BackendHealth, BackendId, BackendQuota, BlobPlacement, RemoteVersion, RoutingPolicy,
    StorageRouterTrait, ZeroVaultError, ZeroVaultResult, validate_remote_object_key,
};

use crate::router::StorageRouter;

/// Maximum basis points (`10_000` = `100.00%` failure probability).
pub const MAX_FAILURE_RATE_BPS: u32 = 10_000;

/// Deterministic byte/bit corruption rule applied to downloads from a targeted replica.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BitFlipRule {
    /// Target byte offset inside the wire blob.
    pub byte_offset: usize,
    /// Non-zero XOR bitmask applied to the selected byte (`0` is normalized to `0x01`).
    pub xor_mask: u8,
    /// When `true`, clamps `byte_offset` to `payload.len() - 1` if `byte_offset >= payload.len()`.
    pub clamp_to_len: bool,
}

impl BitFlipRule {
    /// Constructs a deterministic bit-flip rule clamping `byte_offset` into payload bounds.
    #[must_use]
    pub const fn new(byte_offset: usize, xor_mask: u8) -> Self {
        Self {
            byte_offset,
            xor_mask: if xor_mask == 0 { 0x01 } else { xor_mask },
            clamp_to_len: true,
        }
    }

    fn apply(self, bytes: &Bytes) -> Option<Bytes> {
        if bytes.is_empty() {
            return None;
        }
        let idx = if self.byte_offset >= bytes.len() {
            if self.clamp_to_len {
                bytes.len() - 1
            } else {
                return None;
            }
        } else {
            self.byte_offset
        };
        let mask = if self.xor_mask == 0 {
            0x01
        } else {
            self.xor_mask
        };
        let mut buf = BytesMut::from(bytes.as_ref());
        buf[idx] ^= mask;
        Some(buf.freeze())
    }
}

/// Declarative configuration for [`ChaosStorageRouter`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChaosConfig {
    /// Initial 64-bit SplitMix64 seed.
    pub seed: u64,
    /// Transient failure probability in basis points (`0..=10_000`; `3_000` = `30%`).
    pub failure_rate_bps: u32,
    /// Inject transient failures on `put_blob`.
    pub fail_put_blob: bool,
    /// Inject transient failures on `get_blob` and `get_blob_from_backend`.
    pub fail_get_blob: bool,
    /// Inject transient failures on `put_manifest_cas`.
    pub fail_put_manifest_cas: bool,
}

impl ChaosConfig {
    /// Creates a standard chaos configuration injecting faults on `put_blob`, `get_blob`, and
    /// `put_manifest_cas` at `failure_rate_bps` basis points.
    #[must_use]
    pub const fn new(seed: u64, failure_rate_bps: u32) -> Self {
        let clamped = if failure_rate_bps > MAX_FAILURE_RATE_BPS {
            MAX_FAILURE_RATE_BPS
        } else {
            failure_rate_bps
        };
        Self {
            seed,
            failure_rate_bps: clamped,
            fail_put_blob: true,
            fail_get_blob: true,
            fail_put_manifest_cas: true,
        }
    }
}

impl Default for ChaosConfig {
    fn default() -> Self {
        Self::new(0x5A56_4348_414F_5331, 0)
    }
}

/// Lock-free telemetry counters recorded by [`ChaosStorageRouter`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ChaosStats {
    /// Total storage operations evaluated for chaos fault injection.
    pub total_ops: u64,
    /// Number of transient `StorageBackendError` faults injected.
    pub injected_transient_failures: u64,
    /// Number of replica reads corrupted by targeted bit-flip rules.
    pub injected_bit_flips: u64,
}

/// Lock-free SplitMix64 step advancing `state` atomically.
fn next_splitmix64(state: &AtomicU64) -> u64 {
    let prev = state.fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed);
    let mut z = prev.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Fault-injecting wrapper around any `Arc<dyn StorageRouterTrait>`.
pub struct ChaosStorageRouter {
    inner: Arc<dyn StorageRouterTrait>,
    concrete_router: Option<Arc<StorageRouter>>,
    rng_state: AtomicU64,
    failure_rate_bps: AtomicU32,
    fail_put_blob: AtomicBool,
    fail_get_blob: AtomicBool,
    fail_put_manifest_cas: AtomicBool,
    total_ops: AtomicU64,
    injected_transient_failures: AtomicU64,
    injected_bit_flips: AtomicU64,
    backend_bit_flips: DashMap<BackendId, BitFlipRule>,
    object_bit_flips: DashMap<(BackendId, String), BitFlipRule>,
    degraded_backends: DashMap<BackendId, String>,
}

impl fmt::Debug for ChaosStorageRouter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChaosStorageRouter")
            .field("failure_rate_bps", &self.failure_rate_bps())
            .field("stats", &self.stats())
            .field("corrupted_backends", &self.backend_bit_flips.len())
            .field("degraded_backends", &self.degraded_backends.len())
            .finish_non_exhaustive()
    }
}

impl ChaosStorageRouter {
    /// Wraps `inner` with deterministic SplitMix64 `seed` and `failure_rate_bps` (`3000` = `30%`).
    #[must_use]
    pub fn new(inner: Arc<dyn StorageRouterTrait>, seed: u64, failure_rate_bps: u32) -> Self {
        Self::with_config(inner, ChaosConfig::new(seed, failure_rate_bps))
    }

    /// Wraps `inner` using explicit [`ChaosConfig`] settings.
    #[must_use]
    pub fn with_config(inner: Arc<dyn StorageRouterTrait>, config: ChaosConfig) -> Self {
        Self {
            inner,
            concrete_router: None,
            rng_state: AtomicU64::new(config.seed),
            failure_rate_bps: AtomicU32::new(config.failure_rate_bps.min(MAX_FAILURE_RATE_BPS)),
            fail_put_blob: AtomicBool::new(config.fail_put_blob),
            fail_get_blob: AtomicBool::new(config.fail_get_blob),
            fail_put_manifest_cas: AtomicBool::new(config.fail_put_manifest_cas),
            total_ops: AtomicU64::new(0),
            injected_transient_failures: AtomicU64::new(0),
            injected_bit_flips: AtomicU64::new(0),
            backend_bit_flips: DashMap::new(),
            object_bit_flips: DashMap::new(),
            degraded_backends: DashMap::new(),
        }
    }

    /// Wraps a concrete `Arc<StorageRouter>` so replica verification failures also propagate
    /// degraded health status directly onto the underlying `CloudBackend` instances.
    #[must_use]
    pub fn from_storage_router(
        router: Arc<StorageRouter>,
        seed: u64,
        failure_rate_bps: u32,
    ) -> Self {
        let mut instance = Self::new(router.clone(), seed, failure_rate_bps);
        instance.concrete_router = Some(router);
        instance
    }

    /// Returns a reference to the wrapped `Arc<dyn StorageRouterTrait>`.
    #[must_use]
    pub fn inner(&self) -> &Arc<dyn StorageRouterTrait> {
        &self.inner
    }

    /// Dynamically updates the transient packet-failure rate in basis points (`0..=10_000`).
    pub fn set_failure_rate_bps(&self, failure_rate_bps: u32) {
        self.failure_rate_bps.store(
            failure_rate_bps.min(MAX_FAILURE_RATE_BPS),
            Ordering::Release,
        );
    }

    /// Returns the active transient packet-failure rate in basis points.
    #[must_use]
    pub fn failure_rate_bps(&self) -> u32 {
        self.failure_rate_bps.load(Ordering::Acquire)
    }

    /// Enables or disables transient fault injection per operation class.
    pub fn set_operation_faults(
        &self,
        fail_put_blob: bool,
        fail_get_blob: bool,
        fail_put_manifest_cas: bool,
    ) {
        self.fail_put_blob.store(fail_put_blob, Ordering::Release);
        self.fail_get_blob.store(fail_get_blob, Ordering::Release);
        self.fail_put_manifest_cas
            .store(fail_put_manifest_cas, Ordering::Release);
    }

    /// Injects deterministic byte/bit corruption on all reads served from `backend_id`.
    pub fn corrupt_backend(
        &self,
        backend_id: impl Into<String>,
        byte_offset: usize,
        xor_mask: u8,
    ) {
        self.corrupt_backend_with_rule(backend_id, BitFlipRule::new(byte_offset, xor_mask));
    }

    /// Injects a custom [`BitFlipRule`] on all reads served from `backend_id`.
    pub fn corrupt_backend_with_rule(&self, backend_id: impl Into<String>, rule: BitFlipRule) {
        self.backend_bit_flips.insert(backend_id.into(), rule);
    }

    /// Injects deterministic byte/bit corruption scoped to `(backend_id, object_key)`.
    pub fn corrupt_backend_object(
        &self,
        backend_id: impl Into<String>,
        object_key: impl Into<String>,
        byte_offset: usize,
        xor_mask: u8,
    ) {
        self.object_bit_flips.insert(
            (backend_id.into(), object_key.into()),
            BitFlipRule::new(byte_offset, xor_mask),
        );
    }

    /// Clears bit-flip corruption rules targeting `backend_id`.
    pub fn clear_backend_corruption(&self, backend_id: &str) {
        self.backend_bit_flips.remove(backend_id);
        self.object_bit_flips.retain(|(b, _), _| b != backend_id);
    }

    /// Clears all active bit-flip corruption rules across all replicas.
    pub fn clear_all_corruptions(&self) {
        self.backend_bit_flips.clear();
        self.object_bit_flips.clear();
    }

    /// Marks `backend_id` degraded/unhealthy (demoting it during candidate selection and health reports).
    pub fn mark_backend_degraded(&self, backend_id: &str, reason: impl Into<String>) {
        let msg = reason.into();
        if let Some(router) = &self.concrete_router
            && let Some(backend) = router.backend(backend_id)
        {
            backend.set_healthy(false, Some(msg.clone()));
        }
        self.degraded_backends.insert(backend_id.to_owned(), msg);
    }

    /// Returns `true` if `backend_id` has been marked degraded/unhealthy.
    #[must_use]
    pub fn is_backend_degraded(&self, backend_id: &str) -> bool {
        if self.degraded_backends.contains_key(backend_id) {
            return true;
        }
        if let Some(router) = &self.concrete_router
            && let Some(backend) = router.backend(backend_id)
        {
            return !backend.is_healthy();
        }
        false
    }

    /// Snapshot of chaos fault-injection counters.
    #[must_use]
    pub fn stats(&self) -> ChaosStats {
        ChaosStats {
            total_ops: self.total_ops.load(Ordering::Acquire),
            injected_transient_failures: self.injected_transient_failures.load(Ordering::Acquire),
            injected_bit_flips: self.injected_bit_flips.load(Ordering::Acquire),
        }
    }

    /// Verified read across candidate replicas through the chaos layer: if a replica returns
    /// bit-flipped/tampered bytes that fail `verify`, marks that replica degraded and retries
    /// remaining healthy replicas automatically.
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

        let candidates = self.candidate_backends(preferred_backends);
        if candidates.is_empty() {
            let bytes = self.get_blob(object_key, preferred_backends).await?;
            if verify(&bytes) {
                return Ok(bytes);
            }
            return Err(ZeroVaultError::CryptoTamperDetected(format!(
                "blob verification failed for '{object_key}'"
            )));
        }

        let mut saw_tamper = false;
        let mut all_not_found = true;
        let mut last_err: Option<ZeroVaultError> = None;

        for backend_id in candidates {
            match self.get_blob_from_backend(&backend_id, object_key).await {
                Ok(bytes) => {
                    if verify(&bytes) {
                        return Ok(bytes);
                    }
                    saw_tamper = true;
                    all_not_found = false;
                    self.mark_backend_degraded(
                        &backend_id,
                        format!("cryptographic verification failed on object '{object_key}'"),
                    );
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
                "all candidate replicas failed verification for '{object_key}'"
            )))
        } else if all_not_found {
            Err(ZeroVaultError::StorageNotFound(object_key.to_owned()))
        } else {
            Err(last_err.unwrap_or_else(|| {
                ZeroVaultError::StorageBackendError(format!(
                    "failed verified read on '{object_key}'"
                ))
            }))
        }
    }

    fn maybe_inject_transient_error(&self, enabled: bool, op: &str, key: &str) -> ZeroVaultResult<()> {
        self.total_ops.fetch_add(1, Ordering::Relaxed);
        if !enabled {
            return Ok(());
        }
        let bps = self.failure_rate_bps.load(Ordering::Acquire).min(MAX_FAILURE_RATE_BPS);
        if bps == 0 {
            return Ok(());
        }
        let should_drop = if bps >= MAX_FAILURE_RATE_BPS {
            true
        } else {
            let sample = (next_splitmix64(&self.rng_state) % u64::from(MAX_FAILURE_RATE_BPS)) as u32;
            sample < bps
        };

        if should_drop {
            self.injected_transient_failures
                .fetch_add(1, Ordering::Relaxed);
            return Err(ZeroVaultError::StorageBackendError(format!(
                "chaos injected transient packet failure during {op} on '{key}'"
            )));
        }
        Ok(())
    }

    fn maybe_corrupt_replica_bytes(&self, backend_id: &str, object_key: &str, bytes: Bytes) -> Bytes {
        let specific_rule = self
            .object_bit_flips
            .get(&(backend_id.to_owned(), object_key.to_owned()))
            .map(|r| *r);
        let backend_rule = self.backend_bit_flips.get(backend_id).map(|r| *r);

        if let Some(rule) = specific_rule.or(backend_rule)
            && let Some(corrupted) = rule.apply(&bytes)
        {
            self.injected_bit_flips.fetch_add(1, Ordering::Relaxed);
            return corrupted;
        }
        bytes
    }
}

#[async_trait]
impl StorageRouterTrait for ChaosStorageRouter {
    async fn put_blob(
        &self,
        virtual_hint_path: &str,
        object_key: &str,
        ciphertext: Bytes,
    ) -> ZeroVaultResult<BlobPlacement> {
        validate_remote_object_key(object_key)?;
        self.maybe_inject_transient_error(
            self.fail_put_blob.load(Ordering::Acquire),
            "put_blob",
            object_key,
        )?;
        self.inner
            .put_blob(virtual_hint_path, object_key, ciphertext)
            .await
    }

    async fn get_blob(
        &self,
        object_key: &str,
        preferred_backends: &[BackendId],
    ) -> ZeroVaultResult<Bytes> {
        validate_remote_object_key(object_key)?;
        self.maybe_inject_transient_error(
            self.fail_get_blob.load(Ordering::Acquire),
            "get_blob",
            object_key,
        )?;

        if self.backend_bit_flips.is_empty()
            && self.object_bit_flips.is_empty()
            && self.degraded_backends.is_empty()
        {
            return self.inner.get_blob(object_key, preferred_backends).await;
        }

        let candidates = self.candidate_backends(preferred_backends);
        if candidates.is_empty() {
            return self.inner.get_blob(object_key, preferred_backends).await;
        }

        let mut all_not_found = true;
        let mut last_err: Option<ZeroVaultError> = None;
        for id in candidates {
            match self.inner.get_blob_from_backend(&id, object_key).await {
                Ok(bytes) => {
                    return Ok(self.maybe_corrupt_replica_bytes(&id, object_key, bytes));
                }
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
                    "chaos router exhausted candidates reading '{object_key}'"
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
        self.maybe_inject_transient_error(
            self.fail_get_blob.load(Ordering::Acquire),
            "get_blob_from_backend",
            object_key,
        )?;
        let bytes = self
            .inner
            .get_blob_from_backend(backend_id, object_key)
            .await?;
        Ok(self.maybe_corrupt_replica_bytes(backend_id, object_key, bytes))
    }

    fn candidate_backends(&self, preferred_backends: &[BackendId]) -> Vec<BackendId> {
        let base = self.inner.candidate_backends(preferred_backends);
        if self.degraded_backends.is_empty() {
            return base;
        }
        let mut healthy = Vec::with_capacity(base.len());
        let mut degraded = Vec::new();
        for id in base {
            if self.degraded_backends.contains_key(&id) {
                degraded.push(id);
            } else {
                healthy.push(id);
            }
        }
        healthy.extend(degraded);
        healthy
    }

    async fn delete_blob(
        &self,
        object_key: &str,
        backends: &[BackendId],
    ) -> ZeroVaultResult<()> {
        validate_remote_object_key(object_key)?;
        self.inner.delete_blob(object_key, backends).await
    }

    async fn stat_object(
        &self,
        object_key: &str,
        preferred_backends: &[BackendId],
    ) -> ZeroVaultResult<Option<RemoteVersion>> {
        validate_remote_object_key(object_key)?;
        self.inner.stat_object(object_key, preferred_backends).await
    }

    async fn put_manifest_cas(
        &self,
        object_key: &str,
        sealed_manifest: Bytes,
        expected_etag: Option<&str>,
    ) -> ZeroVaultResult<RemoteVersion> {
        validate_remote_object_key(object_key)?;
        self.maybe_inject_transient_error(
            self.fail_put_manifest_cas.load(Ordering::Acquire),
            "put_manifest_cas",
            object_key,
        )?;
        self.inner
            .put_manifest_cas(object_key, sealed_manifest, expected_etag)
            .await
    }

    async fn list_backend_health(&self) -> ZeroVaultResult<Vec<BackendHealth>> {
        let mut list = self.inner.list_backend_health().await?;
        for item in &mut list {
            if let Some(reason) = self.degraded_backends.get(&item.backend_id) {
                item.healthy = false;
                item.last_error = Some(reason.clone());
            }
        }
        Ok(list)
    }

    async fn pooled_quota(&self) -> ZeroVaultResult<BackendQuota> {
        self.inner.pooled_quota().await
    }

    fn routing_policy(&self) -> RoutingPolicy {
        self.inner.routing_policy()
    }
}

/// Bounded retry helper for converging operations across transient [`ZeroVaultError::StorageBackendError`]
/// faults injected by [`ChaosStorageRouter`].
pub async fn retry_transient<T, F, Fut>(
    max_attempts: usize,
    base_delay: Duration,
    mut op: F,
) -> ZeroVaultResult<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = ZeroVaultResult<T>>,
{
    let attempts = max_attempts.max(1);
    let mut last_err: Option<ZeroVaultError> = None;

    for attempt in 0..attempts {
        match op().await {
            Ok(val) => return Ok(val),
            Err(err @ ZeroVaultError::StorageBackendError(_)) if attempt + 1 < attempts => {
                last_err = Some(err);
                if !base_delay.is_zero() {
                    let shift = u32::try_from(attempt).unwrap_or(4).min(4);
                    let factor = 1u32 << shift;
                    tokio::time::sleep(base_delay.saturating_mul(factor)).await;
                }
            }
            Err(err) => return Err(err),
        }
    }

    Err(last_err.unwrap_or_else(|| {
        ZeroVaultError::StorageBackendError("retry_transient exhausted all attempts".into())
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_splitmix64_determinism_and_bitflip_rule() {
        let s1 = AtomicU64::new(0xCAFE_BABE_0001);
        let s2 = AtomicU64::new(0xCAFE_BABE_0001);
        for _ in 0..16 {
            assert_eq!(next_splitmix64(&s1), next_splitmix64(&s2));
        }

        let rule = BitFlipRule::new(2, 0x0F);
        let orig = Bytes::from_static(&[0x10, 0x20, 0x30, 0x40]);
        assert_eq!(
            rule.apply(&orig),
            Some(Bytes::from_static(&[0x10, 0x20, 0x3F, 0x40]))
        );
    }
}

