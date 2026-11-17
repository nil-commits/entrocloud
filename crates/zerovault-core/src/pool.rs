//! Bounded-memory reusable 4 MiB chunk buffer pool gated by a [`tokio::sync::Semaphore`].

use std::fmt;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use bytes::BytesMut;
use parking_lot::Mutex;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use zeroize::Zeroize;
use zerovault_types::{MAX_ENCRYPTED_CHUNK_SIZE, ZeroVaultError, ZeroVaultResult};

/// Default maximum concurrent 4 MiB transfer buffers (`8 * ~4 MiB ≈ 32 MiB` peak active RAM).
pub const DEFAULT_BUFFER_SLOTS: usize = 8;

/// Thread-safe, semaphore-gated pool of reusable [`BytesMut`] buffers capped at `max_slots`.
///
/// Guarantees that concurrent chunk encrypt/decrypt/transfer pipelines never allocate
/// unbounded memory or buffer entire multi-chunk files in RAM.
pub struct BoundedBufferPool {
    max_slots: usize,
    buffer_capacity: usize,
    semaphore: Arc<Semaphore>,
    free_list: Arc<Mutex<Vec<BytesMut>>>,
}

impl Default for BoundedBufferPool {
    fn default() -> Self {
        Self::new(DEFAULT_BUFFER_SLOTS)
    }
}

impl fmt::Debug for BoundedBufferPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoundedBufferPool")
            .field("max_slots", &self.max_slots)
            .field("buffer_capacity", &self.buffer_capacity)
            .field("in_use_slots", &self.in_use_slots())
            .field("pooled_buffers", &self.pooled_buffers())
            .finish()
    }
}

impl BoundedBufferPool {
    /// Creates a pool allowing at most `max_slots` simultaneous buffers of [`MAX_ENCRYPTED_CHUNK_SIZE`].
    #[must_use]
    pub fn new(max_slots: usize) -> Self {
        Self::with_buffer_capacity(max_slots, MAX_ENCRYPTED_CHUNK_SIZE)
    }

    /// Creates a pool with an explicit per-buffer capacity (primarily for testing).
    #[must_use]
    pub fn with_buffer_capacity(max_slots: usize, buffer_capacity: usize) -> Self {
        let slots = max_slots.max(1);
        let cap = buffer_capacity.max(1);
        Self {
            max_slots: slots,
            buffer_capacity: cap,
            semaphore: Arc::new(Semaphore::new(slots)),
            free_list: Arc::new(Mutex::new(Vec::with_capacity(slots))),
        }
    }

    /// Acquires a bounded buffer permit and returns an RAII [`PooledBuffer`] guard.
    ///
    /// Waits asynchronously when `max_slots` buffers are currently checked out.
    pub async fn acquire_buffer(&self) -> ZeroVaultResult<PooledBuffer> {
        let permit = Arc::clone(&self.semaphore)
            .acquire_owned()
            .await
            .map_err(|_| ZeroVaultError::ConfigError("buffer pool semaphore closed".into()))?;

        let buf = self.take_or_alloc_buf();
        Ok(PooledBuffer {
            buf,
            max_slots: self.max_slots,
            free_list: Arc::clone(&self.free_list),
            _permit: Some(permit),
        })
    }

    /// Atomically acquires a pair of buffer permits (`pt` + `wire`) to prevent dual-buffer deadlock.
    pub async fn acquire_pair(&self) -> ZeroVaultResult<PooledBufferPair> {
        if self.max_slots < 2 {
            return Err(ZeroVaultError::ConfigError(
                "BoundedBufferPool requires at least 2 slots for acquire_pair".into(),
            ));
        }
        let permit = Arc::clone(&self.semaphore)
            .acquire_many_owned(2)
            .await
            .map_err(|_| ZeroVaultError::ConfigError("buffer pool semaphore closed".into()))?;

        let pt = self.take_or_alloc_buf();
        let wire = self.take_or_alloc_buf();
        Ok(PooledBufferPair {
            pt: PooledBuffer {
                buf: pt,
                max_slots: self.max_slots,
                free_list: Arc::clone(&self.free_list),
                _permit: None,
            },
            wire: PooledBuffer {
                buf: wire,
                max_slots: self.max_slots,
                free_list: Arc::clone(&self.free_list),
                _permit: None,
            },
            _permit: Some(permit),
        })
    }

    fn take_or_alloc_buf(&self) -> BytesMut {
        let mut buf = {
            let mut guard = self.free_list.lock();
            guard.pop()
        }
        .unwrap_or_else(|| BytesMut::with_capacity(self.buffer_capacity));

        buf.clear();
        if buf.capacity() < self.buffer_capacity {
            buf.reserve(self.buffer_capacity - buf.capacity());
        }
        buf
    }

    /// Maximum number of concurrent in-flight buffer slots allowed.
    #[must_use]
    pub fn max_slots(&self) -> usize {
        self.max_slots
    }

    /// Per-buffer pre-allocated capacity in bytes.
    #[must_use]
    pub fn buffer_capacity(&self) -> usize {
        self.buffer_capacity
    }

    /// Number of slots currently checked out across active tasks.
    #[must_use]
    pub fn in_use_slots(&self) -> usize {
        self.max_slots
            .saturating_sub(self.semaphore.available_permits())
    }

    /// Number of available semaphore permits remaining.
    #[must_use]
    pub fn available_slots(&self) -> usize {
        self.semaphore.available_permits()
    }

    /// Number of recycled buffers currently sitting idle in the free list.
    #[must_use]
    pub fn pooled_buffers(&self) -> usize {
        self.free_list.lock().len()
    }
}

/// RAII handle to a checked-out [`BytesMut`] buffer from [`BoundedBufferPool`].
///
/// On drop, scrubs active bytes, `.clear()`s the buffer, returns it to the free list,
/// and releases the semaphore permit so waiting tasks can immediately reuse it.
pub struct PooledBuffer {
    buf: BytesMut,
    max_slots: usize,
    free_list: Arc<Mutex<Vec<BytesMut>>>,
    _permit: Option<OwnedSemaphorePermit>,
}

/// RAII handle holding two atomically-acquired [`PooledBuffer`]s (`pt` and `wire`).
#[derive(Debug)]
pub struct PooledBufferPair {
    /// Plaintext chunk buffer.
    pub pt: PooledBuffer,
    /// Wire ciphertext chunk buffer.
    pub wire: PooledBuffer,
    _permit: Option<OwnedSemaphorePermit>,
}

impl fmt::Debug for PooledBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PooledBuffer")
            .field("len", &self.buf.len())
            .field("capacity", &self.buf.capacity())
            .finish()
    }
}

impl PooledBuffer {
    /// Borrows the underlying buffer as an immutable byte slice.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    /// Borrows the underlying buffer as a mutable byte slice.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.buf
    }
}

impl Deref for PooledBuffer {
    type Target = BytesMut;

    fn deref(&self) -> &Self::Target {
        &self.buf
    }
}

impl DerefMut for PooledBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.buf
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        let mut buf = std::mem::take(&mut self.buf);
        // Scrub active plaintext/wire bytes before recycling into the pool.
        buf.as_mut().zeroize();
        buf.clear();
        {
            let mut guard = self.free_list.lock();
            if guard.len() < self.max_slots && buf.capacity() > 0 {
                guard.push(buf);
            }
        }
        // Release permit only after returning `buf` to the free list so the next
        // waiter immediately reuses the recycled allocation.
        let _ = self._permit.take();
    }
}

impl Drop for PooledBufferPair {
    fn drop(&mut self) {
        let _ = self._permit.take();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn pool_recycles_buffers_and_bounds_concurrency() {
        let pool = Arc::new(BoundedBufferPool::with_buffer_capacity(2, 1024));
        assert_eq!(pool.max_slots(), 2);
        assert_eq!(pool.in_use_slots(), 0);
        assert_eq!(pool.pooled_buffers(), 0);

        let mut b1 = pool.acquire_buffer().await.expect("acquire 1");
        b1.extend_from_slice(b"sensitive-plaintext");
        let b2 = pool.acquire_buffer().await.expect("acquire 2");
        assert_eq!(pool.in_use_slots(), 2);

        // Third acquisition blocks until one permit is released.
        let pool_clone = Arc::clone(&pool);
        let waiter = tokio::spawn(async move { pool_clone.acquire_buffer().await.expect("acquire 3") });
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(!waiter.is_finished());

        drop(b1);
        let b3 = waiter.await.expect("waiter completed");
        assert_eq!(b3.len(), 0);
        assert!(b3.capacity() >= 1024);
        assert_eq!(pool.in_use_slots(), 2);

        drop(b2);
        drop(b3);
        assert_eq!(pool.in_use_slots(), 0);
        assert_eq!(pool.pooled_buffers(), 2);
    }
}
