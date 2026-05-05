//! In-memory `NonceStore` — an LRU keyed by `(key_id, nonce_bytes)`.
//!
//! Replay protection per `auth.md`: any `(key_id, nonce)` seen within the
//! 30-second TSO horizon is rejected. The LRU caps memory growth; entries
//! older than the horizon are evicted lazily on each insert so the cache
//! stays bounded even under pathological access patterns.

use std::future::Future;
use std::num::NonZeroUsize;

use headlines_core::{NonceError, NonceStore, Tso};
use lru::LruCache;
use parking_lot::Mutex;
use uuid::Uuid;

/// Key shape for the LRU. `Vec<u8>` rather than `&[u8]` so the LRU owns it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct NonceKey {
    key_id: Uuid,
    nonce: Vec<u8>,
}

/// In-process replay-protection cache.
pub struct InMemoryNonceStore {
    inner: Mutex<LruCache<NonceKey, Tso>>,
    horizon_ms: u64,
}

impl InMemoryNonceStore {
    /// Default capacity (100k) and 30s horizon — the values quoted in
    /// `auth.md` for v1's single-instance deployment.
    pub fn new() -> Self {
        Self::with_config(100_000, 30_000)
    }

    /// Build with explicit capacity (LRU max entries) and horizon (ms).
    /// `capacity` must be non-zero — passing `0` panics.
    pub fn with_config(capacity: usize, horizon_ms: u64) -> Self {
        let cap =
            NonZeroUsize::new(capacity).expect("InMemoryNonceStore capacity must be non-zero");
        Self {
            inner: Mutex::new(LruCache::new(cap)),
            horizon_ms,
        }
    }

    /// Drop entries whose `ts` is older than `now - horizon`. Called inside
    /// `record` to keep memory bounded as a side-effect of writes.
    fn evict_expired(&self, cache: &mut LruCache<NonceKey, Tso>, now: Tso) {
        let now_ms = now.physical_ms();
        let horizon = self.horizon_ms;

        let to_drop: Vec<NonceKey> = cache
            .iter()
            .filter_map(|(k, ts)| {
                if now_ms.saturating_sub(ts.physical_ms()) > horizon {
                    Some(k.clone())
                } else {
                    None
                }
            })
            .collect();
        for k in to_drop {
            cache.pop(&k);
        }
    }
}

impl Default for InMemoryNonceStore {
    fn default() -> Self {
        Self::new()
    }
}

impl NonceStore for InMemoryNonceStore {
    fn record(
        &self,
        key_id: Uuid,
        nonce: Vec<u8>,
        ts: Tso,
    ) -> impl Future<Output = Result<(), NonceError>> + Send {
        let key = NonceKey { key_id, nonce };
        let res = {
            let mut cache = self.inner.lock();

            // Lazy eviction first so an existing-but-expired entry doesn't
            // wrongly trigger Replay. Eviction and the replay check use the
            // same strict-greater-than threshold against the horizon, so any
            // entry surviving eviction is automatically inside the horizon.
            self.evict_expired(&mut cache, ts);

            if cache.get(&key).is_some() {
                Err(NonceError::Replay)
            } else if cache.len() >= cache.cap().get() {
                // Capacity guard. Plain LRU behavior would silently evict
                // the oldest entry to make room — but every surviving entry
                // is by construction inside the replay horizon (see
                // `evict_expired`), so the about-to-be-evicted entry is too.
                // Dropping it would let an attacker who can sustain
                // `>capacity/horizon` qps flush a captured victim nonce out
                // of the window and replay it. We refuse the new insert
                // instead — operators see the cause via the
                // `nonce_store_full` auth-result label and can size the
                // store up.
                Err(NonceError::Capacity)
            } else {
                cache.put(key, ts);
                Ok(())
            }
        };
        async move { res }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nonce_bytes(seed: u8) -> Vec<u8> {
        vec![seed; 16]
    }

    #[tokio::test]
    async fn first_insert_succeeds() {
        // Arrange
        let store = InMemoryNonceStore::new();
        let kid = Uuid::from_u128(1);
        let n = nonce_bytes(0xAA);
        let ts = Tso::from_parts(1_000, 0);

        // Act
        let res = store.record(kid, n, ts).await;

        // Assert
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn duplicate_within_horizon_is_replay() {
        // Arrange
        let store = InMemoryNonceStore::with_config(1024, 30_000);
        let kid = Uuid::from_u128(1);
        let n = nonce_bytes(0xAA);
        let ts1 = Tso::from_parts(1_000, 0);
        let ts2 = Tso::from_parts(2_000, 0); // 1s later, within horizon

        // Act
        store.record(kid, n.clone(), ts1).await.unwrap();
        let res = store.record(kid, n, ts2).await;

        // Assert
        assert_eq!(res, Err(NonceError::Replay));
    }

    #[tokio::test]
    async fn different_nonce_same_key_succeeds() {
        // Arrange
        let store = InMemoryNonceStore::new();
        let kid = Uuid::from_u128(7);
        let ts = Tso::from_parts(1_000, 0);

        // Act
        store.record(kid, nonce_bytes(1), ts).await.unwrap();
        let res = store.record(kid, nonce_bytes(2), ts).await;

        // Assert
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn same_nonce_different_key_succeeds() {
        // Arrange
        let store = InMemoryNonceStore::new();
        let n = nonce_bytes(0xAB);
        let ts = Tso::from_parts(1_000, 0);

        // Act
        store
            .record(Uuid::from_u128(1), n.clone(), ts)
            .await
            .unwrap();
        let res = store.record(Uuid::from_u128(2), n, ts).await;

        // Assert
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn flood_inside_horizon_rejects_new_inserts() {
        // Arrange — capacity 2 with all entries inside the 30s horizon. The
        // store must refuse to evict a still-live entry to make room for a
        // new one (otherwise an attacker who can sustain >capacity/horizon
        // qps would flush a captured victim nonce out of the LRU and replay
        // it).
        let store = InMemoryNonceStore::with_config(2, 30_000);
        let kid = Uuid::from_u128(1);
        let ts = Tso::from_parts(1_000, 0);
        store.record(kid, nonce_bytes(1), ts).await.unwrap();
        store.record(kid, nonce_bytes(2), ts).await.unwrap();

        // Act — third insert at a still-recent ts must be rejected.
        let res = store.record(kid, nonce_bytes(3), ts).await;

        // Assert
        assert_eq!(res, Err(NonceError::Capacity));
    }

    #[tokio::test]
    async fn eviction_outside_horizon_succeeds() {
        // Arrange — capacity 2 with 5s horizon; first two entries are far
        // older than the horizon by the time the third arrives, so the LRU
        // can safely drop the oldest.
        let store = InMemoryNonceStore::with_config(2, 5_000);
        let kid = Uuid::from_u128(1);
        let ts_old = Tso::from_parts(1_000, 0);
        let ts_new = Tso::from_parts(100_000, 0);
        store.record(kid, nonce_bytes(1), ts_old).await.unwrap();
        store.record(kid, nonce_bytes(2), ts_old).await.unwrap();

        // Act
        let res = store.record(kid, nonce_bytes(3), ts_new).await;

        // Assert
        assert!(res.is_ok(), "expired entries make room for new inserts");
    }

    #[tokio::test]
    async fn entry_outside_horizon_is_evicted_on_subsequent_write() {
        // Arrange — horizon 5s; insert at ts=1000ms, then later insert at
        // ts=10_000ms. The first entry is now older than the horizon and
        // should be evicted by the lazy-eviction pass, so re-inserting it
        // succeeds.
        let store = InMemoryNonceStore::with_config(1024, 5_000);
        let kid = Uuid::from_u128(1);
        let n = nonce_bytes(0xAA);
        let ts_old = Tso::from_parts(1_000, 0);
        let ts_new = Tso::from_parts(10_000, 0);

        store.record(kid, n.clone(), ts_old).await.unwrap();
        // A second nonce at the new ts triggers the eviction pass, dropping
        // the stale entry.
        store.record(kid, nonce_bytes(0xBB), ts_new).await.unwrap();

        // Act
        let res = store.record(kid, n, ts_new).await;

        // Assert
        assert!(res.is_ok(), "expired entry should have been evicted");
    }

    #[tokio::test]
    async fn default_constructor_has_capacity_and_horizon() {
        // Arrange / Act
        let store = InMemoryNonceStore::default();
        let kid = Uuid::from_u128(1);
        let res = store
            .record(kid, nonce_bytes(0), Tso::from_parts(1, 0))
            .await;

        // Assert
        assert!(res.is_ok());
    }

    #[test]
    #[should_panic]
    fn zero_capacity_panics() {
        // Arrange / Act / Assert
        let _ = InMemoryNonceStore::with_config(0, 30_000);
    }
}
