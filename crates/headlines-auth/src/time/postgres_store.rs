//! `tso_high_water` storage trait and impls.
//!
//! Split out from the `InProcessTso` itself so tests can mock the persistence
//! layer without spinning up Postgres. The Postgres-backed impl uses the
//! shared `headlines-store` connection pool.

use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use chrono::Utc;
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::RunQueryDsl;
use parking_lot::Mutex;

use headlines_store::{Db, schema::tso_high_water};

/// Read/write surface for the singleton `tso_high_water` row.
///
/// `read` returns `0` when the row hasn't been seeded yet — `InProcessTso`
/// treats this as "no prior high water" and starts from wall clock. `write`
/// overwrites unconditionally (last writer wins inside this process; multi-
/// node TSO is out of scope for v1).
#[async_trait]
pub trait TsoHighWaterStore: Send + Sync {
    async fn read(&self) -> anyhow::Result<u64>;
    async fn write(&self, last_physical_ms: u64) -> anyhow::Result<()>;
}

/// In-memory `TsoHighWaterStore` for tests. Just an `Arc<Mutex<u64>>`.
#[derive(Debug, Clone, Default)]
pub struct InMemoryTsoStore {
    inner: Arc<Mutex<u64>>,
}

impl InMemoryTsoStore {
    /// Empty store — `read` returns `0` until the first `write`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Pre-seed the store. Useful to simulate a server restart with a known
    /// high water mark.
    pub fn with_value(value: u64) -> Self {
        Self {
            inner: Arc::new(Mutex::new(value)),
        }
    }

    /// Snapshot the current value (test helper).
    pub fn current(&self) -> u64 {
        *self.inner.lock()
    }
}

#[async_trait]
impl TsoHighWaterStore for InMemoryTsoStore {
    async fn read(&self) -> anyhow::Result<u64> {
        Ok(*self.inner.lock())
    }

    async fn write(&self, last_physical_ms: u64) -> anyhow::Result<()> {
        *self.inner.lock() = last_physical_ms;
        Ok(())
    }
}

/// Postgres-backed `TsoHighWaterStore`, sharing the `headlines-store` pool.
///
/// On every `read`/`write` we open a pooled `diesel-async` connection. The row
/// is a singleton keyed by the literal string `"singleton"` per
/// `data-model.md`; we seed it on first read with `INSERT … ON CONFLICT DO
/// NOTHING` so subsequent calls always find a row to read.
#[derive(Clone)]
pub struct PostgresTsoStore {
    db: Db,
}

impl PostgresTsoStore {
    /// Wrap the shared `Db` pool.
    pub fn new(db: Db) -> Self {
        Self { db }
    }
}

const SINGLETON_ID: &str = "singleton";

#[async_trait]
impl TsoHighWaterStore for PostgresTsoStore {
    async fn read(&self) -> anyhow::Result<u64> {
        let mut conn = self.db.get().await?;

        // Seed-if-missing using ON CONFLICT DO NOTHING. After this insert the
        // row is guaranteed to exist (either pre-existing or freshly inserted).
        diesel::insert_into(tso_high_water::table)
            .values((
                tso_high_water::id.eq(SINGLETON_ID),
                tso_high_water::last_physical_ms.eq(0_i64),
                tso_high_water::updated_at.eq(Utc::now()),
            ))
            .on_conflict(tso_high_water::id)
            .do_nothing()
            .execute(&mut conn)
            .await
            .context("seed tso_high_water row")?;

        let row: i64 = tso_high_water::table
            .filter(tso_high_water::id.eq(SINGLETON_ID))
            .select(tso_high_water::last_physical_ms)
            .first(&mut conn)
            .await
            .context("read tso_high_water.last_physical_ms")?;

        // Cast i64 -> u64. We never write negative values; saturating to 0
        // defends against external corruption.
        Ok(row.max(0) as u64)
    }

    async fn write(&self, last_physical_ms: u64) -> anyhow::Result<()> {
        let mut conn = self.db.get().await?;
        let target = last_physical_ms.min(i64::MAX as u64) as i64;

        // Upsert: insert if missing, otherwise update the value if the new
        // one is greater. We never go backwards.
        diesel::insert_into(tso_high_water::table)
            .values((
                tso_high_water::id.eq(SINGLETON_ID),
                tso_high_water::last_physical_ms.eq(target),
                tso_high_water::updated_at.eq(Utc::now()),
            ))
            .on_conflict(tso_high_water::id)
            .do_update()
            .set((
                tso_high_water::last_physical_ms.eq(target),
                tso_high_water::updated_at.eq(Utc::now()),
            ))
            .execute(&mut conn)
            .await
            .context("upsert tso_high_water.last_physical_ms")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn in_memory_store_reads_default_zero() {
        // Arrange
        let store = InMemoryTsoStore::new();

        // Act
        let value = store.read().await.unwrap();

        // Assert
        assert_eq!(value, 0);
    }

    #[tokio::test]
    async fn in_memory_store_round_trips_writes() {
        // Arrange
        let store = InMemoryTsoStore::new();

        // Act
        store.write(123_456).await.unwrap();
        let value = store.read().await.unwrap();

        // Assert
        assert_eq!(value, 123_456);
        assert_eq!(store.current(), 123_456);
    }

    #[tokio::test]
    async fn in_memory_store_with_value_seeds_initial() {
        // Arrange / Act
        let store = InMemoryTsoStore::with_value(99);

        // Assert
        assert_eq!(store.read().await.unwrap(), 99);
    }

    /// `PostgresTsoStore` test gated on `DATABASE_URL`. Skipped when the env
    /// var is missing so the offline test run stays green.
    #[tokio::test]
    #[serial_test::serial]
    async fn postgres_store_round_trips_high_water_when_db_available() {
        // Arrange
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping postgres_store test: DATABASE_URL not set");
            return;
        };
        let db = Db::connect(&url, 2).await.expect("connect db");
        headlines_store::run_pending_migrations(&db)
            .await
            .expect("migrate");
        let store = PostgresTsoStore::new(db);

        // Act
        let v0 = store.read().await.expect("read 1");
        store.write(123_000).await.expect("write");
        let v1 = store.read().await.expect("read 2");

        // Assert
        assert!(v0 <= 123_000);
        assert_eq!(v1, 123_000);
    }
}
