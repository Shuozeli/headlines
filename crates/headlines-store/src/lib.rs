//! Postgres storage for headlines: connection pool wiring + embedded migrations.
//!
//! Phase 3 surface only — repository implementations land in Phase 5+.
//!
//! - [`Db`]      : `deadpool` pool of `diesel-async` Postgres connections.
//! - [`run_pending_migrations`] : runs `migrations/` against the target DB.
//! - [`schema`]  : auto-generated Diesel schema (do not hand-edit).

pub mod repo;
pub mod schema;

pub use repo::{
    PgAccountRepo, PgAccountStreamRepo, PgArticleRepo, PgDraftRepo, PgEventRepo, PgFeedFollowRepo,
    PgFeedRecommendationRepo, PgFollowRepo, PgKeyRepo, PgUserRepo,
};

use anyhow::Context;
use diesel::Connection;
use diesel::pg::PgConnection;
use diesel_async::AsyncPgConnection;
use diesel_async::RunQueryDsl;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::deadpool::{Object, Pool};
use diesel_migrations::{EmbeddedMigrations, MigrationHarness, embed_migrations};

/// Embedded migrations rooted at `headlines/migrations/`.
///
/// Resolved at compile time so the binary ships with all migrations baked in.
pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("../../migrations");

/// Pooled handle to the headlines Postgres database.
///
/// Wraps a `deadpool` pool of `diesel-async` `AsyncPgConnection`s. Cheap to
/// clone (it's an `Arc` under the hood).
#[derive(Clone)]
pub struct Db {
    pool: Pool<AsyncPgConnection>,
    /// Kept around so `run_pending_migrations` can open a sync connection
    /// without forcing every caller to thread the URL through.
    database_url: String,
}

impl Db {
    /// Build a pool against `database_url`, sized to `max_connections`, and
    /// ping it once to fail fast on bad config.
    pub async fn connect(database_url: &str, max_connections: usize) -> anyhow::Result<Self> {
        let manager =
            AsyncDieselConnectionManager::<AsyncPgConnection>::new(database_url.to_owned());
        let pool = Pool::builder(manager)
            .max_size(max_connections)
            .build()
            .context("failed to build deadpool-diesel-async pool")?;

        let db = Self {
            pool,
            database_url: database_url.to_owned(),
        };
        db.ping().await.context("ping after pool construction")?;
        Ok(db)
    }

    /// Borrow a connection from the pool.
    pub async fn get(&self) -> anyhow::Result<Object<AsyncPgConnection>> {
        self.pool
            .get()
            .await
            .context("acquire diesel-async connection from deadpool")
    }

    /// Run `SELECT 1;` and assert the result is `1`. Used as a connectivity
    /// probe on startup and in the smoke test.
    pub async fn ping(&self) -> anyhow::Result<()> {
        let mut conn = self.get().await?;
        let row = diesel::sql_query("SELECT 1 AS one")
            .get_result::<PingRow>(&mut conn)
            .await
            .context("SELECT 1 ping query failed")?;
        anyhow::ensure!(row.one == 1, "ping returned unexpected value: {}", row.one);
        Ok(())
    }

    /// Underlying database URL — kept for the migrations runner.
    pub fn database_url(&self) -> &str {
        &self.database_url
    }
}

/// Row type for the `SELECT 1 AS one` ping query.
#[derive(diesel::QueryableByName, Debug)]
struct PingRow {
    #[diesel(sql_type = diesel::sql_types::Integer)]
    one: i32,
}

/// Apply every pending migration under [`MIGRATIONS`] using a fresh sync
/// connection.
///
/// `diesel_migrations` is sync-only; we open a one-shot `PgConnection` inside
/// `tokio::task::spawn_blocking` rather than fight the async harness. The
/// async pool is left untouched.
pub async fn run_pending_migrations(db: &Db) -> anyhow::Result<()> {
    let url = db.database_url().to_owned();
    tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        let mut conn = PgConnection::establish(&url)
            .with_context(|| format!("opening sync PgConnection to {url} for migrations"))?;
        conn.run_pending_migrations(MIGRATIONS)
            .map_err(|e| anyhow::anyhow!("run_pending_migrations failed: {e}"))?;
        Ok(())
    })
    .await
    .context("migrations spawn_blocking join")?
}
