//! Smoke test for the Postgres pool + embedded migrations runner.
//!
//! Skipped (early return, *not* a failure) when `DATABASE_URL` is unset so the
//! test harness still runs cleanly on machines without DB access. CI / local
//! dev exercises the full path by exporting:
//!
//! ```text
//! DATABASE_URL=postgres://cyuan:cyuan@docker.yuacx.com:5432/headlines
//! ```

use headlines_store::{Db, run_pending_migrations};

/// End-to-end: connect, run migrations (no-op once Phase 3's initial migration
/// is applied), run `SELECT 1`, assert the round-trip.
#[tokio::test]
#[serial_test::serial]
async fn smoke_connect_migrate_select_one() {
    // Arrange
    let Ok(database_url) = std::env::var("DATABASE_URL") else {
        println!("DATABASE_URL not set, skipping smoke test");
        return;
    };

    // Act
    let db = Db::connect(&database_url, 4)
        .await
        .expect("Db::connect should succeed against the configured Postgres");
    run_pending_migrations(&db)
        .await
        .expect("run_pending_migrations should be a no-op against a migrated DB");
    db.ping().await.expect("SELECT 1 round-trip should succeed");

    // Assert
    // `Db::connect` already pinged once; a second ping confirms the pool is
    // reusable after a migration pass.
    db.ping().await.expect("second ping should also succeed");
}
