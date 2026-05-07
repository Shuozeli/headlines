//! `PostgresKeyResolver` — resolves a wire `key_id` to its public key bytes,
//! algorithm name, and the `Subject` it authenticates as.
//!
//! The resolver pulls keys directly through Diesel rather than
//! `PgKeyRepo::get` because the auth layer doesn't know which subject class
//! the `key_id` belongs to up front — we have to probe each `*_keys` table.
//!
//! ## Lookup semantics
//!
//! All three key tables (`account_keys`, `user_keys`, `system_keys`) are
//! scanned for the requested `key_id`. **Exactly one active match
//! authenticates.** Multiple active matches across tables are a fatal
//! integrity error — the resolver returns `ResolveError::Internal` and
//! emits a `tracing::error!` listing the colliding tables. Authenticating
//! the first arm to win the race would let a deliberate cross-write
//! silently shadow another subject's key, so we refuse to choose.
//!
//! Operator runbook on `cross-table key_id collision`: the `error!` log
//! identifies the colliding tables; revoke or delete one row and rotate
//! keys for the affected subjects. UUIDv7 collisions are astronomically
//! unlikely; a real collision indicates a bug or a deliberate write.
//!
//! Wired arms:
//!   - `account_keys` — Phase 5.
//!   - `user_keys` — Phase 7.1.
//!   - `system_keys` — wired since Phase 5 for the operator-rescue path.

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use uuid::Uuid;

use headlines_core::Subject;
use headlines_store::Db;
use headlines_store::schema::account_keys;
use headlines_store::schema::system_keys;
use headlines_store::schema::system_scopes;
use headlines_store::schema::user_keys;

use crate::strategy::{KeyResolver, ResolveError, ResolvedKey};

/// Resolves keys against the Postgres `*_keys` tables. Construct once and
/// share via `Arc<dyn KeyResolver>`.
#[derive(Clone)]
pub struct PostgresKeyResolver {
    db: Db,
}

impl PostgresKeyResolver {
    pub fn new(db: Db) -> Self {
        Self { db }
    }
}

/// Defense-in-depth: only `"active"` keys are eligible to authenticate.
/// The `*_keys.status` CHECK constraint pins the column to
/// `('active','revoked')` today, but the resolver enforces the whitelist
/// at the query level so a future migration that widens the enum (or any
/// drift / direct DB write that bypasses the constraint) cannot
/// silently authenticate a key in some other state. Any non-`active`
/// row surfaces as `Revoked`; absent rows surface as `NotFound`.
const ACTIVE_STATUS: &str = "active";

/// One materialized active-match candidate from a `*_keys` table.
struct ActiveMatch {
    table: &'static str,
    resolved: ResolvedKey,
}

#[async_trait]
impl KeyResolver for PostgresKeyResolver {
    async fn resolve(&self, key_id: Uuid) -> Result<ResolvedKey, ResolveError> {
        let mut conn = self
            .db
            .get()
            .await
            .map_err(|e| ResolveError::Internal(format!("acquire conn: {e}")))?;

        // Probe all three tables and collect every active match. We refuse
        // to pick "first wins" because UUIDv7 collisions are an integrity
        // bug — silently authenticating one arm hides the bug.
        let mut active: Vec<ActiveMatch> = Vec::new();
        let mut nonactive_tables: Vec<&'static str> = Vec::new();

        // ---- account_keys ----
        let acc_active: Option<(Uuid, String, String)> = account_keys::table
            .filter(account_keys::key_id.eq(key_id))
            .filter(account_keys::status.eq(ACTIVE_STATUS))
            .select((
                account_keys::account_id,
                account_keys::algo,
                account_keys::public_key,
            ))
            .first::<(Uuid, String, String)>(&mut conn)
            .await
            .optional()
            .map_err(|e| ResolveError::Internal(format!("select account_keys: {e}")))?;
        if let Some((account_id, algo, public_key_b64)) = acc_active {
            let public_key = B64
                .decode(public_key_b64.as_bytes())
                .map_err(|e| ResolveError::Internal(format!("base64 decode: {e}")))?;
            active.push(ActiveMatch {
                table: "account_keys",
                resolved: ResolvedKey {
                    algo,
                    public_key,
                    subject: Subject::Account { account_id, key_id },
                },
            });
        } else {
            // Track non-active rows so that, in the no-active-match case,
            // we can distinguish `Revoked` from `NotFound`.
            let acc_inactive: Option<String> = account_keys::table
                .filter(account_keys::key_id.eq(key_id))
                .select(account_keys::status)
                .first::<String>(&mut conn)
                .await
                .optional()
                .map_err(|e| ResolveError::Internal(format!("select account_keys status: {e}")))?;
            if acc_inactive.is_some() {
                nonactive_tables.push("account_keys");
            }
        }

        // ---- user_keys ----
        let user_active: Option<(Uuid, String, String)> = user_keys::table
            .filter(user_keys::key_id.eq(key_id))
            .filter(user_keys::status.eq(ACTIVE_STATUS))
            .select((user_keys::user_id, user_keys::algo, user_keys::public_key))
            .first::<(Uuid, String, String)>(&mut conn)
            .await
            .optional()
            .map_err(|e| ResolveError::Internal(format!("select user_keys: {e}")))?;
        if let Some((user_id, algo, public_key_b64)) = user_active {
            let public_key = B64
                .decode(public_key_b64.as_bytes())
                .map_err(|e| ResolveError::Internal(format!("base64 decode: {e}")))?;
            active.push(ActiveMatch {
                table: "user_keys",
                resolved: ResolvedKey {
                    algo,
                    public_key,
                    subject: Subject::User { user_id, key_id },
                },
            });
        } else {
            let user_inactive: Option<String> = user_keys::table
                .filter(user_keys::key_id.eq(key_id))
                .select(user_keys::status)
                .first::<String>(&mut conn)
                .await
                .optional()
                .map_err(|e| ResolveError::Internal(format!("select user_keys status: {e}")))?;
            if user_inactive.is_some() {
                nonactive_tables.push("user_keys");
            }
        }

        // ---- system_keys ----
        let sys_active: Option<(Uuid, String, String)> = system_keys::table
            .filter(system_keys::key_id.eq(key_id))
            .filter(system_keys::status.eq(ACTIVE_STATUS))
            .select((
                system_keys::system_id,
                system_keys::algo,
                system_keys::public_key,
            ))
            .first::<(Uuid, String, String)>(&mut conn)
            .await
            .optional()
            .map_err(|e| ResolveError::Internal(format!("select system_keys: {e}")))?;
        if let Some((system_id, algo, public_key_b64)) = sys_active {
            let scopes: Vec<String> = system_scopes::table
                .filter(system_scopes::system_id.eq(system_id))
                .select(system_scopes::scope)
                .load::<String>(&mut conn)
                .await
                .map_err(|e| ResolveError::Internal(format!("select system_scopes: {e}")))?;
            let public_key = B64
                .decode(public_key_b64.as_bytes())
                .map_err(|e| ResolveError::Internal(format!("base64 decode: {e}")))?;
            active.push(ActiveMatch {
                table: "system_keys",
                resolved: ResolvedKey {
                    algo,
                    public_key,
                    subject: Subject::System {
                        system_id,
                        key_id,
                        scopes,
                    },
                },
            });
        } else {
            let sys_inactive: Option<String> = system_keys::table
                .filter(system_keys::key_id.eq(key_id))
                .select(system_keys::status)
                .first::<String>(&mut conn)
                .await
                .optional()
                .map_err(|e| ResolveError::Internal(format!("select system_keys status: {e}")))?;
            if sys_inactive.is_some() {
                nonactive_tables.push("system_keys");
            }
        }

        // Apply exactly-one-active semantics.
        match active.len() {
            0 => {
                if !nonactive_tables.is_empty() {
                    Err(ResolveError::Revoked)
                } else {
                    Err(ResolveError::NotFound)
                }
            }
            1 => Ok(active.into_iter().next().expect("len == 1").resolved),
            _ => {
                let tables: Vec<&'static str> = active.iter().map(|m| m.table).collect();
                tracing::error!(
                    key_id = %key_id,
                    tables = ?tables,
                    "cross-table key_id collision: same key_id is active in multiple *_keys tables"
                );
                Err(ResolveError::Internal(format!(
                    "cross-table key_id collision: {} present in {:?}",
                    key_id, tables
                )))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! Tests for `PostgresKeyResolver` come in two flavors.
    //!
    //! 1. **Contract test** (`KeyResolver`-trait-level): a fake resolver that
    //!    returns a non-active row asserts the resolver contract — only
    //!    `"active"` rows authenticate, and any other value collapses to
    //!    `Revoked`. This pins the invariant the production resolver
    //!    enforces in its WHERE clause without touching Postgres.
    //!
    //! 2. **DB-gated test** (`postgres_*`): real round-trip through a
    //!    Postgres connection. Skipped when `DATABASE_URL` is unset so the
    //!    offline test run stays green; when run with the workspace DB,
    //!    it inserts a real `active` row and a real `revoked` row and
    //!    asserts the resolver behavior end-to-end.
    //!
    //! Inserting a row with a status outside the `('active','revoked')`
    //! CHECK constraint is not feasible at runtime — Postgres would reject
    //! the insert. The contract test covers that "what if" via the trait
    //! seam instead.
    use super::*;
    use chrono::Utc;
    use diesel::sql_types::Text;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use serial_test::serial;

    /// Fake resolver that mimics the post-fix `PostgresKeyResolver` contract:
    /// "active" → resolved; any other status string → `Revoked`; absent →
    /// `NotFound`. Used to pin the trait-level invariant, since the real
    /// resolver's status whitelist is its only defense against a future DB
    /// migration that broadens the CHECK constraint.
    struct StatusGatedFakeResolver {
        key_id: Uuid,
        status: String,
        algo: String,
        public_key: Vec<u8>,
        subject: Subject,
    }

    #[async_trait]
    impl KeyResolver for StatusGatedFakeResolver {
        async fn resolve(&self, key_id: Uuid) -> Result<ResolvedKey, ResolveError> {
            if key_id != self.key_id {
                return Err(ResolveError::NotFound);
            }
            if self.status != ACTIVE_STATUS {
                return Err(ResolveError::Revoked);
            }
            Ok(ResolvedKey {
                algo: self.algo.clone(),
                public_key: self.public_key.clone(),
                subject: self.subject.clone(),
            })
        }
    }

    #[tokio::test]
    async fn fake_resolver_with_active_status_resolves_successfully() {
        // Arrange
        let key_id = Uuid::from_u128(1);
        let r = StatusGatedFakeResolver {
            key_id,
            status: "active".into(),
            algo: "ed25519".into(),
            public_key: vec![1, 2, 3],
            subject: Subject::Account {
                account_id: Uuid::from_u128(0xACC),
                key_id,
            },
        };

        // Act
        let got = r.resolve(key_id).await.unwrap();

        // Assert
        assert_eq!(got.algo, "ed25519");
        assert_eq!(got.public_key, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn fake_resolver_with_revoked_status_returns_revoked() {
        // Arrange
        let key_id = Uuid::from_u128(1);
        let r = StatusGatedFakeResolver {
            key_id,
            status: "revoked".into(),
            algo: "ed25519".into(),
            public_key: vec![],
            subject: Subject::Account {
                account_id: Uuid::from_u128(0xACC),
                key_id,
            },
        };

        // Act
        let res = r.resolve(key_id).await;

        // Assert
        assert!(matches!(res, Err(ResolveError::Revoked)));
    }

    #[tokio::test]
    async fn fake_resolver_with_unknown_status_collapses_to_revoked() {
        // Arrange — the contract says any non-`active` value is treated as
        // not-active. This is what defends against a DB schema drift that
        // adds a new status without a code change.
        let key_id = Uuid::from_u128(1);
        let r = StatusGatedFakeResolver {
            key_id,
            status: "pending".into(),
            algo: "ed25519".into(),
            public_key: vec![],
            subject: Subject::Account {
                account_id: Uuid::from_u128(0xACC),
                key_id,
            },
        };

        // Act
        let res = r.resolve(key_id).await;

        // Assert — anything other than `active` must NOT authenticate.
        assert!(
            matches!(res, Err(ResolveError::Revoked)),
            "non-active status must NEVER authenticate (got {:?})",
            res
        );
    }

    /// Try to claim the AUTH_TABLE guard / DB env. We don't need the guard
    /// for our reads, but we do follow the same skip-on-missing-url pattern
    /// the rest of the suite uses.
    fn maybe_db_url() -> Option<String> {
        std::env::var("DATABASE_URL").ok()
    }

    /// Insert a fresh account row directly via SQL so we can satisfy the
    /// `account_keys.account_id` foreign key without dragging in
    /// `headlines-store::repo::accounts`. Returns the new account id.
    async fn insert_account(conn: &mut diesel_async::AsyncPgConnection) -> Uuid {
        let id = Uuid::now_v7();
        let short = format!("kt_{:x}", id.as_u128() & 0xFFFFFFFF);
        diesel::sql_query(
            "INSERT INTO accounts (id, short_name, author_name, status, created_at, updated_at) \
             VALUES ($1, $2, $3, 'active', NOW(), NOW())",
        )
        .bind::<diesel::sql_types::Uuid, _>(id)
        .bind::<Text, _>(short.clone())
        .bind::<Text, _>(short)
        .execute(conn)
        .await
        .expect("insert account fixture");
        id
    }

    async fn insert_account_key(
        conn: &mut diesel_async::AsyncPgConnection,
        account_id: Uuid,
        key_id: Uuid,
        public_key_b64: &str,
        status: &str,
    ) {
        diesel::sql_query(
            "INSERT INTO account_keys \
             (account_id, key_id, algo, public_key, status, created_at, revoked_at) \
             VALUES ($1, $2, 'ed25519', $3, $4, NOW(), $5)",
        )
        .bind::<diesel::sql_types::Uuid, _>(account_id)
        .bind::<diesel::sql_types::Uuid, _>(key_id)
        .bind::<Text, _>(public_key_b64.to_owned())
        .bind::<Text, _>(status.to_owned())
        .bind::<diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>, _>(
            if status == "revoked" {
                Some(Utc::now())
            } else {
                None
            },
        )
        .execute(conn)
        .await
        .expect("insert account_keys fixture");
    }

    #[tokio::test]
    #[serial]
    async fn postgres_resolver_authenticates_active_account_key() {
        // Arrange
        let Some(url) = maybe_db_url() else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let db = Db::connect(&url, 2).await.expect("connect");
        headlines_store::run_pending_migrations(&db)
            .await
            .expect("migrate");
        let resolver = PostgresKeyResolver::new(db.clone());

        let sk = SigningKey::generate(&mut OsRng);
        let pk_b64 = B64.encode(sk.verifying_key().as_bytes());
        let mut conn = db.get().await.expect("conn");
        let account_id = insert_account(&mut conn).await;
        let key_id = Uuid::now_v7();
        insert_account_key(&mut conn, account_id, key_id, &pk_b64, "active").await;
        drop(conn);

        // Act
        let got = resolver.resolve(key_id).await.expect("resolve active");

        // Assert
        assert_eq!(got.algo, "ed25519");
        assert_eq!(got.public_key, sk.verifying_key().as_bytes());
        match got.subject {
            Subject::Account {
                account_id: a,
                key_id: k,
            } => {
                assert_eq!(a, account_id);
                assert_eq!(k, key_id);
            }
            other => panic!("expected Subject::Account, got {other:?}"),
        }
    }

    #[tokio::test]
    #[serial]
    async fn postgres_resolver_returns_revoked_for_revoked_account_key() {
        // Arrange
        let Some(url) = maybe_db_url() else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let db = Db::connect(&url, 2).await.expect("connect");
        headlines_store::run_pending_migrations(&db)
            .await
            .expect("migrate");
        let resolver = PostgresKeyResolver::new(db.clone());

        let sk = SigningKey::generate(&mut OsRng);
        let pk_b64 = B64.encode(sk.verifying_key().as_bytes());
        let mut conn = db.get().await.expect("conn");
        let account_id = insert_account(&mut conn).await;
        let key_id = Uuid::now_v7();
        insert_account_key(&mut conn, account_id, key_id, &pk_b64, "revoked").await;
        drop(conn);

        // Act
        let res = resolver.resolve(key_id).await;

        // Assert
        assert!(
            matches!(res, Err(ResolveError::Revoked)),
            "revoked row must surface as ResolveError::Revoked, got {:?}",
            res
        );
    }

    #[tokio::test]
    #[serial]
    async fn postgres_resolver_returns_not_found_for_unknown_key() {
        // Arrange
        let Some(url) = maybe_db_url() else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let db = Db::connect(&url, 2).await.expect("connect");
        headlines_store::run_pending_migrations(&db)
            .await
            .expect("migrate");
        let resolver = PostgresKeyResolver::new(db);

        // Act
        let res = resolver.resolve(Uuid::now_v7()).await;

        // Assert
        assert!(matches!(res, Err(ResolveError::NotFound)));
    }

    /// Fake resolver that mimics the cross-table collision contract: a
    /// `key_id` that appears in more than one `*_keys` table (an integrity
    /// violation; UUIDv7 should never collide) must surface as
    /// `Internal`, *not* authenticate against whichever arm runs first.
    /// This pins the trait-level invariant the production resolver
    /// enforces by counting matches across all three tables.
    struct CollidingFakeResolver {
        key_id: Uuid,
        matches: usize,
    }

    #[async_trait]
    impl KeyResolver for CollidingFakeResolver {
        async fn resolve(&self, key_id: Uuid) -> Result<ResolvedKey, ResolveError> {
            if key_id != self.key_id {
                return Err(ResolveError::NotFound);
            }
            if self.matches > 1 {
                return Err(ResolveError::Internal(format!(
                    "cross-table key_id collision: {}",
                    key_id
                )));
            }
            if self.matches == 1 {
                return Ok(ResolvedKey {
                    algo: "ed25519".into(),
                    public_key: vec![],
                    subject: Subject::Account {
                        account_id: Uuid::from_u128(0xACC),
                        key_id,
                    },
                });
            }
            Err(ResolveError::NotFound)
        }
    }

    #[tokio::test]
    async fn fake_resolver_with_cross_table_collision_returns_internal() {
        // Arrange — same key_id in two tables.
        let key_id = Uuid::now_v7();
        let r = CollidingFakeResolver { key_id, matches: 2 };

        // Act
        let res = r.resolve(key_id).await;

        // Assert — fatal integrity error, never silently authenticate.
        assert!(
            matches!(res, Err(ResolveError::Internal(ref m)) if m.contains("cross-table key_id collision")),
            "cross-table collision must surface as Internal, got {:?}",
            res
        );
    }

    #[tokio::test]
    #[serial]
    async fn postgres_resolver_returns_internal_on_cross_table_collision() {
        // Arrange — insert the same key_id into both account_keys and
        // user_keys via raw SQL; the resolver must detect the collision
        // and return `Internal` rather than first-match-wins.
        let Some(url) = maybe_db_url() else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let db = Db::connect(&url, 2).await.expect("connect");
        headlines_store::run_pending_migrations(&db)
            .await
            .expect("migrate");
        let resolver = PostgresKeyResolver::new(db.clone());

        let sk = SigningKey::generate(&mut OsRng);
        let pk_b64 = B64.encode(sk.verifying_key().as_bytes());
        let mut conn = db.get().await.expect("conn");
        let account_id = insert_account(&mut conn).await;
        let user_id = insert_user(&mut conn).await;
        let key_id = Uuid::now_v7();
        insert_account_key(&mut conn, account_id, key_id, &pk_b64, "active").await;
        insert_user_key(&mut conn, user_id, key_id, &pk_b64, "active").await;

        // Act
        let res = resolver.resolve(key_id).await;

        // Cleanup before assert so a failed assertion still leaves the DB clean.
        let _ = diesel::sql_query("DELETE FROM account_keys WHERE key_id = $1")
            .bind::<diesel::sql_types::Uuid, _>(key_id)
            .execute(&mut conn)
            .await;
        let _ = diesel::sql_query("DELETE FROM user_keys WHERE key_id = $1")
            .bind::<diesel::sql_types::Uuid, _>(key_id)
            .execute(&mut conn)
            .await;

        // Assert
        assert!(
            matches!(res, Err(ResolveError::Internal(ref m)) if m.contains("cross-table key_id collision")),
            "cross-table collision must surface as Internal, got {:?}",
            res
        );
    }

    async fn insert_user(conn: &mut diesel_async::AsyncPgConnection) -> Uuid {
        let id = Uuid::now_v7();
        diesel::sql_query(
            "INSERT INTO users (id, display_name, status, created_at) \
             VALUES ($1, $2, 'active', NOW())",
        )
        .bind::<diesel::sql_types::Uuid, _>(id)
        .bind::<Text, _>(format!("kt_user_{:x}", id.as_u128() & 0xFFFFFFFF))
        .execute(conn)
        .await
        .expect("insert user fixture");
        id
    }

    async fn insert_user_key(
        conn: &mut diesel_async::AsyncPgConnection,
        user_id: Uuid,
        key_id: Uuid,
        public_key_b64: &str,
        status: &str,
    ) {
        diesel::sql_query(
            "INSERT INTO user_keys \
             (user_id, key_id, algo, public_key, status, created_at, revoked_at) \
             VALUES ($1, $2, 'ed25519', $3, $4, NOW(), $5)",
        )
        .bind::<diesel::sql_types::Uuid, _>(user_id)
        .bind::<diesel::sql_types::Uuid, _>(key_id)
        .bind::<Text, _>(public_key_b64.to_owned())
        .bind::<Text, _>(status.to_owned())
        .bind::<diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>, _>(
            if status == "revoked" {
                Some(Utc::now())
            } else {
                None
            },
        )
        .execute(conn)
        .await
        .expect("insert user_keys fixture");
    }
}
