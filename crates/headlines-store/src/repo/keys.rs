//! `PgKeyRepo` — Diesel-async impl of `headlines_core::repo::KeyRepo`,
//! covering the three `*_keys` tables (`account_keys`, `user_keys`,
//! `system_keys`).
//!
//! Phase 5 wired up `account_keys` end-to-end. Phase 7.1 lights up
//! `user_keys` so `UserService` can mint, list, revoke, and resolve user
//! keys. The `system_keys` arm remains unwired until the systems pass.

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use uuid::Uuid;

use headlines_core::HeadlinesError;
use headlines_core::repo::keys::{KeyKind, KeyRepo, KeyStatus, NewKey, StoredKey};

use crate::Db;
use crate::schema::{account_keys, user_keys};

/// Concrete `KeyRepo` over the `Db` pool.
#[derive(Clone)]
pub struct PgKeyRepo {
    db: Db,
}

impl PgKeyRepo {
    pub fn new(db: Db) -> Self {
        Self { db }
    }
}

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = account_keys)]
struct AccountKeyRow {
    account_id: Uuid,
    key_id: Uuid,
    algo: String,
    public_key: String,
    status: String,
    created_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
}

impl AccountKeyRow {
    fn into_domain(self) -> Result<StoredKey, HeadlinesError> {
        let status = parse_status("account_keys", &self.status)?;
        Ok(StoredKey {
            kind: KeyKind::Account,
            parent_id: self.account_id,
            key_id: self.key_id,
            algo: self.algo,
            public_key: self.public_key,
            status,
            created_at: self.created_at,
            revoked_at: self.revoked_at,
        })
    }
}

#[derive(Insertable)]
#[diesel(table_name = account_keys)]
struct InsertAccountKey<'a> {
    account_id: Uuid,
    key_id: Uuid,
    algo: &'a str,
    public_key: &'a str,
    status: &'a str,
}

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = user_keys)]
struct UserKeyRow {
    user_id: Uuid,
    key_id: Uuid,
    algo: String,
    public_key: String,
    status: String,
    created_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
}

impl UserKeyRow {
    fn into_domain(self) -> Result<StoredKey, HeadlinesError> {
        let status = parse_status("user_keys", &self.status)?;
        Ok(StoredKey {
            kind: KeyKind::User,
            parent_id: self.user_id,
            key_id: self.key_id,
            algo: self.algo,
            public_key: self.public_key,
            status,
            created_at: self.created_at,
            revoked_at: self.revoked_at,
        })
    }
}

#[derive(Insertable)]
#[diesel(table_name = user_keys)]
struct InsertUserKey<'a> {
    user_id: Uuid,
    key_id: Uuid,
    algo: &'a str,
    public_key: &'a str,
    status: &'a str,
}

fn parse_status(table: &str, raw: &str) -> Result<KeyStatus, HeadlinesError> {
    match raw {
        "active" => Ok(KeyStatus::Active),
        "revoked" => Ok(KeyStatus::Revoked),
        other => Err(HeadlinesError::Internal(anyhow::anyhow!(
            "unknown {table}.status value: {other}"
        ))),
    }
}

impl KeyRepo for PgKeyRepo {
    async fn create(&self, new: NewKey) -> Result<StoredKey, HeadlinesError> {
        match new.kind {
            KeyKind::Account => {
                let mut conn = self.db.get().await.map_err(HeadlinesError::Internal)?;
                let insert = InsertAccountKey {
                    account_id: new.parent_id,
                    key_id: new.key_id,
                    algo: &new.algo,
                    public_key: &new.public_key,
                    status: "active",
                };
                let row: AccountKeyRow = diesel::insert_into(account_keys::table)
                    .values(&insert)
                    .returning(AccountKeyRow::as_returning())
                    .get_result(&mut conn)
                    .await
                    .map_err(|e| {
                        HeadlinesError::Internal(anyhow::anyhow!("insert account_key: {e}"))
                    })?;
                row.into_domain()
            }
            KeyKind::User => {
                let mut conn = self.db.get().await.map_err(HeadlinesError::Internal)?;
                let insert = InsertUserKey {
                    user_id: new.parent_id,
                    key_id: new.key_id,
                    algo: &new.algo,
                    public_key: &new.public_key,
                    status: "active",
                };
                let row: UserKeyRow = diesel::insert_into(user_keys::table)
                    .values(&insert)
                    .returning(UserKeyRow::as_returning())
                    .get_result(&mut conn)
                    .await
                    .map_err(|e| {
                        HeadlinesError::Internal(anyhow::anyhow!("insert user_key: {e}"))
                    })?;
                row.into_domain()
            }
            KeyKind::System => Err(HeadlinesError::Internal(anyhow::anyhow!(
                "PgKeyRepo::create for kind={:?} not implemented",
                new.kind
            ))),
        }
    }

    async fn get(
        &self,
        kind: KeyKind,
        parent_id: Uuid,
        key_id: Uuid,
    ) -> Result<StoredKey, HeadlinesError> {
        match kind {
            KeyKind::Account => {
                let mut conn = self.db.get().await.map_err(HeadlinesError::Internal)?;
                let row = account_keys::table
                    .filter(account_keys::account_id.eq(parent_id))
                    .filter(account_keys::key_id.eq(key_id))
                    .select(AccountKeyRow::as_select())
                    .first::<AccountKeyRow>(&mut conn)
                    .await
                    .optional()
                    .map_err(|e| {
                        HeadlinesError::Internal(anyhow::anyhow!("select account_key: {e}"))
                    })?;
                row.ok_or(HeadlinesError::KeyNotFound { key_id })?
                    .into_domain()
            }
            KeyKind::User => {
                let mut conn = self.db.get().await.map_err(HeadlinesError::Internal)?;
                let row = user_keys::table
                    .filter(user_keys::user_id.eq(parent_id))
                    .filter(user_keys::key_id.eq(key_id))
                    .select(UserKeyRow::as_select())
                    .first::<UserKeyRow>(&mut conn)
                    .await
                    .optional()
                    .map_err(|e| {
                        HeadlinesError::Internal(anyhow::anyhow!("select user_key: {e}"))
                    })?;
                row.ok_or(HeadlinesError::KeyNotFound { key_id })?
                    .into_domain()
            }
            KeyKind::System => Err(HeadlinesError::KeyNotFound { key_id }),
        }
    }

    async fn revoke(
        &self,
        kind: KeyKind,
        parent_id: Uuid,
        key_id: Uuid,
    ) -> Result<StoredKey, HeadlinesError> {
        match kind {
            KeyKind::Account => {
                let mut conn = self.db.get().await.map_err(HeadlinesError::Internal)?;

                let existing = account_keys::table
                    .filter(account_keys::account_id.eq(parent_id))
                    .filter(account_keys::key_id.eq(key_id))
                    .select(AccountKeyRow::as_select())
                    .first::<AccountKeyRow>(&mut conn)
                    .await
                    .optional()
                    .map_err(|e| {
                        HeadlinesError::Internal(anyhow::anyhow!("select account_key: {e}"))
                    })?
                    .ok_or(HeadlinesError::KeyNotFound { key_id })?;

                if existing.status == "revoked" {
                    return Err(HeadlinesError::KeyAlreadyRevoked { key_id });
                }

                let now = Utc::now();
                let updated: AccountKeyRow = diesel::update(
                    account_keys::table
                        .filter(account_keys::account_id.eq(parent_id))
                        .filter(account_keys::key_id.eq(key_id)),
                )
                .set((
                    account_keys::status.eq("revoked"),
                    account_keys::revoked_at.eq(now),
                ))
                .returning(AccountKeyRow::as_returning())
                .get_result(&mut conn)
                .await
                .map_err(|e| {
                    HeadlinesError::Internal(anyhow::anyhow!("revoke account_key: {e}"))
                })?;
                updated.into_domain()
            }
            KeyKind::User => {
                let mut conn = self.db.get().await.map_err(HeadlinesError::Internal)?;

                let existing = user_keys::table
                    .filter(user_keys::user_id.eq(parent_id))
                    .filter(user_keys::key_id.eq(key_id))
                    .select(UserKeyRow::as_select())
                    .first::<UserKeyRow>(&mut conn)
                    .await
                    .optional()
                    .map_err(|e| HeadlinesError::Internal(anyhow::anyhow!("select user_key: {e}")))?
                    .ok_or(HeadlinesError::KeyNotFound { key_id })?;

                if existing.status == "revoked" {
                    return Err(HeadlinesError::KeyAlreadyRevoked { key_id });
                }

                let now = Utc::now();
                let updated: UserKeyRow = diesel::update(
                    user_keys::table
                        .filter(user_keys::user_id.eq(parent_id))
                        .filter(user_keys::key_id.eq(key_id)),
                )
                .set((
                    user_keys::status.eq("revoked"),
                    user_keys::revoked_at.eq(now),
                ))
                .returning(UserKeyRow::as_returning())
                .get_result(&mut conn)
                .await
                .map_err(|e| HeadlinesError::Internal(anyhow::anyhow!("revoke user_key: {e}")))?;
                updated.into_domain()
            }
            KeyKind::System => Err(HeadlinesError::KeyNotFound { key_id }),
        }
    }

    async fn list_active(
        &self,
        kind: KeyKind,
        parent_id: Uuid,
    ) -> Result<Vec<StoredKey>, HeadlinesError> {
        match kind {
            KeyKind::Account => {
                let mut conn = self.db.get().await.map_err(HeadlinesError::Internal)?;
                let rows = account_keys::table
                    .filter(account_keys::account_id.eq(parent_id))
                    .filter(account_keys::status.eq("active"))
                    .select(AccountKeyRow::as_select())
                    .load::<AccountKeyRow>(&mut conn)
                    .await
                    .map_err(|e| {
                        HeadlinesError::Internal(anyhow::anyhow!("list active account_keys: {e}"))
                    })?;
                rows.into_iter()
                    .map(AccountKeyRow::into_domain)
                    .collect::<Result<Vec<_>, _>>()
            }
            KeyKind::User => {
                let mut conn = self.db.get().await.map_err(HeadlinesError::Internal)?;
                let rows = user_keys::table
                    .filter(user_keys::user_id.eq(parent_id))
                    .filter(user_keys::status.eq("active"))
                    .select(UserKeyRow::as_select())
                    .load::<UserKeyRow>(&mut conn)
                    .await
                    .map_err(|e| {
                        HeadlinesError::Internal(anyhow::anyhow!("list active user_keys: {e}"))
                    })?;
                rows.into_iter()
                    .map(UserKeyRow::into_domain)
                    .collect::<Result<Vec<_>, _>>()
            }
            KeyKind::System => Ok(Vec::new()),
        }
    }
}
