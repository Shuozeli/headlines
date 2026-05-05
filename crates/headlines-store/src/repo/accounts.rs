//! `PgAccountRepo` — Diesel-async impl of `headlines_core::repo::AccountRepo`.
//!
//! Maps the rows in the `accounts` table to / from the domain
//! `Account` / `NewAccount` / `AccountUpdate` types. UUIDv7 generation is the
//! service handler's job; this layer only persists.

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use uuid::Uuid;

use headlines_core::HeadlinesError;
use headlines_core::repo::accounts::{
    Account, AccountRepo, AccountStatus, AccountUpdate, NewAccount,
};

use crate::Db;
use crate::schema::accounts::{self, dsl};

/// Concrete `AccountRepo` over the `Db` pool.
#[derive(Clone)]
pub struct PgAccountRepo {
    db: Db,
}

impl PgAccountRepo {
    pub fn new(db: Db) -> Self {
        Self { db }
    }
}

/// Row shape for `SELECT * FROM accounts`.
#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = accounts)]
struct AccountRow {
    id: Uuid,
    short_name: String,
    author_name: String,
    author_url: Option<String>,
    status: String,
    deleted_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl AccountRow {
    fn into_domain(self) -> Result<Account, HeadlinesError> {
        let status = match self.status.as_str() {
            "active" => AccountStatus::Active,
            "deleted" => AccountStatus::Deleted,
            other => {
                return Err(HeadlinesError::Internal(anyhow::anyhow!(
                    "unknown accounts.status value in DB: {other}"
                )));
            }
        };
        Ok(Account {
            id: self.id,
            short_name: self.short_name,
            author_name: self.author_name,
            author_url: self.author_url.unwrap_or_default(),
            status,
            deleted_at: self.deleted_at,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

#[derive(Insertable)]
#[diesel(table_name = accounts)]
struct InsertAccount<'a> {
    id: Uuid,
    short_name: &'a str,
    author_name: &'a str,
    author_url: Option<&'a str>,
    status: &'a str,
}

impl AccountRepo for PgAccountRepo {
    async fn create(&self, new: NewAccount) -> Result<Account, HeadlinesError> {
        let mut conn = self.db.get().await.map_err(HeadlinesError::Internal)?;

        let insert = InsertAccount {
            id: new.id,
            short_name: &new.short_name,
            author_name: &new.author_name,
            author_url: if new.author_url.is_empty() {
                None
            } else {
                Some(new.author_url.as_str())
            },
            status: "active",
        };

        let row: AccountRow = diesel::insert_into(accounts::table)
            .values(&insert)
            .returning(AccountRow::as_returning())
            .get_result(&mut conn)
            .await
            .map_err(|e| HeadlinesError::Internal(anyhow::anyhow!("insert account: {e}")))?;

        row.into_domain()
    }

    async fn get(&self, id: Uuid) -> Result<Account, HeadlinesError> {
        let mut conn = self.db.get().await.map_err(HeadlinesError::Internal)?;

        let row = dsl::accounts
            .filter(dsl::id.eq(id))
            .select(AccountRow::as_select())
            .first::<AccountRow>(&mut conn)
            .await
            .optional()
            .map_err(|e| HeadlinesError::Internal(anyhow::anyhow!("select account: {e}")))?;

        match row {
            Some(r) => r.into_domain(),
            None => Err(HeadlinesError::AccountNotFound { id }),
        }
    }

    async fn update(&self, id: Uuid, update: AccountUpdate) -> Result<Account, HeadlinesError> {
        let mut conn = self.db.get().await.map_err(HeadlinesError::Internal)?;

        // Reject updates on a deleted account up-front so callers get the
        // domain error instead of a silent no-op.
        let existing = dsl::accounts
            .filter(dsl::id.eq(id))
            .select(AccountRow::as_select())
            .first::<AccountRow>(&mut conn)
            .await
            .optional()
            .map_err(|e| HeadlinesError::Internal(anyhow::anyhow!("select account: {e}")))?;
        let existing = existing.ok_or(HeadlinesError::AccountNotFound { id })?;
        if existing.status == "deleted" {
            return Err(HeadlinesError::AccountDeleted { id });
        }

        // Diesel's typed update helpers want each set-clause to be the same
        // SqlType, which doesn't work cleanly for the partial-update shape
        // here. Issue per-field updates only when present, then re-read the
        // row. This is fine for the lightly-used UpdateAccount path; high-rate
        // writers would build a single dynamic update.
        let now = Utc::now();
        if let Some(short_name) = update.short_name.as_deref() {
            diesel::update(dsl::accounts.filter(dsl::id.eq(id)))
                .set((dsl::short_name.eq(short_name), dsl::updated_at.eq(now)))
                .execute(&mut conn)
                .await
                .map_err(|e| HeadlinesError::Internal(anyhow::anyhow!("update short_name: {e}")))?;
        }
        if let Some(author_name) = update.author_name.as_deref() {
            diesel::update(dsl::accounts.filter(dsl::id.eq(id)))
                .set((dsl::author_name.eq(author_name), dsl::updated_at.eq(now)))
                .execute(&mut conn)
                .await
                .map_err(|e| {
                    HeadlinesError::Internal(anyhow::anyhow!("update author_name: {e}"))
                })?;
        }
        if let Some(author_url) = update.author_url.as_ref() {
            let val = if author_url.is_empty() {
                None
            } else {
                Some(author_url.as_str())
            };
            diesel::update(dsl::accounts.filter(dsl::id.eq(id)))
                .set((dsl::author_url.eq(val), dsl::updated_at.eq(now)))
                .execute(&mut conn)
                .await
                .map_err(|e| HeadlinesError::Internal(anyhow::anyhow!("update author_url: {e}")))?;
        }

        let updated = dsl::accounts
            .filter(dsl::id.eq(id))
            .select(AccountRow::as_select())
            .first::<AccountRow>(&mut conn)
            .await
            .map_err(|e| HeadlinesError::Internal(anyhow::anyhow!("re-read after update: {e}")))?;
        updated.into_domain()
    }

    async fn soft_delete(&self, id: Uuid) -> Result<Account, HeadlinesError> {
        let mut conn = self.db.get().await.map_err(HeadlinesError::Internal)?;

        let now = Utc::now();
        let updated = diesel::update(dsl::accounts.filter(dsl::id.eq(id)))
            .set((
                dsl::status.eq("deleted"),
                dsl::deleted_at.eq(now),
                dsl::updated_at.eq(now),
            ))
            .returning(AccountRow::as_returning())
            .get_result::<AccountRow>(&mut conn)
            .await
            .optional()
            .map_err(|e| HeadlinesError::Internal(anyhow::anyhow!("soft-delete: {e}")))?;

        match updated {
            Some(r) => r.into_domain(),
            None => Err(HeadlinesError::AccountNotFound { id }),
        }
    }
}
