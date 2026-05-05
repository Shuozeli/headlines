//! `PgUserRepo` — Diesel-async impl of `headlines_core::repo::UserRepo`.
//!
//! Mirrors `PgAccountRepo`. UUIDv7 generation is the service handler's job;
//! this layer only persists.

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use uuid::Uuid;

use headlines_core::HeadlinesError;
use headlines_core::repo::users::{NewUser, User, UserRepo, UserStatus, UserUpdate};

use crate::Db;
use crate::schema::users::{self, dsl};

/// Concrete `UserRepo` over the `Db` pool.
#[derive(Clone)]
pub struct PgUserRepo {
    db: Db,
}

impl PgUserRepo {
    pub fn new(db: Db) -> Self {
        Self { db }
    }
}

/// Row shape for `SELECT * FROM users`.
#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = users)]
struct UserRow {
    id: Uuid,
    display_name: Option<String>,
    status: String,
    deleted_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

impl UserRow {
    fn into_domain(self) -> Result<User, HeadlinesError> {
        let status = match self.status.as_str() {
            "active" => UserStatus::Active,
            "deleted" => UserStatus::Deleted,
            other => {
                return Err(HeadlinesError::Internal(anyhow::anyhow!(
                    "unknown users.status value in DB: {other}"
                )));
            }
        };
        Ok(User {
            id: self.id,
            display_name: self.display_name.unwrap_or_default(),
            status,
            deleted_at: self.deleted_at,
            created_at: self.created_at,
        })
    }
}

#[derive(Insertable)]
#[diesel(table_name = users)]
struct InsertUser<'a> {
    id: Uuid,
    display_name: Option<&'a str>,
    status: &'a str,
}

impl UserRepo for PgUserRepo {
    async fn create(&self, new: NewUser) -> Result<User, HeadlinesError> {
        let mut conn = self.db.get().await.map_err(HeadlinesError::Internal)?;

        let insert = InsertUser {
            id: new.id,
            display_name: if new.display_name.is_empty() {
                None
            } else {
                Some(new.display_name.as_str())
            },
            status: "active",
        };

        let row: UserRow = diesel::insert_into(users::table)
            .values(&insert)
            .returning(UserRow::as_returning())
            .get_result(&mut conn)
            .await
            .map_err(|e| HeadlinesError::Internal(anyhow::anyhow!("insert user: {e}")))?;

        row.into_domain()
    }

    async fn get(&self, id: Uuid) -> Result<User, HeadlinesError> {
        let mut conn = self.db.get().await.map_err(HeadlinesError::Internal)?;

        let row = dsl::users
            .filter(dsl::id.eq(id))
            .select(UserRow::as_select())
            .first::<UserRow>(&mut conn)
            .await
            .optional()
            .map_err(|e| HeadlinesError::Internal(anyhow::anyhow!("select user: {e}")))?;

        match row {
            Some(r) => r.into_domain(),
            None => Err(HeadlinesError::UserNotFound { id }),
        }
    }

    async fn update(&self, id: Uuid, update: UserUpdate) -> Result<User, HeadlinesError> {
        let mut conn = self.db.get().await.map_err(HeadlinesError::Internal)?;

        // Reject updates on a deleted user up-front so callers get the
        // domain error instead of a silent no-op.
        let existing = dsl::users
            .filter(dsl::id.eq(id))
            .select(UserRow::as_select())
            .first::<UserRow>(&mut conn)
            .await
            .optional()
            .map_err(|e| HeadlinesError::Internal(anyhow::anyhow!("select user: {e}")))?;
        let existing = existing.ok_or(HeadlinesError::UserNotFound { id })?;
        if existing.status == "deleted" {
            return Err(HeadlinesError::UserDeleted { id });
        }

        // Issue per-field updates only when present, then re-read the row.
        // Mirrors `PgAccountRepo::update`.
        if let Some(display_name) = update.display_name.as_ref() {
            let val = if display_name.is_empty() {
                None
            } else {
                Some(display_name.as_str())
            };
            diesel::update(dsl::users.filter(dsl::id.eq(id)))
                .set(dsl::display_name.eq(val))
                .execute(&mut conn)
                .await
                .map_err(|e| {
                    HeadlinesError::Internal(anyhow::anyhow!("update display_name: {e}"))
                })?;
        }

        let updated = dsl::users
            .filter(dsl::id.eq(id))
            .select(UserRow::as_select())
            .first::<UserRow>(&mut conn)
            .await
            .map_err(|e| HeadlinesError::Internal(anyhow::anyhow!("re-read after update: {e}")))?;
        updated.into_domain()
    }

    async fn soft_delete(&self, id: Uuid) -> Result<User, HeadlinesError> {
        let mut conn = self.db.get().await.map_err(HeadlinesError::Internal)?;

        let now = Utc::now();
        let updated = diesel::update(dsl::users.filter(dsl::id.eq(id)))
            .set((dsl::status.eq("deleted"), dsl::deleted_at.eq(now)))
            .returning(UserRow::as_returning())
            .get_result::<UserRow>(&mut conn)
            .await
            .optional()
            .map_err(|e| HeadlinesError::Internal(anyhow::anyhow!("soft-delete user: {e}")))?;

        match updated {
            Some(r) => r.into_domain(),
            None => Err(HeadlinesError::UserNotFound { id }),
        }
    }
}
