//! `PgFollowRepo` — Diesel-async impl of `headlines_core::repo::FollowRepo`.
//!
//! Persistence semantics mirror the state machine in `docs/design/follows.md`:
//!
//! - `follow`: UPSERT — insert when missing, no-op when already active,
//!   re-activate when `unfollowed` (clears `unfollowed_at`, resets
//!   `created_at = now` so list ordering reflects the new relationship).
//! - `unfollow`: flips `active → unfollowed`. Missing rows surface as
//!   `FollowNotFound`; already-unfollowed rows are idempotent successes.
//! - `list_by_user` / `list_by_account`: keyset pagination on
//!   `(created_at DESC, tiebreaker_id DESC)` with the tiebreaker chosen
//!   per query (account_id for user-side, user_id for account-side). No
//!   filtering for deleted users on the account-side per `follows.md`
//!   list behavior.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use uuid::Uuid;

use headlines_core::HeadlinesError;
use headlines_core::repo::PageToken;
use headlines_core::repo::follows::{Follow, FollowRepo, FollowStatus, ListFollowsPage};

use crate::Db;
use crate::schema::follows::{self, dsl};

/// Concrete `FollowRepo` over the `Db` pool.
#[derive(Clone)]
pub struct PgFollowRepo {
    db: Db,
}

impl PgFollowRepo {
    pub fn new(db: Db) -> Self {
        Self { db }
    }
}

// ---------------------------------------------------------------------------
// Diesel row shapes
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = follows)]
struct FollowRow {
    user_id: Uuid,
    account_id: Uuid,
    status: String,
    created_at: DateTime<Utc>,
    unfollowed_at: Option<DateTime<Utc>>,
}

#[derive(Insertable)]
#[diesel(table_name = follows)]
struct InsertFollow {
    user_id: Uuid,
    account_id: Uuid,
    status: &'static str,
    created_at: DateTime<Utc>,
    unfollowed_at: Option<DateTime<Utc>>,
}

impl FollowRow {
    fn into_domain(self) -> Result<Follow, HeadlinesError> {
        let status = match self.status.as_str() {
            "active" => FollowStatus::Active,
            "unfollowed" => FollowStatus::Unfollowed,
            other => {
                return Err(HeadlinesError::Internal(anyhow::anyhow!(
                    "unknown follows.status value in DB: {other}"
                )));
            }
        };
        Ok(Follow {
            user_id: self.user_id,
            account_id: self.account_id,
            status,
            created_at: self.created_at,
            unfollowed_at: self.unfollowed_at,
        })
    }
}

// ---------------------------------------------------------------------------
// Page-token codec — keyset on (created_at, tiebreaker_id)
// ---------------------------------------------------------------------------

const DEFAULT_PAGE_SIZE: i32 = 50;
const MIN_PAGE_SIZE: i32 = 1;
const MAX_PAGE_SIZE: i32 = 200;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct PageCursor {
    /// RFC3339 of the last row's `created_at`.
    c: String,
    /// Last row's tiebreaker id. For `list_by_user` this is the
    /// `account_id`; for `list_by_account` it is the `user_id`.
    i: Uuid,
}

fn encode_cursor(c: &DateTime<Utc>, id: Uuid) -> PageToken {
    let cursor = PageCursor {
        c: c.to_rfc3339(),
        i: id,
    };
    let json = serde_json::to_vec(&cursor).expect("PageCursor is always serializable");
    PageToken(B64URL.encode(json))
}

fn decode_cursor(raw: &str) -> Result<PageCursor, HeadlinesError> {
    let bytes = B64URL
        .decode(raw)
        .map_err(|e| HeadlinesError::InvalidCursor {
            reason: format!("base64: {e}"),
        })?;
    serde_json::from_slice::<PageCursor>(&bytes).map_err(|e| HeadlinesError::InvalidCursor {
        reason: format!("json: {e}"),
    })
}

fn clamp_page_size(raw: i32) -> i32 {
    if raw <= 0 {
        DEFAULT_PAGE_SIZE
    } else {
        raw.clamp(MIN_PAGE_SIZE, MAX_PAGE_SIZE)
    }
}

// ---------------------------------------------------------------------------
// FollowRepo impl
// ---------------------------------------------------------------------------

impl FollowRepo for PgFollowRepo {
    async fn follow(&self, user_id: Uuid, account_id: Uuid) -> Result<Follow, HeadlinesError> {
        let mut conn = self.db.get().await.map_err(HeadlinesError::Internal)?;

        // Read the current row first. If active → no-op (return as-is).
        // Otherwise upsert: insert when missing, re-activate when unfollowed
        // (clear unfollowed_at, reset created_at = now). Two-step so the
        // active-no-op path doesn't bump `created_at`.
        let existing: Option<FollowRow> = dsl::follows
            .filter(dsl::user_id.eq(user_id))
            .filter(dsl::account_id.eq(account_id))
            .select(FollowRow::as_select())
            .first::<FollowRow>(&mut conn)
            .await
            .optional()
            .map_err(|e| HeadlinesError::Internal(anyhow::anyhow!("select follows: {e}")))?;

        if let Some(row) = existing
            && row.status == "active"
        {
            return row.into_domain();
        }

        let now = Utc::now();
        let row: FollowRow = diesel::insert_into(follows::table)
            .values(InsertFollow {
                user_id,
                account_id,
                status: "active",
                created_at: now,
                unfollowed_at: None,
            })
            .on_conflict((follows::user_id, follows::account_id))
            .do_update()
            .set((
                follows::status.eq("active"),
                follows::created_at.eq(now),
                follows::unfollowed_at.eq::<Option<DateTime<Utc>>>(None),
            ))
            .returning(FollowRow::as_returning())
            .get_result(&mut conn)
            .await
            .map_err(|e| HeadlinesError::Internal(anyhow::anyhow!("upsert follow: {e}")))?;

        row.into_domain()
    }

    async fn unfollow(&self, user_id: Uuid, account_id: Uuid) -> Result<Follow, HeadlinesError> {
        let mut conn = self.db.get().await.map_err(HeadlinesError::Internal)?;

        let existing: Option<FollowRow> = dsl::follows
            .filter(dsl::user_id.eq(user_id))
            .filter(dsl::account_id.eq(account_id))
            .select(FollowRow::as_select())
            .first::<FollowRow>(&mut conn)
            .await
            .optional()
            .map_err(|e| HeadlinesError::Internal(anyhow::anyhow!("select follows: {e}")))?;

        let Some(row) = existing else {
            return Err(HeadlinesError::FollowNotFound {
                user_id,
                account_id,
            });
        };
        if row.status == "unfollowed" {
            // Idempotent — already unfollowed, return current row.
            return row.into_domain();
        }

        let now = Utc::now();
        let updated: FollowRow = diesel::update(
            dsl::follows
                .filter(dsl::user_id.eq(user_id))
                .filter(dsl::account_id.eq(account_id)),
        )
        .set((
            dsl::status.eq("unfollowed"),
            dsl::unfollowed_at.eq(Some(now)),
        ))
        .returning(FollowRow::as_returning())
        .get_result(&mut conn)
        .await
        .map_err(|e| HeadlinesError::Internal(anyhow::anyhow!("update follow: {e}")))?;

        updated.into_domain()
    }

    async fn get(&self, user_id: Uuid, account_id: Uuid) -> Result<Follow, HeadlinesError> {
        let mut conn = self.db.get().await.map_err(HeadlinesError::Internal)?;

        let row: Option<FollowRow> = dsl::follows
            .filter(dsl::user_id.eq(user_id))
            .filter(dsl::account_id.eq(account_id))
            .select(FollowRow::as_select())
            .first::<FollowRow>(&mut conn)
            .await
            .optional()
            .map_err(|e| HeadlinesError::Internal(anyhow::anyhow!("select follow: {e}")))?;

        match row {
            Some(r) => r.into_domain(),
            None => Err(HeadlinesError::FollowNotFound {
                user_id,
                account_id,
            }),
        }
    }

    async fn list_by_user(
        &self,
        user_id: Uuid,
        include_unfollowed: bool,
        page_size: i32,
        page_token: PageToken,
    ) -> Result<ListFollowsPage, HeadlinesError> {
        let limit = clamp_page_size(page_size);

        let cursor = if page_token.is_empty() {
            None
        } else {
            Some(decode_cursor(page_token.as_str())?)
        };
        let cursor_dt = match cursor.as_ref() {
            Some(c) => Some(
                DateTime::parse_from_rfc3339(&c.c)
                    .map_err(|e| HeadlinesError::InvalidCursor {
                        reason: format!("rfc3339: {e}"),
                    })?
                    .with_timezone(&Utc),
            ),
            None => None,
        };

        let mut conn = self.db.get().await.map_err(HeadlinesError::Internal)?;

        let mut q = dsl::follows.filter(dsl::user_id.eq(user_id)).into_boxed();
        if !include_unfollowed {
            q = q.filter(dsl::status.eq("active"));
        }
        if let (Some(c_dt), Some(c)) = (cursor_dt, cursor.as_ref()) {
            q = q.filter(
                dsl::created_at
                    .lt(c_dt)
                    .or(dsl::created_at.eq(c_dt).and(dsl::account_id.lt(c.i))),
            );
        }
        let rows: Vec<FollowRow> = q
            .order((dsl::created_at.desc(), dsl::account_id.desc()))
            .limit((limit as i64) + 1)
            .select(FollowRow::as_select())
            .load(&mut conn)
            .await
            .map_err(|e| HeadlinesError::Internal(anyhow::anyhow!("list follows by user: {e}")))?;

        let mut rows = rows;
        let has_more = rows.len() as i32 > limit;
        if has_more {
            rows.truncate(limit as usize);
        }

        let next_page_token = if has_more {
            rows.last()
                .map(|r| encode_cursor(&r.created_at, r.account_id))
                .unwrap_or_else(PageToken::empty)
        } else {
            PageToken::empty()
        };

        let mut items = Vec::with_capacity(rows.len());
        for r in rows {
            items.push(r.into_domain()?);
        }

        Ok(ListFollowsPage {
            items,
            next_page_token,
        })
    }

    async fn list_by_account(
        &self,
        account_id: Uuid,
        include_unfollowed: bool,
        page_size: i32,
        page_token: PageToken,
    ) -> Result<ListFollowsPage, HeadlinesError> {
        let limit = clamp_page_size(page_size);

        let cursor = if page_token.is_empty() {
            None
        } else {
            Some(decode_cursor(page_token.as_str())?)
        };
        let cursor_dt = match cursor.as_ref() {
            Some(c) => Some(
                DateTime::parse_from_rfc3339(&c.c)
                    .map_err(|e| HeadlinesError::InvalidCursor {
                        reason: format!("rfc3339: {e}"),
                    })?
                    .with_timezone(&Utc),
            ),
            None => None,
        };

        let mut conn = self.db.get().await.map_err(HeadlinesError::Internal)?;

        let mut q = dsl::follows
            .filter(dsl::account_id.eq(account_id))
            .into_boxed();
        if !include_unfollowed {
            q = q.filter(dsl::status.eq("active"));
        }
        if let (Some(c_dt), Some(c)) = (cursor_dt, cursor.as_ref()) {
            q = q.filter(
                dsl::created_at
                    .lt(c_dt)
                    .or(dsl::created_at.eq(c_dt).and(dsl::user_id.lt(c.i))),
            );
        }
        let rows: Vec<FollowRow> = q
            .order((dsl::created_at.desc(), dsl::user_id.desc()))
            .limit((limit as i64) + 1)
            .select(FollowRow::as_select())
            .load(&mut conn)
            .await
            .map_err(|e| {
                HeadlinesError::Internal(anyhow::anyhow!("list follows by account: {e}"))
            })?;

        let mut rows = rows;
        let has_more = rows.len() as i32 > limit;
        if has_more {
            rows.truncate(limit as usize);
        }

        let next_page_token = if has_more {
            rows.last()
                .map(|r| encode_cursor(&r.created_at, r.user_id))
                .unwrap_or_else(PageToken::empty)
        } else {
            PageToken::empty()
        };

        let mut items = Vec::with_capacity(rows.len());
        for r in rows {
            items.push(r.into_domain()?);
        }

        Ok(ListFollowsPage {
            items,
            next_page_token,
        })
    }
}
