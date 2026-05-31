//! `PgDraftRepo` — Diesel-async impl of `headlines_core::repo::DraftRepo`.
//!
//! Per `docs/design/drafts.md`:
//!
//! - Drafts are mutable in place; `update` mutates the row directly and
//!   bumps `updated_at`.
//! - `delete` is a hard delete (no tombstone — drafts were never public).
//! - `publish` is a single tx that takes a `FOR UPDATE` lock on the draft
//!   row, hands its fields off into `articles` / `articles_live` /
//!   `article_versions` (preserving the UUID), and `DELETE`s the draft.
//!   The lock serializes concurrent calls; the loser sees `DraftNotFound`
//!   because the winner deleted the row inside the same tx.
//!
//! The publish path duplicates a small amount of logic from
//! `PgArticleRepo::publish` (the three INSERTs into the article table
//! family). Deliberately kept duplicated rather than extracted to a shared
//! helper: the article-side `publish` works from a `NewArticle` DTO over a
//! freshly-minted UUID, while the draft-side `publish` works from rows
//! already locked by `FOR UPDATE` inside the same transaction. Sharing
//! across that boundary would force one of the two to grow a less-natural
//! signature; the three INSERTs are short enough to read in place.

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::{AsyncConnection, RunQueryDsl};
use serde_json::Value as Json;
use uuid::Uuid;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;

use headlines_core::HeadlinesError;
use headlines_core::repo::PageToken;
use headlines_core::repo::articles::{Article, ArticleState, ArticleSummary};
use headlines_core::repo::drafts::{
    Draft, DraftRepo, DraftSummary, DraftUpdate, ListDraftsPage, NewDraft,
};

use crate::Db;
use crate::schema::{article_versions, articles, articles_live, drafts};

/// Intermediate error type used inside `AsyncConnection::transaction`
/// closures. Same pattern as `articles.rs` — Diesel-async needs the closure
/// error to be `From<diesel::result::Error>`, but `HeadlinesError` is
/// deliberately Diesel-agnostic.
#[derive(Debug)]
enum TxError {
    Domain(HeadlinesError),
    Diesel(diesel::result::Error),
}

impl From<diesel::result::Error> for TxError {
    fn from(e: diesel::result::Error) -> Self {
        TxError::Diesel(e)
    }
}

impl From<HeadlinesError> for TxError {
    fn from(e: HeadlinesError) -> Self {
        TxError::Domain(e)
    }
}

impl From<TxError> for HeadlinesError {
    fn from(e: TxError) -> Self {
        match e {
            TxError::Domain(d) => d,
            TxError::Diesel(e) => HeadlinesError::Internal(anyhow::anyhow!("tx: {e}")),
        }
    }
}

/// Wrap a Diesel error with a static context string, projected directly
/// into a `TxError`. Mirrors the `tx_internal` helper in
/// `repo/articles.rs`.
fn tx_internal(ctx: &'static str) -> impl Fn(diesel::result::Error) -> TxError {
    move |e| TxError::Domain(HeadlinesError::Internal(anyhow::anyhow!("{ctx}: {e}")))
}

/// Concrete `DraftRepo` over the `Db` pool.
#[derive(Clone)]
pub struct PgDraftRepo {
    db: Db,
}

impl PgDraftRepo {
    pub fn new(db: Db) -> Self {
        Self { db }
    }
}

// ---------------------------------------------------------------------------
// Diesel row shapes
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = drafts)]
struct DraftRow {
    id: Uuid,
    account_id: Uuid,
    title: String,
    author_name: Option<String>,
    author_url: Option<String>,
    content: Json,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<DraftRow> for Draft {
    fn from(r: DraftRow) -> Draft {
        Draft {
            id: r.id,
            account_id: r.account_id,
            title: r.title,
            author_name: r.author_name.unwrap_or_default(),
            author_url: r.author_url.unwrap_or_default(),
            content: r.content,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

#[derive(Insertable)]
#[diesel(table_name = drafts)]
struct InsertDraft<'a> {
    id: Uuid,
    account_id: Uuid,
    title: &'a str,
    author_name: Option<&'a str>,
    author_url: Option<&'a str>,
    content: &'a Json,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Insertable)]
#[diesel(table_name = articles)]
struct InsertArticle<'a> {
    id: Uuid,
    account_id: Uuid,
    state: &'a str,
    created_at: DateTime<Utc>,
}

#[derive(Insertable)]
#[diesel(table_name = articles_live)]
struct InsertArticleLive {
    article_id: Uuid,
    current_version: i32,
    published_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Insertable)]
#[diesel(table_name = article_versions)]
struct InsertArticleVersion<'a> {
    article_id: Uuid,
    version: i32,
    title: &'a str,
    author_name: Option<&'a str>,
    author_url: Option<&'a str>,
    content: Option<&'a Json>,
    created_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Page-token codec — keyset on (updated_at, id)
// ---------------------------------------------------------------------------

const DEFAULT_PAGE_SIZE: i32 = 20;
const MAX_PAGE_SIZE: i32 = 100;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct PageCursor {
    /// RFC3339 of the last row's `updated_at`.
    u: String,
    /// Last row's id (tiebreaker).
    i: Uuid,
}

fn encode_cursor(u: &DateTime<Utc>, id: Uuid) -> PageToken {
    let cursor = PageCursor {
        u: u.to_rfc3339(),
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

// ---------------------------------------------------------------------------
// DraftRepo impl
// ---------------------------------------------------------------------------

impl DraftRepo for PgDraftRepo {
    async fn create(&self, new: NewDraft) -> Result<Draft, HeadlinesError> {
        let mut conn = self.db.get().await.map_err(HeadlinesError::Internal)?;
        let now = Utc::now();
        let an = if new.author_name.is_empty() {
            None
        } else {
            Some(new.author_name.as_str())
        };
        let au = if new.author_url.is_empty() {
            None
        } else {
            Some(new.author_url.as_str())
        };
        let row: DraftRow = diesel::insert_into(drafts::table)
            .values(InsertDraft {
                id: new.id,
                account_id: new.account_id,
                title: new.title.as_str(),
                author_name: an,
                author_url: au,
                content: &new.content,
                created_at: now,
                updated_at: now,
            })
            .returning(DraftRow::as_returning())
            .get_result(&mut conn)
            .await
            .map_err(|e| HeadlinesError::Internal(anyhow::anyhow!("insert drafts: {e}")))?;
        Ok(row.into())
    }

    async fn get(&self, id: Uuid) -> Result<Draft, HeadlinesError> {
        let mut conn = self.db.get().await.map_err(HeadlinesError::Internal)?;
        let row: Option<DraftRow> = drafts::table
            .filter(drafts::id.eq(id))
            .select(DraftRow::as_select())
            .first(&mut conn)
            .await
            .optional()
            .map_err(|e| HeadlinesError::Internal(anyhow::anyhow!("select drafts: {e}")))?;
        row.map(Draft::from)
            .ok_or(HeadlinesError::DraftNotFound { id })
    }

    async fn update(&self, id: Uuid, update: DraftUpdate) -> Result<Draft, HeadlinesError> {
        let mut conn = self.db.get().await.map_err(HeadlinesError::Internal)?;
        let now = Utc::now();
        // Build a single UPDATE applying only the masked fields. Diesel
        // doesn't have a clean dynamic-set builder for sparse updates, so we
        // dispatch on the option combination.
        let id_for_tx = id;

        let row: DraftRow = conn
            .transaction::<_, TxError, _>(async |conn| {
                let upd = update.clone();
                // Confirm existence first so missing -> DraftNotFound,
                // not just an empty UPDATE result.
                let existing: Option<DraftRow> = drafts::table
                    .filter(drafts::id.eq(id_for_tx))
                    .select(DraftRow::as_select())
                    .first(conn)
                    .await
                    .optional()
                    .map_err(tx_internal("select drafts for update"))?;
                if existing.is_none() {
                    return Err(TxError::Domain(HeadlinesError::DraftNotFound {
                        id: id_for_tx,
                    }));
                }

                let target = drafts::table.filter(drafts::id.eq(id_for_tx));
                let title_ref = upd.title.as_deref();
                let an_ref = upd.author_name.as_deref();
                let au_ref = upd.author_url.as_deref();
                let content_ref = upd.content.as_ref();

                // Always bump updated_at; build a tuple of changes.
                // Use BoxableExpression-style explicit calls.
                if let Some(t) = title_ref {
                    diesel::update(drafts::table.filter(drafts::id.eq(id_for_tx)))
                        .set(drafts::title.eq(t))
                        .execute(conn)
                        .await
                        .map_err(tx_internal("update drafts.title"))?;
                }
                if let Some(an) = an_ref {
                    let v: Option<&str> = if an.is_empty() { None } else { Some(an) };
                    diesel::update(drafts::table.filter(drafts::id.eq(id_for_tx)))
                        .set(drafts::author_name.eq(v))
                        .execute(conn)
                        .await
                        .map_err(tx_internal("update drafts.author_name"))?;
                }
                if let Some(au) = au_ref {
                    let v: Option<&str> = if au.is_empty() { None } else { Some(au) };
                    diesel::update(drafts::table.filter(drafts::id.eq(id_for_tx)))
                        .set(drafts::author_url.eq(v))
                        .execute(conn)
                        .await
                        .map_err(tx_internal("update drafts.author_url"))?;
                }
                if let Some(c) = content_ref {
                    diesel::update(drafts::table.filter(drafts::id.eq(id_for_tx)))
                        .set(drafts::content.eq(c))
                        .execute(conn)
                        .await
                        .map_err(tx_internal("update drafts.content"))?;
                }
                diesel::update(target)
                    .set(drafts::updated_at.eq(now))
                    .execute(conn)
                    .await
                    .map_err(tx_internal("update drafts.updated_at"))?;

                let row: DraftRow = drafts::table
                    .filter(drafts::id.eq(id_for_tx))
                    .select(DraftRow::as_select())
                    .first(conn)
                    .await
                    .map_err(tx_internal("re-select drafts after update"))?;
                Ok::<DraftRow, TxError>(row)
            })
            .await?;

        Ok(row.into())
    }

    async fn delete(&self, id: Uuid) -> Result<(), HeadlinesError> {
        let mut conn = self.db.get().await.map_err(HeadlinesError::Internal)?;
        let n = diesel::delete(drafts::table.filter(drafts::id.eq(id)))
            .execute(&mut conn)
            .await
            .map_err(|e| HeadlinesError::Internal(anyhow::anyhow!("delete drafts: {e}")))?;
        if n == 0 {
            return Err(HeadlinesError::DraftNotFound { id });
        }
        Ok(())
    }

    async fn list_by_account(
        &self,
        account_id: Uuid,
        page_size: i32,
        page_token: PageToken,
    ) -> Result<ListDraftsPage, HeadlinesError> {
        let limit = if page_size <= 0 {
            DEFAULT_PAGE_SIZE
        } else {
            page_size.min(MAX_PAGE_SIZE)
        };

        let cursor = if page_token.is_empty() {
            None
        } else {
            Some(decode_cursor(page_token.as_str())?)
        };
        let cursor_dt = match cursor.as_ref() {
            Some(c) => Some(
                DateTime::parse_from_rfc3339(&c.u)
                    .map_err(|e| HeadlinesError::InvalidCursor {
                        reason: format!("rfc3339: {e}"),
                    })?
                    .with_timezone(&Utc),
            ),
            None => None,
        };

        let mut conn = self.db.get().await.map_err(HeadlinesError::Internal)?;

        let mut q = drafts::table
            .filter(drafts::account_id.eq(account_id))
            .into_boxed();
        if let (Some(c_dt), Some(c)) = (cursor_dt, cursor.as_ref()) {
            // Strict keyset on (updated_at DESC, id DESC).
            q = q.filter(
                drafts::updated_at
                    .lt(c_dt)
                    .or(drafts::updated_at.eq(c_dt).and(drafts::id.lt(c.i))),
            );
        }
        let rows: Vec<DraftRow> = q
            .order((drafts::updated_at.desc(), drafts::id.desc()))
            .limit((limit as i64) + 1)
            .select(DraftRow::as_select())
            .load(&mut conn)
            .await
            .map_err(|e| HeadlinesError::Internal(anyhow::anyhow!("list drafts: {e}")))?;

        let has_more = rows.len() as i32 > limit;
        let mut rows = rows;
        if has_more {
            rows.truncate(limit as usize);
        }

        let items: Vec<DraftSummary> = rows
            .iter()
            .map(|r| DraftSummary {
                id: r.id,
                account_id: r.account_id,
                title: r.title.clone(),
                created_at: r.created_at,
                updated_at: r.updated_at,
            })
            .collect();

        let next_page_token = if has_more {
            if let Some(last) = rows.last() {
                encode_cursor(&last.updated_at, last.id)
            } else {
                PageToken::empty()
            }
        } else {
            PageToken::empty()
        };

        Ok(ListDraftsPage {
            items,
            next_page_token,
        })
    }

    async fn publish(&self, id: Uuid) -> Result<Article, HeadlinesError> {
        let mut conn = self.db.get().await.map_err(HeadlinesError::Internal)?;
        let now = Utc::now();
        let id_for_tx = id;

        // Single tx: SELECT … FOR UPDATE on the draft, INSERT into articles,
        // articles_live, article_versions (preserving the UUID), DELETE the
        // draft. Concurrent publishes serialize on the FOR UPDATE lock; the
        // loser sees DraftNotFound (the row was deleted by the winner inside
        // the same tx).
        let result: ArticlePieces = conn
            .transaction::<_, TxError, _>(async |conn| {
                // FOR UPDATE on the draft row - diesel's `for_update()` is
                // the AsyncConnection-friendly way to take a row lock.
                let row: Option<DraftRow> = drafts::table
                    .filter(drafts::id.eq(id_for_tx))
                    .for_update()
                    .select(DraftRow::as_select())
                    .first(conn)
                    .await
                    .optional()
                    .map_err(tx_internal("select drafts for publish"))?;
                let row = row.ok_or(TxError::Domain(HeadlinesError::DraftNotFound {
                    id: id_for_tx,
                }))?;

                diesel::insert_into(articles::table)
                    .values(InsertArticle {
                        id: row.id,
                        account_id: row.account_id,
                        state: "live",
                        created_at: now,
                    })
                    .execute(conn)
                    .await
                    .map_err(tx_internal("insert articles"))?;

                diesel::insert_into(articles_live::table)
                    .values(InsertArticleLive {
                        article_id: row.id,
                        current_version: 1,
                        published_at: now,
                        updated_at: now,
                    })
                    .execute(conn)
                    .await
                    .map_err(tx_internal("insert articles_live"))?;

                let an: Option<&str> = row.author_name.as_deref();
                let au: Option<&str> = row.author_url.as_deref();
                diesel::insert_into(article_versions::table)
                    .values(InsertArticleVersion {
                        article_id: row.id,
                        version: 1,
                        title: row.title.as_str(),
                        author_name: an,
                        author_url: au,
                        content: Some(&row.content),
                        created_at: now,
                    })
                    .execute(conn)
                    .await
                    .map_err(tx_internal("insert article_versions"))?;

                diesel::delete(drafts::table.filter(drafts::id.eq(id_for_tx)))
                    .execute(conn)
                    .await
                    .map_err(tx_internal("delete drafts after publish"))?;

                Ok::<ArticlePieces, TxError>(ArticlePieces {
                    id: row.id,
                    account_id: row.account_id,
                    title: row.title,
                    author_name: row.author_name.unwrap_or_default(),
                    author_url: row.author_url.unwrap_or_default(),
                    content: row.content,
                    published_at: now,
                    updated_at: now,
                    created_at: now,
                })
            })
            .await?;

        // Assemble the Article view from the pieces we already have. No
        // re-read needed — every field is the value we just persisted.
        Ok(Article {
            summary: ArticleSummary {
                id: result.id,
                account_id: result.account_id,
                state: ArticleState::Live,
                created_at: result.created_at,
                current_version: Some(1),
                title: Some(result.title),
                author_name: Some(result.author_name),
                author_url: Some(result.author_url),
                redacted: false,
                published_at: Some(result.published_at),
                updated_at: Some(result.updated_at),
                tombstone_reason: None,
                tombstoned_at: None,
            },
            content: Some(result.content),
        })
    }
}

/// Pieces of the new article assembled inside the publish transaction. The
/// transaction returns these so the caller can build an `Article` without an
/// extra `SELECT` round trip.
struct ArticlePieces {
    id: Uuid,
    account_id: Uuid,
    title: String,
    author_name: String,
    author_url: String,
    content: Json,
    published_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
}
