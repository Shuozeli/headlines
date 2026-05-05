//! `PgArticleRepo` — Diesel-async impl of `headlines_core::repo::ArticleRepo`.
//!
//! Bridges the `articles` / `articles_live` / `articles_tombstone` /
//! `article_versions` table family. Every multi-table mutation runs in a
//! transaction so the table-family invariants in `data-model.md` hold:
//!
//! - `state='live'`  → exactly one row in `articles_live`, none in `articles_tombstone`.
//! - `state='tombstone'` → exactly one row in `articles_tombstone`, none in `articles_live`.
//! - `articles_live.current_version` always names an existing
//!   `article_versions` row.
//!
//! The repo does NOT mint UUIDs (the service layer does) and does NOT
//! validate body content (the service layer does). It only persists the
//! decisions the handler hands it.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::{AsyncConnection, RunQueryDsl, scoped_futures::ScopedFutureExt};
use serde_json::Value as Json;
use uuid::Uuid;

use headlines_core::HeadlinesError;
use headlines_core::repo::PageToken;
use headlines_core::repo::articles::{
    Article, ArticleEdit, ArticleRepo, ArticleState, ArticleSummary, ListArticlesPage, NewArticle,
};

use crate::Db;
use crate::schema::{article_versions, articles, articles_live, articles_tombstone};

/// Intermediate error type used inside `AsyncConnection::transaction`
/// closures. Diesel-async requires the error type to implement
/// `From<diesel::result::Error>`; `HeadlinesError` does not (and shouldn't —
/// the central error enum stays Diesel-agnostic). This newtype bridges:
/// the closure works in `TxError`, the outer `?` converts to
/// `HeadlinesError` at the function boundary.
#[derive(Debug)]
enum TxError {
    /// A `HeadlinesError` was raised by the closure (for domain rejections
    /// like `ArticleTombstoned`, `VersionAlreadyRedacted`, etc.).
    Domain(HeadlinesError),
    /// A raw Diesel error bubbled out of a query — wrapped into
    /// `HeadlinesError::Internal` at the boundary.
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
/// into a `TxError`. Used inside `transaction` closures so the `?` operator's
/// type inference picks `TxError` (not `HeadlinesError`).
fn tx_internal(ctx: &'static str) -> impl Fn(diesel::result::Error) -> TxError {
    move |e| TxError::Domain(HeadlinesError::Internal(anyhow::anyhow!("{ctx}: {e}")))
}

/// Concrete `ArticleRepo` over the `Db` pool.
#[derive(Clone)]
pub struct PgArticleRepo {
    db: Db,
}

impl PgArticleRepo {
    pub fn new(db: Db) -> Self {
        Self { db }
    }
}

// ---------------------------------------------------------------------------
// Diesel row shapes
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = articles)]
struct ArticleRow {
    id: Uuid,
    account_id: Uuid,
    state: String,
    created_at: DateTime<Utc>,
}

#[derive(Insertable)]
#[diesel(table_name = articles)]
struct InsertArticle<'a> {
    id: Uuid,
    account_id: Uuid,
    state: &'a str,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = articles_live)]
struct ArticleLiveRow {
    #[allow(dead_code)]
    article_id: Uuid,
    current_version: i32,
    published_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Insertable)]
#[diesel(table_name = articles_live)]
struct InsertArticleLive {
    article_id: Uuid,
    current_version: i32,
    published_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = articles_tombstone)]
struct ArticleTombstoneRow {
    #[allow(dead_code)]
    article_id: Uuid,
    reason: Option<String>,
    tombstoned_at: DateTime<Utc>,
}

#[derive(Insertable)]
#[diesel(table_name = articles_tombstone)]
struct InsertArticleTombstone<'a> {
    article_id: Uuid,
    reason: Option<&'a str>,
    tombstoned_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = article_versions)]
struct ArticleVersionRow {
    #[allow(dead_code)]
    article_id: Uuid,
    version: i32,
    title: String,
    author_name: Option<String>,
    author_url: Option<String>,
    content: Option<Json>,
    redacted_at: Option<DateTime<Utc>>,
    #[allow(dead_code)]
    redaction_reason: Option<String>,
    #[allow(dead_code)]
    created_at: DateTime<Utc>,
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
// Page-token codec — keyset on (created_at, id)
// ---------------------------------------------------------------------------

// Pagination defaults pinned by `docs/design/api-conventions.md`: default 50,
// max 200, server-side clamp `[1, 200]`.
const DEFAULT_PAGE_SIZE: i32 = 50;
const MIN_PAGE_SIZE: i32 = 1;
const MAX_PAGE_SIZE: i32 = 200;

/// Resolve the request's `page_size` against the doc-pinned defaults:
///
/// - `<= 0` → `DEFAULT_PAGE_SIZE` (50)
/// - otherwise clamp into `[MIN_PAGE_SIZE, MAX_PAGE_SIZE]` (`[1, 200]`)
///
/// Mirrors the helper used by `events.rs`, `account_stream.rs`, and friends.
fn clamp_page_size(raw: i32) -> i32 {
    if raw <= 0 {
        DEFAULT_PAGE_SIZE
    } else {
        raw.clamp(MIN_PAGE_SIZE, MAX_PAGE_SIZE)
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct PageCursor {
    /// RFC3339 of the last row's `created_at`.
    c: String,
    /// Last row's id (tiebreaker).
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

// ---------------------------------------------------------------------------
// Domain assembly helpers
// ---------------------------------------------------------------------------

fn parse_state(raw: &str) -> Result<ArticleState, HeadlinesError> {
    match raw {
        "live" => Ok(ArticleState::Live),
        "tombstone" => Ok(ArticleState::Tombstone),
        other => Err(HeadlinesError::Internal(anyhow::anyhow!(
            "unknown articles.state value in DB: {other}"
        ))),
    }
}

fn version_to_summary_pieces(v: &ArticleVersionRow) -> (Option<i32>, String, String, String, bool) {
    let redacted = v.redacted_at.is_some();
    (
        Some(v.version),
        v.title.clone(),
        v.author_name.clone().unwrap_or_default(),
        v.author_url.clone().unwrap_or_default(),
        redacted,
    )
}

// ---------------------------------------------------------------------------
// ArticleRepo impl
// ---------------------------------------------------------------------------

impl ArticleRepo for PgArticleRepo {
    async fn publish(&self, new: NewArticle) -> Result<Article, HeadlinesError> {
        let mut conn = self.db.get().await.map_err(HeadlinesError::Internal)?;

        // Single tx: insert into articles, articles_live, article_versions.
        let now = Utc::now();
        let new_id = new.id;
        let new_account_id = new.account_id;
        let new_title = new.title.clone();
        let new_author_name = new.author_name.clone();
        let new_author_url = new.author_url.clone();
        let new_content = new.content.clone();

        conn.transaction::<_, TxError, _>(|conn| {
            async move {
                diesel::insert_into(articles::table)
                    .values(InsertArticle {
                        id: new_id,
                        account_id: new_account_id,
                        state: "live",
                        created_at: now,
                    })
                    .execute(conn)
                    .await
                    .map_err(tx_internal("insert articles"))?;

                diesel::insert_into(articles_live::table)
                    .values(InsertArticleLive {
                        article_id: new_id,
                        current_version: 1,
                        published_at: now,
                        updated_at: now,
                    })
                    .execute(conn)
                    .await
                    .map_err(tx_internal("insert articles_live"))?;

                let title = new_title.as_str();
                let author_name = if new_author_name.is_empty() {
                    None
                } else {
                    Some(new_author_name.as_str())
                };
                let author_url = if new_author_url.is_empty() {
                    None
                } else {
                    Some(new_author_url.as_str())
                };
                let content_ref = &new_content;
                diesel::insert_into(article_versions::table)
                    .values(InsertArticleVersion {
                        article_id: new_id,
                        version: 1,
                        title,
                        author_name,
                        author_url,
                        content: Some(content_ref),
                        created_at: now,
                    })
                    .execute(conn)
                    .await
                    .map_err(tx_internal("insert article_versions"))?;

                Ok::<(), TxError>(())
            }
            .scope_boxed()
        })
        .await?;

        // Re-read for symmetry with edit/get and so timestamps match the row.
        self.get(new_id).await
    }

    async fn get(&self, id: Uuid) -> Result<Article, HeadlinesError> {
        let mut conn = self.db.get().await.map_err(HeadlinesError::Internal)?;

        let article: Option<ArticleRow> = articles::table
            .filter(articles::id.eq(id))
            .select(ArticleRow::as_select())
            .first(&mut conn)
            .await
            .optional()
            .map_err(|e| HeadlinesError::Internal(anyhow::anyhow!("select articles: {e}")))?;
        let article = article.ok_or(HeadlinesError::ArticleNotFound { id })?;
        let state = parse_state(&article.state)?;

        match state {
            ArticleState::Live => {
                let live: ArticleLiveRow = articles_live::table
                    .filter(articles_live::article_id.eq(id))
                    .select(ArticleLiveRow::as_select())
                    .first(&mut conn)
                    .await
                    .map_err(|e| {
                        HeadlinesError::Internal(anyhow::anyhow!(
                            "select articles_live for live article: {e}"
                        ))
                    })?;

                let version: ArticleVersionRow = article_versions::table
                    .filter(article_versions::article_id.eq(id))
                    .filter(article_versions::version.eq(live.current_version))
                    .select(ArticleVersionRow::as_select())
                    .first(&mut conn)
                    .await
                    .map_err(|e| {
                        HeadlinesError::Internal(anyhow::anyhow!(
                            "select current article_versions: {e}"
                        ))
                    })?;

                let (cv, title, author_name, author_url, redacted) =
                    version_to_summary_pieces(&version);
                let summary = ArticleSummary {
                    id: article.id,
                    account_id: article.account_id,
                    state: ArticleState::Live,
                    created_at: article.created_at,
                    current_version: cv,
                    title: Some(title),
                    author_name: Some(author_name),
                    author_url: Some(author_url),
                    redacted,
                    published_at: Some(live.published_at),
                    updated_at: Some(live.updated_at),
                    tombstone_reason: None,
                    tombstoned_at: None,
                };
                Ok(Article {
                    summary,
                    content: version.content,
                })
            }
            ArticleState::Tombstone => {
                let tomb: ArticleTombstoneRow = articles_tombstone::table
                    .filter(articles_tombstone::article_id.eq(id))
                    .select(ArticleTombstoneRow::as_select())
                    .first(&mut conn)
                    .await
                    .map_err(|e| {
                        HeadlinesError::Internal(anyhow::anyhow!("select articles_tombstone: {e}"))
                    })?;
                let summary = ArticleSummary {
                    id: article.id,
                    account_id: article.account_id,
                    state: ArticleState::Tombstone,
                    created_at: article.created_at,
                    current_version: None,
                    title: None,
                    author_name: None,
                    author_url: None,
                    redacted: false,
                    published_at: None,
                    updated_at: None,
                    tombstone_reason: tomb.reason,
                    tombstoned_at: Some(tomb.tombstoned_at),
                };
                Ok(Article {
                    summary,
                    content: None,
                })
            }
        }
    }

    async fn list_by_account(
        &self,
        account_id: Uuid,
        include_tombstoned: bool,
        page_size: i32,
        page_token: PageToken,
    ) -> Result<ListArticlesPage, HeadlinesError> {
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

        // Pull `limit + 1` rows so we can decide if there's a next page.
        let mut q = articles::table
            .filter(articles::account_id.eq(account_id))
            .into_boxed();
        if !include_tombstoned {
            q = q.filter(articles::state.eq("live"));
        }
        if let (Some(c_dt), Some(c)) = (cursor_dt, cursor.as_ref()) {
            // Strict keyset on (created_at DESC, id DESC).
            q = q.filter(
                articles::created_at
                    .lt(c_dt)
                    .or(articles::created_at.eq(c_dt).and(articles::id.lt(c.i))),
            );
        }
        let rows: Vec<ArticleRow> = q
            .order((articles::created_at.desc(), articles::id.desc()))
            .limit((limit as i64) + 1)
            .select(ArticleRow::as_select())
            .load(&mut conn)
            .await
            .map_err(|e| HeadlinesError::Internal(anyhow::anyhow!("list articles: {e}")))?;

        let has_more = rows.len() as i32 > limit;
        let mut rows = rows;
        if has_more {
            rows.truncate(limit as usize);
        }

        // Hydrate each summary by joining live/tombstone + current version.
        let mut items = Vec::with_capacity(rows.len());
        for r in &rows {
            let state = parse_state(&r.state)?;
            let summary = match state {
                ArticleState::Live => {
                    let live: ArticleLiveRow = articles_live::table
                        .filter(articles_live::article_id.eq(r.id))
                        .select(ArticleLiveRow::as_select())
                        .first(&mut conn)
                        .await
                        .map_err(|e| {
                            HeadlinesError::Internal(anyhow::anyhow!(
                                "select articles_live in list: {e}"
                            ))
                        })?;
                    let version: ArticleVersionRow = article_versions::table
                        .filter(article_versions::article_id.eq(r.id))
                        .filter(article_versions::version.eq(live.current_version))
                        .select(ArticleVersionRow::as_select())
                        .first(&mut conn)
                        .await
                        .map_err(|e| {
                            HeadlinesError::Internal(anyhow::anyhow!(
                                "select article_versions in list: {e}"
                            ))
                        })?;
                    let (cv, title, an, au, redacted) = version_to_summary_pieces(&version);
                    ArticleSummary {
                        id: r.id,
                        account_id: r.account_id,
                        state: ArticleState::Live,
                        created_at: r.created_at,
                        current_version: cv,
                        title: Some(title),
                        author_name: Some(an),
                        author_url: Some(au),
                        redacted,
                        published_at: Some(live.published_at),
                        updated_at: Some(live.updated_at),
                        tombstone_reason: None,
                        tombstoned_at: None,
                    }
                }
                ArticleState::Tombstone => {
                    let tomb: ArticleTombstoneRow = articles_tombstone::table
                        .filter(articles_tombstone::article_id.eq(r.id))
                        .select(ArticleTombstoneRow::as_select())
                        .first(&mut conn)
                        .await
                        .map_err(|e| {
                            HeadlinesError::Internal(anyhow::anyhow!(
                                "select articles_tombstone in list: {e}"
                            ))
                        })?;
                    ArticleSummary {
                        id: r.id,
                        account_id: r.account_id,
                        state: ArticleState::Tombstone,
                        created_at: r.created_at,
                        current_version: None,
                        title: None,
                        author_name: None,
                        author_url: None,
                        redacted: false,
                        published_at: None,
                        updated_at: None,
                        tombstone_reason: tomb.reason,
                        tombstoned_at: Some(tomb.tombstoned_at),
                    }
                }
            };
            items.push(summary);
        }

        let next_page_token = if has_more {
            if let Some(last) = rows.last() {
                encode_cursor(&last.created_at, last.id)
            } else {
                PageToken::empty()
            }
        } else {
            PageToken::empty()
        };

        Ok(ListArticlesPage {
            items,
            next_page_token,
        })
    }

    async fn edit(&self, id: Uuid, edit: ArticleEdit) -> Result<Article, HeadlinesError> {
        let mut conn = self.db.get().await.map_err(HeadlinesError::Internal)?;
        let now = Utc::now();
        let id_for_tx = id;

        conn.transaction::<_, TxError, _>(|conn| {
            async move {
                // Lock-free SELECTs first; conflicts are rare and Postgres'
                // RC default is fine for this workload.
                let article: ArticleRow = articles::table
                    .filter(articles::id.eq(id_for_tx))
                    .select(ArticleRow::as_select())
                    .first(conn)
                    .await
                    .optional()
                    .map_err(tx_internal("select articles"))?
                    .ok_or(TxError::Domain(HeadlinesError::ArticleNotFound {
                        id: id_for_tx,
                    }))?;
                if article.state == "tombstone" {
                    return Err(TxError::Domain(HeadlinesError::ArticleTombstoned {
                        id: id_for_tx,
                    }));
                }

                let live: ArticleLiveRow = articles_live::table
                    .filter(articles_live::article_id.eq(id_for_tx))
                    .select(ArticleLiveRow::as_select())
                    .first(conn)
                    .await
                    .map_err(tx_internal("select articles_live"))?;
                let cur_version: ArticleVersionRow = article_versions::table
                    .filter(article_versions::article_id.eq(id_for_tx))
                    .filter(article_versions::version.eq(live.current_version))
                    .select(ArticleVersionRow::as_select())
                    .first(conn)
                    .await
                    .map_err(tx_internal("select current article_versions"))?;

                // Apply the edit on top of the current version. Whichever
                // fields are not in the mask carry over as-is.
                let title = edit.title.clone().unwrap_or(cur_version.title);
                let author_name = edit
                    .author_name
                    .clone()
                    .or(cur_version.author_name)
                    .unwrap_or_default();
                let author_url = edit
                    .author_url
                    .clone()
                    .or(cur_version.author_url)
                    .unwrap_or_default();
                let content = edit
                    .content
                    .clone()
                    .or(cur_version.content)
                    .unwrap_or(Json::Array(vec![]));

                let next_v = live.current_version + 1;
                let an = if author_name.is_empty() {
                    None
                } else {
                    Some(author_name.as_str())
                };
                let au = if author_url.is_empty() {
                    None
                } else {
                    Some(author_url.as_str())
                };
                diesel::insert_into(article_versions::table)
                    .values(InsertArticleVersion {
                        article_id: id_for_tx,
                        version: next_v,
                        title: title.as_str(),
                        author_name: an,
                        author_url: au,
                        content: Some(&content),
                        created_at: now,
                    })
                    .execute(conn)
                    .await
                    .map_err(tx_internal("insert next article_versions"))?;

                diesel::update(
                    articles_live::table.filter(articles_live::article_id.eq(id_for_tx)),
                )
                .set((
                    articles_live::current_version.eq(next_v),
                    articles_live::updated_at.eq(now),
                ))
                .execute(conn)
                .await
                .map_err(tx_internal("update articles_live"))?;

                Ok::<(), TxError>(())
            }
            .scope_boxed()
        })
        .await?;

        self.get(id).await
    }

    async fn tombstone(&self, id: Uuid, reason: Option<String>) -> Result<Article, HeadlinesError> {
        let mut conn = self.db.get().await.map_err(HeadlinesError::Internal)?;
        let now = Utc::now();
        let id_for_tx = id;

        conn.transaction::<_, TxError, _>(|conn| {
            let reason_owned = reason.clone();
            async move {
                let article: ArticleRow = articles::table
                    .filter(articles::id.eq(id_for_tx))
                    .select(ArticleRow::as_select())
                    .first(conn)
                    .await
                    .optional()
                    .map_err(tx_internal("select articles"))?
                    .ok_or(TxError::Domain(HeadlinesError::ArticleNotFound {
                        id: id_for_tx,
                    }))?;
                if article.state == "tombstone" {
                    return Err(TxError::Domain(HeadlinesError::ArticleTombstoned {
                        id: id_for_tx,
                    }));
                }

                diesel::update(articles::table.filter(articles::id.eq(id_for_tx)))
                    .set(articles::state.eq("tombstone"))
                    .execute(conn)
                    .await
                    .map_err(tx_internal("update articles.state"))?;

                let r_ref = reason_owned.as_deref();
                diesel::insert_into(articles_tombstone::table)
                    .values(InsertArticleTombstone {
                        article_id: id_for_tx,
                        reason: r_ref,
                        tombstoned_at: now,
                    })
                    .execute(conn)
                    .await
                    .map_err(tx_internal("insert articles_tombstone"))?;

                diesel::delete(
                    articles_live::table.filter(articles_live::article_id.eq(id_for_tx)),
                )
                .execute(conn)
                .await
                .map_err(tx_internal("delete articles_live"))?;

                Ok::<(), TxError>(())
            }
            .scope_boxed()
        })
        .await?;

        self.get(id).await
    }

    async fn redact_version(
        &self,
        article_id: Uuid,
        version: i32,
        redaction_reason: String,
    ) -> Result<(), HeadlinesError> {
        let mut conn = self.db.get().await.map_err(HeadlinesError::Internal)?;
        let now = Utc::now();
        let aid = article_id;
        let v = version;
        let reason = redaction_reason;

        conn.transaction::<_, TxError, _>(|conn| {
            async move {
                // Verify the article exists (live or tombstoned).
                let article: ArticleRow = articles::table
                    .filter(articles::id.eq(aid))
                    .select(ArticleRow::as_select())
                    .first(conn)
                    .await
                    .optional()
                    .map_err(tx_internal("select articles"))?
                    .ok_or(TxError::Domain(HeadlinesError::ArticleNotFound { id: aid }))?;

                let row: ArticleVersionRow = article_versions::table
                    .filter(article_versions::article_id.eq(aid))
                    .filter(article_versions::version.eq(v))
                    .select(ArticleVersionRow::as_select())
                    .first(conn)
                    .await
                    .optional()
                    .map_err(tx_internal("select article_versions"))?
                    .ok_or(TxError::Domain(HeadlinesError::VersionNotFound {
                        article_id: aid,
                        version: v,
                    }))?;
                if row.redacted_at.is_some() {
                    return Err(TxError::Domain(HeadlinesError::VersionAlreadyRedacted {
                        article_id: aid,
                        version: v,
                    }));
                }

                diesel::update(
                    article_versions::table
                        .filter(article_versions::article_id.eq(aid))
                        .filter(article_versions::version.eq(v)),
                )
                .set((
                    article_versions::content.eq::<Option<Json>>(None),
                    article_versions::redacted_at.eq(Some(now)),
                    article_versions::redaction_reason.eq(Some(reason.as_str())),
                ))
                .execute(conn)
                .await
                .map_err(tx_internal("redact article_versions"))?;

                // If the redacted version is the current version of a live
                // article, bump articles_live.updated_at so the watermark
                // stream surfaces the change.
                if article.state == "live" {
                    let live: ArticleLiveRow = articles_live::table
                        .filter(articles_live::article_id.eq(aid))
                        .select(ArticleLiveRow::as_select())
                        .first(conn)
                        .await
                        .map_err(tx_internal("select articles_live for redact bump"))?;
                    if live.current_version == v {
                        diesel::update(
                            articles_live::table.filter(articles_live::article_id.eq(aid)),
                        )
                        .set(articles_live::updated_at.eq(now))
                        .execute(conn)
                        .await
                        .map_err(tx_internal("bump articles_live.updated_at"))?;
                    }
                }

                Ok::<(), TxError>(())
            }
            .scope_boxed()
        })
        .await
        .map_err(HeadlinesError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `api-conventions.md` pins default 50, max 200, clamp `[1, 200]`. The
    /// repo helper must match — the rest of the workspace already follows
    /// this convention (events, account_stream, follows, …).
    #[test]
    fn list_account_articles_default_page_size_is_50() {
        // Arrange / Act / Assert
        assert_eq!(clamp_page_size(0), 50);
        assert_eq!(clamp_page_size(-1), 50);
    }

    #[test]
    fn list_account_articles_clamps_page_size_to_200() {
        // Arrange / Act / Assert
        assert_eq!(clamp_page_size(999), 200);
        assert_eq!(clamp_page_size(MAX_PAGE_SIZE), 200);
        assert_eq!(clamp_page_size(MAX_PAGE_SIZE + 1), 200);
    }

    #[test]
    fn list_account_articles_clamps_page_size_keeps_in_range_values() {
        // Arrange / Act / Assert
        assert_eq!(clamp_page_size(1), 1);
        assert_eq!(clamp_page_size(123), 123);
    }
}
