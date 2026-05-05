//! `PgFeedRecommendationRepo` — Diesel-async impl of
//! `headlines_core::repo::FeedRecommendationRepo`.
//!
//! Per `docs/design/feed-recommendation.md`:
//!
//! - `replace`: single tx — DELETE existing rows for the user, then INSERT
//!   the new ordered list (position = index). Empty input clears the feed
//!   and is a successful no-op. Article ids are stored as soft references
//!   (no FK enforcement).
//! - `get`: INNER JOIN against `articles_live` + `article_versions` so
//!   tombstones and missing-article-id rows are dropped automatically by
//!   the join. Pagination keys off `position ASC` with an opaque base64
//!   cursor — AIP-158 semantics: server may return fewer than `page_size`.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel::sql_types::{Int4, Uuid as SqlUuid};
use diesel_async::{AsyncConnection, RunQueryDsl, scoped_futures::ScopedFutureExt};
use uuid::Uuid;

use headlines_core::HeadlinesError;
use headlines_core::repo::PageToken;
use headlines_core::repo::articles::{ArticleState, ArticleSummary};
use headlines_core::repo::feed_recommendation::{FeedItem, FeedPage, FeedRecommendationRepo};

use crate::Db;
use crate::schema::feed_recommendation;

/// Concrete `FeedRecommendationRepo` over the `Db` pool.
#[derive(Clone)]
pub struct PgFeedRecommendationRepo {
    db: Db,
}

impl PgFeedRecommendationRepo {
    pub fn new(db: Db) -> Self {
        Self { db }
    }
}

// ---------------------------------------------------------------------------
// Tx error bridge (mirrors PgArticleRepo).
// ---------------------------------------------------------------------------

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

impl From<TxError> for HeadlinesError {
    fn from(e: TxError) -> Self {
        match e {
            TxError::Domain(d) => d,
            TxError::Diesel(e) => HeadlinesError::Internal(anyhow::anyhow!("tx: {e}")),
        }
    }
}

fn tx_internal(ctx: &'static str) -> impl Fn(diesel::result::Error) -> TxError {
    move |e| TxError::Domain(HeadlinesError::Internal(anyhow::anyhow!("{ctx}: {e}")))
}

// ---------------------------------------------------------------------------
// Page token codec (position-only).
// ---------------------------------------------------------------------------

const DEFAULT_PAGE_SIZE: i32 = 50;
const MIN_PAGE_SIZE: i32 = 1;
const MAX_PAGE_SIZE: i32 = 200;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct PageCursor {
    /// Last position returned in the previous page.
    p: i32,
}

fn encode_cursor(position: i32) -> PageToken {
    let cursor = PageCursor { p: position };
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
// Joined row type returned by the GET join.
// ---------------------------------------------------------------------------

#[derive(Debug, Queryable, QueryableByName)]
struct JoinedFeedRow {
    #[diesel(sql_type = Int4)]
    position: i32,
    #[diesel(sql_type = SqlUuid)]
    article_id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    account_id: Uuid,
    #[diesel(sql_type = diesel::sql_types::Text)]
    state: String,
    #[diesel(sql_type = diesel::sql_types::Timestamptz)]
    article_created_at: DateTime<Utc>,
    #[diesel(sql_type = Int4)]
    current_version: i32,
    #[diesel(sql_type = diesel::sql_types::Timestamptz)]
    published_at: DateTime<Utc>,
    #[diesel(sql_type = diesel::sql_types::Timestamptz)]
    updated_at: DateTime<Utc>,
    #[diesel(sql_type = diesel::sql_types::Text)]
    title: String,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    author_name: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    author_url: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Bool)]
    redacted: bool,
}

fn parse_state(raw: &str) -> Result<ArticleState, HeadlinesError> {
    match raw {
        "live" => Ok(ArticleState::Live),
        "tombstone" => Ok(ArticleState::Tombstone),
        other => Err(HeadlinesError::Internal(anyhow::anyhow!(
            "unknown articles.state value in DB: {other}"
        ))),
    }
}

fn row_to_feed_item(r: JoinedFeedRow) -> Result<FeedItem, HeadlinesError> {
    // The inner join against `articles_live` only returns live articles, but
    // be defensive: any unexpected state surfaces as Internal.
    let state = parse_state(&r.state)?;
    let summary = ArticleSummary {
        id: r.article_id,
        account_id: r.account_id,
        state,
        created_at: r.article_created_at,
        current_version: Some(r.current_version),
        title: Some(r.title),
        author_name: Some(r.author_name.unwrap_or_default()),
        author_url: Some(r.author_url.unwrap_or_default()),
        redacted: r.redacted,
        published_at: Some(r.published_at),
        updated_at: Some(r.updated_at),
        tombstone_reason: None,
        tombstoned_at: None,
    };
    Ok(FeedItem {
        position: r.position,
        article: summary,
    })
}

// ---------------------------------------------------------------------------
// FeedRecommendationRepo impl
// ---------------------------------------------------------------------------

impl FeedRecommendationRepo for PgFeedRecommendationRepo {
    async fn replace(&self, user_id: Uuid, article_ids: Vec<Uuid>) -> Result<i32, HeadlinesError> {
        let mut conn = self.db.get().await.map_err(HeadlinesError::Internal)?;
        let n: i32 = article_ids.len() as i32;

        conn.transaction::<_, TxError, _>(|conn| {
            let ids = article_ids.clone();
            async move {
                diesel::delete(
                    feed_recommendation::table.filter(feed_recommendation::user_id.eq(user_id)),
                )
                .execute(conn)
                .await
                .map_err(tx_internal("delete feed_recommendation"))?;

                if !ids.is_empty() {
                    let rows: Vec<NewFeedRow> = ids
                        .into_iter()
                        .enumerate()
                        .map(|(idx, article_id)| NewFeedRow {
                            user_id,
                            position: idx as i32,
                            article_id,
                        })
                        .collect();

                    diesel::insert_into(feed_recommendation::table)
                        .values(&rows)
                        .execute(conn)
                        .await
                        .map_err(tx_internal("insert feed_recommendation"))?;
                }

                Ok::<(), TxError>(())
            }
            .scope_boxed()
        })
        .await?;

        Ok(n)
    }

    async fn get(
        &self,
        user_id: Uuid,
        page_size: i32,
        page_token: PageToken,
    ) -> Result<FeedPage, HeadlinesError> {
        let limit = clamp_page_size(page_size);
        let cursor_pos = if page_token.is_empty() {
            None
        } else {
            Some(decode_cursor(page_token.as_str())?.p)
        };

        let mut conn = self.db.get().await.map_err(HeadlinesError::Internal)?;

        // Inner join: articles_live drops tombstones and missing rows; the
        // JOIN to article_versions hydrates the summary. We explicitly select
        // the columns and bind types via the `JoinedFeedRow` shape.
        //
        // Strict-greater-than on cursor position so the same row isn't
        // returned twice.
        let cursor_clause = match cursor_pos {
            Some(_) => "AND r.position > $4",
            None => "",
        };
        let sql = format!(
            "SELECT r.position AS position, \
                    r.article_id AS article_id, \
                    a.account_id AS account_id, \
                    a.state AS state, \
                    a.created_at AS article_created_at, \
                    l.current_version AS current_version, \
                    l.published_at AS published_at, \
                    l.updated_at AS updated_at, \
                    v.title AS title, \
                    v.author_name AS author_name, \
                    v.author_url AS author_url, \
                    (v.content IS NULL) AS redacted \
             FROM feed_recommendation r \
             INNER JOIN articles a ON a.id = r.article_id \
             INNER JOIN articles_live l ON l.article_id = r.article_id \
             INNER JOIN article_versions v \
                ON v.article_id = a.id AND v.version = l.current_version \
             WHERE r.user_id = $1 \
               AND a.state = $2 \
               {cursor_clause} \
             ORDER BY r.position ASC \
             LIMIT $3"
        );

        // Pull `limit + 1` rows so we can decide if there's a next page.
        let plus_one: i64 = (limit as i64) + 1;
        let rows: Vec<JoinedFeedRow> = match cursor_pos {
            Some(p) => diesel::sql_query(&sql)
                .bind::<SqlUuid, _>(user_id)
                .bind::<diesel::sql_types::Text, _>("live")
                .bind::<diesel::sql_types::BigInt, _>(plus_one)
                .bind::<Int4, _>(p)
                .load(&mut conn)
                .await
                .map_err(|e| {
                    HeadlinesError::Internal(anyhow::anyhow!("get feed_recommendation: {e}"))
                })?,
            None => diesel::sql_query(&sql)
                .bind::<SqlUuid, _>(user_id)
                .bind::<diesel::sql_types::Text, _>("live")
                .bind::<diesel::sql_types::BigInt, _>(plus_one)
                .load(&mut conn)
                .await
                .map_err(|e| {
                    HeadlinesError::Internal(anyhow::anyhow!("get feed_recommendation: {e}"))
                })?,
        };

        let mut rows = rows;
        let has_more = rows.len() as i32 > limit;
        if has_more {
            rows.truncate(limit as usize);
        }

        let last_position = rows.last().map(|r| r.position);
        let mut items = Vec::with_capacity(rows.len());
        for r in rows {
            items.push(row_to_feed_item(r)?);
        }

        let next_page_token = if has_more {
            match last_position {
                Some(p) => encode_cursor(p),
                None => PageToken::empty(),
            }
        } else {
            PageToken::empty()
        };

        Ok(FeedPage {
            items,
            next_page_token,
        })
    }
}

// ---------------------------------------------------------------------------
// Insertable shape for replace().
// ---------------------------------------------------------------------------

#[derive(Insertable)]
#[diesel(table_name = feed_recommendation)]
struct NewFeedRow {
    user_id: Uuid,
    position: i32,
    article_id: Uuid,
}
