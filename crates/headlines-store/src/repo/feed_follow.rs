//! `PgFeedFollowRepo` — Diesel-async impl of
//! `headlines_core::repo::FeedFollowRepo`.
//!
//! Per `docs/design/feed-follow.md`: a single JOIN read across
//! `follows ⨝ articles ⨝ articles_live ⨝ article_versions`, ordered by
//! `articles.created_at DESC, articles.id DESC` with a keyset cursor on
//! `(created_at, id)`.
//!
//! As in `feed_recommendation.rs`, we reach for `diesel::sql_query` because
//! the four-way JOIN with the composite-PK `article_versions` table is not
//! comfortable to express in Diesel's typed DSL. The `JoinedFeedRow`
//! `QueryableByName` shape enumerates the result columns explicitly.
//!
//! Filter rules — all enforced by the JOIN, not application code:
//!
//! - Tombstoned articles → dropped (not in `articles_live`).
//! - Missing articles → dropped (no row in `articles`).
//! - Unfollowed edges → dropped (`f.status = 'active'`).
//! - Articles from deleted accounts → included (per `feed-follow.md`).
//! - Redacted current versions → surface with `redacted=true`.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use chrono::{DateTime, Utc};
use diesel::sql_types::{Int4, Uuid as SqlUuid};
use diesel_async::RunQueryDsl;
use uuid::Uuid;

use headlines_core::HeadlinesError;
use headlines_core::repo::PageToken;
use headlines_core::repo::articles::{ArticleState, ArticleSummary};
use headlines_core::repo::feed_follow::{FeedFollowRepo, FollowFeedItem, FollowFeedPage};

use crate::Db;

/// Concrete `FeedFollowRepo` over the `Db` pool.
#[derive(Clone)]
pub struct PgFeedFollowRepo {
    db: Db,
}

impl PgFeedFollowRepo {
    pub fn new(db: Db) -> Self {
        Self { db }
    }
}

// ---------------------------------------------------------------------------
// Page token codec — keyset on (article.created_at, article.id)
// ---------------------------------------------------------------------------

const DEFAULT_PAGE_SIZE: i32 = 50;
const MIN_PAGE_SIZE: i32 = 1;
const MAX_PAGE_SIZE: i32 = 200;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct PageCursor {
    /// RFC3339 of the last row's `articles.created_at`.
    c: String,
    /// Last row's `articles.id`.
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
// Joined row type returned by the GET join.
// ---------------------------------------------------------------------------

#[derive(Debug, diesel::QueryableByName)]
struct JoinedFeedRow {
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

fn row_to_follow_feed_item(r: JoinedFeedRow) -> Result<FollowFeedItem, HeadlinesError> {
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
    Ok(FollowFeedItem { article: summary })
}

// ---------------------------------------------------------------------------
// FeedFollowRepo impl
// ---------------------------------------------------------------------------

impl FeedFollowRepo for PgFeedFollowRepo {
    async fn get(
        &self,
        user_id: Uuid,
        page_size: i32,
        page_token: PageToken,
    ) -> Result<FollowFeedPage, HeadlinesError> {
        let limit = clamp_page_size(page_size);

        let cursor = if page_token.is_empty() {
            None
        } else {
            let pc = decode_cursor(page_token.as_str())?;
            let dt = DateTime::parse_from_rfc3339(&pc.c)
                .map_err(|e| HeadlinesError::InvalidCursor {
                    reason: format!("rfc3339: {e}"),
                })?
                .with_timezone(&Utc);
            Some((dt, pc.i))
        };

        let mut conn = self.db.get().await.map_err(HeadlinesError::Internal)?;

        // Strict-less-than on `(created_at, id)` so the same row isn't
        // returned twice across page boundaries.
        let cursor_clause = match cursor {
            Some(_) => "AND (a.created_at, a.id) < ($3, $4)",
            None => "",
        };

        let sql = format!(
            "SELECT a.id AS article_id, \
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
             FROM follows f \
             INNER JOIN articles a ON a.account_id = f.account_id \
             INNER JOIN articles_live l ON l.article_id = a.id \
             INNER JOIN article_versions v \
                ON v.article_id = a.id AND v.version = l.current_version \
             WHERE f.user_id = $1 \
               AND f.status = 'active' \
               {cursor_clause} \
             ORDER BY a.created_at DESC, a.id DESC \
             LIMIT $2"
        );

        // Pull `limit + 1` rows so we can decide if there's a next page.
        let plus_one: i64 = (limit as i64) + 1;
        let rows: Vec<JoinedFeedRow> = match cursor {
            Some((dt, id)) => diesel::sql_query(&sql)
                .bind::<SqlUuid, _>(user_id)
                .bind::<diesel::sql_types::BigInt, _>(plus_one)
                .bind::<diesel::sql_types::Timestamptz, _>(dt)
                .bind::<SqlUuid, _>(id)
                .load(&mut conn)
                .await
                .map_err(|e| HeadlinesError::Internal(anyhow::anyhow!("get feed_follow: {e}")))?,
            None => diesel::sql_query(&sql)
                .bind::<SqlUuid, _>(user_id)
                .bind::<diesel::sql_types::BigInt, _>(plus_one)
                .load(&mut conn)
                .await
                .map_err(|e| HeadlinesError::Internal(anyhow::anyhow!("get feed_follow: {e}")))?,
        };

        let mut rows = rows;
        let has_more = rows.len() as i32 > limit;
        if has_more {
            rows.truncate(limit as usize);
        }

        let last_keyset = rows.last().map(|r| (r.article_created_at, r.article_id));
        let mut items = Vec::with_capacity(rows.len());
        for r in rows {
            items.push(row_to_follow_feed_item(r)?);
        }

        let next_page_token = if has_more {
            match last_keyset {
                Some((c, id)) => encode_cursor(&c, id),
                None => PageToken::empty(),
            }
        } else {
            PageToken::empty()
        };

        Ok(FollowFeedPage {
            items,
            next_page_token,
        })
    }
}
