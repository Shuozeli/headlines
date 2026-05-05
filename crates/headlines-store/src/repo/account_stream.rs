//! `PgAccountStreamRepo` — Diesel-async impl of
//! `headlines_core::repo::AccountStreamRepo`.
//!
//! Per `docs/design/account-stream.md`: a single LEFT-JOIN read against
//! `articles ⨝ articles_live? ⨝ articles_tombstone? ⨝ article_versions?`,
//! ordered by `event_at = COALESCE(articles_live.updated_at,
//! articles_tombstone.tombstoned_at) ASC, article.id ASC` with a keyset
//! cursor on `(event_at, article_id)`.
//!
//! As in `feed_follow.rs` / `feed_recommendation.rs`, we reach for
//! `diesel::sql_query` because the four-way JOIN (with a composite-PK
//! `article_versions` table on `(article_id, version)` and the LIVE/TOMBSTONE
//! split) is not comfortable to express in Diesel's typed DSL. The
//! `AccountStreamRow` `QueryableByName` shape enumerates the result columns
//! explicitly. `version`-keyed nullable text columns mean LIVE rows hydrate
//! `current_version` / `published_at` / `updated_at` / `title` etc. and
//! TOMBSTONE rows hydrate `tombstone_reason` / `tombstoned_at` (everything
//! else null).
//!
//! Filter rules — all enforced by the JOIN, not application code:
//!
//! - Drafts → never present in `articles`, so always dropped.
//! - LIVE → emits `ArticleSummary { state: Live, .. }` with `redacted` from
//!   `(v.content IS NULL)`.
//! - TOMBSTONE → emits `ArticleSummary { state: Tombstone, .. }` with the
//!   tombstone metadata.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use chrono::{DateTime, Utc};
use diesel::sql_types::{Int4, Uuid as SqlUuid};
use diesel_async::RunQueryDsl;
use uuid::Uuid;

use headlines_core::HeadlinesError;
use headlines_core::repo::PageToken;
use headlines_core::repo::account_stream::{
    AccountStreamItem, AccountStreamPage, AccountStreamRepo,
};
use headlines_core::repo::articles::{ArticleState, ArticleSummary};

use crate::Db;

/// Concrete `AccountStreamRepo` over the `Db` pool.
#[derive(Clone)]
pub struct PgAccountStreamRepo {
    db: Db,
}

impl PgAccountStreamRepo {
    pub fn new(db: Db) -> Self {
        Self { db }
    }
}

// ---------------------------------------------------------------------------
// Page token codec — keyset on (event_at, article_id) ASC.
// ---------------------------------------------------------------------------

const DEFAULT_PAGE_SIZE: i32 = 50;
const MIN_PAGE_SIZE: i32 = 1;
const MAX_PAGE_SIZE: i32 = 200;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct PageCursor {
    /// RFC3339 of the last row's `event_at`.
    e: String,
    /// Last row's `article.id`.
    i: Uuid,
}

fn encode_cursor(event_at: &DateTime<Utc>, id: Uuid) -> PageToken {
    let cursor = PageCursor {
        e: event_at.to_rfc3339(),
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
// Joined row type returned by the stream JOIN.
// ---------------------------------------------------------------------------

#[derive(Debug, diesel::QueryableByName)]
struct AccountStreamRow {
    #[diesel(sql_type = SqlUuid)]
    article_id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    account_id: Uuid,
    #[diesel(sql_type = diesel::sql_types::Text)]
    state: String,
    #[diesel(sql_type = diesel::sql_types::Timestamptz)]
    article_created_at: DateTime<Utc>,
    #[diesel(sql_type = diesel::sql_types::Timestamptz)]
    event_at: DateTime<Utc>,
    // Live-side columns (null on TOMBSTONE rows).
    #[diesel(sql_type = diesel::sql_types::Nullable<Int4>)]
    current_version: Option<i32>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
    published_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
    updated_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    title: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    author_name: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    author_url: Option<String>,
    /// `(v.content IS NULL)` — null on TOMBSTONE (no version row joined).
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Bool>)]
    redacted: Option<bool>,
    // Tombstone-side columns (null on LIVE rows).
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    tombstone_reason: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
    tombstoned_at: Option<DateTime<Utc>>,
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

fn row_to_item(r: AccountStreamRow) -> Result<AccountStreamItem, HeadlinesError> {
    let state = parse_state(&r.state)?;
    let summary = match state {
        ArticleState::Live => ArticleSummary {
            id: r.article_id,
            account_id: r.account_id,
            state,
            created_at: r.article_created_at,
            current_version: r.current_version,
            title: r.title,
            author_name: Some(r.author_name.unwrap_or_default()),
            author_url: Some(r.author_url.unwrap_or_default()),
            redacted: r.redacted.unwrap_or(false),
            published_at: r.published_at,
            updated_at: r.updated_at,
            tombstone_reason: None,
            tombstoned_at: None,
        },
        ArticleState::Tombstone => ArticleSummary {
            id: r.article_id,
            account_id: r.account_id,
            state,
            created_at: r.article_created_at,
            current_version: None,
            title: None,
            author_name: None,
            author_url: None,
            redacted: false,
            published_at: None,
            updated_at: None,
            tombstone_reason: r.tombstone_reason,
            tombstoned_at: r.tombstoned_at,
        },
    };
    Ok(AccountStreamItem { article: summary })
}

// ---------------------------------------------------------------------------
// AccountStreamRepo impl
// ---------------------------------------------------------------------------

impl AccountStreamRepo for PgAccountStreamRepo {
    async fn stream(
        &self,
        account_id: Uuid,
        page_size: i32,
        page_token: PageToken,
    ) -> Result<AccountStreamPage, HeadlinesError> {
        let limit = clamp_page_size(page_size);

        let cursor = if page_token.is_empty() {
            None
        } else {
            let pc = decode_cursor(page_token.as_str())?;
            let dt = DateTime::parse_from_rfc3339(&pc.e)
                .map_err(|e| HeadlinesError::InvalidCursor {
                    reason: format!("rfc3339: {e}"),
                })?
                .with_timezone(&Utc);
            Some((dt, pc.i))
        };

        let mut conn = self.db.get().await.map_err(HeadlinesError::Internal)?;

        // Strict-greater-than on `(event_at, article_id)` ASC keyset so the
        // same row isn't returned twice across page boundaries.
        let cursor_clause = match cursor {
            Some(_) => "AND (COALESCE(l.updated_at, t.tombstoned_at), a.id) > ($3, $4)",
            None => "",
        };

        let sql = format!(
            "SELECT a.id AS article_id, \
                    a.account_id AS account_id, \
                    a.state AS state, \
                    a.created_at AS article_created_at, \
                    COALESCE(l.updated_at, t.tombstoned_at) AS event_at, \
                    l.current_version AS current_version, \
                    l.published_at AS published_at, \
                    l.updated_at AS updated_at, \
                    v.title AS title, \
                    v.author_name AS author_name, \
                    v.author_url AS author_url, \
                    (v.content IS NULL) AS redacted, \
                    t.reason AS tombstone_reason, \
                    t.tombstoned_at AS tombstoned_at \
             FROM articles a \
             LEFT JOIN articles_live l ON l.article_id = a.id \
             LEFT JOIN articles_tombstone t ON t.article_id = a.id \
             LEFT JOIN article_versions v \
                ON v.article_id = a.id AND v.version = l.current_version \
             WHERE a.account_id = $1 \
               {cursor_clause} \
             ORDER BY event_at ASC, a.id ASC \
             LIMIT $2"
        );

        // Pull `limit + 1` rows so we can decide if there's a next page.
        let plus_one: i64 = (limit as i64) + 1;
        let rows: Vec<AccountStreamRow> = match cursor {
            Some((dt, id)) => diesel::sql_query(&sql)
                .bind::<SqlUuid, _>(account_id)
                .bind::<diesel::sql_types::BigInt, _>(plus_one)
                .bind::<diesel::sql_types::Timestamptz, _>(dt)
                .bind::<SqlUuid, _>(id)
                .load(&mut conn)
                .await
                .map_err(|e| {
                    HeadlinesError::Internal(anyhow::anyhow!("stream account_stream: {e}"))
                })?,
            None => diesel::sql_query(&sql)
                .bind::<SqlUuid, _>(account_id)
                .bind::<diesel::sql_types::BigInt, _>(plus_one)
                .load(&mut conn)
                .await
                .map_err(|e| {
                    HeadlinesError::Internal(anyhow::anyhow!("stream account_stream: {e}"))
                })?,
        };

        let mut rows = rows;
        let has_more = rows.len() as i32 > limit;
        if has_more {
            rows.truncate(limit as usize);
        }

        let last_keyset = rows.last().map(|r| (r.event_at, r.article_id));
        let mut items = Vec::with_capacity(rows.len());
        for r in rows {
            items.push(row_to_item(r)?);
        }

        let next_page_token = if has_more {
            match last_keyset {
                Some((e, id)) => encode_cursor(&e, id),
                None => PageToken::empty(),
            }
        } else {
            PageToken::empty()
        };

        Ok(AccountStreamPage {
            items,
            next_page_token,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_round_trips_through_base64_json() {
        // Arrange
        let now = Utc::now();
        let id = Uuid::now_v7();

        // Act
        let token = encode_cursor(&now, id);
        let decoded = decode_cursor(token.as_str()).unwrap();

        // Assert
        assert_eq!(decoded.i, id);
        // RFC3339 round-trip preserves timestamp.
        let parsed = DateTime::parse_from_rfc3339(&decoded.e)
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(parsed.timestamp(), now.timestamp());
    }

    #[test]
    fn decode_cursor_rejects_non_base64() {
        // Arrange
        let raw = "not!base64";

        // Act
        let res = decode_cursor(raw);

        // Assert
        assert!(matches!(res, Err(HeadlinesError::InvalidCursor { .. })));
    }

    #[test]
    fn decode_cursor_rejects_non_json_payload() {
        // Arrange — valid base64 but not the expected JSON shape.
        let raw = B64URL.encode(b"hello world");

        // Act
        let res = decode_cursor(&raw);

        // Assert
        assert!(matches!(res, Err(HeadlinesError::InvalidCursor { .. })));
    }

    #[test]
    fn clamp_page_size_clamps_into_range() {
        // Arrange / Act / Assert
        assert_eq!(clamp_page_size(0), DEFAULT_PAGE_SIZE);
        assert_eq!(clamp_page_size(-1), DEFAULT_PAGE_SIZE);
        assert_eq!(clamp_page_size(1), 1);
        assert_eq!(clamp_page_size(MAX_PAGE_SIZE), MAX_PAGE_SIZE);
        assert_eq!(clamp_page_size(MAX_PAGE_SIZE + 1), MAX_PAGE_SIZE);
    }

    #[test]
    fn parse_state_recognizes_live_and_tombstone() {
        // Arrange / Act / Assert
        assert_eq!(parse_state("live").unwrap(), ArticleState::Live);
        assert_eq!(parse_state("tombstone").unwrap(), ArticleState::Tombstone);
        assert!(parse_state("draft").is_err());
    }
}
