//! `AccountStreamRepo` — persistence surface for the read-only per-account
//! watermark stream per `docs/design/account-stream.md`.
//!
//! The stream is a JOIN view, not a stored table:
//!
//! ```text
//! articles ⨝ articles_live? ⨝ articles_tombstone? ⨝ article_versions?
//! ```
//!
//! `articles_live` and `articles_tombstone` are mutually exclusive — exactly
//! one is present per row. The repo emits one `AccountStreamItem` per article,
//! ordered by `event_at = COALESCE(articles_live.updated_at,
//! articles_tombstone.tombstoned_at) ASC, article.id ASC`. Drafts are never
//! present in `articles` and so never surface here.
//!
//! Compared to `feed-follow` / `feed-recommendation`, this surface emits
//! BOTH `LIVE` and `TOMBSTONE` summaries: the consumer mirrors to its target
//! platform on `LIVE` and removes on `TOMBSTONE`.

use std::future::Future;

use uuid::Uuid;

use crate::{
    error::HeadlinesError,
    repo::{PageToken, articles::ArticleSummary},
};

/// One stream entry — wraps an `ArticleSummary` whose `state` discriminator
/// signals LIVE vs TOMBSTONE for the republisher.
#[derive(Debug, Clone)]
pub struct AccountStreamItem {
    pub article: ArticleSummary,
}

#[derive(Debug, Clone)]
pub struct AccountStreamPage {
    pub items: Vec<AccountStreamItem>,
    pub next_page_token: PageToken,
}

pub trait AccountStreamRepo: Send + Sync {
    /// Joined read against `articles` LEFT JOIN `articles_live` LEFT JOIN
    /// `articles_tombstone` LEFT JOIN `article_versions` (current). Filters
    /// to one account; orders by `(event_at, id)` ASC; uses keyset
    /// pagination on the same composite key. Drafts (absent from `articles`)
    /// never appear.
    fn stream(
        &self,
        account_id: Uuid,
        page_size: i32,
        page_token: PageToken,
    ) -> impl Future<Output = Result<AccountStreamPage, HeadlinesError>> + Send;
}
