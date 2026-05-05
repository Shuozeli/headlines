//! `FeedFollowRepo` — persistence surface for the read-only follow-derived
//! feed per `docs/design/feed-follow.md`.
//!
//! The follow feed is a JOIN view, not a stored table:
//!
//! ```text
//! follows ⨝ articles ⨝ articles_live ⨝ article_versions
//! ```
//!
//! Tombstoned articles, missing articles, and unfollowed edges are dropped by
//! the JOIN itself. Articles from deleted accounts are included. There is no
//! "since I followed" cutoff — `follows.created_at` does not affect the query.
//! Ordering and keyset pagination are over `(articles.created_at, articles.id)
//! DESC`.

use std::future::Future;

use uuid::Uuid;

use crate::{
    error::HeadlinesError,
    repo::{PageToken, articles::ArticleSummary},
};

/// One follow-feed entry. Distinct from `FeedItem` — no `position` field per
/// `feed-follow.md` Q1; ordering is data-driven by `article.created_at`.
#[derive(Debug, Clone)]
pub struct FollowFeedItem {
    pub article: ArticleSummary,
}

#[derive(Debug, Clone)]
pub struct FollowFeedPage {
    pub items: Vec<FollowFeedItem>,
    pub next_page_token: PageToken,
}

pub trait FeedFollowRepo: Send + Sync {
    /// Joined read against `follows` ⨝ `articles` ⨝ `articles_live` ⨝
    /// `article_versions`. Tombstoned, missing, and unfollowed-edge rows are
    /// dropped by the JOIN. Articles from deleted accounts are included
    /// (per `feed-follow.md`). Keyset cursor on `(created_at, id)`.
    fn get(
        &self,
        user_id: Uuid,
        page_size: i32,
        page_token: PageToken,
    ) -> impl Future<Output = Result<FollowFeedPage, HeadlinesError>> + Send;
}
