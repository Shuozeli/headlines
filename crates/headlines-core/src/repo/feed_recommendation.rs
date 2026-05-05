//! `FeedRecommendationRepo` — persistence surface for `feed_recommendation`
//! per `docs/design/feed-recommendation.md`. Reads return the joined
//! `(position, ArticleSummary)` view; writes are atomic-replace per user.

use std::future::Future;

use uuid::Uuid;

use crate::{
    error::HeadlinesError,
    repo::{PageToken, articles::ArticleSummary},
};

/// One feed entry with its precomputed position.
#[derive(Debug, Clone)]
pub struct FeedItem {
    pub position: i32,
    pub article: ArticleSummary,
}

#[derive(Debug, Clone)]
pub struct FeedPage {
    pub items: Vec<FeedItem>,
    pub next_page_token: PageToken,
}

pub trait FeedRecommendationRepo: Send + Sync {
    /// Atomic replace: delete all rows for `user_id`, insert the supplied
    /// ordered list (`position` = index). Returns the count actually
    /// inserted (== `article_ids.len()`).
    ///
    /// Caller has already validated dedup + size cap. Repo trusts the input.
    fn replace(
        &self,
        user_id: Uuid,
        article_ids: Vec<Uuid>,
    ) -> impl Future<Output = Result<i32, HeadlinesError>> + Send;

    /// Joined read against `articles_live` + `article_versions`. Tombstoned
    /// and missing articles are dropped by the inner join.
    fn get(
        &self,
        user_id: Uuid,
        page_size: i32,
        page_token: PageToken,
    ) -> impl Future<Output = Result<FeedPage, HeadlinesError>> + Send;
}
