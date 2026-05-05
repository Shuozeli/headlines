//! `DraftRepo` — persistence surface for `drafts` per
//! `docs/design/drafts.md`. Drafts are mutable in place; publish is a
//! same-tx hand-off into `articles` performed atomically inside `publish`.

use std::future::Future;

use chrono::{DateTime, Utc};
use serde_json::Value as Json;
use uuid::Uuid;

use crate::repo::articles::Article;
use crate::{error::HeadlinesError, repo::PageToken};

#[derive(Debug, Clone)]
pub struct Draft {
    pub id: Uuid,
    pub account_id: Uuid,
    pub title: String,
    pub author_name: String,
    pub author_url: String,
    pub content: Json,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct DraftSummary {
    pub id: Uuid,
    pub account_id: Uuid,
    pub title: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct NewDraft {
    pub id: Uuid,
    pub account_id: Uuid,
    pub title: String,
    pub author_name: String,
    pub author_url: String,
    pub content: Json,
}

#[derive(Debug, Clone, Default)]
pub struct DraftUpdate {
    pub title: Option<String>,
    pub author_name: Option<String>,
    pub author_url: Option<String>,
    pub content: Option<Json>,
}

#[derive(Debug, Clone)]
pub struct ListDraftsPage {
    pub items: Vec<DraftSummary>,
    pub next_page_token: PageToken,
}

pub trait DraftRepo: Send + Sync {
    fn create(&self, new: NewDraft) -> impl Future<Output = Result<Draft, HeadlinesError>> + Send;

    fn get(&self, id: Uuid) -> impl Future<Output = Result<Draft, HeadlinesError>> + Send;

    fn update(
        &self,
        id: Uuid,
        update: DraftUpdate,
    ) -> impl Future<Output = Result<Draft, HeadlinesError>> + Send;

    /// Hard-delete (drafts were never public; no tombstone row).
    fn delete(&self, id: Uuid) -> impl Future<Output = Result<(), HeadlinesError>> + Send;

    /// `updated_at DESC` listing for one account.
    fn list_by_account(
        &self,
        account_id: Uuid,
        page_size: i32,
        page_token: PageToken,
    ) -> impl Future<Output = Result<ListDraftsPage, HeadlinesError>> + Send;

    /// Atomic publish: under a single transaction, take a `FOR UPDATE` lock on
    /// the draft row, hand its fields off into `articles` / `articles_live` /
    /// `article_versions` (preserving the same UUID), and `DELETE` the draft.
    /// Returns the resulting live `Article`. Concurrent calls on the same
    /// draft serialize via the row lock; the loser sees `DraftNotFound`.
    fn publish(&self, id: Uuid) -> impl Future<Output = Result<Article, HeadlinesError>> + Send;
}
