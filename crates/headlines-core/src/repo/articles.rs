//! `ArticleRepo` — persistence surface for `articles` + `articles_live` +
//! `articles_tombstone` + `article_versions`. Mirrors `docs/design/articles.md`.

use std::future::Future;

use chrono::{DateTime, Utc};
use serde_json::Value as Json;
use uuid::Uuid;

use crate::{error::HeadlinesError, repo::PageToken};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArticleState {
    Live,
    Tombstone,
}

/// Compact view returned by list endpoints. No content nodes.
#[derive(Debug, Clone)]
pub struct ArticleSummary {
    pub id: Uuid,
    pub account_id: Uuid,
    pub state: ArticleState,
    pub created_at: DateTime<Utc>,
    pub current_version: Option<i32>, // None when tombstone
    pub title: Option<String>,
    pub author_name: Option<String>,
    pub author_url: Option<String>,
    pub redacted: bool,
    pub published_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
    pub tombstone_reason: Option<String>,
    pub tombstoned_at: Option<DateTime<Utc>>,
}

/// Full `Article` view (with content). Content is JSON because the Telegraph
/// `Node` tree is stored as `jsonb`.
#[derive(Debug, Clone)]
pub struct Article {
    pub summary: ArticleSummary,
    pub content: Option<Json>,
}

/// Insert payload for direct publish (`PublishArticle`) and the publish-side
/// of `PublishDraft`. The `id` is server-minted by the service layer (or
/// reused from the draft id).
#[derive(Debug, Clone)]
pub struct NewArticle {
    pub id: Uuid,
    pub account_id: Uuid,
    pub title: String,
    pub author_name: String,
    pub author_url: String,
    pub content: Json,
}

/// Mutable fields for `EditArticle`. Field-mask whitelist enforcement is the
/// service layer's job.
#[derive(Debug, Clone, Default)]
pub struct ArticleEdit {
    pub title: Option<String>,
    pub author_name: Option<String>,
    pub author_url: Option<String>,
    pub content: Option<Json>,
}

/// Paged result for list endpoints. `next_page_token.is_empty()` signals
/// end-of-stream (per `api-conventions.md`).
#[derive(Debug, Clone)]
pub struct ListArticlesPage {
    pub items: Vec<ArticleSummary>,
    pub next_page_token: PageToken,
}

pub trait ArticleRepo: Send + Sync {
    /// Single-tx publish: inserts `articles`, `articles_live`,
    /// `article_versions` (version=1). Returns the resulting `Article` with
    /// `state=Live`.
    fn publish(
        &self,
        new: NewArticle,
    ) -> impl Future<Output = Result<Article, HeadlinesError>> + Send;

    /// Read by id. Returns `Live` or `Tombstone` view.
    fn get(&self, id: Uuid) -> impl Future<Output = Result<Article, HeadlinesError>> + Send;

    /// `created_at DESC` listing for one account. `include_tombstoned`
    /// controls whether tombstone rows are returned.
    fn list_by_account(
        &self,
        account_id: Uuid,
        include_tombstoned: bool,
        page_size: i32,
        page_token: PageToken,
    ) -> impl Future<Output = Result<ListArticlesPage, HeadlinesError>> + Send;

    /// Single-tx edit: insert next `article_versions` row, bump
    /// `articles_live.current_version` and `updated_at`. Rejects with
    /// `ArticleTombstoned` if the article is already tombstoned.
    fn edit(
        &self,
        id: Uuid,
        edit: ArticleEdit,
    ) -> impl Future<Output = Result<Article, HeadlinesError>> + Send;

    /// One-way tombstone. Single-tx: flip state, insert
    /// `articles_tombstone`, delete `articles_live`. `article_versions`
    /// retained.
    fn tombstone(
        &self,
        id: Uuid,
        reason: Option<String>,
    ) -> impl Future<Output = Result<Article, HeadlinesError>> + Send;

    /// Compliance redaction for a single version. Sets
    /// `article_versions.content = NULL`, records `redacted_at` +
    /// `redaction_reason`. If the redacted version equals
    /// `articles_live.current_version`, also bumps
    /// `articles_live.updated_at` so the change surfaces in the per-account
    /// stream.
    fn redact_version(
        &self,
        article_id: Uuid,
        version: i32,
        redaction_reason: String,
    ) -> impl Future<Output = Result<(), HeadlinesError>> + Send;
}
