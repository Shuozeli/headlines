//! `AccountStreamServiceImpl` — gRPC handler for
//! `headlines.v1.AccountStreamService`.
//!
//! Authoritative spec: `docs/design/account-stream.md`.
//!
//! The proto-driven `AUTH_TABLE` enforces the **subject class** + **system
//! scope** gate before this handler runs:
//!   - `StreamAccountArticles`: `[SYSTEM]` + `articles.stream`.
//!
//! The handler enforces:
//!   - well-formed `account_id`,
//!   - the account exists (`ACCOUNT_NOT_FOUND` otherwise),
//!   - the account is not deleted (`ACCOUNT_DELETED` otherwise — the stream
//!     **closes** on deletion; republishers must remove all content),
//!   - cursor decoding is left to the repo, which surfaces `INVALID_CURSOR`.
//!
//! Read-only surface — no write-side companion. The stream is computed at
//! read time by the repo's LEFT-JOIN.

use std::sync::Arc;

use async_trait::async_trait;
use prost_types::Timestamp;
use tonic::{Request, Response, Status};
use uuid::Uuid;

use headlines_core::HeadlinesError;
use headlines_core::Subject;
use headlines_core::repo::PageToken;
use headlines_core::repo::account_stream::{
    AccountStreamItem as DomainAccountStreamItem, AccountStreamRepo,
};
use headlines_core::repo::accounts::{AccountRepo, AccountStatus};
use headlines_core::repo::articles::{ArticleState, ArticleSummary};
use headlines_proto::v1::{
    AccountStreamItem as ProtoAccountStreamItem, ArticleLiveSummary as ProtoArticleLiveSummary,
    ArticleState as ProtoArticleState, ArticleSummary as ProtoArticleSummary,
    ArticleTombstoneSummary as ProtoArticleTombstoneSummary, StreamAccountArticlesRequest,
    StreamAccountArticlesResponse, account_stream_service_server::AccountStreamService,
    article_summary,
};

/// Concrete `AccountStreamService` impl.
pub struct AccountStreamServiceImpl<A, S> {
    pub accounts: Arc<A>,
    pub stream: Arc<S>,
}

impl<A, S> AccountStreamServiceImpl<A, S> {
    pub fn new(accounts: Arc<A>, stream: Arc<S>) -> Self {
        Self { accounts, stream }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_uuid(field: &str, raw: &str) -> Result<Uuid, HeadlinesError> {
    Uuid::parse_str(raw).map_err(|e| HeadlinesError::InvalidArgument {
        field: field.into(),
        reason: format!("invalid uuid: {e}"),
    })
}

fn ts_to_proto(t: chrono::DateTime<chrono::Utc>) -> Timestamp {
    Timestamp {
        seconds: t.timestamp(),
        nanos: t.timestamp_subsec_nanos() as i32,
    }
}

fn current_subject<T>(req: &Request<T>) -> Subject {
    req.extensions()
        .get::<Subject>()
        .cloned()
        .unwrap_or(Subject::Anonymous)
}

/// Hand-rolled `ArticleSummary → proto::ArticleSummary` converter. The
/// account-stream surface emits BOTH live and tombstone summaries
/// (republishers dispatch on `state` to mirror or remove). Mirrors
/// `services::feed_recommendation::article_summary_to_proto` and
/// `services::feed_follow::article_summary_to_proto`.
fn article_summary_to_proto(s: ArticleSummary) -> ProtoArticleSummary {
    let state = match s.state {
        ArticleState::Live => ProtoArticleState::Live,
        ArticleState::Tombstone => ProtoArticleState::Tombstone,
    } as i32;
    let state_data = match s.state {
        ArticleState::Live => Some(article_summary::StateData::Live(ProtoArticleLiveSummary {
            current_version: s.current_version.unwrap_or_default(),
            title: s.title.unwrap_or_default(),
            author_name: s.author_name.unwrap_or_default(),
            author_url: s.author_url.unwrap_or_default(),
            redacted: s.redacted,
            published_at: s.published_at.map(ts_to_proto),
            updated_at: s.updated_at.map(ts_to_proto),
        })),
        ArticleState::Tombstone => Some(article_summary::StateData::Tombstone(
            ProtoArticleTombstoneSummary {
                reason: s.tombstone_reason.unwrap_or_default(),
                tombstoned_at: s.tombstoned_at.map(ts_to_proto),
            },
        )),
    };
    ProtoArticleSummary {
        id: s.id.to_string(),
        account_id: s.account_id.to_string(),
        state,
        created_at: Some(ts_to_proto(s.created_at)),
        state_data,
    }
}

fn account_stream_item_to_proto(item: DomainAccountStreamItem) -> ProtoAccountStreamItem {
    ProtoAccountStreamItem {
        article: Some(article_summary_to_proto(item.article)),
    }
}

// ---------------------------------------------------------------------------
// Service impl
// ---------------------------------------------------------------------------

#[async_trait]
impl<A, S> AccountStreamService for AccountStreamServiceImpl<A, S>
where
    A: AccountRepo + 'static,
    S: AccountStreamRepo + 'static,
{
    async fn stream_account_articles(
        &self,
        request: Request<StreamAccountArticlesRequest>,
    ) -> Result<Response<StreamAccountArticlesResponse>, Status> {
        let subject = current_subject(&request);
        let req = request.into_inner();
        let account_id = parse_uuid("account_id", &req.account_id).map_err(Status::from)?;

        // System-only with `articles.stream`. The proto `AUTH_TABLE` already
        // restricts to System+scope, but defense-in-depth — anything else
        // surfaces as PERMISSION_DENIED.
        let allowed =
            matches!(subject, Subject::System { .. }) && subject.has_scope("articles.stream");
        if !allowed {
            return Err(Status::permission_denied("articles.stream required"));
        }

        // Account existence + lifecycle. The stream **closes** on deletion;
        // republishers must remove all content from the target platform when
        // they observe `ACCOUNT_DELETED`.
        let account = self.accounts.get(account_id).await.map_err(Status::from)?;
        if account.status == AccountStatus::Deleted {
            return Err(HeadlinesError::AccountDeleted { id: account_id }.into());
        }

        let page = self
            .stream
            .stream(account_id, req.page_size, PageToken(req.page_token))
            .await
            .map_err(Status::from)?;

        Ok(Response::new(StreamAccountArticlesResponse {
            items: page
                .items
                .into_iter()
                .map(account_stream_item_to_proto)
                .collect(),
            next_page_token: page.next_page_token.0,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn parse_uuid_rejects_garbage() {
        // Arrange
        let bad = "not-a-uuid";

        // Act
        let res = parse_uuid("account_id", bad);

        // Assert
        assert!(matches!(
            res,
            Err(HeadlinesError::InvalidArgument { ref field, .. }) if field == "account_id"
        ));
    }

    #[test]
    fn article_summary_to_proto_round_trips_live() {
        // Arrange
        let s = ArticleSummary {
            id: Uuid::nil(),
            account_id: Uuid::nil(),
            state: ArticleState::Live,
            created_at: Utc::now(),
            current_version: Some(2),
            title: Some("t".into()),
            author_name: Some("a".into()),
            author_url: Some("u".into()),
            redacted: false,
            published_at: Some(Utc::now()),
            updated_at: Some(Utc::now()),
            tombstone_reason: None,
            tombstoned_at: None,
        };

        // Act
        let p = article_summary_to_proto(s);

        // Assert
        assert_eq!(p.state, ProtoArticleState::Live as i32);
        assert!(matches!(
            p.state_data,
            Some(article_summary::StateData::Live(_))
        ));
    }

    #[test]
    fn article_summary_to_proto_round_trips_tombstone() {
        // Arrange — tombstone-shaped summary surfaces with state_data = Tombstone.
        let s = ArticleSummary {
            id: Uuid::nil(),
            account_id: Uuid::nil(),
            state: ArticleState::Tombstone,
            created_at: Utc::now(),
            current_version: None,
            title: None,
            author_name: None,
            author_url: None,
            redacted: false,
            published_at: None,
            updated_at: None,
            tombstone_reason: Some("dmca".into()),
            tombstoned_at: Some(Utc::now()),
        };

        // Act
        let p = article_summary_to_proto(s);

        // Assert
        assert_eq!(p.state, ProtoArticleState::Tombstone as i32);
        match p.state_data {
            Some(article_summary::StateData::Tombstone(t)) => {
                assert_eq!(t.reason, "dmca");
                assert!(t.tombstoned_at.is_some());
            }
            _ => panic!("expected tombstone state_data"),
        }
    }

    #[test]
    fn account_stream_item_to_proto_carries_article() {
        // Arrange — stream item wraps a single ArticleSummary.
        let item = DomainAccountStreamItem {
            article: ArticleSummary {
                id: Uuid::nil(),
                account_id: Uuid::nil(),
                state: ArticleState::Live,
                created_at: Utc::now(),
                current_version: Some(1),
                title: Some("x".into()),
                author_name: Some("y".into()),
                author_url: Some("".into()),
                redacted: false,
                published_at: Some(Utc::now()),
                updated_at: Some(Utc::now()),
                tombstone_reason: None,
                tombstoned_at: None,
            },
        };

        // Act
        let p = account_stream_item_to_proto(item);

        // Assert
        assert!(p.article.is_some());
    }
}
