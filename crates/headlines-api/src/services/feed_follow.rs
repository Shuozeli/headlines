//! `FeedFollowServiceImpl` — gRPC handler for `headlines.v1.FeedFollowService`.
//!
//! Authoritative spec: `docs/design/feed-follow.md`.
//!
//! The proto-driven `AUTH_TABLE` enforces the **subject class** + **system
//! scope** gate before this handler runs:
//!   - `GetFollowFeed`: `[USER_SELF, SYSTEM]` + `feeds.follow.read`.
//!
//! The handler enforces:
//!   - well-formed `user_id`,
//!   - the user exists and is `active` (else `USER_NOT_FOUND` /
//!     `USER_DELETED`),
//!   - a self-or-system check (a User can only read their own follow feed).
//!
//! Read-only surface — no write-side companion. The follow feed is computed
//! at read time by the repo's JOIN.

use std::sync::Arc;

use async_trait::async_trait;
use prost_types::Timestamp;
use tonic::{Request, Response, Status};
use uuid::Uuid;

use headlines_core::HeadlinesError;
use headlines_core::Subject;
use headlines_core::repo::PageToken;
use headlines_core::repo::articles::{ArticleState, ArticleSummary};
use headlines_core::repo::feed_follow::{FeedFollowRepo, FollowFeedItem as DomainFollowFeedItem};
use headlines_core::repo::users::{UserRepo, UserStatus};
use headlines_proto::v1::{
    ArticleLiveSummary as ProtoArticleLiveSummary, ArticleState as ProtoArticleState,
    ArticleSummary as ProtoArticleSummary, ArticleTombstoneSummary as ProtoArticleTombstoneSummary,
    FollowFeedItem as ProtoFollowFeedItem, GetFollowFeedRequest, GetFollowFeedResponse,
    article_summary, feed_follow_service_server::FeedFollowService,
};

/// Concrete `FeedFollowService` impl.
pub struct FeedFollowServiceImpl<U, F> {
    pub users: Arc<U>,
    pub feeds: Arc<F>,
}

impl<U, F> FeedFollowServiceImpl<U, F> {
    pub fn new(users: Arc<U>, feeds: Arc<F>) -> Self {
        Self { users, feeds }
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
/// follow-feed surface only emits live summaries (the inner-join drops
/// tombstones) but we cover both branches so the converter remains a complete
/// mirror of the domain type, mirroring
/// `services::feed_recommendation::article_summary_to_proto`.
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

fn follow_feed_item_to_proto(item: DomainFollowFeedItem) -> ProtoFollowFeedItem {
    ProtoFollowFeedItem {
        article: Some(article_summary_to_proto(item.article)),
    }
}

// ---------------------------------------------------------------------------
// Service impl
// ---------------------------------------------------------------------------

#[async_trait]
impl<U, F> FeedFollowService for FeedFollowServiceImpl<U, F>
where
    U: UserRepo + 'static,
    F: FeedFollowRepo + 'static,
{
    async fn get_follow_feed(
        &self,
        request: Request<GetFollowFeedRequest>,
    ) -> Result<Response<GetFollowFeedResponse>, Status> {
        let subject = current_subject(&request);
        let req = request.into_inner();
        let user_id = parse_uuid("user_id", &req.user_id).map_err(Status::from)?;

        // Self-or-system. Cross-user attempts surface as USER_NOT_FOUND
        // (privacy: don't leak existence to a different User caller).
        let allowed = subject.is_self_for(Some(user_id), None)
            || (matches!(subject, Subject::System { .. })
                && subject.has_scope("feeds.follow.read"));
        if !allowed {
            return Err(HeadlinesError::UserNotFound { id: user_id }.into());
        }

        // User must exist + active.
        let user = self.users.get(user_id).await.map_err(Status::from)?;
        if user.status == UserStatus::Deleted {
            return Err(HeadlinesError::UserDeleted { id: user_id }.into());
        }

        let page = self
            .feeds
            .get(user_id, req.page_size, PageToken(req.page_token))
            .await
            .map_err(Status::from)?;

        Ok(Response::new(GetFollowFeedResponse {
            items: page
                .items
                .into_iter()
                .map(follow_feed_item_to_proto)
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
        let res = parse_uuid("user_id", bad);

        // Assert
        assert!(matches!(
            res,
            Err(HeadlinesError::InvalidArgument { ref field, .. }) if field == "user_id"
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
    fn follow_feed_item_to_proto_carries_article() {
        // Arrange — distinct from `FeedItem`; no `position` field.
        let item = DomainFollowFeedItem {
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
        let p = follow_feed_item_to_proto(item);

        // Assert
        assert!(p.article.is_some());
    }
}
