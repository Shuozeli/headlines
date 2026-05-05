//! `FeedRecommendationServiceImpl` — gRPC handler for
//! `headlines.v1.FeedRecommendationService`.
//!
//! Authoritative spec: `docs/design/feed-recommendation.md`.
//!
//! The proto-driven `AUTH_TABLE` enforces the **subject class** + **system
//! scope** gate before this handler runs:
//!   - `ReplaceRecommendationFeed`: `[SYSTEM]` + `feeds.recommendation.write`.
//!   - `GetRecommendationFeed`:     `[USER_SELF, SYSTEM]` + `feeds.recommendation.read`.
//!
//! The handler enforces:
//!   - well-formed `user_id`,
//!   - the user exists and is `active` (else `USER_NOT_FOUND` /
//!     `USER_DELETED`),
//!   - on Replace: `article_ids` size cap, dedup, and per-id well-formedness,
//!   - on Get: a self-or-system check (a User can only read their own feed).

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use prost_types::Timestamp;
use tonic::{Request, Response, Status};
use uuid::Uuid;

use headlines_core::HeadlinesError;
use headlines_core::Subject;
use headlines_core::repo::PageToken;
use headlines_core::repo::articles::{ArticleState, ArticleSummary};
use headlines_core::repo::feed_recommendation::{
    FeedItem as DomainFeedItem, FeedRecommendationRepo,
};
use headlines_core::repo::users::{UserRepo, UserStatus};
use headlines_proto::v1::{
    ArticleLiveSummary as ProtoArticleLiveSummary, ArticleState as ProtoArticleState,
    ArticleSummary as ProtoArticleSummary, ArticleTombstoneSummary as ProtoArticleTombstoneSummary,
    FeedItem as ProtoFeedItem, GetRecommendationFeedRequest, GetRecommendationFeedResponse,
    ReplaceRecommendationFeedRequest, ReplaceRecommendationFeedResponse, article_summary,
    feed_recommendation_service_server::FeedRecommendationService,
};

/// Default cap on `Replace` payload size, per `feed-recommendation.md`.
pub const DEFAULT_FEEDS_REPLACE_MAX_ITEMS: usize = 5000;

/// Concrete `FeedRecommendationService` impl.
pub struct FeedRecommendationServiceImpl<U, F> {
    pub users: Arc<U>,
    pub feeds: Arc<F>,
    pub replace_max_items: usize,
    pub metrics: Arc<crate::metrics::DomainMetrics>,
}

impl<U, F> FeedRecommendationServiceImpl<U, F> {
    pub fn new(users: Arc<U>, feeds: Arc<F>, replace_max_items: usize) -> Self {
        Self {
            users,
            feeds,
            replace_max_items,
            metrics: crate::metrics::DomainMetrics::shared_no_op(),
        }
    }

    /// Override the default no-op `DomainMetrics`.
    pub fn with_metrics(mut self, metrics: Arc<crate::metrics::DomainMetrics>) -> Self {
        self.metrics = metrics;
        self
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
/// feed surface only emits live summaries (the inner-join drops tombstones)
/// but we cover both branches so the converter remains a complete mirror of
/// the domain type, mirroring `services::article::summary_to_proto`.
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

fn feed_item_to_proto(item: DomainFeedItem) -> ProtoFeedItem {
    ProtoFeedItem {
        position: item.position,
        article: Some(article_summary_to_proto(item.article)),
    }
}

// ---------------------------------------------------------------------------
// Service impl
// ---------------------------------------------------------------------------

#[async_trait]
impl<U, F> FeedRecommendationService for FeedRecommendationServiceImpl<U, F>
where
    U: UserRepo + 'static,
    F: FeedRecommendationRepo + 'static,
{
    async fn replace_recommendation_feed(
        &self,
        request: Request<ReplaceRecommendationFeedRequest>,
    ) -> Result<Response<ReplaceRecommendationFeedResponse>, Status> {
        let subject = current_subject(&request);
        let req = request.into_inner();
        let user_id = parse_uuid("user_id", &req.user_id).map_err(Status::from)?;

        // System-only write per `feed-recommendation.md`. The proto
        // `AUTH_TABLE` already restricts to System+scope, but defense-in-depth.
        let allowed = matches!(subject, Subject::System { .. })
            && subject.has_scope("feeds.recommendation.write");
        if !allowed {
            // Proto-level layer should have caught this; surface as
            // PERMISSION_DENIED via `UnauthorizedUserId` if it ever reaches us.
            return Err(Status::permission_denied(
                "feeds.recommendation.write required",
            ));
        }

        // Size cap.
        if req.article_ids.len() > self.replace_max_items {
            return Err(HeadlinesError::FeedTooLarge {
                actual: req.article_ids.len(),
                max: self.replace_max_items,
            }
            .into());
        }

        // Parse + dedup.
        let mut parsed: Vec<Uuid> = Vec::with_capacity(req.article_ids.len());
        let mut seen: HashSet<Uuid> = HashSet::with_capacity(req.article_ids.len());
        for raw in &req.article_ids {
            let id = parse_uuid("article_ids", raw).map_err(Status::from)?;
            if !seen.insert(id) {
                return Err(HeadlinesError::DuplicateArticleId { id }.into());
            }
            parsed.push(id);
        }

        // User must exist + active.
        let user = self.users.get(user_id).await.map_err(Status::from)?;
        if user.status == UserStatus::Deleted {
            return Err(HeadlinesError::UserDeleted { id: user_id }.into());
        }

        let stored = self
            .feeds
            .replace(user_id, parsed)
            .await
            .map_err(Status::from)?;

        self.metrics
            .feeds_replaced
            .add(1, &crate::metrics::no_attrs());
        Ok(Response::new(ReplaceRecommendationFeedResponse {
            stored_count: stored,
        }))
    }

    async fn get_recommendation_feed(
        &self,
        request: Request<GetRecommendationFeedRequest>,
    ) -> Result<Response<GetRecommendationFeedResponse>, Status> {
        let subject = current_subject(&request);
        let req = request.into_inner();
        let user_id = parse_uuid("user_id", &req.user_id).map_err(Status::from)?;

        // Self-or-system. Cross-user attempts surface as USER_NOT_FOUND
        // (privacy: don't leak existence to a different User caller).
        let allowed = subject.is_self_for(Some(user_id), None)
            || (matches!(subject, Subject::System { .. })
                && subject.has_scope("feeds.recommendation.read"));
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

        Ok(Response::new(GetRecommendationFeedResponse {
            items: page.items.into_iter().map(feed_item_to_proto).collect(),
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
    fn feed_item_to_proto_carries_position_and_article() {
        // Arrange
        let item = DomainFeedItem {
            position: 7,
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
        let p = feed_item_to_proto(item);

        // Assert
        assert_eq!(p.position, 7);
        assert!(p.article.is_some());
    }
}
