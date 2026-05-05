//! `FollowServiceImpl` — gRPC handler for `headlines.v1.FollowService`.
//!
//! Authoritative spec: `docs/design/follows.md`.
//!
//! The proto-driven `AUTH_TABLE` enforces the **subject class** + **system
//! scope** gate before this handler runs (e.g. `Follow` requires
//! `[USER_SELF, SYSTEM]` + `follows.write`). The handler enforces the
//! per-resource self-check (`is_self_for`), well-formedness of UUIDs, the
//! `user_id != account_id` guard, and the existence/active checks on the
//! target user/account before mutating the edge.

use std::sync::Arc;

use async_trait::async_trait;
use prost_types::Timestamp;
use tonic::{Request, Response, Status};
use uuid::Uuid;

use headlines_core::HeadlinesError;
use headlines_core::Subject;
use headlines_core::repo::PageToken;
use headlines_core::repo::accounts::{AccountRepo, AccountStatus};
use headlines_core::repo::follows::{Follow as DomainFollow, FollowRepo, FollowStatus};
use headlines_core::repo::users::{UserRepo, UserStatus};
use headlines_proto::v1::{
    Follow as ProtoFollow, FollowRequest, FollowStatus as ProtoFollowStatus, GetFollowRequest,
    ListAccountFollowersRequest, ListAccountFollowersResponse, ListUserFollowsRequest,
    ListUserFollowsResponse, UnfollowRequest, follow_service_server::FollowService,
};

/// Concrete `FollowService` impl.
pub struct FollowServiceImpl<U, A, F> {
    pub users: Arc<U>,
    pub accounts: Arc<A>,
    pub follows: Arc<F>,
}

impl<U, A, F> FollowServiceImpl<U, A, F> {
    pub fn new(users: Arc<U>, accounts: Arc<A>, follows: Arc<F>) -> Self {
        Self {
            users,
            accounts,
            follows,
        }
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

fn follow_to_proto(f: DomainFollow) -> ProtoFollow {
    let status = match f.status {
        FollowStatus::Active => ProtoFollowStatus::Active,
        FollowStatus::Unfollowed => ProtoFollowStatus::Unfollowed,
    } as i32;
    ProtoFollow {
        user_id: f.user_id.to_string(),
        account_id: f.account_id.to_string(),
        status,
        created_at: Some(ts_to_proto(f.created_at)),
        unfollowed_at: f.unfollowed_at.map(ts_to_proto),
    }
}

fn current_subject<T>(req: &Request<T>) -> Subject {
    req.extensions()
        .get::<Subject>()
        .cloned()
        .unwrap_or(Subject::Anonymous)
}

// ---------------------------------------------------------------------------
// Service impl
// ---------------------------------------------------------------------------

#[async_trait]
impl<U, A, F> FollowService for FollowServiceImpl<U, A, F>
where
    U: UserRepo + 'static,
    A: AccountRepo + 'static,
    F: FollowRepo + 'static,
{
    async fn follow(
        &self,
        request: Request<FollowRequest>,
    ) -> Result<Response<ProtoFollow>, Status> {
        let subject = current_subject(&request);
        let req = request.into_inner();
        let user_id = parse_uuid("user_id", &req.user_id).map_err(Status::from)?;
        let account_id = parse_uuid("account_id", &req.account_id).map_err(Status::from)?;

        // Self-follow guard (cross-namespace UUID collision is astronomically
        // unlikely; `follows.md` rejects it explicitly).
        if user_id == account_id {
            return Err(HeadlinesError::SelfFollowForbidden.into());
        }

        // Authorization: `User` whose `id == request.user_id` OR System with
        // `follows.write`. Cross-user attempts surface as `USER_NOT_FOUND`
        // (privacy: don't leak user existence to a different User caller).
        let allowed = subject.is_self_for(Some(user_id), None)
            || (matches!(subject, Subject::System { .. }) && subject.has_scope("follows.write"));
        if !allowed {
            return Err(HeadlinesError::UserNotFound { id: user_id }.into());
        }

        // Existence + active checks on the target user.
        let target_user = self.users.get(user_id).await.map_err(Status::from)?;
        if target_user.status == UserStatus::Deleted {
            return Err(HeadlinesError::UserDeleted { id: user_id }.into());
        }
        // Existence + active checks on the target account.
        let target_account = self.accounts.get(account_id).await.map_err(Status::from)?;
        if target_account.status == AccountStatus::Deleted {
            return Err(HeadlinesError::AccountDeleted { id: account_id }.into());
        }

        let follow = self
            .follows
            .follow(user_id, account_id)
            .await
            .map_err(Status::from)?;
        Ok(Response::new(follow_to_proto(follow)))
    }

    async fn unfollow(
        &self,
        request: Request<UnfollowRequest>,
    ) -> Result<Response<ProtoFollow>, Status> {
        let subject = current_subject(&request);
        let req = request.into_inner();
        let user_id = parse_uuid("user_id", &req.user_id).map_err(Status::from)?;
        let account_id = parse_uuid("account_id", &req.account_id).map_err(Status::from)?;

        if user_id == account_id {
            return Err(HeadlinesError::SelfFollowForbidden.into());
        }

        let allowed = subject.is_self_for(Some(user_id), None)
            || (matches!(subject, Subject::System { .. }) && subject.has_scope("follows.write"));
        if !allowed {
            return Err(HeadlinesError::UserNotFound { id: user_id }.into());
        }

        // `Unfollow` is allowed regardless of either side's deletion status
        // (per `follows.md`). The repo surfaces FollowNotFound for the
        // never-existed case and is idempotent on already-unfollowed.
        let follow = self
            .follows
            .unfollow(user_id, account_id)
            .await
            .map_err(Status::from)?;
        Ok(Response::new(follow_to_proto(follow)))
    }

    async fn get_follow(
        &self,
        request: Request<GetFollowRequest>,
    ) -> Result<Response<ProtoFollow>, Status> {
        let subject = current_subject(&request);
        let req = request.into_inner();
        let user_id = parse_uuid("user_id", &req.user_id).map_err(Status::from)?;
        let account_id = parse_uuid("account_id", &req.account_id).map_err(Status::from)?;

        if user_id == account_id {
            return Err(HeadlinesError::SelfFollowForbidden.into());
        }

        let allowed = subject.is_self_for(Some(user_id), None)
            || (matches!(subject, Subject::System { .. }) && subject.has_scope("follows.read"));
        if !allowed {
            return Err(HeadlinesError::UserNotFound { id: user_id }.into());
        }

        let follow = self
            .follows
            .get(user_id, account_id)
            .await
            .map_err(Status::from)?;
        Ok(Response::new(follow_to_proto(follow)))
    }

    async fn list_user_follows(
        &self,
        request: Request<ListUserFollowsRequest>,
    ) -> Result<Response<ListUserFollowsResponse>, Status> {
        let subject = current_subject(&request);
        let req = request.into_inner();
        let user_id = parse_uuid("user_id", &req.user_id).map_err(Status::from)?;

        let allowed = subject.is_self_for(Some(user_id), None)
            || (matches!(subject, Subject::System { .. }) && subject.has_scope("follows.read"));
        if !allowed {
            return Err(HeadlinesError::UserNotFound { id: user_id }.into());
        }

        let page = self
            .follows
            .list_by_user(
                user_id,
                req.include_unfollowed,
                req.page_size,
                PageToken(req.page_token),
            )
            .await
            .map_err(Status::from)?;

        Ok(Response::new(ListUserFollowsResponse {
            items: page.items.into_iter().map(follow_to_proto).collect(),
            next_page_token: page.next_page_token.0,
        }))
    }

    async fn list_account_followers(
        &self,
        request: Request<ListAccountFollowersRequest>,
    ) -> Result<Response<ListAccountFollowersResponse>, Status> {
        let subject = current_subject(&request);
        let req = request.into_inner();
        let account_id = parse_uuid("account_id", &req.account_id).map_err(Status::from)?;

        let allowed = subject.is_self_for(None, Some(account_id))
            || (matches!(subject, Subject::System { .. }) && subject.has_scope("follows.read"));
        if !allowed {
            return Err(HeadlinesError::AccountNotFound { id: account_id }.into());
        }

        let page = self
            .follows
            .list_by_account(
                account_id,
                req.include_unfollowed,
                req.page_size,
                PageToken(req.page_token),
            )
            .await
            .map_err(Status::from)?;

        Ok(Response::new(ListAccountFollowersResponse {
            items: page.items.into_iter().map(follow_to_proto).collect(),
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
    fn follow_to_proto_round_trips_status_active() {
        // Arrange
        let f = DomainFollow {
            user_id: Uuid::nil(),
            account_id: Uuid::nil(),
            status: FollowStatus::Active,
            created_at: Utc::now(),
            unfollowed_at: None,
        };

        // Act
        let p = follow_to_proto(f);

        // Assert
        assert_eq!(p.status, ProtoFollowStatus::Active as i32);
        assert!(p.unfollowed_at.is_none());
    }

    #[test]
    fn follow_to_proto_carries_unfollowed_at_when_present() {
        // Arrange
        let f = DomainFollow {
            user_id: Uuid::nil(),
            account_id: Uuid::nil(),
            status: FollowStatus::Unfollowed,
            created_at: Utc::now(),
            unfollowed_at: Some(Utc::now()),
        };

        // Act
        let p = follow_to_proto(f);

        // Assert
        assert_eq!(p.status, ProtoFollowStatus::Unfollowed as i32);
        assert!(p.unfollowed_at.is_some());
    }
}
