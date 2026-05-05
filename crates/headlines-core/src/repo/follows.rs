//! `FollowRepo` — persistence surface for the `follows` aggregate per
//! `docs/design/follows.md`.

use std::future::Future;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{error::HeadlinesError, repo::PageToken};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FollowStatus {
    Active,
    Unfollowed,
}

#[derive(Debug, Clone)]
pub struct Follow {
    pub user_id: Uuid,
    pub account_id: Uuid,
    pub status: FollowStatus,
    pub created_at: DateTime<Utc>,
    pub unfollowed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct ListFollowsPage {
    pub items: Vec<Follow>,
    pub next_page_token: PageToken,
}

pub trait FollowRepo: Send + Sync {
    /// Idempotent follow: insert if missing, re-activate if previously
    /// unfollowed (resets `created_at = now`), no-op if already active. Per
    /// `follows.md` state machine.
    fn follow(
        &self,
        user_id: Uuid,
        account_id: Uuid,
    ) -> impl Future<Output = Result<Follow, HeadlinesError>> + Send;

    /// Set `status='unfollowed'` + `unfollowed_at=now`. `FollowNotFound` if
    /// the row never existed; idempotent on already-unfollowed.
    fn unfollow(
        &self,
        user_id: Uuid,
        account_id: Uuid,
    ) -> impl Future<Output = Result<Follow, HeadlinesError>> + Send;

    /// Read a single edge regardless of status.
    fn get(
        &self,
        user_id: Uuid,
        account_id: Uuid,
    ) -> impl Future<Output = Result<Follow, HeadlinesError>> + Send;

    fn list_by_user(
        &self,
        user_id: Uuid,
        include_unfollowed: bool,
        page_size: i32,
        page_token: PageToken,
    ) -> impl Future<Output = Result<ListFollowsPage, HeadlinesError>> + Send;

    fn list_by_account(
        &self,
        account_id: Uuid,
        include_unfollowed: bool,
        page_size: i32,
        page_token: PageToken,
    ) -> impl Future<Output = Result<ListFollowsPage, HeadlinesError>> + Send;
}
