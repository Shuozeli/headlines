//! `UserRepo` — persistence surface for the `users` aggregate.
//! Mirrors RPCs in `docs/design/users.md`.

use std::future::Future;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::error::HeadlinesError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserStatus {
    Active,
    Deleted,
}

#[derive(Debug, Clone)]
pub struct User {
    pub id: Uuid,
    pub display_name: String,
    pub status: UserStatus,
    pub deleted_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct NewUser {
    pub id: Uuid,
    pub display_name: String,
}

#[derive(Debug, Clone, Default)]
pub struct UserUpdate {
    pub display_name: Option<String>,
}

pub trait UserRepo: Send + Sync {
    fn create(&self, new: NewUser) -> impl Future<Output = Result<User, HeadlinesError>> + Send;

    fn get(&self, id: Uuid) -> impl Future<Output = Result<User, HeadlinesError>> + Send;

    fn update(
        &self,
        id: Uuid,
        update: UserUpdate,
    ) -> impl Future<Output = Result<User, HeadlinesError>> + Send;

    fn soft_delete(&self, id: Uuid) -> impl Future<Output = Result<User, HeadlinesError>> + Send;
}
