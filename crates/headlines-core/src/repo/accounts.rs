//! `AccountRepo` — persistence surface for the `accounts` aggregate.
//! Mirrors the RPCs in `docs/design/accounts.md`.

use std::future::Future;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::error::HeadlinesError;

/// Status mirror of `accounts.status`. Kept as a Rust enum so impls don't
/// stringly-type the column at the call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountStatus {
    Active,
    Deleted,
}

/// Full account row as returned by `Get/Update/Delete`.
#[derive(Debug, Clone)]
pub struct Account {
    pub id: Uuid,
    pub short_name: String,
    pub author_name: String,
    pub author_url: String,
    pub status: AccountStatus,
    pub deleted_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Insert-side DTO for `CreateAccount`. The id is server-minted (UUIDv7);
/// callers don't supply it.
#[derive(Debug, Clone)]
pub struct NewAccount {
    pub id: Uuid,
    pub short_name: String,
    pub author_name: String,
    pub author_url: String,
}

/// `UpdateAccount` payload — only mutable fields, all optional. Whitelist
/// enforcement happens in the service layer via the `update_mask`.
#[derive(Debug, Clone, Default)]
pub struct AccountUpdate {
    pub short_name: Option<String>,
    pub author_name: Option<String>,
    pub author_url: Option<String>,
}

pub trait AccountRepo: Send + Sync {
    /// Insert a new account. Conflict on `id` (UUIDv7 collision —
    /// astronomically unlikely) is `HeadlinesError::Internal`.
    fn create(
        &self,
        new: NewAccount,
    ) -> impl Future<Output = Result<Account, HeadlinesError>> + Send;

    /// Fetch by id. Returns `Ok(account)` for both `active` and `deleted`
    /// (tombstone reads return 200 per `accounts.md`).
    /// `AccountNotFound` if the row doesn't exist.
    fn get(&self, id: Uuid) -> impl Future<Output = Result<Account, HeadlinesError>> + Send;

    /// Apply an update. Rejects with `AccountDeleted` if the account is
    /// already soft-deleted.
    fn update(
        &self,
        id: Uuid,
        update: AccountUpdate,
    ) -> impl Future<Output = Result<Account, HeadlinesError>> + Send;

    /// Soft-delete: sets `status='deleted'`, `deleted_at=now`. Returns the
    /// post-delete row. Idempotent on already-deleted accounts (returns the
    /// existing tombstone).
    fn soft_delete(&self, id: Uuid)
    -> impl Future<Output = Result<Account, HeadlinesError>> + Send;
}
