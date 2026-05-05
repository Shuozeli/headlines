//! `KeyRepo` — generic persistence surface for account/user/system signing
//! keys per `docs/design/auth.md` + the three `*_keys` tables in
//! `data-model.md`.
//!
//! One trait, parameterised over `KeyKind`, instead of three near-identical
//! traits. Phase 4's `SignedRequestStrategy` resolves a key by `(kind,
//! key_id)` exactly the same way for all three kinds; collapsing the surface
//! here keeps the strategy implementation a single function.

use std::future::Future;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::error::HeadlinesError;

/// Which key table this row belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyKind {
    Account,
    User,
    System,
}

/// Status mirror of `*_keys.status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStatus {
    Active,
    Revoked,
}

/// Stored key row. The `parent_id` field is `account_id` / `user_id` /
/// `system_id` depending on `kind`. `algo` and `public_key` are stored as
/// the wire encoding the algorithm impl emits.
#[derive(Debug, Clone)]
pub struct StoredKey {
    pub kind: KeyKind,
    pub parent_id: Uuid,
    pub key_id: Uuid,
    pub algo: String,
    pub public_key: String,
    pub status: KeyStatus,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Insert DTO for `Add*Key`. Caller mints `key_id` (UUIDv7) before calling.
#[derive(Debug, Clone)]
pub struct NewKey {
    pub kind: KeyKind,
    pub parent_id: Uuid,
    pub key_id: Uuid,
    pub algo: String,
    pub public_key: String,
}

pub trait KeyRepo: Send + Sync {
    /// Insert a new key.
    fn create(&self, new: NewKey)
    -> impl Future<Output = Result<StoredKey, HeadlinesError>> + Send;

    /// Look up by `(kind, parent_id, key_id)`. Used during signature
    /// verification to fetch the public key + status.
    fn get(
        &self,
        kind: KeyKind,
        parent_id: Uuid,
        key_id: Uuid,
    ) -> impl Future<Output = Result<StoredKey, HeadlinesError>> + Send;

    /// Flip status to `revoked`, set `revoked_at=now`. Rejects with
    /// `KeyAlreadyRevoked` on a second call. The lockout-protection check
    /// (`LAST_ACTIVE_KEY`) is the **service layer's** responsibility — repos
    /// can be called by the operator-rescue path that bypasses the check.
    fn revoke(
        &self,
        kind: KeyKind,
        parent_id: Uuid,
        key_id: Uuid,
    ) -> impl Future<Output = Result<StoredKey, HeadlinesError>> + Send;

    /// All currently-active keys under a parent. Used by the service-layer
    /// lockout check before honouring a revoke.
    fn list_active(
        &self,
        kind: KeyKind,
        parent_id: Uuid,
    ) -> impl Future<Output = Result<Vec<StoredKey>, HeadlinesError>> + Send;
}
