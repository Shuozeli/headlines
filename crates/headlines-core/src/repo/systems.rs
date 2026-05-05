//! `SystemRepo` — persistence surface for the `systems`, `system_scopes`,
//! and `system_keys` tables per `docs/design/data-model.md`. System
//! identities are seeded out-of-band; this trait covers reads + key
//! lookup needed by the auth layer.

use std::future::Future;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::error::HeadlinesError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemStatus {
    Active,
    Disabled,
}

#[derive(Debug, Clone)]
pub struct System {
    pub id: Uuid,
    pub name: String,
    pub status: SystemStatus,
    pub created_at: DateTime<Utc>,
    pub disabled_at: Option<DateTime<Utc>>,
}

pub trait SystemRepo: Send + Sync {
    /// Read a single system row by id.
    fn get_system(&self, id: Uuid) -> impl Future<Output = Result<System, HeadlinesError>> + Send;

    /// All scopes granted to `system_id`, as the raw dotted strings stored
    /// in `system_scopes`. Wildcard expansion is the authorization layer's
    /// concern (see `Subject::has_scope`).
    fn list_scopes(
        &self,
        system_id: Uuid,
    ) -> impl Future<Output = Result<Vec<String>, HeadlinesError>> + Send;
}
