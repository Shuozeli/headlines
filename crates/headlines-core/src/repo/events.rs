//! `EventRepo` — persistence surface for the append-only `events` table per
//! `docs/design/events.md`. Properties are stored as opaque JSON; the service
//! layer is responsible for type/properties consistency before calling.

use std::future::Future;

use chrono::{DateTime, Utc};
use serde_json::Value as Json;
use uuid::Uuid;

use crate::{error::HeadlinesError, repo::PageToken};

/// String-typed event kind. Stored as text; the v1 vocabulary is in
/// `events.md`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventType(pub String);

#[derive(Debug, Clone)]
pub struct Event {
    pub id: Uuid,
    pub user_id: Uuid,
    pub article_id: Option<Uuid>,
    pub r#type: EventType,
    pub occurred_at: DateTime<Utc>,
    pub received_at: DateTime<Utc>,
    pub surface: String,
    pub properties: Json,
}

/// Insert payload. `id` and `received_at` are server-set by the repo.
#[derive(Debug, Clone)]
pub struct EventRecord {
    pub user_id: Uuid,
    pub article_id: Option<Uuid>,
    pub r#type: EventType,
    pub occurred_at: DateTime<Utc>,
    pub surface: String,
    pub properties: Json,
}

#[derive(Debug, Clone, Default)]
pub struct ListEventsFilter {
    pub user_id: Option<Uuid>,
    pub article_id: Option<Uuid>,
    pub types: Vec<EventType>,
    pub received_after: Option<DateTime<Utc>>,
    pub received_before: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct ListEventsPage {
    pub items: Vec<Event>,
    pub next_page_token: PageToken,
}

pub trait EventRepo: Send + Sync {
    fn record(
        &self,
        record: EventRecord,
    ) -> impl Future<Output = Result<Event, HeadlinesError>> + Send;

    /// All-or-nothing insert. Validation runs over the whole batch first;
    /// any failure rejects the entire batch.
    fn record_batch(
        &self,
        records: Vec<EventRecord>,
    ) -> impl Future<Output = Result<Vec<Event>, HeadlinesError>> + Send;

    fn list(
        &self,
        filter: ListEventsFilter,
        page_size: i32,
        page_token: PageToken,
    ) -> impl Future<Output = Result<ListEventsPage, HeadlinesError>> + Send;
}
