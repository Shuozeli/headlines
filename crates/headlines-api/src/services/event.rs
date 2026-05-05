//! `EventServiceImpl` — gRPC handler for `headlines.v1.EventService`.
//!
//! Authoritative spec: `docs/design/events.md`.
//!
//! The proto-driven `AUTH_TABLE` enforces the **subject class** + **system
//! scope** gate before this handler runs:
//!   - `RecordEvent`:      `[USER_SELF, SYSTEM]` + `events.write`.
//!   - `RecordEventBatch`: `[USER_SELF, SYSTEM]` + `events.write`.
//!   - `ListEvents`:       `[SYSTEM]` + `events.read`.
//!
//! The handler enforces:
//!   - well-formed `user_id` / `article_id` (UUIDs; soft refs, no FK check),
//!   - `type != UNSPECIFIED`,
//!   - `properties` oneof selector matches `type` (`EVENT_TYPE_MISMATCH`),
//!   - per-type validation (`feed_kind` vocab, `position >= 0`, `dwell_ms` in
//!     `[0, 24h]`, `share.target` non-empty + ≤32 chars),
//!   - `surface` non-empty, ≤32 chars, `[a-z0-9_-]`,
//!   - `occurred_at` within `[now − 24h, now + 60s]` else
//!     `EVENT_TIMESTAMP_OUT_OF_RANGE`,
//!   - user-self path: `user_id == subject.user_id` else
//!     `UNAUTHORIZED_USER_ID` (system-write bypasses this),
//!   - batches: validate everything first; reject the whole batch on first
//!     failure; over-cap → `BATCH_TOO_LARGE`.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use prost_types::Timestamp;
use serde_json::{Value as Json, json};
use tonic::{Request, Response, Status};
use uuid::Uuid;

use headlines_core::HeadlinesError;
use headlines_core::Subject;
use headlines_core::TimeSource;
use headlines_core::repo::PageToken;
use headlines_core::repo::events::{
    Event as DomainEvent, EventRecord, EventRepo, EventType as DomainEventType, ListEventsFilter,
};
use headlines_proto::v1::{
    DwellProperties as ProtoDwell, Event as ProtoEvent, EventType as ProtoEventType,
    ImpressionProperties as ProtoImpression, LikeProperties as ProtoLike, ListEventsRequest,
    ListEventsResponse, OpenProperties as ProtoOpen, RecordEventBatchRequest,
    RecordEventBatchResponse, RecordEventRequest, ShareProperties as ProtoShare,
    UnlikeProperties as ProtoUnlike, event, event_service_server::EventService,
    record_event_request,
};

/// Default cap on `RecordEventBatch` payload size, per `events.md`.
pub const DEFAULT_EVENTS_BATCH_MAX_ITEMS: usize = 500;

/// Allowed feed_kind values per `events.md`.
const FEED_KINDS: &[&str] = &["recommendation", "follow", "account", "direct"];

/// Maximum surface length (chars).
const SURFACE_MAX: usize = 32;

/// Maximum share target length (chars).
const SHARE_TARGET_MAX: usize = 32;

/// 24h in milliseconds — dwell upper bound.
const DWELL_MS_MAX: i64 = 86_400_000;

/// `occurred_at` window: 24h backward, 60s forward.
const OCCURRED_AT_PAST_WINDOW_HOURS: i64 = 24;
const OCCURRED_AT_FUTURE_WINDOW_SECONDS: i64 = 60;

/// Concrete `EventService` impl.
pub struct EventServiceImpl<E, T> {
    pub events: Arc<E>,
    pub time: Arc<T>,
    pub batch_max_items: usize,
    pub metrics: Arc<crate::metrics::DomainMetrics>,
}

impl<E, T> EventServiceImpl<E, T> {
    pub fn new(events: Arc<E>, time: Arc<T>, batch_max_items: usize) -> Self {
        Self {
            events,
            time,
            batch_max_items,
            metrics: crate::metrics::DomainMetrics::shared_no_op(),
        }
    }

    /// Override the default no-op `DomainMetrics`.
    pub fn with_metrics(mut self, metrics: Arc<crate::metrics::DomainMetrics>) -> Self {
        self.metrics = metrics;
        self
    }
}

impl<E, T> EventServiceImpl<E, T>
where
    T: TimeSource,
{
    /// Read a fresh TSO and project the physical-ms component onto a
    /// wall-clock `DateTime<Utc>` for the `occurred_at` window check. The
    /// TSO is the spec'd time source ("now (from TSO)"); pinning the
    /// validation to the TSO's physical clock keeps the window enforcement
    /// monotonic across the server boot cycle.
    async fn tso_now(&self) -> Result<DateTime<Utc>, HeadlinesError> {
        let tso = self
            .time
            .now()
            .await
            .map_err(|e| HeadlinesError::Internal(anyhow::anyhow!("time source: {e}")))?;
        let ms = tso.physical_ms() as i64;
        DateTime::<Utc>::from_timestamp_millis(ms).ok_or_else(|| {
            HeadlinesError::Internal(anyhow::anyhow!("TSO physical_ms out of range: {ms}"))
        })
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

fn ts_to_proto(t: DateTime<Utc>) -> Timestamp {
    Timestamp {
        seconds: t.timestamp(),
        nanos: t.timestamp_subsec_nanos() as i32,
    }
}

fn proto_to_chrono(t: &Timestamp) -> Option<DateTime<Utc>> {
    DateTime::<Utc>::from_timestamp(t.seconds, t.nanos as u32)
}

fn current_subject<T>(req: &Request<T>) -> Subject {
    req.extensions()
        .get::<Subject>()
        .cloned()
        .unwrap_or(Subject::Anonymous)
}

/// Convert the proto `EventType` enum into the wire-string used by the DB
/// `events.type` column. Rejects `UNSPECIFIED`. The mapping is the proto enum
/// name minus the `EVENT_TYPE_` prefix (e.g. `IMPRESSION`).
fn event_type_string(t: i32) -> Result<&'static str, HeadlinesError> {
    let parsed = ProtoEventType::try_from(t).unwrap_or(ProtoEventType::Unspecified);
    Ok(match parsed {
        ProtoEventType::Unspecified => {
            return Err(HeadlinesError::InvalidArgument {
                field: "type".into(),
                reason: "must not be EVENT_TYPE_UNSPECIFIED".into(),
            });
        }
        ProtoEventType::Impression => "IMPRESSION",
        ProtoEventType::Open => "OPEN",
        ProtoEventType::Dwell => "DWELL",
        ProtoEventType::Like => "LIKE",
        ProtoEventType::Unlike => "UNLIKE",
        ProtoEventType::Share => "SHARE",
    })
}

/// Reverse mapping for hydrating `EventType` proto enum from the DB string.
fn event_type_from_string(s: &str) -> i32 {
    match s {
        "IMPRESSION" => ProtoEventType::Impression as i32,
        "OPEN" => ProtoEventType::Open as i32,
        "DWELL" => ProtoEventType::Dwell as i32,
        "LIKE" => ProtoEventType::Like as i32,
        "UNLIKE" => ProtoEventType::Unlike as i32,
        "SHARE" => ProtoEventType::Share as i32,
        _ => ProtoEventType::Unspecified as i32,
    }
}

/// Validate `surface` per `events.md`: non-empty, ≤32 chars, `[a-z0-9_-]`.
fn validate_surface(s: &str) -> Result<(), HeadlinesError> {
    if s.is_empty() {
        return Err(HeadlinesError::InvalidArgument {
            field: "surface".into(),
            reason: "must not be empty".into(),
        });
    }
    if s.chars().count() > SURFACE_MAX {
        return Err(HeadlinesError::InvalidArgument {
            field: "surface".into(),
            reason: format!("must be ≤{SURFACE_MAX} chars"),
        });
    }
    for c in s.chars() {
        if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-') {
            return Err(HeadlinesError::InvalidArgument {
                field: "surface".into(),
                reason: format!("contains disallowed char: {c:?}"),
            });
        }
    }
    Ok(())
}

fn validate_feed_kind(s: &str) -> Result<(), HeadlinesError> {
    if FEED_KINDS.contains(&s) {
        Ok(())
    } else {
        Err(HeadlinesError::InvalidArgument {
            field: "feed_kind".into(),
            reason: format!("must be one of {FEED_KINDS:?}"),
        })
    }
}

fn validate_position(p: i32) -> Result<(), HeadlinesError> {
    if p < 0 {
        Err(HeadlinesError::InvalidArgument {
            field: "position".into(),
            reason: "must be ≥ 0".into(),
        })
    } else {
        Ok(())
    }
}

fn validate_dwell_ms(ms: i64) -> Result<(), HeadlinesError> {
    if !(0..=DWELL_MS_MAX).contains(&ms) {
        Err(HeadlinesError::InvalidArgument {
            field: "dwell_ms".into(),
            reason: format!("must be in [0, {DWELL_MS_MAX}]"),
        })
    } else {
        Ok(())
    }
}

fn validate_share_target(t: &str) -> Result<(), HeadlinesError> {
    if t.is_empty() {
        return Err(HeadlinesError::InvalidArgument {
            field: "target".into(),
            reason: "must not be empty".into(),
        });
    }
    if t.chars().count() > SHARE_TARGET_MAX {
        return Err(HeadlinesError::InvalidArgument {
            field: "target".into(),
            reason: format!("must be ≤{SHARE_TARGET_MAX} chars"),
        });
    }
    Ok(())
}

/// Validate the `properties` oneof against `type`. Returns the JSON shape to
/// store in `events.properties`. The shape is the canonical one documented
/// in `events.md` § Storage:
/// - IMPRESSION → `{"feed_kind": "...", "position": N}`
/// - OPEN       → same shape
/// - DWELL      → `{"dwell_ms": N}`
/// - LIKE       → `{}`
/// - UNLIKE     → `{}`
/// - SHARE      → `{"target": "..."}`
fn validate_properties_for_type(
    type_str: &str,
    properties: &Option<record_event_request::Properties>,
) -> Result<Json, HeadlinesError> {
    use record_event_request::Properties as P;
    match (type_str, properties) {
        ("IMPRESSION", Some(P::Impression(p))) => {
            validate_feed_kind(&p.feed_kind)?;
            validate_position(p.position)?;
            Ok(json!({
                "feed_kind": p.feed_kind,
                "position": p.position,
            }))
        }
        ("OPEN", Some(P::Open(p))) => {
            validate_feed_kind(&p.feed_kind)?;
            validate_position(p.position)?;
            Ok(json!({
                "feed_kind": p.feed_kind,
                "position": p.position,
            }))
        }
        ("DWELL", Some(P::Dwell(p))) => {
            validate_dwell_ms(p.dwell_ms)?;
            Ok(json!({ "dwell_ms": p.dwell_ms }))
        }
        ("LIKE", Some(P::Like(_))) => Ok(json!({})),
        ("UNLIKE", Some(P::Unlike(_))) => Ok(json!({})),
        ("SHARE", Some(P::Share(p))) => {
            validate_share_target(&p.target)?;
            Ok(json!({ "target": p.target }))
        }
        // Selector unset or doesn't match.
        (type_str, properties) => {
            let selector = properties_selector_name(properties);
            Err(HeadlinesError::EventTypeMismatch {
                type_field: type_str.to_owned(),
                properties_field: selector.to_owned(),
            })
        }
    }
}

fn properties_selector_name(p: &Option<record_event_request::Properties>) -> &'static str {
    use record_event_request::Properties as P;
    match p {
        None => "<unset>",
        Some(P::Impression(_)) => "impression",
        Some(P::Open(_)) => "open",
        Some(P::Dwell(_)) => "dwell",
        Some(P::Like(_)) => "like",
        Some(P::Unlike(_)) => "unlike",
        Some(P::Share(_)) => "share",
    }
}

/// Validate `occurred_at` window: `[now − 24h, now + 60s]`.
fn validate_occurred_at(
    occurred_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<(), HeadlinesError> {
    let lower = now - Duration::hours(OCCURRED_AT_PAST_WINDOW_HOURS);
    let upper = now + Duration::seconds(OCCURRED_AT_FUTURE_WINDOW_SECONDS);
    if occurred_at < lower || occurred_at > upper {
        return Err(HeadlinesError::EventTimestampOutOfRange { occurred_at });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Per-event validation + record-record conversion
// ---------------------------------------------------------------------------

/// Result of preparing a single event for insertion. The `EventRecord` is
/// what gets passed to the repo; the `subject_check` flag carries whether the
/// caller's `user_id` was self-validated (`true` for User self, `false` for
/// System path — the system path skips the user-id match check).
struct PreparedEvent {
    record: EventRecord,
}

fn prepare_event(
    req: RecordEventRequest,
    subject: &Subject,
    now: DateTime<Utc>,
) -> Result<PreparedEvent, HeadlinesError> {
    let user_id = parse_uuid("user_id", &req.user_id)?;
    let article_id = parse_uuid("article_id", &req.article_id)?;

    let type_str = event_type_string(req.r#type)?;

    let occurred_at = req
        .occurred_at
        .as_ref()
        .and_then(proto_to_chrono)
        .ok_or_else(|| HeadlinesError::InvalidArgument {
            field: "occurred_at".into(),
            reason: "missing or malformed".into(),
        })?;
    validate_occurred_at(occurred_at, now)?;

    validate_surface(&req.surface)?;

    let properties_json = validate_properties_for_type(type_str, &req.properties)?;

    // Authorization: User-self caller must own the user_id. System path is
    // handled by the caller wrapper since it must apply uniformly across the
    // entire batch.
    if let Subject::User {
        user_id: subject_user_id,
        ..
    } = subject
        && user_id != *subject_user_id
    {
        return Err(HeadlinesError::UnauthorizedUserId {
            expected: *subject_user_id,
            got: user_id,
        });
    }

    Ok(PreparedEvent {
        record: EventRecord {
            user_id,
            article_id: Some(article_id),
            r#type: DomainEventType(type_str.to_owned()),
            occurred_at,
            surface: req.surface,
            properties: properties_json,
        },
    })
}

// ---------------------------------------------------------------------------
// Domain → proto converters
// ---------------------------------------------------------------------------

/// Hand-rolled `DomainEvent → proto::Event` converter. Reconstructs the
/// `properties` oneof from the JSON stored in `events.properties`. Any
/// malformed JSON surfaces as `Internal` since the storage layer should never
/// produce a shape the service didn't write.
fn event_to_proto(e: DomainEvent) -> Result<ProtoEvent, HeadlinesError> {
    use event::Properties as P;
    let type_int = event_type_from_string(&e.r#type.0);
    let properties = match e.r#type.0.as_str() {
        "IMPRESSION" => {
            let (feed_kind, position) = parse_feed_kind_and_position(&e.properties)?;
            Some(P::Impression(ProtoImpression {
                feed_kind,
                position,
            }))
        }
        "OPEN" => {
            let (feed_kind, position) = parse_feed_kind_and_position(&e.properties)?;
            Some(P::Open(ProtoOpen {
                feed_kind,
                position,
            }))
        }
        "DWELL" => {
            let dwell_ms = e
                .properties
                .get("dwell_ms")
                .and_then(Json::as_i64)
                .ok_or_else(|| {
                    HeadlinesError::Internal(anyhow::anyhow!("stored DWELL event missing dwell_ms"))
                })?;
            Some(P::Dwell(ProtoDwell { dwell_ms }))
        }
        "LIKE" => Some(P::Like(ProtoLike {})),
        "UNLIKE" => Some(P::Unlike(ProtoUnlike {})),
        "SHARE" => {
            let target = e
                .properties
                .get("target")
                .and_then(Json::as_str)
                .map(str::to_owned)
                .ok_or_else(|| {
                    HeadlinesError::Internal(anyhow::anyhow!("stored SHARE event missing target"))
                })?;
            Some(P::Share(ProtoShare { target }))
        }
        other => {
            return Err(HeadlinesError::Internal(anyhow::anyhow!(
                "stored event has unknown type: {other}"
            )));
        }
    };

    Ok(ProtoEvent {
        id: e.id.to_string(),
        user_id: e.user_id.to_string(),
        article_id: e.article_id.map(|id| id.to_string()).unwrap_or_default(),
        r#type: type_int,
        occurred_at: Some(ts_to_proto(e.occurred_at)),
        received_at: Some(ts_to_proto(e.received_at)),
        surface: e.surface,
        properties,
    })
}

fn parse_feed_kind_and_position(j: &Json) -> Result<(String, i32), HeadlinesError> {
    let feed_kind = j
        .get("feed_kind")
        .and_then(Json::as_str)
        .map(str::to_owned)
        .ok_or_else(|| {
            HeadlinesError::Internal(anyhow::anyhow!("stored event missing feed_kind"))
        })?;
    let position = j
        .get("position")
        .and_then(Json::as_i64)
        .map(|n| n as i32)
        .ok_or_else(|| {
            HeadlinesError::Internal(anyhow::anyhow!("stored event missing position"))
        })?;
    Ok((feed_kind, position))
}

// ---------------------------------------------------------------------------
// Service impl
// ---------------------------------------------------------------------------

#[async_trait]
impl<E, T> EventService for EventServiceImpl<E, T>
where
    E: EventRepo + 'static,
    T: TimeSource + 'static,
{
    async fn record_event(
        &self,
        request: Request<RecordEventRequest>,
    ) -> Result<Response<ProtoEvent>, Status> {
        let subject = current_subject(&request);
        let req = request.into_inner();

        // Defense-in-depth: the AUTH_TABLE has already restricted to
        // `[USER_SELF, SYSTEM] + events.write`. Anything else surfaces here
        // as PERMISSION_DENIED.
        if !is_authorized_writer(&subject) {
            return Err(Status::permission_denied("events.write required"));
        }

        let now_chrono = self.tso_now().await.map_err(Status::from)?;
        let prepared = prepare_event(req, &subject, now_chrono).map_err(Status::from)?;
        let stored = self
            .events
            .record(prepared.record)
            .await
            .map_err(Status::from)?;
        let proto = event_to_proto(stored).map_err(Status::from)?;
        self.metrics
            .events_recorded
            .add(1, &crate::metrics::no_attrs());
        Ok(Response::new(proto))
    }

    async fn record_event_batch(
        &self,
        request: Request<RecordEventBatchRequest>,
    ) -> Result<Response<RecordEventBatchResponse>, Status> {
        let subject = current_subject(&request);
        let req = request.into_inner();

        if !is_authorized_writer(&subject) {
            return Err(Status::permission_denied("events.write required"));
        }

        if req.events.is_empty() {
            return Err(HeadlinesError::InvalidArgument {
                field: "events".into(),
                reason: "must contain at least one event".into(),
            }
            .into());
        }
        if req.events.len() > self.batch_max_items {
            return Err(HeadlinesError::BatchTooLarge {
                actual: req.events.len(),
                max: self.batch_max_items,
            }
            .into());
        }

        let now_chrono = self.tso_now().await.map_err(Status::from)?;
        // Validate all events first; reject the entire batch on first failure.
        let mut prepared: Vec<EventRecord> = Vec::with_capacity(req.events.len());
        for ev in req.events {
            let p = prepare_event(ev, &subject, now_chrono).map_err(Status::from)?;
            prepared.push(p.record);
        }

        let stored = self
            .events
            .record_batch(prepared)
            .await
            .map_err(Status::from)?;
        let stored_count = stored.len() as i32;
        self.metrics
            .events_recorded
            .add(stored_count as u64, &crate::metrics::no_attrs());
        let recorded: Result<Vec<ProtoEvent>, HeadlinesError> =
            stored.into_iter().map(event_to_proto).collect();
        let recorded = recorded.map_err(Status::from)?;
        Ok(Response::new(RecordEventBatchResponse {
            recorded,
            stored_count,
        }))
    }

    async fn list_events(
        &self,
        request: Request<ListEventsRequest>,
    ) -> Result<Response<ListEventsResponse>, Status> {
        let subject = current_subject(&request);
        let req = request.into_inner();

        // System-only with `events.read`. Defense-in-depth — proto AUTH_TABLE
        // already restricts to `[SYSTEM] + events.read`.
        let allowed = matches!(subject, Subject::System { .. }) && subject.has_scope("events.read");
        if !allowed {
            return Err(Status::permission_denied("events.read required"));
        }

        let user_id = if req.user_id.is_empty() {
            None
        } else {
            Some(parse_uuid("user_id", &req.user_id).map_err(Status::from)?)
        };
        let article_id = if req.article_id.is_empty() {
            None
        } else {
            Some(parse_uuid("article_id", &req.article_id).map_err(Status::from)?)
        };

        let mut types: Vec<DomainEventType> = Vec::with_capacity(req.types.len());
        for t in req.types {
            // Reject UNSPECIFIED in the filter list — silently dropping it
            // would mask a client bug.
            let s = event_type_string(t).map_err(Status::from)?;
            types.push(DomainEventType(s.to_owned()));
        }

        let received_after = req.received_after.as_ref().and_then(proto_to_chrono);
        let received_before = req.received_before.as_ref().and_then(proto_to_chrono);

        let filter = ListEventsFilter {
            user_id,
            article_id,
            types,
            received_after,
            received_before,
        };

        let page = self
            .events
            .list(filter, req.page_size, PageToken(req.page_token))
            .await
            .map_err(Status::from)?;

        let items: Result<Vec<ProtoEvent>, HeadlinesError> =
            page.items.into_iter().map(event_to_proto).collect();
        let items = items.map_err(Status::from)?;
        Ok(Response::new(ListEventsResponse {
            items,
            next_page_token: page.next_page_token.0,
        }))
    }
}

/// Authorization for the write surfaces: User-self (id check happens per-event)
/// or System with `events.write`.
fn is_authorized_writer(subject: &Subject) -> bool {
    match subject {
        Subject::User { .. } => true,
        Subject::System { .. } => subject.has_scope("events.write"),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_now() -> DateTime<Utc> {
        Utc::now()
    }

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
    fn validate_surface_accepts_lowercase_alnum_underscore_dash() {
        // Arrange / Act / Assert
        assert!(validate_surface("web").is_ok());
        assert!(validate_surface("twitter-bot").is_ok());
        assert!(validate_surface("a_b-c1").is_ok());
    }

    #[test]
    fn validate_surface_rejects_empty_uppercase_or_overlong() {
        // Arrange / Act / Assert
        assert!(validate_surface("").is_err());
        assert!(validate_surface("Web").is_err());
        assert!(validate_surface("with space").is_err());
        let too_long = "a".repeat(SURFACE_MAX + 1);
        assert!(validate_surface(&too_long).is_err());
    }

    #[test]
    fn validate_feed_kind_accepts_only_known_values() {
        // Arrange / Act / Assert
        for k in ["recommendation", "follow", "account", "direct"] {
            assert!(validate_feed_kind(k).is_ok());
        }
        assert!(validate_feed_kind("explore").is_err());
        assert!(validate_feed_kind("").is_err());
    }

    #[test]
    fn validate_position_rejects_negative() {
        // Arrange / Act / Assert
        assert!(validate_position(0).is_ok());
        assert!(validate_position(7).is_ok());
        assert!(validate_position(-1).is_err());
    }

    #[test]
    fn validate_dwell_ms_clamps_to_24h() {
        // Arrange / Act / Assert
        assert!(validate_dwell_ms(0).is_ok());
        assert!(validate_dwell_ms(DWELL_MS_MAX).is_ok());
        assert!(validate_dwell_ms(-1).is_err());
        assert!(validate_dwell_ms(DWELL_MS_MAX + 1).is_err());
    }

    #[test]
    fn validate_share_target_rejects_empty_and_overlong() {
        // Arrange / Act / Assert
        assert!(validate_share_target("twitter").is_ok());
        assert!(validate_share_target("").is_err());
        let long = "a".repeat(SHARE_TARGET_MAX + 1);
        assert!(validate_share_target(&long).is_err());
    }

    #[test]
    fn validate_occurred_at_inside_window() {
        // Arrange
        let now = ok_now();

        // Act / Assert
        assert!(validate_occurred_at(now, now).is_ok());
        assert!(validate_occurred_at(now - Duration::hours(1), now).is_ok());
        assert!(validate_occurred_at(now + Duration::seconds(30), now).is_ok());
    }

    #[test]
    fn validate_occurred_at_outside_window_rejects() {
        // Arrange
        let now = ok_now();

        // Act / Assert
        assert!(matches!(
            validate_occurred_at(now - Duration::hours(25), now),
            Err(HeadlinesError::EventTimestampOutOfRange { .. })
        ));
        assert!(matches!(
            validate_occurred_at(now + Duration::minutes(5), now),
            Err(HeadlinesError::EventTimestampOutOfRange { .. })
        ));
    }

    #[test]
    fn event_type_string_rejects_unspecified() {
        // Arrange / Act
        let res = event_type_string(ProtoEventType::Unspecified as i32);

        // Assert
        assert!(matches!(
            res,
            Err(HeadlinesError::InvalidArgument { ref field, .. }) if field == "type"
        ));
    }

    #[test]
    fn event_type_string_round_trips_each_v1_kind() {
        // Arrange / Act / Assert
        for (e, s) in [
            (ProtoEventType::Impression, "IMPRESSION"),
            (ProtoEventType::Open, "OPEN"),
            (ProtoEventType::Dwell, "DWELL"),
            (ProtoEventType::Like, "LIKE"),
            (ProtoEventType::Unlike, "UNLIKE"),
            (ProtoEventType::Share, "SHARE"),
        ] {
            assert_eq!(event_type_string(e as i32).unwrap(), s);
            assert_eq!(event_type_from_string(s), e as i32);
        }
    }

    #[test]
    fn validate_properties_for_type_mismatch_surfaces_event_type_mismatch() {
        // Arrange — type=OPEN with dwell oneof.
        use record_event_request::Properties as P;
        let bad = Some(P::Dwell(ProtoDwell { dwell_ms: 100 }));

        // Act
        let res = validate_properties_for_type("OPEN", &bad);

        // Assert
        assert!(matches!(res, Err(HeadlinesError::EventTypeMismatch { .. })));
    }

    #[test]
    fn validate_properties_for_type_open_returns_storage_json() {
        // Arrange
        use record_event_request::Properties as P;
        let p = Some(P::Open(ProtoOpen {
            feed_kind: "follow".into(),
            position: 3,
        }));

        // Act
        let v = validate_properties_for_type("OPEN", &p).unwrap();

        // Assert — storage JSON shape per `events.md` § Storage.
        assert_eq!(v["feed_kind"], "follow");
        assert_eq!(v["position"], 3);
    }

    #[test]
    fn validate_properties_for_type_like_unlike_emit_empty_object() {
        // Arrange
        use record_event_request::Properties as P;

        // Act
        let lv = validate_properties_for_type("LIKE", &Some(P::Like(ProtoLike {}))).unwrap();
        let uv = validate_properties_for_type("UNLIKE", &Some(P::Unlike(ProtoUnlike {}))).unwrap();

        // Assert
        assert_eq!(lv, json!({}));
        assert_eq!(uv, json!({}));
    }

    #[test]
    fn event_to_proto_round_trips_open_payload() {
        // Arrange
        let domain = DomainEvent {
            id: Uuid::nil(),
            user_id: Uuid::nil(),
            article_id: Some(Uuid::nil()),
            r#type: DomainEventType("OPEN".into()),
            occurred_at: Utc::now(),
            received_at: Utc::now(),
            surface: "web".into(),
            properties: json!({"feed_kind": "recommendation", "position": 5}),
        };

        // Act
        let proto = event_to_proto(domain).unwrap();

        // Assert
        assert_eq!(proto.r#type, ProtoEventType::Open as i32);
        match proto.properties {
            Some(event::Properties::Open(p)) => {
                assert_eq!(p.feed_kind, "recommendation");
                assert_eq!(p.position, 5);
            }
            _ => panic!("expected Open properties"),
        }
    }

    #[test]
    fn event_to_proto_handles_like_with_no_payload() {
        // Arrange
        let domain = DomainEvent {
            id: Uuid::nil(),
            user_id: Uuid::nil(),
            article_id: Some(Uuid::nil()),
            r#type: DomainEventType("LIKE".into()),
            occurred_at: Utc::now(),
            received_at: Utc::now(),
            surface: "web".into(),
            properties: json!({}),
        };

        // Act
        let proto = event_to_proto(domain).unwrap();

        // Assert
        assert!(matches!(proto.properties, Some(event::Properties::Like(_))));
    }

    #[test]
    fn is_authorized_writer_matches_user_or_system_with_scope() {
        // Arrange
        let user = Subject::User {
            user_id: Uuid::nil(),
            key_id: Uuid::nil(),
        };
        let sys_ok = Subject::System {
            system_id: Uuid::nil(),
            key_id: Uuid::nil(),
            scopes: vec!["events.write".into()],
        };
        let sys_no_scope = Subject::System {
            system_id: Uuid::nil(),
            key_id: Uuid::nil(),
            scopes: vec![],
        };

        // Act / Assert
        assert!(is_authorized_writer(&user));
        assert!(is_authorized_writer(&sys_ok));
        assert!(!is_authorized_writer(&sys_no_scope));
        assert!(!is_authorized_writer(&Subject::Anonymous));
    }
}
