//! Central error enum for the entire headlines server.
//!
//! Every variant maps to a stable `ErrorInfo.reason` string from the design
//! docs under `docs/design/`. The `Into<tonic::Status>` impl is the **single**
//! place where domain errors become wire-level gRPC failures, attaching
//! `google.rpc.Status` details with `ErrorInfo` per `api-conventions.md`.
//!
//! Adding a variant must:
//!   1. Pick a SCREAMING_SNAKE reason from the relevant design doc (or extend
//!      the doc + add a design-patch entry).
//!   2. Wire it into `code_and_reason` (and optionally into `metadata`).
//!   3. Add a unit test under `error_mapping` covering the new variant.
//!
//! The enum is `#[non_exhaustive]` so adding a variant is always a non-breaking
//! change for downstream `match` users.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use tonic_types::{ErrorDetails, StatusExt};
use uuid::Uuid;

/// `ErrorInfo.domain` value attached to every status. Per
/// `api-conventions.md` the domain is the proto package.
pub const ERROR_DOMAIN: &str = "headlines.v1";

/// Central domain error type — every component returns this (or wraps it).
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum HeadlinesError {
    // --- accounts.md / users.md / drafts.md / articles.md / follows.md / ... ---
    #[error("account not found: {id}")]
    AccountNotFound { id: Uuid },

    #[error("account deleted: {id}")]
    AccountDeleted { id: Uuid },

    #[error("user not found: {id}")]
    UserNotFound { id: Uuid },

    #[error("user deleted: {id}")]
    UserDeleted { id: Uuid },

    #[error("article not found: {id}")]
    ArticleNotFound { id: Uuid },

    #[error("article tombstoned: {id}")]
    ArticleTombstoned { id: Uuid },

    #[error("draft not found: {id}")]
    DraftNotFound { id: Uuid },

    #[error("draft not publishable: {id} ({reason})")]
    DraftNotPublishable { id: Uuid, reason: String },

    #[error("follow not found: user_id={user_id}, account_id={account_id}")]
    FollowNotFound { user_id: Uuid, account_id: Uuid },

    #[error("self-follow forbidden")]
    SelfFollowForbidden,

    // --- key management (accounts.md, users.md, auth.md) ---
    #[error("key not found: {key_id}")]
    KeyNotFound { key_id: Uuid },

    #[error("key already revoked: {key_id}")]
    KeyAlreadyRevoked { key_id: Uuid },

    #[error("revoke would leave zero active keys")]
    LastActiveKey,

    #[error("invalid public key: {reason}")]
    InvalidPublicKey { reason: String },

    #[error("unsupported algorithm: {algo}")]
    UnsupportedAlgorithm { algo: String },

    #[error("registration disabled for surface {surface}")]
    RegistrationDisabled { surface: String },

    // --- articles.md content / mask ---
    #[error("content too large: {actual} bytes (max {max})")]
    ContentTooLarge { actual: usize, max: usize },

    #[error("invalid node tag: {tag}")]
    InvalidNodeTag { tag: String },

    #[error("invalid node attr {attr} on tag {tag}")]
    InvalidNodeAttr { tag: String, attr: String },

    #[error("update mask is empty")]
    EmptyUpdateMask,

    #[error("unallowed mask path: {path}")]
    UnallowedMaskPath { path: String },

    #[error("article version not found: article_id={article_id}, version={version}")]
    VersionNotFound { article_id: Uuid, version: i32 },

    #[error("version already redacted: article_id={article_id}, version={version}")]
    VersionAlreadyRedacted { article_id: Uuid, version: i32 },

    // --- feeds (feed-recommendation.md / feed-follow.md) ---
    #[error("feed too large: {actual} (max {max})")]
    FeedTooLarge { actual: usize, max: usize },

    #[error("duplicate article id in feed: {id}")]
    DuplicateArticleId { id: Uuid },

    #[error("invalid cursor: {reason}")]
    InvalidCursor { reason: String },

    // --- events.md ---
    #[error("event type {type_field} does not match properties {properties_field}")]
    EventTypeMismatch {
        type_field: String,
        properties_field: String,
    },

    #[error("event timestamp out of range: {occurred_at}")]
    EventTimestampOutOfRange { occurred_at: DateTime<Utc> },

    #[error("batch too large: {actual} (max {max})")]
    BatchTooLarge { actual: usize, max: usize },

    #[error("unauthorized user id: expected {expected}, got {got}")]
    UnauthorizedUserId { expected: Uuid, got: Uuid },

    // --- notifications.md (reserved) ---
    #[error("idempotency key conflict: {key}")]
    IdempotencyKeyMismatch { key: String },

    #[error("rpc not implemented in v1: {rpc}")]
    NotImplementedInV1 { rpc: String },

    // --- catch-alls used everywhere ---
    #[error("invalid argument: field={field}, reason={reason}")]
    InvalidArgument { field: String, reason: String },

    #[error("unauthenticated: {reason}")]
    Unauthenticated { reason: String },

    #[error("internal: {0}")]
    Internal(#[from] anyhow::Error),
}

impl HeadlinesError {
    /// Stable SCREAMING_SNAKE reason string carried in `ErrorInfo.reason`.
    /// Used by clients for programmatic dispatch — must never change without
    /// a `v2` proto bump.
    pub fn reason(&self) -> &'static str {
        self.code_and_reason().1
    }

    /// gRPC status code that this error maps to per the design docs.
    pub fn code(&self) -> tonic::Code {
        self.code_and_reason().0
    }

    /// The single source of truth for `(code, reason)`. Centralised so a
    /// table-style review of every variant stays one function long.
    fn code_and_reason(&self) -> (tonic::Code, &'static str) {
        use tonic::Code;
        match self {
            // NOT_FOUND
            HeadlinesError::AccountNotFound { .. } => (Code::NotFound, "ACCOUNT_NOT_FOUND"),
            HeadlinesError::UserNotFound { .. } => (Code::NotFound, "USER_NOT_FOUND"),
            HeadlinesError::ArticleNotFound { .. } => (Code::NotFound, "ARTICLE_NOT_FOUND"),
            HeadlinesError::DraftNotFound { .. } => (Code::NotFound, "DRAFT_NOT_FOUND"),
            HeadlinesError::FollowNotFound { .. } => (Code::NotFound, "FOLLOW_NOT_FOUND"),
            HeadlinesError::KeyNotFound { .. } => (Code::NotFound, "KEY_NOT_FOUND"),
            HeadlinesError::VersionNotFound { .. } => (Code::NotFound, "VERSION_NOT_FOUND"),

            // FAILED_PRECONDITION
            HeadlinesError::AccountDeleted { .. } => (Code::FailedPrecondition, "ACCOUNT_DELETED"),
            HeadlinesError::UserDeleted { .. } => (Code::FailedPrecondition, "USER_DELETED"),
            HeadlinesError::ArticleTombstoned { .. } => {
                (Code::FailedPrecondition, "ARTICLE_TOMBSTONED")
            }
            HeadlinesError::DraftNotPublishable { .. } => {
                (Code::FailedPrecondition, "DRAFT_NOT_PUBLISHABLE")
            }
            HeadlinesError::LastActiveKey => (Code::FailedPrecondition, "LAST_ACTIVE_KEY"),

            // ALREADY_EXISTS
            HeadlinesError::KeyAlreadyRevoked { .. } => {
                (Code::AlreadyExists, "KEY_ALREADY_REVOKED")
            }
            HeadlinesError::VersionAlreadyRedacted { .. } => {
                (Code::AlreadyExists, "VERSION_ALREADY_REDACTED")
            }

            // INVALID_ARGUMENT
            HeadlinesError::InvalidPublicKey { .. } => {
                (Code::InvalidArgument, "INVALID_PUBLIC_KEY")
            }
            HeadlinesError::UnsupportedAlgorithm { .. } => {
                (Code::InvalidArgument, "UNSUPPORTED_ALGORITHM")
            }
            HeadlinesError::InvalidNodeTag { .. } => (Code::InvalidArgument, "INVALID_NODE_TAG"),
            HeadlinesError::InvalidNodeAttr { .. } => (Code::InvalidArgument, "INVALID_NODE_ATTR"),
            HeadlinesError::EmptyUpdateMask => (Code::InvalidArgument, "EMPTY_UPDATE_MASK"),
            HeadlinesError::UnallowedMaskPath { .. } => {
                (Code::InvalidArgument, "UNALLOWED_MASK_PATH")
            }
            HeadlinesError::DuplicateArticleId { .. } => {
                (Code::InvalidArgument, "DUPLICATE_ARTICLE_ID")
            }
            HeadlinesError::InvalidCursor { .. } => (Code::InvalidArgument, "INVALID_CURSOR"),
            HeadlinesError::EventTypeMismatch { .. } => {
                (Code::InvalidArgument, "EVENT_TYPE_MISMATCH")
            }
            HeadlinesError::EventTimestampOutOfRange { .. } => {
                (Code::InvalidArgument, "EVENT_TIMESTAMP_OUT_OF_RANGE")
            }
            HeadlinesError::SelfFollowForbidden => (Code::InvalidArgument, "SELF_FOLLOW_FORBIDDEN"),
            HeadlinesError::IdempotencyKeyMismatch { .. } => {
                (Code::InvalidArgument, "IDEMPOTENCY_KEY_MISMATCH")
            }
            HeadlinesError::InvalidArgument { .. } => (Code::InvalidArgument, "INVALID_ARGUMENT"),

            // RESOURCE_EXHAUSTED
            HeadlinesError::ContentTooLarge { .. } => {
                (Code::ResourceExhausted, "CONTENT_TOO_LARGE")
            }
            HeadlinesError::FeedTooLarge { .. } => (Code::ResourceExhausted, "FEED_TOO_LARGE"),
            HeadlinesError::BatchTooLarge { .. } => (Code::ResourceExhausted, "BATCH_TOO_LARGE"),

            // PERMISSION_DENIED
            HeadlinesError::RegistrationDisabled { .. } => {
                (Code::PermissionDenied, "REGISTRATION_DISABLED")
            }
            HeadlinesError::UnauthorizedUserId { .. } => {
                (Code::PermissionDenied, "UNAUTHORIZED_USER_ID")
            }

            // UNAUTHENTICATED
            HeadlinesError::Unauthenticated { .. } => (Code::Unauthenticated, "UNAUTHENTICATED"),

            // UNIMPLEMENTED
            HeadlinesError::NotImplementedInV1 { .. } => {
                (Code::Unimplemented, "NOT_IMPLEMENTED_IN_V1")
            }

            // INTERNAL
            HeadlinesError::Internal(_) => (Code::Internal, "INTERNAL"),
        }
    }

    /// Variant-specific metadata copied into `ErrorInfo.metadata`. Keeps
    /// machine-readable context alongside the human-readable message.
    fn metadata(&self) -> HashMap<String, String> {
        let mut m = HashMap::new();
        match self {
            HeadlinesError::AccountNotFound { id } | HeadlinesError::AccountDeleted { id } => {
                m.insert("account_id".into(), id.to_string());
            }
            HeadlinesError::UserNotFound { id } | HeadlinesError::UserDeleted { id } => {
                m.insert("user_id".into(), id.to_string());
            }
            HeadlinesError::ArticleNotFound { id }
            | HeadlinesError::ArticleTombstoned { id }
            | HeadlinesError::DuplicateArticleId { id } => {
                m.insert("article_id".into(), id.to_string());
            }
            HeadlinesError::DraftNotFound { id } => {
                m.insert("draft_id".into(), id.to_string());
            }
            HeadlinesError::DraftNotPublishable { id, reason } => {
                m.insert("draft_id".into(), id.to_string());
                m.insert("reason".into(), reason.clone());
            }
            HeadlinesError::FollowNotFound {
                user_id,
                account_id,
            } => {
                m.insert("user_id".into(), user_id.to_string());
                m.insert("account_id".into(), account_id.to_string());
            }
            HeadlinesError::KeyNotFound { key_id }
            | HeadlinesError::KeyAlreadyRevoked { key_id } => {
                m.insert("key_id".into(), key_id.to_string());
            }
            HeadlinesError::InvalidPublicKey { reason } => {
                m.insert("reason".into(), reason.clone());
            }
            HeadlinesError::UnsupportedAlgorithm { algo } => {
                m.insert("algo".into(), algo.clone());
            }
            HeadlinesError::RegistrationDisabled { surface } => {
                m.insert("surface".into(), surface.clone());
            }
            HeadlinesError::ContentTooLarge { actual, max }
            | HeadlinesError::FeedTooLarge { actual, max }
            | HeadlinesError::BatchTooLarge { actual, max } => {
                m.insert("actual".into(), actual.to_string());
                m.insert("max".into(), max.to_string());
            }
            HeadlinesError::InvalidNodeTag { tag } => {
                m.insert("tag".into(), tag.clone());
            }
            HeadlinesError::InvalidNodeAttr { tag, attr } => {
                m.insert("tag".into(), tag.clone());
                m.insert("attr".into(), attr.clone());
            }
            HeadlinesError::UnallowedMaskPath { path } => {
                m.insert("path".into(), path.clone());
            }
            HeadlinesError::VersionNotFound {
                article_id,
                version,
            }
            | HeadlinesError::VersionAlreadyRedacted {
                article_id,
                version,
            } => {
                m.insert("article_id".into(), article_id.to_string());
                m.insert("version".into(), version.to_string());
            }
            HeadlinesError::InvalidCursor { reason } => {
                m.insert("reason".into(), reason.clone());
            }
            HeadlinesError::EventTypeMismatch {
                type_field,
                properties_field,
            } => {
                m.insert("type".into(), type_field.clone());
                m.insert("properties".into(), properties_field.clone());
            }
            HeadlinesError::EventTimestampOutOfRange { occurred_at } => {
                m.insert("occurred_at".into(), occurred_at.to_rfc3339());
            }
            HeadlinesError::UnauthorizedUserId { expected, got } => {
                m.insert("expected_user_id".into(), expected.to_string());
                m.insert("got_user_id".into(), got.to_string());
            }
            HeadlinesError::IdempotencyKeyMismatch { key } => {
                m.insert("idempotency_key".into(), key.clone());
            }
            HeadlinesError::NotImplementedInV1 { rpc } => {
                m.insert("rpc".into(), rpc.clone());
            }
            HeadlinesError::InvalidArgument { field, reason } => {
                m.insert("field".into(), field.clone());
                m.insert("reason".into(), reason.clone());
            }
            HeadlinesError::Unauthenticated { reason } => {
                m.insert("reason".into(), reason.clone());
            }
            // No structured metadata to attach.
            HeadlinesError::SelfFollowForbidden
            | HeadlinesError::EmptyUpdateMask
            | HeadlinesError::LastActiveKey
            | HeadlinesError::Internal(_) => {}
        }
        m
    }
}

impl From<HeadlinesError> for tonic::Status {
    fn from(err: HeadlinesError) -> Self {
        let (code, reason) = err.code_and_reason();
        let message = err.to_string();
        let metadata = err.metadata();

        // Use `tonic-types` to attach a `google.rpc.ErrorInfo` detail. The
        // resulting `tonic::Status` carries `google.rpc.Status` bytes via
        // `with_details`, exactly matching the wire shape sketched in
        // `api-conventions.md`.
        let mut details = ErrorDetails::new();
        details.set_error_info(reason, ERROR_DOMAIN, metadata);

        tonic::Status::with_error_details(code, message, details)
    }
}

#[cfg(test)]
mod tests {
    //! Coverage policy for `headlines-core` is 100% line coverage. Every
    //! variant of `HeadlinesError` must round-trip through the central
    //! `Into<tonic::Status>` impl with the documented (code, reason) pair.

    use super::*;
    use prost::Message;
    use tonic_types::pb::{ErrorInfo, Status as RpcStatus};

    /// Build a stable list of (variant, expected_code, expected_reason) so we
    /// can iterate every variant in one parameterised assertion. New variants
    /// land here when they're added.
    fn all_variants() -> Vec<(HeadlinesError, tonic::Code, &'static str)> {
        let id = Uuid::nil();
        let other_id = Uuid::from_u128(1);
        vec![
            (
                HeadlinesError::AccountNotFound { id },
                tonic::Code::NotFound,
                "ACCOUNT_NOT_FOUND",
            ),
            (
                HeadlinesError::AccountDeleted { id },
                tonic::Code::FailedPrecondition,
                "ACCOUNT_DELETED",
            ),
            (
                HeadlinesError::UserNotFound { id },
                tonic::Code::NotFound,
                "USER_NOT_FOUND",
            ),
            (
                HeadlinesError::UserDeleted { id },
                tonic::Code::FailedPrecondition,
                "USER_DELETED",
            ),
            (
                HeadlinesError::ArticleNotFound { id },
                tonic::Code::NotFound,
                "ARTICLE_NOT_FOUND",
            ),
            (
                HeadlinesError::ArticleTombstoned { id },
                tonic::Code::FailedPrecondition,
                "ARTICLE_TOMBSTONED",
            ),
            (
                HeadlinesError::DraftNotFound { id },
                tonic::Code::NotFound,
                "DRAFT_NOT_FOUND",
            ),
            (
                HeadlinesError::DraftNotPublishable {
                    id,
                    reason: "missing title".into(),
                },
                tonic::Code::FailedPrecondition,
                "DRAFT_NOT_PUBLISHABLE",
            ),
            (
                HeadlinesError::FollowNotFound {
                    user_id: id,
                    account_id: other_id,
                },
                tonic::Code::NotFound,
                "FOLLOW_NOT_FOUND",
            ),
            (
                HeadlinesError::SelfFollowForbidden,
                tonic::Code::InvalidArgument,
                "SELF_FOLLOW_FORBIDDEN",
            ),
            (
                HeadlinesError::KeyNotFound { key_id: id },
                tonic::Code::NotFound,
                "KEY_NOT_FOUND",
            ),
            (
                HeadlinesError::KeyAlreadyRevoked { key_id: id },
                tonic::Code::AlreadyExists,
                "KEY_ALREADY_REVOKED",
            ),
            (
                HeadlinesError::LastActiveKey,
                tonic::Code::FailedPrecondition,
                "LAST_ACTIVE_KEY",
            ),
            (
                HeadlinesError::InvalidPublicKey {
                    reason: "bad len".into(),
                },
                tonic::Code::InvalidArgument,
                "INVALID_PUBLIC_KEY",
            ),
            (
                HeadlinesError::UnsupportedAlgorithm { algo: "rsa".into() },
                tonic::Code::InvalidArgument,
                "UNSUPPORTED_ALGORITHM",
            ),
            (
                HeadlinesError::RegistrationDisabled {
                    surface: "users".into(),
                },
                tonic::Code::PermissionDenied,
                "REGISTRATION_DISABLED",
            ),
            (
                HeadlinesError::ContentTooLarge {
                    actual: 21,
                    max: 20,
                },
                tonic::Code::ResourceExhausted,
                "CONTENT_TOO_LARGE",
            ),
            (
                HeadlinesError::InvalidNodeTag {
                    tag: "marquee".into(),
                },
                tonic::Code::InvalidArgument,
                "INVALID_NODE_TAG",
            ),
            (
                HeadlinesError::InvalidNodeAttr {
                    tag: "a".into(),
                    attr: "onclick".into(),
                },
                tonic::Code::InvalidArgument,
                "INVALID_NODE_ATTR",
            ),
            (
                HeadlinesError::EmptyUpdateMask,
                tonic::Code::InvalidArgument,
                "EMPTY_UPDATE_MASK",
            ),
            (
                HeadlinesError::UnallowedMaskPath { path: "id".into() },
                tonic::Code::InvalidArgument,
                "UNALLOWED_MASK_PATH",
            ),
            (
                HeadlinesError::VersionNotFound {
                    article_id: id,
                    version: 99,
                },
                tonic::Code::NotFound,
                "VERSION_NOT_FOUND",
            ),
            (
                HeadlinesError::VersionAlreadyRedacted {
                    article_id: id,
                    version: 1,
                },
                tonic::Code::AlreadyExists,
                "VERSION_ALREADY_REDACTED",
            ),
            (
                HeadlinesError::FeedTooLarge {
                    actual: 6000,
                    max: 5000,
                },
                tonic::Code::ResourceExhausted,
                "FEED_TOO_LARGE",
            ),
            (
                HeadlinesError::DuplicateArticleId { id },
                tonic::Code::InvalidArgument,
                "DUPLICATE_ARTICLE_ID",
            ),
            (
                HeadlinesError::InvalidCursor {
                    reason: "base64 decode".into(),
                },
                tonic::Code::InvalidArgument,
                "INVALID_CURSOR",
            ),
            (
                HeadlinesError::EventTypeMismatch {
                    type_field: "OPEN".into(),
                    properties_field: "dwell".into(),
                },
                tonic::Code::InvalidArgument,
                "EVENT_TYPE_MISMATCH",
            ),
            (
                HeadlinesError::EventTimestampOutOfRange {
                    occurred_at: chrono::Utc
                        .with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
                        .single()
                        .expect("valid date"),
                },
                tonic::Code::InvalidArgument,
                "EVENT_TIMESTAMP_OUT_OF_RANGE",
            ),
            (
                HeadlinesError::BatchTooLarge {
                    actual: 600,
                    max: 500,
                },
                tonic::Code::ResourceExhausted,
                "BATCH_TOO_LARGE",
            ),
            (
                HeadlinesError::UnauthorizedUserId {
                    expected: id,
                    got: other_id,
                },
                tonic::Code::PermissionDenied,
                "UNAUTHORIZED_USER_ID",
            ),
            (
                HeadlinesError::IdempotencyKeyMismatch { key: "k".into() },
                tonic::Code::InvalidArgument,
                "IDEMPOTENCY_KEY_MISMATCH",
            ),
            (
                HeadlinesError::NotImplementedInV1 {
                    rpc: "/headlines.v1.NotificationService/SendNotification".into(),
                },
                tonic::Code::Unimplemented,
                "NOT_IMPLEMENTED_IN_V1",
            ),
            (
                HeadlinesError::InvalidArgument {
                    field: "title".into(),
                    reason: "too long".into(),
                },
                tonic::Code::InvalidArgument,
                "INVALID_ARGUMENT",
            ),
            (
                HeadlinesError::Unauthenticated {
                    reason: "expired ts".into(),
                },
                tonic::Code::Unauthenticated,
                "UNAUTHENTICATED",
            ),
            (
                HeadlinesError::Internal(anyhow::anyhow!("disk on fire")),
                tonic::Code::Internal,
                "INTERNAL",
            ),
        ]
    }

    use chrono::TimeZone;

    #[test]
    fn each_variant_has_documented_code_and_reason() {
        // Arrange
        let cases = all_variants();

        for (err, expected_code, expected_reason) in cases {
            // Act
            let code = err.code();
            let reason = err.reason();

            // Assert
            assert_eq!(
                code, expected_code,
                "wrong code for reason {expected_reason}"
            );
            assert_eq!(reason, expected_reason);
        }
    }

    #[test]
    fn into_tonic_status_attaches_error_info_with_domain() {
        // Arrange
        let err = HeadlinesError::AccountNotFound {
            id: Uuid::from_u128(0xa11ce),
        };

        // Act
        let status: tonic::Status = err.into();

        // Assert
        assert_eq!(status.code(), tonic::Code::NotFound);
        let details_bytes = status.details();
        assert!(
            !details_bytes.is_empty(),
            "status must carry google.rpc.Status details bytes"
        );
        let rpc_status = RpcStatus::decode(details_bytes).expect("decode google.rpc.Status");
        assert_eq!(rpc_status.code, tonic::Code::NotFound as i32);
        assert_eq!(rpc_status.details.len(), 1);
        let any = &rpc_status.details[0];
        assert_eq!(any.type_url, "type.googleapis.com/google.rpc.ErrorInfo");
        let info = ErrorInfo::decode(any.value.as_ref()).expect("decode ErrorInfo");
        assert_eq!(info.reason, "ACCOUNT_NOT_FOUND");
        assert_eq!(info.domain, ERROR_DOMAIN);
        assert_eq!(
            info.metadata.get("account_id").map(String::as_str),
            Some("00000000-0000-0000-0000-0000000a11ce")
        );
    }

    #[test]
    fn each_variant_round_trips_to_status_with_matching_reason() {
        for (err, expected_code, expected_reason) in all_variants() {
            // Arrange
            let display = err.to_string();

            // Act
            let status: tonic::Status = err.into();

            // Assert
            assert_eq!(status.code(), expected_code, "code for {expected_reason}");
            assert_eq!(status.message(), display, "message for {expected_reason}");

            let rpc_status = RpcStatus::decode(status.details()).expect("decode google.rpc.Status");
            assert_eq!(rpc_status.code, expected_code as i32);
            let any = rpc_status
                .details
                .first()
                .expect("at least one detail (ErrorInfo)");
            let info = ErrorInfo::decode(any.value.as_ref()).expect("decode ErrorInfo");
            assert_eq!(info.reason, expected_reason);
            assert_eq!(info.domain, ERROR_DOMAIN);
        }
    }

    #[test]
    fn anyhow_converts_into_internal_variant() {
        // Arrange
        let underlying: anyhow::Error = anyhow::anyhow!("boom");

        // Act
        let err: HeadlinesError = underlying.into();

        // Assert
        assert!(matches!(err, HeadlinesError::Internal(_)));
        assert_eq!(err.code(), tonic::Code::Internal);
        assert_eq!(err.reason(), "INTERNAL");
    }

    #[test]
    fn metadata_includes_structured_fields_per_variant() {
        // Arrange
        let err = HeadlinesError::ContentTooLarge {
            actual: 100,
            max: 50,
        };

        // Act
        let m = err.metadata();

        // Assert
        assert_eq!(m.get("actual").map(String::as_str), Some("100"));
        assert_eq!(m.get("max").map(String::as_str), Some("50"));
    }
}
