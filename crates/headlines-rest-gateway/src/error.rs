//! REST gateway error type.
//!
//! Translates `tonic::Status` into:
//!
//! - HTTP status per the `gRPC code → HTTP status` table in
//!   `docs/design/api-conventions.md`.
//! - JSON body shaped like `google.rpc.Status` (top-level `code`, `message`,
//!   `details[]`).
//!
//! Design-doc-quoted table:
//!
//! ```text
//! OK                  → 200
//! INVALID_ARGUMENT    → 400
//! UNAUTHENTICATED     → 401
//! PERMISSION_DENIED   → 403
//! NOT_FOUND           → 404
//! ALREADY_EXISTS      → 409
//! FAILED_PRECONDITION → 400
//! RESOURCE_EXHAUSTED  → 429
//! UNIMPLEMENTED       → 501
//! INTERNAL            → 500
//! UNAVAILABLE         → 503
//! ```

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use prost::Message;
use serde_json::{Map, Value, json};
use tonic_types::pb::{ErrorInfo, Status as RpcStatus};

/// Surface for REST gateway handlers. Either a `tonic::Status` (the typical
/// case — upstream gRPC said no) or a transport error reaching the gRPC
/// service at all.
#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    #[error("gRPC status: {0}")]
    Grpc(#[from] tonic::Status),
    #[error("gRPC transport: {0}")]
    Transport(#[from] tonic::transport::Error),
}

impl IntoResponse for GatewayError {
    fn into_response(self) -> Response {
        let (status, code, message, details) = match &self {
            GatewayError::Grpc(s) => (
                grpc_code_to_http(s.code()),
                s.code() as i32,
                s.message().to_owned(),
                decode_status_details(s.details()),
            ),
            GatewayError::Transport(e) => (
                StatusCode::SERVICE_UNAVAILABLE,
                tonic::Code::Unavailable as i32,
                e.to_string(),
                Vec::new(),
            ),
        };

        let body = json!({
            "code": code,
            "message": message,
            "details": details,
        });
        (status, axum::response::Json(body)).into_response()
    }
}

/// Decode the `with_details(...)` bytes carried by `tonic::Status` (a
/// `google.rpc.Status` payload) and project each known `Any` detail into a
/// JSON object.
///
/// Today the only detail type the server attaches is `google.rpc.ErrorInfo`
/// (see `headlines-core::error::HeadlinesError → tonic::Status`). Unknown
/// detail types are passed through as `{ "@type": <type_url> }` so we never
/// silently drop information.
///
/// Returns an empty `Vec` if the bytes are absent (e.g. raw
/// `tonic::Status::not_found("…")` from below the service layer) or fail to
/// decode — we never fabricate a detail in that case.
fn decode_status_details(details_bytes: &[u8]) -> Vec<Value> {
    if details_bytes.is_empty() {
        return Vec::new();
    }
    let Ok(rpc_status) = RpcStatus::decode(details_bytes) else {
        return Vec::new();
    };
    rpc_status.details.iter().map(any_to_json_detail).collect()
}

/// Project a `google.protobuf.Any` carried inside `google.rpc.Status.details`
/// into a JSON object. We only specialise `ErrorInfo` today; everything else
/// gets a stub `{"@type": ...}` so future detail types surface visibly even
/// before the gateway gains an explicit projection.
fn any_to_json_detail(any: &prost_types::Any) -> Value {
    let type_url = any.type_url.as_str();
    if type_url == "type.googleapis.com/google.rpc.ErrorInfo"
        && let Ok(info) = ErrorInfo::decode(any.value.as_ref())
    {
        let mut metadata = Map::new();
        let mut keys: Vec<&String> = info.metadata.keys().collect();
        keys.sort();
        for k in keys {
            if let Some(v) = info.metadata.get(k) {
                metadata.insert(k.clone(), Value::String(v.clone()));
            }
        }
        return json!({
            "@type": type_url,
            "reason": info.reason,
            "domain": info.domain,
            "metadata": Value::Object(metadata),
        });
    }
    json!({ "@type": type_url })
}

/// Map a `tonic::Code` to an HTTP status code per `api-conventions.md`.
/// Anything not in the table falls back to 500.
pub fn grpc_code_to_http(code: tonic::Code) -> StatusCode {
    match code {
        tonic::Code::Ok => StatusCode::OK,
        tonic::Code::InvalidArgument => StatusCode::BAD_REQUEST,
        tonic::Code::Unauthenticated => StatusCode::UNAUTHORIZED,
        tonic::Code::PermissionDenied => StatusCode::FORBIDDEN,
        tonic::Code::NotFound => StatusCode::NOT_FOUND,
        tonic::Code::AlreadyExists => StatusCode::CONFLICT,
        tonic::Code::FailedPrecondition => StatusCode::BAD_REQUEST,
        tonic::Code::ResourceExhausted => StatusCode::TOO_MANY_REQUESTS,
        tonic::Code::Unimplemented => StatusCode::NOT_IMPLEMENTED,
        tonic::Code::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        tonic::Code::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        tonic::Code::Cancelled
        | tonic::Code::Unknown
        | tonic::Code::DeadlineExceeded
        | tonic::Code::Aborted
        | tonic::Code::OutOfRange
        | tonic::Code::DataLoss => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ok_maps_to_200() {
        assert_eq!(grpc_code_to_http(tonic::Code::Ok), StatusCode::OK);
    }

    #[test]
    fn invalid_argument_maps_to_400() {
        assert_eq!(
            grpc_code_to_http(tonic::Code::InvalidArgument),
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn unauthenticated_maps_to_401() {
        assert_eq!(
            grpc_code_to_http(tonic::Code::Unauthenticated),
            StatusCode::UNAUTHORIZED
        );
    }

    #[test]
    fn permission_denied_maps_to_403() {
        assert_eq!(
            grpc_code_to_http(tonic::Code::PermissionDenied),
            StatusCode::FORBIDDEN
        );
    }

    #[test]
    fn not_found_maps_to_404() {
        assert_eq!(
            grpc_code_to_http(tonic::Code::NotFound),
            StatusCode::NOT_FOUND
        );
    }

    #[test]
    fn already_exists_maps_to_409() {
        assert_eq!(
            grpc_code_to_http(tonic::Code::AlreadyExists),
            StatusCode::CONFLICT
        );
    }

    #[test]
    fn failed_precondition_maps_to_400() {
        assert_eq!(
            grpc_code_to_http(tonic::Code::FailedPrecondition),
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn resource_exhausted_maps_to_429() {
        assert_eq!(
            grpc_code_to_http(tonic::Code::ResourceExhausted),
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[test]
    fn unimplemented_maps_to_501() {
        assert_eq!(
            grpc_code_to_http(tonic::Code::Unimplemented),
            StatusCode::NOT_IMPLEMENTED
        );
    }

    #[test]
    fn internal_maps_to_500() {
        assert_eq!(
            grpc_code_to_http(tonic::Code::Internal),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn unavailable_maps_to_503() {
        assert_eq!(
            grpc_code_to_http(tonic::Code::Unavailable),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[test]
    fn unmapped_codes_fall_back_to_500() {
        // Arrange / Act / Assert — any unmapped code falls back to 500.
        for c in [
            tonic::Code::Cancelled,
            tonic::Code::Unknown,
            tonic::Code::DeadlineExceeded,
            tonic::Code::Aborted,
            tonic::Code::OutOfRange,
            tonic::Code::DataLoss,
        ] {
            assert_eq!(grpc_code_to_http(c), StatusCode::INTERNAL_SERVER_ERROR);
        }
    }

    #[tokio::test]
    async fn into_response_emits_empty_details_when_status_has_none() {
        // Arrange — raw `tonic::Status::not_found(...)` carries no
        // `with_details(...)` bytes; we must emit `details: []` rather
        // than fabricate an `ErrorInfo`.
        let err = GatewayError::Grpc(tonic::Status::not_found("nope"));

        // Act
        let resp = err.into_response();

        // Assert
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let body_bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(body["code"], tonic::Code::NotFound as i32);
        assert_eq!(body["message"], "nope");
        let details = body["details"].as_array().expect("details must be array");
        assert!(details.is_empty(), "raw status carries no details");
    }

    #[tokio::test]
    async fn into_response_projects_error_info_detail() {
        // Arrange — a status carrying a `google.rpc.ErrorInfo` detail (the
        // shape produced by `HeadlinesError → tonic::Status` upstream).
        use std::collections::HashMap;
        use tonic_types::{ErrorDetails, StatusExt};

        let mut metadata: HashMap<String, String> = HashMap::new();
        metadata.insert("account_id".into(), "abc-123".into());
        let mut details = ErrorDetails::new();
        details.set_error_info("ACCOUNT_NOT_FOUND", "headlines.v1", metadata);
        let status =
            tonic::Status::with_error_details(tonic::Code::NotFound, "missing acct", details);
        let err = GatewayError::Grpc(status);

        // Act
        let resp = err.into_response();

        // Assert — body carries a single `ErrorInfo`-shaped detail with the
        // expected `@type`, `reason`, `domain`, and `metadata`.
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let body_bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(body["code"], tonic::Code::NotFound as i32);
        assert_eq!(body["message"], "missing acct");
        let arr = body["details"].as_array().expect("details must be array");
        assert_eq!(arr.len(), 1, "one ErrorInfo detail expected");
        assert_eq!(arr[0]["@type"], "type.googleapis.com/google.rpc.ErrorInfo");
        assert_eq!(arr[0]["reason"], "ACCOUNT_NOT_FOUND");
        assert_eq!(arr[0]["domain"], "headlines.v1");
        assert_eq!(arr[0]["metadata"]["account_id"], "abc-123");
    }
}
