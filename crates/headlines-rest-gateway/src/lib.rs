//! Rust-native REST → gRPC proxy built on axum.
//!
//! Phase 6 stood up the first route (`GET /v1/accounts/:id`); Phase 7's
//! per-service sub-phases extend the route table. Phase 7.1 adds the
//! UserService surface (`/v1/users/*`).
//!
//! JSON encoding decision: we hand-roll the `*` → `serde_json::Value`
//! conversions. `pbjson` would require generating extra code in
//! `headlines-proto` and tweaking the build script; for the modest number of
//! routes the manual converter is a smaller change with a smaller blast
//! radius. Phase 7 may revisit if the per-route boilerplate gets painful.
//!
//! ## Authentication (REST)
//!
//! The gateway runs the **full** `SignedRequestStrategy` against every
//! inbound REST request whose `Authorization` header is present, with the
//! canonical built off the **REST URL** (so clients sign the URL they
//! actually called, not a downstream gRPC path). On success it forwards
//! the resolved `Subject` to the trusted in-process gRPC listener via
//! `headlines_auth::TRUSTED_SUBJECT_HEADER`, then strips the inbound
//! `Authorization` so it never escapes the gateway. The gRPC service on
//! the trusted listener uses
//! `headlines_auth::TrustedSubjectInterceptor` to lift the subject into
//! request extensions for `AuthorizationLayer`.
//!
//! Anonymous-allowed REST routes (no `Authorization` header) get
//! `Subject::Anonymous` propagated the same way; `AuthorizationLayer`
//! consults the proto-driven `AUTH_TABLE` to allow or deny.

pub mod error;

use std::sync::Arc;

use axum::Router;
use axum::extract::{FromRequest, Path, Request, State};
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::http::header;
use axum::response::{IntoResponse, Json};
use axum::routing::{delete as axum_delete, get, patch, post, put};
use chrono::{TimeZone, Utc};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use tonic::transport::Channel;
use tower_http::cors::CorsLayer;
use tower_http::decompression::RequestDecompressionLayer;

use headlines_auth::{
    SignedRequestStrategy, TRUSTED_SUBJECT_HEADER, canonicalize_query, parse_authorization_header,
};
use headlines_core::{AuthError, AuthStrategy as _, SignedRequestParts, Subject};

use headlines_proto::v1::AccountStatus;
use headlines_proto::v1::ArticleState;
use headlines_proto::v1::EventType as ProtoEventType;
use headlines_proto::v1::FollowStatus;
use headlines_proto::v1::KeyStatus;
use headlines_proto::v1::UserStatus;
use headlines_proto::v1::account_service_client::AccountServiceClient;
use headlines_proto::v1::account_stream_service_client::AccountStreamServiceClient;
use headlines_proto::v1::article_service_client::ArticleServiceClient;
use headlines_proto::v1::draft_service_client::DraftServiceClient;
use headlines_proto::v1::event_service_client::EventServiceClient;
use headlines_proto::v1::feed_follow_service_client::FeedFollowServiceClient;
use headlines_proto::v1::feed_recommendation_service_client::FeedRecommendationServiceClient;
use headlines_proto::v1::follow_service_client::FollowServiceClient;
use headlines_proto::v1::notification_service_client::NotificationServiceClient;
use headlines_proto::v1::user_service_client::UserServiceClient;

pub use error::GatewayError;

/// JSON body extractor that wraps `axum::Json<T>` and converts the stock
/// `JsonRejection` into a `GatewayError`. The `IntoResponse` for
/// `GatewayError` then emits the standard `{ code, message, details }`
/// envelope, so body-parsing failures (malformed JSON, wrong Content-Type,
/// oversized body, missing field) match the same error shape every other
/// REST surface returns. Replaces every `Json<Value>` extractor in the
/// route handlers below.
pub struct EnvelopeJson<T>(pub T);

#[async_trait::async_trait]
impl<S, T> FromRequest<S> for EnvelopeJson<T>
where
    S: Send + Sync,
    T: serde::de::DeserializeOwned,
{
    type Rejection = GatewayError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match axum::Json::<T>::from_request(req, state).await {
            Ok(axum::Json(value)) => Ok(EnvelopeJson(value)),
            Err(rejection) => Err(GatewayError::from(rejection)),
        }
    }
}

/// Shared state given to each axum handler.
#[derive(Clone)]
pub struct GatewayState {
    pub account_client: AccountServiceClient<Channel>,
    pub user_client: UserServiceClient<Channel>,
    pub article_client: ArticleServiceClient<Channel>,
    pub draft_client: DraftServiceClient<Channel>,
    pub follow_client: FollowServiceClient<Channel>,
    pub feed_recommendation_client: FeedRecommendationServiceClient<Channel>,
    pub feed_follow_client: FeedFollowServiceClient<Channel>,
    pub account_stream_client: AccountStreamServiceClient<Channel>,
    pub event_client: EventServiceClient<Channel>,
    pub notification_client: NotificationServiceClient<Channel>,
    /// Same `SignedRequestStrategy` instance the gRPC server uses on its
    /// public listener (shared `KeyResolver` / `TimeSource` / `NonceStore`
    /// /  `AlgorithmRegistry`). Replay state stays single-source.
    pub auth_strategy: Arc<SignedRequestStrategy>,
}

/// Build the axum router with all REST routes wired to the upstream gRPC
/// `Channel`.
///
/// `grpc_endpoint` must include the scheme — e.g. `http://127.0.0.1:50051`.
/// The returned router takes ownership of one cloned channel per upstream
/// service client. `auth_strategy` is the shared
/// [`SignedRequestStrategy`] the gateway runs against inbound REST
/// requests; it must point at the same `KeyResolver` / `TimeSource` /
/// `NonceStore` / `AlgorithmRegistry` instances the public gRPC server
/// uses, so replay/TSO state stays single-source.
pub async fn build_app(
    grpc_endpoint: &str,
    auth_strategy: Arc<SignedRequestStrategy>,
) -> anyhow::Result<Router> {
    let channel = Channel::from_shared(grpc_endpoint.to_owned())?
        .connect()
        .await?;
    let account_client = AccountServiceClient::new(channel.clone());
    let user_client = UserServiceClient::new(channel.clone());
    let article_client = ArticleServiceClient::new(channel.clone());
    let draft_client = DraftServiceClient::new(channel.clone());
    let follow_client = FollowServiceClient::new(channel.clone());
    let feed_recommendation_client = FeedRecommendationServiceClient::new(channel.clone());
    let feed_follow_client = FeedFollowServiceClient::new(channel.clone());
    let account_stream_client = AccountStreamServiceClient::new(channel.clone());
    let event_client = EventServiceClient::new(channel.clone());
    let notification_client = NotificationServiceClient::new(channel);
    Ok(build_router(GatewayState {
        account_client,
        user_client,
        article_client,
        draft_client,
        follow_client,
        feed_recommendation_client,
        feed_follow_client,
        account_stream_client,
        event_client,
        notification_client,
        auth_strategy,
    }))
}

/// Static OpenAPI/Swagger JSON, embedded at build time. Generated by
/// `buf generate` from `proto/**/*.proto` using the
/// `buf.build/grpc-ecosystem/openapiv2` plugin (see `buf.gen.yaml`). The
/// generated file lives in `gen/openapi/headlines.swagger.json`; the
/// `openapi-drift` CI job re-runs `buf generate` and refuses to merge
/// when the committed file diverges.
const OPENAPI_JSON: &str = include_str!("../../../gen/openapi/headlines.swagger.json");

/// `GET /openapi.json` — anonymous-readable. The body is embedded at build
/// time so the gateway can serve it without filesystem access at runtime.
async fn get_openapi() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "application/json")], OPENAPI_JSON)
}

/// `GET /healthz` — liveness probe. Anonymous, no DB, no auth. Returns
/// `200 OK` with `{"status": "ok"}` so external load balancers can verify
/// the REST surface is up. Skips the auth pipeline because the route
/// emits a constant body and never depends on backend state.
async fn get_healthz() -> impl IntoResponse {
    (StatusCode::OK, Json(json!({"status": "ok"})))
}

/// Build the router from an already-constructed state. Splitting this out
/// keeps the test path connection-free.
///
/// Middleware stack (applied bottom-up):
///
/// - `CorsLayer::permissive()` — v1 default. Production deployments should
///   tighten this with an explicit origin allow-list and credentials policy.
/// - `RequestDecompressionLayer` — transparently decodes
///   `Content-Encoding: gzip` request bodies so clients can compress JSON
///   payloads without having to special-case the gateway.
fn build_router(state: GatewayState) -> Router {
    Router::new()
        .route("/healthz", get(get_healthz))
        .route("/openapi.json", get(get_openapi))
        .route("/v1/accounts", post(create_account))
        .route("/v1/accounts/:id", get(get_account))
        .route("/v1/users", post(create_user))
        .route("/v1/users/:id", get(get_user))
        .route("/v1/users/:id", patch(update_user))
        .route("/v1/users/:id", axum_delete(delete_user))
        .route("/v1/users/:id/keys", post(add_user_key))
        .route("/v1/users/:id/keys/:key_id/revoke", post(revoke_user_key))
        .route(
            "/v1/accounts/:account_id/articles",
            post(publish_article).get(list_account_articles),
        )
        .route(
            "/v1/articles/:id",
            get(get_article_handler).patch(edit_article),
        )
        .route("/v1/articles/:id/tombstone", post(tombstone_article))
        .route(
            "/v1/articles/:article_id/versions/:version/redact",
            post(redact_article_version),
        )
        .route(
            "/v1/accounts/:account_id/drafts",
            post(create_draft).get(list_account_drafts),
        )
        .route(
            "/v1/drafts/:id",
            get(get_draft).patch(update_draft).delete(delete_draft),
        )
        .route("/v1/drafts/:id/publish", post(publish_draft))
        .route(
            "/v1/users/:user_id/follows",
            post(follow_user).get(list_user_follows),
        )
        .route(
            "/v1/users/:user_id/follows/:account_id",
            get(get_follow).delete(unfollow_user),
        )
        .route(
            "/v1/accounts/:account_id/followers",
            get(list_account_followers),
        )
        .route(
            "/v1/users/:user_id/feed/recommendation",
            put(replace_recommendation_feed).get(get_recommendation_feed),
        )
        .route("/v1/users/:user_id/feed/follow", get(get_follow_feed))
        .route(
            "/v1/accounts/:account_id/article-stream",
            get(stream_account_articles),
        )
        .route("/v1/events", post(record_event).get(list_events))
        .route("/v1/events:batch", post(record_event_batch))
        .route("/v1/notifications", post(send_notification))
        .route("/v1/notifications:batch", post(send_notification_batch))
        .route(
            "/v1/users/:user_id/notifications",
            get(list_user_notifications),
        )
        .route("/v1/notifications/:id/read", post(mark_notification_read))
        .route(
            "/v1/users/:user_id/notifications:mark-all-read",
            post(mark_all_user_notifications_read),
        )
        .route(
            "/v1/users/:user_id/notification-preferences",
            get(get_user_notification_preferences).patch(update_user_notification_preferences),
        )
        .with_state(state)
        // Decompression first (request hits this before any handler), then
        // CORS so OPTIONS preflights short-circuit without the body layer.
        .layer(RequestDecompressionLayer::new().gzip(true))
        .layer(CorsLayer::permissive())
}

/// `POST /v1/accounts` — forwards to `AccountService.CreateAccount`.
///
/// Body shape: `{ short_name, author_name, author_url?, initial_key: { algo,
/// public_key } }`. Mirrors the `POST /v1/users` handler.
async fn create_account(
    State(mut state): State<GatewayState>,
    method: axum::http::Method,
    axum::extract::OriginalUri(original_uri): axum::extract::OriginalUri,
    headers: HeaderMap,
    EnvelopeJson(body): EnvelopeJson<Value>,
) -> Result<Json<Value>, GatewayError> {
    let short_name = body
        .get("short_name")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let author_name = body
        .get("author_name")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let author_url = body
        .get("author_url")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let initial_key = body.get("initial_key").map(parse_public_key);
    let mut req = tonic::Request::new(headlines_proto::v1::CreateAccountRequest {
        short_name,
        author_name,
        author_url,
        initial_key,
    });
    attach_auth(
        method.as_str(),
        original_uri.path(),
        original_uri.query().unwrap_or(""),
        &headers,
        &mut req,
        &state.auth_strategy,
    )
    .await?;
    let resp = state.account_client.create_account(req).await?.into_inner();
    Ok(Json(json!({
        "account": resp.account.as_ref().map(account_to_json),
        "key_id": resp.key_id,
    })))
}

/// `GET /v1/accounts/{id}` — forwards to `AccountService.GetAccount`.
async fn get_account(
    State(mut state): State<GatewayState>,
    method: axum::http::Method,
    axum::extract::OriginalUri(original_uri): axum::extract::OriginalUri,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, GatewayError> {
    let mut req = tonic::Request::new(headlines_proto::v1::GetAccountRequest { id });
    attach_auth(
        method.as_str(),
        original_uri.path(),
        original_uri.query().unwrap_or(""),
        &headers,
        &mut req,
        &state.auth_strategy,
    )
    .await?;
    let resp = state.account_client.get_account(req).await?;
    Ok(Json(account_to_json(&resp.into_inner())))
}

// ---------------------------------------------------------------------------
// UserService routes
// ---------------------------------------------------------------------------

/// `POST /v1/users` — forwards to `UserService.CreateUser`.
async fn create_user(
    State(mut state): State<GatewayState>,
    method: axum::http::Method,
    axum::extract::OriginalUri(original_uri): axum::extract::OriginalUri,
    headers: HeaderMap,
    EnvelopeJson(body): EnvelopeJson<Value>,
) -> Result<Json<Value>, GatewayError> {
    let display_name = body
        .get("display_name")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let initial_key = body.get("initial_key").map(parse_public_key);
    let mut req = tonic::Request::new(headlines_proto::v1::CreateUserRequest {
        display_name,
        initial_key,
    });
    attach_auth(
        method.as_str(),
        original_uri.path(),
        original_uri.query().unwrap_or(""),
        &headers,
        &mut req,
        &state.auth_strategy,
    )
    .await?;
    let resp = state.user_client.create_user(req).await?.into_inner();
    Ok(Json(json!({
        "user": resp.user.as_ref().map(user_to_json),
        "key_id": resp.key_id,
    })))
}

/// `GET /v1/users/{id}` — forwards to `UserService.GetUser`.
async fn get_user(
    State(mut state): State<GatewayState>,
    method: axum::http::Method,
    axum::extract::OriginalUri(original_uri): axum::extract::OriginalUri,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, GatewayError> {
    let mut req = tonic::Request::new(headlines_proto::v1::GetUserRequest { id });
    attach_auth(
        method.as_str(),
        original_uri.path(),
        original_uri.query().unwrap_or(""),
        &headers,
        &mut req,
        &state.auth_strategy,
    )
    .await?;
    let resp = state.user_client.get_user(req).await?;
    Ok(Json(user_to_json(&resp.into_inner())))
}

/// `PATCH /v1/users/{id}` — forwards to `UserService.UpdateUser`.
///
/// Body is the JSON-encoded `User` minus the id (the id comes from the
/// path) plus an optional `update_mask` carrying a `paths` string array.
async fn update_user(
    State(mut state): State<GatewayState>,
    method: axum::http::Method,
    axum::extract::OriginalUri(original_uri): axum::extract::OriginalUri,
    Path(id): Path<String>,
    headers: HeaderMap,
    EnvelopeJson(body): EnvelopeJson<Value>,
) -> Result<Json<Value>, GatewayError> {
    // Build the inner User: id from the path; display_name from the body.
    let display_name = body
        .get("display_name")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let user = headlines_proto::v1::User {
        id,
        display_name,
        ..Default::default()
    };
    let update_mask = body.get("update_mask").map(parse_field_mask);

    let mut req = tonic::Request::new(headlines_proto::v1::UpdateUserRequest {
        user: Some(user),
        update_mask,
    });
    attach_auth(
        method.as_str(),
        original_uri.path(),
        original_uri.query().unwrap_or(""),
        &headers,
        &mut req,
        &state.auth_strategy,
    )
    .await?;
    let resp = state.user_client.update_user(req).await?;
    Ok(Json(user_to_json(&resp.into_inner())))
}

/// `DELETE /v1/users/{id}` — forwards to `UserService.DeleteUser`.
async fn delete_user(
    State(mut state): State<GatewayState>,
    method: axum::http::Method,
    axum::extract::OriginalUri(original_uri): axum::extract::OriginalUri,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, GatewayError> {
    let mut req = tonic::Request::new(headlines_proto::v1::DeleteUserRequest { id });
    attach_auth(
        method.as_str(),
        original_uri.path(),
        original_uri.query().unwrap_or(""),
        &headers,
        &mut req,
        &state.auth_strategy,
    )
    .await?;
    let resp = state.user_client.delete_user(req).await?;
    Ok(Json(user_to_json(&resp.into_inner())))
}

/// `POST /v1/users/{id}/keys` — forwards to `UserService.AddUserKey`.
async fn add_user_key(
    State(mut state): State<GatewayState>,
    method: axum::http::Method,
    axum::extract::OriginalUri(original_uri): axum::extract::OriginalUri,
    Path(id): Path<String>,
    headers: HeaderMap,
    EnvelopeJson(body): EnvelopeJson<Value>,
) -> Result<Json<Value>, GatewayError> {
    let key = body.get("key").map(parse_public_key);
    let mut req = tonic::Request::new(headlines_proto::v1::AddUserKeyRequest { user_id: id, key });
    attach_auth(
        method.as_str(),
        original_uri.path(),
        original_uri.query().unwrap_or(""),
        &headers,
        &mut req,
        &state.auth_strategy,
    )
    .await?;
    let resp = state.user_client.add_user_key(req).await?;
    Ok(Json(user_key_to_json(&resp.into_inner())))
}

/// `POST /v1/users/{id}/keys/{key_id}/revoke` — forwards to
/// `UserService.RevokeUserKey`.
async fn revoke_user_key(
    State(mut state): State<GatewayState>,
    method: axum::http::Method,
    axum::extract::OriginalUri(original_uri): axum::extract::OriginalUri,
    Path((id, key_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<Value>, GatewayError> {
    let mut req = tonic::Request::new(headlines_proto::v1::RevokeUserKeyRequest {
        user_id: id,
        key_id,
    });
    attach_auth(
        method.as_str(),
        original_uri.path(),
        original_uri.query().unwrap_or(""),
        &headers,
        &mut req,
        &state.auth_strategy,
    )
    .await?;
    let resp = state.user_client.revoke_user_key(req).await?;
    Ok(Json(user_key_to_json(&resp.into_inner())))
}

fn parse_public_key(v: &Value) -> headlines_proto::v1::PublicKey {
    headlines_proto::v1::PublicKey {
        algo: v
            .get("algo")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        public_key: v
            .get("public_key")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
    }
}

fn parse_field_mask(v: &Value) -> prost_types::FieldMask {
    let paths = v
        .get("paths")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|p| p.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    prost_types::FieldMask { paths }
}

/// Map an `AuthError` into a `GatewayError` so the gateway emits the right
/// REST envelope on credential failure. All variants surface as HTTP 401
/// (`UNAUTHENTICATED`) per `docs/design/api-conventions.md` — strategies
/// never produce `INTERNAL` (internal failures get wrapped at the strategy
/// boundary).
fn auth_err_to_gateway_err(e: AuthError) -> GatewayError {
    GatewayError::from(tonic::Status::unauthenticated(e.to_string()))
}

/// Run the gateway-side auth strategy on the inbound REST request and
/// attach the resolved `Subject` to the outbound tonic request via
/// `TRUSTED_SUBJECT_HEADER`. Strips the inbound `Authorization` from the
/// outbound metadata — the trusted listener doesn't need it (the subject
/// is already resolved) and we never want to forward a credential past
/// the gateway boundary.
///
/// Behavior:
///
/// - **Authorization present**: parse the header, build canonical-string
///   inputs from `(method, rest_path, canonical_query)`, encode the proto
///   message and SHA-256 the bytes (matches the client's
///   `hash_proto_request`), run `SignedRequestStrategy::authenticate`. On
///   success forward `Subject::*`. On failure return 401.
/// - **Authorization absent**: forward `Subject::Anonymous`. The
///   downstream `AuthorizationLayer` consults the proto-driven
///   `AUTH_TABLE` to allow or deny.
async fn attach_auth<M: prost::Message>(
    method: &str,
    rest_path: &str,
    raw_query: &str,
    headers: &HeaderMap,
    req: &mut tonic::Request<M>,
    strategy: &SignedRequestStrategy,
) -> Result<(), GatewayError> {
    let subject = match headers.get(http::header::AUTHORIZATION) {
        None => Subject::Anonymous,
        Some(value) => {
            let raw = value
                .to_str()
                .map_err(|_| {
                    GatewayError::from(tonic::Status::unauthenticated(
                        "malformed_authorization_header",
                    ))
                })?
                .to_owned();
            let parsed = parse_authorization_header(&raw).map_err(|_| {
                GatewayError::from(tonic::Status::unauthenticated(
                    "malformed_authorization_header",
                ))
            })?;

            // Hash the canonical proto encoding the gateway will forward.
            // Mirrors `headlines_auth::hash_proto_request` byte-for-byte;
            // the client signs over the same hash so verification matches.
            let proto_bytes = req.get_ref().encode_to_vec();
            let request_hash: [u8; 32] = Sha256::digest(&proto_bytes).into();

            let parts = SignedRequestParts {
                method: method.to_owned(),
                path: rest_path.to_owned(),
                canonical_query: canonicalize_query(raw_query),
                request_hash,
                key_id: parsed.key_id,
                algo: parsed.algo,
                ts: parsed.ts,
                nonce: parsed.nonce,
                signature: parsed.signature,
            };
            strategy
                .authenticate(&parts)
                .await
                .map_err(auth_err_to_gateway_err)?
        }
    };

    let json = serde_json::to_string(&subject).map_err(|e| {
        GatewayError::from(tonic::Status::internal(format!(
            "subject serialization failed: {e}"
        )))
    })?;
    let meta_value: tonic::metadata::MetadataValue<_> = json.parse().map_err(|_| {
        GatewayError::from(tonic::Status::internal("subject metadata encode failed"))
    })?;
    req.metadata_mut()
        .insert(TRUSTED_SUBJECT_HEADER, meta_value);
    // Defense in depth: if anything ever inserted an outgoing
    // `authorization` metadata above us, scrub it now.
    req.metadata_mut().remove("authorization");
    Ok(())
}

/// Hand-rolled `Account → JSON` converter. Field names are `snake_case`
/// per `api-conventions.md`. Empty optional fields drop to `null` rather
/// than to their proto defaults.
pub fn account_to_json(a: &headlines_proto::v1::Account) -> Value {
    json!({
        "id": a.id,
        "short_name": a.short_name,
        "author_name": a.author_name,
        "author_url": a.author_url,
        "status": account_status_str(a.status),
        "deleted_at": a.deleted_at.as_ref().map(timestamp_to_rfc3339),
        "created_at": a.created_at.as_ref().map(timestamp_to_rfc3339),
        "updated_at": a.updated_at.as_ref().map(timestamp_to_rfc3339),
    })
}

fn account_status_str(value: i32) -> &'static str {
    match AccountStatus::try_from(value).unwrap_or(AccountStatus::Unspecified) {
        AccountStatus::Unspecified => "ACCOUNT_STATUS_UNSPECIFIED",
        AccountStatus::Active => "ACCOUNT_STATUS_ACTIVE",
        AccountStatus::Deleted => "ACCOUNT_STATUS_DELETED",
    }
}

/// Hand-rolled `User → JSON` converter mirroring `account_to_json`.
pub fn user_to_json(u: &headlines_proto::v1::User) -> Value {
    json!({
        "id": u.id,
        "display_name": u.display_name,
        "status": user_status_str(u.status),
        "deleted_at": u.deleted_at.as_ref().map(timestamp_to_rfc3339),
        "created_at": u.created_at.as_ref().map(timestamp_to_rfc3339),
    })
}

/// Hand-rolled `UserKey → JSON` converter.
pub fn user_key_to_json(k: &headlines_proto::v1::UserKey) -> Value {
    json!({
        "user_id": k.user_id,
        "key_id": k.key_id,
        "algo": k.algo,
        "public_key": k.public_key,
        "status": key_status_str(k.status),
        "created_at": k.created_at.as_ref().map(timestamp_to_rfc3339),
        "revoked_at": k.revoked_at.as_ref().map(timestamp_to_rfc3339),
    })
}

fn user_status_str(value: i32) -> &'static str {
    match UserStatus::try_from(value).unwrap_or(UserStatus::Unspecified) {
        UserStatus::Unspecified => "USER_STATUS_UNSPECIFIED",
        UserStatus::Active => "USER_STATUS_ACTIVE",
        UserStatus::Deleted => "USER_STATUS_DELETED",
    }
}

fn key_status_str(value: i32) -> &'static str {
    match KeyStatus::try_from(value).unwrap_or(KeyStatus::Unspecified) {
        KeyStatus::Unspecified => "KEY_STATUS_UNSPECIFIED",
        KeyStatus::Active => "KEY_STATUS_ACTIVE",
        KeyStatus::Revoked => "KEY_STATUS_REVOKED",
    }
}

fn timestamp_to_rfc3339(ts: &prost_types::Timestamp) -> String {
    Utc.timestamp_opt(ts.seconds, ts.nanos as u32)
        .single()
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// ArticleService routes
// ---------------------------------------------------------------------------

/// `POST /v1/accounts/{account_id}/articles` — forwards to
/// `ArticleService.PublishArticle`.
async fn publish_article(
    State(mut state): State<GatewayState>,
    method: axum::http::Method,
    axum::extract::OriginalUri(original_uri): axum::extract::OriginalUri,
    Path(account_id): Path<String>,
    headers: HeaderMap,
    EnvelopeJson(body): EnvelopeJson<Value>,
) -> Result<Json<Value>, GatewayError> {
    let title = body
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let author_name = body
        .get("author_name")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let author_url = body
        .get("author_url")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let content = body.get("content").map(parse_nodes).unwrap_or_default();

    let mut req = tonic::Request::new(headlines_proto::v1::PublishArticleRequest {
        account_id,
        title,
        author_name,
        author_url,
        content,
    });
    attach_auth(
        method.as_str(),
        original_uri.path(),
        original_uri.query().unwrap_or(""),
        &headers,
        &mut req,
        &state.auth_strategy,
    )
    .await?;
    let resp = state.article_client.publish_article(req).await?;
    Ok(Json(article_to_json(&resp.into_inner())))
}

/// `GET /v1/articles/{id}` — forwards to `ArticleService.GetArticle`.
async fn get_article_handler(
    State(mut state): State<GatewayState>,
    method: axum::http::Method,
    axum::extract::OriginalUri(original_uri): axum::extract::OriginalUri,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, GatewayError> {
    let mut req = tonic::Request::new(headlines_proto::v1::GetArticleRequest { id });
    attach_auth(
        method.as_str(),
        original_uri.path(),
        original_uri.query().unwrap_or(""),
        &headers,
        &mut req,
        &state.auth_strategy,
    )
    .await?;
    let resp = state.article_client.get_article(req).await?;
    Ok(Json(article_to_json(&resp.into_inner())))
}

/// `GET /v1/accounts/{account_id}/articles` — forwards to
/// `ArticleService.ListAccountArticles`.
async fn list_account_articles(
    State(mut state): State<GatewayState>,
    method: axum::http::Method,
    axum::extract::OriginalUri(original_uri): axum::extract::OriginalUri,
    Path(account_id): Path<String>,
    axum::extract::Query(qs): axum::extract::Query<std::collections::HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Json<Value>, GatewayError> {
    let page_size = qs
        .get("page_size")
        .and_then(|v| v.parse::<i32>().ok())
        .unwrap_or(0);
    let page_token = qs.get("page_token").cloned().unwrap_or_default();
    let include_tombstoned = qs
        .get("include_tombstoned")
        .map(|v| v == "true")
        .unwrap_or(false);
    let mut req = tonic::Request::new(headlines_proto::v1::ListAccountArticlesRequest {
        account_id,
        page_size,
        page_token,
        include_tombstoned,
    });
    attach_auth(
        method.as_str(),
        original_uri.path(),
        original_uri.query().unwrap_or(""),
        &headers,
        &mut req,
        &state.auth_strategy,
    )
    .await?;
    let resp = state
        .article_client
        .list_account_articles(req)
        .await?
        .into_inner();
    Ok(Json(json!({
        "items": resp.items.iter().map(article_summary_to_json).collect::<Vec<_>>(),
        "next_page_token": resp.next_page_token,
    })))
}

/// `PATCH /v1/articles/{id}` — forwards to `ArticleService.EditArticle`.
async fn edit_article(
    State(mut state): State<GatewayState>,
    method: axum::http::Method,
    axum::extract::OriginalUri(original_uri): axum::extract::OriginalUri,
    Path(id): Path<String>,
    headers: HeaderMap,
    EnvelopeJson(body): EnvelopeJson<Value>,
) -> Result<Json<Value>, GatewayError> {
    let edit = body.get("edit").map(|v| {
        let title = v
            .get("title")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let author_name = v
            .get("author_name")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let author_url = v
            .get("author_url")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let content = v.get("content").map(parse_nodes).unwrap_or_default();
        headlines_proto::v1::ArticleEdit {
            title,
            author_name,
            author_url,
            content,
        }
    });
    let update_mask = body.get("update_mask").map(parse_field_mask);

    let mut req = tonic::Request::new(headlines_proto::v1::EditArticleRequest {
        id,
        edit,
        update_mask,
    });
    attach_auth(
        method.as_str(),
        original_uri.path(),
        original_uri.query().unwrap_or(""),
        &headers,
        &mut req,
        &state.auth_strategy,
    )
    .await?;
    let resp = state.article_client.edit_article(req).await?;
    Ok(Json(article_to_json(&resp.into_inner())))
}

/// `POST /v1/articles/{id}/tombstone` — forwards to
/// `ArticleService.TombstoneArticle`.
async fn tombstone_article(
    State(mut state): State<GatewayState>,
    method: axum::http::Method,
    axum::extract::OriginalUri(original_uri): axum::extract::OriginalUri,
    Path(id): Path<String>,
    headers: HeaderMap,
    EnvelopeJson(body): EnvelopeJson<Value>,
) -> Result<Json<Value>, GatewayError> {
    let reason = body
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let mut req = tonic::Request::new(headlines_proto::v1::TombstoneArticleRequest { id, reason });
    attach_auth(
        method.as_str(),
        original_uri.path(),
        original_uri.query().unwrap_or(""),
        &headers,
        &mut req,
        &state.auth_strategy,
    )
    .await?;
    let resp = state.article_client.tombstone_article(req).await?;
    Ok(Json(article_to_json(&resp.into_inner())))
}

/// `POST /v1/articles/{article_id}/versions/{version}/redact` — forwards to
/// `ArticleService.RedactArticleVersion`.
async fn redact_article_version(
    State(mut state): State<GatewayState>,
    method: axum::http::Method,
    axum::extract::OriginalUri(original_uri): axum::extract::OriginalUri,
    Path((article_id, version)): Path<(String, String)>,
    headers: HeaderMap,
    EnvelopeJson(body): EnvelopeJson<Value>,
) -> Result<Json<Value>, GatewayError> {
    let v: i32 = version.parse().map_err(|_| {
        GatewayError::from(tonic::Status::invalid_argument("version must be an int"))
    })?;
    let redaction_reason = body
        .get("redaction_reason")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let mut req = tonic::Request::new(headlines_proto::v1::RedactArticleVersionRequest {
        article_id,
        version: v,
        redaction_reason,
    });
    attach_auth(
        method.as_str(),
        original_uri.path(),
        original_uri.query().unwrap_or(""),
        &headers,
        &mut req,
        &state.auth_strategy,
    )
    .await?;
    state.article_client.redact_article_version(req).await?;
    Ok(Json(json!({})))
}

// ---------------------------------------------------------------------------
// JSON converters for ArticleService responses
// ---------------------------------------------------------------------------

/// Hand-rolled `Article → JSON` converter. The inner Live/Tombstone variant
/// is flattened into a `live` / `tombstone` sibling keyed by state.
pub fn article_to_json(a: &headlines_proto::v1::Article) -> Value {
    let mut obj = Map::new();
    obj.insert("id".into(), Value::String(a.id.clone()));
    obj.insert("account_id".into(), Value::String(a.account_id.clone()));
    obj.insert(
        "state".into(),
        Value::String(article_state_str(a.state).to_owned()),
    );
    obj.insert(
        "created_at".into(),
        a.created_at
            .as_ref()
            .map(|t| Value::String(timestamp_to_rfc3339(t)))
            .unwrap_or(Value::Null),
    );
    match &a.state_data {
        Some(headlines_proto::v1::article::StateData::Live(live)) => {
            obj.insert("live".into(), article_live_to_json(live));
        }
        Some(headlines_proto::v1::article::StateData::Tombstone(t)) => {
            obj.insert("tombstone".into(), article_tombstone_to_json(t));
        }
        None => {}
    }
    Value::Object(obj)
}

/// Hand-rolled `ArticleSummary → JSON` converter.
pub fn article_summary_to_json(s: &headlines_proto::v1::ArticleSummary) -> Value {
    let mut obj = Map::new();
    obj.insert("id".into(), Value::String(s.id.clone()));
    obj.insert("account_id".into(), Value::String(s.account_id.clone()));
    obj.insert(
        "state".into(),
        Value::String(article_state_str(s.state).to_owned()),
    );
    obj.insert(
        "created_at".into(),
        s.created_at
            .as_ref()
            .map(|t| Value::String(timestamp_to_rfc3339(t)))
            .unwrap_or(Value::Null),
    );
    match &s.state_data {
        Some(headlines_proto::v1::article_summary::StateData::Live(live)) => {
            obj.insert("live".into(), article_live_summary_to_json(live));
        }
        Some(headlines_proto::v1::article_summary::StateData::Tombstone(t)) => {
            obj.insert("tombstone".into(), article_tombstone_summary_to_json(t));
        }
        None => {}
    }
    Value::Object(obj)
}

fn article_live_to_json(live: &headlines_proto::v1::ArticleLive) -> Value {
    json!({
        "current_version": live.current_version,
        "title": live.title,
        "author_name": live.author_name,
        "author_url": live.author_url,
        "content": nodes_to_json_array(&live.content),
        "redacted": live.redacted,
        "published_at": live.published_at.as_ref().map(timestamp_to_rfc3339),
        "updated_at": live.updated_at.as_ref().map(timestamp_to_rfc3339),
    })
}

fn article_live_summary_to_json(live: &headlines_proto::v1::ArticleLiveSummary) -> Value {
    json!({
        "current_version": live.current_version,
        "title": live.title,
        "author_name": live.author_name,
        "author_url": live.author_url,
        "redacted": live.redacted,
        "published_at": live.published_at.as_ref().map(timestamp_to_rfc3339),
        "updated_at": live.updated_at.as_ref().map(timestamp_to_rfc3339),
    })
}

fn article_tombstone_to_json(t: &headlines_proto::v1::ArticleTombstone) -> Value {
    json!({
        "reason": t.reason,
        "tombstoned_at": t.tombstoned_at.as_ref().map(timestamp_to_rfc3339),
    })
}

fn article_tombstone_summary_to_json(t: &headlines_proto::v1::ArticleTombstoneSummary) -> Value {
    json!({
        "reason": t.reason,
        "tombstoned_at": t.tombstoned_at.as_ref().map(timestamp_to_rfc3339),
    })
}

fn article_state_str(value: i32) -> &'static str {
    match ArticleState::try_from(value).unwrap_or(ArticleState::Unspecified) {
        ArticleState::Unspecified => "ARTICLE_STATE_UNSPECIFIED",
        ArticleState::Live => "ARTICLE_STATE_LIVE",
        ArticleState::Tombstone => "ARTICLE_STATE_TOMBSTONE",
    }
}

/// Recursive `[Node] → [JSON]` converter for the REST surface. Mirrors
/// `headlines-api`'s storage encoding (see `services::article::nodes_to_json`)
/// but is independent because the gateway has no dependency on
/// `headlines-api`.
pub fn nodes_to_json_array(nodes: &[headlines_proto::v1::Node]) -> Value {
    Value::Array(nodes.iter().map(node_to_json).collect())
}

pub fn node_to_json(node: &headlines_proto::v1::Node) -> Value {
    use headlines_proto::v1::node::Kind;
    match node.kind.as_ref() {
        None => Value::Null,
        Some(Kind::Text(t)) => json!({ "text": t }),
        Some(Kind::Element(el)) => {
            let mut obj = Map::new();
            obj.insert("tag".into(), Value::String(el.tag.clone()));
            if !el.attrs.is_empty() {
                let mut attrs = Map::new();
                let mut keys: Vec<&String> = el.attrs.keys().collect();
                keys.sort();
                for k in keys {
                    if let Some(v) = el.attrs.get(k) {
                        attrs.insert(k.clone(), Value::String(v.clone()));
                    }
                }
                obj.insert("attrs".into(), Value::Object(attrs));
            }
            if !el.children.is_empty() {
                obj.insert("children".into(), nodes_to_json_array(&el.children));
            }
            Value::Object(obj)
        }
    }
}

fn parse_nodes(v: &Value) -> Vec<headlines_proto::v1::Node> {
    let Value::Array(arr) = v else {
        return Vec::new();
    };
    arr.iter().map(parse_node).collect()
}

fn parse_node(v: &Value) -> headlines_proto::v1::Node {
    use headlines_proto::v1::node::Kind;
    let Value::Object(obj) = v else {
        return headlines_proto::v1::Node::default();
    };
    if let Some(Value::String(t)) = obj.get("text") {
        return headlines_proto::v1::Node {
            kind: Some(Kind::Text(t.clone())),
        };
    }
    let tag = obj
        .get("tag")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let attrs = obj
        .get("attrs")
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_owned())))
                .collect()
        })
        .unwrap_or_default();
    let children = obj.get("children").map(parse_nodes).unwrap_or_default();
    headlines_proto::v1::Node {
        kind: Some(Kind::Element(headlines_proto::v1::NodeElement {
            tag,
            attrs,
            children,
        })),
    }
}

// ---------------------------------------------------------------------------
// DraftService routes
// ---------------------------------------------------------------------------

/// `POST /v1/accounts/{account_id}/drafts` — forwards to
/// `DraftService.CreateDraft`.
async fn create_draft(
    State(mut state): State<GatewayState>,
    method: axum::http::Method,
    axum::extract::OriginalUri(original_uri): axum::extract::OriginalUri,
    Path(account_id): Path<String>,
    headers: HeaderMap,
    EnvelopeJson(body): EnvelopeJson<Value>,
) -> Result<Json<Value>, GatewayError> {
    let title = body
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let author_name = body
        .get("author_name")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let author_url = body
        .get("author_url")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let content = body.get("content").map(parse_nodes).unwrap_or_default();

    let mut req = tonic::Request::new(headlines_proto::v1::CreateDraftRequest {
        account_id,
        title,
        author_name,
        author_url,
        content,
    });
    attach_auth(
        method.as_str(),
        original_uri.path(),
        original_uri.query().unwrap_or(""),
        &headers,
        &mut req,
        &state.auth_strategy,
    )
    .await?;
    let resp = state.draft_client.create_draft(req).await?;
    Ok(Json(draft_to_json(&resp.into_inner())))
}

/// `GET /v1/drafts/{id}` — forwards to `DraftService.GetDraft`.
async fn get_draft(
    State(mut state): State<GatewayState>,
    method: axum::http::Method,
    axum::extract::OriginalUri(original_uri): axum::extract::OriginalUri,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, GatewayError> {
    let mut req = tonic::Request::new(headlines_proto::v1::GetDraftRequest { id });
    attach_auth(
        method.as_str(),
        original_uri.path(),
        original_uri.query().unwrap_or(""),
        &headers,
        &mut req,
        &state.auth_strategy,
    )
    .await?;
    let resp = state.draft_client.get_draft(req).await?;
    Ok(Json(draft_to_json(&resp.into_inner())))
}

/// `PATCH /v1/drafts/{id}` — forwards to `DraftService.UpdateDraft`.
///
/// Body shape mirrors the proto: `{ "draft": { ... }, "update_mask": { "paths": [...] } }`.
async fn update_draft(
    State(mut state): State<GatewayState>,
    method: axum::http::Method,
    axum::extract::OriginalUri(original_uri): axum::extract::OriginalUri,
    Path(id): Path<String>,
    headers: HeaderMap,
    EnvelopeJson(body): EnvelopeJson<Value>,
) -> Result<Json<Value>, GatewayError> {
    let draft = body.get("draft").map(|v| {
        let title = v
            .get("title")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let author_name = v
            .get("author_name")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let author_url = v
            .get("author_url")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let content = v.get("content").map(parse_nodes).unwrap_or_default();
        headlines_proto::v1::Draft {
            id: id.clone(),
            account_id: String::new(),
            title,
            author_name,
            author_url,
            content,
            created_at: None,
            updated_at: None,
        }
    });
    let update_mask = body.get("update_mask").map(parse_field_mask);
    let mut req =
        tonic::Request::new(headlines_proto::v1::UpdateDraftRequest { draft, update_mask });
    attach_auth(
        method.as_str(),
        original_uri.path(),
        original_uri.query().unwrap_or(""),
        &headers,
        &mut req,
        &state.auth_strategy,
    )
    .await?;
    let resp = state.draft_client.update_draft(req).await?;
    Ok(Json(draft_to_json(&resp.into_inner())))
}

/// `DELETE /v1/drafts/{id}` — forwards to `DraftService.DeleteDraft`.
async fn delete_draft(
    State(mut state): State<GatewayState>,
    method: axum::http::Method,
    axum::extract::OriginalUri(original_uri): axum::extract::OriginalUri,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, GatewayError> {
    let mut req = tonic::Request::new(headlines_proto::v1::DeleteDraftRequest { id });
    attach_auth(
        method.as_str(),
        original_uri.path(),
        original_uri.query().unwrap_or(""),
        &headers,
        &mut req,
        &state.auth_strategy,
    )
    .await?;
    state.draft_client.delete_draft(req).await?;
    Ok(Json(json!({})))
}

/// `GET /v1/accounts/{account_id}/drafts` — forwards to
/// `DraftService.ListAccountDrafts`.
async fn list_account_drafts(
    State(mut state): State<GatewayState>,
    method: axum::http::Method,
    axum::extract::OriginalUri(original_uri): axum::extract::OriginalUri,
    Path(account_id): Path<String>,
    axum::extract::Query(qs): axum::extract::Query<std::collections::HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Json<Value>, GatewayError> {
    let page_size = qs
        .get("page_size")
        .and_then(|v| v.parse::<i32>().ok())
        .unwrap_or(0);
    let page_token = qs.get("page_token").cloned().unwrap_or_default();
    let mut req = tonic::Request::new(headlines_proto::v1::ListAccountDraftsRequest {
        account_id,
        page_size,
        page_token,
    });
    attach_auth(
        method.as_str(),
        original_uri.path(),
        original_uri.query().unwrap_or(""),
        &headers,
        &mut req,
        &state.auth_strategy,
    )
    .await?;
    let resp = state
        .draft_client
        .list_account_drafts(req)
        .await?
        .into_inner();
    Ok(Json(json!({
        "items": resp.items.iter().map(draft_summary_to_json).collect::<Vec<_>>(),
        "next_page_token": resp.next_page_token,
    })))
}

/// `POST /v1/drafts/{id}/publish` — forwards to `DraftService.PublishDraft`.
async fn publish_draft(
    State(mut state): State<GatewayState>,
    method: axum::http::Method,
    axum::extract::OriginalUri(original_uri): axum::extract::OriginalUri,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, GatewayError> {
    let mut req = tonic::Request::new(headlines_proto::v1::PublishDraftRequest { id });
    attach_auth(
        method.as_str(),
        original_uri.path(),
        original_uri.query().unwrap_or(""),
        &headers,
        &mut req,
        &state.auth_strategy,
    )
    .await?;
    let resp = state.draft_client.publish_draft(req).await?;
    Ok(Json(article_to_json(&resp.into_inner())))
}

// ---------------------------------------------------------------------------
// JSON converters for DraftService responses
// ---------------------------------------------------------------------------

/// Hand-rolled `Draft → JSON` converter. Mirrors `account_to_json` /
/// `article_to_json` shape (snake_case fields, RFC3339 timestamps, no proto
/// defaults bleeding through).
pub fn draft_to_json(d: &headlines_proto::v1::Draft) -> Value {
    json!({
        "id": d.id,
        "account_id": d.account_id,
        "title": d.title,
        "author_name": d.author_name,
        "author_url": d.author_url,
        "content": nodes_to_json_array(&d.content),
        "created_at": d.created_at.as_ref().map(timestamp_to_rfc3339),
        "updated_at": d.updated_at.as_ref().map(timestamp_to_rfc3339),
    })
}

/// Hand-rolled `DraftSummary → JSON` converter.
pub fn draft_summary_to_json(s: &headlines_proto::v1::DraftSummary) -> Value {
    json!({
        "id": s.id,
        "account_id": s.account_id,
        "title": s.title,
        "created_at": s.created_at.as_ref().map(timestamp_to_rfc3339),
        "updated_at": s.updated_at.as_ref().map(timestamp_to_rfc3339),
    })
}

// ---------------------------------------------------------------------------
// FollowService routes
// ---------------------------------------------------------------------------

/// `POST /v1/users/{user_id}/follows` — forwards to `FollowService.Follow`.
async fn follow_user(
    State(mut state): State<GatewayState>,
    method: axum::http::Method,
    axum::extract::OriginalUri(original_uri): axum::extract::OriginalUri,
    Path(user_id): Path<String>,
    headers: HeaderMap,
    EnvelopeJson(body): EnvelopeJson<Value>,
) -> Result<Json<Value>, GatewayError> {
    let account_id = body
        .get("account_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let mut req = tonic::Request::new(headlines_proto::v1::FollowRequest {
        user_id,
        account_id,
    });
    attach_auth(
        method.as_str(),
        original_uri.path(),
        original_uri.query().unwrap_or(""),
        &headers,
        &mut req,
        &state.auth_strategy,
    )
    .await?;
    let resp = state.follow_client.follow(req).await?;
    Ok(Json(follow_to_json(&resp.into_inner())))
}

/// `DELETE /v1/users/{user_id}/follows/{account_id}` — forwards to
/// `FollowService.Unfollow`.
async fn unfollow_user(
    State(mut state): State<GatewayState>,
    method: axum::http::Method,
    axum::extract::OriginalUri(original_uri): axum::extract::OriginalUri,
    Path((user_id, account_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<Value>, GatewayError> {
    let mut req = tonic::Request::new(headlines_proto::v1::UnfollowRequest {
        user_id,
        account_id,
    });
    attach_auth(
        method.as_str(),
        original_uri.path(),
        original_uri.query().unwrap_or(""),
        &headers,
        &mut req,
        &state.auth_strategy,
    )
    .await?;
    let resp = state.follow_client.unfollow(req).await?;
    Ok(Json(follow_to_json(&resp.into_inner())))
}

/// `GET /v1/users/{user_id}/follows/{account_id}` — forwards to
/// `FollowService.GetFollow`.
async fn get_follow(
    State(mut state): State<GatewayState>,
    method: axum::http::Method,
    axum::extract::OriginalUri(original_uri): axum::extract::OriginalUri,
    Path((user_id, account_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<Value>, GatewayError> {
    let mut req = tonic::Request::new(headlines_proto::v1::GetFollowRequest {
        user_id,
        account_id,
    });
    attach_auth(
        method.as_str(),
        original_uri.path(),
        original_uri.query().unwrap_or(""),
        &headers,
        &mut req,
        &state.auth_strategy,
    )
    .await?;
    let resp = state.follow_client.get_follow(req).await?;
    Ok(Json(follow_to_json(&resp.into_inner())))
}

/// `GET /v1/users/{user_id}/follows` — forwards to
/// `FollowService.ListUserFollows`.
async fn list_user_follows(
    State(mut state): State<GatewayState>,
    method: axum::http::Method,
    axum::extract::OriginalUri(original_uri): axum::extract::OriginalUri,
    Path(user_id): Path<String>,
    axum::extract::Query(qs): axum::extract::Query<std::collections::HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Json<Value>, GatewayError> {
    let page_size = qs
        .get("page_size")
        .and_then(|v| v.parse::<i32>().ok())
        .unwrap_or(0);
    let page_token = qs.get("page_token").cloned().unwrap_or_default();
    let include_unfollowed = qs
        .get("include_unfollowed")
        .map(|v| v == "true")
        .unwrap_or(false);
    let mut req = tonic::Request::new(headlines_proto::v1::ListUserFollowsRequest {
        user_id,
        page_size,
        page_token,
        include_unfollowed,
    });
    attach_auth(
        method.as_str(),
        original_uri.path(),
        original_uri.query().unwrap_or(""),
        &headers,
        &mut req,
        &state.auth_strategy,
    )
    .await?;
    let resp = state
        .follow_client
        .list_user_follows(req)
        .await?
        .into_inner();
    Ok(Json(json!({
        "items": resp.items.iter().map(follow_to_json).collect::<Vec<_>>(),
        "next_page_token": resp.next_page_token,
    })))
}

/// `GET /v1/accounts/{account_id}/followers` — forwards to
/// `FollowService.ListAccountFollowers`.
async fn list_account_followers(
    State(mut state): State<GatewayState>,
    method: axum::http::Method,
    axum::extract::OriginalUri(original_uri): axum::extract::OriginalUri,
    Path(account_id): Path<String>,
    axum::extract::Query(qs): axum::extract::Query<std::collections::HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Json<Value>, GatewayError> {
    let page_size = qs
        .get("page_size")
        .and_then(|v| v.parse::<i32>().ok())
        .unwrap_or(0);
    let page_token = qs.get("page_token").cloned().unwrap_or_default();
    let include_unfollowed = qs
        .get("include_unfollowed")
        .map(|v| v == "true")
        .unwrap_or(false);
    let mut req = tonic::Request::new(headlines_proto::v1::ListAccountFollowersRequest {
        account_id,
        page_size,
        page_token,
        include_unfollowed,
    });
    attach_auth(
        method.as_str(),
        original_uri.path(),
        original_uri.query().unwrap_or(""),
        &headers,
        &mut req,
        &state.auth_strategy,
    )
    .await?;
    let resp = state
        .follow_client
        .list_account_followers(req)
        .await?
        .into_inner();
    Ok(Json(json!({
        "items": resp.items.iter().map(follow_to_json).collect::<Vec<_>>(),
        "next_page_token": resp.next_page_token,
    })))
}

/// Hand-rolled `Follow → JSON` converter mirroring the other domain types.
pub fn follow_to_json(f: &headlines_proto::v1::Follow) -> Value {
    json!({
        "user_id": f.user_id,
        "account_id": f.account_id,
        "status": follow_status_str(f.status),
        "created_at": f.created_at.as_ref().map(timestamp_to_rfc3339),
        "unfollowed_at": f.unfollowed_at.as_ref().map(timestamp_to_rfc3339),
    })
}

fn follow_status_str(value: i32) -> &'static str {
    match FollowStatus::try_from(value).unwrap_or(FollowStatus::Unspecified) {
        FollowStatus::Unspecified => "FOLLOW_STATUS_UNSPECIFIED",
        FollowStatus::Active => "FOLLOW_STATUS_ACTIVE",
        FollowStatus::Unfollowed => "FOLLOW_STATUS_UNFOLLOWED",
    }
}

// ---------------------------------------------------------------------------
// FeedRecommendationService routes
// ---------------------------------------------------------------------------

/// `PUT /v1/users/{user_id}/feed/recommendation` — forwards to
/// `FeedRecommendationService.ReplaceRecommendationFeed`.
async fn replace_recommendation_feed(
    State(mut state): State<GatewayState>,
    method: axum::http::Method,
    axum::extract::OriginalUri(original_uri): axum::extract::OriginalUri,
    Path(user_id): Path<String>,
    headers: HeaderMap,
    EnvelopeJson(body): EnvelopeJson<Value>,
) -> Result<Json<Value>, GatewayError> {
    let article_ids = body
        .get("article_ids")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let mut req = tonic::Request::new(headlines_proto::v1::ReplaceRecommendationFeedRequest {
        user_id,
        article_ids,
    });
    attach_auth(
        method.as_str(),
        original_uri.path(),
        original_uri.query().unwrap_or(""),
        &headers,
        &mut req,
        &state.auth_strategy,
    )
    .await?;
    let resp = state
        .feed_recommendation_client
        .replace_recommendation_feed(req)
        .await?
        .into_inner();
    Ok(Json(json!({
        "stored_count": resp.stored_count,
    })))
}

/// `GET /v1/users/{user_id}/feed/recommendation` — forwards to
/// `FeedRecommendationService.GetRecommendationFeed`.
async fn get_recommendation_feed(
    State(mut state): State<GatewayState>,
    method: axum::http::Method,
    axum::extract::OriginalUri(original_uri): axum::extract::OriginalUri,
    Path(user_id): Path<String>,
    axum::extract::Query(qs): axum::extract::Query<std::collections::HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Json<Value>, GatewayError> {
    let page_size = qs
        .get("page_size")
        .and_then(|v| v.parse::<i32>().ok())
        .unwrap_or(0);
    let page_token = qs.get("page_token").cloned().unwrap_or_default();
    let mut req = tonic::Request::new(headlines_proto::v1::GetRecommendationFeedRequest {
        user_id,
        page_size,
        page_token,
    });
    attach_auth(
        method.as_str(),
        original_uri.path(),
        original_uri.query().unwrap_or(""),
        &headers,
        &mut req,
        &state.auth_strategy,
    )
    .await?;
    let resp = state
        .feed_recommendation_client
        .get_recommendation_feed(req)
        .await?
        .into_inner();
    Ok(Json(json!({
        "items": resp.items.iter().map(feed_item_to_json).collect::<Vec<_>>(),
        "next_page_token": resp.next_page_token,
    })))
}

/// Hand-rolled `FeedItem → JSON` converter. Reuses
/// `article_summary_to_json` for the inner `ArticleSummary` body.
pub fn feed_item_to_json(item: &headlines_proto::v1::FeedItem) -> Value {
    json!({
        "position": item.position,
        "article": item.article.as_ref().map(article_summary_to_json),
    })
}

// ---------------------------------------------------------------------------
// FeedFollowService routes
// ---------------------------------------------------------------------------

/// `GET /v1/users/{user_id}/feed/follow` — forwards to
/// `FeedFollowService.GetFollowFeed`.
async fn get_follow_feed(
    State(mut state): State<GatewayState>,
    method: axum::http::Method,
    axum::extract::OriginalUri(original_uri): axum::extract::OriginalUri,
    Path(user_id): Path<String>,
    axum::extract::Query(qs): axum::extract::Query<std::collections::HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Json<Value>, GatewayError> {
    let page_size = qs
        .get("page_size")
        .and_then(|v| v.parse::<i32>().ok())
        .unwrap_or(0);
    let page_token = qs.get("page_token").cloned().unwrap_or_default();
    let mut req = tonic::Request::new(headlines_proto::v1::GetFollowFeedRequest {
        user_id,
        page_size,
        page_token,
    });
    attach_auth(
        method.as_str(),
        original_uri.path(),
        original_uri.query().unwrap_or(""),
        &headers,
        &mut req,
        &state.auth_strategy,
    )
    .await?;
    let resp = state
        .feed_follow_client
        .get_follow_feed(req)
        .await?
        .into_inner();
    Ok(Json(json!({
        "items": resp.items.iter().map(follow_feed_item_to_json).collect::<Vec<_>>(),
        "next_page_token": resp.next_page_token,
    })))
}

/// Hand-rolled `FollowFeedItem → JSON` converter. Reuses
/// `article_summary_to_json` for the inner body. No `position` field per
/// `feed-follow.md`.
pub fn follow_feed_item_to_json(item: &headlines_proto::v1::FollowFeedItem) -> Value {
    json!({
        "article": item.article.as_ref().map(article_summary_to_json),
    })
}

// ---------------------------------------------------------------------------
// AccountStreamService routes
// ---------------------------------------------------------------------------

/// `GET /v1/accounts/{account_id}/article-stream` — forwards to
/// `AccountStreamService.StreamAccountArticles`.
async fn stream_account_articles(
    State(mut state): State<GatewayState>,
    method: axum::http::Method,
    axum::extract::OriginalUri(original_uri): axum::extract::OriginalUri,
    Path(account_id): Path<String>,
    axum::extract::Query(qs): axum::extract::Query<std::collections::HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Json<Value>, GatewayError> {
    let page_size = qs
        .get("page_size")
        .and_then(|v| v.parse::<i32>().ok())
        .unwrap_or(0);
    let page_token = qs.get("page_token").cloned().unwrap_or_default();
    let mut req = tonic::Request::new(headlines_proto::v1::StreamAccountArticlesRequest {
        account_id,
        page_size,
        page_token,
    });
    attach_auth(
        method.as_str(),
        original_uri.path(),
        original_uri.query().unwrap_or(""),
        &headers,
        &mut req,
        &state.auth_strategy,
    )
    .await?;
    let resp = state
        .account_stream_client
        .stream_account_articles(req)
        .await?
        .into_inner();
    Ok(Json(json!({
        "items": resp.items.iter().map(account_stream_item_to_json).collect::<Vec<_>>(),
        "next_page_token": resp.next_page_token,
    })))
}

/// Hand-rolled `AccountStreamItem → JSON` converter. Wraps the inner
/// `ArticleSummary`; the summary's `state` discriminator already signals
/// LIVE vs TOMBSTONE to republishers.
pub fn account_stream_item_to_json(item: &headlines_proto::v1::AccountStreamItem) -> Value {
    json!({
        "article": item.article.as_ref().map(article_summary_to_json),
    })
}

// ---------------------------------------------------------------------------
// EventService routes
// ---------------------------------------------------------------------------

/// `POST /v1/events` — forwards to `EventService.RecordEvent`.
async fn record_event(
    State(mut state): State<GatewayState>,
    method: axum::http::Method,
    axum::extract::OriginalUri(original_uri): axum::extract::OriginalUri,
    headers: HeaderMap,
    EnvelopeJson(body): EnvelopeJson<Value>,
) -> Result<Json<Value>, GatewayError> {
    let req = parse_record_event_request(&body);
    let mut tonic_req = tonic::Request::new(req);
    attach_auth(
        method.as_str(),
        original_uri.path(),
        original_uri.query().unwrap_or(""),
        &headers,
        &mut tonic_req,
        &state.auth_strategy,
    )
    .await?;
    let resp = state.event_client.record_event(tonic_req).await?;
    Ok(Json(event_to_json(&resp.into_inner())))
}

/// `POST /v1/events:batch` — forwards to `EventService.RecordEventBatch`.
async fn record_event_batch(
    State(mut state): State<GatewayState>,
    method: axum::http::Method,
    axum::extract::OriginalUri(original_uri): axum::extract::OriginalUri,
    headers: HeaderMap,
    EnvelopeJson(body): EnvelopeJson<Value>,
) -> Result<Json<Value>, GatewayError> {
    let events = body
        .get("events")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().map(parse_record_event_request).collect())
        .unwrap_or_default();
    let mut req = tonic::Request::new(headlines_proto::v1::RecordEventBatchRequest { events });
    attach_auth(
        method.as_str(),
        original_uri.path(),
        original_uri.query().unwrap_or(""),
        &headers,
        &mut req,
        &state.auth_strategy,
    )
    .await?;
    let resp = state
        .event_client
        .record_event_batch(req)
        .await?
        .into_inner();
    Ok(Json(json!({
        "recorded": resp.recorded.iter().map(event_to_json).collect::<Vec<_>>(),
        "stored_count": resp.stored_count,
    })))
}

/// `GET /v1/events` — forwards to `EventService.ListEvents`. Supports query
/// params: `user_id`, `article_id`, `types[]` (repeatable), `received_after`,
/// `received_before`, `page_size`, `page_token`.
async fn list_events(
    State(mut state): State<GatewayState>,
    method: axum::http::Method,
    axum::extract::OriginalUri(original_uri): axum::extract::OriginalUri,
    axum::extract::Query(qs): axum::extract::Query<Vec<(String, String)>>,
    headers: HeaderMap,
) -> Result<Json<Value>, GatewayError> {
    let mut user_id = String::new();
    let mut article_id = String::new();
    let mut page_size: i32 = 0;
    let mut page_token = String::new();
    let mut received_after: Option<prost_types::Timestamp> = None;
    let mut received_before: Option<prost_types::Timestamp> = None;
    let mut types: Vec<i32> = Vec::new();

    for (k, v) in qs {
        match k.as_str() {
            "user_id" => user_id = v,
            "article_id" => article_id = v,
            "page_size" => page_size = v.parse().unwrap_or(0),
            "page_token" => page_token = v,
            "received_after" => received_after = parse_rfc3339_to_proto(&v),
            "received_before" => received_before = parse_rfc3339_to_proto(&v),
            "types" | "types[]" => {
                if let Some(t) = parse_event_type_str(&v) {
                    types.push(t);
                }
            }
            _ => {}
        }
    }

    let mut req = tonic::Request::new(headlines_proto::v1::ListEventsRequest {
        user_id,
        article_id,
        page_size,
        page_token,
        types,
        received_after,
        received_before,
    });
    attach_auth(
        method.as_str(),
        original_uri.path(),
        original_uri.query().unwrap_or(""),
        &headers,
        &mut req,
        &state.auth_strategy,
    )
    .await?;
    let resp = state.event_client.list_events(req).await?.into_inner();
    Ok(Json(json!({
        "items": resp.items.iter().map(event_to_json).collect::<Vec<_>>(),
        "next_page_token": resp.next_page_token,
    })))
}

fn parse_record_event_request(v: &Value) -> headlines_proto::v1::RecordEventRequest {
    let user_id = v
        .get("user_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let article_id = v
        .get("article_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let r#type = v
        .get("type")
        .and_then(Value::as_str)
        .and_then(parse_event_type_str)
        .unwrap_or(ProtoEventType::Unspecified as i32);
    let occurred_at = v
        .get("occurred_at")
        .and_then(Value::as_str)
        .and_then(parse_rfc3339_to_proto);
    let surface = v
        .get("surface")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();

    let properties = v.get("properties").and_then(parse_record_event_properties);

    headlines_proto::v1::RecordEventRequest {
        user_id,
        article_id,
        r#type,
        occurred_at,
        surface,
        properties,
    }
}

fn parse_record_event_properties(
    v: &Value,
) -> Option<headlines_proto::v1::record_event_request::Properties> {
    use headlines_proto::v1::record_event_request::Properties as P;
    if let Some(o) = v.get("impression") {
        let feed_kind = o
            .get("feed_kind")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let position = o
            .get("position")
            .and_then(Value::as_i64)
            .map(|n| n as i32)
            .unwrap_or(0);
        return Some(P::Impression(headlines_proto::v1::ImpressionProperties {
            feed_kind,
            position,
        }));
    }
    if let Some(o) = v.get("open") {
        let feed_kind = o
            .get("feed_kind")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let position = o
            .get("position")
            .and_then(Value::as_i64)
            .map(|n| n as i32)
            .unwrap_or(0);
        return Some(P::Open(headlines_proto::v1::OpenProperties {
            feed_kind,
            position,
        }));
    }
    if let Some(o) = v.get("dwell") {
        let dwell_ms = o.get("dwell_ms").and_then(Value::as_i64).unwrap_or(0);
        return Some(P::Dwell(headlines_proto::v1::DwellProperties { dwell_ms }));
    }
    if v.get("like").is_some() {
        return Some(P::Like(headlines_proto::v1::LikeProperties {}));
    }
    if v.get("unlike").is_some() {
        return Some(P::Unlike(headlines_proto::v1::UnlikeProperties {}));
    }
    if let Some(o) = v.get("share") {
        let target = o
            .get("target")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        return Some(P::Share(headlines_proto::v1::ShareProperties { target }));
    }
    None
}

/// Parse an `EventType` enum string (with or without the `EVENT_TYPE_`
/// prefix) into the proto integer. Returns `None` for unknown values.
fn parse_event_type_str(s: &str) -> Option<i32> {
    let bare = s.strip_prefix("EVENT_TYPE_").unwrap_or(s);
    Some(match bare {
        "IMPRESSION" => ProtoEventType::Impression as i32,
        "OPEN" => ProtoEventType::Open as i32,
        "DWELL" => ProtoEventType::Dwell as i32,
        "LIKE" => ProtoEventType::Like as i32,
        "UNLIKE" => ProtoEventType::Unlike as i32,
        "SHARE" => ProtoEventType::Share as i32,
        "UNSPECIFIED" => ProtoEventType::Unspecified as i32,
        _ => return None,
    })
}

fn event_type_str(value: i32) -> &'static str {
    match ProtoEventType::try_from(value).unwrap_or(ProtoEventType::Unspecified) {
        ProtoEventType::Unspecified => "EVENT_TYPE_UNSPECIFIED",
        ProtoEventType::Impression => "EVENT_TYPE_IMPRESSION",
        ProtoEventType::Open => "EVENT_TYPE_OPEN",
        ProtoEventType::Dwell => "EVENT_TYPE_DWELL",
        ProtoEventType::Like => "EVENT_TYPE_LIKE",
        ProtoEventType::Unlike => "EVENT_TYPE_UNLIKE",
        ProtoEventType::Share => "EVENT_TYPE_SHARE",
    }
}

fn parse_rfc3339_to_proto(s: &str) -> Option<prost_types::Timestamp> {
    let dt = chrono::DateTime::parse_from_rfc3339(s).ok()?;
    Some(prost_types::Timestamp {
        seconds: dt.timestamp(),
        nanos: dt.timestamp_subsec_nanos() as i32,
    })
}

/// Hand-rolled `Event → JSON` converter. The `properties` oneof emits as a
/// tagged sibling key (`impression` / `open` / `dwell` / `like` / `unlike` /
/// `share`) so the JSON shape exactly mirrors the proto oneof.
pub fn event_to_json(e: &headlines_proto::v1::Event) -> Value {
    let mut obj = Map::new();
    obj.insert("id".into(), Value::String(e.id.clone()));
    obj.insert("user_id".into(), Value::String(e.user_id.clone()));
    obj.insert("article_id".into(), Value::String(e.article_id.clone()));
    obj.insert(
        "type".into(),
        Value::String(event_type_str(e.r#type).to_owned()),
    );
    obj.insert(
        "occurred_at".into(),
        e.occurred_at
            .as_ref()
            .map(|t| Value::String(timestamp_to_rfc3339(t)))
            .unwrap_or(Value::Null),
    );
    obj.insert(
        "received_at".into(),
        e.received_at
            .as_ref()
            .map(|t| Value::String(timestamp_to_rfc3339(t)))
            .unwrap_or(Value::Null),
    );
    obj.insert("surface".into(), Value::String(e.surface.clone()));
    obj.insert("properties".into(), event_properties_to_json(&e.properties));
    Value::Object(obj)
}

fn event_properties_to_json(p: &Option<headlines_proto::v1::event::Properties>) -> Value {
    use headlines_proto::v1::event::Properties as P;
    match p {
        None => Value::Null,
        Some(P::Impression(o)) => json!({
            "impression": {
                "feed_kind": o.feed_kind,
                "position": o.position,
            }
        }),
        Some(P::Open(o)) => json!({
            "open": {
                "feed_kind": o.feed_kind,
                "position": o.position,
            }
        }),
        Some(P::Dwell(o)) => json!({"dwell": {"dwell_ms": o.dwell_ms}}),
        Some(P::Like(_)) => json!({"like": {}}),
        Some(P::Unlike(_)) => json!({"unlike": {}}),
        Some(P::Share(o)) => json!({"share": {"target": o.target}}),
    }
}

// ---------------------------------------------------------------------------
// NotificationService routes
// ---------------------------------------------------------------------------
//
// Phase 7.9 ships the URL surface on top of a stub gRPC handler that always
// returns `UNIMPLEMENTED` (REST 501). The handlers parse a minimal request
// body so a real client can hit the endpoint without being rejected at the
// gateway — the 501 must come from the handler chain, not the parser.
//
// No JSON converters for `Notification` / `NotificationPreferences` are
// defined here because every response is an error; when implementation lands
// we'll add `notification_to_json` / `notification_preferences_to_json`
// alongside the other domain converters above.

/// `POST /v1/notifications` — forwards to `NotificationService.SendNotification`.
async fn send_notification(
    State(mut state): State<GatewayState>,
    method: axum::http::Method,
    axum::extract::OriginalUri(original_uri): axum::extract::OriginalUri,
    headers: HeaderMap,
    EnvelopeJson(body): EnvelopeJson<Value>,
) -> Result<Json<Value>, GatewayError> {
    let req = parse_send_notification_request(&body);
    let mut tonic_req = tonic::Request::new(req);
    attach_auth(
        method.as_str(),
        original_uri.path(),
        original_uri.query().unwrap_or(""),
        &headers,
        &mut tonic_req,
        &state.auth_strategy,
    )
    .await?;
    let _ = state
        .notification_client
        .send_notification(tonic_req)
        .await?;
    // Unreachable in v1 (handler always returns UNIMPLEMENTED), but kept for
    // when this is implemented.
    Ok(Json(json!({})))
}

/// `POST /v1/notifications:batch` — forwards to
/// `NotificationService.SendNotificationBatch`.
async fn send_notification_batch(
    State(mut state): State<GatewayState>,
    method: axum::http::Method,
    axum::extract::OriginalUri(original_uri): axum::extract::OriginalUri,
    headers: HeaderMap,
    EnvelopeJson(body): EnvelopeJson<Value>,
) -> Result<Json<Value>, GatewayError> {
    let notifications = body
        .get("notifications")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().map(parse_send_notification_request).collect())
        .unwrap_or_default();
    let mut req =
        tonic::Request::new(headlines_proto::v1::SendNotificationBatchRequest { notifications });
    attach_auth(
        method.as_str(),
        original_uri.path(),
        original_uri.query().unwrap_or(""),
        &headers,
        &mut req,
        &state.auth_strategy,
    )
    .await?;
    let _ = state
        .notification_client
        .send_notification_batch(req)
        .await?;
    Ok(Json(json!({})))
}

/// `GET /v1/users/{user_id}/notifications` — forwards to
/// `NotificationService.ListUserNotifications`.
async fn list_user_notifications(
    State(mut state): State<GatewayState>,
    method: axum::http::Method,
    axum::extract::OriginalUri(original_uri): axum::extract::OriginalUri,
    Path(user_id): Path<String>,
    axum::extract::Query(qs): axum::extract::Query<std::collections::HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Json<Value>, GatewayError> {
    let page_size = qs
        .get("page_size")
        .and_then(|v| v.parse::<i32>().ok())
        .unwrap_or(0);
    let page_token = qs.get("page_token").cloned().unwrap_or_default();
    let unread_only = qs.get("unread_only").map(|v| v == "true").unwrap_or(false);
    let mut req = tonic::Request::new(headlines_proto::v1::ListUserNotificationsRequest {
        user_id,
        page_size,
        page_token,
        unread_only,
    });
    attach_auth(
        method.as_str(),
        original_uri.path(),
        original_uri.query().unwrap_or(""),
        &headers,
        &mut req,
        &state.auth_strategy,
    )
    .await?;
    let _ = state
        .notification_client
        .list_user_notifications(req)
        .await?;
    Ok(Json(json!({})))
}

/// `POST /v1/notifications/{id}/read` — forwards to
/// `NotificationService.MarkNotificationRead`.
async fn mark_notification_read(
    State(mut state): State<GatewayState>,
    method: axum::http::Method,
    axum::extract::OriginalUri(original_uri): axum::extract::OriginalUri,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, GatewayError> {
    let mut req = tonic::Request::new(headlines_proto::v1::MarkNotificationReadRequest { id });
    attach_auth(
        method.as_str(),
        original_uri.path(),
        original_uri.query().unwrap_or(""),
        &headers,
        &mut req,
        &state.auth_strategy,
    )
    .await?;
    let _ = state
        .notification_client
        .mark_notification_read(req)
        .await?;
    Ok(Json(json!({})))
}

/// `POST /v1/users/{user_id}/notifications:mark-all-read` — forwards to
/// `NotificationService.MarkAllUserNotificationsRead`.
async fn mark_all_user_notifications_read(
    State(mut state): State<GatewayState>,
    method: axum::http::Method,
    axum::extract::OriginalUri(original_uri): axum::extract::OriginalUri,
    Path(user_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, GatewayError> {
    let mut req =
        tonic::Request::new(headlines_proto::v1::MarkAllUserNotificationsReadRequest { user_id });
    attach_auth(
        method.as_str(),
        original_uri.path(),
        original_uri.query().unwrap_or(""),
        &headers,
        &mut req,
        &state.auth_strategy,
    )
    .await?;
    let _ = state
        .notification_client
        .mark_all_user_notifications_read(req)
        .await?;
    Ok(Json(json!({})))
}

/// `GET /v1/users/{user_id}/notification-preferences` — forwards to
/// `NotificationService.GetUserNotificationPreferences`.
async fn get_user_notification_preferences(
    State(mut state): State<GatewayState>,
    method: axum::http::Method,
    axum::extract::OriginalUri(original_uri): axum::extract::OriginalUri,
    Path(user_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, GatewayError> {
    let mut req =
        tonic::Request::new(headlines_proto::v1::GetUserNotificationPreferencesRequest { user_id });
    attach_auth(
        method.as_str(),
        original_uri.path(),
        original_uri.query().unwrap_or(""),
        &headers,
        &mut req,
        &state.auth_strategy,
    )
    .await?;
    let _ = state
        .notification_client
        .get_user_notification_preferences(req)
        .await?;
    Ok(Json(json!({})))
}

/// `PATCH /v1/users/{user_id}/notification-preferences` — forwards to
/// `NotificationService.UpdateUserNotificationPreferences`.
async fn update_user_notification_preferences(
    State(mut state): State<GatewayState>,
    method: axum::http::Method,
    axum::extract::OriginalUri(original_uri): axum::extract::OriginalUri,
    Path(user_id): Path<String>,
    headers: HeaderMap,
    EnvelopeJson(body): EnvelopeJson<Value>,
) -> Result<Json<Value>, GatewayError> {
    // Body shape: `{ "preferences": {...}, "update_mask": {"paths": [...]} }`.
    // Per the proto, the `preferences.user_id` field is the canonical
    // identifier; we override it with the path param so a client can't
    // mismatch the URL and the body.
    let mut preferences = body
        .get("preferences")
        .map(parse_notification_preferences)
        .unwrap_or_default();
    preferences.user_id = user_id;
    let update_mask = body.get("update_mask").map(parse_field_mask);

    let mut req = tonic::Request::new(
        headlines_proto::v1::UpdateUserNotificationPreferencesRequest {
            preferences: Some(preferences),
            update_mask,
        },
    );
    attach_auth(
        method.as_str(),
        original_uri.path(),
        original_uri.query().unwrap_or(""),
        &headers,
        &mut req,
        &state.auth_strategy,
    )
    .await?;
    let _ = state
        .notification_client
        .update_user_notification_preferences(req)
        .await?;
    Ok(Json(json!({})))
}

fn parse_send_notification_request(v: &Value) -> headlines_proto::v1::SendNotificationRequest {
    let idempotency_key = v
        .get("idempotency_key")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let user_id = v
        .get("user_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let article_id = v
        .get("article_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let kind = v
        .get("kind")
        .and_then(Value::as_str)
        .and_then(parse_notification_kind_str)
        .unwrap_or(0);
    let channels = v
        .get("channels")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|c| c.as_str().and_then(parse_notification_channel_str))
                .collect()
        })
        .unwrap_or_default();
    let payload = v.get("payload").map(parse_notification_payload);
    headlines_proto::v1::SendNotificationRequest {
        idempotency_key,
        user_id,
        article_id,
        kind,
        channels,
        payload,
    }
}

fn parse_notification_payload(v: &Value) -> headlines_proto::v1::NotificationPayload {
    let title = v
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let body = v
        .get("body")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let image_url = v
        .get("image_url")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let data = v
        .get("data")
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_owned())))
                .collect()
        })
        .unwrap_or_default();
    headlines_proto::v1::NotificationPayload {
        title,
        body,
        image_url,
        data,
    }
}

fn parse_notification_preferences(v: &Value) -> headlines_proto::v1::NotificationPreferences {
    let disabled_channels = v
        .get("disabled_channels")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|c| c.as_str().and_then(parse_notification_channel_str))
                .collect()
        })
        .unwrap_or_default();
    let disabled_kinds = v
        .get("disabled_kinds")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|c| c.as_str().and_then(parse_notification_kind_str))
                .collect()
        })
        .unwrap_or_default();
    let quiet_hours = v.get("quiet_hours").map(parse_quiet_hours);
    headlines_proto::v1::NotificationPreferences {
        user_id: String::new(),
        disabled_channels,
        disabled_kinds,
        quiet_hours,
        updated_at: None,
    }
}

fn parse_quiet_hours(v: &Value) -> headlines_proto::v1::QuietHours {
    let enabled = v.get("enabled").and_then(Value::as_bool).unwrap_or(false);
    let timezone = v
        .get("timezone")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let start_hour = v
        .get("start_hour")
        .and_then(Value::as_i64)
        .map(|n| n as i32)
        .unwrap_or(0);
    let end_hour = v
        .get("end_hour")
        .and_then(Value::as_i64)
        .map(|n| n as i32)
        .unwrap_or(0);
    headlines_proto::v1::QuietHours {
        enabled,
        timezone,
        start_hour,
        end_hour,
    }
}

/// Parse a `NotificationKind` enum string (with or without the
/// `NOTIFICATION_KIND_` prefix) into the proto integer. Returns `None` for
/// unknown values.
fn parse_notification_kind_str(s: &str) -> Option<i32> {
    use headlines_proto::v1::NotificationKind as K;
    let bare = s.strip_prefix("NOTIFICATION_KIND_").unwrap_or(s);
    Some(match bare {
        "UNSPECIFIED" => K::Unspecified as i32,
        "NEW_ARTICLE" => K::NewArticle as i32,
        "NEW_FOLLOWER" => K::NewFollower as i32,
        "ARTICLE_TOMBSTONED" => K::ArticleTombstoned as i32,
        "ARTICLE_EDITED" => K::ArticleEdited as i32,
        "MENTION" => K::Mention as i32,
        "REPLY" => K::Reply as i32,
        "SYSTEM" => K::System as i32,
        _ => return None,
    })
}

/// Parse a `NotificationChannel` enum string (with or without the
/// `NOTIFICATION_CHANNEL_` prefix) into the proto integer. Returns `None`
/// for unknown values.
fn parse_notification_channel_str(s: &str) -> Option<i32> {
    use headlines_proto::v1::NotificationChannel as C;
    let bare = s.strip_prefix("NOTIFICATION_CHANNEL_").unwrap_or(s);
    Some(match bare {
        "UNSPECIFIED" => C::Unspecified as i32,
        "PUSH" => C::Push as i32,
        "EMAIL" => C::Email as i32,
        "SMS" => C::Sms as i32,
        "IN_APP" => C::InApp as i32,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_to_json_emits_snake_case_fields() {
        // Arrange
        let acc = headlines_proto::v1::Account {
            id: "abc".into(),
            short_name: "sn".into(),
            author_name: "an".into(),
            author_url: "https://x".into(),
            status: AccountStatus::Active as i32,
            deleted_at: None,
            created_at: Some(prost_types::Timestamp {
                seconds: 1_700_000_000,
                nanos: 0,
            }),
            updated_at: None,
        };

        // Act
        let v = account_to_json(&acc);

        // Assert — fields are snake_case, status is the enum string, the
        // populated timestamp is RFC3339 and the absent ones are `null`.
        assert_eq!(v["id"], "abc");
        assert_eq!(v["short_name"], "sn");
        assert_eq!(v["author_name"], "an");
        assert_eq!(v["author_url"], "https://x");
        assert_eq!(v["status"], "ACCOUNT_STATUS_ACTIVE");
        assert!(v["deleted_at"].is_null());
        assert!(v["updated_at"].is_null());
        assert!(v["created_at"].as_str().unwrap().starts_with("2023-"));
    }

    #[test]
    fn account_status_str_round_trips_each_variant() {
        // Arrange / Act / Assert — every enum value maps to its proto
        // identifier.
        assert_eq!(
            account_status_str(AccountStatus::Unspecified as i32),
            "ACCOUNT_STATUS_UNSPECIFIED"
        );
        assert_eq!(
            account_status_str(AccountStatus::Active as i32),
            "ACCOUNT_STATUS_ACTIVE"
        );
        assert_eq!(
            account_status_str(AccountStatus::Deleted as i32),
            "ACCOUNT_STATUS_DELETED"
        );
    }

    #[test]
    fn account_status_str_falls_back_to_unspecified_for_unknown_int() {
        // Arrange / Act
        let s = account_status_str(9999);

        // Assert
        assert_eq!(s, "ACCOUNT_STATUS_UNSPECIFIED");
    }

    #[test]
    fn timestamp_to_rfc3339_is_iso8601_z() {
        // Arrange
        let ts = prost_types::Timestamp {
            seconds: 0,
            nanos: 0,
        };

        // Act
        let s = timestamp_to_rfc3339(&ts);

        // Assert
        assert!(s.starts_with("1970-01-01T00:00:00"));
    }

    /// Build a minimal `SignedRequestStrategy` so the unit tests can run
    /// `attach_auth` without spinning up Postgres. Uses an empty resolver
    /// (the strategy is only invoked on the malformed-header / anonymous
    /// paths in these tests) and a `LocalClock` time source.
    fn build_test_strategy() -> Arc<SignedRequestStrategy> {
        use headlines_auth::{
            AlgorithmRegistry, Ed25519, InMemoryKeyResolver, InMemoryNonceStore, LocalClock,
        };
        let resolver = Arc::new(InMemoryKeyResolver::new());
        let algos = Arc::new(AlgorithmRegistry::new().with(Box::new(Ed25519)));
        let clock = Arc::new(LocalClock::default());
        let nonces = Arc::new(InMemoryNonceStore::new());
        Arc::new(SignedRequestStrategy::new(resolver, algos, clock, nonces))
    }

    #[tokio::test]
    async fn attach_auth_with_no_authorization_forwards_anonymous_subject() {
        // Arrange — no Authorization header at all; gateway should attach
        // `Subject::Anonymous` so AuthorizationLayer can decide.
        let strategy = build_test_strategy();
        let headers = HeaderMap::new();
        let mut req =
            tonic::Request::new(headlines_proto::v1::GetAccountRequest { id: "abc".into() });

        // Act
        attach_auth("GET", "/v1/accounts/abc", "", &headers, &mut req, &strategy)
            .await
            .expect("anonymous attach must succeed");

        // Assert — outbound metadata carries the trust header with an
        // Anonymous subject; no `authorization` metadata leaks downstream.
        let trust = req
            .metadata()
            .get(TRUSTED_SUBJECT_HEADER)
            .expect("trust header present");
        let subj: Subject = serde_json::from_str(trust.to_str().unwrap()).unwrap();
        assert_eq!(subj, Subject::Anonymous);
        assert!(req.metadata().get("authorization").is_none());
    }

    #[tokio::test]
    async fn attach_auth_with_malformed_authorization_returns_401() {
        // Arrange — header doesn't start with `Signature`; gateway must
        // refuse rather than passing the request through.
        let strategy = build_test_strategy();
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            "Bearer not-our-format".parse().unwrap(),
        );
        let mut req =
            tonic::Request::new(headlines_proto::v1::GetAccountRequest { id: "abc".into() });

        // Act
        let res = attach_auth("GET", "/v1/accounts/abc", "", &headers, &mut req, &strategy).await;

        // Assert
        let err = res.expect_err("malformed header must surface as GatewayError");
        match err {
            GatewayError::Grpc(s) => assert_eq!(s.code(), tonic::Code::Unauthenticated),
            other => panic!("expected Grpc(Unauthenticated), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn attach_auth_strips_inbound_authorization_metadata() {
        // Arrange — caller pre-populated outgoing `authorization` metadata
        // (defense-in-depth). Even on the anonymous path, gateway must not
        // forward an `authorization` to the gRPC service.
        let strategy = build_test_strategy();
        let headers = HeaderMap::new();
        let mut req =
            tonic::Request::new(headlines_proto::v1::GetAccountRequest { id: "abc".into() });
        req.metadata_mut()
            .insert("authorization", "leftover".parse().unwrap());

        // Act
        attach_auth("GET", "/v1/accounts/abc", "", &headers, &mut req, &strategy)
            .await
            .unwrap();

        // Assert
        assert!(req.metadata().get("authorization").is_none());
    }

    #[test]
    fn openapi_constant_is_valid_json_with_paths() {
        // Arrange / Act
        let parsed: serde_json::Value =
            serde_json::from_str(OPENAPI_JSON).expect("openapi.json parses");

        // Assert
        assert_eq!(parsed["swagger"], "2.0");
        assert!(parsed["paths"]["/v1/accounts/{id}"].is_object());
        assert!(
            parsed["paths"]["/v1/accounts"]["post"]["operationId"]
                .as_str()
                .unwrap()
                .starts_with("AccountService_")
        );
    }
}
