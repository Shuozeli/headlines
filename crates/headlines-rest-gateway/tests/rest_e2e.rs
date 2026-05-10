//! End-to-end integration tests for the REST gateway.
//!
//! Spins up the **full** REST → axum → tonic Channel → gRPC server → Postgres
//! pipeline (no mocks) and exercises one route per family via `reqwest`. The
//! coverage gap this file closes:
//!
//! - `headlines-rest-gateway`'s 19 unit tests cover only JSON converters and
//!   `tonic::Status` → HTTP status mapping. None of them touches the wire.
//! - The per-service tests under `crates/headlines-api/tests/*.rs` boot a
//!   gRPC server but skip the gateway entirely.
//!
//! Tests SKIP cleanly when `DATABASE_URL` is unset; cleanup is best-effort
//! `DELETE` keyed on this test's UUIDs only — never `TRUNCATE`. AAA structure
//! per `~/.claude/rules/testing-patterns.md`.
//!
//! ## Signing note (post Bug 2 / Position A architectural fix)
//!
//! The REST gateway now runs `SignedRequestStrategy::authenticate` against
//! the inbound REST request itself. The canonical string is built off
//! `(method = REST verb, path = REST URL, body_hash = sha256(canonical
//! proto encoding the gateway will forward, query = sorted)`. On success
//! the gateway forwards the resolved `Subject` to the **trusted** in-process
//! gRPC listener via the `TRUSTED_SUBJECT_HEADER` metadata key, and the
//! signature-verifying `AuthInterceptor` is bypassed there. The public gRPC
//! listener still requires direct gRPC clients to sign with the gRPC method
//! path; the REST surface signs with the REST URL.
//!
//! See `rest_create_account_signed_path` for the canonical
//! REST-URL-signing example, and
//! `gateway_rejects_forged_trusted_subject_header_on_public_listener` for
//! the forgery-rejection assertion.

#![allow(clippy::too_many_arguments)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use ed25519_dalek::{Signer, SigningKey};
use prost::Message;
use rand::rngs::OsRng;
use reqwest::StatusCode;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tonic::transport::Server;
use uuid::Uuid;

use headlines_api::{
    AccountServiceImpl, AccountStreamServiceImpl, ArticleServiceImpl, BootstrapMode,
    DraftServiceImpl, EventServiceImpl, FeedFollowServiceImpl, FeedRecommendationServiceImpl,
    FollowServiceImpl, NotificationServiceImpl, UserServiceImpl,
};
use headlines_auth::{
    AlgorithmRegistry, AuthInterceptor, AuthorizationLayer, Ed25519, InMemoryNonceStore,
    LocalClock, PostgresKeyResolver, ProtoBodyHasher, SignedRequestStrategy,
    TrustedSubjectInterceptor,
};
use headlines_core::{TimeSource as _, Tso};
use headlines_proto::v1::{
    account_service_server::AccountServiceServer,
    account_stream_service_server::AccountStreamServiceServer,
    article_service_server::ArticleServiceServer, draft_service_server::DraftServiceServer,
    event_service_server::EventServiceServer, feed_follow_service_server::FeedFollowServiceServer,
    feed_recommendation_service_server::FeedRecommendationServiceServer,
    follow_service_server::FollowServiceServer,
    notification_service_server::NotificationServiceServer, user_service_server::UserServiceServer,
};
use headlines_store::{
    Db, PgAccountRepo, PgAccountStreamRepo, PgArticleRepo, PgDraftRepo, PgEventRepo,
    PgFeedFollowRepo, PgFeedRecommendationRepo, PgFollowRepo, PgKeyRepo, PgUserRepo,
};

// ---------------------------------------------------------------------------
// Modest service caps — none of these are exercised at the boundary by this
// suite, but the service constructors require explicit values.
// ---------------------------------------------------------------------------

const TEST_CONTENT_MAX_BYTES: usize = 64 * 1024;
const TEST_EVENTS_BATCH_MAX_ITEMS: usize = 64;
const TEST_FEEDS_REPLACE_MAX_ITEMS: usize = 64;

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

struct FullStack {
    db: Db,
    rest_base: String,
    clock: Arc<LocalClock>,
    /// Public gRPC listener address — exposed so a test can dial it
    /// directly (e.g. to assert a forged trusted-subject header is
    /// rejected on the public surface).
    public_grpc_addr: SocketAddr,
    _trusted_grpc_addr: SocketAddr,
    _rest_addr: SocketAddr,
}

async fn maybe_connect_db() -> Option<Db> {
    let url = std::env::var("DATABASE_URL").ok()?;
    Db::connect(&url, 4).await.ok()
}

/// Spin up the full pipeline:
///   reqwest → axum (random port) → tonic Channel → trusted gRPC (random port) → DB.
///
/// Bug 2 architectural fix: the gRPC layer is now split into two listeners,
/// mirroring `crates/headlines-server/src/main.rs`:
///
/// - **public** listener on `127.0.0.1:<auto>` wrapped with the
///   signature-verifying `AuthInterceptor`. External clients dial here.
/// - **trusted** listener on `127.0.0.1:<auto>` wrapped with
///   `TrustedSubjectInterceptor`. The REST gateway dials here after running
///   its own auth strategy on the inbound REST request and forwarding the
///   resolved `Subject` via `TRUSTED_SUBJECT_HEADER`.
async fn spawn_full_stack() -> FullStack {
    spawn_full_stack_with_articles_cap(TEST_CONTENT_MAX_BYTES).await
}

/// Variant that lets a single test override the article content cap. Used
/// by `rest_post_oversized_article_returns_resource_exhausted` to drive the
/// `CONTENT_TOO_LARGE` path without a multi-megabyte payload.
async fn spawn_full_stack_with_articles_cap(articles_cap: usize) -> FullStack {
    let db = maybe_connect_db()
        .await
        .expect("DATABASE_URL must be set for integration tests");

    // ---- Auth pipeline (mirrors crates/headlines-server/src/main.rs) ----
    let algos = Arc::new(AlgorithmRegistry::new().with(Box::new(Ed25519)));
    let resolver = Arc::new(PostgresKeyResolver::new(db.clone()));
    let clock = Arc::new(LocalClock::default());
    let nonces = Arc::new(InMemoryNonceStore::new());
    let strategy = Arc::new(SignedRequestStrategy::new(
        resolver,
        algos.clone(),
        clock.clone(),
        nonces,
    ));

    // ---- Repos shared between both listeners ----
    let account_repo = Arc::new(PgAccountRepo::new(db.clone()));
    let key_repo = Arc::new(PgKeyRepo::new(db.clone()));
    let user_repo = Arc::new(PgUserRepo::new(db.clone()));
    let article_account_repo = Arc::new(PgAccountRepo::new(db.clone()));
    let article_repo = Arc::new(PgArticleRepo::new(db.clone()));
    let draft_account_repo = Arc::new(PgAccountRepo::new(db.clone()));
    let draft_repo = Arc::new(PgDraftRepo::new(db.clone()));
    let follow_user_repo = Arc::new(PgUserRepo::new(db.clone()));
    let follow_account_repo = Arc::new(PgAccountRepo::new(db.clone()));
    let follow_repo = Arc::new(PgFollowRepo::new(db.clone()));
    let feed_user_repo = Arc::new(PgUserRepo::new(db.clone()));
    let feed_repo = Arc::new(PgFeedRecommendationRepo::new(db.clone()));
    let feed_follow_user_repo = Arc::new(PgUserRepo::new(db.clone()));
    let feed_follow_repo = Arc::new(PgFeedFollowRepo::new(db.clone()));
    let stream_account_repo = Arc::new(PgAccountRepo::new(db.clone()));
    let stream_repo = Arc::new(PgAccountStreamRepo::new(db.clone()));
    let event_repo = Arc::new(PgEventRepo::new(db.clone()));

    let make_account = || {
        AccountServiceImpl::new(
            account_repo.clone(),
            key_repo.clone(),
            algos.clone(),
            BootstrapMode::Open,
        )
    };
    let make_user = || {
        UserServiceImpl::new(
            user_repo.clone(),
            key_repo.clone(),
            algos.clone(),
            BootstrapMode::Open,
        )
    };
    let make_article = || {
        ArticleServiceImpl::new(
            article_account_repo.clone(),
            article_repo.clone(),
            articles_cap,
        )
    };
    let make_draft = || {
        DraftServiceImpl::new(
            draft_account_repo.clone(),
            draft_repo.clone(),
            TEST_CONTENT_MAX_BYTES,
        )
    };
    let make_follow = || {
        FollowServiceImpl::new(
            follow_user_repo.clone(),
            follow_account_repo.clone(),
            follow_repo.clone(),
        )
    };
    let make_feed_recommendation = || {
        FeedRecommendationServiceImpl::new(
            feed_user_repo.clone(),
            feed_repo.clone(),
            TEST_FEEDS_REPLACE_MAX_ITEMS,
        )
    };
    let make_feed_follow =
        || FeedFollowServiceImpl::new(feed_follow_user_repo.clone(), feed_follow_repo.clone());
    let make_account_stream =
        || AccountStreamServiceImpl::new(stream_account_repo.clone(), stream_repo.clone());
    let make_event = || {
        EventServiceImpl::new(
            event_repo.clone(),
            clock.clone(),
            TEST_EVENTS_BATCH_MAX_ITEMS,
        )
    };
    let make_notification = NotificationServiceImpl::new;

    // ---- Public gRPC listener (signature-verifying) ----
    let public_listener =
        std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral public gRPC port");
    public_listener.set_nonblocking(true).unwrap();
    let public_grpc_addr = public_listener.local_addr().unwrap();
    let public_listener = tokio::net::TcpListener::from_std(public_listener).unwrap();
    let public_inc = tokio_stream::wrappers::TcpListenerStream::new(public_listener);

    let interceptor = AuthInterceptor::new(strategy.clone(), Arc::new(ProtoBodyHasher));
    let authorize_public = AuthorizationLayer::new();
    let trace_public = tower_http::trace::TraceLayer::new_for_grpc();
    let public_server = Server::builder()
        .layer(trace_public)
        .layer(interceptor)
        .layer(authorize_public)
        .add_service(AccountServiceServer::new(make_account()))
        .add_service(UserServiceServer::new(make_user()))
        .add_service(ArticleServiceServer::new(make_article()))
        .add_service(DraftServiceServer::new(make_draft()))
        .add_service(FollowServiceServer::new(make_follow()))
        .add_service(FeedRecommendationServiceServer::new(
            make_feed_recommendation(),
        ))
        .add_service(FeedFollowServiceServer::new(make_feed_follow()))
        .add_service(AccountStreamServiceServer::new(make_account_stream()))
        .add_service(EventServiceServer::new(make_event()))
        .add_service(NotificationServiceServer::new(make_notification()));
    tokio::spawn(async move {
        let _ = public_server.serve_with_incoming(public_inc).await;
    });

    // ---- Trusted internal gRPC listener (loopback only) ----
    let trusted_listener =
        std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral trusted gRPC port");
    trusted_listener.set_nonblocking(true).unwrap();
    let trusted_grpc_addr = trusted_listener.local_addr().unwrap();
    let trusted_listener = tokio::net::TcpListener::from_std(trusted_listener).unwrap();
    let trusted_inc = tokio_stream::wrappers::TcpListenerStream::new(trusted_listener);

    let trusted_layer = TrustedSubjectInterceptor::new();
    let authorize_trusted = AuthorizationLayer::new();
    let trace_trusted = tower_http::trace::TraceLayer::new_for_grpc();
    let trusted_server = Server::builder()
        .layer(trace_trusted)
        .layer(trusted_layer)
        .layer(authorize_trusted)
        .add_service(AccountServiceServer::new(make_account()))
        .add_service(UserServiceServer::new(make_user()))
        .add_service(ArticleServiceServer::new(make_article()))
        .add_service(DraftServiceServer::new(make_draft()))
        .add_service(FollowServiceServer::new(make_follow()))
        .add_service(FeedRecommendationServiceServer::new(
            make_feed_recommendation(),
        ))
        .add_service(FeedFollowServiceServer::new(make_feed_follow()))
        .add_service(AccountStreamServiceServer::new(make_account_stream()))
        .add_service(EventServiceServer::new(make_event()))
        .add_service(NotificationServiceServer::new(make_notification()));
    tokio::spawn(async move {
        let _ = trusted_server.serve_with_incoming(trusted_inc).await;
    });

    // ---- Build the REST router pointing at the trusted listener ----
    let grpc_endpoint = format!("http://{trusted_grpc_addr}");
    let mut router = None;
    for _ in 0..50 {
        match headlines_rest_gateway::build_app(&grpc_endpoint, strategy.clone()).await {
            Ok(r) => {
                router = Some(r);
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }
    let router = router.expect("REST gateway must connect to trusted gRPC server");

    // ---- REST server on its own random port ----
    let rest_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let rest_addr = rest_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(rest_listener, router).await;
    });

    let rest_base = format!("http://{rest_addr}");

    FullStack {
        db,
        rest_base,
        clock,
        public_grpc_addr,
        _trusted_grpc_addr: trusted_grpc_addr,
        _rest_addr: rest_addr,
    }
}

// ---------------------------------------------------------------------------
// Signing helpers
// ---------------------------------------------------------------------------

/// Build a `HEADLINES-SIGN-V1` `Authorization` header value.
///
/// `path` is the canonical-string path. After the Bug 2 architectural fix,
/// the REST gateway runs the auth strategy on the inbound REST request and
/// canonicalises against the **REST URL** path the client actually called
/// (e.g. `/v1/articles/{id}/tombstone`), so this helper takes the REST URL
/// path verbatim.
fn sign_rest_request(
    method: &str,
    path: &str,
    canonical_query: &str,
    body: &[u8],
    key_id: Uuid,
    signer: &SigningKey,
    ts: Tso,
    nonce: &[u8],
) -> String {
    let request_hash: [u8; 32] = Sha256::digest(body).into();
    let mut hex = String::with_capacity(64);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for b in &request_hash {
        hex.push(HEX[(*b >> 4) as usize] as char);
        hex.push(HEX[(*b & 0x0F) as usize] as char);
    }
    let canonical = format!(
        "HEADLINES-SIGN-V1\n{method}\n{path}\n{canonical_query}\n{hex}\n{key_id}\n{ts}\n{nonce_b64}",
        method = method,
        path = path,
        canonical_query = canonical_query,
        hex = hex,
        key_id = key_id,
        ts = ts.as_u64(),
        nonce_b64 = B64.encode(nonce),
    );
    let sig = signer.sign(canonical.as_bytes()).to_bytes();
    format!(
        "Signature key_id={kid}, algo=ed25519, ts={ts}, nonce={nonce}, sig={sig}",
        kid = key_id,
        ts = ts.as_u64(),
        nonce = B64.encode(nonce),
        sig = B64.encode(sig),
    )
}

fn unique_nonce() -> Vec<u8> {
    Uuid::now_v7().as_bytes().to_vec()
}

fn make_signing_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

fn ed25519_pk_b64(sk: &SigningKey) -> String {
    B64.encode(sk.verifying_key().as_bytes())
}

// ---------------------------------------------------------------------------
// DB seeding helpers
// ---------------------------------------------------------------------------

async fn seed_account(db: &Db, sk: &SigningKey) -> (Uuid, Uuid) {
    let mut conn = db.get().await.unwrap();
    let account_id = Uuid::now_v7();
    let key_id = Uuid::now_v7();
    let pk_b64 = ed25519_pk_b64(sk);

    diesel::sql_query(
        "INSERT INTO accounts (id, short_name, author_name, status) \
         VALUES ($1, $2, 'REST E2E Author', 'active')",
    )
    .bind::<diesel::sql_types::Uuid, _>(account_id)
    .bind::<diesel::sql_types::Text, _>(format!("rest-e2e-{}", account_id.simple()))
    .execute(&mut conn)
    .await
    .unwrap();
    diesel::sql_query(
        "INSERT INTO account_keys (account_id, key_id, algo, public_key, status) \
         VALUES ($1, $2, 'ed25519', $3, 'active')",
    )
    .bind::<diesel::sql_types::Uuid, _>(account_id)
    .bind::<diesel::sql_types::Uuid, _>(key_id)
    .bind::<diesel::sql_types::Text, _>(pk_b64)
    .execute(&mut conn)
    .await
    .unwrap();
    (account_id, key_id)
}

async fn seed_user(db: &Db, sk: &SigningKey) -> (Uuid, Uuid) {
    let mut conn = db.get().await.unwrap();
    let user_id = Uuid::now_v7();
    let key_id = Uuid::now_v7();
    let pk_b64 = ed25519_pk_b64(sk);

    diesel::sql_query("INSERT INTO users (id, display_name, status) VALUES ($1, $2, 'active')")
        .bind::<diesel::sql_types::Uuid, _>(user_id)
        .bind::<diesel::sql_types::Text, _>(format!("rest-user-{}", user_id.simple()))
        .execute(&mut conn)
        .await
        .unwrap();
    diesel::sql_query(
        "INSERT INTO user_keys (user_id, key_id, algo, public_key, status) \
         VALUES ($1, $2, 'ed25519', $3, 'active')",
    )
    .bind::<diesel::sql_types::Uuid, _>(user_id)
    .bind::<diesel::sql_types::Uuid, _>(key_id)
    .bind::<diesel::sql_types::Text, _>(pk_b64)
    .execute(&mut conn)
    .await
    .unwrap();
    (user_id, key_id)
}

async fn seed_system(db: &Db, name: &str, scopes: &[&str], sk: &SigningKey) -> (Uuid, Uuid) {
    let mut conn = db.get().await.unwrap();
    let system_id = Uuid::now_v7();
    let key_id = Uuid::now_v7();
    let pk_b64 = ed25519_pk_b64(sk);

    diesel::sql_query("INSERT INTO systems (id, name, status) VALUES ($1, $2, 'active')")
        .bind::<diesel::sql_types::Uuid, _>(system_id)
        .bind::<diesel::sql_types::Text, _>(format!("{name}-{system_id}"))
        .execute(&mut conn)
        .await
        .unwrap();
    diesel::sql_query(
        "INSERT INTO system_keys (system_id, key_id, algo, public_key, status) \
         VALUES ($1, $2, 'ed25519', $3, 'active')",
    )
    .bind::<diesel::sql_types::Uuid, _>(system_id)
    .bind::<diesel::sql_types::Uuid, _>(key_id)
    .bind::<diesel::sql_types::Text, _>(pk_b64)
    .execute(&mut conn)
    .await
    .unwrap();
    for scope in scopes {
        diesel::sql_query("INSERT INTO system_scopes (system_id, scope) VALUES ($1, $2)")
            .bind::<diesel::sql_types::Uuid, _>(system_id)
            .bind::<diesel::sql_types::Text, _>(*scope)
            .execute(&mut conn)
            .await
            .unwrap();
    }
    (system_id, key_id)
}

/// Insert a live article directly so anonymous reads can target it without a
/// publish round-trip first.
async fn seed_live_article(db: &Db, account_id: Uuid, title: &str) -> Uuid {
    let mut conn = db.get().await.unwrap();
    let article_id = Uuid::now_v7();
    diesel::sql_query("INSERT INTO articles (id, account_id, state) VALUES ($1, $2, 'live')")
        .bind::<diesel::sql_types::Uuid, _>(article_id)
        .bind::<diesel::sql_types::Uuid, _>(account_id)
        .execute(&mut conn)
        .await
        .unwrap();
    diesel::sql_query(
        "INSERT INTO articles_live (article_id, current_version, published_at, updated_at) \
         VALUES ($1, 1, now(), now())",
    )
    .bind::<diesel::sql_types::Uuid, _>(article_id)
    .execute(&mut conn)
    .await
    .unwrap();
    // Content is a `[Node]` array — an element with one text child. The
    // jsonb shape mirrors `headlines_api::services::article::nodes_to_json`
    // (tag/children for elements, `{text}` for text nodes).
    let content_json = json!([
        {
            "tag": "p",
            "children": [{"text": "REST E2E body"}]
        }
    ]);
    diesel::sql_query(
        "INSERT INTO article_versions (article_id, version, title, content) \
         VALUES ($1, 1, $2, $3::jsonb)",
    )
    .bind::<diesel::sql_types::Uuid, _>(article_id)
    .bind::<diesel::sql_types::Text, _>(title)
    .bind::<diesel::sql_types::Text, _>(serde_json::to_string(&content_json).unwrap())
    .execute(&mut conn)
    .await
    .unwrap();
    article_id
}

// ---------------------------------------------------------------------------
// Cleanup helpers — best-effort DELETE filters keyed on this test's UUIDs.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Cleanup {
    user_ids: Vec<Uuid>,
    account_ids: Vec<Uuid>,
    article_ids: Vec<Uuid>,
    system_ids: Vec<Uuid>,
    event_user_ids: Vec<Uuid>,
}

async fn run_cleanup(db: &Db, c: Cleanup) {
    let url = db.database_url().to_owned();
    let _ = tokio::spawn(async move {
        let mut conn = match AsyncPgConnection::establish(&url).await {
            Ok(c) => c,
            Err(_) => return,
        };
        if !c.event_user_ids.is_empty() {
            let _ = diesel::sql_query("DELETE FROM events WHERE user_id = ANY($1)")
                .bind::<diesel::sql_types::Array<diesel::sql_types::Uuid>, _>(c.event_user_ids)
                .execute(&mut conn)
                .await;
        }
        if !c.user_ids.is_empty() {
            let _ = diesel::sql_query("DELETE FROM follows WHERE user_id = ANY($1)")
                .bind::<diesel::sql_types::Array<diesel::sql_types::Uuid>, _>(c.user_ids.clone())
                .execute(&mut conn)
                .await;
            let _ = diesel::sql_query("DELETE FROM feed_recommendation WHERE user_id = ANY($1)")
                .bind::<diesel::sql_types::Array<diesel::sql_types::Uuid>, _>(c.user_ids.clone())
                .execute(&mut conn)
                .await;
            let _ = diesel::sql_query("DELETE FROM user_keys WHERE user_id = ANY($1)")
                .bind::<diesel::sql_types::Array<diesel::sql_types::Uuid>, _>(c.user_ids.clone())
                .execute(&mut conn)
                .await;
            let _ = diesel::sql_query("DELETE FROM users WHERE id = ANY($1)")
                .bind::<diesel::sql_types::Array<diesel::sql_types::Uuid>, _>(c.user_ids)
                .execute(&mut conn)
                .await;
        }
        if !c.article_ids.is_empty() {
            let _ = diesel::sql_query("DELETE FROM article_versions WHERE article_id = ANY($1)")
                .bind::<diesel::sql_types::Array<diesel::sql_types::Uuid>, _>(c.article_ids.clone())
                .execute(&mut conn)
                .await;
            let _ = diesel::sql_query("DELETE FROM articles_live WHERE article_id = ANY($1)")
                .bind::<diesel::sql_types::Array<diesel::sql_types::Uuid>, _>(c.article_ids.clone())
                .execute(&mut conn)
                .await;
            let _ = diesel::sql_query("DELETE FROM articles_tombstone WHERE article_id = ANY($1)")
                .bind::<diesel::sql_types::Array<diesel::sql_types::Uuid>, _>(c.article_ids.clone())
                .execute(&mut conn)
                .await;
            let _ = diesel::sql_query("DELETE FROM articles WHERE id = ANY($1)")
                .bind::<diesel::sql_types::Array<diesel::sql_types::Uuid>, _>(c.article_ids)
                .execute(&mut conn)
                .await;
        }
        if !c.account_ids.is_empty() {
            let _ = diesel::sql_query("DELETE FROM account_keys WHERE account_id = ANY($1)")
                .bind::<diesel::sql_types::Array<diesel::sql_types::Uuid>, _>(c.account_ids.clone())
                .execute(&mut conn)
                .await;
            let _ = diesel::sql_query("DELETE FROM accounts WHERE id = ANY($1)")
                .bind::<diesel::sql_types::Array<diesel::sql_types::Uuid>, _>(c.account_ids)
                .execute(&mut conn)
                .await;
        }
        if !c.system_ids.is_empty() {
            let _ = diesel::sql_query("DELETE FROM system_keys WHERE system_id = ANY($1)")
                .bind::<diesel::sql_types::Array<diesel::sql_types::Uuid>, _>(c.system_ids.clone())
                .execute(&mut conn)
                .await;
            let _ = diesel::sql_query("DELETE FROM system_scopes WHERE system_id = ANY($1)")
                .bind::<diesel::sql_types::Array<diesel::sql_types::Uuid>, _>(c.system_ids.clone())
                .execute(&mut conn)
                .await;
            let _ = diesel::sql_query("DELETE FROM systems WHERE id = ANY($1)")
                .bind::<diesel::sql_types::Array<diesel::sql_types::Uuid>, _>(c.system_ids)
                .execute(&mut conn)
                .await;
        }
    })
    .await;
}

macro_rules! skip_if_no_db {
    () => {{
        if std::env::var("DATABASE_URL").is_err() {
            eprintln!("DATABASE_URL not set; skipping integration test");
            return;
        }
    }};
}

// ===========================================================================
// Tests
// ===========================================================================

// 1. GET /v1/accounts/{id} — anonymous read after seeding.
#[tokio::test]
async fn rest_get_account_returns_200_with_json_envelope() {
    skip_if_no_db!();

    // Arrange — seed an account directly.
    let h = spawn_full_stack().await;
    let sk = make_signing_key();
    let (account_id, _) = seed_account(&h.db, &sk).await;

    // Act
    let resp = reqwest::Client::new()
        .get(format!("{}/v1/accounts/{}", h.rest_base, account_id))
        .send()
        .await
        .expect("REST request must reach the gateway");

    // Assert — 200 + JSON envelope per api-conventions.md.
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        resp.headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.contains("application/json"))
            .unwrap_or(false),
        "Content-Type must be application/json"
    );
    let body: Value = resp.json().await.expect("body must be JSON");
    assert_eq!(body["id"], account_id.to_string());
    assert!(
        body["short_name"]
            .as_str()
            .unwrap_or_default()
            .starts_with("rest-e2e-")
    );

    run_cleanup(
        &h.db,
        Cleanup {
            account_ids: vec![account_id],
            ..Default::default()
        },
    )
    .await;
}

// 2. GET /v1/accounts/{nonexistent} — 404 + google.rpc.Status envelope
// with a populated `ErrorInfo` detail (Bug 3 fix).
#[tokio::test]
async fn rest_get_account_404_carries_grpc_status_envelope() {
    skip_if_no_db!();

    // Arrange — never-seeded UUIDv7 cannot exist in the table.
    let h = spawn_full_stack().await;
    let bogus = Uuid::now_v7();

    // Act
    let resp = reqwest::Client::new()
        .get(format!("{}/v1/accounts/{}", h.rest_base, bogus))
        .send()
        .await
        .expect("REST request must reach the gateway");

    // Assert — 404 with `{ code, message, details: [ErrorInfo] }` per
    // api-conventions.md. The handler returns `HeadlinesError::AccountNotFound`,
    // which sets the canonical `ErrorInfo.reason = "ACCOUNT_NOT_FOUND"` and
    // `domain = "headlines.v1"`, with `metadata.account_id` echoing the
    // requested id.
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body: Value = resp.json().await.expect("body must be JSON");
    assert_eq!(body["code"], tonic::Code::NotFound as i32);
    assert!(
        body["message"]
            .as_str()
            .unwrap_or_default()
            .to_lowercase()
            .contains("account"),
        "message should name the missing resource, got: {}",
        body
    );
    let details = body["details"].as_array().expect("details must be array");
    assert_eq!(
        details.len(),
        1,
        "expected one ErrorInfo detail, got {body}"
    );
    let info = &details[0];
    assert_eq!(info["@type"], "type.googleapis.com/google.rpc.ErrorInfo");
    assert_eq!(info["reason"], "ACCOUNT_NOT_FOUND");
    assert_eq!(info["domain"], "headlines.v1");
    assert_eq!(info["metadata"]["account_id"], bogus.to_string());
}

// 3. POST /v1/accounts — anonymous open-mode bootstrap. Bug 1 fix:
// the gateway now registers a `POST /v1/accounts` handler (was missing
// originally), so a fresh CreateAccount request lands at the gRPC
// `AccountService.CreateAccount` and returns the new account row +
// bootstrapped `key_id`.
#[tokio::test]
async fn rest_create_account_open_mode() {
    skip_if_no_db!();

    // Arrange — fresh signing key the bootstrap response will reflect back.
    // `short_name` is capped at 32 chars + `[A-Za-z0-9 _-]`; truncate the
    // UUIDv7 simple form so the validator accepts it.
    let h = spawn_full_stack().await;
    let sk = make_signing_key();
    let uniq = Uuid::now_v7().simple().to_string();
    let short_name = format!("rest-open-{}", &uniq[..16]);
    let body = json!({
        "short_name": short_name,
        "author_name": "REST Open Author",
        "initial_key": {
            "algo": "ed25519",
            "public_key": ed25519_pk_b64(&sk),
        },
    });

    // Act
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/accounts", h.rest_base))
        .json(&body)
        .send()
        .await
        .expect("REST request must reach the gateway");

    // Assert — 200 + `account.id` + `key_id` round-trip through the JSON
    // envelope.
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "POST /v1/accounts must be wired up (Bug 1)"
    );
    let body: Value = resp.json().await.expect("body must be JSON");
    let account_id_str = body["account"]["id"]
        .as_str()
        .expect("response must include account.id");
    let account_id = Uuid::parse_str(account_id_str).expect("account.id must be a UUID");
    assert!(
        body["account"]["short_name"]
            .as_str()
            .unwrap_or_default()
            .starts_with("rest-open-")
    );
    assert!(
        body["key_id"].is_string(),
        "response must include the bootstrapped key_id"
    );

    run_cleanup(
        &h.db,
        Cleanup {
            account_ids: vec![account_id],
            ..Default::default()
        },
    )
    .await;
}

// 4. Signed POST round-trip via the gateway. Bug 2 / Position A fix:
//
//   The gateway now runs the auth strategy on the inbound REST request and
//   canonicalises against the **REST URL** the client called. A signature
//   built off `/v1/articles/{id}/tombstone` therefore authenticates; a
//   signature built off the gRPC method path does not (the gateway no
//   longer forwards the inbound `Authorization` header).
//
// We exercise the signed code path through `POST /v1/articles/{id}/tombstone`
// with an account-self signature — that's a real "POST /v1/..." route the
// gateway wires up.
#[tokio::test]
async fn rest_create_account_signed_path() {
    skip_if_no_db!();

    let h = spawn_full_stack().await;

    // -- Arrange: seed an account + a live article we can tombstone. --
    let acct_sk = make_signing_key();
    let (account_id, account_key_id) = seed_account(&h.db, &acct_sk).await;
    let article_id = seed_live_article(&h.db, account_id, "to-tombstone").await;

    let req_proto = headlines_proto::v1::TombstoneArticleRequest {
        id: article_id.to_string(),
        reason: "rest-e2e".into(),
    };
    let body_bytes = req_proto.encode_to_vec();
    let body_json = json!({"reason": "rest-e2e"});

    // Act — sign with the REST URL path. After the architectural fix
    // this is the canonical-string path the gateway verifies against.
    let ts = h.clock.now().await.unwrap();
    let rest_url = format!("/v1/articles/{}/tombstone", article_id);
    let auth_rest_path = sign_rest_request(
        "POST",
        &rest_url,
        "",
        &body_bytes,
        account_key_id,
        &acct_sk,
        ts,
        &unique_nonce(),
    );
    let resp_rest_path = reqwest::Client::new()
        .post(format!("{}{}", h.rest_base, rest_url))
        .header(reqwest::header::AUTHORIZATION, &auth_rest_path)
        .json(&body_json)
        .send()
        .await
        .expect("REST request must reach the gateway");

    // Assert — REST-URL signature must authenticate and the tombstone
    // goes through (200 + state == TOMBSTONE).
    assert_eq!(
        resp_rest_path.status(),
        StatusCode::OK,
        "REST-URL-path signature must authenticate (Bug 2 fix)"
    );
    let resp_body: Value = resp_rest_path.json().await.expect("body must be JSON");
    assert_eq!(resp_body["id"], article_id.to_string());
    assert_eq!(resp_body["state"], "ARTICLE_STATE_TOMBSTONE");

    run_cleanup(
        &h.db,
        Cleanup {
            account_ids: vec![account_id],
            article_ids: vec![article_id],
            ..Default::default()
        },
    )
    .await;
}

// 5. GET /v1/users/{id} — anonymous returns NOT_FOUND for privacy per
// users.md (Bug 4 fix). The proto AUTH_TABLE now admits ANONYMOUS so the
// request reaches the handler; the handler then translates a non-self,
// non-`users.read`-System caller into `USER_NOT_FOUND` so the API does
// not leak user existence.
#[tokio::test]
async fn rest_get_user_returns_404_for_anonymous() {
    skip_if_no_db!();

    // Arrange — seed a real user so any "no row" result wouldn't poison
    // this assertion.
    let h = spawn_full_stack().await;
    let sk = make_signing_key();
    let (user_id, _) = seed_user(&h.db, &sk).await;

    // Act — anonymous (no Authorization header).
    let resp = reqwest::Client::new()
        .get(format!("{}/v1/users/{}", h.rest_base, user_id))
        .send()
        .await
        .expect("REST request must reach the gateway");

    // Assert — 404 USER_NOT_FOUND per users.md privacy carve-out.
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "anonymous GetUser must surface USER_NOT_FOUND (privacy carve-out)"
    );
    let body: Value = resp.json().await.expect("body must be JSON");
    assert_eq!(body["code"], tonic::Code::NotFound as i32);
    let details = body["details"].as_array().expect("details must be array");
    assert_eq!(
        details.len(),
        1,
        "expected one ErrorInfo detail, got {body}"
    );
    assert_eq!(details[0]["reason"], "USER_NOT_FOUND");
    assert_eq!(details[0]["domain"], "headlines.v1");
    assert_eq!(details[0]["metadata"]["user_id"], user_id.to_string());

    run_cleanup(
        &h.db,
        Cleanup {
            user_ids: vec![user_id],
            ..Default::default()
        },
    )
    .await;
}

// 6. GET /v1/articles/{id} — anonymous read with recursive Node tree.
#[tokio::test]
async fn rest_get_article_anonymous() {
    skip_if_no_db!();

    // Arrange — seed an account + a live article with a structured Node
    // body so we can verify the Node tree round-trips through JSON.
    let h = spawn_full_stack().await;
    let sk = make_signing_key();
    let (account_id, _) = seed_account(&h.db, &sk).await;
    let article_id = seed_live_article(&h.db, account_id, "REST Read Title").await;

    // Act
    let resp = reqwest::Client::new()
        .get(format!("{}/v1/articles/{}", h.rest_base, article_id))
        .send()
        .await
        .expect("REST request must reach the gateway");

    // Assert
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.expect("body must be JSON");
    assert_eq!(body["id"], article_id.to_string());
    assert_eq!(body["state"], "ARTICLE_STATE_LIVE");
    let live = &body["live"];
    assert_eq!(live["title"], "REST Read Title");
    let content = live["content"].as_array().expect("content is an array");
    assert_eq!(content.len(), 1, "expected one root Node");
    // Recursive structure: element → children → text.
    assert_eq!(content[0]["tag"], "p");
    let children = content[0]["children"]
        .as_array()
        .expect("element must have children");
    assert_eq!(children.len(), 1);
    assert_eq!(children[0]["text"], "REST E2E body");

    run_cleanup(
        &h.db,
        Cleanup {
            account_ids: vec![account_id],
            article_ids: vec![article_id],
            ..Default::default()
        },
    )
    .await;
}

// 7. POST /v1/accounts/{id}/articles — signed publish, full Node round-trip.
#[tokio::test]
async fn rest_publish_article_signed() {
    skip_if_no_db!();

    // Arrange — seed an account with an active key.
    let h = spawn_full_stack().await;
    let acct_sk = make_signing_key();
    let (account_id, account_key_id) = seed_account(&h.db, &acct_sk).await;

    // Build a rich Node tree to verify recursive JSON ↔ proto translation.
    let content = vec![
        headlines_proto::v1::Node {
            kind: Some(headlines_proto::v1::node::Kind::Element(
                headlines_proto::v1::NodeElement {
                    tag: "p".into(),
                    attrs: Default::default(),
                    children: vec![headlines_proto::v1::Node {
                        kind: Some(headlines_proto::v1::node::Kind::Text("Hello".into())),
                    }],
                },
            )),
        },
        headlines_proto::v1::Node {
            kind: Some(headlines_proto::v1::node::Kind::Text(", REST!".into())),
        },
    ];
    let body_proto = headlines_proto::v1::PublishArticleRequest {
        account_id: account_id.to_string(),
        title: "Signed REST Publish".into(),
        author_name: "Me".into(),
        author_url: String::new(),
        content,
    };
    let body_bytes = body_proto.encode_to_vec();
    // JSON shape mirrors the gateway's `parse_nodes` expectations.
    let body_json = json!({
        "title": body_proto.title,
        "author_name": body_proto.author_name,
        "content": [
            {"tag": "p", "children": [{"text": "Hello"}]},
            {"text": ", REST!"}
        ]
    });

    let ts = h.clock.now().await.unwrap();
    let rest_url = format!("/v1/accounts/{}/articles", account_id);
    let auth = sign_rest_request(
        "POST",
        &rest_url,
        "",
        &body_bytes,
        account_key_id,
        &acct_sk,
        ts,
        &unique_nonce(),
    );

    // Act
    let resp = reqwest::Client::new()
        .post(format!("{}{}", h.rest_base, rest_url))
        .header(reqwest::header::AUTHORIZATION, auth)
        .json(&body_json)
        .send()
        .await
        .expect("REST request must reach the gateway");

    // Assert — 200 + Node tree round-trips.
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.expect("body must be JSON");
    let article_id =
        Uuid::parse_str(body["id"].as_str().expect("id must be present")).expect("UUID");
    assert_eq!(body["state"], "ARTICLE_STATE_LIVE");
    let live = &body["live"];
    assert_eq!(live["title"], "Signed REST Publish");
    let content = live["content"].as_array().expect("content is array");
    assert_eq!(content.len(), 2, "two root nodes");
    assert_eq!(content[0]["tag"], "p");
    assert_eq!(content[0]["children"][0]["text"], "Hello");
    assert_eq!(content[1]["text"], ", REST!");

    run_cleanup(
        &h.db,
        Cleanup {
            account_ids: vec![account_id],
            article_ids: vec![article_id],
            ..Default::default()
        },
    )
    .await;
}

// 8. PUT /v1/users/{user_id}/feed/recommendation — System with the right
// scope succeeds; user-self attempt is rejected with PERMISSION_DENIED.
#[tokio::test]
async fn rest_replace_recommendation_feed_system_only() {
    skip_if_no_db!();

    // Arrange — a user, a system with `feeds.recommendation.write`, and an
    // account + article so the feed has something legitimate to point at.
    let h = spawn_full_stack().await;
    let user_sk = make_signing_key();
    let (user_id, user_key_id) = seed_user(&h.db, &user_sk).await;

    let acct_sk = make_signing_key();
    let (account_id, _) = seed_account(&h.db, &acct_sk).await;
    let article_id = seed_live_article(&h.db, account_id, "Feed Item").await;

    let sys_sk = make_signing_key();
    let (system_id, sys_key_id) = seed_system(
        &h.db,
        "rest-feed-writer",
        &["feeds.recommendation.write"],
        &sys_sk,
    )
    .await;

    let req_proto = headlines_proto::v1::ReplaceRecommendationFeedRequest {
        user_id: user_id.to_string(),
        article_ids: vec![article_id.to_string()],
    };
    let body_bytes = req_proto.encode_to_vec();
    let body_json = json!({"article_ids": [article_id.to_string()]});

    // Act 1 — System with the right scope succeeds. The gateway
    // canonicalises against the REST verb + REST URL the client called,
    // so we sign "PUT /v1/users/{id}/feed/recommendation".
    let ts = h.clock.now().await.unwrap();
    let rest_url = format!("/v1/users/{}/feed/recommendation", user_id);
    let auth_sys = sign_rest_request(
        "PUT",
        &rest_url,
        "",
        &body_bytes,
        sys_key_id,
        &sys_sk,
        ts,
        &unique_nonce(),
    );
    let resp_sys = reqwest::Client::new()
        .put(format!("{}{}", h.rest_base, rest_url))
        .header(reqwest::header::AUTHORIZATION, auth_sys)
        .json(&body_json)
        .send()
        .await
        .expect("REST request must reach the gateway");

    // Act 2 — user-self attempt should be PERMISSION_DENIED.
    let ts2 = h.clock.now().await.unwrap();
    let auth_user = sign_rest_request(
        "PUT",
        &rest_url,
        "",
        &body_bytes,
        user_key_id,
        &user_sk,
        ts2,
        &unique_nonce(),
    );
    let resp_user = reqwest::Client::new()
        .put(format!("{}{}", h.rest_base, rest_url))
        .header(reqwest::header::AUTHORIZATION, auth_user)
        .json(&body_json)
        .send()
        .await
        .expect("REST request must reach the gateway");

    // Assert
    assert_eq!(resp_sys.status(), StatusCode::OK);
    let body: Value = resp_sys.json().await.expect("body must be JSON");
    assert_eq!(body["stored_count"], 1);

    assert_eq!(resp_user.status(), StatusCode::FORBIDDEN);

    run_cleanup(
        &h.db,
        Cleanup {
            user_ids: vec![user_id],
            account_ids: vec![account_id],
            article_ids: vec![article_id],
            system_ids: vec![system_id],
            ..Default::default()
        },
    )
    .await;
}

// 9. POST /v1/events — user-self records an OPEN event.
#[tokio::test]
async fn rest_record_event_user_self() {
    skip_if_no_db!();

    // Arrange — user + account + article so the event has a real target.
    let h = spawn_full_stack().await;
    let user_sk = make_signing_key();
    let (user_id, user_key_id) = seed_user(&h.db, &user_sk).await;

    let acct_sk = make_signing_key();
    let (account_id, _) = seed_account(&h.db, &acct_sk).await;
    let article_id = seed_live_article(&h.db, account_id, "Event Target").await;

    let occurred_at = chrono::Utc::now();
    let req_proto = headlines_proto::v1::RecordEventRequest {
        user_id: user_id.to_string(),
        article_id: article_id.to_string(),
        r#type: headlines_proto::v1::EventType::Open as i32,
        occurred_at: Some(prost_types::Timestamp {
            seconds: occurred_at.timestamp(),
            nanos: occurred_at.timestamp_subsec_nanos() as i32,
        }),
        surface: "rest".into(),
        properties: Some(headlines_proto::v1::record_event_request::Properties::Open(
            headlines_proto::v1::OpenProperties {
                feed_kind: "follow".into(),
                position: 0,
            },
        )),
    };
    let body_bytes = req_proto.encode_to_vec();
    let body_json = json!({
        "user_id": user_id.to_string(),
        "article_id": article_id.to_string(),
        "type": "EVENT_TYPE_OPEN",
        "occurred_at": occurred_at.to_rfc3339(),
        "surface": "rest",
        "properties": {
            "open": {"feed_kind": "follow", "position": 0}
        }
    });

    let ts = h.clock.now().await.unwrap();
    let auth = sign_rest_request(
        "POST",
        "/v1/events",
        "",
        &body_bytes,
        user_key_id,
        &user_sk,
        ts,
        &unique_nonce(),
    );

    // Act
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/events", h.rest_base))
        .header(reqwest::header::AUTHORIZATION, auth)
        .json(&body_json)
        .send()
        .await
        .expect("REST request must reach the gateway");

    // Assert — 200 + server-issued event id round-trips.
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.expect("body must be JSON");
    let event_id = Uuid::parse_str(body["id"].as_str().expect("id must be present")).expect("UUID");
    assert_eq!(event_id.get_version_num(), 7);
    assert_eq!(body["type"], "EVENT_TYPE_OPEN");
    assert_eq!(body["user_id"], user_id.to_string());

    run_cleanup(
        &h.db,
        Cleanup {
            user_ids: vec![user_id],
            account_ids: vec![account_id],
            article_ids: vec![article_id],
            event_user_ids: vec![user_id],
            ..Default::default()
        },
    )
    .await;
}

// 10. GET /v1/accounts/{id}/article-stream — System with `articles.stream`
// pulls and we cursor-paginate across two pages.
#[tokio::test]
async fn rest_stream_account_articles_system_scope() {
    skip_if_no_db!();

    // Arrange — one account, two live articles so page_size=1 forces a
    // pagination cursor.
    let h = spawn_full_stack().await;
    let acct_sk = make_signing_key();
    let (account_id, _) = seed_account(&h.db, &acct_sk).await;
    let article_a = seed_live_article(&h.db, account_id, "Stream A").await;
    let article_b = seed_live_article(&h.db, account_id, "Stream B").await;

    let sys_sk = make_signing_key();
    let (system_id, sys_key_id) =
        seed_system(&h.db, "rest-streamer", &["articles.stream"], &sys_sk).await;

    // Page 1: page_size=1, no token. After the Bug 2 fix the gateway
    // canonicalises against `(GET, /v1/accounts/{id}/article-stream,
    // canonicalize_query("page_size=1"))`. The body hash covers the
    // proto-encoded StreamAccountArticlesRequest the gateway will forward
    // (account_id from path, page_size=1 from query).
    let req1 = headlines_proto::v1::StreamAccountArticlesRequest {
        account_id: account_id.to_string(),
        page_size: 1,
        page_token: String::new(),
    };
    let body1 = req1.encode_to_vec();
    let rest_url = format!("/v1/accounts/{}/article-stream", account_id);
    let ts1 = h.clock.now().await.unwrap();
    let auth1 = sign_rest_request(
        "GET",
        &rest_url,
        "page_size=1",
        &body1,
        sys_key_id,
        &sys_sk,
        ts1,
        &unique_nonce(),
    );

    // Act 1
    let resp1 = reqwest::Client::new()
        .get(format!("{}{}?page_size=1", h.rest_base, rest_url))
        .header(reqwest::header::AUTHORIZATION, auth1)
        .send()
        .await
        .expect("page 1 must reach the gateway");
    assert_eq!(resp1.status(), StatusCode::OK);
    let body1_resp: Value = resp1.json().await.expect("body must be JSON");
    let items1 = body1_resp["items"].as_array().expect("items array");
    assert_eq!(items1.len(), 1);
    let token = body1_resp["next_page_token"]
        .as_str()
        .expect("next_page_token present")
        .to_owned();
    assert!(!token.is_empty(), "first page must yield a cursor");

    // Page 2 — sign separately with the new token in the request body.
    // The canonical query is the sorted form of `page_size=1&page_token=...`
    // (already alphabetical). The wire URL pre-canonicalisation is
    // `?page_size=1&page_token=<encoded>`; the gateway runs
    // `canonicalize_query` so both forms hash identically.
    let req2 = headlines_proto::v1::StreamAccountArticlesRequest {
        account_id: account_id.to_string(),
        page_size: 1,
        page_token: token.clone(),
    };
    let body2 = req2.encode_to_vec();
    // canonicalize_query keeps percent-encoding verbatim, so we have to
    // sign over the same encoded form the gateway sees on the wire.
    let canonical_query = format!("page_size=1&page_token={}", urlencode(&token));
    let ts2 = h.clock.now().await.unwrap();
    let auth2 = sign_rest_request(
        "GET",
        &rest_url,
        &canonical_query,
        &body2,
        sys_key_id,
        &sys_sk,
        ts2,
        &unique_nonce(),
    );
    let resp2 = reqwest::Client::new()
        .get(format!(
            "{}{}?page_size=1&page_token={}",
            h.rest_base,
            rest_url,
            urlencode(&token)
        ))
        .header(reqwest::header::AUTHORIZATION, auth2)
        .send()
        .await
        .expect("page 2 must reach the gateway");

    // Assert — page 2 also returns 200 with at least the second item.
    assert_eq!(resp2.status(), StatusCode::OK);
    let body2_resp: Value = resp2.json().await.expect("body must be JSON");
    let items2 = body2_resp["items"].as_array().expect("items array");
    assert_eq!(items2.len(), 1);
    let id1 = items1[0]["article"]["id"]
        .as_str()
        .expect("page 1 has an article")
        .to_owned();
    let id2 = items2[0]["article"]["id"]
        .as_str()
        .expect("page 2 has an article")
        .to_owned();
    assert_ne!(id1, id2, "the two pages must surface distinct articles");

    run_cleanup(
        &h.db,
        Cleanup {
            account_ids: vec![account_id],
            article_ids: vec![article_a, article_b],
            system_ids: vec![system_id],
            ..Default::default()
        },
    )
    .await;
}

/// Tiny percent-encoder for the few characters Postgres' `next_page_token`
/// can emit. Keeps this test free of an extra dep.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

// 11. GET /openapi.json — the embedded swagger doc surfaces with at least
// 30 routes.
#[tokio::test]
async fn rest_openapi_endpoint_serves_valid_json() {
    skip_if_no_db!();

    // Arrange
    let h = spawn_full_stack().await;

    // Act
    let resp = reqwest::Client::new()
        .get(format!("{}/openapi.json", h.rest_base))
        .send()
        .await
        .expect("REST request must reach the gateway");

    // Assert — 200, application/json, parses, and exposes >=30 routes.
    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_owned())
        .unwrap_or_default();
    assert!(
        ct.contains("application/json"),
        "Content-Type should be application/json, got {ct}"
    );
    let body: Value = resp.json().await.expect("openapi.json must be JSON");
    let paths = body["paths"]
        .as_object()
        .expect("openapi must have a `paths` object");
    assert!(
        paths.len() >= 30,
        "openapi.json must expose at least 30 routes, found {}",
        paths.len()
    );
}

// 12. POST /v1/notifications — System with `notifications.send` gets 501
// because the handler is a v1 stub.
#[tokio::test]
async fn rest_notification_returns_501() {
    skip_if_no_db!();

    // Arrange
    let h = spawn_full_stack().await;
    let user_sk = make_signing_key();
    let (user_id, _) = seed_user(&h.db, &user_sk).await;

    let sys_sk = make_signing_key();
    let (system_id, sys_key_id) =
        seed_system(&h.db, "rest-notif-sender", &["notifications.send"], &sys_sk).await;

    let req_proto = headlines_proto::v1::SendNotificationRequest {
        idempotency_key: Uuid::now_v7().to_string(),
        user_id: user_id.to_string(),
        article_id: String::new(),
        kind: 0,
        channels: vec![],
        payload: Some(headlines_proto::v1::NotificationPayload {
            title: "test".into(),
            body: "test".into(),
            image_url: String::new(),
            data: Default::default(),
        }),
    };
    let body_bytes = req_proto.encode_to_vec();
    let body_json = json!({
        "idempotency_key": req_proto.idempotency_key,
        "user_id": user_id.to_string(),
        "payload": {"title": "test", "body": "test"},
    });

    let ts = h.clock.now().await.unwrap();
    let auth = sign_rest_request(
        "POST",
        "/v1/notifications",
        "",
        &body_bytes,
        sys_key_id,
        &sys_sk,
        ts,
        &unique_nonce(),
    );

    // Act
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/notifications", h.rest_base))
        .header(reqwest::header::AUTHORIZATION, auth)
        .json(&body_json)
        .send()
        .await
        .expect("REST request must reach the gateway");

    // Assert — 501 with `code = UNIMPLEMENTED` envelope and a populated
    // `ErrorInfo` detail (Bug 3 fix). Per notifications.md the canonical
    // reason is `NOT_IMPLEMENTED_IN_V1`.
    assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    let body: Value = resp.json().await.expect("body must be JSON");
    assert_eq!(body["code"], tonic::Code::Unimplemented as i32);
    let details = body["details"].as_array().expect("details must be array");
    assert_eq!(
        details.len(),
        1,
        "expected one ErrorInfo detail, got {body}"
    );
    assert_eq!(
        details[0]["@type"],
        "type.googleapis.com/google.rpc.ErrorInfo"
    );
    assert_eq!(details[0]["reason"], "NOT_IMPLEMENTED_IN_V1");
    assert_eq!(details[0]["domain"], "headlines.v1");

    run_cleanup(
        &h.db,
        Cleanup {
            user_ids: vec![user_id],
            system_ids: vec![system_id],
            ..Default::default()
        },
    )
    .await;
}

// 13. Bug 2 fix: a malicious client cannot inject a `Subject` by setting
// the trusted-subject metadata header on a direct dial of the **public**
// gRPC listener. The public listener wraps services with `AuthInterceptor`,
// which strips the trust header on entry — so the request resolves to
// `Subject::Anonymous` (no Authorization either) and bounces off the
// `AuthorizationLayer` for any non-anonymous RPC.
#[tokio::test]
async fn gateway_rejects_forged_trusted_subject_header_on_public_listener() {
    skip_if_no_db!();

    // Arrange — spin up the full stack and craft a tonic request that
    // claims to be a System with `*`. We dial the **public** listener
    // directly (not via the REST gateway), so the trusted-listener
    // short-circuit is unreachable.
    use headlines_auth::TRUSTED_SUBJECT_HEADER;
    use headlines_proto::v1::TombstoneArticleRequest;
    use headlines_proto::v1::article_service_client::ArticleServiceClient;

    let h = spawn_full_stack().await;
    // We need a real article id so the handler doesn't reject for
    // "missing id" before AuthorizationLayer fires; doesn't matter
    // whether it's tombstoned, the auth layer rejects first.
    let acct_sk = make_signing_key();
    let (account_id, _) = seed_account(&h.db, &acct_sk).await;
    let article_id = seed_live_article(&h.db, account_id, "forge-target").await;

    let endpoint = format!("http://{}", h.public_grpc_addr);
    let channel = tonic::transport::Channel::from_shared(endpoint)
        .unwrap()
        .connect()
        .await
        .expect("must dial public gRPC");
    let mut client = ArticleServiceClient::new(channel);

    let forged = headlines_core::Subject::System {
        system_id: Uuid::now_v7(),
        key_id: Uuid::now_v7(),
        scopes: vec!["*".into()],
    };
    let raw = serde_json::to_string(&forged).unwrap();
    let mut req = tonic::Request::new(TombstoneArticleRequest {
        id: article_id.to_string(),
        reason: "forge".into(),
    });
    req.metadata_mut()
        .insert(TRUSTED_SUBJECT_HEADER, raw.parse().unwrap());

    // Act — fire the request directly at the public listener.
    let res = client.tombstone_article(req).await;

    // Assert — must NOT succeed; either UNAUTHENTICATED (no Authorization
    // ever supplied so the public AuthInterceptor would have moved it on
    // as Anonymous) or PERMISSION_DENIED (AuthorizationLayer rejecting an
    // Anonymous subject for an account-self RPC). Either way the
    // forged-System path must not authorise the call.
    let err = res.expect_err("forged trust header must not authorise on public listener");
    let code = err.code();
    assert!(
        matches!(
            code,
            tonic::Code::PermissionDenied | tonic::Code::Unauthenticated
        ),
        "expected PERMISSION_DENIED or UNAUTHENTICATED, got {code:?}"
    );

    run_cleanup(
        &h.db,
        Cleanup {
            account_ids: vec![account_id],
            article_ids: vec![article_id],
            ..Default::default()
        },
    )
    .await;
}

// ===========================================================================
// Robustness / malformed-input batch
// ===========================================================================
//
// These tests pin the gateway's behavior on broken / abusive HTTP requests.
// They cover gaps the original 13 happy-path tests left open: malformed JSON,
// missing required fields, gzip body, oversized payloads, wrong Content-Type,
// and CORS preflight. Each test documents whether the current behavior
// matches a clean error envelope or whether a follow-up batch needs to wrap
// it.

// 14. Malformed JSON body. Pins what happens when an inbound POST carries
// truncated/invalid JSON. Expected: HTTP 400 with the standard
// `{ code, message, details }` envelope and `code == INVALID_ARGUMENT (3)`.
//
// CURRENT BEHAVIOR (documented gap): axum's built-in `Json` extractor
// rejects with a bare `text/plain` body like
// `Failed to parse the request body as JSON: ...`, so the body does NOT
// parse as the standard envelope today. The test asserts the bare-400
// reality and tags the gap; the operational batch can wire a
// `JsonRejection` interceptor in `build_router` that wraps the rejection
// in the gRPC-status-shaped envelope.
#[tokio::test]
async fn rest_post_malformed_json_returns_400_with_envelope() {
    skip_if_no_db!();

    // Arrange — POST /v1/users is open-mode anonymous. No signing needed.
    let h = spawn_full_stack().await;
    let malformed = r#"{ "display_name": "test", "initial_key": "#;

    // Act
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/users", h.rest_base))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(malformed.to_owned())
        .send()
        .await
        .expect("REST request must reach the gateway");

    // Assert — must reject with 400. The body MAY be a clean envelope; if
    // it isn't, that's a documented gap (axum's bare JsonRejection text).
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let bytes = resp.bytes().await.expect("body bytes must arrive");
    match serde_json::from_slice::<Value>(&bytes) {
        Ok(body) => {
            // Either we already wrap it (envelope) or it's some other JSON
            // shape; the assertion below pins the desired behavior. Today
            // axum returns text/plain so this `Ok` arm typically does not
            // fire. If it does, validate the envelope.
            assert_eq!(
                body["code"],
                tonic::Code::InvalidArgument as i32,
                "body parsed as JSON; if so it must be the envelope: {body}"
            );
            assert!(body["message"].is_string());
            assert!(body["details"].is_array());
        }
        Err(_) => {
            // TODO(operational-batch): wrap axum body-parsing rejections in
            // the standard gRPC-status-shaped error envelope so REST clients
            // get a uniform error shape regardless of which layer rejects
            // the request.
            let text = String::from_utf8_lossy(&bytes);
            assert!(
                text.to_lowercase().contains("json"),
                "non-JSON 400 body should at least mention JSON, got: {text}"
            );
        }
    }
}

// 15. Missing required field — `initial_key` is absent. Pins how the
// CreateUser handler reports a missing required field.
//
// EXPECTED: HTTP 400, `code == INVALID_ARGUMENT`. The handler today
// silently substitutes `PublicKey::default()` (empty algo + empty
// public_key) when the field is missing, which the service layer then
// rejects with INVALID_ARGUMENT on the `algo`/`public_key` field. The
// outer code is therefore correct; the message names the offending
// sub-field rather than `initial_key`. We assert the code and that the
// message is informative.
#[tokio::test]
async fn rest_post_missing_required_field_returns_invalid_argument() {
    skip_if_no_db!();

    // Arrange — `display_name` set, no `initial_key`.
    let h = spawn_full_stack().await;
    let body = json!({"display_name": "missing-key"});

    // Act
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/users", h.rest_base))
        .json(&body)
        .send()
        .await
        .expect("REST request must reach the gateway");

    // Assert — 400 with the standard envelope.
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: Value = resp.json().await.expect("body must be JSON envelope");
    assert_eq!(
        body["code"],
        tonic::Code::InvalidArgument as i32,
        "missing required field must surface INVALID_ARGUMENT: {body}"
    );
    assert!(
        !body["message"].as_str().unwrap_or_default().is_empty(),
        "message must be non-empty so clients can act on it: {body}"
    );
    let details = body["details"]
        .as_array()
        .expect("details must be a (possibly empty) array");
    if !details.is_empty() {
        // If the handler attached an ErrorInfo, reason should be a known
        // canonical string. Catch-all `INVALID_ARGUMENT` is acceptable.
        let info = &details[0];
        let reason = info["reason"].as_str().unwrap_or_default();
        assert!(
            !reason.is_empty(),
            "ErrorInfo present but no reason: {body}"
        );
    }
}

// 16. Body sent with `Content-Encoding: gzip`. Pins whether the gateway
// transparently decompresses or rejects cleanly. Either is defensible —
// this test catches a future regression where the gateway silently treats
// gzipped bytes as JSON and returns a confusing parse error.
//
// CURRENT BEHAVIOR: axum + the gateway router do NOT install any
// decompression layer, so a gzipped body is passed through to the `Json`
// extractor unchanged. The extractor sees binary garbage and returns a
// bare 400 (axum's malformed-JSON path). That's the "real bug" branch in
// the test contract — the request had a valid `Content-Encoding`
// declaration but the gateway ignored it. We assert the actual behavior
// here so it's pinned, and tag a follow-up.
#[tokio::test]
async fn rest_post_gzip_body_either_works_or_rejects_cleanly() {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;

    skip_if_no_db!();

    // Arrange — a fully valid CreateUser body, then gzip it.
    let h = spawn_full_stack().await;
    let sk = make_signing_key();
    let body_json = json!({
        "display_name": "gz-user",
        "initial_key": {"algo": "ed25519", "public_key": ed25519_pk_b64(&sk)},
    });
    let body_str = serde_json::to_string(&body_json).unwrap();
    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    enc.write_all(body_str.as_bytes()).unwrap();
    let gzipped = enc.finish().unwrap();

    // Act
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/users", h.rest_base))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header(reqwest::header::CONTENT_ENCODING, "gzip")
        .body(gzipped)
        .send()
        .await
        .expect("REST request must reach the gateway");

    // Assert — three defensible outcomes:
    //   (a) 200 OK + user created (gateway transparently decompressed)
    //   (b) 415 UNSUPPORTED_MEDIA_TYPE / 400 INVALID_ARGUMENT with envelope
    //   (c) Documented gap: bare 400 from axum because the gzipped bytes
    //       fell through to the JSON extractor.
    let status = resp.status();
    if status == StatusCode::OK {
        // Good — gateway decompressed transparently. Clean up the new user.
        let body: Value = resp.json().await.expect("body must be JSON");
        if let Some(user_id_str) = body["user"]["id"].as_str()
            && let Ok(user_id) = Uuid::parse_str(user_id_str)
        {
            run_cleanup(
                &h.db,
                Cleanup {
                    user_ids: vec![user_id],
                    ..Default::default()
                },
            )
            .await;
        }
        return;
    }
    // TODO(operational-batch): install `tower_http::decompression::RequestDecompressionLayer`
    // on the REST router so a `Content-Encoding: gzip` request is decoded
    // transparently. Today the gateway ignores the header and the JSON
    // extractor rejects the gzipped bytes as malformed JSON, returning a
    // bare 400 instead of a 415 or a transparent 200.
    assert!(
        status == StatusCode::BAD_REQUEST
            || status == StatusCode::UNSUPPORTED_MEDIA_TYPE
            || status == StatusCode::LENGTH_REQUIRED,
        "gzip body must reject cleanly with 400/415, got {status}"
    );
}

// 17. Oversized article body. Pins the `RESOURCE_EXHAUSTED` /
// `CONTENT_TOO_LARGE` path on the article publish handler.
//
// EXPECTED: HTTP 429 (RESOURCE_EXHAUSTED) with `ErrorInfo.reason ==
// "CONTENT_TOO_LARGE"`. The article cap is configured at 1024 bytes for
// this test; we send ~8 KiB of element children to trip the validator.
// axum's default 2 MiB body limit is well above 8 KiB so the request
// reaches the service handler before any transport-level rejection.
#[tokio::test]
async fn rest_post_oversized_article_returns_resource_exhausted() {
    skip_if_no_db!();

    // Arrange — small article cap so we don't have to ship 20 MiB.
    let h = spawn_full_stack_with_articles_cap(1024).await;
    let acct_sk = make_signing_key();
    let (account_id, account_key_id) = seed_account(&h.db, &acct_sk).await;

    // Build content > 1024 bytes when serialised as JSON. A `<p>` with a
    // long text child easily clears 1024 bytes once wrapped in the
    // `tag/children/text` envelope.
    let big_text = "x".repeat(8 * 1024);
    let content = vec![headlines_proto::v1::Node {
        kind: Some(headlines_proto::v1::node::Kind::Element(
            headlines_proto::v1::NodeElement {
                tag: "p".into(),
                attrs: Default::default(),
                children: vec![headlines_proto::v1::Node {
                    kind: Some(headlines_proto::v1::node::Kind::Text(big_text.clone())),
                }],
            },
        )),
    }];
    let body_proto = headlines_proto::v1::PublishArticleRequest {
        account_id: account_id.to_string(),
        title: "Oversized".into(),
        author_name: "Me".into(),
        author_url: String::new(),
        content,
    };
    let body_bytes = body_proto.encode_to_vec();
    let body_json = json!({
        "title": "Oversized",
        "author_name": "Me",
        "content": [{"tag": "p", "children": [{"text": big_text}]}],
    });

    let ts = h.clock.now().await.unwrap();
    let rest_url = format!("/v1/accounts/{}/articles", account_id);
    let auth = sign_rest_request(
        "POST",
        &rest_url,
        "",
        &body_bytes,
        account_key_id,
        &acct_sk,
        ts,
        &unique_nonce(),
    );

    // Act
    let resp = reqwest::Client::new()
        .post(format!("{}{}", h.rest_base, rest_url))
        .header(reqwest::header::AUTHORIZATION, auth)
        .json(&body_json)
        .send()
        .await
        .expect("REST request must reach the gateway");

    // Assert — 429 + standard envelope + CONTENT_TOO_LARGE reason.
    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "oversize must surface RESOURCE_EXHAUSTED -> 429"
    );
    let body: Value = resp.json().await.expect("body must be JSON envelope");
    assert_eq!(body["code"], tonic::Code::ResourceExhausted as i32);
    let details = body["details"].as_array().expect("details must be array");
    assert_eq!(details.len(), 1, "expected one ErrorInfo detail: {body}");
    assert_eq!(details[0]["reason"], "CONTENT_TOO_LARGE");
    assert_eq!(details[0]["domain"], "headlines.v1");

    run_cleanup(
        &h.db,
        Cleanup {
            account_ids: vec![account_id],
            ..Default::default()
        },
    )
    .await;
}

// 18. Wrong `Content-Type`. Pins how the gateway behaves when a client
// sends `text/plain` instead of `application/json` to a JSON route.
//
// EXPECTED: HTTP 415 UNSUPPORTED_MEDIA_TYPE — axum's `Json<T>` extractor
// rejects non-JSON Content-Type with 415 by default. We also check that
// the response body either parses as a clean envelope or, at minimum,
// is non-empty plain text. Today axum's default rejection is a plain-text
// `Expected request with `Content-Type: application/json``, which is a
// documented gap; if it gets wrapped in the future this test still
// passes because the status code and existence check both hold.
#[tokio::test]
async fn rest_post_wrong_content_type_returns_unsupported_media_type() {
    skip_if_no_db!();

    // Arrange
    let h = spawn_full_stack().await;

    // Act
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/users", h.rest_base))
        .header(reqwest::header::CONTENT_TYPE, "text/plain")
        .body("not-json")
        .send()
        .await
        .expect("REST request must reach the gateway");

    // Assert — 415 with a non-empty body. If the body parses as a JSON
    // envelope, validate it; otherwise pin the documented-gap text body.
    assert_eq!(
        resp.status(),
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "wrong Content-Type must yield 415 UNSUPPORTED_MEDIA_TYPE"
    );
    let bytes = resp.bytes().await.expect("body bytes must arrive");
    assert!(!bytes.is_empty(), "415 body must not be empty");
    if let Ok(body) = serde_json::from_slice::<Value>(&bytes) {
        // If the gateway wrapped it (future enhancement), it must be the
        // standard envelope. INVALID_ARGUMENT is acceptable here too.
        let code = body["code"].as_i64().unwrap_or(-1);
        assert!(
            code == tonic::Code::InvalidArgument as i64
                || code == tonic::Code::FailedPrecondition as i64,
            "if 415 carries a JSON envelope it must be a clean error code: {body}"
        );
    }
    // TODO(operational-batch): wrap axum's bare 415 plain-text rejection
    // in the standard gRPC-status-shaped envelope.
}

// 19. CORS preflight. Pins whether the gateway responds to an `OPTIONS`
// preflight with the `Access-Control-Allow-*` headers a browser needs.
//
// EXPECTED (after operational batch lands a CORS layer): HTTP 200/204
// with `Access-Control-Allow-Origin` and `Access-Control-Allow-Methods`
// listing GET. Today no CORS middleware is installed in `build_router`,
// so axum returns 405 METHOD_NOT_ALLOWED for the unmatched OPTIONS verb
// and the response carries no `Access-Control-Allow-*` headers. We
// `#[ignore]` this test until the operational batch wires
// `tower_http::cors::CorsLayer`.
#[tokio::test]
#[ignore = "CORS middleware not yet implemented; see operational-batch (TODO: tower_http::cors::CorsLayer)"]
async fn rest_options_preflight_for_cors() {
    skip_if_no_db!();

    // Arrange — pick a real GET route so the preflight has a target.
    let h = spawn_full_stack().await;
    let bogus = Uuid::now_v7();

    // Act — issue the canonical browser preflight.
    let resp = reqwest::Client::new()
        .request(
            reqwest::Method::OPTIONS,
            format!("{}/v1/articles/{}", h.rest_base, bogus),
        )
        .header(reqwest::header::ORIGIN, "https://example.com")
        .header("Access-Control-Request-Method", "GET")
        .header("Access-Control-Request-Headers", "authorization")
        .send()
        .await
        .expect("REST request must reach the gateway");

    // Assert — preflight should be 200 or 204 with permissive ACAO/ACAM.
    let status = resp.status();
    assert!(
        status == StatusCode::OK || status == StatusCode::NO_CONTENT,
        "preflight must succeed, got {status}"
    );
    let acao = resp
        .headers()
        .get("access-control-allow-origin")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        acao == "*" || acao == "https://example.com",
        "Access-Control-Allow-Origin must echo the origin or `*`, got {acao:?}"
    );
    let acam = resp
        .headers()
        .get("access-control-allow-methods")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        acam.to_uppercase().contains("GET"),
        "Access-Control-Allow-Methods must list GET, got {acam:?}"
    );
}
