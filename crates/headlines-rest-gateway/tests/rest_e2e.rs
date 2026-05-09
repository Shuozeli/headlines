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
//! ## Signing note
//!
//! The current REST gateway forwards the inbound `Authorization` header
//! verbatim into outbound gRPC metadata; the gateway does **not** re-derive a
//! body hash off the JSON it received. Authentication therefore happens
//! downstream at the gRPC server's `AuthInterceptor`, where the canonical
//! string fields are `(method=POST, path=/headlines.v1.Foo/Bar, body=proto
//! bytes)` — i.e. the gRPC method path, **not** the REST URL path the client
//! actually hit. Tests that need a valid signature therefore sign with the
//! gRPC method path. See `rest_create_account_signed_path` for an explicit
//! comparison and the bug observation in this file's report.

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
    _grpc_addr: SocketAddr,
    _rest_addr: SocketAddr,
}

async fn maybe_connect_db() -> Option<Db> {
    let url = std::env::var("DATABASE_URL").ok()?;
    Db::connect(&url, 4).await.ok()
}

/// Spin up the full pipeline:
///   reqwest → axum (random port) → tonic Channel → gRPC (random port) → DB.
async fn spawn_full_stack() -> FullStack {
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

    // ---- 10 ServiceImpl instances ----
    let account_repo = Arc::new(PgAccountRepo::new(db.clone()));
    let key_repo = Arc::new(PgKeyRepo::new(db.clone()));
    let account_svc = AccountServiceImpl::new(
        account_repo,
        key_repo.clone(),
        algos.clone(),
        BootstrapMode::Open,
    );

    let user_repo = Arc::new(PgUserRepo::new(db.clone()));
    let user_svc = UserServiceImpl::new(
        user_repo,
        key_repo.clone(),
        algos.clone(),
        BootstrapMode::Open,
    );

    let article_account_repo = Arc::new(PgAccountRepo::new(db.clone()));
    let article_repo = Arc::new(PgArticleRepo::new(db.clone()));
    let article_svc =
        ArticleServiceImpl::new(article_account_repo, article_repo, TEST_CONTENT_MAX_BYTES);

    let draft_account_repo = Arc::new(PgAccountRepo::new(db.clone()));
    let draft_repo = Arc::new(PgDraftRepo::new(db.clone()));
    let draft_svc = DraftServiceImpl::new(draft_account_repo, draft_repo, TEST_CONTENT_MAX_BYTES);

    let follow_user_repo = Arc::new(PgUserRepo::new(db.clone()));
    let follow_account_repo = Arc::new(PgAccountRepo::new(db.clone()));
    let follow_repo = Arc::new(PgFollowRepo::new(db.clone()));
    let follow_svc = FollowServiceImpl::new(follow_user_repo, follow_account_repo, follow_repo);

    let feed_user_repo = Arc::new(PgUserRepo::new(db.clone()));
    let feed_repo = Arc::new(PgFeedRecommendationRepo::new(db.clone()));
    let feed_recommendation_svc =
        FeedRecommendationServiceImpl::new(feed_user_repo, feed_repo, TEST_FEEDS_REPLACE_MAX_ITEMS);

    let feed_follow_user_repo = Arc::new(PgUserRepo::new(db.clone()));
    let feed_follow_repo = Arc::new(PgFeedFollowRepo::new(db.clone()));
    let feed_follow_svc = FeedFollowServiceImpl::new(feed_follow_user_repo, feed_follow_repo);

    let stream_account_repo = Arc::new(PgAccountRepo::new(db.clone()));
    let stream_repo = Arc::new(PgAccountStreamRepo::new(db.clone()));
    let account_stream_svc = AccountStreamServiceImpl::new(stream_account_repo, stream_repo);

    let event_repo = Arc::new(PgEventRepo::new(db.clone()));
    let event_svc = EventServiceImpl::new(event_repo, clock.clone(), TEST_EVENTS_BATCH_MAX_ITEMS);

    let notification_svc = NotificationServiceImpl::new();

    // ---- Tower stack: AuthInterceptor → AuthorizationLayer → TraceLayer ----
    let interceptor = AuthInterceptor::new(strategy, Arc::new(ProtoBodyHasher));
    let authorize = AuthorizationLayer::new();
    let trace = tower_http::trace::TraceLayer::new_for_grpc();

    // ---- gRPC server on a random port ----
    let grpc_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    grpc_listener.set_nonblocking(true).unwrap();
    let grpc_addr = grpc_listener.local_addr().unwrap();
    let grpc_listener = tokio::net::TcpListener::from_std(grpc_listener).unwrap();
    let grpc_inc = tokio_stream::wrappers::TcpListenerStream::new(grpc_listener);

    let server = Server::builder()
        .layer(trace)
        .layer(interceptor)
        .layer(authorize)
        .add_service(AccountServiceServer::new(account_svc))
        .add_service(UserServiceServer::new(user_svc))
        .add_service(ArticleServiceServer::new(article_svc))
        .add_service(DraftServiceServer::new(draft_svc))
        .add_service(FollowServiceServer::new(follow_svc))
        .add_service(FeedRecommendationServiceServer::new(
            feed_recommendation_svc,
        ))
        .add_service(FeedFollowServiceServer::new(feed_follow_svc))
        .add_service(AccountStreamServiceServer::new(account_stream_svc))
        .add_service(EventServiceServer::new(event_svc))
        .add_service(NotificationServiceServer::new(notification_svc));

    tokio::spawn(async move {
        let _ = server.serve_with_incoming(grpc_inc).await;
    });

    // ---- Build the REST router off a tonic Channel pointing at the gRPC port ----
    let grpc_endpoint = format!("http://{grpc_addr}");
    let mut router = None;
    for _ in 0..50 {
        match headlines_rest_gateway::build_app(&grpc_endpoint).await {
            Ok(r) => {
                router = Some(r);
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }
    let router = router.expect("REST gateway must connect to gRPC server");

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
        _grpc_addr: grpc_addr,
        _rest_addr: rest_addr,
    }
}

// ---------------------------------------------------------------------------
// Signing helpers
// ---------------------------------------------------------------------------

/// Build a `HEADLINES-SIGN-V1` `Authorization` header value.
///
/// `path` is the canonical-string path. Per the bug noted at the top of this
/// file, the gRPC server's `AuthInterceptor` re-derives the canonical from
/// the inbound HTTP `Request`, which (after gateway forwarding) carries the
/// **gRPC** method path. So `path` here should be the gRPC method path even
/// when the client hit the REST URL.
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

// 4. Signed POST round-trip via the gateway. Documents one remaining
// quirk after Bug 1 was fixed (POST /v1/accounts is now wired):
//
//   Signed REST requests authenticate correctly when the canonical
//   string uses the **gRPC method path** (`/headlines.v1.X/Y`), not
//   the **REST URL path** (`/v1/...`). The gateway forwards the
//   `Authorization` header verbatim, so the downstream gRPC
//   `AuthInterceptor` verifies against the gRPC path it actually
//   sees on its inbound request. This contradicts the prompt /
//   design intent ("REST signing covers the REST URL path"); the
//   report calls it out (Bug 2 — out of scope for this fix).
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

    // Act 1 — sign with the REST URL path. The gateway forwards the
    // header verbatim, so the gRPC server's interceptor verifies against
    // the gRPC method path and rejects.
    let ts = h.clock.now().await.unwrap();
    let auth_rest_path = sign_rest_request(
        "POST",
        &format!("/v1/articles/{}/tombstone", article_id),
        "",
        &body_bytes,
        account_key_id,
        &acct_sk,
        ts,
        &unique_nonce(),
    );
    let resp_rest_path = reqwest::Client::new()
        .post(format!(
            "{}/v1/articles/{}/tombstone",
            h.rest_base, article_id
        ))
        .header(reqwest::header::AUTHORIZATION, &auth_rest_path)
        .json(&body_json)
        .send()
        .await
        .expect("REST request must reach the gateway");
    let rest_path_status = resp_rest_path.status();

    // Act 2 — sign with the gRPC method path; this matches today's
    // forwarding behavior.
    let ts2 = h.clock.now().await.unwrap();
    let auth_grpc_path = sign_rest_request(
        "POST",
        "/headlines.v1.ArticleService/TombstoneArticle",
        "",
        &body_bytes,
        account_key_id,
        &acct_sk,
        ts2,
        &unique_nonce(),
    );
    let resp_grpc_path = reqwest::Client::new()
        .post(format!(
            "{}/v1/articles/{}/tombstone",
            h.rest_base, article_id
        ))
        .header(reqwest::header::AUTHORIZATION, &auth_grpc_path)
        .json(&body_json)
        .send()
        .await
        .expect("REST request must reach the gateway");

    // Assert — REST-URL-path signature is rejected (401); the
    // gRPC-method-path signature authenticates and the tombstone goes
    // through (200 + state == TOMBSTONE).
    assert!(
        rest_path_status.is_client_error() || rest_path_status.is_server_error(),
        "REST-URL-path signature should currently be rejected; got {}",
        rest_path_status
    );
    assert_eq!(
        resp_grpc_path.status(),
        StatusCode::OK,
        "gRPC-method-path signature must authenticate"
    );
    let resp_body: Value = resp_grpc_path.json().await.expect("body must be JSON");
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
    let auth = sign_rest_request(
        "POST",
        "/headlines.v1.ArticleService/PublishArticle",
        "",
        &body_bytes,
        account_key_id,
        &acct_sk,
        ts,
        &unique_nonce(),
    );

    // Act
    let resp = reqwest::Client::new()
        .post(format!(
            "{}/v1/accounts/{}/articles",
            h.rest_base, account_id
        ))
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

    // Act 1 — System with the right scope succeeds. Note the canonical
    // method is "POST": the gateway forwards via a gRPC unary call which
    // is always HTTP/2 POST under tonic, regardless of the REST verb.
    let ts = h.clock.now().await.unwrap();
    let auth_sys = sign_rest_request(
        "POST",
        "/headlines.v1.FeedRecommendationService/ReplaceRecommendationFeed",
        "",
        &body_bytes,
        sys_key_id,
        &sys_sk,
        ts,
        &unique_nonce(),
    );
    let resp_sys = reqwest::Client::new()
        .put(format!(
            "{}/v1/users/{}/feed/recommendation",
            h.rest_base, user_id
        ))
        .header(reqwest::header::AUTHORIZATION, auth_sys)
        .json(&body_json)
        .send()
        .await
        .expect("REST request must reach the gateway");

    // Act 2 — user-self attempt should be PERMISSION_DENIED.
    let ts2 = h.clock.now().await.unwrap();
    let auth_user = sign_rest_request(
        "POST",
        "/headlines.v1.FeedRecommendationService/ReplaceRecommendationFeed",
        "",
        &body_bytes,
        user_key_id,
        &user_sk,
        ts2,
        &unique_nonce(),
    );
    let resp_user = reqwest::Client::new()
        .put(format!(
            "{}/v1/users/{}/feed/recommendation",
            h.rest_base, user_id
        ))
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
        "/headlines.v1.EventService/RecordEvent",
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

    // Page 1: page_size=1, no token. The gateway forwards `?page_size=1`
    // as proto fields; the server's interceptor canonicalizes the query
    // string `page_size=1` into the signing canonical.
    let req1 = headlines_proto::v1::StreamAccountArticlesRequest {
        account_id: account_id.to_string(),
        page_size: 1,
        page_token: String::new(),
    };
    let body1 = req1.encode_to_vec();
    let ts1 = h.clock.now().await.unwrap();
    let auth1 = sign_rest_request(
        "POST",
        "/headlines.v1.AccountStreamService/StreamAccountArticles",
        "",
        &body1,
        sys_key_id,
        &sys_sk,
        ts1,
        &unique_nonce(),
    );

    // Act 1
    let resp1 = reqwest::Client::new()
        .get(format!(
            "{}/v1/accounts/{}/article-stream?page_size=1",
            h.rest_base, account_id
        ))
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
    let req2 = headlines_proto::v1::StreamAccountArticlesRequest {
        account_id: account_id.to_string(),
        page_size: 1,
        page_token: token.clone(),
    };
    let body2 = req2.encode_to_vec();
    let ts2 = h.clock.now().await.unwrap();
    let auth2 = sign_rest_request(
        "POST",
        "/headlines.v1.AccountStreamService/StreamAccountArticles",
        "",
        &body2,
        sys_key_id,
        &sys_sk,
        ts2,
        &unique_nonce(),
    );
    let resp2 = reqwest::Client::new()
        .get(format!(
            "{}/v1/accounts/{}/article-stream?page_size=1&page_token={}",
            h.rest_base,
            account_id,
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
        "/headlines.v1.NotificationService/SendNotification",
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
