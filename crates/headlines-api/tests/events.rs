//! End-to-end integration tests for `EventService`, exercised through a real
//! tonic in-process server (random TCP port) backed by Postgres on
//! `docker.yuacx.com`. Mirrors `tests/feeds_recommendation.rs` and
//! `tests/account_stream.rs`.
//!
//! Each test mints fresh UUIDv7s. Cleanup is best-effort via DELETE filters
//! at the end; no TRUNCATE.
//!
//! Tests SKIP cleanly when `DATABASE_URL` is unset.
//!
//! AAA structure throughout, per `~/.claude/rules/testing-patterns.md`.

#![allow(clippy::too_many_arguments)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use chrono::Utc;
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use ed25519_dalek::{Signer, SigningKey};
use prost_types::Timestamp;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use tonic::transport::{Channel, Endpoint, Server};
use uuid::Uuid;

use headlines_api::EventServiceImpl;
use headlines_auth::{
    AlgorithmRegistry, AuthInterceptor, AuthorizationLayer, Ed25519, InMemoryNonceStore,
    LocalClock, PostgresKeyResolver, ProtoBodyHasher, SignedRequestStrategy,
};
use headlines_core::{TimeSource as _, Tso};
use headlines_proto::v1::{
    DwellProperties, EventType, ImpressionProperties, LikeProperties, ListEventsRequest,
    OpenProperties, RecordEventBatchRequest, RecordEventRequest, ShareProperties,
    event_service_client::EventServiceClient, event_service_server::EventServiceServer,
    record_event_request,
};
use headlines_store::{Db, PgEventRepo};

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

/// Small batch cap so the BATCH_TOO_LARGE test only needs to push 4 items.
const TEST_BATCH_CAP: usize = 3;

struct Harness {
    db: Db,
    client: EventServiceClient<Channel>,
    clock: Arc<LocalClock>,
    _addr: SocketAddr,
}

async fn maybe_connect_db() -> Option<Db> {
    let url = std::env::var("DATABASE_URL").ok()?;
    Db::connect(&url, 4).await.ok()
}

async fn spawn_server() -> Harness {
    let db = maybe_connect_db()
        .await
        .expect("DATABASE_URL must be set for integration tests");

    let events = Arc::new(PgEventRepo::new(db.clone()));

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

    let svc = EventServiceImpl::new(events, clock.clone(), TEST_BATCH_CAP);

    let interceptor = AuthInterceptor::new(strategy, Arc::new(ProtoBodyHasher));
    let authorize = AuthorizationLayer::new();

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    let listener = tokio::net::TcpListener::from_std(listener).unwrap();
    let stream = tokio_stream::wrappers::TcpListenerStream::new(listener);

    let server = Server::builder()
        .layer(interceptor)
        .layer(authorize)
        .add_service(EventServiceServer::new(svc));

    tokio::spawn(async move {
        let _ = server.serve_with_incoming(stream).await;
    });

    let endpoint = Endpoint::from_shared(format!("http://{addr}"))
        .expect("endpoint")
        .connect_timeout(Duration::from_secs(5));
    let channel = endpoint.connect().await.expect("client connect");
    let client = EventServiceClient::new(channel);

    Harness {
        db,
        client,
        clock,
        _addr: addr,
    }
}

// ---------------------------------------------------------------------------
// Signing helpers (mirrors tests/feeds_recommendation.rs)
// ---------------------------------------------------------------------------

fn build_auth_header<M: prost::Message>(
    sk: &SigningKey,
    key_id: Uuid,
    method: &str,
    path: &str,
    body: &M,
    ts: Tso,
    nonce: &[u8],
) -> String {
    let body_bytes = body.encode_to_vec();
    let request_hash: [u8; 32] = Sha256::digest(&body_bytes).into();
    let mut hex = String::with_capacity(64);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for b in &request_hash {
        hex.push(HEX[(*b >> 4) as usize] as char);
        hex.push(HEX[(*b & 0x0F) as usize] as char);
    }
    let canonical = format!(
        "HEADLINES-SIGN-V1\n{method}\n{path}\n\n{hex}\n{key_id}\n{ts}\n{nonce_b64}",
        method = method,
        path = path,
        hex = hex,
        key_id = key_id,
        ts = ts.as_u64(),
        nonce_b64 = B64.encode(nonce),
    );
    let sig = sk.sign(canonical.as_bytes()).to_bytes();
    format!(
        "Signature key_id={kid}, algo=ed25519, ts={ts}, nonce={nonce}, sig={sig}",
        kid = key_id,
        ts = ts.as_u64(),
        nonce = B64.encode(nonce),
        sig = B64.encode(sig),
    )
}

fn signed<T: prost::Message>(
    msg: T,
    sk: &SigningKey,
    key_id: Uuid,
    full_method: &str,
    ts: Tso,
    nonce: &[u8],
) -> tonic::Request<T> {
    let header = build_auth_header(sk, key_id, "POST", full_method, &msg, ts, nonce);
    let mut req = tonic::Request::new(msg);
    req.metadata_mut()
        .insert("authorization", header.parse().unwrap());
    req
}

fn unique_nonce() -> Vec<u8> {
    Uuid::now_v7().as_bytes().to_vec()
}

fn make_signing_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

// ---------------------------------------------------------------------------
// Seeding / cleanup
// ---------------------------------------------------------------------------

async fn seed_user_with_key(db: &Db, sk: &SigningKey) -> (Uuid, Uuid) {
    let mut conn = db.get().await.unwrap();
    let user_id = Uuid::now_v7();
    let key_id = Uuid::now_v7();
    let pk_b64 = B64.encode(sk.verifying_key().as_bytes());

    diesel::sql_query("INSERT INTO users (id, display_name, status) VALUES ($1, $2, 'active')")
        .bind::<diesel::sql_types::Uuid, _>(user_id)
        .bind::<diesel::sql_types::Text, _>(format!("user-{}", user_id.simple()))
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

async fn insert_system(db: &Db, name: &str, scopes: &[&str], sk: &SigningKey) -> (Uuid, Uuid) {
    let mut conn = db.get().await.unwrap();
    let system_id = Uuid::now_v7();
    let key_id = Uuid::now_v7();
    let pk_b64 = B64.encode(sk.verifying_key().as_bytes());

    diesel::sql_query("INSERT INTO systems (id, name, status) VALUES ($1, $2, 'active')")
        .bind::<diesel::sql_types::Uuid, _>(system_id)
        .bind::<diesel::sql_types::Text, _>(format!("{name}-{system_id}"))
        .execute(&mut conn)
        .await
        .unwrap();
    diesel::sql_query("INSERT INTO system_keys (system_id, key_id, algo, public_key, status) VALUES ($1, $2, 'ed25519', $3, 'active')")
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

async fn cleanup(db: &Db, user_ids: &[Uuid], event_ids: &[Uuid]) {
    let url = db.database_url().to_owned();
    let users = user_ids.to_owned();
    let events = event_ids.to_owned();
    let _ = tokio::spawn(async move {
        let mut conn = match AsyncPgConnection::establish(&url).await {
            Ok(c) => c,
            Err(_) => return,
        };
        if !events.is_empty() {
            let _ = diesel::sql_query("DELETE FROM events WHERE id = ANY($1)")
                .bind::<diesel::sql_types::Array<diesel::sql_types::Uuid>, _>(events)
                .execute(&mut conn)
                .await;
        }
        if !users.is_empty() {
            // Clean up any events authored by these users (bookkeeping).
            let _ = diesel::sql_query("DELETE FROM events WHERE user_id = ANY($1)")
                .bind::<diesel::sql_types::Array<diesel::sql_types::Uuid>, _>(users.clone())
                .execute(&mut conn)
                .await;
            let _ = diesel::sql_query("DELETE FROM user_keys WHERE user_id = ANY($1)")
                .bind::<diesel::sql_types::Array<diesel::sql_types::Uuid>, _>(users.clone())
                .execute(&mut conn)
                .await;
            let _ = diesel::sql_query("DELETE FROM users WHERE id = ANY($1)")
                .bind::<diesel::sql_types::Array<diesel::sql_types::Uuid>, _>(users)
                .execute(&mut conn)
                .await;
        }
    })
    .await;
}

async fn cleanup_system(db: &Db, system_id: Uuid) {
    let mut conn = match db.get().await {
        Ok(c) => c,
        Err(_) => return,
    };
    let _ = diesel::sql_query("DELETE FROM system_keys WHERE system_id = $1")
        .bind::<diesel::sql_types::Uuid, _>(system_id)
        .execute(&mut conn)
        .await;
    let _ = diesel::sql_query("DELETE FROM system_scopes WHERE system_id = $1")
        .bind::<diesel::sql_types::Uuid, _>(system_id)
        .execute(&mut conn)
        .await;
    let _ = diesel::sql_query("DELETE FROM systems WHERE id = $1")
        .bind::<diesel::sql_types::Uuid, _>(system_id)
        .execute(&mut conn)
        .await;
}

/// Delete events filtered by user_id (used for ListEvents tests where ids
/// aren't known up-front).
async fn cleanup_events_for_users(db: &Db, user_ids: &[Uuid]) {
    let mut conn = match db.get().await {
        Ok(c) => c,
        Err(_) => return,
    };
    let _ = diesel::sql_query("DELETE FROM events WHERE user_id = ANY($1)")
        .bind::<diesel::sql_types::Array<diesel::sql_types::Uuid>, _>(user_ids.to_owned())
        .execute(&mut conn)
        .await;
}

// ---------------------------------------------------------------------------
// Skip-when-no-DB shim
// ---------------------------------------------------------------------------

macro_rules! skip_if_no_db {
    () => {{
        if std::env::var("DATABASE_URL").is_err() {
            eprintln!("DATABASE_URL not set; skipping integration test");
            return;
        }
    }};
}

const RPC_RECORD: &str = "/headlines.v1.EventService/RecordEvent";
const RPC_BATCH: &str = "/headlines.v1.EventService/RecordEventBatch";
const RPC_LIST: &str = "/headlines.v1.EventService/ListEvents";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn now_proto() -> Timestamp {
    let dt = Utc::now();
    Timestamp {
        seconds: dt.timestamp(),
        nanos: dt.timestamp_subsec_nanos() as i32,
    }
}

fn open_event(user_id: Uuid, article_id: Uuid) -> RecordEventRequest {
    RecordEventRequest {
        user_id: user_id.to_string(),
        article_id: article_id.to_string(),
        r#type: EventType::Open as i32,
        occurred_at: Some(now_proto()),
        surface: "web".into(),
        properties: Some(record_event_request::Properties::Open(OpenProperties {
            feed_kind: "recommendation".into(),
            position: 0,
        })),
    }
}

// ===========================================================================
// RecordEvent
// ===========================================================================

#[tokio::test]
async fn user_self_records_own_event() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let (user_id, user_key) = seed_user_with_key(&h.db, &user_sk).await;
    let article_id = Uuid::now_v7();
    let req = open_event(user_id, article_id);
    let ts = h.clock.now().await.unwrap();

    // Act
    let resp = h
        .client
        .record_event(signed(
            req,
            &user_sk,
            user_key,
            RPC_RECORD,
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();

    // Assert
    assert_eq!(resp.user_id, user_id.to_string());
    assert_eq!(resp.article_id, article_id.to_string());
    assert_eq!(resp.r#type, EventType::Open as i32);
    assert!(!resp.id.is_empty());
    assert!(resp.received_at.is_some());

    cleanup(&h.db, &[user_id], &[Uuid::parse_str(&resp.id).unwrap()]).await;
}

#[tokio::test]
async fn user_self_records_for_different_user_is_unauthorized() {
    skip_if_no_db!();

    // Arrange — Caller signs as user A but records an event with user B.
    let mut h = spawn_server().await;
    let caller_sk = make_signing_key();
    let (caller_id, caller_key) = seed_user_with_key(&h.db, &caller_sk).await;
    let other_user_id = Uuid::now_v7();
    let article_id = Uuid::now_v7();
    let req = open_event(other_user_id, article_id);
    let ts = h.clock.now().await.unwrap();

    // Act
    let err = h
        .client
        .record_event(signed(
            req,
            &caller_sk,
            caller_key,
            RPC_RECORD,
            ts,
            &unique_nonce(),
        ))
        .await
        .expect_err("user-self mismatch must reject");

    // Assert — UNAUTHORIZED_USER_ID → PERMISSION_DENIED.
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    cleanup(&h.db, &[caller_id], &[]).await;
}

#[tokio::test]
async fn system_with_events_write_can_record_for_any_user() {
    skip_if_no_db!();

    // Arrange — System with `events.write` records for a different user.
    let mut h = spawn_server().await;
    let sys_sk = make_signing_key();
    let (system_id, sys_key) = insert_system(&h.db, "events-w", &["events.write"], &sys_sk).await;
    let target_user = Uuid::now_v7();
    let article_id = Uuid::now_v7();
    let req = open_event(target_user, article_id);
    let ts = h.clock.now().await.unwrap();

    // Act
    let resp = h
        .client
        .record_event(signed(
            req,
            &sys_sk,
            sys_key,
            RPC_RECORD,
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();

    // Assert
    assert_eq!(resp.user_id, target_user.to_string());

    cleanup(&h.db, &[target_user], &[Uuid::parse_str(&resp.id).unwrap()]).await;
    cleanup_system(&h.db, system_id).await;
}

#[tokio::test]
async fn type_properties_mismatch_surfaces_event_type_mismatch() {
    skip_if_no_db!();

    // Arrange — type=OPEN but DwellProperties supplied.
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let (user_id, user_key) = seed_user_with_key(&h.db, &user_sk).await;
    let article_id = Uuid::now_v7();
    let req = RecordEventRequest {
        user_id: user_id.to_string(),
        article_id: article_id.to_string(),
        r#type: EventType::Open as i32,
        occurred_at: Some(now_proto()),
        surface: "web".into(),
        properties: Some(record_event_request::Properties::Dwell(DwellProperties {
            dwell_ms: 1000,
        })),
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let err = h
        .client
        .record_event(signed(
            req,
            &user_sk,
            user_key,
            RPC_RECORD,
            ts,
            &unique_nonce(),
        ))
        .await
        .expect_err("type/properties mismatch must reject");

    // Assert — EVENT_TYPE_MISMATCH → INVALID_ARGUMENT.
    assert_eq!(err.code(), tonic::Code::InvalidArgument);

    cleanup(&h.db, &[user_id], &[]).await;
}

#[tokio::test]
async fn occurred_at_too_far_past_rejected() {
    skip_if_no_db!();

    // Arrange — occurred_at 25h ago, outside [now − 24h, now + 60s].
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let (user_id, user_key) = seed_user_with_key(&h.db, &user_sk).await;
    let article_id = Uuid::now_v7();
    let stale = (Utc::now() - chrono::Duration::hours(25)).timestamp();
    let req = RecordEventRequest {
        user_id: user_id.to_string(),
        article_id: article_id.to_string(),
        r#type: EventType::Open as i32,
        occurred_at: Some(Timestamp {
            seconds: stale,
            nanos: 0,
        }),
        surface: "web".into(),
        properties: Some(record_event_request::Properties::Open(OpenProperties {
            feed_kind: "recommendation".into(),
            position: 0,
        })),
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let err = h
        .client
        .record_event(signed(
            req,
            &user_sk,
            user_key,
            RPC_RECORD,
            ts,
            &unique_nonce(),
        ))
        .await
        .expect_err("stale occurred_at must reject");

    // Assert — EVENT_TIMESTAMP_OUT_OF_RANGE → INVALID_ARGUMENT.
    assert_eq!(err.code(), tonic::Code::InvalidArgument);

    cleanup(&h.db, &[user_id], &[]).await;
}

#[tokio::test]
async fn occurred_at_too_far_future_rejected() {
    skip_if_no_db!();

    // Arrange — occurred_at 5 minutes ahead, outside the +60s slack.
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let (user_id, user_key) = seed_user_with_key(&h.db, &user_sk).await;
    let article_id = Uuid::now_v7();
    let future = (Utc::now() + chrono::Duration::minutes(5)).timestamp();
    let req = RecordEventRequest {
        user_id: user_id.to_string(),
        article_id: article_id.to_string(),
        r#type: EventType::Open as i32,
        occurred_at: Some(Timestamp {
            seconds: future,
            nanos: 0,
        }),
        surface: "web".into(),
        properties: Some(record_event_request::Properties::Open(OpenProperties {
            feed_kind: "recommendation".into(),
            position: 0,
        })),
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let err = h
        .client
        .record_event(signed(
            req,
            &user_sk,
            user_key,
            RPC_RECORD,
            ts,
            &unique_nonce(),
        ))
        .await
        .expect_err("future occurred_at must reject");

    // Assert
    assert_eq!(err.code(), tonic::Code::InvalidArgument);

    cleanup(&h.db, &[user_id], &[]).await;
}

#[tokio::test]
async fn bad_surface_rejected() {
    skip_if_no_db!();

    // Arrange — `surface` contains spaces.
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let (user_id, user_key) = seed_user_with_key(&h.db, &user_sk).await;
    let article_id = Uuid::now_v7();
    let req = RecordEventRequest {
        surface: "with space".into(),
        ..open_event(user_id, article_id)
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let err = h
        .client
        .record_event(signed(
            req,
            &user_sk,
            user_key,
            RPC_RECORD,
            ts,
            &unique_nonce(),
        ))
        .await
        .expect_err("bad surface must reject");

    // Assert
    assert_eq!(err.code(), tonic::Code::InvalidArgument);

    cleanup(&h.db, &[user_id], &[]).await;
}

#[tokio::test]
async fn negative_position_rejected() {
    skip_if_no_db!();

    // Arrange — IMPRESSION with position = -1.
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let (user_id, user_key) = seed_user_with_key(&h.db, &user_sk).await;
    let article_id = Uuid::now_v7();
    let req = RecordEventRequest {
        user_id: user_id.to_string(),
        article_id: article_id.to_string(),
        r#type: EventType::Impression as i32,
        occurred_at: Some(now_proto()),
        surface: "web".into(),
        properties: Some(record_event_request::Properties::Impression(
            ImpressionProperties {
                feed_kind: "recommendation".into(),
                position: -1,
            },
        )),
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let err = h
        .client
        .record_event(signed(
            req,
            &user_sk,
            user_key,
            RPC_RECORD,
            ts,
            &unique_nonce(),
        ))
        .await
        .expect_err("negative position must reject");

    // Assert
    assert_eq!(err.code(), tonic::Code::InvalidArgument);

    cleanup(&h.db, &[user_id], &[]).await;
}

#[tokio::test]
async fn dwell_over_24h_rejected() {
    skip_if_no_db!();

    // Arrange — DWELL with 25h.
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let (user_id, user_key) = seed_user_with_key(&h.db, &user_sk).await;
    let article_id = Uuid::now_v7();
    let req = RecordEventRequest {
        user_id: user_id.to_string(),
        article_id: article_id.to_string(),
        r#type: EventType::Dwell as i32,
        occurred_at: Some(now_proto()),
        surface: "web".into(),
        properties: Some(record_event_request::Properties::Dwell(DwellProperties {
            dwell_ms: 86_400_001,
        })),
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let err = h
        .client
        .record_event(signed(
            req,
            &user_sk,
            user_key,
            RPC_RECORD,
            ts,
            &unique_nonce(),
        ))
        .await
        .expect_err("dwell > 24h must reject");

    // Assert
    assert_eq!(err.code(), tonic::Code::InvalidArgument);

    cleanup(&h.db, &[user_id], &[]).await;
}

#[tokio::test]
async fn bad_feed_kind_rejected() {
    skip_if_no_db!();

    // Arrange — IMPRESSION with feed_kind=explore (not in vocabulary).
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let (user_id, user_key) = seed_user_with_key(&h.db, &user_sk).await;
    let article_id = Uuid::now_v7();
    let req = RecordEventRequest {
        user_id: user_id.to_string(),
        article_id: article_id.to_string(),
        r#type: EventType::Impression as i32,
        occurred_at: Some(now_proto()),
        surface: "web".into(),
        properties: Some(record_event_request::Properties::Impression(
            ImpressionProperties {
                feed_kind: "explore".into(),
                position: 0,
            },
        )),
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let err = h
        .client
        .record_event(signed(
            req,
            &user_sk,
            user_key,
            RPC_RECORD,
            ts,
            &unique_nonce(),
        ))
        .await
        .expect_err("bad feed_kind must reject");

    // Assert
    assert_eq!(err.code(), tonic::Code::InvalidArgument);

    cleanup(&h.db, &[user_id], &[]).await;
}

// ===========================================================================
// RecordEventBatch
// ===========================================================================

#[tokio::test]
async fn batch_of_three_succeeds() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let (user_id, user_key) = seed_user_with_key(&h.db, &user_sk).await;
    let article_id = Uuid::now_v7();
    let req = RecordEventBatchRequest {
        events: vec![
            open_event(user_id, article_id),
            RecordEventRequest {
                r#type: EventType::Like as i32,
                properties: Some(record_event_request::Properties::Like(LikeProperties {})),
                ..open_event(user_id, article_id)
            },
            RecordEventRequest {
                r#type: EventType::Share as i32,
                properties: Some(record_event_request::Properties::Share(ShareProperties {
                    target: "twitter".into(),
                })),
                ..open_event(user_id, article_id)
            },
        ],
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let resp = h
        .client
        .record_event_batch(signed(
            req,
            &user_sk,
            user_key,
            RPC_BATCH,
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();

    // Assert
    assert_eq!(resp.stored_count, 3);
    assert_eq!(resp.recorded.len(), 3);

    cleanup(&h.db, &[user_id], &[]).await;
}

#[tokio::test]
async fn batch_over_cap_rejected_with_batch_too_large() {
    skip_if_no_db!();

    // Arrange — TEST_BATCH_CAP=3; submit 4.
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let (user_id, user_key) = seed_user_with_key(&h.db, &user_sk).await;
    let article_id = Uuid::now_v7();
    let req = RecordEventBatchRequest {
        events: (0..4).map(|_| open_event(user_id, article_id)).collect(),
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let err = h
        .client
        .record_event_batch(signed(
            req,
            &user_sk,
            user_key,
            RPC_BATCH,
            ts,
            &unique_nonce(),
        ))
        .await
        .expect_err("over-cap batch must reject");

    // Assert — BATCH_TOO_LARGE → RESOURCE_EXHAUSTED.
    assert_eq!(err.code(), tonic::Code::ResourceExhausted);

    cleanup(&h.db, &[user_id], &[]).await;
}

#[tokio::test]
async fn batch_with_one_bad_event_rolls_back_entire_batch() {
    skip_if_no_db!();

    // Arrange — three events; the middle one has a bad surface, which must
    // reject the whole batch with no rows inserted.
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let (user_id, user_key) = seed_user_with_key(&h.db, &user_sk).await;
    let article_id = Uuid::now_v7();

    let req = RecordEventBatchRequest {
        events: vec![
            open_event(user_id, article_id),
            RecordEventRequest {
                surface: "Bad Surface!".into(),
                ..open_event(user_id, article_id)
            },
            open_event(user_id, article_id),
        ],
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let err = h
        .client
        .record_event_batch(signed(
            req,
            &user_sk,
            user_key,
            RPC_BATCH,
            ts,
            &unique_nonce(),
        ))
        .await
        .expect_err("bad event must reject whole batch");

    // Assert — error is INVALID_ARGUMENT and no rows landed.
    assert_eq!(err.code(), tonic::Code::InvalidArgument);

    // Verify via System ListEvents that no events for this user exist.
    let sys_sk = make_signing_key();
    let (system_id, sys_key) = insert_system(&h.db, "events-r", &["events.read"], &sys_sk).await;
    let list_req = ListEventsRequest {
        user_id: user_id.to_string(),
        page_size: 50,
        ..Default::default()
    };
    let ts2 = h.clock.now().await.unwrap();
    let resp = h
        .client
        .list_events(signed(
            list_req,
            &sys_sk,
            sys_key,
            RPC_LIST,
            ts2,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(resp.items.len(), 0, "no rows should have landed");

    cleanup(&h.db, &[user_id], &[]).await;
    cleanup_system(&h.db, system_id).await;
}

#[tokio::test]
async fn batch_user_self_with_mixed_user_ids_rejected() {
    skip_if_no_db!();

    // Arrange — caller signs as user A but the batch carries an event for B.
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let (user_id, user_key) = seed_user_with_key(&h.db, &user_sk).await;
    let other_user = Uuid::now_v7();
    let article_id = Uuid::now_v7();

    let req = RecordEventBatchRequest {
        events: vec![
            open_event(user_id, article_id),
            open_event(other_user, article_id),
        ],
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let err = h
        .client
        .record_event_batch(signed(
            req,
            &user_sk,
            user_key,
            RPC_BATCH,
            ts,
            &unique_nonce(),
        ))
        .await
        .expect_err("mixed user_ids on user-self path must reject");

    // Assert — UNAUTHORIZED_USER_ID → PERMISSION_DENIED.
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    cleanup(&h.db, &[user_id], &[]).await;
}

// ===========================================================================
// ListEvents
// ===========================================================================

#[tokio::test]
async fn system_with_events_read_lists_all() {
    skip_if_no_db!();

    // Arrange — record 2 events, then list them.
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let (user_id, user_key) = seed_user_with_key(&h.db, &user_sk).await;
    let article_id = Uuid::now_v7();
    let ts = h.clock.now().await.unwrap();
    let r1 = h
        .client
        .record_event(signed(
            open_event(user_id, article_id),
            &user_sk,
            user_key,
            RPC_RECORD,
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();
    let ts = h.clock.now().await.unwrap();
    let r2 = h
        .client
        .record_event(signed(
            RecordEventRequest {
                r#type: EventType::Like as i32,
                properties: Some(record_event_request::Properties::Like(LikeProperties {})),
                ..open_event(user_id, article_id)
            },
            &user_sk,
            user_key,
            RPC_RECORD,
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();

    let sys_sk = make_signing_key();
    let (system_id, sys_key) = insert_system(&h.db, "events-r", &["events.read"], &sys_sk).await;
    let list_req = ListEventsRequest {
        user_id: user_id.to_string(),
        page_size: 50,
        ..Default::default()
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let resp = h
        .client
        .list_events(signed(
            list_req,
            &sys_sk,
            sys_key,
            RPC_LIST,
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();

    // Assert
    assert_eq!(resp.items.len(), 2);
    let ids: Vec<String> = resp.items.iter().map(|e| e.id.clone()).collect();
    assert!(ids.contains(&r1.id));
    assert!(ids.contains(&r2.id));

    cleanup(&h.db, &[user_id], &[]).await;
    cleanup_system(&h.db, system_id).await;
}

#[tokio::test]
async fn user_self_list_is_permission_denied() {
    skip_if_no_db!();

    // Arrange — User signs the call; ListEvents is system-only.
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let (user_id, user_key) = seed_user_with_key(&h.db, &user_sk).await;
    let req = ListEventsRequest {
        user_id: user_id.to_string(),
        page_size: 50,
        ..Default::default()
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let err = h
        .client
        .list_events(signed(
            req,
            &user_sk,
            user_key,
            RPC_LIST,
            ts,
            &unique_nonce(),
        ))
        .await
        .expect_err("user-self list must reject");

    // Assert — proto AUTH_TABLE blocks non-system subjects → PERMISSION_DENIED.
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    cleanup(&h.db, &[user_id], &[]).await;
}

#[tokio::test]
async fn list_filters_by_user_id() {
    skip_if_no_db!();

    // Arrange — two users; record one event each; filter by one.
    let mut h = spawn_server().await;
    let sk_a = make_signing_key();
    let (user_a, key_a) = seed_user_with_key(&h.db, &sk_a).await;
    let sk_b = make_signing_key();
    let (user_b, key_b) = seed_user_with_key(&h.db, &sk_b).await;
    let article_id = Uuid::now_v7();
    let ts = h.clock.now().await.unwrap();
    let _ = h
        .client
        .record_event(signed(
            open_event(user_a, article_id),
            &sk_a,
            key_a,
            RPC_RECORD,
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap();
    let ts = h.clock.now().await.unwrap();
    let _ = h
        .client
        .record_event(signed(
            open_event(user_b, article_id),
            &sk_b,
            key_b,
            RPC_RECORD,
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap();

    let sys_sk = make_signing_key();
    let (system_id, sys_key) = insert_system(&h.db, "events-r", &["events.read"], &sys_sk).await;
    let list_req = ListEventsRequest {
        user_id: user_a.to_string(),
        page_size: 50,
        ..Default::default()
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let resp = h
        .client
        .list_events(signed(
            list_req,
            &sys_sk,
            sys_key,
            RPC_LIST,
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();

    // Assert — only user_a's event surfaces.
    assert_eq!(resp.items.len(), 1);
    assert_eq!(resp.items[0].user_id, user_a.to_string());

    cleanup(&h.db, &[user_a, user_b], &[]).await;
    cleanup_system(&h.db, system_id).await;
}

#[tokio::test]
async fn list_filters_by_article_id() {
    skip_if_no_db!();

    // Arrange — one user, two events on different articles.
    let mut h = spawn_server().await;
    let sk = make_signing_key();
    let (user_id, key) = seed_user_with_key(&h.db, &sk).await;
    let a1 = Uuid::now_v7();
    let a2 = Uuid::now_v7();
    let ts = h.clock.now().await.unwrap();
    let _ = h
        .client
        .record_event(signed(
            open_event(user_id, a1),
            &sk,
            key,
            RPC_RECORD,
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap();
    let ts = h.clock.now().await.unwrap();
    let _ = h
        .client
        .record_event(signed(
            open_event(user_id, a2),
            &sk,
            key,
            RPC_RECORD,
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap();

    let sys_sk = make_signing_key();
    let (system_id, sys_key) = insert_system(&h.db, "events-r", &["events.read"], &sys_sk).await;
    let list_req = ListEventsRequest {
        article_id: a1.to_string(),
        page_size: 50,
        ..Default::default()
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let resp = h
        .client
        .list_events(signed(
            list_req,
            &sys_sk,
            sys_key,
            RPC_LIST,
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();

    // Assert
    assert_eq!(resp.items.len(), 1);
    assert_eq!(resp.items[0].article_id, a1.to_string());

    cleanup(&h.db, &[user_id], &[]).await;
    cleanup_system(&h.db, system_id).await;
}

#[tokio::test]
async fn list_filters_by_types_union() {
    skip_if_no_db!();

    // Arrange — record OPEN, LIKE, SHARE; filter by [OPEN, SHARE].
    let mut h = spawn_server().await;
    let sk = make_signing_key();
    let (user_id, key) = seed_user_with_key(&h.db, &sk).await;
    let article_id = Uuid::now_v7();
    let ts = h.clock.now().await.unwrap();
    let _ = h
        .client
        .record_event(signed(
            open_event(user_id, article_id),
            &sk,
            key,
            RPC_RECORD,
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap();
    let ts = h.clock.now().await.unwrap();
    let _ = h
        .client
        .record_event(signed(
            RecordEventRequest {
                r#type: EventType::Like as i32,
                properties: Some(record_event_request::Properties::Like(LikeProperties {})),
                ..open_event(user_id, article_id)
            },
            &sk,
            key,
            RPC_RECORD,
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap();
    let ts = h.clock.now().await.unwrap();
    let _ = h
        .client
        .record_event(signed(
            RecordEventRequest {
                r#type: EventType::Share as i32,
                properties: Some(record_event_request::Properties::Share(ShareProperties {
                    target: "twitter".into(),
                })),
                ..open_event(user_id, article_id)
            },
            &sk,
            key,
            RPC_RECORD,
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap();

    let sys_sk = make_signing_key();
    let (system_id, sys_key) = insert_system(&h.db, "events-r", &["events.read"], &sys_sk).await;
    let list_req = ListEventsRequest {
        user_id: user_id.to_string(),
        types: vec![EventType::Open as i32, EventType::Share as i32],
        page_size: 50,
        ..Default::default()
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let resp = h
        .client
        .list_events(signed(
            list_req,
            &sys_sk,
            sys_key,
            RPC_LIST,
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();

    // Assert — only OPEN and SHARE returned (LIKE excluded).
    assert_eq!(resp.items.len(), 2);
    let kinds: Vec<i32> = resp.items.iter().map(|e| e.r#type).collect();
    assert!(kinds.contains(&(EventType::Open as i32)));
    assert!(kinds.contains(&(EventType::Share as i32)));
    assert!(!kinds.contains(&(EventType::Like as i32)));

    cleanup(&h.db, &[user_id], &[]).await;
    cleanup_system(&h.db, system_id).await;
}

#[tokio::test]
async fn list_filters_by_received_after_and_before() {
    skip_if_no_db!();

    // Arrange — record one event. Use received_after = far past + before = now+1h
    // to bound a window that includes it; then narrow to exclude it.
    let mut h = spawn_server().await;
    let sk = make_signing_key();
    let (user_id, key) = seed_user_with_key(&h.db, &sk).await;
    let article_id = Uuid::now_v7();
    let ts = h.clock.now().await.unwrap();
    let recorded = h
        .client
        .record_event(signed(
            open_event(user_id, article_id),
            &sk,
            key,
            RPC_RECORD,
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();

    let sys_sk = make_signing_key();
    let (system_id, sys_key) = insert_system(&h.db, "events-r", &["events.read"], &sys_sk).await;

    // Inclusive window — should include the event.
    let after = (Utc::now() - chrono::Duration::hours(1)).timestamp();
    let before = (Utc::now() + chrono::Duration::hours(1)).timestamp();
    let list_req = ListEventsRequest {
        user_id: user_id.to_string(),
        received_after: Some(Timestamp {
            seconds: after,
            nanos: 0,
        }),
        received_before: Some(Timestamp {
            seconds: before,
            nanos: 0,
        }),
        page_size: 50,
        ..Default::default()
    };
    let ts = h.clock.now().await.unwrap();
    let resp_inclusive = h
        .client
        .list_events(signed(
            list_req,
            &sys_sk,
            sys_key,
            RPC_LIST,
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(resp_inclusive.items.len(), 1);
    assert_eq!(resp_inclusive.items[0].id, recorded.id);

    // Exclusive window — `received_before` ahead of `received_after` but in
    // the past, so the event shouldn't surface.
    let bad_before = (Utc::now() - chrono::Duration::hours(2)).timestamp();
    let exclusive_req = ListEventsRequest {
        user_id: user_id.to_string(),
        received_before: Some(Timestamp {
            seconds: bad_before,
            nanos: 0,
        }),
        page_size: 50,
        ..Default::default()
    };
    let ts = h.clock.now().await.unwrap();
    let resp_exclusive = h
        .client
        .list_events(signed(
            exclusive_req,
            &sys_sk,
            sys_key,
            RPC_LIST,
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(resp_exclusive.items.len(), 0);

    cleanup(&h.db, &[user_id], &[]).await;
    cleanup_system(&h.db, system_id).await;
}

#[tokio::test]
async fn list_paginates_across_multiple_pages() {
    skip_if_no_db!();

    // Arrange — 5 events; page_size=2 should yield 2 + 2 + 1.
    let mut h = spawn_server().await;
    let sk = make_signing_key();
    let (user_id, key) = seed_user_with_key(&h.db, &sk).await;
    let article_id = Uuid::now_v7();
    let mut recorded_ids = Vec::new();
    for _ in 0..5 {
        let ts = h.clock.now().await.unwrap();
        let r = h
            .client
            .record_event(signed(
                open_event(user_id, article_id),
                &sk,
                key,
                RPC_RECORD,
                ts,
                &unique_nonce(),
            ))
            .await
            .unwrap()
            .into_inner();
        recorded_ids.push(r.id);
    }

    let sys_sk = make_signing_key();
    let (system_id, sys_key) = insert_system(&h.db, "events-r", &["events.read"], &sys_sk).await;

    // Page 1.
    let req = ListEventsRequest {
        user_id: user_id.to_string(),
        page_size: 2,
        ..Default::default()
    };
    let ts = h.clock.now().await.unwrap();
    let p1 = h
        .client
        .list_events(signed(req, &sys_sk, sys_key, RPC_LIST, ts, &unique_nonce()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(p1.items.len(), 2);
    assert!(!p1.next_page_token.is_empty());

    // Page 2.
    let req = ListEventsRequest {
        user_id: user_id.to_string(),
        page_size: 2,
        page_token: p1.next_page_token.clone(),
        ..Default::default()
    };
    let ts = h.clock.now().await.unwrap();
    let p2 = h
        .client
        .list_events(signed(req, &sys_sk, sys_key, RPC_LIST, ts, &unique_nonce()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(p2.items.len(), 2);
    assert!(!p2.next_page_token.is_empty());

    // Page 3.
    let req = ListEventsRequest {
        user_id: user_id.to_string(),
        page_size: 2,
        page_token: p2.next_page_token.clone(),
        ..Default::default()
    };
    let ts = h.clock.now().await.unwrap();
    let p3 = h
        .client
        .list_events(signed(req, &sys_sk, sys_key, RPC_LIST, ts, &unique_nonce()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(p3.items.len(), 1);
    assert!(p3.next_page_token.is_empty());

    cleanup_events_for_users(&h.db, &[user_id]).await;
    cleanup(&h.db, &[user_id], &[]).await;
    cleanup_system(&h.db, system_id).await;
}

#[tokio::test]
async fn soft_refs_record_events_for_unknown_user_or_article() {
    skip_if_no_db!();

    // Arrange — System records events with a phantom user_id and article_id.
    // No FK enforcement; the row should land and surface on ListEvents.
    let mut h = spawn_server().await;
    let phantom_user = Uuid::now_v7();
    let phantom_article = Uuid::now_v7();

    let sys_sk = make_signing_key();
    let (system_id, sys_key) = insert_system(
        &h.db,
        "events-rw",
        &["events.write", "events.read"],
        &sys_sk,
    )
    .await;
    let ts = h.clock.now().await.unwrap();
    let recorded = h
        .client
        .record_event(signed(
            open_event(phantom_user, phantom_article),
            &sys_sk,
            sys_key,
            RPC_RECORD,
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();

    let list_req = ListEventsRequest {
        user_id: phantom_user.to_string(),
        page_size: 50,
        ..Default::default()
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let resp = h
        .client
        .list_events(signed(
            list_req,
            &sys_sk,
            sys_key,
            RPC_LIST,
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();

    // Assert
    assert_eq!(resp.items.len(), 1);
    assert_eq!(resp.items[0].id, recorded.id);

    cleanup(
        &h.db,
        &[phantom_user],
        &[Uuid::parse_str(&recorded.id).unwrap()],
    )
    .await;
    cleanup_system(&h.db, system_id).await;
}
