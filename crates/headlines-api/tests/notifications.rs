//! End-to-end integration tests for `NotificationService`, exercised through
//! a real tonic in-process server (random TCP port) backed by Postgres on
//! `docker.yuacx.com`. Mirrors `tests/events.rs` and
//! `tests/account_stream.rs`.
//!
//! Phase 7.9 ships the surface as **reserved**: every RPC returns
//! `UNIMPLEMENTED` with `ErrorInfo.reason = "NOT_IMPLEMENTED_IN_V1"`. These
//! tests exercise three things, per `notifications.md` § "v1 behavior":
//!   1. The proto `auth_requirement` MethodOption is correctly projected
//!      into the `AUTH_TABLE` (a misconfigured caller is rejected with
//!      `PERMISSION_DENIED` *before* reaching the handler).
//!   2. The handler chain reaches the impl when authorization passes.
//!   3. The 501 envelope carries the documented stable reason.
//!
//! Each RPC has two test cases:
//!   - **happy path** (correct subject + scope) → `UNIMPLEMENTED` with
//!     `reason = "NOT_IMPLEMENTED_IN_V1"`.
//!   - **denied path** (wrong subject class) → `PERMISSION_DENIED` from the
//!     `AuthorizationLayer`.
//!
//! No notification semantics are validated (there are none yet). When the
//! delivery phase begins, this file gains real behavioral tests alongside
//! these gate tests.
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
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use ed25519_dalek::{Signer, SigningKey};
use prost::Message;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use tonic::transport::{Channel, Endpoint, Server};
use tonic_types::pb::{ErrorInfo, Status as RpcStatus};
use uuid::Uuid;

use headlines_api::NotificationServiceImpl;
use headlines_auth::{
    AlgorithmRegistry, AuthInterceptor, AuthorizationLayer, Ed25519, InMemoryNonceStore,
    LocalClock, PostgresKeyResolver, ProtoBodyHasher, SignedRequestStrategy,
};
use headlines_core::{TimeSource as _, Tso};
use headlines_proto::v1::{
    GetUserNotificationPreferencesRequest, ListUserNotificationsRequest,
    MarkAllUserNotificationsReadRequest, MarkNotificationReadRequest, NotificationPreferences,
    SendNotificationBatchRequest, SendNotificationRequest,
    UpdateUserNotificationPreferencesRequest,
    notification_service_client::NotificationServiceClient,
    notification_service_server::NotificationServiceServer,
};
use headlines_store::Db;

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

struct Harness {
    db: Db,
    client: NotificationServiceClient<Channel>,
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

    let svc = NotificationServiceImpl::new();

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
        .add_service(NotificationServiceServer::new(svc));

    tokio::spawn(async move {
        let _ = server.serve_with_incoming(stream).await;
    });

    let endpoint = Endpoint::from_shared(format!("http://{addr}"))
        .expect("endpoint")
        .connect_timeout(Duration::from_secs(5));
    let channel = endpoint.connect().await.expect("client connect");
    let client = NotificationServiceClient::new(channel);

    Harness {
        db,
        client,
        clock,
        _addr: addr,
    }
}

// ---------------------------------------------------------------------------
// Signing helpers (mirrors tests/events.rs)
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

async fn cleanup_users(db: &Db, user_ids: &[Uuid]) {
    let url = db.database_url().to_owned();
    let users = user_ids.to_owned();
    let _ = tokio::spawn(async move {
        let mut conn = match AsyncPgConnection::establish(&url).await {
            Ok(c) => c,
            Err(_) => return,
        };
        if !users.is_empty() {
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

const RPC_SEND: &str = "/headlines.v1.NotificationService/SendNotification";
const RPC_SEND_BATCH: &str = "/headlines.v1.NotificationService/SendNotificationBatch";
const RPC_LIST: &str = "/headlines.v1.NotificationService/ListUserNotifications";
const RPC_MARK_READ: &str = "/headlines.v1.NotificationService/MarkNotificationRead";
const RPC_MARK_ALL: &str = "/headlines.v1.NotificationService/MarkAllUserNotificationsRead";
const RPC_GET_PREFS: &str = "/headlines.v1.NotificationService/GetUserNotificationPreferences";
const RPC_UPDATE_PREFS: &str =
    "/headlines.v1.NotificationService/UpdateUserNotificationPreferences";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Pull `ErrorInfo.reason` out of a tonic `Status`. Empty string if no
/// `google.rpc.Status` details were attached or the detail isn't an
/// `ErrorInfo`. The handler always attaches one via `HeadlinesError`'s
/// `Into<Status>` impl.
fn error_reason(status: &tonic::Status) -> String {
    let bytes = status.details();
    if bytes.is_empty() {
        return String::new();
    }
    let rpc = match RpcStatus::decode(bytes) {
        Ok(s) => s,
        Err(_) => return String::new(),
    };
    for any in &rpc.details {
        if any.type_url == "type.googleapis.com/google.rpc.ErrorInfo"
            && let Ok(info) = ErrorInfo::decode(any.value.as_ref())
        {
            return info.reason;
        }
    }
    String::new()
}

// ===========================================================================
// SendNotification
// ===========================================================================

#[tokio::test]
async fn send_notification_system_correct_scope_returns_unimplemented() {
    skip_if_no_db!();

    // Arrange — System with `notifications.send` is the allowed subject.
    let mut h = spawn_server().await;
    let sys_sk = make_signing_key();
    let (system_id, sys_key) =
        insert_system(&h.db, "notif-send", &["notifications.send"], &sys_sk).await;
    let target_user = Uuid::now_v7();
    let req = SendNotificationRequest {
        user_id: target_user.to_string(),
        ..Default::default()
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let err = h
        .client
        .send_notification(signed(req, &sys_sk, sys_key, RPC_SEND, ts, &unique_nonce()))
        .await
        .expect_err("must surface UNIMPLEMENTED");

    // Assert
    assert_eq!(err.code(), tonic::Code::Unimplemented);
    assert_eq!(error_reason(&err), "NOT_IMPLEMENTED_IN_V1");

    cleanup_system(&h.db, system_id).await;
}

#[tokio::test]
async fn send_notification_user_self_is_permission_denied() {
    skip_if_no_db!();

    // Arrange — User caller is not in the allowed-subjects list for
    // SendNotification (System-only). The AUTH_TABLE rejects before the
    // handler runs.
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let (user_id, user_key) = seed_user_with_key(&h.db, &user_sk).await;
    let req = SendNotificationRequest {
        user_id: user_id.to_string(),
        ..Default::default()
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let err = h
        .client
        .send_notification(signed(
            req,
            &user_sk,
            user_key,
            RPC_SEND,
            ts,
            &unique_nonce(),
        ))
        .await
        .expect_err("user-self must be denied on system-only RPC");

    // Assert
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    cleanup_users(&h.db, &[user_id]).await;
}

// ===========================================================================
// SendNotificationBatch
// ===========================================================================

#[tokio::test]
async fn send_notification_batch_system_correct_scope_returns_unimplemented() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server().await;
    let sys_sk = make_signing_key();
    let (system_id, sys_key) =
        insert_system(&h.db, "notif-send-batch", &["notifications.send"], &sys_sk).await;
    let req = SendNotificationBatchRequest {
        notifications: vec![SendNotificationRequest {
            user_id: Uuid::now_v7().to_string(),
            ..Default::default()
        }],
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let err = h
        .client
        .send_notification_batch(signed(
            req,
            &sys_sk,
            sys_key,
            RPC_SEND_BATCH,
            ts,
            &unique_nonce(),
        ))
        .await
        .expect_err("must surface UNIMPLEMENTED");

    // Assert
    assert_eq!(err.code(), tonic::Code::Unimplemented);
    assert_eq!(error_reason(&err), "NOT_IMPLEMENTED_IN_V1");

    cleanup_system(&h.db, system_id).await;
}

#[tokio::test]
async fn send_notification_batch_user_self_is_permission_denied() {
    skip_if_no_db!();

    // Arrange — User caller hits a System-only RPC.
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let (user_id, user_key) = seed_user_with_key(&h.db, &user_sk).await;
    let req = SendNotificationBatchRequest::default();
    let ts = h.clock.now().await.unwrap();

    // Act
    let err = h
        .client
        .send_notification_batch(signed(
            req,
            &user_sk,
            user_key,
            RPC_SEND_BATCH,
            ts,
            &unique_nonce(),
        ))
        .await
        .expect_err("user-self must be denied on system-only RPC");

    // Assert
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    cleanup_users(&h.db, &[user_id]).await;
}

// ===========================================================================
// ListUserNotifications
// ===========================================================================

#[tokio::test]
async fn list_user_notifications_user_self_returns_unimplemented() {
    skip_if_no_db!();

    // Arrange — User is allowed (User self path).
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let (user_id, user_key) = seed_user_with_key(&h.db, &user_sk).await;
    let req = ListUserNotificationsRequest {
        user_id: user_id.to_string(),
        page_size: 50,
        ..Default::default()
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let err = h
        .client
        .list_user_notifications(signed(
            req,
            &user_sk,
            user_key,
            RPC_LIST,
            ts,
            &unique_nonce(),
        ))
        .await
        .expect_err("must surface UNIMPLEMENTED");

    // Assert
    assert_eq!(err.code(), tonic::Code::Unimplemented);
    assert_eq!(error_reason(&err), "NOT_IMPLEMENTED_IN_V1");

    cleanup_users(&h.db, &[user_id]).await;
}

#[tokio::test]
async fn list_user_notifications_system_without_scope_is_permission_denied() {
    skip_if_no_db!();

    // Arrange — System missing the `notifications.read` scope. The
    // AUTH_TABLE gate rejects before the handler runs.
    let mut h = spawn_server().await;
    let sys_sk = make_signing_key();
    let (system_id, sys_key) = insert_system(&h.db, "notif-no-scope", &[], &sys_sk).await;
    let req = ListUserNotificationsRequest {
        user_id: Uuid::now_v7().to_string(),
        page_size: 50,
        ..Default::default()
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let err = h
        .client
        .list_user_notifications(signed(req, &sys_sk, sys_key, RPC_LIST, ts, &unique_nonce()))
        .await
        .expect_err("system without scope must be denied");

    // Assert
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    cleanup_system(&h.db, system_id).await;
}

// ===========================================================================
// MarkNotificationRead
// ===========================================================================

#[tokio::test]
async fn mark_notification_read_user_self_returns_unimplemented() {
    skip_if_no_db!();

    // Arrange — User self is the only allowed subject.
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let (user_id, user_key) = seed_user_with_key(&h.db, &user_sk).await;
    let req = MarkNotificationReadRequest {
        id: Uuid::now_v7().to_string(),
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let err = h
        .client
        .mark_notification_read(signed(
            req,
            &user_sk,
            user_key,
            RPC_MARK_READ,
            ts,
            &unique_nonce(),
        ))
        .await
        .expect_err("must surface UNIMPLEMENTED");

    // Assert
    assert_eq!(err.code(), tonic::Code::Unimplemented);
    assert_eq!(error_reason(&err), "NOT_IMPLEMENTED_IN_V1");

    cleanup_users(&h.db, &[user_id]).await;
}

#[tokio::test]
async fn mark_notification_read_system_is_permission_denied() {
    skip_if_no_db!();

    // Arrange — System (even with broad scopes) is not allowed; only User
    // self can mark their own notification read.
    let mut h = spawn_server().await;
    let sys_sk = make_signing_key();
    let (system_id, sys_key) = insert_system(
        &h.db,
        "notif-sys-mark",
        &[
            "notifications.send",
            "notifications.admin",
            "notifications.read",
        ],
        &sys_sk,
    )
    .await;
    let req = MarkNotificationReadRequest {
        id: Uuid::now_v7().to_string(),
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let err = h
        .client
        .mark_notification_read(signed(
            req,
            &sys_sk,
            sys_key,
            RPC_MARK_READ,
            ts,
            &unique_nonce(),
        ))
        .await
        .expect_err("system must be denied on user-self-only RPC");

    // Assert
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    cleanup_system(&h.db, system_id).await;
}

// ===========================================================================
// MarkAllUserNotificationsRead
// ===========================================================================

#[tokio::test]
async fn mark_all_user_notifications_read_user_self_returns_unimplemented() {
    skip_if_no_db!();

    // Arrange — User self is allowed.
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let (user_id, user_key) = seed_user_with_key(&h.db, &user_sk).await;
    let req = MarkAllUserNotificationsReadRequest {
        user_id: user_id.to_string(),
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let err = h
        .client
        .mark_all_user_notifications_read(signed(
            req,
            &user_sk,
            user_key,
            RPC_MARK_ALL,
            ts,
            &unique_nonce(),
        ))
        .await
        .expect_err("must surface UNIMPLEMENTED");

    // Assert
    assert_eq!(err.code(), tonic::Code::Unimplemented);
    assert_eq!(error_reason(&err), "NOT_IMPLEMENTED_IN_V1");

    cleanup_users(&h.db, &[user_id]).await;
}

#[tokio::test]
async fn mark_all_user_notifications_read_system_without_scope_is_permission_denied() {
    skip_if_no_db!();

    // Arrange — System missing the required `notifications.admin` scope.
    let mut h = spawn_server().await;
    let sys_sk = make_signing_key();
    let (system_id, sys_key) = insert_system(
        &h.db,
        "notif-sys-mark-all",
        &["notifications.read"],
        &sys_sk,
    )
    .await;
    let req = MarkAllUserNotificationsReadRequest {
        user_id: Uuid::now_v7().to_string(),
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let err = h
        .client
        .mark_all_user_notifications_read(signed(
            req,
            &sys_sk,
            sys_key,
            RPC_MARK_ALL,
            ts,
            &unique_nonce(),
        ))
        .await
        .expect_err("system without scope must be denied");

    // Assert
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    cleanup_system(&h.db, system_id).await;
}

// ===========================================================================
// GetUserNotificationPreferences
// ===========================================================================

#[tokio::test]
async fn get_user_notification_preferences_user_self_returns_unimplemented() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let (user_id, user_key) = seed_user_with_key(&h.db, &user_sk).await;
    let req = GetUserNotificationPreferencesRequest {
        user_id: user_id.to_string(),
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let err = h
        .client
        .get_user_notification_preferences(signed(
            req,
            &user_sk,
            user_key,
            RPC_GET_PREFS,
            ts,
            &unique_nonce(),
        ))
        .await
        .expect_err("must surface UNIMPLEMENTED");

    // Assert
    assert_eq!(err.code(), tonic::Code::Unimplemented);
    assert_eq!(error_reason(&err), "NOT_IMPLEMENTED_IN_V1");

    cleanup_users(&h.db, &[user_id]).await;
}

#[tokio::test]
async fn get_user_notification_preferences_system_without_scope_is_permission_denied() {
    skip_if_no_db!();

    // Arrange — System without `notifications.read`.
    let mut h = spawn_server().await;
    let sys_sk = make_signing_key();
    let (system_id, sys_key) = insert_system(
        &h.db,
        "notif-sys-getprefs",
        &["notifications.send"],
        &sys_sk,
    )
    .await;
    let req = GetUserNotificationPreferencesRequest {
        user_id: Uuid::now_v7().to_string(),
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let err = h
        .client
        .get_user_notification_preferences(signed(
            req,
            &sys_sk,
            sys_key,
            RPC_GET_PREFS,
            ts,
            &unique_nonce(),
        ))
        .await
        .expect_err("system without scope must be denied");

    // Assert
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    cleanup_system(&h.db, system_id).await;
}

// ===========================================================================
// UpdateUserNotificationPreferences
// ===========================================================================

#[tokio::test]
async fn update_user_notification_preferences_user_self_returns_unimplemented() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let (user_id, user_key) = seed_user_with_key(&h.db, &user_sk).await;
    let req = UpdateUserNotificationPreferencesRequest {
        preferences: Some(NotificationPreferences {
            user_id: user_id.to_string(),
            ..Default::default()
        }),
        update_mask: None,
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let err = h
        .client
        .update_user_notification_preferences(signed(
            req,
            &user_sk,
            user_key,
            RPC_UPDATE_PREFS,
            ts,
            &unique_nonce(),
        ))
        .await
        .expect_err("must surface UNIMPLEMENTED");

    // Assert
    assert_eq!(err.code(), tonic::Code::Unimplemented);
    assert_eq!(error_reason(&err), "NOT_IMPLEMENTED_IN_V1");

    cleanup_users(&h.db, &[user_id]).await;
}

#[tokio::test]
async fn update_user_notification_preferences_system_without_scope_is_permission_denied() {
    skip_if_no_db!();

    // Arrange — System without `notifications.admin`.
    let mut h = spawn_server().await;
    let sys_sk = make_signing_key();
    let (system_id, sys_key) = insert_system(
        &h.db,
        "notif-sys-updateprefs",
        &["notifications.read"],
        &sys_sk,
    )
    .await;
    let req = UpdateUserNotificationPreferencesRequest {
        preferences: Some(NotificationPreferences {
            user_id: Uuid::now_v7().to_string(),
            ..Default::default()
        }),
        update_mask: None,
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let err = h
        .client
        .update_user_notification_preferences(signed(
            req,
            &sys_sk,
            sys_key,
            RPC_UPDATE_PREFS,
            ts,
            &unique_nonce(),
        ))
        .await
        .expect_err("system without scope must be denied");

    // Assert
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    cleanup_system(&h.db, system_id).await;
}
