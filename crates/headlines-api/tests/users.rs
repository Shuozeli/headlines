//! End-to-end integration tests for `UserService`, exercised through a real
//! tonic in-process server (random TCP port) backed by Postgres on
//! `docker.yuacx.com`. Mirror of `tests/accounts.rs`.
//!
//! Each test mints fresh UUIDv7s so it doesn't collide with sibling tests;
//! cleanup is best-effort via `DELETE` filters at the end so data doesn't
//! pile up over a long workday. We never `TRUNCATE`.
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
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use tonic::transport::{Channel, Endpoint, Server};
use uuid::Uuid;

use headlines_api::{BootstrapMode, UserServiceImpl};
use headlines_auth::{
    AlgorithmRegistry, AuthInterceptor, AuthorizationLayer, Ed25519, InMemoryNonceStore,
    LocalClock, PostgresKeyResolver, ProtoBodyHasher, SignedRequestStrategy,
};
use headlines_core::{TimeSource as _, Tso};
use headlines_proto::v1::{
    AddUserKeyRequest, CreateUserRequest, DeleteUserRequest, GetUserRequest, PublicKey,
    RevokeUserKeyRequest, UpdateUserRequest, user_service_client::UserServiceClient,
    user_service_server::UserServiceServer,
};
use headlines_store::{Db, PgKeyRepo, PgUserRepo};

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

struct Harness {
    db: Db,
    client: UserServiceClient<Channel>,
    clock: Arc<LocalClock>,
    _addr: SocketAddr,
}

async fn maybe_connect_db() -> Option<Db> {
    let url = std::env::var("DATABASE_URL").ok()?;
    Db::connect(&url, 4).await.ok()
}

async fn spawn_server(bootstrap: BootstrapMode) -> Harness {
    let db = maybe_connect_db()
        .await
        .expect("DATABASE_URL must be set for integration tests");

    let users = Arc::new(PgUserRepo::new(db.clone()));
    let keys = Arc::new(PgKeyRepo::new(db.clone()));
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

    let svc = UserServiceImpl::new(users, keys, algos, bootstrap);

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
        .add_service(UserServiceServer::new(svc));

    tokio::spawn(async move {
        let _ = server.serve_with_incoming(stream).await;
    });

    let endpoint = Endpoint::from_shared(format!("http://{addr}"))
        .expect("endpoint")
        .connect_timeout(Duration::from_secs(5));
    let channel = endpoint.connect().await.expect("client connect");
    let client = UserServiceClient::new(channel);

    Harness {
        db,
        client,
        clock,
        _addr: addr,
    }
}

// ---------------------------------------------------------------------------
// Signing helpers (mirror what a real client would do)
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

fn user_msg(id: &str, display_name: &str) -> headlines_proto::v1::User {
    headlines_proto::v1::User {
        id: id.to_owned(),
        display_name: display_name.to_owned(),
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// DB cleanup helpers — best-effort, never panics on failure.
// ---------------------------------------------------------------------------

async fn cleanup(db: &Db, user_ids: &[Uuid]) {
    if user_ids.is_empty() {
        return;
    }
    let url = db.database_url().to_owned();
    let owned_ids: Vec<Uuid> = user_ids.to_owned();
    let _ = tokio::spawn(async move {
        let mut conn = match AsyncPgConnection::establish(&url).await {
            Ok(c) => c,
            Err(_) => return,
        };
        let _ = diesel::sql_query("DELETE FROM user_keys WHERE user_id = ANY($1)")
            .bind::<diesel::sql_types::Array<diesel::sql_types::Uuid>, _>(owned_ids.clone())
            .execute(&mut conn)
            .await;
        let _ = diesel::sql_query("DELETE FROM users WHERE id = ANY($1)")
            .bind::<diesel::sql_types::Array<diesel::sql_types::Uuid>, _>(owned_ids)
            .execute(&mut conn)
            .await;
    })
    .await;
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

fn ed25519_pk_b64(sk: &SigningKey) -> String {
    B64.encode(sk.verifying_key().as_bytes())
}

fn make_signing_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
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

async fn create_self_user(h: &mut Harness, sk: &SigningKey, display_name: &str) -> (Uuid, Uuid) {
    let create_resp = h
        .client
        .create_user(tonic::Request::new(CreateUserRequest {
            display_name: display_name.to_owned(),
            initial_key: Some(PublicKey {
                algo: "ed25519".into(),
                public_key: ed25519_pk_b64(sk),
            }),
        }))
        .await
        .unwrap()
        .into_inner();
    let user = create_resp.user.unwrap();
    (
        Uuid::parse_str(&user.id).unwrap(),
        Uuid::parse_str(&create_resp.key_id).unwrap(),
    )
}

// ===========================================================================
// CreateUser
// ===========================================================================

#[tokio::test]
async fn create_user_anonymous_open_mode_succeeds() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server(BootstrapMode::Open).await;
    let sk = make_signing_key();
    let req = CreateUserRequest {
        display_name: "anon-user".into(),
        initial_key: Some(PublicKey {
            algo: "ed25519".into(),
            public_key: ed25519_pk_b64(&sk),
        }),
    };

    // Act
    let resp = h
        .client
        .create_user(tonic::Request::new(req))
        .await
        .expect("CreateUser should succeed for anonymous in Open mode");

    // Assert
    let body = resp.into_inner();
    let u = body.user.expect("user in response");
    assert_eq!(u.display_name, "anon-user");
    assert!(!body.key_id.is_empty());
    let user_id = Uuid::parse_str(&u.id).unwrap();

    cleanup(&h.db, &[user_id]).await;
}

#[tokio::test]
async fn create_user_anonymous_in_system_only_mode_is_registration_disabled() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server(BootstrapMode::SystemOnly).await;
    let sk = make_signing_key();
    let req = CreateUserRequest {
        display_name: "reject-anon".into(),
        initial_key: Some(PublicKey {
            algo: "ed25519".into(),
            public_key: ed25519_pk_b64(&sk),
        }),
    };

    // Act
    let err = h
        .client
        .create_user(tonic::Request::new(req))
        .await
        .expect_err("system_only mode must reject anonymous");

    // Assert
    assert_eq!(err.code(), tonic::Code::PermissionDenied, "{err}");
}

#[tokio::test]
async fn create_user_system_with_users_write_in_system_only_mode_succeeds() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server(BootstrapMode::SystemOnly).await;
    let system_sk = make_signing_key();
    let (system_id, system_key_id) =
        insert_system(&h.db, "creator", &["users.write"], &system_sk).await;
    let user_sk = make_signing_key();
    let req = CreateUserRequest {
        display_name: "by-system".into(),
        initial_key: Some(PublicKey {
            algo: "ed25519".into(),
            public_key: ed25519_pk_b64(&user_sk),
        }),
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let request = signed(
        req,
        &system_sk,
        system_key_id,
        "/headlines.v1.UserService/CreateUser",
        ts,
        &unique_nonce(),
    );
    let resp = h
        .client
        .create_user(request)
        .await
        .expect("system creation should succeed");

    // Assert
    let u = resp.into_inner().user.unwrap();
    let user_id = Uuid::parse_str(&u.id).unwrap();

    cleanup(&h.db, &[user_id]).await;
    cleanup_system(&h.db, system_id).await;
}

#[tokio::test]
async fn create_user_validation_rejects_overlength_display_name() {
    skip_if_no_db!();

    // Arrange — 65 ASCII chars
    let mut h = spawn_server(BootstrapMode::Open).await;
    let sk = make_signing_key();
    let req = CreateUserRequest {
        display_name: "x".repeat(65),
        initial_key: Some(PublicKey {
            algo: "ed25519".into(),
            public_key: ed25519_pk_b64(&sk),
        }),
    };

    // Act
    let err = h
        .client
        .create_user(tonic::Request::new(req))
        .await
        .expect_err("overlength display_name");

    // Assert
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn create_user_validation_rejects_unsupported_algo() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server(BootstrapMode::Open).await;
    let req = CreateUserRequest {
        display_name: "alg".into(),
        initial_key: Some(PublicKey {
            algo: "rsa".into(),
            public_key: B64.encode([0u8; 32]),
        }),
    };

    // Act
    let err = h
        .client
        .create_user(tonic::Request::new(req))
        .await
        .expect_err("unsupported algo");

    // Assert
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(err.message().contains("rsa"), "{}", err.message());
}

#[tokio::test]
async fn create_user_validation_rejects_short_ed25519_public_key() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server(BootstrapMode::Open).await;
    let req = CreateUserRequest {
        display_name: "ed".into(),
        initial_key: Some(PublicKey {
            algo: "ed25519".into(),
            public_key: B64.encode([0u8; 16]),
        }),
    };

    // Act
    let err = h
        .client
        .create_user(tonic::Request::new(req))
        .await
        .expect_err("short ed25519 key");

    // Assert
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(err.message().contains("32 bytes"), "{}", err.message());
}

// ===========================================================================
// GetUser
// ===========================================================================

#[tokio::test]
async fn get_user_self_returns_user() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server(BootstrapMode::Open).await;
    let sk = make_signing_key();
    let (user_id, key_id) = create_self_user(&mut h, &sk, "get-me").await;

    // Act — sign as self.
    let ts = h.clock.now().await.unwrap();
    let req = signed(
        GetUserRequest {
            id: user_id.to_string(),
        },
        &sk,
        key_id,
        "/headlines.v1.UserService/GetUser",
        ts,
        &unique_nonce(),
    );
    let got = h.client.get_user(req).await.unwrap().into_inner();

    // Assert
    assert_eq!(got.display_name, "get-me");

    cleanup(&h.db, &[user_id]).await;
}

#[tokio::test]
async fn get_user_anonymous_returns_not_found_for_privacy() {
    skip_if_no_db!();

    // Arrange — create a real user, then try anonymously.
    let mut h = spawn_server(BootstrapMode::Open).await;
    let sk = make_signing_key();
    let (user_id, _) = create_self_user(&mut h, &sk, "private").await;

    // Act — anonymous (no auth header) call.
    let err = h
        .client
        .get_user(tonic::Request::new(GetUserRequest {
            id: user_id.to_string(),
        }))
        .await
        .expect_err("anonymous must be rejected");

    // Assert — per `users.md` privacy carve-out, anonymous must surface
    // USER_NOT_FOUND so the API does not leak user existence. The proto
    // AUTH_TABLE admits ANONYMOUS for `GetUser`; the handler then
    // translates an unauthorized (non-self) caller into `USER_NOT_FOUND`.
    assert_eq!(err.code(), tonic::Code::NotFound);

    cleanup(&h.db, &[user_id]).await;
}

#[tokio::test]
async fn get_user_cross_user_returns_user_not_found() {
    skip_if_no_db!();

    // Arrange — two users; A queries B.
    let mut h = spawn_server(BootstrapMode::Open).await;
    let sk_a = make_signing_key();
    let sk_b = make_signing_key();
    let (user_a, key_a) = create_self_user(&mut h, &sk_a, "alice").await;
    let (user_b, _) = create_self_user(&mut h, &sk_b, "bob").await;

    let ts = h.clock.now().await.unwrap();
    let req = signed(
        GetUserRequest {
            id: user_b.to_string(),
        },
        &sk_a,
        key_a,
        "/headlines.v1.UserService/GetUser",
        ts,
        &unique_nonce(),
    );

    // Act
    let err = h
        .client
        .get_user(req)
        .await
        .expect_err("cross-user GetUser must reject");

    // Assert — privacy: NOT_FOUND, not PERMISSION_DENIED.
    assert_eq!(err.code(), tonic::Code::NotFound);

    cleanup(&h.db, &[user_a, user_b]).await;
}

#[tokio::test]
async fn get_user_system_with_users_read_can_get_any() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server(BootstrapMode::Open).await;
    let target_sk = make_signing_key();
    let (user_id, _) = create_self_user(&mut h, &target_sk, "target").await;

    let sys_sk = make_signing_key();
    let (system_id, sys_key_id) = insert_system(&h.db, "reader", &["users.read"], &sys_sk).await;

    let ts = h.clock.now().await.unwrap();
    let req = signed(
        GetUserRequest {
            id: user_id.to_string(),
        },
        &sys_sk,
        sys_key_id,
        "/headlines.v1.UserService/GetUser",
        ts,
        &unique_nonce(),
    );

    // Act
    let got = h.client.get_user(req).await.unwrap().into_inner();

    // Assert
    assert_eq!(got.display_name, "target");

    cleanup(&h.db, &[user_id]).await;
    cleanup_system(&h.db, system_id).await;
}

// ===========================================================================
// UpdateUser
// ===========================================================================

#[tokio::test]
async fn update_user_self_changes_display_name() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server(BootstrapMode::Open).await;
    let sk = make_signing_key();
    let (user_id, key_id) = create_self_user(&mut h, &sk, "before").await;
    let new_name = "After";

    // Act
    let req = UpdateUserRequest {
        user: Some(user_msg(&user_id.to_string(), new_name)),
        update_mask: Some(prost_types::FieldMask {
            paths: vec!["display_name".into()],
        }),
    };
    let ts = h.clock.now().await.unwrap();
    let signed_req = signed(
        req,
        &sk,
        key_id,
        "/headlines.v1.UserService/UpdateUser",
        ts,
        &unique_nonce(),
    );
    let updated = h.client.update_user(signed_req).await.unwrap().into_inner();

    // Assert
    assert_eq!(updated.display_name, new_name);

    cleanup(&h.db, &[user_id]).await;
}

#[tokio::test]
async fn update_user_cross_user_returns_user_not_found() {
    skip_if_no_db!();

    // Arrange — A signs, B is target.
    let mut h = spawn_server(BootstrapMode::Open).await;
    let sk_a = make_signing_key();
    let sk_b = make_signing_key();
    let (user_a, key_a) = create_self_user(&mut h, &sk_a, "A").await;
    let (user_b, _) = create_self_user(&mut h, &sk_b, "B").await;

    let req = UpdateUserRequest {
        user: Some(user_msg(&user_b.to_string(), "Hostile")),
        update_mask: Some(prost_types::FieldMask {
            paths: vec!["display_name".into()],
        }),
    };
    let ts = h.clock.now().await.unwrap();
    let signed_req = signed(
        req,
        &sk_a,
        key_a,
        "/headlines.v1.UserService/UpdateUser",
        ts,
        &unique_nonce(),
    );

    // Act
    let err = h
        .client
        .update_user(signed_req)
        .await
        .expect_err("cross-user write must reject");

    // Assert
    assert_eq!(err.code(), tonic::Code::NotFound);

    cleanup(&h.db, &[user_a, user_b]).await;
}

#[tokio::test]
async fn update_user_system_with_users_admin_can_update_any() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server(BootstrapMode::Open).await;
    let target_sk = make_signing_key();
    let (user_id, _) = create_self_user(&mut h, &target_sk, "before").await;

    let sys_sk = make_signing_key();
    let (system_id, sys_key_id) = insert_system(&h.db, "admin", &["users.admin"], &sys_sk).await;

    let req = UpdateUserRequest {
        user: Some(user_msg(&user_id.to_string(), "by-admin")),
        update_mask: Some(prost_types::FieldMask {
            paths: vec!["display_name".into()],
        }),
    };
    let ts = h.clock.now().await.unwrap();
    let signed_req = signed(
        req,
        &sys_sk,
        sys_key_id,
        "/headlines.v1.UserService/UpdateUser",
        ts,
        &unique_nonce(),
    );

    // Act
    let updated = h.client.update_user(signed_req).await.unwrap().into_inner();

    // Assert
    assert_eq!(updated.display_name, "by-admin");

    cleanup(&h.db, &[user_id]).await;
    cleanup_system(&h.db, system_id).await;
}

#[tokio::test]
async fn update_user_on_deleted_returns_user_deleted() {
    skip_if_no_db!();

    // Arrange — create user, delete via system path so the user-self can
    // still sign (its keys remain active).
    let mut h = spawn_server(BootstrapMode::Open).await;
    let sk = make_signing_key();
    let (user_id, key_id) = create_self_user(&mut h, &sk, "cond").await;

    let sys_sk = make_signing_key();
    let (system_id, sys_key_id) = insert_system(&h.db, "deleter", &["users.delete"], &sys_sk).await;
    let ts = h.clock.now().await.unwrap();
    let del = signed(
        DeleteUserRequest {
            id: user_id.to_string(),
        },
        &sys_sk,
        sys_key_id,
        "/headlines.v1.UserService/DeleteUser",
        ts,
        &unique_nonce(),
    );
    h.client.delete_user(del).await.unwrap();

    // Now user-self tries to update.
    let req = UpdateUserRequest {
        user: Some(user_msg(&user_id.to_string(), "post-del")),
        update_mask: Some(prost_types::FieldMask {
            paths: vec!["display_name".into()],
        }),
    };
    let ts = h.clock.now().await.unwrap();
    let signed_req = signed(
        req,
        &sk,
        key_id,
        "/headlines.v1.UserService/UpdateUser",
        ts,
        &unique_nonce(),
    );

    // Act
    let err = h
        .client
        .update_user(signed_req)
        .await
        .expect_err("update on deleted");

    // Assert
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);

    cleanup(&h.db, &[user_id]).await;
    cleanup_system(&h.db, system_id).await;
}

#[tokio::test]
async fn update_user_unallowed_mask_path_rejected() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server(BootstrapMode::Open).await;
    let sk = make_signing_key();
    let (user_id, key_id) = create_self_user(&mut h, &sk, "x").await;

    let req = UpdateUserRequest {
        user: Some(user_msg(&user_id.to_string(), "")),
        update_mask: Some(prost_types::FieldMask {
            paths: vec!["status".into()],
        }),
    };
    let ts = h.clock.now().await.unwrap();
    let signed_req = signed(
        req,
        &sk,
        key_id,
        "/headlines.v1.UserService/UpdateUser",
        ts,
        &unique_nonce(),
    );

    // Act
    let err = h
        .client
        .update_user(signed_req)
        .await
        .expect_err("unallowed path");

    // Assert
    assert_eq!(err.code(), tonic::Code::InvalidArgument);

    cleanup(&h.db, &[user_id]).await;
}

// ===========================================================================
// DeleteUser
// ===========================================================================

#[tokio::test]
async fn delete_user_self_succeeds() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server(BootstrapMode::Open).await;
    let sk = make_signing_key();
    let (user_id, key_id) = create_self_user(&mut h, &sk, "self-del").await;

    let ts = h.clock.now().await.unwrap();
    let req = signed(
        DeleteUserRequest {
            id: user_id.to_string(),
        },
        &sk,
        key_id,
        "/headlines.v1.UserService/DeleteUser",
        ts,
        &unique_nonce(),
    );

    // Act
    let resp = h.client.delete_user(req).await.unwrap().into_inner();

    // Assert
    assert_eq!(resp.status, headlines_proto::v1::UserStatus::Deleted as i32);

    cleanup(&h.db, &[user_id]).await;
}

#[tokio::test]
async fn delete_user_system_with_users_delete_succeeds() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server(BootstrapMode::Open).await;
    let target_sk = make_signing_key();
    let (user_id, _) = create_self_user(&mut h, &target_sk, "victim").await;

    let sys_sk = make_signing_key();
    let (system_id, sys_key_id) = insert_system(&h.db, "deleter", &["users.delete"], &sys_sk).await;

    let ts = h.clock.now().await.unwrap();
    let req = signed(
        DeleteUserRequest {
            id: user_id.to_string(),
        },
        &sys_sk,
        sys_key_id,
        "/headlines.v1.UserService/DeleteUser",
        ts,
        &unique_nonce(),
    );

    // Act
    let resp = h.client.delete_user(req).await.unwrap().into_inner();

    // Assert
    assert_eq!(resp.status, headlines_proto::v1::UserStatus::Deleted as i32);

    cleanup(&h.db, &[user_id]).await;
    cleanup_system(&h.db, system_id).await;
}

// ===========================================================================
// AddUserKey
// ===========================================================================

#[tokio::test]
async fn add_user_key_self_succeeds_and_new_key_can_sign() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server(BootstrapMode::Open).await;
    let sk1 = make_signing_key();
    let (user_id, key1) = create_self_user(&mut h, &sk1, "addkey").await;

    let sk2 = make_signing_key();
    let add_req = AddUserKeyRequest {
        user_id: user_id.to_string(),
        key: Some(PublicKey {
            algo: "ed25519".into(),
            public_key: ed25519_pk_b64(&sk2),
        }),
    };
    let ts = h.clock.now().await.unwrap();
    let request = signed(
        add_req,
        &sk1,
        key1,
        "/headlines.v1.UserService/AddUserKey",
        ts,
        &unique_nonce(),
    );

    // Act
    let new_key = h.client.add_user_key(request).await.unwrap().into_inner();
    let key2 = Uuid::parse_str(&new_key.key_id).unwrap();

    // Assert — round-trip: sign a follow-up call with the new key.
    let upd = UpdateUserRequest {
        user: Some(user_msg(&user_id.to_string(), "Two")),
        update_mask: Some(prost_types::FieldMask {
            paths: vec!["display_name".into()],
        }),
    };
    let ts = h.clock.now().await.unwrap();
    let signed_upd = signed(
        upd,
        &sk2,
        key2,
        "/headlines.v1.UserService/UpdateUser",
        ts,
        &unique_nonce(),
    );
    let r = h.client.update_user(signed_upd).await.unwrap().into_inner();
    assert_eq!(r.display_name, "Two");

    cleanup(&h.db, &[user_id]).await;
}

// ===========================================================================
// RevokeUserKey
// ===========================================================================

#[tokio::test]
async fn revoke_user_key_one_of_many_succeeds() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server(BootstrapMode::Open).await;
    let sk1 = make_signing_key();
    let (user_id, key1) = create_self_user(&mut h, &sk1, "many").await;

    let sk2 = make_signing_key();
    let add_req = AddUserKeyRequest {
        user_id: user_id.to_string(),
        key: Some(PublicKey {
            algo: "ed25519".into(),
            public_key: ed25519_pk_b64(&sk2),
        }),
    };
    let ts = h.clock.now().await.unwrap();
    let request = signed(
        add_req,
        &sk1,
        key1,
        "/headlines.v1.UserService/AddUserKey",
        ts,
        &unique_nonce(),
    );
    let added = h.client.add_user_key(request).await.unwrap().into_inner();
    let key2 = Uuid::parse_str(&added.key_id).unwrap();

    // Revoke key2 with key1 still active.
    let revoke = RevokeUserKeyRequest {
        user_id: user_id.to_string(),
        key_id: key2.to_string(),
    };
    let ts = h.clock.now().await.unwrap();
    let signed_revoke = signed(
        revoke,
        &sk1,
        key1,
        "/headlines.v1.UserService/RevokeUserKey",
        ts,
        &unique_nonce(),
    );

    // Act
    let r = h
        .client
        .revoke_user_key(signed_revoke)
        .await
        .unwrap()
        .into_inner();

    // Assert
    assert_eq!(r.status, headlines_proto::v1::KeyStatus::Revoked as i32);

    cleanup(&h.db, &[user_id]).await;
}

#[tokio::test]
async fn revoke_user_key_last_active_is_rejected() {
    skip_if_no_db!();

    // Arrange — single key.
    let mut h = spawn_server(BootstrapMode::Open).await;
    let sk = make_signing_key();
    let (user_id, key1) = create_self_user(&mut h, &sk, "single").await;

    let revoke = RevokeUserKeyRequest {
        user_id: user_id.to_string(),
        key_id: key1.to_string(),
    };
    let ts = h.clock.now().await.unwrap();
    let signed_revoke = signed(
        revoke,
        &sk,
        key1,
        "/headlines.v1.UserService/RevokeUserKey",
        ts,
        &unique_nonce(),
    );

    // Act
    let err = h
        .client
        .revoke_user_key(signed_revoke)
        .await
        .expect_err("last-key revoke rejected");

    // Assert
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);

    cleanup(&h.db, &[user_id]).await;
}

#[tokio::test]
async fn revoke_user_key_admin_star_can_override_lockout() {
    skip_if_no_db!();

    // Arrange — single key, system with admin.* overrides.
    let mut h = spawn_server(BootstrapMode::Open).await;
    let sk = make_signing_key();
    let (user_id, key1) = create_self_user(&mut h, &sk, "rescue").await;

    let sys_sk = make_signing_key();
    let (system_id, sys_key_id) =
        insert_system(&h.db, "rescue", &["users.admin", "admin.*"], &sys_sk).await;

    let revoke = RevokeUserKeyRequest {
        user_id: user_id.to_string(),
        key_id: key1.to_string(),
    };
    let ts = h.clock.now().await.unwrap();
    let signed_revoke = signed(
        revoke,
        &sys_sk,
        sys_key_id,
        "/headlines.v1.UserService/RevokeUserKey",
        ts,
        &unique_nonce(),
    );

    // Act
    let r = h
        .client
        .revoke_user_key(signed_revoke)
        .await
        .expect("admin.* must override lockout")
        .into_inner();

    // Assert
    assert_eq!(r.status, headlines_proto::v1::KeyStatus::Revoked as i32);

    cleanup(&h.db, &[user_id]).await;
    cleanup_system(&h.db, system_id).await;
}

#[tokio::test]
async fn revoke_user_key_already_revoked_is_already_exists() {
    skip_if_no_db!();

    // Arrange — add a 2nd key, revoke it twice.
    let mut h = spawn_server(BootstrapMode::Open).await;
    let sk1 = make_signing_key();
    let (user_id, key1) = create_self_user(&mut h, &sk1, "double").await;
    let sk2 = make_signing_key();
    let ts = h.clock.now().await.unwrap();
    let added = h
        .client
        .add_user_key(signed(
            AddUserKeyRequest {
                user_id: user_id.to_string(),
                key: Some(PublicKey {
                    algo: "ed25519".into(),
                    public_key: ed25519_pk_b64(&sk2),
                }),
            },
            &sk1,
            key1,
            "/headlines.v1.UserService/AddUserKey",
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();
    let key2 = Uuid::parse_str(&added.key_id).unwrap();

    let ts = h.clock.now().await.unwrap();
    h.client
        .revoke_user_key(signed(
            RevokeUserKeyRequest {
                user_id: user_id.to_string(),
                key_id: key2.to_string(),
            },
            &sk1,
            key1,
            "/headlines.v1.UserService/RevokeUserKey",
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap();

    // Act — revoke again.
    let ts = h.clock.now().await.unwrap();
    let err = h
        .client
        .revoke_user_key(signed(
            RevokeUserKeyRequest {
                user_id: user_id.to_string(),
                key_id: key2.to_string(),
            },
            &sk1,
            key1,
            "/headlines.v1.UserService/RevokeUserKey",
            ts,
            &unique_nonce(),
        ))
        .await
        .expect_err("double revoke");

    // Assert
    assert_eq!(err.code(), tonic::Code::AlreadyExists);

    cleanup(&h.db, &[user_id]).await;
}

#[tokio::test]
async fn revoke_user_key_missing_key_returns_not_found() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server(BootstrapMode::Open).await;
    let sk = make_signing_key();
    let (user_id, key1) = create_self_user(&mut h, &sk, "miss").await;
    let phantom = Uuid::now_v7();

    let ts = h.clock.now().await.unwrap();
    let signed_revoke = signed(
        RevokeUserKeyRequest {
            user_id: user_id.to_string(),
            key_id: phantom.to_string(),
        },
        &sk,
        key1,
        "/headlines.v1.UserService/RevokeUserKey",
        ts,
        &unique_nonce(),
    );

    // Act
    let err = h
        .client
        .revoke_user_key(signed_revoke)
        .await
        .expect_err("missing key");

    // Assert
    assert_eq!(err.code(), tonic::Code::NotFound);

    cleanup(&h.db, &[user_id]).await;
}
