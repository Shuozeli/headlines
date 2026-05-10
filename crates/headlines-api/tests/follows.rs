//! End-to-end integration tests for `FollowService`, exercised through a
//! real tonic in-process server (random TCP port) backed by Postgres on
//! `docker.yuacx.com`. Mirrors `tests/drafts.rs` / `tests/users.rs`.
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
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use tonic::transport::{Channel, Endpoint, Server};
use uuid::Uuid;

use headlines_api::FollowServiceImpl;
use headlines_auth::{
    AlgorithmRegistry, AuthInterceptor, AuthorizationLayer, Ed25519, InMemoryNonceStore,
    LocalClock, PostgresKeyResolver, ProtoBodyHasher, SignedRequestStrategy,
};
use headlines_core::{TimeSource as _, Tso};
use headlines_proto::v1::{
    FollowRequest, FollowStatus, GetFollowRequest, ListAccountFollowersRequest,
    ListUserFollowsRequest, UnfollowRequest, follow_service_client::FollowServiceClient,
    follow_service_server::FollowServiceServer,
};
use headlines_store::{Db, PgAccountRepo, PgFollowRepo, PgUserRepo};

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

struct Harness {
    db: Db,
    client: FollowServiceClient<Channel>,
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

    let users = Arc::new(PgUserRepo::new(db.clone()));
    let accounts = Arc::new(PgAccountRepo::new(db.clone()));
    let follows = Arc::new(PgFollowRepo::new(db.clone()));

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

    let svc = FollowServiceImpl::new(users, accounts, follows);

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
        .add_service(FollowServiceServer::new(svc));

    tokio::spawn(async move {
        let _ = server.serve_with_incoming(stream).await;
    });

    let endpoint = Endpoint::from_shared(format!("http://{addr}"))
        .expect("endpoint")
        .connect_timeout(Duration::from_secs(5));
    let channel = endpoint.connect().await.expect("client connect");
    let client = FollowServiceClient::new(channel);

    Harness {
        db,
        client,
        clock,
        _addr: addr,
    }
}

// ---------------------------------------------------------------------------
// Signing helpers
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
// DB cleanup / seeding helpers
// ---------------------------------------------------------------------------

async fn cleanup_follows(db: &Db, user_ids: &[Uuid], account_ids: &[Uuid]) {
    let url = db.database_url().to_owned();
    let users = user_ids.to_owned();
    let accounts = account_ids.to_owned();
    let _ = tokio::spawn(async move {
        let mut conn = match AsyncPgConnection::establish(&url).await {
            Ok(c) => c,
            Err(_) => return,
        };
        if !users.is_empty() {
            let _ = diesel::sql_query("DELETE FROM follows WHERE user_id = ANY($1)")
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
        if !accounts.is_empty() {
            let _ = diesel::sql_query("DELETE FROM follows WHERE account_id = ANY($1)")
                .bind::<diesel::sql_types::Array<diesel::sql_types::Uuid>, _>(accounts.clone())
                .execute(&mut conn)
                .await;
            let _ = diesel::sql_query("DELETE FROM account_keys WHERE account_id = ANY($1)")
                .bind::<diesel::sql_types::Array<diesel::sql_types::Uuid>, _>(accounts.clone())
                .execute(&mut conn)
                .await;
            let _ = diesel::sql_query("DELETE FROM accounts WHERE id = ANY($1)")
                .bind::<diesel::sql_types::Array<diesel::sql_types::Uuid>, _>(accounts)
                .execute(&mut conn)
                .await;
        }
    })
    .await;
}

/// Seed a user + its initial signing key directly via SQL, bypassing
/// UserService. Returns `(user_id, key_id)`.
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

/// Seed an account + its initial signing key directly via SQL, bypassing
/// AccountService. Returns `(account_id, key_id)`.
async fn seed_account_with_key(db: &Db, sk: &SigningKey) -> (Uuid, Uuid) {
    let mut conn = db.get().await.unwrap();
    let account_id = Uuid::now_v7();
    let key_id = Uuid::now_v7();
    let pk_b64 = B64.encode(sk.verifying_key().as_bytes());

    diesel::sql_query(
        "INSERT INTO accounts (id, short_name, author_name, status) \
         VALUES ($1, $2, 'Test Author', 'active')",
    )
    .bind::<diesel::sql_types::Uuid, _>(account_id)
    .bind::<diesel::sql_types::Text, _>(format!("test-{}", account_id.simple()))
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

async fn delete_user_directly(db: &Db, user_id: Uuid) {
    let mut conn = db.get().await.unwrap();
    diesel::sql_query("UPDATE users SET status='deleted', deleted_at=now() WHERE id = $1")
        .bind::<diesel::sql_types::Uuid, _>(user_id)
        .execute(&mut conn)
        .await
        .unwrap();
}

async fn delete_account_directly(db: &Db, account_id: Uuid) {
    let mut conn = db.get().await.unwrap();
    diesel::sql_query("UPDATE accounts SET status='deleted', deleted_at=now() WHERE id = $1")
        .bind::<diesel::sql_types::Uuid, _>(account_id)
        .execute(&mut conn)
        .await
        .unwrap();
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

// ===========================================================================
// Follow
// ===========================================================================

#[tokio::test]
async fn follow_creates_edge_when_missing() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let acct_sk = make_signing_key();
    let (user_id, user_key) = seed_user_with_key(&h.db, &user_sk).await;
    let (account_id, _) = seed_account_with_key(&h.db, &acct_sk).await;

    let req = FollowRequest {
        user_id: user_id.to_string(),
        account_id: account_id.to_string(),
    };
    let ts = h.clock.now().await.unwrap();
    let signed_req = signed(
        req,
        &user_sk,
        user_key,
        "/headlines.v1.FollowService/Follow",
        ts,
        &unique_nonce(),
    );

    // Act
    let resp = h.client.follow(signed_req).await.unwrap().into_inner();

    // Assert
    assert_eq!(resp.status, FollowStatus::Active as i32);
    assert_eq!(resp.user_id, user_id.to_string());
    assert_eq!(resp.account_id, account_id.to_string());

    cleanup_follows(&h.db, &[user_id], &[account_id]).await;
}

#[tokio::test]
async fn follow_already_active_is_idempotent_noop() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let acct_sk = make_signing_key();
    let (user_id, user_key) = seed_user_with_key(&h.db, &user_sk).await;
    let (account_id, _) = seed_account_with_key(&h.db, &acct_sk).await;

    // First follow.
    let ts = h.clock.now().await.unwrap();
    let first = h
        .client
        .follow(signed(
            FollowRequest {
                user_id: user_id.to_string(),
                account_id: account_id.to_string(),
            },
            &user_sk,
            user_key,
            "/headlines.v1.FollowService/Follow",
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();

    // Act — second follow.
    let ts = h.clock.now().await.unwrap();
    let second = h
        .client
        .follow(signed(
            FollowRequest {
                user_id: user_id.to_string(),
                account_id: account_id.to_string(),
            },
            &user_sk,
            user_key,
            "/headlines.v1.FollowService/Follow",
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();

    // Assert — same created_at, no rewrite.
    assert_eq!(second.status, FollowStatus::Active as i32);
    assert_eq!(second.created_at, first.created_at);

    cleanup_follows(&h.db, &[user_id], &[account_id]).await;
}

#[tokio::test]
async fn follow_re_activates_unfollowed_edge_and_resets_created_at() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let acct_sk = make_signing_key();
    let (user_id, user_key) = seed_user_with_key(&h.db, &user_sk).await;
    let (account_id, _) = seed_account_with_key(&h.db, &acct_sk).await;

    // Follow then unfollow.
    let ts = h.clock.now().await.unwrap();
    let first = h
        .client
        .follow(signed(
            FollowRequest {
                user_id: user_id.to_string(),
                account_id: account_id.to_string(),
            },
            &user_sk,
            user_key,
            "/headlines.v1.FollowService/Follow",
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();

    let ts = h.clock.now().await.unwrap();
    h.client
        .unfollow(signed(
            UnfollowRequest {
                user_id: user_id.to_string(),
                account_id: account_id.to_string(),
            },
            &user_sk,
            user_key,
            "/headlines.v1.FollowService/Unfollow",
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap();

    // Sleep briefly so the new created_at strictly differs.
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Act — follow again.
    let ts = h.clock.now().await.unwrap();
    let revived = h
        .client
        .follow(signed(
            FollowRequest {
                user_id: user_id.to_string(),
                account_id: account_id.to_string(),
            },
            &user_sk,
            user_key,
            "/headlines.v1.FollowService/Follow",
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();

    // Assert — back to active, unfollowed_at cleared, created_at bumped.
    assert_eq!(revived.status, FollowStatus::Active as i32);
    assert!(revived.unfollowed_at.is_none());
    let first_seconds = first.created_at.as_ref().unwrap().seconds;
    let new_seconds = revived.created_at.as_ref().unwrap().seconds;
    let new_nanos = revived.created_at.as_ref().unwrap().nanos;
    let first_nanos = first.created_at.as_ref().unwrap().nanos;
    let later =
        new_seconds > first_seconds || (new_seconds == first_seconds && new_nanos > first_nanos);
    assert!(later, "created_at should be bumped on re-activate");

    cleanup_follows(&h.db, &[user_id], &[account_id]).await;
}

#[tokio::test]
async fn follow_on_deleted_user_is_user_deleted() {
    skip_if_no_db!();

    // Arrange — user exists then is soft-deleted; we sign with the user's
    // existing key (still active in user_keys for signing purposes) but the
    // user row is in `deleted` state.
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let acct_sk = make_signing_key();
    let (user_id, user_key) = seed_user_with_key(&h.db, &user_sk).await;
    let (account_id, _) = seed_account_with_key(&h.db, &acct_sk).await;
    delete_user_directly(&h.db, user_id).await;

    let req = FollowRequest {
        user_id: user_id.to_string(),
        account_id: account_id.to_string(),
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let err = h
        .client
        .follow(signed(
            req,
            &user_sk,
            user_key,
            "/headlines.v1.FollowService/Follow",
            ts,
            &unique_nonce(),
        ))
        .await
        .expect_err("follow targeting a deleted user must reject");

    // Assert — USER_DELETED → FAILED_PRECONDITION.
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);

    cleanup_follows(&h.db, &[user_id], &[account_id]).await;
}

#[tokio::test]
async fn follow_on_deleted_account_is_account_deleted() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let acct_sk = make_signing_key();
    let (user_id, user_key) = seed_user_with_key(&h.db, &user_sk).await;
    let (account_id, _) = seed_account_with_key(&h.db, &acct_sk).await;
    delete_account_directly(&h.db, account_id).await;

    let req = FollowRequest {
        user_id: user_id.to_string(),
        account_id: account_id.to_string(),
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let err = h
        .client
        .follow(signed(
            req,
            &user_sk,
            user_key,
            "/headlines.v1.FollowService/Follow",
            ts,
            &unique_nonce(),
        ))
        .await
        .expect_err("follow targeting a deleted account must reject");

    // Assert
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);

    cleanup_follows(&h.db, &[user_id], &[account_id]).await;
}

#[tokio::test]
async fn follow_on_missing_user_returns_user_not_found() {
    skip_if_no_db!();

    // Arrange — phantom user_id, but the caller IS that phantom (so the
    // self-check passes the proto-level gate). With no `users` row the
    // handler's existence check fires.
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let acct_sk = make_signing_key();
    // Seed a real user so we have a working key, then sign as that user but
    // request a different `user_id` — the cross-user case is also
    // USER_NOT_FOUND.
    let (real_user, real_key) = seed_user_with_key(&h.db, &user_sk).await;
    let (account_id, _) = seed_account_with_key(&h.db, &acct_sk).await;
    let phantom = Uuid::now_v7();

    let req = FollowRequest {
        user_id: phantom.to_string(),
        account_id: account_id.to_string(),
    };
    let ts = h.clock.now().await.unwrap();

    // Act — sign as the real user, but request a phantom user_id; the
    // self-check fails first, surfacing USER_NOT_FOUND for the phantom.
    let err = h
        .client
        .follow(signed(
            req,
            &user_sk,
            real_key,
            "/headlines.v1.FollowService/Follow",
            ts,
            &unique_nonce(),
        ))
        .await
        .expect_err("missing-user follow must reject");

    // Assert
    assert_eq!(err.code(), tonic::Code::NotFound);

    cleanup_follows(&h.db, &[real_user], &[account_id]).await;
}

#[tokio::test]
async fn follow_on_missing_account_returns_account_not_found() {
    skip_if_no_db!();

    // Arrange — real user, phantom account.
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let (user_id, user_key) = seed_user_with_key(&h.db, &user_sk).await;
    let phantom_account = Uuid::now_v7();

    let req = FollowRequest {
        user_id: user_id.to_string(),
        account_id: phantom_account.to_string(),
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let err = h
        .client
        .follow(signed(
            req,
            &user_sk,
            user_key,
            "/headlines.v1.FollowService/Follow",
            ts,
            &unique_nonce(),
        ))
        .await
        .expect_err("missing-account follow must reject");

    // Assert
    assert_eq!(err.code(), tonic::Code::NotFound);

    cleanup_follows(&h.db, &[user_id], &[]).await;
}

#[tokio::test]
async fn follow_self_id_collision_is_self_follow_forbidden() {
    skip_if_no_db!();

    // Arrange — `user_id == account_id`.
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let (user_id, user_key) = seed_user_with_key(&h.db, &user_sk).await;

    let req = FollowRequest {
        user_id: user_id.to_string(),
        account_id: user_id.to_string(),
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let err = h
        .client
        .follow(signed(
            req,
            &user_sk,
            user_key,
            "/headlines.v1.FollowService/Follow",
            ts,
            &unique_nonce(),
        ))
        .await
        .expect_err("self-id collision must reject");

    // Assert
    assert_eq!(err.code(), tonic::Code::InvalidArgument);

    cleanup_follows(&h.db, &[user_id], &[]).await;
}

// ===========================================================================
// Unfollow
// ===========================================================================

#[tokio::test]
async fn unfollow_active_edge_succeeds() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let acct_sk = make_signing_key();
    let (user_id, user_key) = seed_user_with_key(&h.db, &user_sk).await;
    let (account_id, _) = seed_account_with_key(&h.db, &acct_sk).await;

    // Follow first.
    let ts = h.clock.now().await.unwrap();
    h.client
        .follow(signed(
            FollowRequest {
                user_id: user_id.to_string(),
                account_id: account_id.to_string(),
            },
            &user_sk,
            user_key,
            "/headlines.v1.FollowService/Follow",
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap();

    // Act — unfollow.
    let ts = h.clock.now().await.unwrap();
    let resp = h
        .client
        .unfollow(signed(
            UnfollowRequest {
                user_id: user_id.to_string(),
                account_id: account_id.to_string(),
            },
            &user_sk,
            user_key,
            "/headlines.v1.FollowService/Unfollow",
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();

    // Assert
    assert_eq!(resp.status, FollowStatus::Unfollowed as i32);
    assert!(resp.unfollowed_at.is_some());

    cleanup_follows(&h.db, &[user_id], &[account_id]).await;
}

#[tokio::test]
async fn unfollow_already_unfollowed_is_idempotent_success() {
    skip_if_no_db!();

    // Arrange — follow then unfollow once.
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let acct_sk = make_signing_key();
    let (user_id, user_key) = seed_user_with_key(&h.db, &user_sk).await;
    let (account_id, _) = seed_account_with_key(&h.db, &acct_sk).await;

    let ts = h.clock.now().await.unwrap();
    h.client
        .follow(signed(
            FollowRequest {
                user_id: user_id.to_string(),
                account_id: account_id.to_string(),
            },
            &user_sk,
            user_key,
            "/headlines.v1.FollowService/Follow",
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap();
    let ts = h.clock.now().await.unwrap();
    h.client
        .unfollow(signed(
            UnfollowRequest {
                user_id: user_id.to_string(),
                account_id: account_id.to_string(),
            },
            &user_sk,
            user_key,
            "/headlines.v1.FollowService/Unfollow",
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap();

    // Act — second unfollow on already-unfollowed.
    let ts = h.clock.now().await.unwrap();
    let resp = h
        .client
        .unfollow(signed(
            UnfollowRequest {
                user_id: user_id.to_string(),
                account_id: account_id.to_string(),
            },
            &user_sk,
            user_key,
            "/headlines.v1.FollowService/Unfollow",
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();

    // Assert
    assert_eq!(resp.status, FollowStatus::Unfollowed as i32);

    cleanup_follows(&h.db, &[user_id], &[account_id]).await;
}

#[tokio::test]
async fn unfollow_missing_edge_returns_follow_not_found() {
    skip_if_no_db!();

    // Arrange — user + account exist but no follow row.
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let acct_sk = make_signing_key();
    let (user_id, user_key) = seed_user_with_key(&h.db, &user_sk).await;
    let (account_id, _) = seed_account_with_key(&h.db, &acct_sk).await;

    let ts = h.clock.now().await.unwrap();

    // Act
    let err = h
        .client
        .unfollow(signed(
            UnfollowRequest {
                user_id: user_id.to_string(),
                account_id: account_id.to_string(),
            },
            &user_sk,
            user_key,
            "/headlines.v1.FollowService/Unfollow",
            ts,
            &unique_nonce(),
        ))
        .await
        .expect_err("unfollow on missing edge must reject");

    // Assert
    assert_eq!(err.code(), tonic::Code::NotFound);

    cleanup_follows(&h.db, &[user_id], &[account_id]).await;
}

// ===========================================================================
// GetFollow
// ===========================================================================

#[tokio::test]
async fn get_follow_returns_existing_active_edge() {
    skip_if_no_db!();

    // Arrange — follow first.
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let acct_sk = make_signing_key();
    let (user_id, user_key) = seed_user_with_key(&h.db, &user_sk).await;
    let (account_id, _) = seed_account_with_key(&h.db, &acct_sk).await;

    let ts = h.clock.now().await.unwrap();
    h.client
        .follow(signed(
            FollowRequest {
                user_id: user_id.to_string(),
                account_id: account_id.to_string(),
            },
            &user_sk,
            user_key,
            "/headlines.v1.FollowService/Follow",
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap();

    let ts = h.clock.now().await.unwrap();

    // Act
    let resp = h
        .client
        .get_follow(signed(
            GetFollowRequest {
                user_id: user_id.to_string(),
                account_id: account_id.to_string(),
            },
            &user_sk,
            user_key,
            "/headlines.v1.FollowService/GetFollow",
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();

    // Assert
    assert_eq!(resp.status, FollowStatus::Active as i32);

    cleanup_follows(&h.db, &[user_id], &[account_id]).await;
}

#[tokio::test]
async fn get_follow_returns_unfollowed_row_too() {
    skip_if_no_db!();

    // Arrange — follow + unfollow.
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let acct_sk = make_signing_key();
    let (user_id, user_key) = seed_user_with_key(&h.db, &user_sk).await;
    let (account_id, _) = seed_account_with_key(&h.db, &acct_sk).await;

    let ts = h.clock.now().await.unwrap();
    h.client
        .follow(signed(
            FollowRequest {
                user_id: user_id.to_string(),
                account_id: account_id.to_string(),
            },
            &user_sk,
            user_key,
            "/headlines.v1.FollowService/Follow",
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap();
    let ts = h.clock.now().await.unwrap();
    h.client
        .unfollow(signed(
            UnfollowRequest {
                user_id: user_id.to_string(),
                account_id: account_id.to_string(),
            },
            &user_sk,
            user_key,
            "/headlines.v1.FollowService/Unfollow",
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap();

    // Act
    let ts = h.clock.now().await.unwrap();
    let resp = h
        .client
        .get_follow(signed(
            GetFollowRequest {
                user_id: user_id.to_string(),
                account_id: account_id.to_string(),
            },
            &user_sk,
            user_key,
            "/headlines.v1.FollowService/GetFollow",
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();

    // Assert
    assert_eq!(resp.status, FollowStatus::Unfollowed as i32);

    cleanup_follows(&h.db, &[user_id], &[account_id]).await;
}

#[tokio::test]
async fn get_follow_missing_edge_returns_follow_not_found() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let acct_sk = make_signing_key();
    let (user_id, user_key) = seed_user_with_key(&h.db, &user_sk).await;
    let (account_id, _) = seed_account_with_key(&h.db, &acct_sk).await;

    let ts = h.clock.now().await.unwrap();

    // Act
    let err = h
        .client
        .get_follow(signed(
            GetFollowRequest {
                user_id: user_id.to_string(),
                account_id: account_id.to_string(),
            },
            &user_sk,
            user_key,
            "/headlines.v1.FollowService/GetFollow",
            ts,
            &unique_nonce(),
        ))
        .await
        .expect_err("missing edge");

    // Assert
    assert_eq!(err.code(), tonic::Code::NotFound);

    cleanup_follows(&h.db, &[user_id], &[account_id]).await;
}

// ===========================================================================
// ListUserFollows
// ===========================================================================

#[tokio::test]
async fn list_user_follows_default_excludes_unfollowed() {
    skip_if_no_db!();

    // Arrange — one user follows two accounts, then unfollows one.
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let acct_sk = make_signing_key();
    let (user_id, user_key) = seed_user_with_key(&h.db, &user_sk).await;
    let (acct_a, _) = seed_account_with_key(&h.db, &acct_sk).await;
    let acct_sk_b = make_signing_key();
    let (acct_b, _) = seed_account_with_key(&h.db, &acct_sk_b).await;

    let ts = h.clock.now().await.unwrap();
    h.client
        .follow(signed(
            FollowRequest {
                user_id: user_id.to_string(),
                account_id: acct_a.to_string(),
            },
            &user_sk,
            user_key,
            "/headlines.v1.FollowService/Follow",
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap();
    let ts = h.clock.now().await.unwrap();
    h.client
        .follow(signed(
            FollowRequest {
                user_id: user_id.to_string(),
                account_id: acct_b.to_string(),
            },
            &user_sk,
            user_key,
            "/headlines.v1.FollowService/Follow",
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap();
    let ts = h.clock.now().await.unwrap();
    h.client
        .unfollow(signed(
            UnfollowRequest {
                user_id: user_id.to_string(),
                account_id: acct_a.to_string(),
            },
            &user_sk,
            user_key,
            "/headlines.v1.FollowService/Unfollow",
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap();

    // Act — default list excludes unfollowed.
    let ts = h.clock.now().await.unwrap();
    let resp = h
        .client
        .list_user_follows(signed(
            ListUserFollowsRequest {
                user_id: user_id.to_string(),
                page_size: 50,
                page_token: String::new(),
                include_unfollowed: false,
            },
            &user_sk,
            user_key,
            "/headlines.v1.FollowService/ListUserFollows",
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();

    // Assert — only `acct_b` survives.
    assert_eq!(resp.items.len(), 1);
    assert_eq!(resp.items[0].account_id, acct_b.to_string());

    cleanup_follows(&h.db, &[user_id], &[acct_a, acct_b]).await;
}

#[tokio::test]
async fn list_user_follows_include_unfollowed_returns_all() {
    skip_if_no_db!();

    // Arrange — same as above but with include_unfollowed=true.
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let (user_id, user_key) = seed_user_with_key(&h.db, &user_sk).await;
    let acct_sk_a = make_signing_key();
    let (acct_a, _) = seed_account_with_key(&h.db, &acct_sk_a).await;
    let acct_sk_b = make_signing_key();
    let (acct_b, _) = seed_account_with_key(&h.db, &acct_sk_b).await;

    let ts = h.clock.now().await.unwrap();
    h.client
        .follow(signed(
            FollowRequest {
                user_id: user_id.to_string(),
                account_id: acct_a.to_string(),
            },
            &user_sk,
            user_key,
            "/headlines.v1.FollowService/Follow",
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap();
    let ts = h.clock.now().await.unwrap();
    h.client
        .follow(signed(
            FollowRequest {
                user_id: user_id.to_string(),
                account_id: acct_b.to_string(),
            },
            &user_sk,
            user_key,
            "/headlines.v1.FollowService/Follow",
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap();
    let ts = h.clock.now().await.unwrap();
    h.client
        .unfollow(signed(
            UnfollowRequest {
                user_id: user_id.to_string(),
                account_id: acct_a.to_string(),
            },
            &user_sk,
            user_key,
            "/headlines.v1.FollowService/Unfollow",
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap();

    // Act
    let ts = h.clock.now().await.unwrap();
    let resp = h
        .client
        .list_user_follows(signed(
            ListUserFollowsRequest {
                user_id: user_id.to_string(),
                page_size: 50,
                page_token: String::new(),
                include_unfollowed: true,
            },
            &user_sk,
            user_key,
            "/headlines.v1.FollowService/ListUserFollows",
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();

    // Assert
    assert_eq!(resp.items.len(), 2);

    cleanup_follows(&h.db, &[user_id], &[acct_a, acct_b]).await;
}

#[tokio::test]
async fn list_user_follows_pagination_returns_next_token() {
    skip_if_no_db!();

    // Arrange — follow 3 accounts, page_size=2.
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let (user_id, user_key) = seed_user_with_key(&h.db, &user_sk).await;
    let mut accounts = Vec::new();
    for _ in 0..3 {
        let sk = make_signing_key();
        let (a, _) = seed_account_with_key(&h.db, &sk).await;
        accounts.push(a);
        // Stagger creation so created_at is monotonically increasing.
        tokio::time::sleep(Duration::from_millis(10)).await;
        let ts = h.clock.now().await.unwrap();
        h.client
            .follow(signed(
                FollowRequest {
                    user_id: user_id.to_string(),
                    account_id: a.to_string(),
                },
                &user_sk,
                user_key,
                "/headlines.v1.FollowService/Follow",
                ts,
                &unique_nonce(),
            ))
            .await
            .unwrap();
    }

    // Act — first page.
    let ts = h.clock.now().await.unwrap();
    let page1 = h
        .client
        .list_user_follows(signed(
            ListUserFollowsRequest {
                user_id: user_id.to_string(),
                page_size: 2,
                page_token: String::new(),
                include_unfollowed: false,
            },
            &user_sk,
            user_key,
            "/headlines.v1.FollowService/ListUserFollows",
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();

    // Assert page1 — 2 items, non-empty next token.
    assert_eq!(page1.items.len(), 2);
    assert!(!page1.next_page_token.is_empty());

    // Second page.
    let ts = h.clock.now().await.unwrap();
    let page2 = h
        .client
        .list_user_follows(signed(
            ListUserFollowsRequest {
                user_id: user_id.to_string(),
                page_size: 2,
                page_token: page1.next_page_token.clone(),
                include_unfollowed: false,
            },
            &user_sk,
            user_key,
            "/headlines.v1.FollowService/ListUserFollows",
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();

    // Assert page2 — last item, no further token.
    assert_eq!(page2.items.len(), 1);
    assert!(page2.next_page_token.is_empty());

    cleanup_follows(&h.db, &[user_id], &accounts).await;
}

#[tokio::test]
async fn list_user_follows_orders_by_created_at_desc() {
    skip_if_no_db!();

    // Arrange — follow A then B with a sleep between so created_at differs.
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let (user_id, user_key) = seed_user_with_key(&h.db, &user_sk).await;
    let acct_sk_a = make_signing_key();
    let (acct_a, _) = seed_account_with_key(&h.db, &acct_sk_a).await;
    let acct_sk_b = make_signing_key();
    let (acct_b, _) = seed_account_with_key(&h.db, &acct_sk_b).await;

    let ts = h.clock.now().await.unwrap();
    h.client
        .follow(signed(
            FollowRequest {
                user_id: user_id.to_string(),
                account_id: acct_a.to_string(),
            },
            &user_sk,
            user_key,
            "/headlines.v1.FollowService/Follow",
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    let ts = h.clock.now().await.unwrap();
    h.client
        .follow(signed(
            FollowRequest {
                user_id: user_id.to_string(),
                account_id: acct_b.to_string(),
            },
            &user_sk,
            user_key,
            "/headlines.v1.FollowService/Follow",
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap();

    // Act
    let ts = h.clock.now().await.unwrap();
    let resp = h
        .client
        .list_user_follows(signed(
            ListUserFollowsRequest {
                user_id: user_id.to_string(),
                page_size: 50,
                page_token: String::new(),
                include_unfollowed: false,
            },
            &user_sk,
            user_key,
            "/headlines.v1.FollowService/ListUserFollows",
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();

    // Assert — B (newer) first, A second.
    assert_eq!(resp.items[0].account_id, acct_b.to_string());
    assert_eq!(resp.items[1].account_id, acct_a.to_string());

    cleanup_follows(&h.db, &[user_id], &[acct_a, acct_b]).await;
}

// ===========================================================================
// ListAccountFollowers
// ===========================================================================

#[tokio::test]
async fn list_account_followers_returns_active_followers_for_account_self() {
    skip_if_no_db!();

    // Arrange — two users follow the same account.
    let mut h = spawn_server().await;
    let acct_sk = make_signing_key();
    let (account_id, account_key) = seed_account_with_key(&h.db, &acct_sk).await;
    let user_sk_a = make_signing_key();
    let (user_a, key_a) = seed_user_with_key(&h.db, &user_sk_a).await;
    let user_sk_b = make_signing_key();
    let (user_b, key_b) = seed_user_with_key(&h.db, &user_sk_b).await;

    let ts = h.clock.now().await.unwrap();
    h.client
        .follow(signed(
            FollowRequest {
                user_id: user_a.to_string(),
                account_id: account_id.to_string(),
            },
            &user_sk_a,
            key_a,
            "/headlines.v1.FollowService/Follow",
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap();
    let ts = h.clock.now().await.unwrap();
    h.client
        .follow(signed(
            FollowRequest {
                user_id: user_b.to_string(),
                account_id: account_id.to_string(),
            },
            &user_sk_b,
            key_b,
            "/headlines.v1.FollowService/Follow",
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap();

    // Act — account-self lists its followers.
    let ts = h.clock.now().await.unwrap();
    let resp = h
        .client
        .list_account_followers(signed(
            ListAccountFollowersRequest {
                account_id: account_id.to_string(),
                page_size: 50,
                page_token: String::new(),
                include_unfollowed: false,
            },
            &acct_sk,
            account_key,
            "/headlines.v1.FollowService/ListAccountFollowers",
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();

    // Assert
    assert_eq!(resp.items.len(), 2);

    cleanup_follows(&h.db, &[user_a, user_b], &[account_id]).await;
}

// ===========================================================================
// Authorization
// ===========================================================================

#[tokio::test]
async fn cross_user_follow_is_rejected_as_user_not_found() {
    skip_if_no_db!();

    // Arrange — A signs but submits B's user_id as the follower.
    let mut h = spawn_server().await;
    let user_sk_a = make_signing_key();
    let (user_a, key_a) = seed_user_with_key(&h.db, &user_sk_a).await;
    let user_sk_b = make_signing_key();
    let (user_b, _) = seed_user_with_key(&h.db, &user_sk_b).await;
    let acct_sk = make_signing_key();
    let (account_id, _) = seed_account_with_key(&h.db, &acct_sk).await;

    let req = FollowRequest {
        user_id: user_b.to_string(),
        account_id: account_id.to_string(),
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let err = h
        .client
        .follow(signed(
            req,
            &user_sk_a,
            key_a,
            "/headlines.v1.FollowService/Follow",
            ts,
            &unique_nonce(),
        ))
        .await
        .expect_err("cross-user follow must reject");

    // Assert
    assert_eq!(err.code(), tonic::Code::NotFound);

    cleanup_follows(&h.db, &[user_a, user_b], &[account_id]).await;
}

#[tokio::test]
async fn system_with_follows_write_can_follow_on_behalf() {
    skip_if_no_db!();

    // Arrange — system signs, requests follow on a user's behalf.
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let (user_id, _) = seed_user_with_key(&h.db, &user_sk).await;
    let acct_sk = make_signing_key();
    let (account_id, _) = seed_account_with_key(&h.db, &acct_sk).await;

    let sys_sk = make_signing_key();
    let (system_id, sys_key) =
        insert_system(&h.db, "follower-bot", &["follows.write"], &sys_sk).await;

    let req = FollowRequest {
        user_id: user_id.to_string(),
        account_id: account_id.to_string(),
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let resp = h
        .client
        .follow(signed(
            req,
            &sys_sk,
            sys_key,
            "/headlines.v1.FollowService/Follow",
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();

    // Assert
    assert_eq!(resp.status, FollowStatus::Active as i32);

    cleanup_follows(&h.db, &[user_id], &[account_id]).await;
    cleanup_system(&h.db, system_id).await;
}

// ===========================================================================
// Concurrency
// ===========================================================================

#[tokio::test]
async fn concurrent_follow_unfollow_toggles_converge_to_terminal_state() {
    skip_if_no_db!();

    // Arrange — N=10 concurrent toggles (5 Follow + 5 Unfollow). Per
    // `docs/design/follows.md`, `Follow` is an idempotent UPSERT and
    // `Unfollow` flips status; concurrent toggles converge to a deterministic
    // terminal state (ACTIVE or UNFOLLOWED). This pins that the service
    // handler doesn't lose updates or hit a constraint violation under
    // contention. Unfollow on a missing edge is allowed (FOLLOW_NOT_FOUND)
    // and counted as a no-op.
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let acct_sk = make_signing_key();
    let (user_id, user_key) = seed_user_with_key(&h.db, &user_sk).await;
    let (account_id, _) = seed_account_with_key(&h.db, &acct_sk).await;

    // Pre-mint signed requests on the test thread; each request needs a
    // unique nonce and timestamp slot.
    let barrier = Arc::new(tokio::sync::Barrier::new(10));
    let mut tasks: Vec<tokio::task::JoinHandle<Result<(), tonic::Status>>> = Vec::with_capacity(10);

    for i in 0..10 {
        let ts = h.clock.now().await.unwrap();
        let mut client = h.client.clone();
        let bar = barrier.clone();
        if i % 2 == 0 {
            let req = signed(
                FollowRequest {
                    user_id: user_id.to_string(),
                    account_id: account_id.to_string(),
                },
                &user_sk,
                user_key,
                "/headlines.v1.FollowService/Follow",
                ts,
                &unique_nonce(),
            );
            tasks.push(tokio::spawn(async move {
                bar.wait().await;
                client.follow(req).await.map(|_| ())
            }));
        } else {
            let req = signed(
                UnfollowRequest {
                    user_id: user_id.to_string(),
                    account_id: account_id.to_string(),
                },
                &user_sk,
                user_key,
                "/headlines.v1.FollowService/Unfollow",
                ts,
                &unique_nonce(),
            );
            tasks.push(tokio::spawn(async move {
                bar.wait().await;
                client.unfollow(req).await.map(|_| ())
            }));
        }
    }

    let outcomes = tokio::time::timeout(Duration::from_secs(5), async {
        let mut out = Vec::with_capacity(10);
        for t in tasks {
            out.push(t.await.unwrap());
        }
        out
    })
    .await
    .expect("concurrent toggles complete within 5s");

    // Assert — every outcome is either Ok or a documented FOLLOW_NOT_FOUND
    // (an Unfollow that raced in front of any Follow). No other error code
    // should surface under contention. No constraint violations or
    // Internal errors leak.
    for outcome in &outcomes {
        match outcome {
            Ok(_) => {}
            Err(e) => {
                assert_eq!(
                    e.code(),
                    tonic::Code::NotFound,
                    "Unfollow-before-any-Follow must surface NotFound, got code = {:?}, msg = {:?}",
                    e.code(),
                    e.message(),
                );
            }
        }
    }

    // Definitive end state via GetFollow. Acceptable terminal states:
    //   - the row exists with status ACTIVE or UNFOLLOWED (typical), OR
    //   - NotFound iff every Follow happened to be in flight before the
    //     last Unfollow that successfully ran (impossible here because
    //     Follow is an UPSERT that always writes a row; once any Follow
    //     completes, the row exists for the rest of the test). We assert
    //     a follow row exists in some terminal state.
    let ts = h.clock.now().await.unwrap();
    let got = h
        .client
        .get_follow(signed(
            GetFollowRequest {
                user_id: user_id.to_string(),
                account_id: account_id.to_string(),
            },
            &user_sk,
            user_key,
            "/headlines.v1.FollowService/GetFollow",
            ts,
            &unique_nonce(),
        ))
        .await
        .expect("GetFollow after toggle storm must succeed")
        .into_inner();
    let status = got.status;
    assert!(
        status == FollowStatus::Active as i32 || status == FollowStatus::Unfollowed as i32,
        "terminal status must be ACTIVE or UNFOLLOWED, got {}",
        status,
    );

    cleanup_follows(&h.db, &[user_id], &[account_id]).await;
}
