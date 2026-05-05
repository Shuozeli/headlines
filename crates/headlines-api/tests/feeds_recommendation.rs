//! End-to-end integration tests for `FeedRecommendationService`, exercised
//! through a real tonic in-process server (random TCP port) backed by Postgres
//! on `docker.yuacx.com`. Mirrors `tests/follows.rs`.
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

use headlines_api::FeedRecommendationServiceImpl;
use headlines_auth::{
    AlgorithmRegistry, AuthInterceptor, AuthorizationLayer, Ed25519, InMemoryNonceStore,
    LocalClock, PostgresKeyResolver, ProtoBodyHasher, SignedRequestStrategy,
};
use headlines_core::{TimeSource as _, Tso};
use headlines_proto::v1::{
    GetRecommendationFeedRequest, ReplaceRecommendationFeedRequest,
    feed_recommendation_service_client::FeedRecommendationServiceClient,
    feed_recommendation_service_server::FeedRecommendationServiceServer,
};
use headlines_store::{Db, PgFeedRecommendationRepo, PgUserRepo};

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

const TEST_REPLACE_CAP: usize = 3;

struct Harness {
    db: Db,
    client: FeedRecommendationServiceClient<Channel>,
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
    let feeds = Arc::new(PgFeedRecommendationRepo::new(db.clone()));

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

    // Use a small replace cap (3) so the FEED_TOO_LARGE test only needs to
    // push 4 items rather than 5001.
    let svc = FeedRecommendationServiceImpl::new(users, feeds, TEST_REPLACE_CAP);

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
        .add_service(FeedRecommendationServiceServer::new(svc));

    tokio::spawn(async move {
        let _ = server.serve_with_incoming(stream).await;
    });

    let endpoint = Endpoint::from_shared(format!("http://{addr}"))
        .expect("endpoint")
        .connect_timeout(Duration::from_secs(5));
    let channel = endpoint.connect().await.expect("client connect");
    let client = FeedRecommendationServiceClient::new(channel);

    Harness {
        db,
        client,
        clock,
        _addr: addr,
    }
}

// ---------------------------------------------------------------------------
// Signing helpers (mirrors tests/follows.rs)
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

async fn cleanup_feed(db: &Db, user_ids: &[Uuid], account_ids: &[Uuid], article_ids: &[Uuid]) {
    let url = db.database_url().to_owned();
    let users = user_ids.to_owned();
    let accounts = account_ids.to_owned();
    let articles = article_ids.to_owned();
    let _ = tokio::spawn(async move {
        let mut conn = match AsyncPgConnection::establish(&url).await {
            Ok(c) => c,
            Err(_) => return,
        };
        if !users.is_empty() {
            let _ = diesel::sql_query("DELETE FROM feed_recommendation WHERE user_id = ANY($1)")
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
        if !articles.is_empty() {
            let _ = diesel::sql_query("DELETE FROM article_versions WHERE article_id = ANY($1)")
                .bind::<diesel::sql_types::Array<diesel::sql_types::Uuid>, _>(articles.clone())
                .execute(&mut conn)
                .await;
            let _ = diesel::sql_query("DELETE FROM articles_live WHERE article_id = ANY($1)")
                .bind::<diesel::sql_types::Array<diesel::sql_types::Uuid>, _>(articles.clone())
                .execute(&mut conn)
                .await;
            let _ = diesel::sql_query("DELETE FROM articles_tombstone WHERE article_id = ANY($1)")
                .bind::<diesel::sql_types::Array<diesel::sql_types::Uuid>, _>(articles.clone())
                .execute(&mut conn)
                .await;
            let _ = diesel::sql_query("DELETE FROM articles WHERE id = ANY($1)")
                .bind::<diesel::sql_types::Array<diesel::sql_types::Uuid>, _>(articles)
                .execute(&mut conn)
                .await;
        }
        if !accounts.is_empty() {
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

async fn seed_account(db: &Db) -> Uuid {
    let mut conn = db.get().await.unwrap();
    let account_id = Uuid::now_v7();
    diesel::sql_query(
        "INSERT INTO accounts (id, short_name, author_name, status) \
         VALUES ($1, $2, 'Test Author', 'active')",
    )
    .bind::<diesel::sql_types::Uuid, _>(account_id)
    .bind::<diesel::sql_types::Text, _>(format!("test-{}", account_id.simple()))
    .execute(&mut conn)
    .await
    .unwrap();
    account_id
}

/// Insert a live article directly (bypasses ArticleService) so the feed-read
/// JOIN succeeds. Returns the article id.
async fn seed_live_article(db: &Db, account_id: Uuid) -> Uuid {
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
    diesel::sql_query(
        "INSERT INTO article_versions (article_id, version, title, content) \
         VALUES ($1, 1, $2, '[]'::jsonb)",
    )
    .bind::<diesel::sql_types::Uuid, _>(article_id)
    .bind::<diesel::sql_types::Text, _>(format!("title-{}", article_id.simple()))
    .execute(&mut conn)
    .await
    .unwrap();
    article_id
}

/// Tombstone a previously-live article: delete from articles_live, insert
/// into articles_tombstone, flip articles.state. Mirrors what
/// `PgArticleRepo::tombstone` does.
async fn tombstone_article_directly(db: &Db, article_id: Uuid) {
    let mut conn = db.get().await.unwrap();
    diesel::sql_query("UPDATE articles SET state='tombstone' WHERE id = $1")
        .bind::<diesel::sql_types::Uuid, _>(article_id)
        .execute(&mut conn)
        .await
        .unwrap();
    diesel::sql_query("DELETE FROM articles_live WHERE article_id = $1")
        .bind::<diesel::sql_types::Uuid, _>(article_id)
        .execute(&mut conn)
        .await
        .unwrap();
    diesel::sql_query(
        "INSERT INTO articles_tombstone (article_id, reason, tombstoned_at) \
         VALUES ($1, 'test', now())",
    )
    .bind::<diesel::sql_types::Uuid, _>(article_id)
    .execute(&mut conn)
    .await
    .unwrap();
}

async fn delete_user_directly(db: &Db, user_id: Uuid) {
    let mut conn = db.get().await.unwrap();
    diesel::sql_query("UPDATE users SET status='deleted', deleted_at=now() WHERE id = $1")
        .bind::<diesel::sql_types::Uuid, _>(user_id)
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
// ReplaceRecommendationFeed
// ===========================================================================

#[tokio::test]
async fn replace_with_system_scope_succeeds_and_reports_stored_count() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let (user_id, _) = seed_user_with_key(&h.db, &user_sk).await;
    let account_id = seed_account(&h.db).await;
    let a1 = seed_live_article(&h.db, account_id).await;
    let a2 = seed_live_article(&h.db, account_id).await;

    let sys_sk = make_signing_key();
    let (system_id, sys_key) =
        insert_system(&h.db, "ranker", &["feeds.recommendation.write"], &sys_sk).await;

    let req = ReplaceRecommendationFeedRequest {
        user_id: user_id.to_string(),
        article_ids: vec![a1.to_string(), a2.to_string()],
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let resp = h
        .client
        .replace_recommendation_feed(signed(
            req,
            &sys_sk,
            sys_key,
            "/headlines.v1.FeedRecommendationService/ReplaceRecommendationFeed",
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();

    // Assert
    assert_eq!(resp.stored_count, 2);

    cleanup_feed(&h.db, &[user_id], &[account_id], &[a1, a2]).await;
    cleanup_system(&h.db, system_id).await;
}

#[tokio::test]
async fn replace_with_empty_article_ids_clears_feed() {
    skip_if_no_db!();

    // Arrange — seed a feed first, then call replace with [].
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let (user_id, _) = seed_user_with_key(&h.db, &user_sk).await;
    let account_id = seed_account(&h.db).await;
    let a1 = seed_live_article(&h.db, account_id).await;

    let sys_sk = make_signing_key();
    let (system_id, sys_key) = insert_system(
        &h.db,
        "ranker",
        &["feeds.recommendation.write", "feeds.recommendation.read"],
        &sys_sk,
    )
    .await;

    let ts = h.clock.now().await.unwrap();
    h.client
        .replace_recommendation_feed(signed(
            ReplaceRecommendationFeedRequest {
                user_id: user_id.to_string(),
                article_ids: vec![a1.to_string()],
            },
            &sys_sk,
            sys_key,
            "/headlines.v1.FeedRecommendationService/ReplaceRecommendationFeed",
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap();

    // Act — replace with empty set.
    let ts = h.clock.now().await.unwrap();
    let resp = h
        .client
        .replace_recommendation_feed(signed(
            ReplaceRecommendationFeedRequest {
                user_id: user_id.to_string(),
                article_ids: vec![],
            },
            &sys_sk,
            sys_key,
            "/headlines.v1.FeedRecommendationService/ReplaceRecommendationFeed",
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();

    // Assert — succeeds with stored_count=0; subsequent get returns no items.
    assert_eq!(resp.stored_count, 0);

    let ts = h.clock.now().await.unwrap();
    let get_resp = h
        .client
        .get_recommendation_feed(signed(
            GetRecommendationFeedRequest {
                user_id: user_id.to_string(),
                page_size: 50,
                page_token: String::new(),
            },
            &sys_sk,
            sys_key,
            "/headlines.v1.FeedRecommendationService/GetRecommendationFeed",
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(get_resp.items.is_empty());

    cleanup_feed(&h.db, &[user_id], &[account_id], &[a1]).await;
    cleanup_system(&h.db, system_id).await;
}

#[tokio::test]
async fn replace_as_user_self_is_permission_denied() {
    skip_if_no_db!();

    // Arrange — User signs the replace; per spec, write is system-only.
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let (user_id, user_key) = seed_user_with_key(&h.db, &user_sk).await;

    let req = ReplaceRecommendationFeedRequest {
        user_id: user_id.to_string(),
        article_ids: vec![],
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let err = h
        .client
        .replace_recommendation_feed(signed(
            req,
            &user_sk,
            user_key,
            "/headlines.v1.FeedRecommendationService/ReplaceRecommendationFeed",
            ts,
            &unique_nonce(),
        ))
        .await
        .expect_err("user-self replace must reject");

    // Assert — the proto AUTH_TABLE blocks non-system subjects, surfacing
    // PERMISSION_DENIED.
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    cleanup_feed(&h.db, &[user_id], &[], &[]).await;
}

#[tokio::test]
async fn replace_with_duplicate_article_ids_is_rejected() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let (user_id, _) = seed_user_with_key(&h.db, &user_sk).await;
    let account_id = seed_account(&h.db).await;
    let a1 = seed_live_article(&h.db, account_id).await;

    let sys_sk = make_signing_key();
    let (system_id, sys_key) =
        insert_system(&h.db, "ranker", &["feeds.recommendation.write"], &sys_sk).await;

    let req = ReplaceRecommendationFeedRequest {
        user_id: user_id.to_string(),
        article_ids: vec![a1.to_string(), a1.to_string()],
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let err = h
        .client
        .replace_recommendation_feed(signed(
            req,
            &sys_sk,
            sys_key,
            "/headlines.v1.FeedRecommendationService/ReplaceRecommendationFeed",
            ts,
            &unique_nonce(),
        ))
        .await
        .expect_err("duplicate article_ids must reject");

    // Assert — DUPLICATE_ARTICLE_ID maps to INVALID_ARGUMENT.
    assert_eq!(err.code(), tonic::Code::InvalidArgument);

    cleanup_feed(&h.db, &[user_id], &[account_id], &[a1]).await;
    cleanup_system(&h.db, system_id).await;
}

#[tokio::test]
async fn replace_over_cap_is_feed_too_large() {
    skip_if_no_db!();

    // Arrange — TEST_REPLACE_CAP=3, so pushing 4 ids must reject.
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let (user_id, _) = seed_user_with_key(&h.db, &user_sk).await;

    let sys_sk = make_signing_key();
    let (system_id, sys_key) =
        insert_system(&h.db, "ranker", &["feeds.recommendation.write"], &sys_sk).await;

    let mut ids = Vec::new();
    for _ in 0..(TEST_REPLACE_CAP + 1) {
        ids.push(Uuid::now_v7().to_string());
    }
    let req = ReplaceRecommendationFeedRequest {
        user_id: user_id.to_string(),
        article_ids: ids,
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let err = h
        .client
        .replace_recommendation_feed(signed(
            req,
            &sys_sk,
            sys_key,
            "/headlines.v1.FeedRecommendationService/ReplaceRecommendationFeed",
            ts,
            &unique_nonce(),
        ))
        .await
        .expect_err("over-cap replace must reject");

    // Assert — FEED_TOO_LARGE → RESOURCE_EXHAUSTED.
    assert_eq!(err.code(), tonic::Code::ResourceExhausted);

    cleanup_feed(&h.db, &[user_id], &[], &[]).await;
    cleanup_system(&h.db, system_id).await;
}

#[tokio::test]
async fn replace_on_deleted_user_is_user_deleted() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let (user_id, _) = seed_user_with_key(&h.db, &user_sk).await;
    delete_user_directly(&h.db, user_id).await;

    let sys_sk = make_signing_key();
    let (system_id, sys_key) =
        insert_system(&h.db, "ranker", &["feeds.recommendation.write"], &sys_sk).await;

    let req = ReplaceRecommendationFeedRequest {
        user_id: user_id.to_string(),
        article_ids: vec![],
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let err = h
        .client
        .replace_recommendation_feed(signed(
            req,
            &sys_sk,
            sys_key,
            "/headlines.v1.FeedRecommendationService/ReplaceRecommendationFeed",
            ts,
            &unique_nonce(),
        ))
        .await
        .expect_err("replace on deleted user must reject");

    // Assert — USER_DELETED → FAILED_PRECONDITION.
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);

    cleanup_feed(&h.db, &[user_id], &[], &[]).await;
    cleanup_system(&h.db, system_id).await;
}

#[tokio::test]
async fn replace_on_missing_user_is_user_not_found() {
    skip_if_no_db!();

    // Arrange — phantom user_id.
    let mut h = spawn_server().await;
    let phantom = Uuid::now_v7();
    let sys_sk = make_signing_key();
    let (system_id, sys_key) =
        insert_system(&h.db, "ranker", &["feeds.recommendation.write"], &sys_sk).await;

    let req = ReplaceRecommendationFeedRequest {
        user_id: phantom.to_string(),
        article_ids: vec![],
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let err = h
        .client
        .replace_recommendation_feed(signed(
            req,
            &sys_sk,
            sys_key,
            "/headlines.v1.FeedRecommendationService/ReplaceRecommendationFeed",
            ts,
            &unique_nonce(),
        ))
        .await
        .expect_err("missing-user replace must reject");

    // Assert
    assert_eq!(err.code(), tonic::Code::NotFound);

    cleanup_system(&h.db, system_id).await;
}

// ===========================================================================
// GetRecommendationFeed
// ===========================================================================

#[tokio::test]
async fn user_self_get_returns_pushed_items() {
    skip_if_no_db!();

    // Arrange — system pushes a feed; user reads.
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let (user_id, user_key) = seed_user_with_key(&h.db, &user_sk).await;
    let account_id = seed_account(&h.db).await;
    let a1 = seed_live_article(&h.db, account_id).await;
    let a2 = seed_live_article(&h.db, account_id).await;

    let sys_sk = make_signing_key();
    let (system_id, sys_key) =
        insert_system(&h.db, "ranker", &["feeds.recommendation.write"], &sys_sk).await;

    let ts = h.clock.now().await.unwrap();
    h.client
        .replace_recommendation_feed(signed(
            ReplaceRecommendationFeedRequest {
                user_id: user_id.to_string(),
                article_ids: vec![a1.to_string(), a2.to_string()],
            },
            &sys_sk,
            sys_key,
            "/headlines.v1.FeedRecommendationService/ReplaceRecommendationFeed",
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap();

    // Act — user-self read.
    let ts = h.clock.now().await.unwrap();
    let resp = h
        .client
        .get_recommendation_feed(signed(
            GetRecommendationFeedRequest {
                user_id: user_id.to_string(),
                page_size: 50,
                page_token: String::new(),
            },
            &user_sk,
            user_key,
            "/headlines.v1.FeedRecommendationService/GetRecommendationFeed",
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();

    // Assert — both items present, ordered by position 0..1.
    assert_eq!(resp.items.len(), 2);
    assert_eq!(resp.items[0].position, 0);
    assert_eq!(resp.items[0].article.as_ref().unwrap().id, a1.to_string());
    assert_eq!(resp.items[1].position, 1);
    assert_eq!(resp.items[1].article.as_ref().unwrap().id, a2.to_string());
    assert!(resp.next_page_token.is_empty());

    cleanup_feed(&h.db, &[user_id], &[account_id], &[a1, a2]).await;
    cleanup_system(&h.db, system_id).await;
}

#[tokio::test]
async fn system_with_read_scope_can_get_any_users_feed() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let (user_id, _) = seed_user_with_key(&h.db, &user_sk).await;
    let account_id = seed_account(&h.db).await;
    let a1 = seed_live_article(&h.db, account_id).await;

    let writer_sk = make_signing_key();
    let (writer_id, writer_key) =
        insert_system(&h.db, "ranker", &["feeds.recommendation.write"], &writer_sk).await;
    let reader_sk = make_signing_key();
    let (reader_id, reader_key) = insert_system(
        &h.db,
        "feed-reader",
        &["feeds.recommendation.read"],
        &reader_sk,
    )
    .await;

    let ts = h.clock.now().await.unwrap();
    h.client
        .replace_recommendation_feed(signed(
            ReplaceRecommendationFeedRequest {
                user_id: user_id.to_string(),
                article_ids: vec![a1.to_string()],
            },
            &writer_sk,
            writer_key,
            "/headlines.v1.FeedRecommendationService/ReplaceRecommendationFeed",
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap();

    // Act — read as system.
    let ts = h.clock.now().await.unwrap();
    let resp = h
        .client
        .get_recommendation_feed(signed(
            GetRecommendationFeedRequest {
                user_id: user_id.to_string(),
                page_size: 50,
                page_token: String::new(),
            },
            &reader_sk,
            reader_key,
            "/headlines.v1.FeedRecommendationService/GetRecommendationFeed",
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();

    // Assert
    assert_eq!(resp.items.len(), 1);

    cleanup_feed(&h.db, &[user_id], &[account_id], &[a1]).await;
    cleanup_system(&h.db, writer_id).await;
    cleanup_system(&h.db, reader_id).await;
}

#[tokio::test]
async fn get_skips_tombstoned_articles() {
    skip_if_no_db!();

    // Arrange — push 3, tombstone the middle one, expect 2 returned.
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let (user_id, user_key) = seed_user_with_key(&h.db, &user_sk).await;
    let account_id = seed_account(&h.db).await;
    let a1 = seed_live_article(&h.db, account_id).await;
    let a2 = seed_live_article(&h.db, account_id).await;
    let a3 = seed_live_article(&h.db, account_id).await;

    let sys_sk = make_signing_key();
    let (system_id, sys_key) =
        insert_system(&h.db, "ranker", &["feeds.recommendation.write"], &sys_sk).await;

    let ts = h.clock.now().await.unwrap();
    h.client
        .replace_recommendation_feed(signed(
            ReplaceRecommendationFeedRequest {
                user_id: user_id.to_string(),
                article_ids: vec![a1.to_string(), a2.to_string(), a3.to_string()],
            },
            &sys_sk,
            sys_key,
            "/headlines.v1.FeedRecommendationService/ReplaceRecommendationFeed",
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap();

    tombstone_article_directly(&h.db, a2).await;

    // Act
    let ts = h.clock.now().await.unwrap();
    let resp = h
        .client
        .get_recommendation_feed(signed(
            GetRecommendationFeedRequest {
                user_id: user_id.to_string(),
                page_size: 50,
                page_token: String::new(),
            },
            &user_sk,
            user_key,
            "/headlines.v1.FeedRecommendationService/GetRecommendationFeed",
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();

    // Assert — only a1 (pos 0) and a3 (pos 2) survive the inner join.
    assert_eq!(resp.items.len(), 2);
    let returned_ids: Vec<String> = resp
        .items
        .iter()
        .map(|i| i.article.as_ref().unwrap().id.clone())
        .collect();
    assert!(returned_ids.contains(&a1.to_string()));
    assert!(returned_ids.contains(&a3.to_string()));
    assert!(!returned_ids.contains(&a2.to_string()));

    cleanup_feed(&h.db, &[user_id], &[account_id], &[a1, a2, a3]).await;
    cleanup_system(&h.db, system_id).await;
}

#[tokio::test]
async fn get_skips_articles_that_dont_exist() {
    skip_if_no_db!();

    // Arrange — push 2 ids, only one of which has a real `articles` row.
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let (user_id, user_key) = seed_user_with_key(&h.db, &user_sk).await;
    let account_id = seed_account(&h.db).await;
    let a1 = seed_live_article(&h.db, account_id).await;
    let phantom = Uuid::now_v7();

    let sys_sk = make_signing_key();
    let (system_id, sys_key) =
        insert_system(&h.db, "ranker", &["feeds.recommendation.write"], &sys_sk).await;

    let ts = h.clock.now().await.unwrap();
    h.client
        .replace_recommendation_feed(signed(
            ReplaceRecommendationFeedRequest {
                user_id: user_id.to_string(),
                article_ids: vec![phantom.to_string(), a1.to_string()],
            },
            &sys_sk,
            sys_key,
            "/headlines.v1.FeedRecommendationService/ReplaceRecommendationFeed",
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap();

    // Act
    let ts = h.clock.now().await.unwrap();
    let resp = h
        .client
        .get_recommendation_feed(signed(
            GetRecommendationFeedRequest {
                user_id: user_id.to_string(),
                page_size: 50,
                page_token: String::new(),
            },
            &user_sk,
            user_key,
            "/headlines.v1.FeedRecommendationService/GetRecommendationFeed",
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();

    // Assert — only the real article survives.
    assert_eq!(resp.items.len(), 1);
    assert_eq!(resp.items[0].article.as_ref().unwrap().id, a1.to_string());

    cleanup_feed(&h.db, &[user_id], &[account_id], &[a1]).await;
    cleanup_system(&h.db, system_id).await;
}

#[tokio::test]
async fn get_paginates_across_multiple_pages() {
    skip_if_no_db!();

    // Arrange — push 5 articles, page_size=2.
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let (user_id, user_key) = seed_user_with_key(&h.db, &user_sk).await;
    let account_id = seed_account(&h.db).await;
    let mut articles = Vec::new();
    for _ in 0..5 {
        articles.push(seed_live_article(&h.db, account_id).await);
    }

    let sys_sk = make_signing_key();
    let (system_id, sys_key) =
        insert_system(&h.db, "ranker", &["feeds.recommendation.write"], &sys_sk).await;

    let ts = h.clock.now().await.unwrap();
    let article_ids_str: Vec<String> = articles.iter().map(|a| a.to_string()).collect();
    // The configured TEST_REPLACE_CAP is 3, but the test needs 5 ids. We
    // use 3 here and exercise pagination across the 3 stored items with
    // page_size=2 (page1=2, page2=1).
    let push_count = TEST_REPLACE_CAP;
    h.client
        .replace_recommendation_feed(signed(
            ReplaceRecommendationFeedRequest {
                user_id: user_id.to_string(),
                article_ids: article_ids_str[..push_count].to_vec(),
            },
            &sys_sk,
            sys_key,
            "/headlines.v1.FeedRecommendationService/ReplaceRecommendationFeed",
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap();

    // Act — first page.
    let ts = h.clock.now().await.unwrap();
    let page1 = h
        .client
        .get_recommendation_feed(signed(
            GetRecommendationFeedRequest {
                user_id: user_id.to_string(),
                page_size: 2,
                page_token: String::new(),
            },
            &user_sk,
            user_key,
            "/headlines.v1.FeedRecommendationService/GetRecommendationFeed",
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();

    // Assert page1 — 2 items, non-empty next token (3 stored, page_size=2).
    assert_eq!(page1.items.len(), 2);
    assert!(!page1.next_page_token.is_empty());

    // Second page.
    let ts = h.clock.now().await.unwrap();
    let page2 = h
        .client
        .get_recommendation_feed(signed(
            GetRecommendationFeedRequest {
                user_id: user_id.to_string(),
                page_size: 2,
                page_token: page1.next_page_token.clone(),
            },
            &user_sk,
            user_key,
            "/headlines.v1.FeedRecommendationService/GetRecommendationFeed",
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();

    // Assert page2 — last item, no further token. AIP-158 allows fewer than
    // page_size on the final page.
    assert_eq!(page2.items.len(), 1);
    assert!(page2.next_page_token.is_empty());

    cleanup_feed(&h.db, &[user_id], &[account_id], &articles).await;
    cleanup_system(&h.db, system_id).await;
}

#[tokio::test]
async fn get_on_deleted_user_is_user_deleted() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let (user_id, user_key) = seed_user_with_key(&h.db, &user_sk).await;
    delete_user_directly(&h.db, user_id).await;

    let req = GetRecommendationFeedRequest {
        user_id: user_id.to_string(),
        page_size: 50,
        page_token: String::new(),
    };
    let ts = h.clock.now().await.unwrap();

    // Act — sign as the (now deleted) user; the user key is still active so
    // the auth interceptor allows it through.
    let err = h
        .client
        .get_recommendation_feed(signed(
            req,
            &user_sk,
            user_key,
            "/headlines.v1.FeedRecommendationService/GetRecommendationFeed",
            ts,
            &unique_nonce(),
        ))
        .await
        .expect_err("get on deleted user must reject");

    // Assert — USER_DELETED → FAILED_PRECONDITION.
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);

    cleanup_feed(&h.db, &[user_id], &[], &[]).await;
}
