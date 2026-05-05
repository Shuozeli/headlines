//! End-to-end integration tests for `FeedFollowService`, exercised through a
//! real tonic in-process server (random TCP port) backed by Postgres on
//! `docker.yuacx.com`. Mirrors `tests/feeds_recommendation.rs`.
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

use headlines_api::FeedFollowServiceImpl;
use headlines_auth::{
    AlgorithmRegistry, AuthInterceptor, AuthorizationLayer, Ed25519, InMemoryNonceStore,
    LocalClock, PostgresKeyResolver, ProtoBodyHasher, SignedRequestStrategy,
};
use headlines_core::{TimeSource as _, Tso};
use headlines_proto::v1::{
    GetFollowFeedRequest, feed_follow_service_client::FeedFollowServiceClient,
    feed_follow_service_server::FeedFollowServiceServer,
};
use headlines_store::{Db, PgFeedFollowRepo, PgUserRepo};

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

struct Harness {
    db: Db,
    client: FeedFollowServiceClient<Channel>,
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
    let feeds = Arc::new(PgFeedFollowRepo::new(db.clone()));

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

    let svc = FeedFollowServiceImpl::new(users, feeds);

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
        .add_service(FeedFollowServiceServer::new(svc));

    tokio::spawn(async move {
        let _ = server.serve_with_incoming(stream).await;
    });

    let endpoint = Endpoint::from_shared(format!("http://{addr}"))
        .expect("endpoint")
        .connect_timeout(Duration::from_secs(5));
    let channel = endpoint.connect().await.expect("client connect");
    let client = FeedFollowServiceClient::new(channel);

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
// DB cleanup / seeding helpers
// ---------------------------------------------------------------------------

async fn cleanup(db: &Db, user_ids: &[Uuid], account_ids: &[Uuid], article_ids: &[Uuid]) {
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

/// Stamp `articles.created_at` to a known point so order-by tests are
/// deterministic. UUIDv7 ordering and `now()` ordering can drift on a busy
/// box; pinning lets us assert exact descending order.
async fn set_article_created_at(db: &Db, article_id: Uuid, ts_iso: &str) {
    let mut conn = db.get().await.unwrap();
    diesel::sql_query("UPDATE articles SET created_at = $1::timestamptz WHERE id = $2")
        .bind::<diesel::sql_types::Text, _>(ts_iso)
        .bind::<diesel::sql_types::Uuid, _>(article_id)
        .execute(&mut conn)
        .await
        .unwrap();
}

/// Seed an active follow edge for `(user, account)`.
async fn seed_active_follow(db: &Db, user_id: Uuid, account_id: Uuid) {
    let mut conn = db.get().await.unwrap();
    diesel::sql_query(
        "INSERT INTO follows (user_id, account_id, status, created_at) \
         VALUES ($1, $2, 'active', now())",
    )
    .bind::<diesel::sql_types::Uuid, _>(user_id)
    .bind::<diesel::sql_types::Uuid, _>(account_id)
    .execute(&mut conn)
    .await
    .unwrap();
}

/// Seed an unfollowed edge for `(user, account)` directly.
async fn seed_unfollowed_follow(db: &Db, user_id: Uuid, account_id: Uuid) {
    let mut conn = db.get().await.unwrap();
    diesel::sql_query(
        "INSERT INTO follows (user_id, account_id, status, created_at, unfollowed_at) \
         VALUES ($1, $2, 'unfollowed', now(), now())",
    )
    .bind::<diesel::sql_types::Uuid, _>(user_id)
    .bind::<diesel::sql_types::Uuid, _>(account_id)
    .execute(&mut conn)
    .await
    .unwrap();
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

async fn redact_article_v1(db: &Db, article_id: Uuid) {
    let mut conn = db.get().await.unwrap();
    diesel::sql_query(
        "UPDATE article_versions SET content = NULL, redacted_at = now(), \
         redaction_reason = 'test' WHERE article_id = $1 AND version = 1",
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

const RPC_GET: &str = "/headlines.v1.FeedFollowService/GetFollowFeed";

// ===========================================================================
// GetFollowFeed
// ===========================================================================

#[tokio::test]
async fn user_self_get_returns_only_followed_accounts_articles() {
    skip_if_no_db!();

    // Arrange — user follows account A, not B. Both have one live article.
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let (user_id, user_key) = seed_user_with_key(&h.db, &user_sk).await;
    let account_a = seed_account(&h.db).await;
    let account_b = seed_account(&h.db).await;
    let a1 = seed_live_article(&h.db, account_a).await;
    let b1 = seed_live_article(&h.db, account_b).await;
    seed_active_follow(&h.db, user_id, account_a).await;

    let req = GetFollowFeedRequest {
        user_id: user_id.to_string(),
        page_size: 50,
        page_token: String::new(),
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let resp = h
        .client
        .get_follow_feed(signed(
            req,
            &user_sk,
            user_key,
            RPC_GET,
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();

    // Assert — only `a1` is present; `b1` (from unfollowed account_b) is
    // filtered out by the JOIN.
    assert_eq!(resp.items.len(), 1);
    assert_eq!(resp.items[0].article.as_ref().unwrap().id, a1.to_string());

    cleanup(&h.db, &[user_id], &[account_a, account_b], &[a1, b1]).await;
}

#[tokio::test]
async fn get_orders_articles_by_created_at_desc() {
    skip_if_no_db!();

    // Arrange — three articles in one followed account, distinct `created_at`.
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let (user_id, user_key) = seed_user_with_key(&h.db, &user_sk).await;
    let account_id = seed_account(&h.db).await;
    let a1 = seed_live_article(&h.db, account_id).await;
    let a2 = seed_live_article(&h.db, account_id).await;
    let a3 = seed_live_article(&h.db, account_id).await;

    // Pin distinct timestamps so the assertion is deterministic. Newest first.
    set_article_created_at(&h.db, a1, "2024-01-01T00:00:00Z").await;
    set_article_created_at(&h.db, a2, "2024-01-02T00:00:00Z").await;
    set_article_created_at(&h.db, a3, "2024-01-03T00:00:00Z").await;

    seed_active_follow(&h.db, user_id, account_id).await;

    let req = GetFollowFeedRequest {
        user_id: user_id.to_string(),
        page_size: 50,
        page_token: String::new(),
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let resp = h
        .client
        .get_follow_feed(signed(
            req,
            &user_sk,
            user_key,
            RPC_GET,
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();

    // Assert — descending by created_at: a3, a2, a1.
    assert_eq!(resp.items.len(), 3);
    let ids: Vec<String> = resp
        .items
        .iter()
        .map(|i| i.article.as_ref().unwrap().id.clone())
        .collect();
    assert_eq!(ids, vec![a3.to_string(), a2.to_string(), a1.to_string()]);

    cleanup(&h.db, &[user_id], &[account_id], &[a1, a2, a3]).await;
}

#[tokio::test]
async fn get_excludes_tombstoned_articles() {
    skip_if_no_db!();

    // Arrange — two live articles in followed account; tombstone one.
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let (user_id, user_key) = seed_user_with_key(&h.db, &user_sk).await;
    let account_id = seed_account(&h.db).await;
    let a1 = seed_live_article(&h.db, account_id).await;
    let a2 = seed_live_article(&h.db, account_id).await;
    seed_active_follow(&h.db, user_id, account_id).await;
    tombstone_article_directly(&h.db, a2).await;

    let req = GetFollowFeedRequest {
        user_id: user_id.to_string(),
        page_size: 50,
        page_token: String::new(),
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let resp = h
        .client
        .get_follow_feed(signed(
            req,
            &user_sk,
            user_key,
            RPC_GET,
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();

    // Assert — only the live article remains; the tombstoned row is dropped
    // by the inner join against `articles_live`.
    assert_eq!(resp.items.len(), 1);
    assert_eq!(resp.items[0].article.as_ref().unwrap().id, a1.to_string());

    cleanup(&h.db, &[user_id], &[account_id], &[a1, a2]).await;
}

#[tokio::test]
async fn get_includes_articles_from_deleted_accounts() {
    skip_if_no_db!();

    // Arrange — followed account is later soft-deleted; its live article must
    // still surface (per `feed-follow.md`).
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let (user_id, user_key) = seed_user_with_key(&h.db, &user_sk).await;
    let account_id = seed_account(&h.db).await;
    let a1 = seed_live_article(&h.db, account_id).await;
    seed_active_follow(&h.db, user_id, account_id).await;
    delete_account_directly(&h.db, account_id).await;

    let req = GetFollowFeedRequest {
        user_id: user_id.to_string(),
        page_size: 50,
        page_token: String::new(),
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let resp = h
        .client
        .get_follow_feed(signed(
            req,
            &user_sk,
            user_key,
            RPC_GET,
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();

    // Assert — article still present.
    assert_eq!(resp.items.len(), 1);
    assert_eq!(resp.items[0].article.as_ref().unwrap().id, a1.to_string());

    cleanup(&h.db, &[user_id], &[account_id], &[a1]).await;
}

#[tokio::test]
async fn get_excludes_unfollowed_edges() {
    skip_if_no_db!();

    // Arrange — user has an `unfollowed` row for account A; account A has a
    // live article. The article must NOT surface.
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let (user_id, user_key) = seed_user_with_key(&h.db, &user_sk).await;
    let account_a = seed_account(&h.db).await;
    let account_b = seed_account(&h.db).await;
    let a1 = seed_live_article(&h.db, account_a).await;
    let b1 = seed_live_article(&h.db, account_b).await;
    seed_unfollowed_follow(&h.db, user_id, account_a).await;
    seed_active_follow(&h.db, user_id, account_b).await;

    let req = GetFollowFeedRequest {
        user_id: user_id.to_string(),
        page_size: 50,
        page_token: String::new(),
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let resp = h
        .client
        .get_follow_feed(signed(
            req,
            &user_sk,
            user_key,
            RPC_GET,
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();

    // Assert — only b1 surfaces.
    assert_eq!(resp.items.len(), 1);
    assert_eq!(resp.items[0].article.as_ref().unwrap().id, b1.to_string());

    cleanup(&h.db, &[user_id], &[account_a, account_b], &[a1, b1]).await;
}

#[tokio::test]
async fn get_paginates_keyset_across_multiple_pages() {
    skip_if_no_db!();

    // Arrange — one followed account with five articles, all distinct
    // timestamps. Page size 2 → expect 3 pages (2 + 2 + 1).
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let (user_id, user_key) = seed_user_with_key(&h.db, &user_sk).await;
    let account_id = seed_account(&h.db).await;
    let a1 = seed_live_article(&h.db, account_id).await;
    let a2 = seed_live_article(&h.db, account_id).await;
    let a3 = seed_live_article(&h.db, account_id).await;
    let a4 = seed_live_article(&h.db, account_id).await;
    let a5 = seed_live_article(&h.db, account_id).await;
    set_article_created_at(&h.db, a1, "2024-02-01T00:00:00Z").await;
    set_article_created_at(&h.db, a2, "2024-02-02T00:00:00Z").await;
    set_article_created_at(&h.db, a3, "2024-02-03T00:00:00Z").await;
    set_article_created_at(&h.db, a4, "2024-02-04T00:00:00Z").await;
    set_article_created_at(&h.db, a5, "2024-02-05T00:00:00Z").await;
    seed_active_follow(&h.db, user_id, account_id).await;

    // Act — page 1.
    let ts = h.clock.now().await.unwrap();
    let page1 = h
        .client
        .get_follow_feed(signed(
            GetFollowFeedRequest {
                user_id: user_id.to_string(),
                page_size: 2,
                page_token: String::new(),
            },
            &user_sk,
            user_key,
            RPC_GET,
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();

    // Assert page 1 — newest two: a5, a4. Token present.
    assert_eq!(page1.items.len(), 2);
    assert_eq!(page1.items[0].article.as_ref().unwrap().id, a5.to_string());
    assert_eq!(page1.items[1].article.as_ref().unwrap().id, a4.to_string());
    assert!(!page1.next_page_token.is_empty());

    // Page 2.
    let ts = h.clock.now().await.unwrap();
    let page2 = h
        .client
        .get_follow_feed(signed(
            GetFollowFeedRequest {
                user_id: user_id.to_string(),
                page_size: 2,
                page_token: page1.next_page_token.clone(),
            },
            &user_sk,
            user_key,
            RPC_GET,
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();

    // Assert page 2 — a3, a2.
    assert_eq!(page2.items.len(), 2);
    assert_eq!(page2.items[0].article.as_ref().unwrap().id, a3.to_string());
    assert_eq!(page2.items[1].article.as_ref().unwrap().id, a2.to_string());
    assert!(!page2.next_page_token.is_empty());

    // Page 3 — a1 only, no further token.
    let ts = h.clock.now().await.unwrap();
    let page3 = h
        .client
        .get_follow_feed(signed(
            GetFollowFeedRequest {
                user_id: user_id.to_string(),
                page_size: 2,
                page_token: page2.next_page_token.clone(),
            },
            &user_sk,
            user_key,
            RPC_GET,
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(page3.items.len(), 1);
    assert_eq!(page3.items[0].article.as_ref().unwrap().id, a1.to_string());
    assert!(page3.next_page_token.is_empty());

    cleanup(&h.db, &[user_id], &[account_id], &[a1, a2, a3, a4, a5]).await;
}

#[tokio::test]
async fn get_on_deleted_user_is_user_deleted() {
    skip_if_no_db!();

    // Arrange — soft-delete the user; the user key is still active so the
    // auth interceptor lets the call through to the handler precondition.
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let (user_id, user_key) = seed_user_with_key(&h.db, &user_sk).await;
    delete_user_directly(&h.db, user_id).await;

    let req = GetFollowFeedRequest {
        user_id: user_id.to_string(),
        page_size: 50,
        page_token: String::new(),
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let err = h
        .client
        .get_follow_feed(signed(
            req,
            &user_sk,
            user_key,
            RPC_GET,
            ts,
            &unique_nonce(),
        ))
        .await
        .expect_err("get on deleted user must reject");

    // Assert — USER_DELETED → FAILED_PRECONDITION.
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);

    cleanup(&h.db, &[user_id], &[], &[]).await;
}

#[tokio::test]
async fn get_on_missing_user_is_user_not_found() {
    skip_if_no_db!();

    // Arrange — phantom user_id (system caller, since the user doesn't exist
    // there's no key to sign with).
    let mut h = spawn_server().await;
    let phantom = Uuid::now_v7();
    let sys_sk = make_signing_key();
    let (system_id, sys_key) =
        insert_system(&h.db, "feed-follow-reader", &["feeds.follow.read"], &sys_sk).await;

    let req = GetFollowFeedRequest {
        user_id: phantom.to_string(),
        page_size: 50,
        page_token: String::new(),
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let err = h
        .client
        .get_follow_feed(signed(req, &sys_sk, sys_key, RPC_GET, ts, &unique_nonce()))
        .await
        .expect_err("missing-user get must reject");

    // Assert
    assert_eq!(err.code(), tonic::Code::NotFound);

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
    seed_active_follow(&h.db, user_id, account_id).await;

    let reader_sk = make_signing_key();
    let (reader_id, reader_key) = insert_system(
        &h.db,
        "feed-follow-reader",
        &["feeds.follow.read"],
        &reader_sk,
    )
    .await;

    let req = GetFollowFeedRequest {
        user_id: user_id.to_string(),
        page_size: 50,
        page_token: String::new(),
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let resp = h
        .client
        .get_follow_feed(signed(
            req,
            &reader_sk,
            reader_key,
            RPC_GET,
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();

    // Assert
    assert_eq!(resp.items.len(), 1);
    assert_eq!(resp.items[0].article.as_ref().unwrap().id, a1.to_string());

    cleanup(&h.db, &[user_id], &[account_id], &[a1]).await;
    cleanup_system(&h.db, reader_id).await;
}

#[tokio::test]
async fn cross_user_get_is_user_not_found() {
    skip_if_no_db!();

    // Arrange — caller_a (user A) tries to read user_b's feed.
    let mut h = spawn_server().await;
    let sk_a = make_signing_key();
    let (user_a, key_a) = seed_user_with_key(&h.db, &sk_a).await;
    let sk_b = make_signing_key();
    let (user_b, _) = seed_user_with_key(&h.db, &sk_b).await;

    let req = GetFollowFeedRequest {
        user_id: user_b.to_string(),
        page_size: 50,
        page_token: String::new(),
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let err = h
        .client
        .get_follow_feed(signed(req, &sk_a, key_a, RPC_GET, ts, &unique_nonce()))
        .await
        .expect_err("cross-user get must reject");

    // Assert — privacy: surface as USER_NOT_FOUND, not PERMISSION_DENIED.
    assert_eq!(err.code(), tonic::Code::NotFound);

    cleanup(&h.db, &[user_a, user_b], &[], &[]).await;
}

#[tokio::test]
async fn redacted_current_version_surfaces_with_redacted_true() {
    skip_if_no_db!();

    // Arrange — followed account, single live article whose v1 was redacted.
    let mut h = spawn_server().await;
    let user_sk = make_signing_key();
    let (user_id, user_key) = seed_user_with_key(&h.db, &user_sk).await;
    let account_id = seed_account(&h.db).await;
    let a1 = seed_live_article(&h.db, account_id).await;
    seed_active_follow(&h.db, user_id, account_id).await;
    redact_article_v1(&h.db, a1).await;

    let req = GetFollowFeedRequest {
        user_id: user_id.to_string(),
        page_size: 50,
        page_token: String::new(),
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let resp = h
        .client
        .get_follow_feed(signed(
            req,
            &user_sk,
            user_key,
            RPC_GET,
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();

    // Assert — `redacted=true` reaches the wire on the live summary.
    assert_eq!(resp.items.len(), 1);
    let summary = resp.items[0].article.as_ref().unwrap();
    let live = match summary.state_data.as_ref().unwrap() {
        headlines_proto::v1::article_summary::StateData::Live(l) => l,
        _ => panic!("expected live state_data"),
    };
    assert!(live.redacted);

    cleanup(&h.db, &[user_id], &[account_id], &[a1]).await;
}
