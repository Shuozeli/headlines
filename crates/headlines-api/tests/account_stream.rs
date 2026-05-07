//! End-to-end integration tests for `AccountStreamService`, exercised through
//! a real tonic in-process server (random TCP port) backed by Postgres on
//! `docker.yuacx.com`. Mirrors `tests/feeds_follow.rs`.
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

use headlines_api::AccountStreamServiceImpl;
use headlines_auth::{
    AlgorithmRegistry, AuthInterceptor, AuthorizationLayer, Ed25519, InMemoryNonceStore,
    LocalClock, PostgresKeyResolver, ProtoBodyHasher, SignedRequestStrategy,
};
use headlines_core::{TimeSource as _, Tso};
use headlines_proto::v1::{
    StreamAccountArticlesRequest, account_stream_service_client::AccountStreamServiceClient,
    account_stream_service_server::AccountStreamServiceServer,
};
use headlines_store::{Db, PgAccountRepo, PgAccountStreamRepo};

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

struct Harness {
    db: Db,
    client: AccountStreamServiceClient<Channel>,
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

    let accounts = Arc::new(PgAccountRepo::new(db.clone()));
    let stream = Arc::new(PgAccountStreamRepo::new(db.clone()));

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

    let svc = AccountStreamServiceImpl::new(accounts, stream);

    let interceptor = AuthInterceptor::new(strategy, Arc::new(ProtoBodyHasher));
    let authorize = AuthorizationLayer::new();

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    let listener = tokio::net::TcpListener::from_std(listener).unwrap();
    let stream_inc = tokio_stream::wrappers::TcpListenerStream::new(listener);

    let server = Server::builder()
        .layer(interceptor)
        .layer(authorize)
        .add_service(AccountStreamServiceServer::new(svc));

    tokio::spawn(async move {
        let _ = server.serve_with_incoming(stream_inc).await;
    });

    let endpoint = Endpoint::from_shared(format!("http://{addr}"))
        .expect("endpoint")
        .connect_timeout(Duration::from_secs(5));
    let channel = endpoint.connect().await.expect("client connect");
    let client = AccountStreamServiceClient::new(channel);

    Harness {
        db,
        client,
        clock,
        _addr: addr,
    }
}

// ---------------------------------------------------------------------------
// Signing helpers (mirrors tests/feeds_follow.rs)
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

/// Account-scoped key, used to test Account-self rejection.
async fn seed_account_key(db: &Db, account_id: Uuid, sk: &SigningKey) -> Uuid {
    let mut conn = db.get().await.unwrap();
    let key_id = Uuid::now_v7();
    let pk_b64 = B64.encode(sk.verifying_key().as_bytes());
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
    key_id
}

/// Insert a live article with explicit `published_at`/`updated_at` so the
/// stream's ASC `event_at` order can be asserted deterministically. UUIDv7
/// ordering and `now()` ordering can drift on a busy box; pinning matches
/// the discipline used in `tests/feeds_follow.rs`.
async fn seed_live_article_at(db: &Db, account_id: Uuid, ts_iso: &str) -> Uuid {
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
         VALUES ($1, 1, $2::timestamptz, $2::timestamptz)",
    )
    .bind::<diesel::sql_types::Uuid, _>(article_id)
    .bind::<diesel::sql_types::Text, _>(ts_iso)
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

/// Bump `articles_live.updated_at` to a known timestamp — simulates an edit
/// re-emitting on the stream with a new `event_at`.
async fn bump_article_updated_at(db: &Db, article_id: Uuid, ts_iso: &str) {
    let mut conn = db.get().await.unwrap();
    diesel::sql_query(
        "UPDATE articles_live SET updated_at = $1::timestamptz WHERE article_id = $2",
    )
    .bind::<diesel::sql_types::Text, _>(ts_iso)
    .bind::<diesel::sql_types::Uuid, _>(article_id)
    .execute(&mut conn)
    .await
    .unwrap();
}

/// Tombstone a previously-live article at a known timestamp. Mirrors what
/// `PgArticleRepo::tombstone` does, plus a custom `tombstoned_at`.
async fn tombstone_article_at(db: &Db, article_id: Uuid, reason: &str, ts_iso: &str) {
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
         VALUES ($1, $2, $3::timestamptz)",
    )
    .bind::<diesel::sql_types::Uuid, _>(article_id)
    .bind::<diesel::sql_types::Text, _>(reason)
    .bind::<diesel::sql_types::Text, _>(ts_iso)
    .execute(&mut conn)
    .await
    .unwrap();
}

/// Redact v1 of an article (current version). Bumps `articles_live.updated_at`
/// to mimic `RedactArticleVersion`'s behavior so the stream re-emits.
async fn redact_article_v1(db: &Db, article_id: Uuid, new_updated_at: &str) {
    let mut conn = db.get().await.unwrap();
    diesel::sql_query(
        "UPDATE article_versions SET content = NULL, redacted_at = now(), \
         redaction_reason = 'test' WHERE article_id = $1 AND version = 1",
    )
    .bind::<diesel::sql_types::Uuid, _>(article_id)
    .execute(&mut conn)
    .await
    .unwrap();
    diesel::sql_query(
        "UPDATE articles_live SET updated_at = $1::timestamptz WHERE article_id = $2",
    )
    .bind::<diesel::sql_types::Text, _>(new_updated_at)
    .bind::<diesel::sql_types::Uuid, _>(article_id)
    .execute(&mut conn)
    .await
    .unwrap();
}

/// Insert a draft (NOT in `articles`) — verifies drafts never surface.
async fn seed_draft(db: &Db, account_id: Uuid) -> Uuid {
    let mut conn = db.get().await.unwrap();
    let draft_id = Uuid::now_v7();
    diesel::sql_query(
        "INSERT INTO drafts (id, account_id, title, author_name, author_url, content) \
         VALUES ($1, $2, $3, '', '', '[]'::jsonb)",
    )
    .bind::<diesel::sql_types::Uuid, _>(draft_id)
    .bind::<diesel::sql_types::Uuid, _>(account_id)
    .bind::<diesel::sql_types::Text, _>(format!("draft-{}", draft_id.simple()))
    .execute(&mut conn)
    .await
    .unwrap();
    draft_id
}

async fn cleanup_drafts(db: &Db, draft_ids: &[Uuid]) {
    let url = db.database_url().to_owned();
    let drafts = draft_ids.to_owned();
    let _ = tokio::spawn(async move {
        let mut conn = match AsyncPgConnection::establish(&url).await {
            Ok(c) => c,
            Err(_) => return,
        };
        if !drafts.is_empty() {
            let _ = diesel::sql_query("DELETE FROM drafts WHERE id = ANY($1)")
                .bind::<diesel::sql_types::Array<diesel::sql_types::Uuid>, _>(drafts)
                .execute(&mut conn)
                .await;
        }
    })
    .await;
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

const RPC_STREAM: &str = "/headlines.v1.AccountStreamService/StreamAccountArticles";

// ===========================================================================
// StreamAccountArticles
// ===========================================================================

#[tokio::test]
async fn system_with_stream_scope_succeeds() {
    skip_if_no_db!();

    // Arrange — one account with one article and a system with `articles.stream`.
    let mut h = spawn_server().await;
    let account_id = seed_account(&h.db).await;
    let a1 = seed_live_article_at(&h.db, account_id, "2024-03-01T00:00:00Z").await;

    let sys_sk = make_signing_key();
    let (system_id, sys_key) =
        insert_system(&h.db, "stream-republisher", &["articles.stream"], &sys_sk).await;

    let req = StreamAccountArticlesRequest {
        account_id: account_id.to_string(),
        page_size: 50,
        page_token: String::new(),
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let resp = h
        .client
        .stream_account_articles(signed(
            req,
            &sys_sk,
            sys_key,
            RPC_STREAM,
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();

    // Assert
    assert_eq!(resp.items.len(), 1);
    assert_eq!(resp.items[0].article.as_ref().unwrap().id, a1.to_string());

    cleanup(&h.db, &[], &[account_id], &[a1]).await;
    cleanup_system(&h.db, system_id).await;
}

#[tokio::test]
async fn user_self_call_is_rejected() {
    skip_if_no_db!();

    // Arrange — User signs the call; per spec the surface is system-only.
    let mut h = spawn_server().await;
    let account_id = seed_account(&h.db).await;
    let user_sk = make_signing_key();
    let (user_id, user_key) = seed_user_with_key(&h.db, &user_sk).await;

    let req = StreamAccountArticlesRequest {
        account_id: account_id.to_string(),
        page_size: 50,
        page_token: String::new(),
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let err = h
        .client
        .stream_account_articles(signed(
            req,
            &user_sk,
            user_key,
            RPC_STREAM,
            ts,
            &unique_nonce(),
        ))
        .await
        .expect_err("user-self stream must reject");

    // Assert — proto AUTH_TABLE blocks non-system subjects.
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    cleanup(&h.db, &[user_id], &[account_id], &[]).await;
}

#[tokio::test]
async fn account_self_call_is_rejected() {
    skip_if_no_db!();

    // Arrange — the owning Account signs the call; still rejected.
    let mut h = spawn_server().await;
    let account_id = seed_account(&h.db).await;
    let acct_sk = make_signing_key();
    let acct_key = seed_account_key(&h.db, account_id, &acct_sk).await;

    let req = StreamAccountArticlesRequest {
        account_id: account_id.to_string(),
        page_size: 50,
        page_token: String::new(),
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let err = h
        .client
        .stream_account_articles(signed(
            req,
            &acct_sk,
            acct_key,
            RPC_STREAM,
            ts,
            &unique_nonce(),
        ))
        .await
        .expect_err("account-self stream must reject");

    // Assert
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    cleanup(&h.db, &[], &[account_id], &[]).await;
}

#[tokio::test]
async fn anonymous_call_is_rejected() {
    skip_if_no_db!();

    // Arrange — no Authorization header at all. The interceptor resolves the
    // request to `Subject::Anonymous` (no credential presented), and the
    // AuthorizationLayer rejects with PERMISSION_DENIED because Anonymous is
    // not in this RPC's `allowed` subject classes. UNAUTHENTICATED is reserved
    // for failed credentials (see `docs/design/auth.md` "Layer-vs-code
    // mapping").
    let mut h = spawn_server().await;
    let account_id = seed_account(&h.db).await;

    let req = tonic::Request::new(StreamAccountArticlesRequest {
        account_id: account_id.to_string(),
        page_size: 50,
        page_token: String::new(),
    });

    // Act
    let err = h
        .client
        .stream_account_articles(req)
        .await
        .expect_err("anonymous stream must reject");

    // Assert — pin PERMISSION_DENIED exactly (the AuthorizationLayer's
    // outcome for Anonymous).
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    cleanup(&h.db, &[], &[account_id], &[]).await;
}

#[tokio::test]
async fn malformed_authorization_returns_unauthenticated() {
    skip_if_no_db!();

    // Arrange — a non-empty but unparseable Authorization header. The
    // interceptor recognizes a presented credential (Authorization header
    // exists) and fails to parse it → UNAUTHENTICATED, *not*
    // PERMISSION_DENIED. This pins the layer-vs-code mapping in
    // `docs/design/auth.md`.
    let mut h = spawn_server().await;
    let account_id = seed_account(&h.db).await;

    let mut req = tonic::Request::new(StreamAccountArticlesRequest {
        account_id: account_id.to_string(),
        page_size: 50,
        page_token: String::new(),
    });
    req.metadata_mut()
        .insert("authorization", "Bearer not-our-format".parse().unwrap());

    // Act
    let err = h
        .client
        .stream_account_articles(req)
        .await
        .expect_err("malformed Authorization header must reject");

    // Assert — failed credential → UNAUTHENTICATED (not PERMISSION_DENIED).
    assert_eq!(err.code(), tonic::Code::Unauthenticated);

    cleanup(&h.db, &[], &[account_id], &[]).await;
}

#[tokio::test]
async fn stream_orders_articles_by_event_at_asc() {
    skip_if_no_db!();

    // Arrange — three articles in one account, distinct `published_at`/
    // `updated_at`. Publish order: a1 → a2 → a3. Expect ASC order on the stream.
    let mut h = spawn_server().await;
    let account_id = seed_account(&h.db).await;
    let a1 = seed_live_article_at(&h.db, account_id, "2024-04-01T00:00:00Z").await;
    let a2 = seed_live_article_at(&h.db, account_id, "2024-04-02T00:00:00Z").await;
    let a3 = seed_live_article_at(&h.db, account_id, "2024-04-03T00:00:00Z").await;

    let sys_sk = make_signing_key();
    let (system_id, sys_key) =
        insert_system(&h.db, "stream-r", &["articles.stream"], &sys_sk).await;

    let req = StreamAccountArticlesRequest {
        account_id: account_id.to_string(),
        page_size: 50,
        page_token: String::new(),
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let resp = h
        .client
        .stream_account_articles(signed(
            req,
            &sys_sk,
            sys_key,
            RPC_STREAM,
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();

    // Assert — ascending by event_at: a1, a2, a3.
    assert_eq!(resp.items.len(), 3);
    let ids: Vec<String> = resp
        .items
        .iter()
        .map(|i| i.article.as_ref().unwrap().id.clone())
        .collect();
    assert_eq!(ids, vec![a1.to_string(), a2.to_string(), a3.to_string()]);

    cleanup(&h.db, &[], &[account_id], &[a1, a2, a3]).await;
    cleanup_system(&h.db, system_id).await;
}

#[tokio::test]
async fn edited_article_re_emits_with_new_event_at() {
    skip_if_no_db!();

    // Arrange — a1 published at T0, a2 at T1, then a1 edited at T2. Expected
    // ASC order: a2, a1 (a1's new event_at is T2 > T1).
    let mut h = spawn_server().await;
    let account_id = seed_account(&h.db).await;
    let a1 = seed_live_article_at(&h.db, account_id, "2024-05-01T00:00:00Z").await;
    let a2 = seed_live_article_at(&h.db, account_id, "2024-05-02T00:00:00Z").await;
    bump_article_updated_at(&h.db, a1, "2024-05-03T00:00:00Z").await;

    let sys_sk = make_signing_key();
    let (system_id, sys_key) =
        insert_system(&h.db, "stream-r", &["articles.stream"], &sys_sk).await;

    let req = StreamAccountArticlesRequest {
        account_id: account_id.to_string(),
        page_size: 50,
        page_token: String::new(),
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let resp = h
        .client
        .stream_account_articles(signed(
            req,
            &sys_sk,
            sys_key,
            RPC_STREAM,
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();

    // Assert — a1 surfaces *after* a2 because its updated_at was bumped past
    // a2's published_at.
    assert_eq!(resp.items.len(), 2);
    let ids: Vec<String> = resp
        .items
        .iter()
        .map(|i| i.article.as_ref().unwrap().id.clone())
        .collect();
    assert_eq!(ids, vec![a2.to_string(), a1.to_string()]);

    cleanup(&h.db, &[], &[account_id], &[a1, a2]).await;
    cleanup_system(&h.db, system_id).await;
}

#[tokio::test]
async fn tombstoned_article_emits_with_tombstone_state() {
    skip_if_no_db!();

    // Arrange — publish then tombstone; the row surfaces with state=TOMBSTONE
    // and `event_at = tombstoned_at`.
    let mut h = spawn_server().await;
    let account_id = seed_account(&h.db).await;
    let a1 = seed_live_article_at(&h.db, account_id, "2024-06-01T00:00:00Z").await;
    tombstone_article_at(&h.db, a1, "dmca", "2024-06-02T00:00:00Z").await;

    let sys_sk = make_signing_key();
    let (system_id, sys_key) =
        insert_system(&h.db, "stream-r", &["articles.stream"], &sys_sk).await;

    let req = StreamAccountArticlesRequest {
        account_id: account_id.to_string(),
        page_size: 50,
        page_token: String::new(),
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let resp = h
        .client
        .stream_account_articles(signed(
            req,
            &sys_sk,
            sys_key,
            RPC_STREAM,
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();

    // Assert — single row, state=TOMBSTONE with reason carried.
    assert_eq!(resp.items.len(), 1);
    let summary = resp.items[0].article.as_ref().unwrap();
    assert_eq!(summary.id, a1.to_string());
    assert_eq!(
        summary.state,
        headlines_proto::v1::ArticleState::Tombstone as i32
    );
    let tomb = match summary.state_data.as_ref().unwrap() {
        headlines_proto::v1::article_summary::StateData::Tombstone(t) => t,
        _ => panic!("expected tombstone state_data"),
    };
    assert_eq!(tomb.reason, "dmca");

    cleanup(&h.db, &[], &[account_id], &[a1]).await;
    cleanup_system(&h.db, system_id).await;
}

#[tokio::test]
async fn redacted_current_version_surfaces_with_redacted_true() {
    skip_if_no_db!();

    // Arrange — publish, then redact v1 (current). The redact path bumps
    // `articles_live.updated_at` so the stream re-emits with `redacted=true`.
    // Verifies the 7.2 RedactArticleVersion `updated_at` bump reaches the
    // stream.
    let mut h = spawn_server().await;
    let account_id = seed_account(&h.db).await;
    let a1 = seed_live_article_at(&h.db, account_id, "2024-07-01T00:00:00Z").await;
    redact_article_v1(&h.db, a1, "2024-07-02T00:00:00Z").await;

    let sys_sk = make_signing_key();
    let (system_id, sys_key) =
        insert_system(&h.db, "stream-r", &["articles.stream"], &sys_sk).await;

    let req = StreamAccountArticlesRequest {
        account_id: account_id.to_string(),
        page_size: 50,
        page_token: String::new(),
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let resp = h
        .client
        .stream_account_articles(signed(
            req,
            &sys_sk,
            sys_key,
            RPC_STREAM,
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

    cleanup(&h.db, &[], &[account_id], &[a1]).await;
    cleanup_system(&h.db, system_id).await;
}

#[tokio::test]
async fn drafts_never_surface_on_stream() {
    skip_if_no_db!();

    // Arrange — one live article and one separate draft on the same account.
    // Only the live article should appear; drafts live in a different table
    // and never enter `articles`.
    let mut h = spawn_server().await;
    let account_id = seed_account(&h.db).await;
    let a1 = seed_live_article_at(&h.db, account_id, "2024-08-01T00:00:00Z").await;
    let d1 = seed_draft(&h.db, account_id).await;

    let sys_sk = make_signing_key();
    let (system_id, sys_key) =
        insert_system(&h.db, "stream-r", &["articles.stream"], &sys_sk).await;

    let req = StreamAccountArticlesRequest {
        account_id: account_id.to_string(),
        page_size: 50,
        page_token: String::new(),
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let resp = h
        .client
        .stream_account_articles(signed(
            req,
            &sys_sk,
            sys_key,
            RPC_STREAM,
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();

    // Assert — only the live article surfaces.
    assert_eq!(resp.items.len(), 1);
    assert_eq!(resp.items[0].article.as_ref().unwrap().id, a1.to_string());

    cleanup_drafts(&h.db, &[d1]).await;
    cleanup(&h.db, &[], &[account_id], &[a1]).await;
    cleanup_system(&h.db, system_id).await;
}

#[tokio::test]
async fn stream_paginates_keyset_across_multiple_pages() {
    skip_if_no_db!();

    // Arrange — five articles, distinct event_at. page_size=2 → 3 pages
    // (2 + 2 + 1).
    let mut h = spawn_server().await;
    let account_id = seed_account(&h.db).await;
    let a1 = seed_live_article_at(&h.db, account_id, "2024-09-01T00:00:00Z").await;
    let a2 = seed_live_article_at(&h.db, account_id, "2024-09-02T00:00:00Z").await;
    let a3 = seed_live_article_at(&h.db, account_id, "2024-09-03T00:00:00Z").await;
    let a4 = seed_live_article_at(&h.db, account_id, "2024-09-04T00:00:00Z").await;
    let a5 = seed_live_article_at(&h.db, account_id, "2024-09-05T00:00:00Z").await;

    let sys_sk = make_signing_key();
    let (system_id, sys_key) =
        insert_system(&h.db, "stream-r", &["articles.stream"], &sys_sk).await;

    // Page 1 — oldest two: a1, a2.
    let ts = h.clock.now().await.unwrap();
    let page1 = h
        .client
        .stream_account_articles(signed(
            StreamAccountArticlesRequest {
                account_id: account_id.to_string(),
                page_size: 2,
                page_token: String::new(),
            },
            &sys_sk,
            sys_key,
            RPC_STREAM,
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(page1.items.len(), 2);
    assert_eq!(page1.items[0].article.as_ref().unwrap().id, a1.to_string());
    assert_eq!(page1.items[1].article.as_ref().unwrap().id, a2.to_string());
    assert!(!page1.next_page_token.is_empty());

    // Page 2 — a3, a4.
    let ts = h.clock.now().await.unwrap();
    let page2 = h
        .client
        .stream_account_articles(signed(
            StreamAccountArticlesRequest {
                account_id: account_id.to_string(),
                page_size: 2,
                page_token: page1.next_page_token.clone(),
            },
            &sys_sk,
            sys_key,
            RPC_STREAM,
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(page2.items.len(), 2);
    assert_eq!(page2.items[0].article.as_ref().unwrap().id, a3.to_string());
    assert_eq!(page2.items[1].article.as_ref().unwrap().id, a4.to_string());
    assert!(!page2.next_page_token.is_empty());

    // Page 3 — a5 only.
    let ts = h.clock.now().await.unwrap();
    let page3 = h
        .client
        .stream_account_articles(signed(
            StreamAccountArticlesRequest {
                account_id: account_id.to_string(),
                page_size: 2,
                page_token: page2.next_page_token.clone(),
            },
            &sys_sk,
            sys_key,
            RPC_STREAM,
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(page3.items.len(), 1);
    assert_eq!(page3.items[0].article.as_ref().unwrap().id, a5.to_string());
    assert!(page3.next_page_token.is_empty());

    cleanup(&h.db, &[], &[account_id], &[a1, a2, a3, a4, a5]).await;
    cleanup_system(&h.db, system_id).await;
}

#[tokio::test]
async fn deleted_account_surfaces_account_deleted() {
    skip_if_no_db!();

    // Arrange — soft-delete the account; the stream closes per
    // `account-stream.md` (republishers must remove all content).
    let mut h = spawn_server().await;
    let account_id = seed_account(&h.db).await;
    delete_account_directly(&h.db, account_id).await;

    let sys_sk = make_signing_key();
    let (system_id, sys_key) =
        insert_system(&h.db, "stream-r", &["articles.stream"], &sys_sk).await;

    let req = StreamAccountArticlesRequest {
        account_id: account_id.to_string(),
        page_size: 50,
        page_token: String::new(),
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let err = h
        .client
        .stream_account_articles(signed(
            req,
            &sys_sk,
            sys_key,
            RPC_STREAM,
            ts,
            &unique_nonce(),
        ))
        .await
        .expect_err("deleted-account stream must close");

    // Assert — ACCOUNT_DELETED → FAILED_PRECONDITION.
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);

    cleanup(&h.db, &[], &[account_id], &[]).await;
    cleanup_system(&h.db, system_id).await;
}

#[tokio::test]
async fn missing_account_is_account_not_found() {
    skip_if_no_db!();

    // Arrange — phantom account id; system caller only.
    let mut h = spawn_server().await;
    let phantom = Uuid::now_v7();

    let sys_sk = make_signing_key();
    let (system_id, sys_key) =
        insert_system(&h.db, "stream-r", &["articles.stream"], &sys_sk).await;

    let req = StreamAccountArticlesRequest {
        account_id: phantom.to_string(),
        page_size: 50,
        page_token: String::new(),
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let err = h
        .client
        .stream_account_articles(signed(
            req,
            &sys_sk,
            sys_key,
            RPC_STREAM,
            ts,
            &unique_nonce(),
        ))
        .await
        .expect_err("missing-account stream must reject");

    // Assert — ACCOUNT_NOT_FOUND → NOT_FOUND.
    assert_eq!(err.code(), tonic::Code::NotFound);

    cleanup_system(&h.db, system_id).await;
}

#[tokio::test]
async fn invalid_cursor_is_rejected() {
    skip_if_no_db!();

    // Arrange — well-formed account, non-empty but malformed cursor.
    let mut h = spawn_server().await;
    let account_id = seed_account(&h.db).await;

    let sys_sk = make_signing_key();
    let (system_id, sys_key) =
        insert_system(&h.db, "stream-r", &["articles.stream"], &sys_sk).await;

    let req = StreamAccountArticlesRequest {
        account_id: account_id.to_string(),
        page_size: 50,
        page_token: "!!!not-a-valid-base64-cursor!!!".into(),
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let err = h
        .client
        .stream_account_articles(signed(
            req,
            &sys_sk,
            sys_key,
            RPC_STREAM,
            ts,
            &unique_nonce(),
        ))
        .await
        .expect_err("malformed cursor must reject");

    // Assert — INVALID_CURSOR → INVALID_ARGUMENT.
    assert_eq!(err.code(), tonic::Code::InvalidArgument);

    cleanup(&h.db, &[], &[account_id], &[]).await;
    cleanup_system(&h.db, system_id).await;
}
