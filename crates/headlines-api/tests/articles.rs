//! End-to-end integration tests for `ArticleService`, exercised through a
//! real tonic in-process server (random TCP port) backed by Postgres on
//! `docker.yuacx.com`. Mirror of `tests/accounts.rs` and `tests/users.rs`.
//!
//! Each test mints fresh UUIDv7s. Cleanup is best-effort via DELETE filters
//! at the end; no TRUNCATE.
//!
//! Tests SKIP cleanly when `DATABASE_URL` is unset.
//!
//! AAA structure throughout, per `~/.claude/rules/testing-patterns.md`.

#![allow(clippy::too_many_arguments)]

use std::collections::HashMap;
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

use headlines_api::ArticleServiceImpl;
use headlines_auth::{
    AlgorithmRegistry, AuthInterceptor, AuthorizationLayer, Ed25519, InMemoryNonceStore,
    LocalClock, PostgresKeyResolver, ProtoBodyHasher, SignedRequestStrategy,
};
use headlines_core::{TimeSource as _, Tso};
use headlines_proto::v1::{
    ArticleEdit, ArticleState, EditArticleRequest, GetArticleRequest, ListAccountArticlesRequest,
    Node, NodeElement, PublishArticleRequest, RedactArticleVersionRequest, TombstoneArticleRequest,
    article::StateData, article_service_client::ArticleServiceClient,
    article_service_server::ArticleServiceServer, node::Kind,
};
use headlines_store::{Db, PgAccountRepo, PgArticleRepo};

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

/// Small content cap so CONTENT_TOO_LARGE fires without 20 MiB blobs.
const TEST_CONTENT_MAX_BYTES: usize = 1024;

struct Harness {
    db: Db,
    client: ArticleServiceClient<Channel>,
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
    let articles = Arc::new(PgArticleRepo::new(db.clone()));
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

    let svc = ArticleServiceImpl::new(accounts, articles, TEST_CONTENT_MAX_BYTES);

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
        .add_service(ArticleServiceServer::new(svc));

    tokio::spawn(async move {
        let _ = server.serve_with_incoming(stream).await;
    });

    let endpoint = Endpoint::from_shared(format!("http://{addr}"))
        .expect("endpoint")
        .connect_timeout(Duration::from_secs(5));
    let channel = endpoint.connect().await.expect("client connect");
    let client = ArticleServiceClient::new(channel);

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

async fn cleanup_articles(db: &Db, account_ids: &[Uuid]) {
    if account_ids.is_empty() {
        return;
    }
    let url = db.database_url().to_owned();
    let owned_ids: Vec<Uuid> = account_ids.to_owned();
    let _ = tokio::spawn(async move {
        let mut conn = match AsyncPgConnection::establish(&url).await {
            Ok(c) => c,
            Err(_) => return,
        };
        // Order matters: child tables before parents.
        let _ = diesel::sql_query(
            "DELETE FROM article_versions WHERE article_id IN \
             (SELECT id FROM articles WHERE account_id = ANY($1))",
        )
        .bind::<diesel::sql_types::Array<diesel::sql_types::Uuid>, _>(owned_ids.clone())
        .execute(&mut conn)
        .await;
        let _ = diesel::sql_query(
            "DELETE FROM articles_live WHERE article_id IN \
             (SELECT id FROM articles WHERE account_id = ANY($1))",
        )
        .bind::<diesel::sql_types::Array<diesel::sql_types::Uuid>, _>(owned_ids.clone())
        .execute(&mut conn)
        .await;
        let _ = diesel::sql_query(
            "DELETE FROM articles_tombstone WHERE article_id IN \
             (SELECT id FROM articles WHERE account_id = ANY($1))",
        )
        .bind::<diesel::sql_types::Array<diesel::sql_types::Uuid>, _>(owned_ids.clone())
        .execute(&mut conn)
        .await;
        let _ = diesel::sql_query("DELETE FROM articles WHERE account_id = ANY($1)")
            .bind::<diesel::sql_types::Array<diesel::sql_types::Uuid>, _>(owned_ids.clone())
            .execute(&mut conn)
            .await;
        let _ = diesel::sql_query("DELETE FROM account_keys WHERE account_id = ANY($1)")
            .bind::<diesel::sql_types::Array<diesel::sql_types::Uuid>, _>(owned_ids.clone())
            .execute(&mut conn)
            .await;
        let _ = diesel::sql_query("DELETE FROM accounts WHERE id = ANY($1)")
            .bind::<diesel::sql_types::Array<diesel::sql_types::Uuid>, _>(owned_ids)
            .execute(&mut conn)
            .await;
    })
    .await;
}

/// Seed an account directly via SQL — bypassing AccountService keeps these
/// tests focused on ArticleService behavior. Returns `(account_id, key_id)`.
async fn seed_account_with_key(db: &Db, sk: &SigningKey) -> (Uuid, Uuid) {
    let mut conn = db.get().await.unwrap();
    let account_id = Uuid::now_v7();
    let key_id = Uuid::now_v7();
    let pk_b64 = B64.encode(sk.verifying_key().as_bytes());

    let short = format!("test-{}", account_id.simple());
    diesel::sql_query(
        "INSERT INTO accounts (id, short_name, author_name, status) \
         VALUES ($1, $2, 'Test Author', 'active')",
    )
    .bind::<diesel::sql_types::Uuid, _>(account_id)
    .bind::<diesel::sql_types::Text, _>(short)
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

/// Read articles_live.updated_at directly so we can assert the redact-bump
/// behavior end-to-end.
async fn read_articles_live_updated_at(
    db: &Db,
    article_id: Uuid,
) -> Option<chrono::DateTime<chrono::Utc>> {
    use diesel::QueryableByName;
    let mut conn = db.get().await.ok()?;
    #[derive(QueryableByName)]
    struct Row {
        #[diesel(sql_type = diesel::sql_types::Timestamptz)]
        updated_at: chrono::DateTime<chrono::Utc>,
    }
    diesel::sql_query("SELECT updated_at FROM articles_live WHERE article_id = $1")
        .bind::<diesel::sql_types::Uuid, _>(article_id)
        .get_result::<Row>(&mut conn)
        .await
        .ok()
        .map(|r| r.updated_at)
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

// ---------------------------------------------------------------------------
// Content helpers
// ---------------------------------------------------------------------------

fn p(text: &str) -> Node {
    Node {
        kind: Some(Kind::Element(NodeElement {
            tag: "p".into(),
            attrs: HashMap::new(),
            children: vec![Node {
                kind: Some(Kind::Text(text.into())),
            }],
        })),
    }
}

fn simple_content() -> Vec<Node> {
    vec![p("hello world")]
}

async fn publish_one(
    h: &mut Harness,
    sk: &SigningKey,
    account_id: Uuid,
    key_id: Uuid,
    title: &str,
) -> Uuid {
    let req = PublishArticleRequest {
        account_id: account_id.to_string(),
        title: title.to_owned(),
        author_name: "Author".into(),
        author_url: String::new(),
        content: simple_content(),
    };
    let ts = h.clock.now().await.unwrap();
    let signed_req = signed(
        req,
        sk,
        key_id,
        "/headlines.v1.ArticleService/PublishArticle",
        ts,
        &unique_nonce(),
    );
    let resp = h
        .client
        .publish_article(signed_req)
        .await
        .unwrap()
        .into_inner();
    Uuid::parse_str(&resp.id).unwrap()
}

// ===========================================================================
// PublishArticle
// ===========================================================================

#[tokio::test]
async fn publish_article_account_self_succeeds() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server().await;
    let sk = make_signing_key();
    let (acct, key_id) = seed_account_with_key(&h.db, &sk).await;
    let req = PublishArticleRequest {
        account_id: acct.to_string(),
        title: "Hello".into(),
        author_name: "Me".into(),
        author_url: "https://example.com".into(),
        content: simple_content(),
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let signed_req = signed(
        req,
        &sk,
        key_id,
        "/headlines.v1.ArticleService/PublishArticle",
        ts,
        &unique_nonce(),
    );
    let resp = h
        .client
        .publish_article(signed_req)
        .await
        .expect("PublishArticle account-self should succeed");

    // Assert
    let article = resp.into_inner();
    assert_eq!(article.account_id, acct.to_string());
    assert_eq!(article.state, ArticleState::Live as i32);
    let Some(StateData::Live(live)) = article.state_data else {
        panic!("expected live state_data");
    };
    assert_eq!(live.title, "Hello");
    assert_eq!(live.current_version, 1);
    assert!(!live.redacted);

    cleanup_articles(&h.db, &[acct]).await;
}

#[tokio::test]
async fn publish_article_with_deleted_account_returns_account_deleted() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server().await;
    let sk = make_signing_key();
    let (acct, key_id) = seed_account_with_key(&h.db, &sk).await;
    delete_account_directly(&h.db, acct).await;

    let req = PublishArticleRequest {
        account_id: acct.to_string(),
        title: "x".into(),
        author_name: String::new(),
        author_url: String::new(),
        content: simple_content(),
    };
    let ts = h.clock.now().await.unwrap();
    let signed_req = signed(
        req,
        &sk,
        key_id,
        "/headlines.v1.ArticleService/PublishArticle",
        ts,
        &unique_nonce(),
    );

    // Act
    let err = h
        .client
        .publish_article(signed_req)
        .await
        .expect_err("publish on deleted account");

    // Assert
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);

    cleanup_articles(&h.db, &[acct]).await;
}

#[tokio::test]
async fn publish_article_missing_account_returns_account_not_found() {
    skip_if_no_db!();

    // Arrange — sign with the system to bypass account-self auth, then
    // target a non-existent account so the precondition itself fires.
    let mut h = spawn_server().await;
    let sys_sk = make_signing_key();
    let (system_id, sys_key) = insert_system(&h.db, "writer", &["articles.write"], &sys_sk).await;
    let phantom = Uuid::now_v7();

    let req = PublishArticleRequest {
        account_id: phantom.to_string(),
        title: "x".into(),
        author_name: String::new(),
        author_url: String::new(),
        content: simple_content(),
    };
    let ts = h.clock.now().await.unwrap();
    let signed_req = signed(
        req,
        &sys_sk,
        sys_key,
        "/headlines.v1.ArticleService/PublishArticle",
        ts,
        &unique_nonce(),
    );

    // Act
    let err = h
        .client
        .publish_article(signed_req)
        .await
        .expect_err("missing account");

    // Assert
    assert_eq!(err.code(), tonic::Code::NotFound);

    cleanup_system(&h.db, system_id).await;
}

#[tokio::test]
async fn publish_article_oversize_content_returns_content_too_large() {
    skip_if_no_db!();

    // Arrange — single text node bigger than the 1 KiB cap.
    let mut h = spawn_server().await;
    let sk = make_signing_key();
    let (acct, key_id) = seed_account_with_key(&h.db, &sk).await;
    let big = Node {
        kind: Some(Kind::Text("x".repeat(3000))),
    };
    let req = PublishArticleRequest {
        account_id: acct.to_string(),
        title: "x".into(),
        author_name: String::new(),
        author_url: String::new(),
        content: vec![big],
    };
    let ts = h.clock.now().await.unwrap();
    let signed_req = signed(
        req,
        &sk,
        key_id,
        "/headlines.v1.ArticleService/PublishArticle",
        ts,
        &unique_nonce(),
    );

    // Act
    let err = h
        .client
        .publish_article(signed_req)
        .await
        .expect_err("oversize");

    // Assert
    assert_eq!(err.code(), tonic::Code::ResourceExhausted);

    cleanup_articles(&h.db, &[acct]).await;
}

#[tokio::test]
async fn publish_article_invalid_node_tag_rejected() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server().await;
    let sk = make_signing_key();
    let (acct, key_id) = seed_account_with_key(&h.db, &sk).await;
    let bad = Node {
        kind: Some(Kind::Element(NodeElement {
            tag: "marquee".into(),
            attrs: HashMap::new(),
            children: vec![],
        })),
    };
    let req = PublishArticleRequest {
        account_id: acct.to_string(),
        title: "x".into(),
        author_name: String::new(),
        author_url: String::new(),
        content: vec![bad],
    };
    let ts = h.clock.now().await.unwrap();
    let signed_req = signed(
        req,
        &sk,
        key_id,
        "/headlines.v1.ArticleService/PublishArticle",
        ts,
        &unique_nonce(),
    );

    // Act
    let err = h
        .client
        .publish_article(signed_req)
        .await
        .expect_err("bad tag");

    // Assert
    assert_eq!(err.code(), tonic::Code::InvalidArgument);

    cleanup_articles(&h.db, &[acct]).await;
}

#[tokio::test]
async fn publish_article_invalid_node_attr_rejected() {
    skip_if_no_db!();

    // Arrange — `<a onclick=...>` is not in the allow-list.
    let mut h = spawn_server().await;
    let sk = make_signing_key();
    let (acct, key_id) = seed_account_with_key(&h.db, &sk).await;
    let mut attrs = HashMap::new();
    attrs.insert("onclick".to_owned(), "x".to_owned());
    let bad = Node {
        kind: Some(Kind::Element(NodeElement {
            tag: "a".into(),
            attrs,
            children: vec![],
        })),
    };
    let req = PublishArticleRequest {
        account_id: acct.to_string(),
        title: "x".into(),
        author_name: String::new(),
        author_url: String::new(),
        content: vec![bad],
    };
    let ts = h.clock.now().await.unwrap();
    let signed_req = signed(
        req,
        &sk,
        key_id,
        "/headlines.v1.ArticleService/PublishArticle",
        ts,
        &unique_nonce(),
    );

    // Act
    let err = h
        .client
        .publish_article(signed_req)
        .await
        .expect_err("bad attr");

    // Assert
    assert_eq!(err.code(), tonic::Code::InvalidArgument);

    cleanup_articles(&h.db, &[acct]).await;
}

#[tokio::test]
async fn publish_article_empty_title_rejected() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server().await;
    let sk = make_signing_key();
    let (acct, key_id) = seed_account_with_key(&h.db, &sk).await;
    let req = PublishArticleRequest {
        account_id: acct.to_string(),
        title: "   ".into(),
        author_name: String::new(),
        author_url: String::new(),
        content: simple_content(),
    };
    let ts = h.clock.now().await.unwrap();
    let signed_req = signed(
        req,
        &sk,
        key_id,
        "/headlines.v1.ArticleService/PublishArticle",
        ts,
        &unique_nonce(),
    );

    // Act
    let err = h
        .client
        .publish_article(signed_req)
        .await
        .expect_err("empty title");

    // Assert
    assert_eq!(err.code(), tonic::Code::InvalidArgument);

    cleanup_articles(&h.db, &[acct]).await;
}

// ===========================================================================
// GetArticle
// ===========================================================================

#[tokio::test]
async fn get_article_anonymous_returns_live_article() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server().await;
    let sk = make_signing_key();
    let (acct, key_id) = seed_account_with_key(&h.db, &sk).await;
    let article_id = publish_one(&mut h, &sk, acct, key_id, "Live").await;

    // Act — anonymous GET (no auth header).
    let got = h
        .client
        .get_article(tonic::Request::new(GetArticleRequest {
            id: article_id.to_string(),
        }))
        .await
        .unwrap()
        .into_inner();

    // Assert
    assert_eq!(got.state, ArticleState::Live as i32);
    let Some(StateData::Live(live)) = got.state_data else {
        panic!("expected live");
    };
    assert_eq!(live.title, "Live");

    cleanup_articles(&h.db, &[acct]).await;
}

#[tokio::test]
async fn get_article_returns_tombstone_after_tombstone() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server().await;
    let sk = make_signing_key();
    let (acct, key_id) = seed_account_with_key(&h.db, &sk).await;
    let article_id = publish_one(&mut h, &sk, acct, key_id, "DoomedLive").await;

    let ts = h.clock.now().await.unwrap();
    let req = signed(
        TombstoneArticleRequest {
            id: article_id.to_string(),
            reason: "policy violation".into(),
        },
        &sk,
        key_id,
        "/headlines.v1.ArticleService/TombstoneArticle",
        ts,
        &unique_nonce(),
    );
    h.client.tombstone_article(req).await.unwrap();

    // Act
    let got = h
        .client
        .get_article(tonic::Request::new(GetArticleRequest {
            id: article_id.to_string(),
        }))
        .await
        .unwrap()
        .into_inner();

    // Assert
    assert_eq!(got.state, ArticleState::Tombstone as i32);
    let Some(StateData::Tombstone(t)) = got.state_data else {
        panic!("expected tombstone state_data");
    };
    assert_eq!(t.reason, "policy violation");

    cleanup_articles(&h.db, &[acct]).await;
}

#[tokio::test]
async fn get_article_missing_returns_article_not_found() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server().await;
    let phantom = Uuid::now_v7();

    // Act
    let err = h
        .client
        .get_article(tonic::Request::new(GetArticleRequest {
            id: phantom.to_string(),
        }))
        .await
        .expect_err("missing");

    // Assert
    assert_eq!(err.code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn get_article_returns_redacted_marker_for_redacted_current_version() {
    skip_if_no_db!();

    // Arrange — publish, then redact version 1 via system path.
    let mut h = spawn_server().await;
    let sk = make_signing_key();
    let (acct, key_id) = seed_account_with_key(&h.db, &sk).await;
    let article_id = publish_one(&mut h, &sk, acct, key_id, "Redactable").await;

    let sys_sk = make_signing_key();
    let (system_id, sys_key) =
        insert_system(&h.db, "redactor", &["articles.redact"], &sys_sk).await;

    let ts = h.clock.now().await.unwrap();
    let req = signed(
        RedactArticleVersionRequest {
            article_id: article_id.to_string(),
            version: 1,
            redaction_reason: "GDPR".into(),
        },
        &sys_sk,
        sys_key,
        "/headlines.v1.ArticleService/RedactArticleVersion",
        ts,
        &unique_nonce(),
    );
    h.client.redact_article_version(req).await.unwrap();

    // Act
    let got = h
        .client
        .get_article(tonic::Request::new(GetArticleRequest {
            id: article_id.to_string(),
        }))
        .await
        .unwrap()
        .into_inner();

    // Assert
    let Some(StateData::Live(live)) = got.state_data else {
        panic!("expected live");
    };
    assert!(live.redacted);
    assert!(live.content.is_empty());

    cleanup_articles(&h.db, &[acct]).await;
    cleanup_system(&h.db, system_id).await;
}

// ===========================================================================
// ListAccountArticles
// ===========================================================================

#[tokio::test]
async fn list_account_articles_paginates_through_five_articles() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server().await;
    let sk = make_signing_key();
    let (acct, key_id) = seed_account_with_key(&h.db, &sk).await;
    for i in 0..5 {
        publish_one(&mut h, &sk, acct, key_id, &format!("Title {i}")).await;
    }

    // Act — pull two pages of 2 (anonymous).
    let p1 = h
        .client
        .list_account_articles(tonic::Request::new(ListAccountArticlesRequest {
            account_id: acct.to_string(),
            page_size: 2,
            page_token: String::new(),
            include_tombstoned: false,
        }))
        .await
        .unwrap()
        .into_inner();
    let p2 = h
        .client
        .list_account_articles(tonic::Request::new(ListAccountArticlesRequest {
            account_id: acct.to_string(),
            page_size: 2,
            page_token: p1.next_page_token.clone(),
            include_tombstoned: false,
        }))
        .await
        .unwrap()
        .into_inner();
    let p3 = h
        .client
        .list_account_articles(tonic::Request::new(ListAccountArticlesRequest {
            account_id: acct.to_string(),
            page_size: 2,
            page_token: p2.next_page_token.clone(),
            include_tombstoned: false,
        }))
        .await
        .unwrap()
        .into_inner();

    // Assert
    assert_eq!(p1.items.len(), 2);
    assert!(!p1.next_page_token.is_empty());
    assert_eq!(p2.items.len(), 2);
    assert_eq!(p3.items.len(), 1);
    assert!(p3.next_page_token.is_empty());

    cleanup_articles(&h.db, &[acct]).await;
}

#[tokio::test]
async fn list_account_articles_excludes_tombstones_by_default_and_includes_them_when_asked() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server().await;
    let sk = make_signing_key();
    let (acct, key_id) = seed_account_with_key(&h.db, &sk).await;
    let live_id = publish_one(&mut h, &sk, acct, key_id, "Live").await;
    let tombstone_id = publish_one(&mut h, &sk, acct, key_id, "ToTombstone").await;

    let ts = h.clock.now().await.unwrap();
    let req = signed(
        TombstoneArticleRequest {
            id: tombstone_id.to_string(),
            reason: String::new(),
        },
        &sk,
        key_id,
        "/headlines.v1.ArticleService/TombstoneArticle",
        ts,
        &unique_nonce(),
    );
    h.client.tombstone_article(req).await.unwrap();

    // Act
    let excluded = h
        .client
        .list_account_articles(tonic::Request::new(ListAccountArticlesRequest {
            account_id: acct.to_string(),
            page_size: 50,
            page_token: String::new(),
            include_tombstoned: false,
        }))
        .await
        .unwrap()
        .into_inner();
    let included = h
        .client
        .list_account_articles(tonic::Request::new(ListAccountArticlesRequest {
            account_id: acct.to_string(),
            page_size: 50,
            page_token: String::new(),
            include_tombstoned: true,
        }))
        .await
        .unwrap()
        .into_inner();

    // Assert — excluded should only contain the live one; included both.
    let ex_ids: Vec<String> = excluded.items.iter().map(|i| i.id.clone()).collect();
    let in_ids: Vec<String> = included.items.iter().map(|i| i.id.clone()).collect();
    assert!(ex_ids.contains(&live_id.to_string()));
    assert!(!ex_ids.contains(&tombstone_id.to_string()));
    assert!(in_ids.contains(&live_id.to_string()));
    assert!(in_ids.contains(&tombstone_id.to_string()));

    cleanup_articles(&h.db, &[acct]).await;
}

// ===========================================================================
// EditArticle
// ===========================================================================

#[tokio::test]
async fn edit_article_account_self_bumps_current_version() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server().await;
    let sk = make_signing_key();
    let (acct, key_id) = seed_account_with_key(&h.db, &sk).await;
    let article_id = publish_one(&mut h, &sk, acct, key_id, "v1").await;

    let edit = EditArticleRequest {
        id: article_id.to_string(),
        edit: Some(ArticleEdit {
            title: "v2".into(),
            author_name: String::new(),
            author_url: String::new(),
            content: vec![],
        }),
        update_mask: Some(prost_types::FieldMask {
            paths: vec!["title".into()],
        }),
    };
    let ts = h.clock.now().await.unwrap();
    let signed_req = signed(
        edit,
        &sk,
        key_id,
        "/headlines.v1.ArticleService/EditArticle",
        ts,
        &unique_nonce(),
    );

    // Act
    let updated = h
        .client
        .edit_article(signed_req)
        .await
        .unwrap()
        .into_inner();

    // Assert
    let Some(StateData::Live(live)) = updated.state_data else {
        panic!("expected live");
    };
    assert_eq!(live.title, "v2");
    assert_eq!(live.current_version, 2);

    cleanup_articles(&h.db, &[acct]).await;
}

#[tokio::test]
async fn edit_article_on_tombstoned_returns_article_tombstoned() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server().await;
    let sk = make_signing_key();
    let (acct, key_id) = seed_account_with_key(&h.db, &sk).await;
    let article_id = publish_one(&mut h, &sk, acct, key_id, "doom").await;
    let ts = h.clock.now().await.unwrap();
    h.client
        .tombstone_article(signed(
            TombstoneArticleRequest {
                id: article_id.to_string(),
                reason: String::new(),
            },
            &sk,
            key_id,
            "/headlines.v1.ArticleService/TombstoneArticle",
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap();

    let edit = EditArticleRequest {
        id: article_id.to_string(),
        edit: Some(ArticleEdit {
            title: "post-tombstone".into(),
            ..Default::default()
        }),
        update_mask: Some(prost_types::FieldMask {
            paths: vec!["title".into()],
        }),
    };
    let ts = h.clock.now().await.unwrap();
    let signed_req = signed(
        edit,
        &sk,
        key_id,
        "/headlines.v1.ArticleService/EditArticle",
        ts,
        &unique_nonce(),
    );

    // Act
    let err = h
        .client
        .edit_article(signed_req)
        .await
        .expect_err("edit on tombstoned");

    // Assert
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);

    cleanup_articles(&h.db, &[acct]).await;
}

#[tokio::test]
async fn edit_article_empty_mask_is_invalid_argument() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server().await;
    let sk = make_signing_key();
    let (acct, key_id) = seed_account_with_key(&h.db, &sk).await;
    let article_id = publish_one(&mut h, &sk, acct, key_id, "x").await;
    let edit = EditArticleRequest {
        id: article_id.to_string(),
        edit: Some(ArticleEdit::default()),
        update_mask: Some(prost_types::FieldMask { paths: vec![] }),
    };
    let ts = h.clock.now().await.unwrap();
    let signed_req = signed(
        edit,
        &sk,
        key_id,
        "/headlines.v1.ArticleService/EditArticle",
        ts,
        &unique_nonce(),
    );

    // Act
    let err = h
        .client
        .edit_article(signed_req)
        .await
        .expect_err("empty mask");

    // Assert
    assert_eq!(err.code(), tonic::Code::InvalidArgument);

    cleanup_articles(&h.db, &[acct]).await;
}

#[tokio::test]
async fn edit_article_unallowed_mask_path_rejected() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server().await;
    let sk = make_signing_key();
    let (acct, key_id) = seed_account_with_key(&h.db, &sk).await;
    let article_id = publish_one(&mut h, &sk, acct, key_id, "x").await;
    let edit = EditArticleRequest {
        id: article_id.to_string(),
        edit: Some(ArticleEdit::default()),
        update_mask: Some(prost_types::FieldMask {
            paths: vec!["account_id".into()],
        }),
    };
    let ts = h.clock.now().await.unwrap();
    let signed_req = signed(
        edit,
        &sk,
        key_id,
        "/headlines.v1.ArticleService/EditArticle",
        ts,
        &unique_nonce(),
    );

    // Act
    let err = h
        .client
        .edit_article(signed_req)
        .await
        .expect_err("unallowed path");

    // Assert
    assert_eq!(err.code(), tonic::Code::InvalidArgument);

    cleanup_articles(&h.db, &[acct]).await;
}

// ===========================================================================
// TombstoneArticle
// ===========================================================================

#[tokio::test]
async fn tombstone_article_account_self_succeeds_then_get_returns_tombstone() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server().await;
    let sk = make_signing_key();
    let (acct, key_id) = seed_account_with_key(&h.db, &sk).await;
    let article_id = publish_one(&mut h, &sk, acct, key_id, "x").await;
    let ts = h.clock.now().await.unwrap();
    let req = signed(
        TombstoneArticleRequest {
            id: article_id.to_string(),
            reason: "spam".into(),
        },
        &sk,
        key_id,
        "/headlines.v1.ArticleService/TombstoneArticle",
        ts,
        &unique_nonce(),
    );

    // Act
    let resp = h.client.tombstone_article(req).await.unwrap().into_inner();

    // Assert — first the response, then a follow-up Get.
    assert_eq!(resp.state, ArticleState::Tombstone as i32);
    let got = h
        .client
        .get_article(tonic::Request::new(GetArticleRequest {
            id: article_id.to_string(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(got.state, ArticleState::Tombstone as i32);

    cleanup_articles(&h.db, &[acct]).await;
}

#[tokio::test]
async fn tombstone_article_already_tombstoned_returns_article_tombstoned() {
    skip_if_no_db!();

    // Arrange — tombstone, then tombstone again.
    let mut h = spawn_server().await;
    let sk = make_signing_key();
    let (acct, key_id) = seed_account_with_key(&h.db, &sk).await;
    let article_id = publish_one(&mut h, &sk, acct, key_id, "x").await;
    let ts = h.clock.now().await.unwrap();
    h.client
        .tombstone_article(signed(
            TombstoneArticleRequest {
                id: article_id.to_string(),
                reason: String::new(),
            },
            &sk,
            key_id,
            "/headlines.v1.ArticleService/TombstoneArticle",
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap();
    let ts = h.clock.now().await.unwrap();
    let req = signed(
        TombstoneArticleRequest {
            id: article_id.to_string(),
            reason: String::new(),
        },
        &sk,
        key_id,
        "/headlines.v1.ArticleService/TombstoneArticle",
        ts,
        &unique_nonce(),
    );

    // Act
    let err = h
        .client
        .tombstone_article(req)
        .await
        .expect_err("double tombstone");

    // Assert
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);

    cleanup_articles(&h.db, &[acct]).await;
}

#[tokio::test]
async fn edit_article_by_non_owner_account_is_permission_denied() {
    skip_if_no_db!();

    // Arrange — A publishes, B tries to edit. Existence of the article is
    // already public via anonymous GetArticle, so a privacy-style NOT_FOUND
    // carve-out doesn't help here — PERMISSION_DENIED is the correct surface.
    let mut h = spawn_server().await;
    let sk_a = make_signing_key();
    let (acct_a, key_a) = seed_account_with_key(&h.db, &sk_a).await;
    let sk_b = make_signing_key();
    let (acct_b, key_b) = seed_account_with_key(&h.db, &sk_b).await;
    let article_id = publish_one(&mut h, &sk_a, acct_a, key_a, "A's").await;

    let edit = EditArticleRequest {
        id: article_id.to_string(),
        edit: Some(ArticleEdit {
            title: "B's takeover".into(),
            author_name: String::new(),
            author_url: String::new(),
            content: vec![],
        }),
        update_mask: Some(prost_types::FieldMask {
            paths: vec!["title".into()],
        }),
    };
    let ts = h.clock.now().await.unwrap();
    let signed_req = signed(
        edit,
        &sk_b,
        key_b,
        "/headlines.v1.ArticleService/EditArticle",
        ts,
        &unique_nonce(),
    );

    // Act
    let err = h
        .client
        .edit_article(signed_req)
        .await
        .expect_err("non-owner edit");

    // Assert
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    cleanup_articles(&h.db, &[acct_a, acct_b]).await;
}

#[tokio::test]
async fn tombstone_article_by_non_owner_account_is_permission_denied() {
    skip_if_no_db!();

    // Arrange — A publishes, B tries to tombstone.
    let mut h = spawn_server().await;
    let sk_a = make_signing_key();
    let (acct_a, key_a) = seed_account_with_key(&h.db, &sk_a).await;
    let sk_b = make_signing_key();
    let (acct_b, key_b) = seed_account_with_key(&h.db, &sk_b).await;
    let article_id = publish_one(&mut h, &sk_a, acct_a, key_a, "A's").await;

    let ts = h.clock.now().await.unwrap();
    let req = signed(
        TombstoneArticleRequest {
            id: article_id.to_string(),
            reason: String::new(),
        },
        &sk_b,
        key_b,
        "/headlines.v1.ArticleService/TombstoneArticle",
        ts,
        &unique_nonce(),
    );

    // Act
    let err = h
        .client
        .tombstone_article(req)
        .await
        .expect_err("non-owner tombstone");

    // Assert
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    cleanup_articles(&h.db, &[acct_a, acct_b]).await;
}

// ===========================================================================
// RedactArticleVersion
// ===========================================================================

#[tokio::test]
async fn redact_article_version_system_with_articles_redact_succeeds() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server().await;
    let sk = make_signing_key();
    let (acct, key_id) = seed_account_with_key(&h.db, &sk).await;
    let article_id = publish_one(&mut h, &sk, acct, key_id, "redactable").await;

    let sys_sk = make_signing_key();
    let (system_id, sys_key) =
        insert_system(&h.db, "redactor", &["articles.redact"], &sys_sk).await;

    let updated_before = read_articles_live_updated_at(&h.db, article_id)
        .await
        .unwrap();
    // Sleep just enough for now()-tick granularity so the bump is observable.
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    let ts = h.clock.now().await.unwrap();
    let req = signed(
        RedactArticleVersionRequest {
            article_id: article_id.to_string(),
            version: 1,
            redaction_reason: "GDPR".into(),
        },
        &sys_sk,
        sys_key,
        "/headlines.v1.ArticleService/RedactArticleVersion",
        ts,
        &unique_nonce(),
    );

    // Act
    h.client
        .redact_article_version(req)
        .await
        .expect("system redact");

    // Assert — articles_live.updated_at must have moved forward.
    let updated_after = read_articles_live_updated_at(&h.db, article_id)
        .await
        .unwrap();
    assert!(
        updated_after > updated_before,
        "redact of current version must bump articles_live.updated_at: \
         before={updated_before}, after={updated_after}",
    );

    cleanup_articles(&h.db, &[acct]).await;
    cleanup_system(&h.db, system_id).await;
}

#[tokio::test]
async fn redact_article_version_non_system_account_is_denied() {
    skip_if_no_db!();

    // Arrange — sign as the article-owning account, not as a system.
    let mut h = spawn_server().await;
    let sk = make_signing_key();
    let (acct, key_id) = seed_account_with_key(&h.db, &sk).await;
    let article_id = publish_one(&mut h, &sk, acct, key_id, "x").await;
    let ts = h.clock.now().await.unwrap();
    let req = signed(
        RedactArticleVersionRequest {
            article_id: article_id.to_string(),
            version: 1,
            redaction_reason: "self".into(),
        },
        &sk,
        key_id,
        "/headlines.v1.ArticleService/RedactArticleVersion",
        ts,
        &unique_nonce(),
    );

    // Act
    let err = h
        .client
        .redact_article_version(req)
        .await
        .expect_err("account-self redact must be denied");

    // Assert — proto-level gate rejects non-System with PERMISSION_DENIED.
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    cleanup_articles(&h.db, &[acct]).await;
}

#[tokio::test]
async fn redact_article_version_missing_version_returns_version_not_found() {
    skip_if_no_db!();

    // Arrange — version 99 never exists for a freshly-published article.
    let mut h = spawn_server().await;
    let sk = make_signing_key();
    let (acct, key_id) = seed_account_with_key(&h.db, &sk).await;
    let article_id = publish_one(&mut h, &sk, acct, key_id, "x").await;

    let sys_sk = make_signing_key();
    let (system_id, sys_key) =
        insert_system(&h.db, "redactor", &["articles.redact"], &sys_sk).await;

    let ts = h.clock.now().await.unwrap();
    let req = signed(
        RedactArticleVersionRequest {
            article_id: article_id.to_string(),
            version: 99,
            redaction_reason: "x".into(),
        },
        &sys_sk,
        sys_key,
        "/headlines.v1.ArticleService/RedactArticleVersion",
        ts,
        &unique_nonce(),
    );

    // Act
    let err = h
        .client
        .redact_article_version(req)
        .await
        .expect_err("missing version");

    // Assert
    assert_eq!(err.code(), tonic::Code::NotFound);

    cleanup_articles(&h.db, &[acct]).await;
    cleanup_system(&h.db, system_id).await;
}

#[tokio::test]
async fn redact_article_version_already_redacted_is_already_exists() {
    skip_if_no_db!();

    // Arrange — redact once, then redact again.
    let mut h = spawn_server().await;
    let sk = make_signing_key();
    let (acct, key_id) = seed_account_with_key(&h.db, &sk).await;
    let article_id = publish_one(&mut h, &sk, acct, key_id, "x").await;

    let sys_sk = make_signing_key();
    let (system_id, sys_key) =
        insert_system(&h.db, "redactor", &["articles.redact"], &sys_sk).await;

    let ts = h.clock.now().await.unwrap();
    h.client
        .redact_article_version(signed(
            RedactArticleVersionRequest {
                article_id: article_id.to_string(),
                version: 1,
                redaction_reason: "first".into(),
            },
            &sys_sk,
            sys_key,
            "/headlines.v1.ArticleService/RedactArticleVersion",
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap();

    let ts = h.clock.now().await.unwrap();
    let req = signed(
        RedactArticleVersionRequest {
            article_id: article_id.to_string(),
            version: 1,
            redaction_reason: "second".into(),
        },
        &sys_sk,
        sys_key,
        "/headlines.v1.ArticleService/RedactArticleVersion",
        ts,
        &unique_nonce(),
    );

    // Act
    let err = h
        .client
        .redact_article_version(req)
        .await
        .expect_err("double redact");

    // Assert
    assert_eq!(err.code(), tonic::Code::AlreadyExists);

    cleanup_articles(&h.db, &[acct]).await;
    cleanup_system(&h.db, system_id).await;
}
