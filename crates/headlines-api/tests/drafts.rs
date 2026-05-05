//! End-to-end integration tests for `DraftService`, exercised through a
//! real tonic in-process server (random TCP port) backed by Postgres on
//! `docker.yuacx.com`. Mirror of `tests/articles.rs`.
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

use headlines_api::{ArticleServiceImpl, DraftServiceImpl};
use headlines_auth::{
    AlgorithmRegistry, AuthInterceptor, AuthorizationLayer, Ed25519, InMemoryNonceStore,
    LocalClock, PostgresKeyResolver, ProtoBodyHasher, SignedRequestStrategy,
};
use headlines_core::{TimeSource as _, Tso};
use headlines_proto::v1::{
    ArticleState, CreateDraftRequest, DeleteDraftRequest, Draft as ProtoDraft, GetArticleRequest,
    GetDraftRequest, ListAccountDraftsRequest, Node, NodeElement, PublishDraftRequest,
    UpdateDraftRequest, article::StateData, article_service_client::ArticleServiceClient,
    article_service_server::ArticleServiceServer, draft_service_client::DraftServiceClient,
    draft_service_server::DraftServiceServer, node::Kind,
};
use headlines_store::{Db, PgAccountRepo, PgArticleRepo, PgDraftRepo};

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

/// Small content cap so CONTENT_TOO_LARGE fires without 20 MiB blobs.
const TEST_CONTENT_MAX_BYTES: usize = 1024;

struct Harness {
    db: Db,
    drafts: DraftServiceClient<Channel>,
    articles: ArticleServiceClient<Channel>,
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

    // Both DraftService and ArticleService are wired so we can verify the
    // PublishDraft → GetArticle UUID-continuity invariant end-to-end.
    let draft_account_repo = Arc::new(PgAccountRepo::new(db.clone()));
    let draft_repo = Arc::new(PgDraftRepo::new(db.clone()));
    let article_account_repo = Arc::new(PgAccountRepo::new(db.clone()));
    let article_repo = Arc::new(PgArticleRepo::new(db.clone()));

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

    let draft_svc = DraftServiceImpl::new(draft_account_repo, draft_repo, TEST_CONTENT_MAX_BYTES);
    let article_svc =
        ArticleServiceImpl::new(article_account_repo, article_repo, TEST_CONTENT_MAX_BYTES);

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
        .add_service(DraftServiceServer::new(draft_svc))
        .add_service(ArticleServiceServer::new(article_svc));

    tokio::spawn(async move {
        let _ = server.serve_with_incoming(stream).await;
    });

    let endpoint = Endpoint::from_shared(format!("http://{addr}"))
        .expect("endpoint")
        .connect_timeout(Duration::from_secs(5));
    let channel = endpoint.connect().await.expect("client connect");
    let drafts = DraftServiceClient::new(channel.clone());
    let articles = ArticleServiceClient::new(channel);

    Harness {
        db,
        drafts,
        articles,
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

async fn cleanup_drafts_and_articles(db: &Db, account_ids: &[Uuid]) {
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
        let _ = diesel::sql_query("DELETE FROM drafts WHERE account_id = ANY($1)")
            .bind::<diesel::sql_types::Array<diesel::sql_types::Uuid>, _>(owned_ids.clone())
            .execute(&mut conn)
            .await;
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
/// tests focused on DraftService behavior. Returns `(account_id, key_id)`.
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

async fn create_draft(
    h: &mut Harness,
    sk: &SigningKey,
    account_id: Uuid,
    key_id: Uuid,
    title: &str,
) -> Uuid {
    let req = CreateDraftRequest {
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
        "/headlines.v1.DraftService/CreateDraft",
        ts,
        &unique_nonce(),
    );
    let resp = h
        .drafts
        .create_draft(signed_req)
        .await
        .unwrap()
        .into_inner();
    Uuid::parse_str(&resp.id).unwrap()
}

// ===========================================================================
// CreateDraft
// ===========================================================================

#[tokio::test]
async fn create_draft_account_self_succeeds() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server().await;
    let sk = make_signing_key();
    let (acct, key_id) = seed_account_with_key(&h.db, &sk).await;
    let req = CreateDraftRequest {
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
        "/headlines.v1.DraftService/CreateDraft",
        ts,
        &unique_nonce(),
    );
    let resp = h
        .drafts
        .create_draft(signed_req)
        .await
        .expect("CreateDraft account-self should succeed");

    // Assert
    let draft = resp.into_inner();
    assert_eq!(draft.account_id, acct.to_string());
    assert_eq!(draft.title, "Hello");
    assert!(!draft.id.is_empty());

    cleanup_drafts_and_articles(&h.db, &[acct]).await;
}

#[tokio::test]
async fn create_draft_with_deleted_account_returns_account_deleted() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server().await;
    let sk = make_signing_key();
    let (acct, key_id) = seed_account_with_key(&h.db, &sk).await;
    delete_account_directly(&h.db, acct).await;

    let req = CreateDraftRequest {
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
        "/headlines.v1.DraftService/CreateDraft",
        ts,
        &unique_nonce(),
    );

    // Act
    let err = h
        .drafts
        .create_draft(signed_req)
        .await
        .expect_err("create on deleted account");

    // Assert
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);

    cleanup_drafts_and_articles(&h.db, &[acct]).await;
}

#[tokio::test]
async fn create_draft_missing_account_returns_account_not_found() {
    skip_if_no_db!();

    // Arrange — sign as a system to bypass account-self auth, then target
    // a non-existent account so the precondition itself fires.
    let mut h = spawn_server().await;
    let sys_sk = make_signing_key();
    let (system_id, sys_key) = insert_system(&h.db, "writer", &["drafts.write"], &sys_sk).await;
    let phantom = Uuid::now_v7();

    let req = CreateDraftRequest {
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
        "/headlines.v1.DraftService/CreateDraft",
        ts,
        &unique_nonce(),
    );

    // Act
    let err = h
        .drafts
        .create_draft(signed_req)
        .await
        .expect_err("missing account");

    // Assert
    assert_eq!(err.code(), tonic::Code::NotFound);

    cleanup_system(&h.db, system_id).await;
}

#[tokio::test]
async fn create_draft_empty_title_rejected() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server().await;
    let sk = make_signing_key();
    let (acct, key_id) = seed_account_with_key(&h.db, &sk).await;
    let req = CreateDraftRequest {
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
        "/headlines.v1.DraftService/CreateDraft",
        ts,
        &unique_nonce(),
    );

    // Act
    let err = h
        .drafts
        .create_draft(signed_req)
        .await
        .expect_err("empty title");

    // Assert
    assert_eq!(err.code(), tonic::Code::InvalidArgument);

    cleanup_drafts_and_articles(&h.db, &[acct]).await;
}

#[tokio::test]
async fn create_draft_oversize_content_returns_content_too_large() {
    skip_if_no_db!();

    // Arrange — single text node bigger than the 1 KiB cap.
    let mut h = spawn_server().await;
    let sk = make_signing_key();
    let (acct, key_id) = seed_account_with_key(&h.db, &sk).await;
    let big = Node {
        kind: Some(Kind::Text("x".repeat(3000))),
    };
    let req = CreateDraftRequest {
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
        "/headlines.v1.DraftService/CreateDraft",
        ts,
        &unique_nonce(),
    );

    // Act
    let err = h
        .drafts
        .create_draft(signed_req)
        .await
        .expect_err("oversize");

    // Assert
    assert_eq!(err.code(), tonic::Code::ResourceExhausted);

    cleanup_drafts_and_articles(&h.db, &[acct]).await;
}

#[tokio::test]
async fn create_draft_invalid_node_tag_rejected() {
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
    let req = CreateDraftRequest {
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
        "/headlines.v1.DraftService/CreateDraft",
        ts,
        &unique_nonce(),
    );

    // Act
    let err = h
        .drafts
        .create_draft(signed_req)
        .await
        .expect_err("bad tag");

    // Assert
    assert_eq!(err.code(), tonic::Code::InvalidArgument);

    cleanup_drafts_and_articles(&h.db, &[acct]).await;
}

// ===========================================================================
// GetDraft
// ===========================================================================

#[tokio::test]
async fn get_draft_account_self_succeeds() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server().await;
    let sk = make_signing_key();
    let (acct, key_id) = seed_account_with_key(&h.db, &sk).await;
    let id = create_draft(&mut h, &sk, acct, key_id, "title").await;

    let ts = h.clock.now().await.unwrap();
    let req = signed(
        GetDraftRequest { id: id.to_string() },
        &sk,
        key_id,
        "/headlines.v1.DraftService/GetDraft",
        ts,
        &unique_nonce(),
    );

    // Act
    let got = h.drafts.get_draft(req).await.unwrap().into_inner();

    // Assert
    assert_eq!(got.id, id.to_string());
    assert_eq!(got.title, "title");

    cleanup_drafts_and_articles(&h.db, &[acct]).await;
}

#[tokio::test]
async fn get_draft_non_owner_account_returns_draft_not_found() {
    skip_if_no_db!();

    // Arrange — A creates a draft, B tries to read it.
    let mut h = spawn_server().await;
    let sk_a = make_signing_key();
    let (acct_a, key_a) = seed_account_with_key(&h.db, &sk_a).await;
    let sk_b = make_signing_key();
    let (acct_b, key_b) = seed_account_with_key(&h.db, &sk_b).await;
    let id = create_draft(&mut h, &sk_a, acct_a, key_a, "private").await;

    let ts = h.clock.now().await.unwrap();
    let req = signed(
        GetDraftRequest { id: id.to_string() },
        &sk_b,
        key_b,
        "/headlines.v1.DraftService/GetDraft",
        ts,
        &unique_nonce(),
    );

    // Act
    let err = h
        .drafts
        .get_draft(req)
        .await
        .expect_err("non-owner read should be denied");

    // Assert — drafts.md says NOT_FOUND, not PERMISSION_DENIED, to avoid
    // leaking existence.
    assert_eq!(err.code(), tonic::Code::NotFound);

    cleanup_drafts_and_articles(&h.db, &[acct_a, acct_b]).await;
}

#[tokio::test]
async fn get_draft_system_with_drafts_read_succeeds() {
    skip_if_no_db!();

    // Arrange — owner creates the draft, a system with `drafts.read` reads it.
    let mut h = spawn_server().await;
    let sk = make_signing_key();
    let (acct, key_id) = seed_account_with_key(&h.db, &sk).await;
    let id = create_draft(&mut h, &sk, acct, key_id, "system-readable").await;

    let sys_sk = make_signing_key();
    let (system_id, sys_key) = insert_system(&h.db, "reader", &["drafts.read"], &sys_sk).await;

    let ts = h.clock.now().await.unwrap();
    let req = signed(
        GetDraftRequest { id: id.to_string() },
        &sys_sk,
        sys_key,
        "/headlines.v1.DraftService/GetDraft",
        ts,
        &unique_nonce(),
    );

    // Act
    let got = h.drafts.get_draft(req).await.unwrap().into_inner();

    // Assert
    assert_eq!(got.id, id.to_string());

    cleanup_drafts_and_articles(&h.db, &[acct]).await;
    cleanup_system(&h.db, system_id).await;
}

// ===========================================================================
// UpdateDraft
// ===========================================================================

#[tokio::test]
async fn update_draft_account_self_bumps_updated_at() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server().await;
    let sk = make_signing_key();
    let (acct, key_id) = seed_account_with_key(&h.db, &sk).await;
    let id = create_draft(&mut h, &sk, acct, key_id, "v1").await;

    // Read original updated_at, then sleep 20ms so the bump is observable.
    let ts0 = h.clock.now().await.unwrap();
    let original = h
        .drafts
        .get_draft(signed(
            GetDraftRequest { id: id.to_string() },
            &sk,
            key_id,
            "/headlines.v1.DraftService/GetDraft",
            ts0,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();
    let updated_before = original
        .updated_at
        .as_ref()
        .map(|t| (t.seconds, t.nanos))
        .unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;

    let req = UpdateDraftRequest {
        draft: Some(ProtoDraft {
            id: id.to_string(),
            title: "v2".into(),
            ..Default::default()
        }),
        update_mask: Some(prost_types::FieldMask {
            paths: vec!["title".into()],
        }),
    };
    let ts = h.clock.now().await.unwrap();
    let signed_req = signed(
        req,
        &sk,
        key_id,
        "/headlines.v1.DraftService/UpdateDraft",
        ts,
        &unique_nonce(),
    );

    // Act
    let updated = h
        .drafts
        .update_draft(signed_req)
        .await
        .unwrap()
        .into_inner();

    // Assert
    assert_eq!(updated.title, "v2");
    let updated_after = updated
        .updated_at
        .as_ref()
        .map(|t| (t.seconds, t.nanos))
        .unwrap();
    assert!(
        updated_after > updated_before,
        "UpdateDraft must bump updated_at",
    );

    cleanup_drafts_and_articles(&h.db, &[acct]).await;
}

#[tokio::test]
async fn update_draft_empty_mask_is_invalid_argument() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server().await;
    let sk = make_signing_key();
    let (acct, key_id) = seed_account_with_key(&h.db, &sk).await;
    let id = create_draft(&mut h, &sk, acct, key_id, "x").await;
    let req = UpdateDraftRequest {
        draft: Some(ProtoDraft {
            id: id.to_string(),
            ..Default::default()
        }),
        update_mask: Some(prost_types::FieldMask { paths: vec![] }),
    };
    let ts = h.clock.now().await.unwrap();
    let signed_req = signed(
        req,
        &sk,
        key_id,
        "/headlines.v1.DraftService/UpdateDraft",
        ts,
        &unique_nonce(),
    );

    // Act
    let err = h
        .drafts
        .update_draft(signed_req)
        .await
        .expect_err("empty mask");

    // Assert
    assert_eq!(err.code(), tonic::Code::InvalidArgument);

    cleanup_drafts_and_articles(&h.db, &[acct]).await;
}

#[tokio::test]
async fn update_draft_unallowed_mask_path_rejected() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server().await;
    let sk = make_signing_key();
    let (acct, key_id) = seed_account_with_key(&h.db, &sk).await;
    let id = create_draft(&mut h, &sk, acct, key_id, "x").await;
    let req = UpdateDraftRequest {
        draft: Some(ProtoDraft {
            id: id.to_string(),
            ..Default::default()
        }),
        update_mask: Some(prost_types::FieldMask {
            paths: vec!["account_id".into()],
        }),
    };
    let ts = h.clock.now().await.unwrap();
    let signed_req = signed(
        req,
        &sk,
        key_id,
        "/headlines.v1.DraftService/UpdateDraft",
        ts,
        &unique_nonce(),
    );

    // Act
    let err = h
        .drafts
        .update_draft(signed_req)
        .await
        .expect_err("unallowed path");

    // Assert
    assert_eq!(err.code(), tonic::Code::InvalidArgument);

    cleanup_drafts_and_articles(&h.db, &[acct]).await;
}

// ===========================================================================
// DeleteDraft
// ===========================================================================

#[tokio::test]
async fn delete_draft_hard_deletes_the_row() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server().await;
    let sk = make_signing_key();
    let (acct, key_id) = seed_account_with_key(&h.db, &sk).await;
    let id = create_draft(&mut h, &sk, acct, key_id, "to-delete").await;

    let ts = h.clock.now().await.unwrap();
    let req = signed(
        DeleteDraftRequest { id: id.to_string() },
        &sk,
        key_id,
        "/headlines.v1.DraftService/DeleteDraft",
        ts,
        &unique_nonce(),
    );

    // Act
    h.drafts.delete_draft(req).await.unwrap();

    // Assert — subsequent GetDraft returns DRAFT_NOT_FOUND.
    let ts = h.clock.now().await.unwrap();
    let get_req = signed(
        GetDraftRequest { id: id.to_string() },
        &sk,
        key_id,
        "/headlines.v1.DraftService/GetDraft",
        ts,
        &unique_nonce(),
    );
    let err = h
        .drafts
        .get_draft(get_req)
        .await
        .expect_err("deleted draft must not be found");
    assert_eq!(err.code(), tonic::Code::NotFound);

    cleanup_drafts_and_articles(&h.db, &[acct]).await;
}

// ===========================================================================
// ListAccountDrafts
// ===========================================================================

#[tokio::test]
async fn list_account_drafts_paginates_and_orders_by_updated_at_desc() {
    skip_if_no_db!();

    // Arrange — create 5 drafts in sequence; later creates have larger
    // updated_at, so updated_at DESC means newest-first.
    let mut h = spawn_server().await;
    let sk = make_signing_key();
    let (acct, key_id) = seed_account_with_key(&h.db, &sk).await;
    let mut ids = Vec::new();
    for i in 0..5 {
        let id = create_draft(&mut h, &sk, acct, key_id, &format!("Title {i}")).await;
        ids.push(id);
        // Tiny gap so updated_at is monotonic for ordering.
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // Act — pull pages of 2 (signed as account-self).
    let ts = h.clock.now().await.unwrap();
    let p1 = h
        .drafts
        .list_account_drafts(signed(
            ListAccountDraftsRequest {
                account_id: acct.to_string(),
                page_size: 2,
                page_token: String::new(),
            },
            &sk,
            key_id,
            "/headlines.v1.DraftService/ListAccountDrafts",
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();
    let ts = h.clock.now().await.unwrap();
    let p2 = h
        .drafts
        .list_account_drafts(signed(
            ListAccountDraftsRequest {
                account_id: acct.to_string(),
                page_size: 2,
                page_token: p1.next_page_token.clone(),
            },
            &sk,
            key_id,
            "/headlines.v1.DraftService/ListAccountDrafts",
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();
    let ts = h.clock.now().await.unwrap();
    let p3 = h
        .drafts
        .list_account_drafts(signed(
            ListAccountDraftsRequest {
                account_id: acct.to_string(),
                page_size: 2,
                page_token: p2.next_page_token.clone(),
            },
            &sk,
            key_id,
            "/headlines.v1.DraftService/ListAccountDrafts",
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();

    // Assert
    assert_eq!(p1.items.len(), 2);
    assert!(!p1.next_page_token.is_empty());
    assert_eq!(p2.items.len(), 2);
    assert_eq!(p3.items.len(), 1);
    assert!(p3.next_page_token.is_empty());

    // updated_at DESC: page 1 first item == ids.last() (newest first).
    assert_eq!(p1.items[0].id, ids.last().unwrap().to_string());

    cleanup_drafts_and_articles(&h.db, &[acct]).await;
}

// ===========================================================================
// PublishDraft
// ===========================================================================

#[tokio::test]
async fn publish_draft_uses_same_uuid_and_clears_the_draft() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server().await;
    let sk = make_signing_key();
    let (acct, key_id) = seed_account_with_key(&h.db, &sk).await;
    let id = create_draft(&mut h, &sk, acct, key_id, "to-publish").await;

    // Act — publish.
    let ts = h.clock.now().await.unwrap();
    let req = signed(
        PublishDraftRequest { id: id.to_string() },
        &sk,
        key_id,
        "/headlines.v1.DraftService/PublishDraft",
        ts,
        &unique_nonce(),
    );
    let article = h.drafts.publish_draft(req).await.unwrap().into_inner();

    // Assert — same UUID, state=Live, content reflects the draft.
    assert_eq!(article.id, id.to_string());
    assert_eq!(article.account_id, acct.to_string());
    assert_eq!(article.state, ArticleState::Live as i32);
    let Some(StateData::Live(live)) = &article.state_data else {
        panic!("expected live state_data");
    };
    assert_eq!(live.title, "to-publish");
    assert_eq!(live.current_version, 1);

    // Subsequent GetDraft → DRAFT_NOT_FOUND.
    let ts = h.clock.now().await.unwrap();
    let get_draft = signed(
        GetDraftRequest { id: id.to_string() },
        &sk,
        key_id,
        "/headlines.v1.DraftService/GetDraft",
        ts,
        &unique_nonce(),
    );
    let err = h
        .drafts
        .get_draft(get_draft)
        .await
        .expect_err("draft should be gone after publish");
    assert_eq!(err.code(), tonic::Code::NotFound);

    // Subsequent GetArticle returns the new live article (anonymous-readable).
    let got = h
        .articles
        .get_article(tonic::Request::new(GetArticleRequest {
            id: id.to_string(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(got.id, id.to_string());
    assert_eq!(got.state, ArticleState::Live as i32);

    cleanup_drafts_and_articles(&h.db, &[acct]).await;
}

#[tokio::test]
async fn publish_draft_concurrent_calls_serialize_loser_sees_draft_not_found() {
    skip_if_no_db!();

    // Arrange — one draft, two concurrent PublishDraft calls. Exactly one
    // wins; the other observes the post-deletion state and returns
    // DRAFT_NOT_FOUND.
    let mut h = spawn_server().await;
    let sk = make_signing_key();
    let (acct, key_id) = seed_account_with_key(&h.db, &sk).await;
    let id = create_draft(&mut h, &sk, acct, key_id, "race-me").await;

    let ts1 = h.clock.now().await.unwrap();
    let ts2 = h.clock.now().await.unwrap();
    let req1 = signed(
        PublishDraftRequest { id: id.to_string() },
        &sk,
        key_id,
        "/headlines.v1.DraftService/PublishDraft",
        ts1,
        &unique_nonce(),
    );
    let req2 = signed(
        PublishDraftRequest { id: id.to_string() },
        &sk,
        key_id,
        "/headlines.v1.DraftService/PublishDraft",
        ts2,
        &unique_nonce(),
    );

    // Act — fire both concurrently on independent client clones (spawn
    // task per call so the runtime executes them in parallel).
    let mut c1 = h.drafts.clone();
    let mut c2 = h.drafts.clone();
    let f1 = tokio::spawn(async move { c1.publish_draft(req1).await });
    let f2 = tokio::spawn(async move { c2.publish_draft(req2).await });
    let r1 = f1.await.unwrap();
    let r2 = f2.await.unwrap();

    // Assert — exactly one Ok and one NotFound.
    let oks = [r1.is_ok(), r2.is_ok()].iter().filter(|b| **b).count();
    assert_eq!(oks, 1, "exactly one PublishDraft must win the race");
    let err = if let Err(e) = r1 { e } else { r2.unwrap_err() };
    assert_eq!(err.code(), tonic::Code::NotFound);

    cleanup_drafts_and_articles(&h.db, &[acct]).await;
}
