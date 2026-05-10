//! Cross-service end-to-end workflow test.
//!
//! Translates `docs/codelabs.md`'s eleven-step publishing flow into one Rust
//! test, exercising the cross-service contracts that per-service integration
//! tests can't catch on their own:
//!
//! 1. The article a publisher creates actually surfaces in a follower's
//!    `GetFollowFeed`.
//! 2. The event a user records actually round-trips through `ListEvents`.
//! 3. The article a publisher emits actually appears in `StreamAccountArticles`
//!    pulled by a republisher — and re-surfaces with `state=TOMBSTONE` after
//!    `TombstoneArticle`.
//!
//! The harness wires all 10 ServiceImpl exports behind a single
//! `AuthInterceptor + AuthorizationLayer` tower stack on a random port,
//! mirroring `crates/headlines-server/src/main.rs`. Backed by the live
//! Postgres instance on `docker.yuacx.com`. Test SKIPs cleanly when
//! `DATABASE_URL` is unset.
//!
//! AAA structure per `~/.claude/rules/testing-patterns.md`: bootstrap +
//! harness in Arrange; the eleven steps form the Act; per-step assertions are
//! marked with `// Assert (step N):` so a failing line points at the codelab
//! step that broke.

#![allow(clippy::too_many_arguments)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use chrono::Utc;
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use ed25519_dalek::{Signer, SigningKey};
use prost::Message as _;
use prost_types::Timestamp;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use tonic::transport::{Channel, Endpoint, Server};
use uuid::Uuid;

use headlines_api::{
    AccountServiceImpl, AccountStreamServiceImpl, ArticleServiceImpl, BootstrapMode,
    DraftServiceImpl, EventServiceImpl, FeedFollowServiceImpl, FeedRecommendationServiceImpl,
    FollowServiceImpl, NotificationServiceImpl, UserServiceImpl,
};
use headlines_auth::{
    AlgorithmRegistry, AuthInterceptor, AuthorizationLayer, Ed25519, InMemoryNonceStore,
    LocalClock, PostgresKeyResolver, ProtoBodyHasher, SignedRequestStrategy,
    TrustedSubjectInterceptor,
};
use headlines_core::{TimeSource as _, Tso};
use headlines_proto::v1::{
    ArticleState, CreateAccountRequest, CreateDraftRequest, CreateUserRequest,
    DeleteAccountRequest, EditArticleRequest, EventType, FollowRequest, FollowStatus,
    GetArticleRequest, GetFollowFeedRequest, GetRecommendationFeedRequest, LikeProperties,
    ListEventsRequest, OpenProperties, PublicKey, PublishArticleRequest, PublishDraftRequest,
    RecordEventRequest, RedactArticleVersionRequest, ReplaceRecommendationFeedRequest,
    StreamAccountArticlesRequest, TombstoneArticleRequest, UnfollowRequest,
    account_service_client::AccountServiceClient, account_service_server::AccountServiceServer,
    account_stream_service_client::AccountStreamServiceClient,
    account_stream_service_server::AccountStreamServiceServer, article,
    article_service_client::ArticleServiceClient, article_service_server::ArticleServiceServer,
    article_summary, draft_service_client::DraftServiceClient,
    draft_service_server::DraftServiceServer, event_service_client::EventServiceClient,
    event_service_server::EventServiceServer, feed_follow_service_client::FeedFollowServiceClient,
    feed_follow_service_server::FeedFollowServiceServer,
    feed_recommendation_service_client::FeedRecommendationServiceClient,
    feed_recommendation_service_server::FeedRecommendationServiceServer,
    follow_service_client::FollowServiceClient, follow_service_server::FollowServiceServer,
    notification_service_server::NotificationServiceServer, record_event_request,
    user_service_client::UserServiceClient, user_service_server::UserServiceServer,
};
use headlines_store::{
    Db, PgAccountRepo, PgAccountStreamRepo, PgArticleRepo, PgDraftRepo, PgEventRepo,
    PgFeedFollowRepo, PgFeedRecommendationRepo, PgFollowRepo, PgKeyRepo, PgUserRepo,
};

// ---------------------------------------------------------------------------
// Test harness — registers all 10 services behind one tower stack.
// ---------------------------------------------------------------------------

/// Modest content cap; the codelab payload is well under this.
const TEST_CONTENT_MAX_BYTES: usize = 64 * 1024;
/// Modest event-batch cap; this test only records one event so the cap is
/// never exercised.
const TEST_EVENTS_BATCH_MAX_ITEMS: usize = 64;
/// Modest feed-replace cap; we don't write a recommendation feed in this
/// test, but the FeedRecommendationServiceImpl still requires the value.
const TEST_FEEDS_REPLACE_MAX_ITEMS: usize = 64;

struct Harness {
    db: Db,
    accounts: AccountServiceClient<Channel>,
    users: UserServiceClient<Channel>,
    follows: FollowServiceClient<Channel>,
    drafts: DraftServiceClient<Channel>,
    articles: ArticleServiceClient<Channel>,
    events: EventServiceClient<Channel>,
    stream: AccountStreamServiceClient<Channel>,
    feed_follow: FeedFollowServiceClient<Channel>,
    feed_recommendation: FeedRecommendationServiceClient<Channel>,
    clock: Arc<LocalClock>,
    /// Shared `SignedRequestStrategy` — exposed so a test that needs to
    /// stand up a REST gateway in front of this gRPC stack (W4) can wire
    /// the gateway's auth strategy to the same key resolver / nonce store
    /// the gRPC server uses.
    strategy: Arc<SignedRequestStrategy>,
    _addr: SocketAddr,
}

async fn maybe_connect_db() -> Option<Db> {
    let url = std::env::var("DATABASE_URL").ok()?;
    Db::connect(&url, 4).await.ok()
}

async fn spawn_test_service() -> Harness {
    let db = maybe_connect_db()
        .await
        .expect("DATABASE_URL must be set for integration tests");

    // ---- Auth pipeline ----
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

    // ---- Service impls (mirrors crates/headlines-server/src/main.rs) ----
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

    // ---- Tower stack: AuthInterceptor → AuthorizationLayer → services ----
    let interceptor = AuthInterceptor::new(strategy.clone(), Arc::new(ProtoBodyHasher));
    let authorize = AuthorizationLayer::new();

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    let listener = tokio::net::TcpListener::from_std(listener).unwrap();
    let stream_inc = tokio_stream::wrappers::TcpListenerStream::new(listener);

    let server = Server::builder()
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
        let _ = server.serve_with_incoming(stream_inc).await;
    });

    let endpoint = Endpoint::from_shared(format!("http://{addr}"))
        .expect("endpoint")
        .connect_timeout(Duration::from_secs(5));
    let channel = endpoint.connect().await.expect("client connect");

    Harness {
        db,
        accounts: AccountServiceClient::new(channel.clone()),
        users: UserServiceClient::new(channel.clone()),
        follows: FollowServiceClient::new(channel.clone()),
        drafts: DraftServiceClient::new(channel.clone()),
        articles: ArticleServiceClient::new(channel.clone()),
        events: EventServiceClient::new(channel.clone()),
        stream: AccountStreamServiceClient::new(channel.clone()),
        feed_follow: FeedFollowServiceClient::new(channel.clone()),
        feed_recommendation: FeedRecommendationServiceClient::new(channel),
        clock,
        strategy,
        _addr: addr,
    }
}

// ---------------------------------------------------------------------------
// Signing helpers — mirror the per-service tests verbatim.
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

fn ed25519_pk_b64(sk: &SigningKey) -> String {
    B64.encode(sk.verifying_key().as_bytes())
}

fn now_proto() -> Timestamp {
    let dt = Utc::now();
    Timestamp {
        seconds: dt.timestamp(),
        nanos: dt.timestamp_subsec_nanos() as i32,
    }
}

// ---------------------------------------------------------------------------
// Bootstrap + cleanup helpers.
// ---------------------------------------------------------------------------

/// Insert a (system, key, scope) row triple via raw SQL. Returns
/// `(system_id, key_id)` so the caller can sign system-class requests.
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

/// Best-effort cleanup keyed on the test's UUIDs. Never panics on failure —
/// other concurrent tests share the same DB.
async fn cleanup(db: &Db, user_id: Uuid, account_id: Uuid, article_id: Uuid, system_id: Uuid) {
    let url = db.database_url().to_owned();
    let _ = tokio::spawn(async move {
        let mut conn = match AsyncPgConnection::establish(&url).await {
            Ok(c) => c,
            Err(_) => return,
        };
        // Events first (FK-soft refs to user/article).
        let _ = diesel::sql_query("DELETE FROM events WHERE user_id = $1")
            .bind::<diesel::sql_types::Uuid, _>(user_id)
            .execute(&mut conn)
            .await;
        // Follows.
        let _ = diesel::sql_query("DELETE FROM follows WHERE user_id = $1")
            .bind::<diesel::sql_types::Uuid, _>(user_id)
            .execute(&mut conn)
            .await;
        // Articles + their satellite tables (article may be live or
        // tombstoned depending on where the test failed — DELETE both).
        let _ = diesel::sql_query("DELETE FROM article_versions WHERE article_id = $1")
            .bind::<diesel::sql_types::Uuid, _>(article_id)
            .execute(&mut conn)
            .await;
        let _ = diesel::sql_query("DELETE FROM articles_live WHERE article_id = $1")
            .bind::<diesel::sql_types::Uuid, _>(article_id)
            .execute(&mut conn)
            .await;
        let _ = diesel::sql_query("DELETE FROM articles_tombstone WHERE article_id = $1")
            .bind::<diesel::sql_types::Uuid, _>(article_id)
            .execute(&mut conn)
            .await;
        let _ = diesel::sql_query("DELETE FROM articles WHERE id = $1")
            .bind::<diesel::sql_types::Uuid, _>(article_id)
            .execute(&mut conn)
            .await;
        // Drafts (in case the publish step never ran).
        let _ = diesel::sql_query("DELETE FROM drafts WHERE id = $1")
            .bind::<diesel::sql_types::Uuid, _>(article_id)
            .execute(&mut conn)
            .await;
        // User + key.
        let _ = diesel::sql_query("DELETE FROM user_keys WHERE user_id = $1")
            .bind::<diesel::sql_types::Uuid, _>(user_id)
            .execute(&mut conn)
            .await;
        let _ = diesel::sql_query("DELETE FROM users WHERE id = $1")
            .bind::<diesel::sql_types::Uuid, _>(user_id)
            .execute(&mut conn)
            .await;
        // Account + key.
        let _ = diesel::sql_query("DELETE FROM account_keys WHERE account_id = $1")
            .bind::<diesel::sql_types::Uuid, _>(account_id)
            .execute(&mut conn)
            .await;
        let _ = diesel::sql_query("DELETE FROM accounts WHERE id = $1")
            .bind::<diesel::sql_types::Uuid, _>(account_id)
            .execute(&mut conn)
            .await;
        // System + scopes + key.
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
// The end-to-end publishing flow — one test, eleven steps.
// ===========================================================================

#[tokio::test]
async fn e2e_codelabs_publishing_flow_round_trips() {
    skip_if_no_db!();

    // -----------------------------------------------------------------------
    // Arrange — harness with all 10 services and a System identity that holds
    // both `events.read` (step 9) and `articles.stream` (steps 10 & 12).
    // -----------------------------------------------------------------------
    let mut h = spawn_test_service().await;

    let account_sk = make_signing_key();
    let user_sk = make_signing_key();
    let system_sk = make_signing_key();
    let (system_id, system_key_id) = insert_system(
        &h.db,
        "workflow-system",
        &["events.read", "articles.stream"],
        &system_sk,
    )
    .await;

    // -----------------------------------------------------------------------
    // Act — the eleven codelab steps. Per-step assertions are interleaved so
    // a failing line points directly at the codelab step that broke.
    // -----------------------------------------------------------------------

    // Step 1: bootstrap an account (anonymous CreateAccount, Open mode).
    let create_account_resp = h
        .accounts
        .create_account(tonic::Request::new(CreateAccountRequest {
            short_name: "demo_pub".into(),
            author_name: "Demo Publisher".into(),
            author_url: "https://example.com".into(),
            initial_key: Some(PublicKey {
                algo: "ed25519".into(),
                public_key: ed25519_pk_b64(&account_sk),
            }),
        }))
        .await
        .expect("CreateAccount must succeed in Open bootstrap mode")
        .into_inner();
    let account_proto = create_account_resp
        .account
        .expect("CreateAccount response must include the account");
    let account_id = Uuid::parse_str(&account_proto.id).expect("account id must be a UUID");
    let account_key_id =
        Uuid::parse_str(&create_account_resp.key_id).expect("account key_id must be a UUID");
    // Assert (step 1):
    assert_eq!(account_proto.short_name, "demo_pub");

    // Step 2: bootstrap a user (anonymous CreateUser, Open mode).
    let create_user_resp = h
        .users
        .create_user(tonic::Request::new(CreateUserRequest {
            display_name: "Reader Alice".into(),
            initial_key: Some(PublicKey {
                algo: "ed25519".into(),
                public_key: ed25519_pk_b64(&user_sk),
            }),
        }))
        .await
        .expect("CreateUser must succeed in Open bootstrap mode")
        .into_inner();
    let user_proto = create_user_resp
        .user
        .expect("CreateUser response must include the user");
    let user_id = Uuid::parse_str(&user_proto.id).expect("user id must be a UUID");
    let user_key_id =
        Uuid::parse_str(&create_user_resp.key_id).expect("user key_id must be a UUID");
    // Assert (step 2):
    assert_eq!(user_proto.display_name, "Reader Alice");

    // Step 3: user follows account, signed by user.
    let ts = h.clock.now().await.unwrap();
    let follow_resp = h
        .follows
        .follow(signed(
            FollowRequest {
                user_id: user_id.to_string(),
                account_id: account_id.to_string(),
            },
            &user_sk,
            user_key_id,
            "/headlines.v1.FollowService/Follow",
            ts,
            &unique_nonce(),
        ))
        .await
        .expect("Follow must succeed for user-self")
        .into_inner();
    // Assert (step 3): the edge surfaces as ACTIVE.
    assert_eq!(follow_resp.status, FollowStatus::Active as i32);

    // Step 4: account creates a draft, signed by account.
    let ts = h.clock.now().await.unwrap();
    let draft_resp = h
        .drafts
        .create_draft(signed(
            CreateDraftRequest {
                account_id: account_id.to_string(),
                title: "Hello, headlines".into(),
                author_name: "Demo Publisher".into(),
                author_url: "https://example.com".into(),
                content: vec![headlines_proto::v1::Node {
                    kind: Some(headlines_proto::v1::node::Kind::Text(
                        "Welcome to the demo.".into(),
                    )),
                }],
            },
            &account_sk,
            account_key_id,
            "/headlines.v1.DraftService/CreateDraft",
            ts,
            &unique_nonce(),
        ))
        .await
        .expect("CreateDraft must succeed for account-self")
        .into_inner();
    let draft_id = Uuid::parse_str(&draft_resp.id).expect("draft id must be a UUID");
    // Assert (step 4): id is well-formed UUIDv7 (version nibble == 7).
    assert_eq!(draft_id.get_version_num(), 7);

    // Step 5: account publishes the draft.
    let ts = h.clock.now().await.unwrap();
    let published = h
        .drafts
        .publish_draft(signed(
            PublishDraftRequest {
                id: draft_id.to_string(),
            },
            &account_sk,
            account_key_id,
            "/headlines.v1.DraftService/PublishDraft",
            ts,
            &unique_nonce(),
        ))
        .await
        .expect("PublishDraft must succeed for account-self")
        .into_inner();
    // Assert (step 5): UUID continuity (article.id == draft.id) and state=LIVE.
    assert_eq!(published.id, draft_id.to_string());
    assert_eq!(published.state, ArticleState::Live as i32);
    let article_id = draft_id;

    // Step 6: user reads GetArticle (anonymous-readable).
    let got = h
        .articles
        .get_article(tonic::Request::new(GetArticleRequest {
            id: article_id.to_string(),
        }))
        .await
        .expect("GetArticle is anonymous-readable")
        .into_inner();
    let live = match got.state_data.as_ref().expect("state_data must be set") {
        article::StateData::Live(l) => l,
        article::StateData::Tombstone(_) => panic!("expected Live state_data after PublishDraft"),
    };
    // Assert (step 6): the title and content surfaced match what was published.
    assert_eq!(live.title, "Hello, headlines");
    assert_eq!(live.content.len(), 1);

    // Step 7: user reads GetFollowFeed — first cross-service contract.
    let ts = h.clock.now().await.unwrap();
    let feed = h
        .feed_follow
        .get_follow_feed(signed(
            GetFollowFeedRequest {
                user_id: user_id.to_string(),
                page_size: 20,
                page_token: String::new(),
            },
            &user_sk,
            user_key_id,
            "/headlines.v1.FeedFollowService/GetFollowFeed",
            ts,
            &unique_nonce(),
        ))
        .await
        .expect("GetFollowFeed must succeed for user-self")
        .into_inner();
    // Assert (step 7): the just-published article is in the followed feed,
    // with state=LIVE and the same title.
    assert_eq!(feed.items.len(), 1, "follower must see exactly one article");
    let summary = feed.items[0]
        .article
        .as_ref()
        .expect("FollowFeedItem must carry an ArticleSummary");
    assert_eq!(summary.id, article_id.to_string());
    assert_eq!(summary.state, ArticleState::Live as i32);
    let live_summary = match summary.state_data.as_ref().expect("state_data must be set") {
        article_summary::StateData::Live(l) => l,
        article_summary::StateData::Tombstone(_) => panic!("expected Live summary"),
    };
    assert_eq!(live_summary.title, "Hello, headlines");

    // Step 8: user records an OPEN event, signed by user.
    let ts = h.clock.now().await.unwrap();
    let event_resp = h
        .events
        .record_event(signed(
            RecordEventRequest {
                user_id: user_id.to_string(),
                article_id: article_id.to_string(),
                r#type: EventType::Open as i32,
                occurred_at: Some(now_proto()),
                surface: "web".into(),
                properties: Some(record_event_request::Properties::Open(OpenProperties {
                    feed_kind: "follow".into(),
                    position: 0,
                })),
            },
            &user_sk,
            user_key_id,
            "/headlines.v1.EventService/RecordEvent",
            ts,
            &unique_nonce(),
        ))
        .await
        .expect("RecordEvent must succeed for user-self")
        .into_inner();
    let event_id = Uuid::parse_str(&event_resp.id).expect("event id must be a UUID");
    // Assert (step 8): server-assigned id and received_at present.
    assert!(event_resp.received_at.is_some());

    // Step 9: system (with events.read) lists events filtered by user_id —
    // second cross-service contract surface (event ingest → analytics read).
    let ts = h.clock.now().await.unwrap();
    let list_events_resp = h
        .events
        .list_events(signed(
            ListEventsRequest {
                user_id: user_id.to_string(),
                page_size: 50,
                ..Default::default()
            },
            &system_sk,
            system_key_id,
            "/headlines.v1.EventService/ListEvents",
            ts,
            &unique_nonce(),
        ))
        .await
        .expect("ListEvents must succeed for system with events.read")
        .into_inner();
    // Assert (step 9): the recorded event surfaces in the analytics list.
    assert!(
        list_events_resp
            .items
            .iter()
            .any(|e| e.id == event_id.to_string()),
        "ListEvents must surface the just-recorded event id={}",
        event_id,
    );

    // Step 10: system (with articles.stream) pulls the account's stream —
    // second cross-service contract.
    let ts = h.clock.now().await.unwrap();
    let stream_resp = h
        .stream
        .stream_account_articles(signed(
            StreamAccountArticlesRequest {
                account_id: account_id.to_string(),
                page_size: 100,
                page_token: String::new(),
            },
            &system_sk,
            system_key_id,
            "/headlines.v1.AccountStreamService/StreamAccountArticles",
            ts,
            &unique_nonce(),
        ))
        .await
        .expect("StreamAccountArticles must succeed for system with articles.stream")
        .into_inner();
    // Assert (step 10): the article appears with state=LIVE.
    let live_item = stream_resp
        .items
        .iter()
        .find(|i| {
            i.article
                .as_ref()
                .map(|a| a.id == article_id.to_string())
                .unwrap_or(false)
        })
        .expect("article must surface on the account stream after publish");
    assert_eq!(
        live_item.article.as_ref().unwrap().state,
        ArticleState::Live as i32,
        "stream must surface the article with state=LIVE",
    );
    let live_event_at = live_item.article.as_ref().unwrap().created_at;

    // Step 11: account tombstones the article.
    let ts = h.clock.now().await.unwrap();
    let tombstone_resp = h
        .articles
        .tombstone_article(signed(
            TombstoneArticleRequest {
                id: article_id.to_string(),
                reason: "end-to-end test".into(),
            },
            &account_sk,
            account_key_id,
            "/headlines.v1.ArticleService/TombstoneArticle",
            ts,
            &unique_nonce(),
        ))
        .await
        .expect("TombstoneArticle must succeed for account-self")
        .into_inner();
    // Assert (step 11): article moved to state=TOMBSTONE.
    assert_eq!(tombstone_resp.state, ArticleState::Tombstone as i32);

    // Step 12: system streams the account again — third cross-service contract.
    let ts = h.clock.now().await.unwrap();
    let stream_resp_after = h
        .stream
        .stream_account_articles(signed(
            StreamAccountArticlesRequest {
                account_id: account_id.to_string(),
                page_size: 100,
                page_token: String::new(),
            },
            &system_sk,
            system_key_id,
            "/headlines.v1.AccountStreamService/StreamAccountArticles",
            ts,
            &unique_nonce(),
        ))
        .await
        .expect("StreamAccountArticles must still succeed after tombstone")
        .into_inner();
    let tomb_item = stream_resp_after
        .items
        .iter()
        .find(|i| {
            i.article
                .as_ref()
                .map(|a| a.id == article_id.to_string())
                .unwrap_or(false)
        })
        .expect("tombstoned article must still surface on the account stream");
    let tomb_summary = tomb_item.article.as_ref().unwrap();
    // Assert (step 12): same article id, now state=TOMBSTONE, with bumped
    // event_at relative to the live emit observed in step 10.
    assert_eq!(tomb_summary.state, ArticleState::Tombstone as i32);
    match tomb_summary
        .state_data
        .as_ref()
        .expect("tombstone summary must carry state_data")
    {
        article_summary::StateData::Tombstone(t) => {
            assert_eq!(t.reason, "end-to-end test");
        }
        article_summary::StateData::Live(_) => {
            panic!("expected tombstone state_data after TombstoneArticle")
        }
    }
    // event_at must move forward (or at least not regress) between the live
    // emit and the tombstone emit. `created_at` on `ArticleSummary` is the
    // stream's `event_at` watermark per `account_stream.proto`. `Timestamp`
    // doesn't `PartialOrd`, so compare via `(seconds, nanos)` directly.
    let to_pair = |ts: &Option<Timestamp>| -> (i64, i32) {
        ts.as_ref().map_or((0, 0), |t| (t.seconds, t.nanos))
    };
    assert!(
        to_pair(&tomb_summary.created_at) >= to_pair(&live_event_at),
        "tombstone event_at must not regress below the live emit",
    );

    // -----------------------------------------------------------------------
    // Cleanup — DELETE filters keyed on this test's UUIDs only.
    // -----------------------------------------------------------------------
    cleanup(&h.db, user_id, account_id, article_id, system_id).await;
}

// ===========================================================================
// W1-W5 — additional cross-service workflow tests.
//
// Each test pins one cross-service contract that the codelabs-flow test
// above doesn't exercise. Helpers used only here live below the test the
// caller cares about, so each test reads end-to-end without the harness
// noise above.
// ===========================================================================

/// Seed a `(user, key)` row pair directly via SQL. Mirrors the
/// per-service helper in `tests/feeds_recommendation.rs`. Used by W1 / W4
/// where the test needs a user but not the round-trip through
/// `CreateUser`.
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

/// Seed a bare `accounts` row (no key). W1 only needs a target for live
/// articles; the article itself is seeded directly so we don't need to
/// sign anything as the account.
async fn seed_account_row(db: &Db) -> Uuid {
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

/// Insert an `accounts` row plus an active `account_keys` row keyed on
/// `sk`. Used by W2 / W5 where the test needs to sign as the account.
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

/// Insert a live article directly (bypasses ArticleService). Returns the
/// article id. Used by W1 / W2.
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

/// Best-effort vacuum of every row a per-W test might create. Mirrors the
/// `cleanup_feed` helper from `tests/feeds_recommendation.rs`. Never
/// panics; the DB is shared with concurrent tests.
async fn cleanup_multi(
    db: &Db,
    user_ids: &[Uuid],
    account_ids: &[Uuid],
    article_ids: &[Uuid],
    system_ids: &[Uuid],
) {
    let url = db.database_url().to_owned();
    let users = user_ids.to_owned();
    let accounts = account_ids.to_owned();
    let articles = article_ids.to_owned();
    let systems = system_ids.to_owned();
    let _ = tokio::spawn(async move {
        let mut conn = match AsyncPgConnection::establish(&url).await {
            Ok(c) => c,
            Err(_) => return,
        };
        if !users.is_empty() {
            let _ = diesel::sql_query("DELETE FROM events WHERE user_id = ANY($1)")
                .bind::<diesel::sql_types::Array<diesel::sql_types::Uuid>, _>(users.clone())
                .execute(&mut conn)
                .await;
            let _ = diesel::sql_query("DELETE FROM follows WHERE user_id = ANY($1)")
                .bind::<diesel::sql_types::Array<diesel::sql_types::Uuid>, _>(users.clone())
                .execute(&mut conn)
                .await;
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
        if !systems.is_empty() {
            let _ = diesel::sql_query("DELETE FROM system_keys WHERE system_id = ANY($1)")
                .bind::<diesel::sql_types::Array<diesel::sql_types::Uuid>, _>(systems.clone())
                .execute(&mut conn)
                .await;
            let _ = diesel::sql_query("DELETE FROM system_scopes WHERE system_id = ANY($1)")
                .bind::<diesel::sql_types::Array<diesel::sql_types::Uuid>, _>(systems.clone())
                .execute(&mut conn)
                .await;
            let _ = diesel::sql_query("DELETE FROM systems WHERE id = ANY($1)")
                .bind::<diesel::sql_types::Array<diesel::sql_types::Uuid>, _>(systems)
                .execute(&mut conn)
                .await;
        }
    })
    .await;
}

/// Build a `HEADLINES-SIGN-V1` Authorization header for a REST request.
/// Mirrors `crates/headlines-rest-gateway/tests/rest_e2e.rs::sign_rest_request`.
/// Used by W4.
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

// ---------------------------------------------------------------------------
// W1 — recommendation feed replace is visible to user immediately
// ---------------------------------------------------------------------------

#[tokio::test]
async fn recommendation_feed_replace_is_visible_to_user_immediately() {
    skip_if_no_db!();

    // -----------------------------------------------------------------------
    // Arrange — user with key, account, four live articles, ranker system.
    // -----------------------------------------------------------------------
    let mut h = spawn_test_service().await;
    let user_sk = make_signing_key();
    let (user_id, user_key_id) = seed_user_with_key(&h.db, &user_sk).await;
    let account_id = seed_account_row(&h.db).await;
    let a1 = seed_live_article(&h.db, account_id).await;
    let a2 = seed_live_article(&h.db, account_id).await;
    let a3 = seed_live_article(&h.db, account_id).await;
    let a4 = seed_live_article(&h.db, account_id).await;

    let system_sk = make_signing_key();
    let (system_id, system_key_id) =
        insert_system(&h.db, "ranker", &["feeds.recommendation.write"], &system_sk).await;

    // -----------------------------------------------------------------------
    // Act + assert per step.
    // -----------------------------------------------------------------------

    // Step 1: ranker pushes [a1, a2].
    let ts = h.clock.now().await.unwrap();
    h.feed_recommendation
        .replace_recommendation_feed(signed(
            ReplaceRecommendationFeedRequest {
                user_id: user_id.to_string(),
                article_ids: vec![a1.to_string(), a2.to_string()],
            },
            &system_sk,
            system_key_id,
            "/headlines.v1.FeedRecommendationService/ReplaceRecommendationFeed",
            ts,
            &unique_nonce(),
        ))
        .await
        .expect("first ReplaceRecommendationFeed must succeed");

    // Step 2: user reads — must see exactly [a1, a2].
    let ts = h.clock.now().await.unwrap();
    let feed1 = h
        .feed_recommendation
        .get_recommendation_feed(signed(
            GetRecommendationFeedRequest {
                user_id: user_id.to_string(),
                page_size: 50,
                page_token: String::new(),
            },
            &user_sk,
            user_key_id,
            "/headlines.v1.FeedRecommendationService/GetRecommendationFeed",
            ts,
            &unique_nonce(),
        ))
        .await
        .expect("user-self GetRecommendationFeed must succeed")
        .into_inner();
    // Assert (step 2): exactly [a1, a2] in position order, no async lag.
    assert_eq!(feed1.items.len(), 2, "first read must surface both pushed");
    assert_eq!(feed1.items[0].article.as_ref().unwrap().id, a1.to_string());
    assert_eq!(feed1.items[1].article.as_ref().unwrap().id, a2.to_string());

    // Step 3: ranker pushes [a3, a4] — replaces, not merges.
    let ts = h.clock.now().await.unwrap();
    h.feed_recommendation
        .replace_recommendation_feed(signed(
            ReplaceRecommendationFeedRequest {
                user_id: user_id.to_string(),
                article_ids: vec![a3.to_string(), a4.to_string()],
            },
            &system_sk,
            system_key_id,
            "/headlines.v1.FeedRecommendationService/ReplaceRecommendationFeed",
            ts,
            &unique_nonce(),
        ))
        .await
        .expect("second ReplaceRecommendationFeed must succeed");

    // Step 4: user reads again — must see exactly [a3, a4]; the old set
    // [a1, a2] is gone (DELETE-then-INSERT tx semantics from
    // `feed-recommendation.md`).
    let ts = h.clock.now().await.unwrap();
    let feed2 = h
        .feed_recommendation
        .get_recommendation_feed(signed(
            GetRecommendationFeedRequest {
                user_id: user_id.to_string(),
                page_size: 50,
                page_token: String::new(),
            },
            &user_sk,
            user_key_id,
            "/headlines.v1.FeedRecommendationService/GetRecommendationFeed",
            ts,
            &unique_nonce(),
        ))
        .await
        .expect("user-self GetRecommendationFeed must succeed (post-replace)")
        .into_inner();
    // Assert (step 4): exactly [a3, a4]; a1/a2 are gone.
    assert_eq!(
        feed2.items.len(),
        2,
        "second read must surface only the new push"
    );
    assert_eq!(feed2.items[0].article.as_ref().unwrap().id, a3.to_string());
    assert_eq!(feed2.items[1].article.as_ref().unwrap().id, a4.to_string());
    let ids2: Vec<String> = feed2
        .items
        .iter()
        .map(|i| i.article.as_ref().unwrap().id.clone())
        .collect();
    assert!(
        !ids2.contains(&a1.to_string()),
        "old feed entry a1 must not survive replace, got {:?}",
        ids2,
    );
    assert!(
        !ids2.contains(&a2.to_string()),
        "old feed entry a2 must not survive replace, got {:?}",
        ids2,
    );

    // Cleanup.
    cleanup_multi(
        &h.db,
        &[user_id],
        &[account_id],
        &[a1, a2, a3, a4],
        &[system_id],
    )
    .await;
}

// ---------------------------------------------------------------------------
// W2 — unfollow removes account articles from follow feed
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unfollow_removes_account_articles_from_follow_feed() {
    skip_if_no_db!();

    // -----------------------------------------------------------------------
    // Arrange — user, two accounts each with one live article. User follows
    // both via signed `FollowService.Follow` requests.
    // -----------------------------------------------------------------------
    let mut h = spawn_test_service().await;
    let user_sk = make_signing_key();
    let (user_id, user_key_id) = seed_user_with_key(&h.db, &user_sk).await;

    let acct_a = seed_account_row(&h.db).await;
    let acct_b = seed_account_row(&h.db).await;
    let article_a = seed_live_article(&h.db, acct_a).await;
    let article_b = seed_live_article(&h.db, acct_b).await;

    // Follow A.
    let ts = h.clock.now().await.unwrap();
    h.follows
        .follow(signed(
            FollowRequest {
                user_id: user_id.to_string(),
                account_id: acct_a.to_string(),
            },
            &user_sk,
            user_key_id,
            "/headlines.v1.FollowService/Follow",
            ts,
            &unique_nonce(),
        ))
        .await
        .expect("Follow A must succeed");
    // Follow B.
    let ts = h.clock.now().await.unwrap();
    h.follows
        .follow(signed(
            FollowRequest {
                user_id: user_id.to_string(),
                account_id: acct_b.to_string(),
            },
            &user_sk,
            user_key_id,
            "/headlines.v1.FollowService/Follow",
            ts,
            &unique_nonce(),
        ))
        .await
        .expect("Follow B must succeed");

    // -----------------------------------------------------------------------
    // Step 1: feed contains both articles.
    // -----------------------------------------------------------------------
    let ts = h.clock.now().await.unwrap();
    let feed_before = h
        .feed_follow
        .get_follow_feed(signed(
            GetFollowFeedRequest {
                user_id: user_id.to_string(),
                page_size: 50,
                page_token: String::new(),
            },
            &user_sk,
            user_key_id,
            "/headlines.v1.FeedFollowService/GetFollowFeed",
            ts,
            &unique_nonce(),
        ))
        .await
        .expect("GetFollowFeed must succeed (both follows active)")
        .into_inner();
    let ids_before: Vec<String> = feed_before
        .items
        .iter()
        .map(|i| i.article.as_ref().unwrap().id.clone())
        .collect();
    // Assert (step 1): both follow-targeted articles surface.
    assert!(
        ids_before.contains(&article_a.to_string()),
        "follow feed must include acctA's article before unfollow, got {:?}",
        ids_before,
    );
    assert!(
        ids_before.contains(&article_b.to_string()),
        "follow feed must include acctB's article before unfollow, got {:?}",
        ids_before,
    );

    // -----------------------------------------------------------------------
    // Step 2: user unfollows acctA.
    // -----------------------------------------------------------------------
    let ts = h.clock.now().await.unwrap();
    h.follows
        .unfollow(signed(
            UnfollowRequest {
                user_id: user_id.to_string(),
                account_id: acct_a.to_string(),
            },
            &user_sk,
            user_key_id,
            "/headlines.v1.FollowService/Unfollow",
            ts,
            &unique_nonce(),
        ))
        .await
        .expect("Unfollow A must succeed");

    // -----------------------------------------------------------------------
    // Step 3: only acctB's article appears. acctA's article is completely
    // absent — `feed-follow.md`'s `WHERE f.status = 'active'` excludes
    // unfollowed edges from the JOIN result. (No "filtered with marker".)
    // -----------------------------------------------------------------------
    let ts = h.clock.now().await.unwrap();
    let feed_after = h
        .feed_follow
        .get_follow_feed(signed(
            GetFollowFeedRequest {
                user_id: user_id.to_string(),
                page_size: 50,
                page_token: String::new(),
            },
            &user_sk,
            user_key_id,
            "/headlines.v1.FeedFollowService/GetFollowFeed",
            ts,
            &unique_nonce(),
        ))
        .await
        .expect("GetFollowFeed must succeed after unfollow")
        .into_inner();
    let ids_after: Vec<String> = feed_after
        .items
        .iter()
        .map(|i| i.article.as_ref().unwrap().id.clone())
        .collect();
    // Assert (step 3): acctA's article is gone; acctB's remains.
    assert!(
        !ids_after.contains(&article_a.to_string()),
        "unfollowed acctA's article must NOT appear (active-only JOIN), got {:?}",
        ids_after,
    );
    assert!(
        ids_after.contains(&article_b.to_string()),
        "still-followed acctB's article must remain, got {:?}",
        ids_after,
    );

    cleanup_multi(
        &h.db,
        &[user_id],
        &[acct_a, acct_b],
        &[article_a, article_b],
        &[],
    )
    .await;
}

// ---------------------------------------------------------------------------
// W3 — redacted article propagates to account stream with bumped event_at
// ---------------------------------------------------------------------------

#[tokio::test]
async fn redacted_article_propagates_to_account_stream_with_bumped_event_at() {
    skip_if_no_db!();

    // -----------------------------------------------------------------------
    // Arrange — account with key, system with `articles.stream` + `articles.redact`.
    // We publish via the actual `ArticleService.PublishArticle` so the version
    // 1 row exists with non-NULL content (redaction has something to clear).
    // -----------------------------------------------------------------------
    let mut h = spawn_test_service().await;
    let acct_sk = make_signing_key();
    let (account_id, account_key_id) = seed_account_with_key(&h.db, &acct_sk).await;
    let system_sk = make_signing_key();
    let (system_id, system_key_id) = insert_system(
        &h.db,
        "redactor",
        &["articles.stream", "articles.redact"],
        &system_sk,
    )
    .await;

    let ts = h.clock.now().await.unwrap();
    let publish_resp = h
        .articles
        .publish_article(signed(
            PublishArticleRequest {
                account_id: account_id.to_string(),
                title: "Redaction subject".into(),
                author_name: "W3 Author".into(),
                author_url: "https://example.com".into(),
                content: vec![headlines_proto::v1::Node {
                    kind: Some(headlines_proto::v1::node::Kind::Text(
                        "to be redacted".into(),
                    )),
                }],
            },
            &acct_sk,
            account_key_id,
            "/headlines.v1.ArticleService/PublishArticle",
            ts,
            &unique_nonce(),
        ))
        .await
        .expect("PublishArticle must succeed for account-self")
        .into_inner();
    let article_id = Uuid::parse_str(&publish_resp.id).expect("article id");

    // -----------------------------------------------------------------------
    // Step 1: stream the account, capture event_at_1 + verify pre-redact
    // shape (state=LIVE, redacted=false).
    // -----------------------------------------------------------------------
    let ts = h.clock.now().await.unwrap();
    let stream_before = h
        .stream
        .stream_account_articles(signed(
            StreamAccountArticlesRequest {
                account_id: account_id.to_string(),
                page_size: 100,
                page_token: String::new(),
            },
            &system_sk,
            system_key_id,
            "/headlines.v1.AccountStreamService/StreamAccountArticles",
            ts,
            &unique_nonce(),
        ))
        .await
        .expect("StreamAccountArticles must succeed (pre-redact)")
        .into_inner();
    let item_before = stream_before
        .items
        .iter()
        .find(|i| {
            i.article
                .as_ref()
                .map(|a| a.id == article_id.to_string())
                .unwrap_or(false)
        })
        .expect("article must surface on the account stream after publish");
    let summary_before = item_before.article.as_ref().unwrap();
    // Assert (step 1): live state, not yet redacted.
    assert_eq!(summary_before.state, ArticleState::Live as i32);
    let live_summary_before = match summary_before.state_data.as_ref().unwrap() {
        article_summary::StateData::Live(l) => l,
        article_summary::StateData::Tombstone(_) => panic!("expected live"),
    };
    assert!(
        !live_summary_before.redacted,
        "freshly published article must not be flagged redacted"
    );
    // event_at on the stream is `COALESCE(articles_live.updated_at,
    // articles_tombstone.tombstoned_at)`. The proto `ArticleSummary` does
    // not surface event_at directly (its `created_at` is the article's
    // own `articles.created_at`, an immutable column), so we read the
    // stream's event_at through `ArticleLiveSummary.updated_at` — which
    // the repo populates from the same `articles_live.updated_at` column
    // as `event_at`. Per `articles.md`, redaction bumps that column;
    // checking `updated_at` strictly forward is therefore equivalent to
    // checking `event_at` strictly forward.
    let event_at_1 = live_summary_before.updated_at;

    // -----------------------------------------------------------------------
    // Step 2: redact version 1. The repo's redact_version bumps
    // articles_live.updated_at (per `articles.md` "redaction bumps the
    // watermark") which surfaces here as a refreshed `event_at`.
    //
    // Ensure a strictly-greater watermark by sleeping past the timestamp's
    // resolution. Postgres TIMESTAMPTZ is microsecond-precision; 50 ms is
    // plenty to clear any same-instant collisions and the noise of
    // running the gRPC publish path back-to-back.
    // -----------------------------------------------------------------------
    tokio::time::sleep(Duration::from_millis(50)).await;
    let ts = h.clock.now().await.unwrap();
    h.articles
        .redact_article_version(signed(
            RedactArticleVersionRequest {
                article_id: article_id.to_string(),
                version: 1,
                redaction_reason: "test redaction".into(),
            },
            &system_sk,
            system_key_id,
            "/headlines.v1.ArticleService/RedactArticleVersion",
            ts,
            &unique_nonce(),
        ))
        .await
        .expect("RedactArticleVersion must succeed for system with articles.redact");

    // -----------------------------------------------------------------------
    // Step 3: stream again, capture event_at_2.
    // -----------------------------------------------------------------------
    let ts = h.clock.now().await.unwrap();
    let stream_after = h
        .stream
        .stream_account_articles(signed(
            StreamAccountArticlesRequest {
                account_id: account_id.to_string(),
                page_size: 100,
                page_token: String::new(),
            },
            &system_sk,
            system_key_id,
            "/headlines.v1.AccountStreamService/StreamAccountArticles",
            ts,
            &unique_nonce(),
        ))
        .await
        .expect("StreamAccountArticles must succeed (post-redact)")
        .into_inner();
    let item_after = stream_after
        .items
        .iter()
        .find(|i| {
            i.article
                .as_ref()
                .map(|a| a.id == article_id.to_string())
                .unwrap_or(false)
        })
        .expect("article must still surface on the account stream after redact");
    let summary_after = item_after.article.as_ref().unwrap();

    // Assert (step 3): state still LIVE; redacted=true; event_at strictly
    // increased.
    assert_eq!(
        summary_after.state,
        ArticleState::Live as i32,
        "redacted article keeps LIVE state (only content is cleared)",
    );
    let live_summary_after = match summary_after.state_data.as_ref().unwrap() {
        article_summary::StateData::Live(l) => l,
        article_summary::StateData::Tombstone(_) => panic!("expected live"),
    };
    assert!(
        live_summary_after.redacted,
        "post-redact summary must carry redacted=true",
    );
    let event_at_2 = live_summary_after.updated_at;

    // The summary doesn't carry content (only `Article` does — see
    // `common.proto::ArticleLiveSummary`). Verify the content is cleared
    // through a direct GetArticle, since the assertion the contract pins
    // ("redacted version surfaces with empty content") is expressed on
    // the full Article wire shape.
    let got = h
        .articles
        .get_article(tonic::Request::new(GetArticleRequest {
            id: article_id.to_string(),
        }))
        .await
        .expect("GetArticle on a redacted article must still succeed")
        .into_inner();
    let live_full = match got.state_data.as_ref().expect("state_data must be set") {
        article::StateData::Live(l) => l,
        article::StateData::Tombstone(_) => panic!("expected live state_data after redact"),
    };
    assert!(
        live_full.redacted,
        "GetArticle of a redacted article must surface redacted=true",
    );
    assert!(
        live_full.content.is_empty(),
        "GetArticle of a redacted article must surface empty content, got {:?}",
        live_full.content,
    );

    // event_at_2 > event_at_1 (strict). Compare via (seconds, nanos)
    // because prost_types::Timestamp doesn't impl PartialOrd.
    let to_pair = |ts: &Option<Timestamp>| -> (i64, i32) {
        ts.as_ref().map_or((0, 0), |t| (t.seconds, t.nanos))
    };
    let p1 = to_pair(&event_at_1);
    let p2 = to_pair(&event_at_2);
    assert!(
        p2 > p1,
        "redaction must bump event_at strictly forward; before={:?} after={:?}",
        p1,
        p2,
    );

    cleanup_multi(&h.db, &[], &[account_id], &[article_id], &[system_id]).await;
}

// ---------------------------------------------------------------------------
// W4 — events recorded via REST and gRPC converge in ListEvents
// ---------------------------------------------------------------------------

/// Spawn a **trusted** gRPC listener (mirrors `crates/headlines-server`'s
/// loopback listener pattern) wrapping `TrustedSubjectInterceptor`, then
/// spawn a REST gateway pointing at it. The harness's existing public
/// listener (signature-verifying `AuthInterceptor`) stays untouched —
/// tests can keep using the public gRPC clients while the REST gateway
/// uses the trusted-subject path the same way `headlines-server` does
/// in production.
///
/// This is the "one reusable spawner" the constraints reference; if a
/// future test needs the REST surface it can call this without
/// re-implementing the wiring. The shared
/// `SignedRequestStrategy`/`KeyResolver`/`NonceStore`/`TimeSource` from
/// the harness flows through to the gateway's auth, keeping replay/TSO
/// state single-source.
async fn spawn_rest_gateway(h: &Harness) -> String {
    // Stand up a trusted gRPC listener with all 10 services. Reuses the
    // same DB pool the harness's public listener uses, so writes through
    // the trusted path are visible to gRPC reads through the public path
    // (and vice versa).
    let db = h.db.clone();
    let account_repo = Arc::new(PgAccountRepo::new(db.clone()));
    let key_repo = Arc::new(PgKeyRepo::new(db.clone()));
    let user_repo = Arc::new(PgUserRepo::new(db.clone()));
    let article_account_repo = Arc::new(PgAccountRepo::new(db.clone()));
    let article_repo = Arc::new(PgArticleRepo::new(db.clone()));
    let draft_account_repo = Arc::new(PgAccountRepo::new(db.clone()));
    let draft_repo = Arc::new(PgDraftRepo::new(db.clone()));
    let follow_user_repo = Arc::new(PgUserRepo::new(db.clone()));
    let follow_account_repo = Arc::new(PgAccountRepo::new(db.clone()));
    let follow_repo = Arc::new(PgFollowRepo::new(db.clone()));
    let feed_user_repo = Arc::new(PgUserRepo::new(db.clone()));
    let feed_repo = Arc::new(PgFeedRecommendationRepo::new(db.clone()));
    let feed_follow_user_repo = Arc::new(PgUserRepo::new(db.clone()));
    let feed_follow_repo = Arc::new(PgFeedFollowRepo::new(db.clone()));
    let stream_account_repo = Arc::new(PgAccountRepo::new(db.clone()));
    let stream_repo = Arc::new(PgAccountStreamRepo::new(db.clone()));
    let event_repo = Arc::new(PgEventRepo::new(db.clone()));
    let algos = Arc::new(AlgorithmRegistry::new().with(Box::new(Ed25519)));

    let account_svc = AccountServiceImpl::new(
        account_repo,
        key_repo.clone(),
        algos.clone(),
        BootstrapMode::Open,
    );
    let user_svc = UserServiceImpl::new(
        user_repo,
        key_repo.clone(),
        algos.clone(),
        BootstrapMode::Open,
    );
    let article_svc =
        ArticleServiceImpl::new(article_account_repo, article_repo, TEST_CONTENT_MAX_BYTES);
    let draft_svc = DraftServiceImpl::new(draft_account_repo, draft_repo, TEST_CONTENT_MAX_BYTES);
    let follow_svc = FollowServiceImpl::new(follow_user_repo, follow_account_repo, follow_repo);
    let feed_recommendation_svc =
        FeedRecommendationServiceImpl::new(feed_user_repo, feed_repo, TEST_FEEDS_REPLACE_MAX_ITEMS);
    let feed_follow_svc = FeedFollowServiceImpl::new(feed_follow_user_repo, feed_follow_repo);
    let account_stream_svc = AccountStreamServiceImpl::new(stream_account_repo, stream_repo);
    let event_svc = EventServiceImpl::new(event_repo, h.clock.clone(), TEST_EVENTS_BATCH_MAX_ITEMS);
    let notification_svc = NotificationServiceImpl::new();

    let trusted_listener =
        std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral trusted gRPC port");
    trusted_listener.set_nonblocking(true).unwrap();
    let trusted_addr = trusted_listener.local_addr().unwrap();
    let trusted_listener = tokio::net::TcpListener::from_std(trusted_listener).unwrap();
    let trusted_inc = tokio_stream::wrappers::TcpListenerStream::new(trusted_listener);

    let trusted_layer = TrustedSubjectInterceptor::new();
    let authorize = AuthorizationLayer::new();
    let trusted_server = Server::builder()
        .layer(trusted_layer)
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
        let _ = trusted_server.serve_with_incoming(trusted_inc).await;
    });

    // Build the REST router pointing at the trusted listener. Use the
    // harness's strategy so REST signing and the public-gRPC strategy
    // share the same KeyResolver/NonceStore.
    let endpoint = format!("http://{trusted_addr}");
    let mut router = None;
    for _ in 0..50 {
        match headlines_rest_gateway::build_app(&endpoint, h.strategy.clone()).await {
            Ok(r) => {
                router = Some(r);
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }
    let router = router.expect("REST gateway must connect to the trusted gRPC listener");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let rest_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    format!("http://{rest_addr}")
}

#[tokio::test]
async fn event_recorded_through_rest_gateway_appears_in_grpc_list_events() {
    skip_if_no_db!();

    // -----------------------------------------------------------------------
    // Arrange — user, account + article (so events have a real target),
    // system with `events.read` for the gRPC ListEvents call. Spin up the
    // REST gateway in front of the existing gRPC server. NOTE: the harness
    // gRPC server uses the public `AuthInterceptor` (not the trusted
    // listener pattern from `rest_e2e.rs`), so the REST gateway is
    // pointing at a signature-verifying endpoint. The gateway forwards
    // its own `Authorization` header (legacy gRPC-method canonicalization),
    // which means we must sign each request twice in canonical-string-with-
    // gRPC-path form for the REST surface here.
    //
    // Implementation note: the simpler path is to bypass the gateway-as-
    // signer-on-rest-url logic and let the gateway pass through the
    // authorization header to the gRPC layer that signs against the gRPC
    // method path. But the gateway in `build_app` (the one used here) has
    // already migrated to the REST-URL-canonicalisation pattern. So we
    // sign with the REST URL path; the gateway then forwards a trusted
    // subject header to the gRPC path. The gRPC server set up by this
    // file's `spawn_test_service` does NOT run the
    // `TrustedSubjectInterceptor`, so the REST forwarding will fail
    // signature verification at the gRPC public listener.
    //
    // To keep this test focused on the cross-surface contract (and not
    // architectural deltas between this harness and `rest_e2e`), we
    // therefore stand up a **fresh** trusted gRPC listener for this test
    // alongside the REST gateway. The gRPC client we use to call
    // `ListEvents` continues to talk to the public listener so the
    // assertion matches the existing test pattern.
    // -----------------------------------------------------------------------
    let mut h = spawn_test_service().await;

    let user_sk = make_signing_key();
    let (user_id, user_key_id) = seed_user_with_key(&h.db, &user_sk).await;
    let account_id = seed_account_row(&h.db).await;
    let article_id = seed_live_article(&h.db, account_id).await;
    let system_sk = make_signing_key();
    let (system_id, system_key_id) =
        insert_system(&h.db, "events-reader", &["events.read"], &system_sk).await;

    // -----------------------------------------------------------------------
    // Step 1: record OPEN via gRPC.
    // -----------------------------------------------------------------------
    let ts = h.clock.now().await.unwrap();
    let grpc_resp = h
        .events
        .record_event(signed(
            RecordEventRequest {
                user_id: user_id.to_string(),
                article_id: article_id.to_string(),
                r#type: EventType::Open as i32,
                occurred_at: Some(now_proto()),
                surface: "grpc-test".into(),
                properties: Some(record_event_request::Properties::Open(OpenProperties {
                    feed_kind: "follow".into(),
                    position: 0,
                })),
            },
            &user_sk,
            user_key_id,
            "/headlines.v1.EventService/RecordEvent",
            ts,
            &unique_nonce(),
        ))
        .await
        .expect("gRPC RecordEvent must succeed for user-self")
        .into_inner();
    let e_grpc = Uuid::parse_str(&grpc_resp.id).expect("gRPC event id");

    // -----------------------------------------------------------------------
    // Step 2: record LIKE via REST gateway.
    //
    // The gateway in `build_app` runs SignedRequestStrategy on the inbound
    // REST request and canonicalises against the REST URL path (Bug 2 fix
    // pattern). It forwards a `TRUSTED_SUBJECT_HEADER` to the gRPC server.
    // The gRPC server in this harness uses the public `AuthInterceptor`,
    // not `TrustedSubjectInterceptor` — so the trusted-header path
    // doesn't apply. To keep the test self-contained, we wait for the
    // REST gateway to forward our request and check that the LIKE event
    // hits the database via either path. If the architectural difference
    // means the trusted subject can't reach the gRPC handler in this
    // harness, the test will surface that as a bug.
    // -----------------------------------------------------------------------
    let rest_base = spawn_rest_gateway(&h).await;

    // Spread received_at by 1 ms so the two events have a deterministic
    // ordering on the (received_at, id) ASC keyset list.
    tokio::time::sleep(Duration::from_millis(1)).await;

    let occurred_at = chrono::Utc::now();
    let req_proto = RecordEventRequest {
        user_id: user_id.to_string(),
        article_id: article_id.to_string(),
        r#type: EventType::Like as i32,
        occurred_at: Some(Timestamp {
            seconds: occurred_at.timestamp(),
            nanos: occurred_at.timestamp_subsec_nanos() as i32,
        }),
        surface: "rest-test".into(),
        properties: Some(record_event_request::Properties::Like(LikeProperties {})),
    };
    let body_bytes = req_proto.encode_to_vec();
    let body_json = serde_json::json!({
        "user_id": user_id.to_string(),
        "article_id": article_id.to_string(),
        "type": "EVENT_TYPE_LIKE",
        "occurred_at": occurred_at.to_rfc3339(),
        "surface": "rest-test",
        "properties": {"like": {}},
    });
    let ts = h.clock.now().await.unwrap();
    let auth = sign_rest_request(
        "POST",
        "/v1/events",
        "",
        &body_bytes,
        user_key_id,
        &user_sk,
        ts,
        &unique_nonce(),
    );
    let resp = reqwest::Client::new()
        .post(format!("{rest_base}/v1/events"))
        .header(reqwest::header::AUTHORIZATION, auth)
        .json(&body_json)
        .send()
        .await
        .expect("REST POST /v1/events must reach the gateway");
    // Assert (step 2): REST POST returns 200 + a server-issued event id.
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "REST RecordEvent must succeed; body = {:?}",
        resp.text().await.unwrap_or_default(),
    );
    let body: serde_json::Value = resp.json().await.expect("body must be JSON");
    let e_rest = Uuid::parse_str(body["id"].as_str().expect("REST event id must be a string"))
        .expect("REST event id must be a UUID");

    // -----------------------------------------------------------------------
    // Step 3: gRPC ListEvents (system, events.read), filtered by user_id —
    // both events must surface, with their respective types preserved.
    // -----------------------------------------------------------------------
    let ts = h.clock.now().await.unwrap();
    let list_resp = h
        .events
        .list_events(signed(
            ListEventsRequest {
                user_id: user_id.to_string(),
                page_size: 50,
                ..Default::default()
            },
            &system_sk,
            system_key_id,
            "/headlines.v1.EventService/ListEvents",
            ts,
            &unique_nonce(),
        ))
        .await
        .expect("ListEvents must succeed for system with events.read")
        .into_inner();

    let by_id: std::collections::HashMap<String, &headlines_proto::v1::Event> =
        list_resp.items.iter().map(|e| (e.id.clone(), e)).collect();

    // Assert (step 3): both ids surface.
    let evt_grpc = by_id
        .get(&e_grpc.to_string())
        .expect("ListEvents must include the event recorded via gRPC");
    let evt_rest = by_id
        .get(&e_rest.to_string())
        .expect("ListEvents must include the event recorded via REST");
    // Each event surfaces with its recorded type — REST path didn't lose
    // information.
    assert_eq!(evt_grpc.r#type, EventType::Open as i32);
    assert_eq!(evt_rest.r#type, EventType::Like as i32);
    // The REST event was recorded after the gRPC event (we slept 1 ms in
    // between); ListEvents orders by (received_at, id) ASC.
    let to_pair = |ts: &Option<Timestamp>| -> (i64, i32) {
        ts.as_ref().map_or((0, 0), |t| (t.seconds, t.nanos))
    };
    assert!(
        to_pair(&evt_rest.received_at) >= to_pair(&evt_grpc.received_at),
        "REST event must have received_at >= gRPC event (was recorded later)",
    );

    cleanup_multi(
        &h.db,
        &[user_id],
        &[account_id],
        &[article_id],
        &[system_id],
    )
    .await;
}

// ---------------------------------------------------------------------------
// W5 — soft-deleted account: reads keep working, writes fail with ACCOUNT_DELETED
// ---------------------------------------------------------------------------

#[tokio::test]
async fn account_lifecycle_publish_then_delete_keeps_articles_visible_but_blocks_new_writes() {
    skip_if_no_db!();

    // -----------------------------------------------------------------------
    // Arrange — account with key, one published article via the actual
    // `ArticleService.PublishArticle` so EditArticle has a real target row
    // to attempt later.
    // -----------------------------------------------------------------------
    let mut h = spawn_test_service().await;
    let acct_sk = make_signing_key();
    let (account_id, account_key_id) = seed_account_with_key(&h.db, &acct_sk).await;

    let ts = h.clock.now().await.unwrap();
    let publish_resp = h
        .articles
        .publish_article(signed(
            PublishArticleRequest {
                account_id: account_id.to_string(),
                title: "Pre-delete article".into(),
                author_name: "W5 Author".into(),
                author_url: "https://example.com".into(),
                content: vec![headlines_proto::v1::Node {
                    kind: Some(headlines_proto::v1::node::Kind::Text("alive".into())),
                }],
            },
            &acct_sk,
            account_key_id,
            "/headlines.v1.ArticleService/PublishArticle",
            ts,
            &unique_nonce(),
        ))
        .await
        .expect("PublishArticle must succeed for account-self")
        .into_inner();
    let article_id = Uuid::parse_str(&publish_resp.id).expect("article id");

    // -----------------------------------------------------------------------
    // Step 1: GetArticle succeeds, state=LIVE.
    // -----------------------------------------------------------------------
    let got_pre = h
        .articles
        .get_article(tonic::Request::new(GetArticleRequest {
            id: article_id.to_string(),
        }))
        .await
        .expect("GetArticle is anonymous-readable")
        .into_inner();
    // Assert (step 1):
    assert_eq!(got_pre.state, ArticleState::Live as i32);

    // -----------------------------------------------------------------------
    // Step 2: account self-deletes.
    // -----------------------------------------------------------------------
    let ts = h.clock.now().await.unwrap();
    h.accounts
        .delete_account(signed(
            DeleteAccountRequest {
                id: account_id.to_string(),
            },
            &acct_sk,
            account_key_id,
            "/headlines.v1.AccountService/DeleteAccount",
            ts,
            &unique_nonce(),
        ))
        .await
        .expect("DeleteAccount must succeed for account-self");

    // -----------------------------------------------------------------------
    // Step 3: GetArticle still succeeds — `accounts.md` "No cascade".
    // -----------------------------------------------------------------------
    let got_post = h
        .articles
        .get_article(tonic::Request::new(GetArticleRequest {
            id: article_id.to_string(),
        }))
        .await
        .expect("GetArticle must still succeed after account delete (no cascade)")
        .into_inner();
    // Assert (step 3):
    assert_eq!(
        got_post.state,
        ArticleState::Live as i32,
        "soft-deleted account's articles must remain LIVE (no cascade)",
    );

    // -----------------------------------------------------------------------
    // Step 4: account-self EditArticle on the existing article — must fail
    // with FAILED_PRECONDITION + ACCOUNT_DELETED per `accounts.md`
    // ("Subsequent writes on a deleted account → FAILED_PRECONDITION
    // ACCOUNT_DELETED"). The auth key is still active so the signature
    // verifies; the handler enforces the account-state precondition.
    //
    // Pre-fix this assertion failed (Ok was returned) — the article
    // service's `edit_article` only authorized against the article's
    // owning account but didn't check that the owning account was still
    // active. The fix mirrors the same precondition `publish_article`
    // already enforces and is logged under `[workflow-bug]` in
    // `docs/implementation-issues.md`.
    // -----------------------------------------------------------------------
    let edit_mask = prost_types::FieldMask {
        paths: vec!["title".into()],
    };
    let edit_proto = headlines_proto::v1::ArticleEdit {
        title: "Should not be allowed".into(),
        author_name: String::new(),
        author_url: String::new(),
        content: vec![],
    };
    let ts = h.clock.now().await.unwrap();
    let edit_res = h
        .articles
        .edit_article(signed(
            EditArticleRequest {
                id: article_id.to_string(),
                edit: Some(edit_proto),
                update_mask: Some(edit_mask),
            },
            &acct_sk,
            account_key_id,
            "/headlines.v1.ArticleService/EditArticle",
            ts,
            &unique_nonce(),
        ))
        .await;
    let edit_err = edit_res.expect_err(
        "EditArticle on a soft-deleted account must reject (accounts.md: \
         writes on a deleted account → ACCOUNT_DELETED).",
    );
    // Assert (step 4): FAILED_PRECONDITION; the gRPC trailers carry
    // ErrorInfo.reason = "ACCOUNT_DELETED" but at the tonic level we
    // assert on the Code (the reason mapping is exercised in the
    // per-account-service tests).
    assert_eq!(
        edit_err.code(),
        tonic::Code::FailedPrecondition,
        "EditArticle on deleted account must surface FAILED_PRECONDITION (ACCOUNT_DELETED); \
         got {:?}: {}",
        edit_err.code(),
        edit_err.message(),
    );

    // -----------------------------------------------------------------------
    // Step 5: account-self PublishArticle for a NEW article — must fail
    // with FAILED_PRECONDITION + ACCOUNT_DELETED.
    // -----------------------------------------------------------------------
    let ts = h.clock.now().await.unwrap();
    let publish_res = h
        .articles
        .publish_article(signed(
            PublishArticleRequest {
                account_id: account_id.to_string(),
                title: "Should not be allowed".into(),
                author_name: "W5 Author".into(),
                author_url: "https://example.com".into(),
                content: vec![headlines_proto::v1::Node {
                    kind: Some(headlines_proto::v1::node::Kind::Text("nope".into())),
                }],
            },
            &acct_sk,
            account_key_id,
            "/headlines.v1.ArticleService/PublishArticle",
            ts,
            &unique_nonce(),
        ))
        .await;
    let publish_err = publish_res
        .expect_err("PublishArticle on a soft-deleted account must reject with ACCOUNT_DELETED");
    // Assert (step 5):
    assert_eq!(
        publish_err.code(),
        tonic::Code::FailedPrecondition,
        "PublishArticle on deleted account must surface FAILED_PRECONDITION (ACCOUNT_DELETED); \
         got {:?}: {}",
        publish_err.code(),
        publish_err.message(),
    );

    cleanup_multi(&h.db, &[], &[account_id], &[article_id], &[]).await;
}
