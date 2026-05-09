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
};
use headlines_core::{TimeSource as _, Tso};
use headlines_proto::v1::{
    ArticleState, CreateAccountRequest, CreateDraftRequest, CreateUserRequest, EventType,
    FollowRequest, FollowStatus, GetArticleRequest, GetFollowFeedRequest, ListEventsRequest,
    OpenProperties, PublicKey, PublishDraftRequest, RecordEventRequest,
    StreamAccountArticlesRequest, TombstoneArticleRequest,
    account_service_client::AccountServiceClient, account_service_server::AccountServiceServer,
    account_stream_service_client::AccountStreamServiceClient,
    account_stream_service_server::AccountStreamServiceServer, article,
    article_service_client::ArticleServiceClient, article_service_server::ArticleServiceServer,
    article_summary, draft_service_client::DraftServiceClient,
    draft_service_server::DraftServiceServer, event_service_client::EventServiceClient,
    event_service_server::EventServiceServer, feed_follow_service_client::FeedFollowServiceClient,
    feed_follow_service_server::FeedFollowServiceServer,
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
    clock: Arc<LocalClock>,
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
        feed_follow: FeedFollowServiceClient::new(channel),
        clock,
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
