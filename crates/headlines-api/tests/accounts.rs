//! End-to-end integration tests for `AccountService`, exercised through a
//! real tonic in-process server (random TCP port) backed by Postgres on
//! `docker.yuacx.com`.
//!
//! Each test mints fresh UUIDv7s so it doesn't collide with sibling tests;
//! cleanup is best-effort via `DELETE` filters at the end so data doesn't
//! pile up over a long workday. We never `TRUNCATE` — other phases share the
//! same DB.
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

use headlines_api::{AccountServiceImpl, BootstrapMode};
use headlines_auth::{
    AlgorithmRegistry, AuthInterceptor, AuthorizationLayer, Ed25519, InMemoryNonceStore,
    LocalClock, PostgresKeyResolver, ProtoBodyHasher, SignedRequestStrategy,
};
use headlines_core::{TimeSource as _, Tso};
use headlines_proto::v1::{
    AddAccountKeyRequest, CreateAccountRequest, DeleteAccountRequest, GetAccountRequest, PublicKey,
    RevokeAccountKeyRequest, UpdateAccountRequest, account_service_client::AccountServiceClient,
    account_service_server::AccountServiceServer,
};
use headlines_store::{Db, PgAccountRepo, PgKeyRepo};

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

struct Harness {
    db: Db,
    /// gRPC client targeting the spawned server.
    client: AccountServiceClient<Channel>,
    /// Wall-clock TSO source the test client must use to sign with timestamps
    /// the server will accept.
    clock: Arc<LocalClock>,
    /// The bootstrap-mode string the server was configured with — tests can
    /// branch on it if they cover both modes.
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

    // Pieces.
    let accounts = Arc::new(PgAccountRepo::new(db.clone()));
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

    let svc = AccountServiceImpl::new(accounts, keys, algos, bootstrap);

    // tower stack: AuthInterceptor → AuthorizationLayer → service. The service
    // is wrapped in `AccountServiceServer` so the layers see `Request<BoxBody>`.
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
        .add_service(AccountServiceServer::new(svc));

    tokio::spawn(async move {
        let _ = server.serve_with_incoming(stream).await;
    });

    // Connect a client.
    let endpoint = Endpoint::from_shared(format!("http://{addr}"))
        .expect("endpoint")
        .connect_timeout(Duration::from_secs(5));
    let channel = endpoint.connect().await.expect("client connect");
    let client = AccountServiceClient::new(channel);

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

/// Build the `authorization` metadata value for a unary request signed by
/// `sk` under `key_id`.
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

/// Attach a signed `authorization` metadata header to a tonic request.
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

/// Build an `Account` proto with only the fields we set in tests; the rest
/// stay at proto defaults. Keeping this helper avoids `Default::default() +
/// field assign` patterns that trip clippy.
fn account_msg(
    id: &str,
    short_name: &str,
    author_name: &str,
    author_url: &str,
) -> headlines_proto::v1::Account {
    headlines_proto::v1::Account {
        id: id.to_owned(),
        short_name: short_name.to_owned(),
        author_name: author_name.to_owned(),
        author_url: author_url.to_owned(),
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// DB cleanup helpers — best-effort, never panics on failure.
// ---------------------------------------------------------------------------

async fn cleanup(db: &Db, account_ids: &[Uuid]) {
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

/// Insert a (system, key, scope) row triple so a System-class signed request
/// can resolve. Returns `(system_id, key_id)` so the caller can sign with it.
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

// ===========================================================================
// CreateAccount
// ===========================================================================

#[tokio::test]
async fn create_account_anonymous_open_mode_succeeds() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server(BootstrapMode::Open).await;
    let sk = make_signing_key();
    let req = CreateAccountRequest {
        short_name: "anon-test".into(),
        author_name: "Anon Tester".into(),
        author_url: "https://example.com/anon".into(),
        initial_key: Some(PublicKey {
            algo: "ed25519".into(),
            public_key: ed25519_pk_b64(&sk),
        }),
    };

    // Act — anonymous (no auth header) call.
    let resp = h
        .client
        .create_account(tonic::Request::new(req))
        .await
        .expect("CreateAccount should succeed for anonymous in Open mode");

    // Assert
    let body = resp.into_inner();
    let acc = body.account.expect("account in response");
    assert_eq!(acc.short_name, "anon-test");
    assert!(!body.key_id.is_empty());
    let account_id = Uuid::parse_str(&acc.id).unwrap();

    cleanup(&h.db, &[account_id]).await;
}

#[tokio::test]
async fn create_account_anonymous_in_system_only_mode_is_registration_disabled() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server(BootstrapMode::SystemOnly).await;
    let sk = make_signing_key();
    let req = CreateAccountRequest {
        short_name: "reject-anon".into(),
        author_name: "Anon".into(),
        author_url: String::new(),
        initial_key: Some(PublicKey {
            algo: "ed25519".into(),
            public_key: ed25519_pk_b64(&sk),
        }),
    };

    // Act
    let err = h
        .client
        .create_account(tonic::Request::new(req))
        .await
        .expect_err("system_only mode must reject anonymous");

    // Assert
    assert_eq!(err.code(), tonic::Code::PermissionDenied, "{err}");
}

#[tokio::test]
async fn create_account_system_with_accounts_write_in_system_only_mode_succeeds() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server(BootstrapMode::SystemOnly).await;
    let system_sk = make_signing_key();
    let (system_id, system_key_id) =
        insert_system(&h.db, "creator", &["accounts.write"], &system_sk).await;
    let acct_sk = make_signing_key();
    let req = CreateAccountRequest {
        short_name: "by-system".into(),
        author_name: "BySystem".into(),
        author_url: String::new(),
        initial_key: Some(PublicKey {
            algo: "ed25519".into(),
            public_key: ed25519_pk_b64(&acct_sk),
        }),
    };
    let ts = h.clock.now().await.unwrap();

    // Act
    let request = signed(
        req,
        &system_sk,
        system_key_id,
        "/headlines.v1.AccountService/CreateAccount",
        ts,
        &unique_nonce(),
    );
    let resp = h
        .client
        .create_account(request)
        .await
        .expect("system creation should succeed");

    // Assert
    let acc = resp.into_inner().account.unwrap();
    let account_id = Uuid::parse_str(&acc.id).unwrap();

    cleanup(&h.db, &[account_id]).await;
    cleanup_system(&h.db, system_id).await;
}

#[tokio::test]
async fn create_account_validation_rejects_empty_short_name() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server(BootstrapMode::Open).await;
    let sk = make_signing_key();
    let req = CreateAccountRequest {
        short_name: "   ".into(),
        author_name: "X".into(),
        author_url: String::new(),
        initial_key: Some(PublicKey {
            algo: "ed25519".into(),
            public_key: ed25519_pk_b64(&sk),
        }),
    };

    // Act
    let err = h
        .client
        .create_account(tonic::Request::new(req))
        .await
        .expect_err("empty short_name");

    // Assert
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn create_account_validation_rejects_overlength_author_url() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server(BootstrapMode::Open).await;
    let sk = make_signing_key();
    let req = CreateAccountRequest {
        short_name: "ok".into(),
        author_name: "ok".into(),
        author_url: format!("https://example.com/{}", "x".repeat(600)),
        initial_key: Some(PublicKey {
            algo: "ed25519".into(),
            public_key: ed25519_pk_b64(&sk),
        }),
    };

    // Act
    let err = h
        .client
        .create_account(tonic::Request::new(req))
        .await
        .expect_err("over-long URL");

    // Assert
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn create_account_validation_rejects_unsupported_algo() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server(BootstrapMode::Open).await;
    let req = CreateAccountRequest {
        short_name: "alg".into(),
        author_name: "Alg".into(),
        author_url: String::new(),
        initial_key: Some(PublicKey {
            algo: "rsa".into(),
            public_key: B64.encode([0u8; 32]),
        }),
    };

    // Act
    let err = h
        .client
        .create_account(tonic::Request::new(req))
        .await
        .expect_err("unsupported algo");

    // Assert
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(err.message().contains("rsa"), "{}", err.message());
}

#[tokio::test]
async fn create_account_validation_rejects_short_ed25519_public_key() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server(BootstrapMode::Open).await;
    let req = CreateAccountRequest {
        short_name: "ed".into(),
        author_name: "Ed".into(),
        author_url: String::new(),
        initial_key: Some(PublicKey {
            algo: "ed25519".into(),
            public_key: B64.encode([0u8; 16]), // wrong length
        }),
    };

    // Act
    let err = h
        .client
        .create_account(tonic::Request::new(req))
        .await
        .expect_err("short ed25519 key");

    // Assert
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(err.message().contains("32 bytes"), "{}", err.message());
}

// ===========================================================================
// GetAccount
// ===========================================================================

#[tokio::test]
async fn get_account_anonymous_returns_existing() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server(BootstrapMode::Open).await;
    let sk = make_signing_key();
    let create_resp = h
        .client
        .create_account(tonic::Request::new(CreateAccountRequest {
            short_name: "get-me".into(),
            author_name: "Getter".into(),
            author_url: String::new(),
            initial_key: Some(PublicKey {
                algo: "ed25519".into(),
                public_key: ed25519_pk_b64(&sk),
            }),
        }))
        .await
        .unwrap()
        .into_inner();
    let account_id = Uuid::parse_str(&create_resp.account.unwrap().id).unwrap();

    // Act
    let got = h
        .client
        .get_account(tonic::Request::new(GetAccountRequest {
            id: account_id.to_string(),
        }))
        .await
        .unwrap()
        .into_inner();

    // Assert
    assert_eq!(got.short_name, "get-me");

    cleanup(&h.db, &[account_id]).await;
}

#[tokio::test]
async fn get_account_returns_not_found_for_unknown_id() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server(BootstrapMode::Open).await;
    let unknown = Uuid::now_v7();

    // Act
    let err = h
        .client
        .get_account(tonic::Request::new(GetAccountRequest {
            id: unknown.to_string(),
        }))
        .await
        .expect_err("unknown id");

    // Assert
    assert_eq!(err.code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn get_account_of_soft_deleted_returns_deleted_status() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server(BootstrapMode::Open).await;
    let sk = make_signing_key();
    let create_resp = h
        .client
        .create_account(tonic::Request::new(CreateAccountRequest {
            short_name: "soft-del".into(),
            author_name: "Sd".into(),
            author_url: String::new(),
            initial_key: Some(PublicKey {
                algo: "ed25519".into(),
                public_key: ed25519_pk_b64(&sk),
            }),
        }))
        .await
        .unwrap()
        .into_inner();
    let account_id = Uuid::parse_str(&create_resp.account.unwrap().id).unwrap();
    let key_id = Uuid::parse_str(&create_resp.key_id).unwrap();

    // Self-delete via Account subject.
    let ts = h.clock.now().await.unwrap();
    let del = signed(
        DeleteAccountRequest {
            id: account_id.to_string(),
        },
        &sk,
        key_id,
        "/headlines.v1.AccountService/DeleteAccount",
        ts,
        &unique_nonce(),
    );
    h.client.delete_account(del).await.unwrap();

    // Act
    let got = h
        .client
        .get_account(tonic::Request::new(GetAccountRequest {
            id: account_id.to_string(),
        }))
        .await
        .unwrap()
        .into_inner();

    // Assert — DELETED status, not NOT_FOUND.
    assert_eq!(
        got.status,
        headlines_proto::v1::AccountStatus::Deleted as i32
    );
    assert!(got.deleted_at.is_some());

    cleanup(&h.db, &[account_id]).await;
}

// ===========================================================================
// UpdateAccount
// ===========================================================================

async fn create_self_account(h: &mut Harness, sk: &SigningKey) -> (Uuid, Uuid) {
    let create_resp = h
        .client
        .create_account(tonic::Request::new(CreateAccountRequest {
            short_name: "self-up".into(),
            author_name: "S".into(),
            author_url: String::new(),
            initial_key: Some(PublicKey {
                algo: "ed25519".into(),
                public_key: ed25519_pk_b64(sk),
            }),
        }))
        .await
        .unwrap()
        .into_inner();
    let acc = create_resp.account.unwrap();
    (
        Uuid::parse_str(&acc.id).unwrap(),
        Uuid::parse_str(&create_resp.key_id).unwrap(),
    )
}

#[tokio::test]
async fn update_account_self_changes_author_name() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server(BootstrapMode::Open).await;
    let sk = make_signing_key();
    let (account_id, key_id) = create_self_account(&mut h, &sk).await;
    let new_name = "Updated Name";

    // Act
    let req = UpdateAccountRequest {
        account: Some(account_msg(&account_id.to_string(), "", new_name, "")),
        update_mask: Some(prost_types::FieldMask {
            paths: vec!["author_name".into()],
        }),
    };
    let ts = h.clock.now().await.unwrap();
    let signed_req = signed(
        req,
        &sk,
        key_id,
        "/headlines.v1.AccountService/UpdateAccount",
        ts,
        &unique_nonce(),
    );
    let updated = h
        .client
        .update_account(signed_req)
        .await
        .unwrap()
        .into_inner();

    // Assert
    assert_eq!(updated.author_name, new_name);

    cleanup(&h.db, &[account_id]).await;
}

#[tokio::test]
async fn update_account_cross_account_returns_account_not_found() {
    skip_if_no_db!();

    // Arrange — account A signs, account B is the target.
    let mut h = spawn_server(BootstrapMode::Open).await;
    let sk_a = make_signing_key();
    let sk_b = make_signing_key();
    let (acc_a, key_a) = create_self_account(&mut h, &sk_a).await;
    let (acc_b, _) = create_self_account(&mut h, &sk_b).await;

    let req = UpdateAccountRequest {
        account: Some(account_msg(&acc_b.to_string(), "", "Hostile", "")),
        update_mask: Some(prost_types::FieldMask {
            paths: vec!["author_name".into()],
        }),
    };
    let ts = h.clock.now().await.unwrap();
    let signed_req = signed(
        req,
        &sk_a,
        key_a,
        "/headlines.v1.AccountService/UpdateAccount",
        ts,
        &unique_nonce(),
    );

    // Act
    let err = h
        .client
        .update_account(signed_req)
        .await
        .expect_err("cross-account write must reject");

    // Assert
    assert_eq!(err.code(), tonic::Code::NotFound);

    cleanup(&h.db, &[acc_a, acc_b]).await;
}

#[tokio::test]
async fn update_account_system_with_accounts_admin_can_update_any() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server(BootstrapMode::Open).await;
    let target_sk = make_signing_key();
    let (acc, _) = create_self_account(&mut h, &target_sk).await;

    let sys_sk = make_signing_key();
    let (system_id, sys_key_id) = insert_system(&h.db, "admin", &["accounts.admin"], &sys_sk).await;

    let req = UpdateAccountRequest {
        account: Some(account_msg(&acc.to_string(), "by-admin", "", "")),
        update_mask: Some(prost_types::FieldMask {
            paths: vec!["short_name".into()],
        }),
    };
    let ts = h.clock.now().await.unwrap();
    let signed_req = signed(
        req,
        &sys_sk,
        sys_key_id,
        "/headlines.v1.AccountService/UpdateAccount",
        ts,
        &unique_nonce(),
    );

    // Act
    let updated = h
        .client
        .update_account(signed_req)
        .await
        .unwrap()
        .into_inner();

    // Assert
    assert_eq!(updated.short_name, "by-admin");

    cleanup(&h.db, &[acc]).await;
    cleanup_system(&h.db, system_id).await;
}

#[tokio::test]
async fn update_account_on_deleted_returns_account_deleted() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server(BootstrapMode::Open).await;
    let sk = make_signing_key();
    let (acc, key_id) = create_self_account(&mut h, &sk).await;

    // Soft-delete via system path so we can still update (account self can't
    // sign after delete: keys still active but writes rejected by AccountDeleted).
    let sys_sk = make_signing_key();
    let (system_id, sys_key_id) =
        insert_system(&h.db, "deleter", &["accounts.delete"], &sys_sk).await;
    let ts = h.clock.now().await.unwrap();
    let del = signed(
        DeleteAccountRequest {
            id: acc.to_string(),
        },
        &sys_sk,
        sys_key_id,
        "/headlines.v1.AccountService/DeleteAccount",
        ts,
        &unique_nonce(),
    );
    h.client.delete_account(del).await.unwrap();

    // Now the account-self tries to update its short_name.
    let req = UpdateAccountRequest {
        account: Some(account_msg(&acc.to_string(), "post-del", "", "")),
        update_mask: Some(prost_types::FieldMask {
            paths: vec!["short_name".into()],
        }),
    };
    let ts = h.clock.now().await.unwrap();
    let signed_req = signed(
        req,
        &sk,
        key_id,
        "/headlines.v1.AccountService/UpdateAccount",
        ts,
        &unique_nonce(),
    );

    // Act
    let err = h
        .client
        .update_account(signed_req)
        .await
        .expect_err("update on deleted");

    // Assert
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);

    cleanup(&h.db, &[acc]).await;
    cleanup_system(&h.db, system_id).await;
}

#[tokio::test]
async fn update_account_unallowed_mask_path_rejected() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server(BootstrapMode::Open).await;
    let sk = make_signing_key();
    let (acc, key_id) = create_self_account(&mut h, &sk).await;

    let req = UpdateAccountRequest {
        account: Some(account_msg(&acc.to_string(), "", "", "")),
        update_mask: Some(prost_types::FieldMask {
            paths: vec!["status".into()],
        }),
    };
    let ts = h.clock.now().await.unwrap();
    let signed_req = signed(
        req,
        &sk,
        key_id,
        "/headlines.v1.AccountService/UpdateAccount",
        ts,
        &unique_nonce(),
    );

    // Act
    let err = h
        .client
        .update_account(signed_req)
        .await
        .expect_err("unallowed path");

    // Assert
    assert_eq!(err.code(), tonic::Code::InvalidArgument);

    cleanup(&h.db, &[acc]).await;
}

// ===========================================================================
// DeleteAccount
// ===========================================================================

#[tokio::test]
async fn delete_account_self_succeeds() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server(BootstrapMode::Open).await;
    let sk = make_signing_key();
    let (acc, key_id) = create_self_account(&mut h, &sk).await;

    let ts = h.clock.now().await.unwrap();
    let req = signed(
        DeleteAccountRequest {
            id: acc.to_string(),
        },
        &sk,
        key_id,
        "/headlines.v1.AccountService/DeleteAccount",
        ts,
        &unique_nonce(),
    );

    // Act
    let resp = h.client.delete_account(req).await.unwrap().into_inner();

    // Assert
    assert_eq!(
        resp.status,
        headlines_proto::v1::AccountStatus::Deleted as i32
    );

    cleanup(&h.db, &[acc]).await;
}

#[tokio::test]
async fn delete_account_system_with_accounts_delete_succeeds() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server(BootstrapMode::Open).await;
    let target_sk = make_signing_key();
    let (acc, _) = create_self_account(&mut h, &target_sk).await;

    let sys_sk = make_signing_key();
    let (system_id, sys_key_id) =
        insert_system(&h.db, "deleter", &["accounts.delete"], &sys_sk).await;

    let ts = h.clock.now().await.unwrap();
    let req = signed(
        DeleteAccountRequest {
            id: acc.to_string(),
        },
        &sys_sk,
        sys_key_id,
        "/headlines.v1.AccountService/DeleteAccount",
        ts,
        &unique_nonce(),
    );

    // Act
    let resp = h.client.delete_account(req).await.unwrap().into_inner();

    // Assert
    assert_eq!(
        resp.status,
        headlines_proto::v1::AccountStatus::Deleted as i32
    );

    cleanup(&h.db, &[acc]).await;
    cleanup_system(&h.db, system_id).await;
}

#[tokio::test]
async fn delete_account_system_without_delete_scope_denied() {
    skip_if_no_db!();

    // Arrange — system has only `accounts.write`, NOT `accounts.delete`.
    let mut h = spawn_server(BootstrapMode::Open).await;
    let target_sk = make_signing_key();
    let (acc, _) = create_self_account(&mut h, &target_sk).await;

    let sys_sk = make_signing_key();
    let (system_id, sys_key_id) =
        insert_system(&h.db, "writer", &["accounts.write"], &sys_sk).await;

    let ts = h.clock.now().await.unwrap();
    let req = signed(
        DeleteAccountRequest {
            id: acc.to_string(),
        },
        &sys_sk,
        sys_key_id,
        "/headlines.v1.AccountService/DeleteAccount",
        ts,
        &unique_nonce(),
    );

    // Act
    let err = h
        .client
        .delete_account(req)
        .await
        .expect_err("missing scope");

    // Assert — AuthorizationLayer rejects PERMISSION_DENIED (the proto-level
    // scope gate) before the handler sees the call.
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    cleanup(&h.db, &[acc]).await;
    cleanup_system(&h.db, system_id).await;
}

// ===========================================================================
// AddAccountKey
// ===========================================================================

#[tokio::test]
async fn add_account_key_self_succeeds_and_new_key_can_sign() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server(BootstrapMode::Open).await;
    let sk1 = make_signing_key();
    let (acc, key1) = create_self_account(&mut h, &sk1).await;

    let sk2 = make_signing_key();
    let add_req = AddAccountKeyRequest {
        account_id: acc.to_string(),
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
        "/headlines.v1.AccountService/AddAccountKey",
        ts,
        &unique_nonce(),
    );

    // Act
    let new_key = h
        .client
        .add_account_key(request)
        .await
        .unwrap()
        .into_inner();
    let key2 = Uuid::parse_str(&new_key.key_id).unwrap();

    // Assert — round-trip: sign a follow-up call with the new key.
    let upd = UpdateAccountRequest {
        account: Some(account_msg(&acc.to_string(), "", "Two", "")),
        update_mask: Some(prost_types::FieldMask {
            paths: vec!["author_name".into()],
        }),
    };
    let ts = h.clock.now().await.unwrap();
    let signed_upd = signed(
        upd,
        &sk2,
        key2,
        "/headlines.v1.AccountService/UpdateAccount",
        ts,
        &unique_nonce(),
    );
    let r = h
        .client
        .update_account(signed_upd)
        .await
        .unwrap()
        .into_inner();
    assert_eq!(r.author_name, "Two");

    cleanup(&h.db, &[acc]).await;
}

// ===========================================================================
// RevokeAccountKey
// ===========================================================================

#[tokio::test]
async fn revoke_account_key_one_of_many_succeeds() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server(BootstrapMode::Open).await;
    let sk1 = make_signing_key();
    let (acc, key1) = create_self_account(&mut h, &sk1).await;

    // Add a second key so revoking key1 is allowed.
    let sk2 = make_signing_key();
    let add_req = AddAccountKeyRequest {
        account_id: acc.to_string(),
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
        "/headlines.v1.AccountService/AddAccountKey",
        ts,
        &unique_nonce(),
    );
    let added = h
        .client
        .add_account_key(request)
        .await
        .unwrap()
        .into_inner();
    let key2 = Uuid::parse_str(&added.key_id).unwrap();

    // Revoke key2 with key1 still active.
    let revoke = RevokeAccountKeyRequest {
        account_id: acc.to_string(),
        key_id: key2.to_string(),
    };
    let ts = h.clock.now().await.unwrap();
    let signed_revoke = signed(
        revoke,
        &sk1,
        key1,
        "/headlines.v1.AccountService/RevokeAccountKey",
        ts,
        &unique_nonce(),
    );

    // Act
    let r = h
        .client
        .revoke_account_key(signed_revoke)
        .await
        .unwrap()
        .into_inner();

    // Assert
    assert_eq!(r.status, headlines_proto::v1::KeyStatus::Revoked as i32);

    cleanup(&h.db, &[acc]).await;
}

#[tokio::test]
async fn revoke_account_key_last_active_is_rejected() {
    skip_if_no_db!();

    // Arrange — single key.
    let mut h = spawn_server(BootstrapMode::Open).await;
    let sk = make_signing_key();
    let (acc, key1) = create_self_account(&mut h, &sk).await;

    let revoke = RevokeAccountKeyRequest {
        account_id: acc.to_string(),
        key_id: key1.to_string(),
    };
    let ts = h.clock.now().await.unwrap();
    let signed_revoke = signed(
        revoke,
        &sk,
        key1,
        "/headlines.v1.AccountService/RevokeAccountKey",
        ts,
        &unique_nonce(),
    );

    // Act
    let err = h
        .client
        .revoke_account_key(signed_revoke)
        .await
        .expect_err("last-key revoke rejected");

    // Assert
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);

    cleanup(&h.db, &[acc]).await;
}

#[tokio::test]
async fn revoke_account_key_admin_star_can_override_lockout() {
    skip_if_no_db!();

    // Arrange — single account key, system with admin.* overrides.
    let mut h = spawn_server(BootstrapMode::Open).await;
    let sk = make_signing_key();
    let (acc, key1) = create_self_account(&mut h, &sk).await;

    let sys_sk = make_signing_key();
    // `admin.*` doesn't include `accounts.admin` (different prefix) — give
    // the system both so it passes the proto-level gate AND the override
    // check.
    let (system_id, sys_key_id) =
        insert_system(&h.db, "rescue", &["accounts.admin", "admin.*"], &sys_sk).await;

    let revoke = RevokeAccountKeyRequest {
        account_id: acc.to_string(),
        key_id: key1.to_string(),
    };
    let ts = h.clock.now().await.unwrap();
    let signed_revoke = signed(
        revoke,
        &sys_sk,
        sys_key_id,
        "/headlines.v1.AccountService/RevokeAccountKey",
        ts,
        &unique_nonce(),
    );

    // Act
    let r = h
        .client
        .revoke_account_key(signed_revoke)
        .await
        .expect("admin.* must override lockout")
        .into_inner();

    // Assert
    assert_eq!(r.status, headlines_proto::v1::KeyStatus::Revoked as i32);

    cleanup(&h.db, &[acc]).await;
    cleanup_system(&h.db, system_id).await;
}

#[tokio::test]
async fn revoke_account_key_already_revoked_is_already_exists() {
    skip_if_no_db!();

    // Arrange — add a 2nd key, revoke it twice.
    let mut h = spawn_server(BootstrapMode::Open).await;
    let sk1 = make_signing_key();
    let (acc, key1) = create_self_account(&mut h, &sk1).await;
    let sk2 = make_signing_key();
    let ts = h.clock.now().await.unwrap();
    let added = h
        .client
        .add_account_key(signed(
            AddAccountKeyRequest {
                account_id: acc.to_string(),
                key: Some(PublicKey {
                    algo: "ed25519".into(),
                    public_key: ed25519_pk_b64(&sk2),
                }),
            },
            &sk1,
            key1,
            "/headlines.v1.AccountService/AddAccountKey",
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();
    let key2 = Uuid::parse_str(&added.key_id).unwrap();

    let ts = h.clock.now().await.unwrap();
    h.client
        .revoke_account_key(signed(
            RevokeAccountKeyRequest {
                account_id: acc.to_string(),
                key_id: key2.to_string(),
            },
            &sk1,
            key1,
            "/headlines.v1.AccountService/RevokeAccountKey",
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap();

    // Act — revoke again.
    let ts = h.clock.now().await.unwrap();
    let err = h
        .client
        .revoke_account_key(signed(
            RevokeAccountKeyRequest {
                account_id: acc.to_string(),
                key_id: key2.to_string(),
            },
            &sk1,
            key1,
            "/headlines.v1.AccountService/RevokeAccountKey",
            ts,
            &unique_nonce(),
        ))
        .await
        .expect_err("double revoke");

    // Assert
    assert_eq!(err.code(), tonic::Code::AlreadyExists);

    cleanup(&h.db, &[acc]).await;
}

#[tokio::test]
async fn revoke_account_key_missing_key_returns_not_found() {
    skip_if_no_db!();

    // Arrange
    let mut h = spawn_server(BootstrapMode::Open).await;
    let sk = make_signing_key();
    let (acc, key1) = create_self_account(&mut h, &sk).await;
    let phantom = Uuid::now_v7();

    let ts = h.clock.now().await.unwrap();
    let signed_revoke = signed(
        RevokeAccountKeyRequest {
            account_id: acc.to_string(),
            key_id: phantom.to_string(),
        },
        &sk,
        key1,
        "/headlines.v1.AccountService/RevokeAccountKey",
        ts,
        &unique_nonce(),
    );

    // Act — note: lockout check sees one active key (`key1`), the target is
    // missing so `target_active=false` and we go to repo, which returns
    // KeyNotFound.
    let err = h
        .client
        .revoke_account_key(signed_revoke)
        .await
        .expect_err("missing key");

    // Assert
    assert_eq!(err.code(), tonic::Code::NotFound);

    cleanup(&h.db, &[acc]).await;
}

#[tokio::test]
async fn revoke_account_key_on_deleted_account_returns_account_deleted() {
    skip_if_no_db!();

    // Arrange — create an account with two keys, soft-delete it via a System
    // caller (so the Account's own keys remain valid for signing the revoke
    // attempt), then have the Account try to revoke one of its (still
    // active) keys. `accounts.md` says all writes on a deleted account →
    // `FAILED_PRECONDITION` with `ACCOUNT_DELETED`. This must trigger BEFORE
    // the lockout check — the post-tombstone state is the controlling reason.
    let mut h = spawn_server(BootstrapMode::Open).await;
    let sk1 = make_signing_key();
    let (acc, key1) = create_self_account(&mut h, &sk1).await;

    // Add a second key so the lockout-protection branch wouldn't be the
    // reason for a failure here — the test must fail on AccountDeleted.
    let sk2 = make_signing_key();
    let ts = h.clock.now().await.unwrap();
    let added = h
        .client
        .add_account_key(signed(
            AddAccountKeyRequest {
                account_id: acc.to_string(),
                key: Some(PublicKey {
                    algo: "ed25519".into(),
                    public_key: ed25519_pk_b64(&sk2),
                }),
            },
            &sk1,
            key1,
            "/headlines.v1.AccountService/AddAccountKey",
            ts,
            &unique_nonce(),
        ))
        .await
        .unwrap()
        .into_inner();
    let key2 = Uuid::parse_str(&added.key_id).unwrap();

    // Soft-delete via System with `accounts.delete` so the account-self keys
    // stay valid signers for the follow-up revoke attempt.
    let sys_sk = make_signing_key();
    let (system_id, sys_key_id) =
        insert_system(&h.db, "deleter", &["accounts.delete"], &sys_sk).await;
    let ts = h.clock.now().await.unwrap();
    let del = signed(
        DeleteAccountRequest {
            id: acc.to_string(),
        },
        &sys_sk,
        sys_key_id,
        "/headlines.v1.AccountService/DeleteAccount",
        ts,
        &unique_nonce(),
    );
    h.client.delete_account(del).await.unwrap();

    // Now the (still-signing) Account tries to revoke its own second key.
    let revoke = RevokeAccountKeyRequest {
        account_id: acc.to_string(),
        key_id: key2.to_string(),
    };
    let ts = h.clock.now().await.unwrap();
    let signed_revoke = signed(
        revoke,
        &sk1,
        key1,
        "/headlines.v1.AccountService/RevokeAccountKey",
        ts,
        &unique_nonce(),
    );

    // Act
    let err = h
        .client
        .revoke_account_key(signed_revoke)
        .await
        .expect_err("revoke on deleted account must fail");

    // Assert — FAILED_PRECONDITION, with `ACCOUNT_DELETED` mentioned in the
    // message (the same shape `update_account_on_deleted_returns_account_deleted`
    // exercises).
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);

    cleanup(&h.db, &[acc]).await;
    cleanup_system(&h.db, system_id).await;
}
