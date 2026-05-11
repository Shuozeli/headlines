//! Orchestrates the demo seed sequence end-to-end.
//!
//! Dials the local gRPC server (the public listener) over a `tonic::Channel`
//! and walks each step in turn, signing requests with the keys under
//! `demo/keys/`. Each step is idempotent: it consults `seed-state.json`
//! to skip work that's already been done.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, anyhow};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use chrono::{DateTime, Utc};
use diesel::sql_types::{Text, Timestamptz, Uuid as SqlUuid};
use diesel_async::RunQueryDsl;
use ed25519_dalek::{Signer, SigningKey};
use prost_types::Timestamp;
use rand::Rng;
use rand::SeedableRng;
use rand::seq::SliceRandom;
use rand_chacha::ChaCha8Rng;
use sha2::{Digest, Sha256};
use tonic::transport::{Channel, Endpoint};
use uuid::Uuid;

use headlines_proto::v1::{
    CreateAccountRequest, CreateDraftRequest, CreateUserRequest, DwellProperties, EventType,
    FollowRequest, ImpressionProperties, LikeProperties, OpenProperties, PublicKey,
    PublishArticleRequest, RecordEventBatchRequest, RecordEventRequest,
    ReplaceRecommendationFeedRequest, TombstoneArticleRequest,
    account_service_client::AccountServiceClient, article_service_client::ArticleServiceClient,
    draft_service_client::DraftServiceClient, event_service_client::EventServiceClient,
    feed_recommendation_service_client::FeedRecommendationServiceClient,
    follow_service_client::FollowServiceClient, record_event_request,
    user_service_client::UserServiceClient,
};
use headlines_store::Db;

use super::articles::{LoadedArticle, load_account_articles};
use super::content_md::markdown_to_nodes;
use super::keys::{LoadedKey, load_kind};
use super::plan::{ACCOUNTS, FOLLOWS, SYSTEMS, USERS};
use super::state::{IdRecord, SeedState};

/// Top-level seed entrypoint.
#[allow(clippy::too_many_arguments)]
pub async fn run_seed(
    db: Db,
    grpc_endpoint: &str,
    demo_path: &Path,
    rng_seed: u64,
    skip_articles: bool,
    reset: bool,
) -> anyhow::Result<()> {
    if reset {
        tracing::warn!("seed --reset: clearing demo data before reseeding");
        clear_demo_data(&db).await?;
        // Also wipe the seed-state.json so we re-record fresh ids.
        let path = demo_path.join("seed-state.json");
        if path.exists() {
            let _ = std::fs::remove_file(&path);
        }
    }

    let (mut state, state_path) = SeedState::load_or_default(demo_path)?;

    // -- Load keypairs --
    let system_keys = load_kind(demo_path, "system")?;
    let account_keys = load_kind(demo_path, "account")?;
    let user_keys = load_kind(demo_path, "user")?;

    // -- 1. Insert systems via direct SQL --
    seed_systems(&db, &system_keys, &mut state).await?;
    state.save(&state_path)?;

    // -- Connect gRPC channel --
    let channel = build_channel(grpc_endpoint).await?;

    // -- 2. Accounts --
    seed_accounts(&channel, &account_keys, &mut state).await?;
    state.save(&state_path)?;

    // -- 3. Users --
    seed_users(&channel, &user_keys, &mut state).await?;
    state.save(&state_path)?;

    if skip_articles {
        tracing::info!("skip_articles set; halting seed before article publish");
        return Ok(());
    }

    // -- 4. Publish articles --
    seed_articles(&db, &channel, &account_keys, demo_path, &mut state).await?;
    state.save(&state_path)?;

    // -- 5. Follows --
    seed_follows(&channel, &user_keys, &state).await?;

    // -- 6. Drafts --
    seed_drafts(&channel, &account_keys, demo_path, &mut state).await?;
    state.save(&state_path)?;

    // -- 7. Recommendation feeds --
    seed_recommendation_feeds(&channel, &system_keys, &state, rng_seed).await?;

    // -- 8. Events --
    seed_events(&channel, &user_keys, &state, rng_seed).await?;

    tracing::info!("seed completed");
    Ok(())
}

// ---------------------------------------------------------------------------
// Step 1 — systems via direct SQL.
// ---------------------------------------------------------------------------

async fn seed_systems(
    db: &Db,
    system_keys: &[LoadedKey],
    state: &mut SeedState,
) -> anyhow::Result<()> {
    let plan_map: std::collections::HashMap<&str, &[&str]> =
        SYSTEMS.iter().map(|(n, scopes)| (*n, *scopes)).collect();
    let mut conn = db.get().await?;
    for key in system_keys {
        if state.systems.contains_key(&key.name) {
            continue;
        }
        let scopes = plan_map
            .get(key.name.as_str())
            .ok_or_else(|| anyhow!("no scope plan for system {}", key.name))?;
        let system_id = Uuid::now_v7();
        let key_id = Uuid::now_v7();

        // Idempotency: check if a system with this name already exists.
        let existing = diesel::sql_query("SELECT id FROM systems WHERE name = $1")
            .bind::<Text, _>(&key.name)
            .load::<ExistingId>(&mut conn)
            .await?;
        if !existing.is_empty() {
            tracing::info!(name = %key.name, "system already present; skipping");
            // Still record the existing id so seed-state.json is complete.
            // We'd need to fetch the key_id too — try the keys table.
            let key_rows = diesel::sql_query(
                "SELECT key_id AS id FROM system_keys WHERE system_id = $1 LIMIT 1",
            )
            .bind::<SqlUuid, _>(existing[0].id)
            .load::<ExistingId>(&mut conn)
            .await?;
            let kid = if let [r, ..] = key_rows.as_slice() {
                r.id.to_string()
            } else {
                String::new()
            };
            state.systems.insert(
                key.name.clone(),
                IdRecord {
                    id: existing[0].id.to_string(),
                    key_id: kid,
                },
            );
            continue;
        }

        diesel::sql_query("INSERT INTO systems (id, name, status) VALUES ($1, $2, 'active')")
            .bind::<SqlUuid, _>(system_id)
            .bind::<Text, _>(&key.name)
            .execute(&mut conn)
            .await?;
        diesel::sql_query(
            "INSERT INTO system_keys (system_id, key_id, algo, public_key, status) \
             VALUES ($1, $2, 'ed25519', $3, 'active')",
        )
        .bind::<SqlUuid, _>(system_id)
        .bind::<SqlUuid, _>(key_id)
        .bind::<Text, _>(&key.public_b64)
        .execute(&mut conn)
        .await?;
        for scope in *scopes {
            diesel::sql_query("INSERT INTO system_scopes (system_id, scope) VALUES ($1, $2)")
                .bind::<SqlUuid, _>(system_id)
                .bind::<Text, _>(*scope)
                .execute(&mut conn)
                .await?;
        }
        state.systems.insert(
            key.name.clone(),
            IdRecord {
                id: system_id.to_string(),
                key_id: key_id.to_string(),
            },
        );
        tracing::info!(name = %key.name, %system_id, "seeded system");
    }
    Ok(())
}

#[derive(diesel::QueryableByName, Debug)]
struct ExistingId {
    #[diesel(sql_type = SqlUuid)]
    id: Uuid,
}

// ---------------------------------------------------------------------------
// Step 2 — accounts via CreateAccount RPC.
// ---------------------------------------------------------------------------

async fn seed_accounts(
    channel: &Channel,
    account_keys: &[LoadedKey],
    state: &mut SeedState,
) -> anyhow::Result<()> {
    let plan_map: std::collections::HashMap<&str, &super::plan::AccountSpec> =
        ACCOUNTS.iter().map(|(n, s)| (*n, s)).collect();
    let mut client = AccountServiceClient::new(channel.clone());
    for key in account_keys {
        if state.accounts.contains_key(&key.name) {
            continue;
        }
        let spec = plan_map
            .get(key.name.as_str())
            .ok_or_else(|| anyhow!("no plan for account {}", key.name))?;
        let req = CreateAccountRequest {
            short_name: spec.short_name.into(),
            author_name: spec.author_name.into(),
            author_url: spec.author_url.into(),
            initial_key: Some(PublicKey {
                algo: "ed25519".into(),
                public_key: key.public_b64.clone(),
            }),
        };
        // CreateAccount is anonymous in Open mode.
        let resp = client
            .create_account(tonic::Request::new(req))
            .await
            .with_context(|| format!("CreateAccount({})", key.name))?
            .into_inner();
        let account = resp
            .account
            .ok_or_else(|| anyhow!("CreateAccount response missing account"))?;
        state.accounts.insert(
            key.name.clone(),
            IdRecord {
                id: account.id,
                key_id: resp.key_id,
            },
        );
        tracing::info!(name = %key.name, "seeded account");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Step 3 — users via CreateUser RPC.
// ---------------------------------------------------------------------------

async fn seed_users(
    channel: &Channel,
    user_keys: &[LoadedKey],
    state: &mut SeedState,
) -> anyhow::Result<()> {
    let plan_map: std::collections::HashMap<&str, &str> = USERS.iter().copied().collect();
    let mut client = UserServiceClient::new(channel.clone());
    for key in user_keys {
        if state.users.contains_key(&key.name) {
            continue;
        }
        let display = plan_map
            .get(key.name.as_str())
            .copied()
            .unwrap_or(&key.name);
        let req = CreateUserRequest {
            display_name: display.into(),
            initial_key: Some(PublicKey {
                algo: "ed25519".into(),
                public_key: key.public_b64.clone(),
            }),
        };
        let resp = client
            .create_user(tonic::Request::new(req))
            .await
            .with_context(|| format!("CreateUser({})", key.name))?
            .into_inner();
        let user = resp
            .user
            .ok_or_else(|| anyhow!("CreateUser response missing user"))?;
        state.users.insert(
            key.name.clone(),
            IdRecord {
                id: user.id,
                key_id: resp.key_id,
            },
        );
        tracing::info!(name = %key.name, "seeded user");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Step 4 — articles.
// ---------------------------------------------------------------------------

async fn seed_articles(
    db: &Db,
    channel: &Channel,
    account_keys: &[LoadedKey],
    demo_path: &Path,
    state: &mut SeedState,
) -> anyhow::Result<()> {
    let mut articles_client = ArticleServiceClient::new(channel.clone());
    let mut drafts_client = DraftServiceClient::new(channel.clone());
    for key in account_keys {
        let articles = load_account_articles(demo_path, &key.name, "articles")?;
        let account_record = state
            .accounts
            .get(&key.name)
            .cloned()
            .ok_or_else(|| anyhow!("missing account for {}", key.name))?;
        let account_uuid = Uuid::parse_str(&account_record.id)?;
        let key_uuid = Uuid::parse_str(&account_record.key_id)?;
        for la in articles {
            let map_key = format!("{}/{}", key.name, la.filename);
            if state.articles.contains_key(&map_key) {
                continue;
            }
            publish_one(
                db,
                &mut articles_client,
                &mut drafts_client,
                account_uuid,
                key_uuid,
                &key.signing_key,
                state,
                &la,
                &map_key,
            )
            .await?;
        }
    }
    let _ = (db, drafts_client);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn publish_one(
    db: &Db,
    articles_client: &mut ArticleServiceClient<Channel>,
    _drafts_client: &mut DraftServiceClient<Channel>,
    account_uuid: Uuid,
    key_uuid: Uuid,
    signing_key: &SigningKey,
    state: &mut SeedState,
    la: &LoadedArticle,
    map_key: &str,
) -> anyhow::Result<()> {
    let fm = &la.article.frontmatter;
    let nodes = markdown_to_nodes(&la.article.body);

    let author_name = fm
        .author_name
        .clone()
        .unwrap_or_else(|| "Demo Author".into());
    let author_url = fm
        .author_url
        .clone()
        .unwrap_or_else(|| "https://example.com".into());

    let req = PublishArticleRequest {
        account_id: account_uuid.to_string(),
        title: fm.title.clone(),
        author_name,
        author_url,
        content: nodes,
    };

    let signed = signed_request(
        req.clone(),
        signing_key,
        key_uuid,
        "/headlines.v1.ArticleService/PublishArticle",
    )?;
    let resp = articles_client
        .publish_article(signed)
        .await
        .with_context(|| format!("PublishArticle({})", map_key))?
        .into_inner();
    let article_id = Uuid::parse_str(&resp.id)?;
    state.articles.insert(map_key.to_owned(), resp.id.clone());

    // Override created_at if the frontmatter supplied one.
    if let Some(created_at) = &fm.created_at
        && let Ok(dt) = DateTime::parse_from_rfc3339(created_at)
    {
        let dt_utc = dt.with_timezone(&Utc);
        let mut conn = db.get().await?;
        diesel::sql_query("UPDATE articles SET created_at = $1 WHERE id = $2")
            .bind::<Timestamptz, _>(dt_utc)
            .bind::<SqlUuid, _>(article_id)
            .execute(&mut conn)
            .await?;
    }

    // State transitions.
    match fm.state.as_deref() {
        Some("tombstone") => {
            let req = TombstoneArticleRequest {
                id: resp.id.clone(),
                reason: fm
                    .tombstone_reason
                    .clone()
                    .unwrap_or_else(|| "demo tombstone".into()),
            };
            let signed = signed_request(
                req,
                signing_key,
                key_uuid,
                "/headlines.v1.ArticleService/TombstoneArticle",
            )?;
            articles_client
                .tombstone_article(signed)
                .await
                .with_context(|| format!("TombstoneArticle({})", map_key))?;
        }
        Some("redacted-current") => {
            // RedactArticleVersion is system-only. Use the demo-admin system
            // identity by inserting via SQL — simpler than wiring a separate
            // signed RPC for the rare case.
            let mut conn = db.get().await?;
            diesel::sql_query(
                "UPDATE article_versions \
                 SET content = NULL, redacted_at = now(), redaction_reason = $1 \
                 WHERE article_id = $2 AND version = 1",
            )
            .bind::<Text, _>(
                fm.redaction_reason
                    .clone()
                    .unwrap_or_else(|| "demo redaction".into()),
            )
            .bind::<SqlUuid, _>(article_id)
            .execute(&mut conn)
            .await?;
        }
        _ => {}
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Step 5 — follows.
// ---------------------------------------------------------------------------

async fn seed_follows(
    channel: &Channel,
    user_keys: &[LoadedKey],
    state: &SeedState,
) -> anyhow::Result<()> {
    let user_map: std::collections::HashMap<&str, &LoadedKey> =
        user_keys.iter().map(|k| (k.name.as_str(), k)).collect();
    let mut client = FollowServiceClient::new(channel.clone());
    for (user_name, accts) in FOLLOWS {
        let user_key = match user_map.get(user_name) {
            Some(k) => *k,
            None => continue,
        };
        let user_record = match state.users.get(*user_name) {
            Some(r) => r,
            None => continue,
        };
        let user_id = match Uuid::parse_str(&user_record.id) {
            Ok(u) => u,
            Err(_) => continue,
        };
        let user_key_id = match Uuid::parse_str(&user_record.key_id) {
            Ok(u) => u,
            Err(_) => continue,
        };
        for acct in *accts {
            let acct_record = match state.accounts.get(*acct) {
                Some(r) => r,
                None => continue,
            };
            let req = FollowRequest {
                user_id: user_id.to_string(),
                account_id: acct_record.id.clone(),
            };
            let signed = signed_request(
                req,
                &user_key.signing_key,
                user_key_id,
                "/headlines.v1.FollowService/Follow",
            )?;
            // Idempotency: server's Follow is idempotent (re-following is OK)
            // but we still try once and ignore "AlreadyExists".
            match client.follow(signed).await {
                Ok(_) => {}
                Err(e) if e.code() == tonic::Code::AlreadyExists => {}
                Err(e) => {
                    return Err(anyhow!("Follow({user_name} → {acct}): {e}"));
                }
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Step 6 — drafts.
// ---------------------------------------------------------------------------

async fn seed_drafts(
    channel: &Channel,
    account_keys: &[LoadedKey],
    demo_path: &Path,
    state: &mut SeedState,
) -> anyhow::Result<()> {
    let mut client = DraftServiceClient::new(channel.clone());
    for key in account_keys {
        let drafts = load_account_articles(demo_path, &key.name, "drafts")?;
        let acct_record = match state.accounts.get(&key.name) {
            Some(r) => r,
            None => continue,
        };
        let acct_uuid = Uuid::parse_str(&acct_record.id)?;
        let key_uuid = Uuid::parse_str(&acct_record.key_id)?;
        for la in drafts {
            let map_key = format!("{}/{}", key.name, la.filename);
            if state.drafts.contains_key(&map_key) {
                continue;
            }
            let fm = &la.article.frontmatter;
            let req = CreateDraftRequest {
                account_id: acct_uuid.to_string(),
                title: fm.title.clone(),
                author_name: fm
                    .author_name
                    .clone()
                    .unwrap_or_else(|| "Demo Author".into()),
                author_url: fm
                    .author_url
                    .clone()
                    .unwrap_or_else(|| "https://example.com".into()),
                content: markdown_to_nodes(&la.article.body),
            };
            let signed = signed_request(
                req,
                &key.signing_key,
                key_uuid,
                "/headlines.v1.DraftService/CreateDraft",
            )?;
            let resp = client
                .create_draft(signed)
                .await
                .with_context(|| format!("CreateDraft({map_key})"))?
                .into_inner();
            state.drafts.insert(map_key, resp.id);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Step 7 — recommendation feeds.
// ---------------------------------------------------------------------------

async fn seed_recommendation_feeds(
    channel: &Channel,
    system_keys: &[LoadedKey],
    state: &SeedState,
    rng_seed: u64,
) -> anyhow::Result<()> {
    let ranker = system_keys
        .iter()
        .find(|k| k.name == "demo-ranker")
        .ok_or_else(|| anyhow!("demo-ranker key not loaded"))?;
    let ranker_record = state
        .systems
        .get("demo-ranker")
        .ok_or_else(|| anyhow!("demo-ranker not seeded"))?;
    let ranker_key_id = Uuid::parse_str(&ranker_record.key_id)?;

    let mut client = FeedRecommendationServiceClient::new(channel.clone());
    let all_articles: Vec<&String> = state.articles.values().collect();
    if all_articles.is_empty() {
        tracing::info!("no articles seeded; skipping recommendation feeds");
        return Ok(());
    }
    let mut rng = ChaCha8Rng::seed_from_u64(rng_seed);
    for user_record in state.users.values() {
        // Pick ~15 articles per user, deterministically.
        let mut pool: Vec<String> = all_articles.iter().map(|s| (*s).clone()).collect();
        pool.shuffle(&mut rng);
        let pick = pool.into_iter().take(15).collect::<Vec<_>>();
        let req = ReplaceRecommendationFeedRequest {
            user_id: user_record.id.clone(),
            article_ids: pick,
        };
        let signed = signed_request(
            req,
            &ranker.signing_key,
            ranker_key_id,
            "/headlines.v1.FeedRecommendationService/ReplaceRecommendationFeed",
        )?;
        client
            .replace_recommendation_feed(signed)
            .await
            .context("ReplaceRecommendationFeed")?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Step 8 — events.
// ---------------------------------------------------------------------------

async fn seed_events(
    channel: &Channel,
    user_keys: &[LoadedKey],
    state: &SeedState,
    rng_seed: u64,
) -> anyhow::Result<()> {
    let mut client = EventServiceClient::new(channel.clone());
    let user_lookup: std::collections::HashMap<&str, &LoadedKey> =
        user_keys.iter().map(|k| (k.name.as_str(), k)).collect();
    let articles: Vec<String> = state.articles.values().cloned().collect();
    if articles.is_empty() {
        tracing::info!("no articles; skipping events");
        return Ok(());
    }
    let mut rng = ChaCha8Rng::seed_from_u64(rng_seed.wrapping_add(1));
    // Target distribution: ~3000 events total, spread roughly evenly over
    // users. Server clamps occurred_at to [now-24h, now+60s] per events.md,
    // so we emit recent timestamps — we record events as near-`now` to
    // stay safely inside that window, regardless of frontmatter dates.
    let target_per_user = 3000 / state.users.len().max(1);
    for (user_name, user_record) in &state.users {
        let user_key = match user_lookup.get(user_name.as_str()) {
            Some(k) => *k,
            None => continue,
        };
        let user_key_id = Uuid::parse_str(&user_record.key_id)?;

        // Build batches of ~100; the configured cap is 500 (default), so we
        // stay well under it.
        let mut emitted = 0;
        while emitted < target_per_user {
            let batch_size = (target_per_user - emitted).min(100);
            let mut events = Vec::with_capacity(batch_size);
            for _ in 0..batch_size {
                let article = articles
                    .choose(&mut rng)
                    .cloned()
                    .unwrap_or_else(|| Uuid::nil().to_string());
                let etype_pick = rng.gen_range(0..100);
                let (etype, props) = if etype_pick < 50 {
                    (
                        EventType::Impression,
                        record_event_request::Properties::Impression(ImpressionProperties {
                            feed_kind: "follow".into(),
                            position: rng.gen_range(0..20),
                        }),
                    )
                } else if etype_pick < 75 {
                    (
                        EventType::Open,
                        record_event_request::Properties::Open(OpenProperties {
                            feed_kind: "recommendation".into(),
                            position: rng.gen_range(0..20),
                        }),
                    )
                } else if etype_pick < 90 {
                    (
                        EventType::Dwell,
                        record_event_request::Properties::Dwell(DwellProperties {
                            // log-normal-ish distribution: bias toward small
                            // dwell, with occasional long ones.
                            dwell_ms: lognormal_dwell(&mut rng),
                        }),
                    )
                } else {
                    (
                        EventType::Like,
                        record_event_request::Properties::Like(LikeProperties {}),
                    )
                };
                let occurred_at = now_minus_jitter(&mut rng);
                events.push(RecordEventRequest {
                    user_id: user_record.id.clone(),
                    article_id: article,
                    r#type: etype as i32,
                    occurred_at: Some(occurred_at),
                    surface: pick_surface(&mut rng).into(),
                    properties: Some(props),
                });
            }
            let req = RecordEventBatchRequest { events };
            let signed = signed_request(
                req,
                &user_key.signing_key,
                user_key_id,
                "/headlines.v1.EventService/RecordEventBatch",
            )?;
            let resp = client
                .record_event_batch(signed)
                .await
                .context("RecordEventBatch")?
                .into_inner();
            emitted += resp.stored_count as usize;
            if resp.stored_count == 0 {
                break;
            }
        }
    }
    Ok(())
}

fn pick_surface(rng: &mut ChaCha8Rng) -> &'static str {
    let r: u32 = rng.gen_range(0..100);
    if r < 60 {
        "web"
    } else if r < 90 {
        "mobile"
    } else {
        "tablet"
    }
}

fn lognormal_dwell(rng: &mut ChaCha8Rng) -> i64 {
    // Approximation: pick a small base, then occasionally multiply.
    let base: i64 = rng.gen_range(500..5_000);
    let amplifier: i64 = if rng.gen_range(0..10) == 0 { 10 } else { 1 };
    base * amplifier
}

fn now_minus_jitter(rng: &mut ChaCha8Rng) -> Timestamp {
    // Sample within the last 6 hours so the events service's occurred_at
    // window (now-24h .. now+60s) accepts every emission.
    let now = Utc::now();
    let jitter_minutes: i64 = rng.gen_range(0..(6 * 60));
    let dt = now - chrono::Duration::minutes(jitter_minutes);
    Timestamp {
        seconds: dt.timestamp(),
        nanos: dt.timestamp_subsec_nanos() as i32,
    }
}

// ---------------------------------------------------------------------------
// Reset helper — for `--reset`.
// ---------------------------------------------------------------------------

async fn clear_demo_data(db: &Db) -> anyhow::Result<()> {
    let mut conn = db.get().await?;
    // Order matters per FK constraints. This is a destructive op intended
    // for demo-only databases.
    let stmts = [
        "DELETE FROM events",
        "DELETE FROM feed_recommendation",
        "DELETE FROM follows",
        "DELETE FROM article_versions",
        "DELETE FROM articles_live",
        "DELETE FROM articles_tombstone",
        "DELETE FROM articles",
        "DELETE FROM drafts",
        "DELETE FROM account_keys",
        "DELETE FROM accounts",
        "DELETE FROM user_keys",
        "DELETE FROM users",
        "DELETE FROM system_keys",
        "DELETE FROM system_scopes",
        "DELETE FROM systems",
    ];
    for s in stmts {
        diesel::sql_query(s).execute(&mut conn).await?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Channel + signing helpers.
// ---------------------------------------------------------------------------

async fn build_channel(endpoint: &str) -> anyhow::Result<Channel> {
    let endpoint = Endpoint::from_shared(endpoint.to_owned())
        .with_context(|| format!("invalid endpoint {endpoint}"))?
        .connect_timeout(Duration::from_secs(5));
    // Retry briefly to give the server a moment if seed runs alongside boot.
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    let mut last_err = None;
    while std::time::Instant::now() < deadline {
        match endpoint.connect().await {
            Ok(c) => return Ok(c),
            Err(e) => {
                last_err = Some(e);
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
    }
    Err(anyhow!(
        "could not connect to gRPC server at {endpoint:?}: {}",
        last_err
            .map(|e| e.to_string())
            .unwrap_or_else(|| "unknown".into())
    ))
}

fn signed_request<M: prost::Message + Clone>(
    msg: M,
    sk: &SigningKey,
    key_id: Uuid,
    full_method: &str,
) -> anyhow::Result<tonic::Request<M>> {
    let body_bytes = msg.encode_to_vec();
    let request_hash: [u8; 32] = Sha256::digest(&body_bytes).into();
    let mut hex_str = String::with_capacity(64);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for b in &request_hash {
        hex_str.push(HEX[(*b >> 4) as usize] as char);
        hex_str.push(HEX[(*b & 0x0F) as usize] as char);
    }
    // Tso encoding: `(physical_ms << 18) | logical`. We always use logical=0
    // for seed requests; the physical ms is the wall clock the server's
    // InProcessTso compares against its horizon (default 30s).
    let ts_ms = (Utc::now().timestamp_millis() as u64) << 18;
    let nonce = Uuid::now_v7().as_bytes().to_vec();
    let canonical = format!(
        "HEADLINES-SIGN-V1\nPOST\n{path}\n\n{hex}\n{kid}\n{ts}\n{nonce_b64}",
        path = full_method,
        hex = hex_str,
        kid = key_id,
        ts = ts_ms,
        nonce_b64 = B64.encode(&nonce),
    );
    let sig = sk.sign(canonical.as_bytes()).to_bytes();
    let header = format!(
        "Signature key_id={kid}, algo=ed25519, ts={ts}, nonce={nonce_b64}, sig={sig_b64}",
        kid = key_id,
        ts = ts_ms,
        nonce_b64 = B64.encode(&nonce),
        sig_b64 = B64.encode(sig),
    );
    let mut req = tonic::Request::new(msg);
    req.metadata_mut()
        .insert("authorization", header.parse().unwrap());
    Ok(req)
}

// Convenience: best-effort parse of a path or default to the canonical
// `./demo` layout — used by the boot-time auto-seed gate.
pub fn default_demo_path() -> PathBuf {
    if let Ok(p) = std::env::var("HEADLINES_DEMO_PATH") {
        return PathBuf::from(p);
    }
    PathBuf::from("demo")
}
