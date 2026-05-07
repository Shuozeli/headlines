//! `headlines-server` binary — wires gRPC + REST gateway + auth + observability.
//!
//! Phase 6 boot sequence:
//!
//! 1. Parse CLI flags (`clap`).
//! 2. Layer config (defaults → file → env → CLI) via `figment`.
//! 3. Initialize tracing-subscriber + OpenTelemetry OTLP exporter.
//! 4. Resolve bind addresses (Tailscale-IP override).
//! 5. Connect to Postgres; optionally run pending migrations.
//! 6. Build the auth pipeline: time source (`InProcessTso` → Postgres),
//!    nonce store (in-process LRU), algorithm registry (`Ed25519`), key
//!    resolver (Postgres-backed), then `SignedRequestStrategy`.
//! 7. Compose tower stack: `AuthInterceptor` → `AuthorizationLayer` →
//!    `TraceLayer` → service.
//! 8. Spawn gRPC server.
//! 9. Connect a local tonic `Channel` and bring up the axum REST gateway
//!    over the same set of services.
//! 10. Wait on Ctrl-C / SIGTERM and graceful-shutdown both surfaces.

mod cli;
mod config;
mod metrics;
mod observability;
mod tailscale;

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use clap::Parser;
use tonic::transport::Server;
use tracing::info;

use headlines_api::{
    AccountServiceImpl, AccountStreamServiceImpl, ArticleServiceImpl, BootstrapMode, DomainMetrics,
    DraftServiceImpl, EventServiceImpl, FeedFollowServiceImpl, FeedRecommendationServiceImpl,
    FollowServiceImpl, NotificationServiceImpl, UserServiceImpl,
};
use headlines_auth::{
    AlgorithmRegistry, AuthInterceptor, AuthMetrics, AuthorizationLayer, InMemoryNonceStore,
    InProcessTso, InProcessTsoConfig, LocalClock, PostgresKeyResolver, PostgresTsoStore,
    ProtoBodyHasher, SignedRequestStrategy,
};
use headlines_core::TimeSource;
use headlines_proto::v1::account_service_server::AccountServiceServer;
use headlines_proto::v1::account_stream_service_server::AccountStreamServiceServer;
use headlines_proto::v1::article_service_server::ArticleServiceServer;
use headlines_proto::v1::draft_service_server::DraftServiceServer;
use headlines_proto::v1::event_service_server::EventServiceServer;
use headlines_proto::v1::feed_follow_service_server::FeedFollowServiceServer;
use headlines_proto::v1::feed_recommendation_service_server::FeedRecommendationServiceServer;
use headlines_proto::v1::follow_service_server::FollowServiceServer;
use headlines_proto::v1::notification_service_server::NotificationServiceServer;
use headlines_proto::v1::user_service_server::UserServiceServer;
use headlines_store::Db;

use crate::cli::Cli;
use crate::config::Config;
use crate::tailscale::{BindAddrs, BindSource};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let config = Config::load(&cli)?;
    let _otel_guard = observability::init(&config.observability)?;
    let _metrics_guard = metrics::init_meter_provider(&config.observability);

    // Build the shared instrument bundles once the global meter provider is
    // registered. The `headlines-api` and `headlines-auth` crates pick up
    // `global::meter("...")` so we can build their counters here too.
    let domain_metrics = Arc::new(DomainMetrics::new(&opentelemetry::global::meter(
        "headlines-server",
    )));
    let auth_metrics = Arc::new(AuthMetrics::new(&opentelemetry::global::meter(
        "headlines-server",
    )));
    let rpc_metrics = Arc::new(metrics::RpcMetrics::new(&opentelemetry::global::meter(
        "headlines-server",
    )));

    let bind = tailscale::resolve_bind(&config.server)?;

    info!(
        grpc = %bind.grpc_addr,
        rest = %bind.rest_addr,
        source = ?bind.source,
        version = env!("CARGO_PKG_VERSION"),
        "headlines-server starting",
    );
    log_bind_source(&bind);

    let db = Db::connect(&config.database.url, config.database.max_connections)
        .await
        .context("connect to Postgres")?;
    if !cli.skip_migrations {
        info!("running pending migrations");
        headlines_store::run_pending_migrations(&db)
            .await
            .context("apply pending migrations")?;
    } else {
        info!("--skip-migrations set: not running embedded migrations");
    }

    // ---- Time source ----
    //
    // Default to InProcessTso backed by Postgres (matches `auth.md`). Operator
    // can opt out of Postgres persistence via [auth.time].source = "local_clock"
    // for dev / smoke runs.
    let time_source: Arc<TimeSourceArc> = Arc::new(build_time_source(&config, db.clone()).await?);

    // ---- Nonce store ----
    let nonce_store = Arc::new(InMemoryNonceStore::new());

    // ---- Algorithm registry ----
    let algos = Arc::new(build_algorithm_registry(&config)?);

    // ---- Resolver ----
    let resolver = Arc::new(PostgresKeyResolver::new(db.clone()));

    // ---- Strategy ----
    let strategy = Arc::new(SignedRequestStrategy::new(
        resolver,
        algos.clone(),
        Arc::clone(&time_source),
        Arc::clone(&nonce_store),
    ));

    // ---- AccountService ----
    let account_repo = Arc::new(headlines_store::PgAccountRepo::new(db.clone()));
    let key_repo = Arc::new(headlines_store::PgKeyRepo::new(db.clone()));
    let account_bootstrap = parse_bootstrap_mode(&config.auth.bootstrap.account_registration)?;
    let account_svc = AccountServiceImpl::new(
        account_repo,
        key_repo.clone(),
        algos.clone(),
        account_bootstrap,
    );

    // ---- UserService ----
    let user_repo = Arc::new(headlines_store::PgUserRepo::new(db.clone()));
    let user_bootstrap = parse_bootstrap_mode(&config.auth.bootstrap.user_registration)?;
    let user_svc = UserServiceImpl::new(user_repo, key_repo, algos.clone(), user_bootstrap);

    // ---- ArticleService ----
    //
    // The Article handler holds an `Arc<dyn AccountRepo>` for the
    // account-active precondition on Publish; it shares the same Postgres
    // pool. `content_max_bytes` flows through `[articles]` (default in
    // `Config::default` via the api-crate `DEFAULT_CONTENT_MAX_BYTES`).
    let article_account_repo = Arc::new(headlines_store::PgAccountRepo::new(db.clone()));
    let article_repo = Arc::new(headlines_store::PgArticleRepo::new(db.clone()));
    let article_svc = ArticleServiceImpl::new(
        article_account_repo,
        article_repo,
        config.articles.content_max_bytes,
    )
    .with_metrics(Arc::clone(&domain_metrics));

    // ---- DraftService ----
    //
    // Same content cap as ArticleService — drafts must be valid articles per
    // `drafts.md`. Holds its own `Arc<dyn AccountRepo>` so the
    // CreateDraft / PublishDraft handlers can re-check the owning account
    // is active. Shares `[articles].content_max_bytes` because drafts and
    // published articles must agree on the cap.
    let draft_account_repo = Arc::new(headlines_store::PgAccountRepo::new(db.clone()));
    let draft_repo = Arc::new(headlines_store::PgDraftRepo::new(db.clone()));
    let draft_svc = DraftServiceImpl::new(
        draft_account_repo,
        draft_repo,
        config.articles.content_max_bytes,
    )
    .with_metrics(Arc::clone(&domain_metrics));

    // ---- FollowService ----
    //
    // Holds its own user/account repo handles to validate the target rows
    // before mutating the edge (`UserDeleted` / `AccountDeleted` per
    // `follows.md`). The `FollowRepo` is a separate concrete impl over the
    // shared pool.
    let follow_user_repo = Arc::new(headlines_store::PgUserRepo::new(db.clone()));
    let follow_account_repo = Arc::new(headlines_store::PgAccountRepo::new(db.clone()));
    let follow_repo = Arc::new(headlines_store::PgFollowRepo::new(db.clone()));
    let follow_svc = FollowServiceImpl::new(follow_user_repo, follow_account_repo, follow_repo);

    // ---- FeedRecommendationService ----
    //
    // System-only writer (the ranker), user-self reader. Holds its own
    // `UserRepo` handle to enforce existence + status checks before mutating
    // or reading the feed (per `feed-recommendation.md`).
    let feed_user_repo = Arc::new(headlines_store::PgUserRepo::new(db.clone()));
    let feed_repo = Arc::new(headlines_store::PgFeedRecommendationRepo::new(db.clone()));
    let feed_recommendation_svc = FeedRecommendationServiceImpl::new(
        feed_user_repo,
        feed_repo,
        config.feeds.replace_max_items,
    )
    .with_metrics(Arc::clone(&domain_metrics));

    // ---- FeedFollowService ----
    //
    // Read-only computed feed: `follows ⨝ articles_live` ordered by
    // `articles.created_at DESC`. User-self read or System with
    // `feeds.follow.read`. Holds its own `UserRepo` handle for the
    // existence + status precondition (per `feed-follow.md`).
    let feed_follow_user_repo = Arc::new(headlines_store::PgUserRepo::new(db.clone()));
    let feed_follow_repo = Arc::new(headlines_store::PgFeedFollowRepo::new(db.clone()));
    let feed_follow_svc = FeedFollowServiceImpl::new(feed_follow_user_repo, feed_follow_repo);

    // ---- AccountStreamService ----
    //
    // Pull-only watermark stream per account, system-only with
    // `articles.stream`. Holds an `AccountRepo` handle for the existence +
    // lifecycle precondition (per `account-stream.md`: the stream **closes**
    // on account deletion).
    let account_stream_account_repo = Arc::new(headlines_store::PgAccountRepo::new(db.clone()));
    let account_stream_repo = Arc::new(headlines_store::PgAccountStreamRepo::new(db.clone()));
    let account_stream_svc =
        AccountStreamServiceImpl::new(account_stream_account_repo, account_stream_repo);

    // ---- EventService ----
    //
    // Append-only user-activity log per `events.md`. Holds an `EventRepo`
    // handle and a shared `TimeSource` (the same one used by the auth
    // strategy) so the `occurred_at` window check is anchored to the same
    // monotonic TSO clock the rest of the server uses. `batch_max_items`
    // flows through `[events]` (default in `Config::default` via the api
    // crate's `DEFAULT_EVENTS_BATCH_MAX_ITEMS`).
    let event_repo = Arc::new(headlines_store::PgEventRepo::new(db.clone()));
    let event_svc = EventServiceImpl::new(
        event_repo,
        Arc::clone(&time_source),
        config.events.batch_max_items,
    )
    .with_metrics(Arc::clone(&domain_metrics));

    // ---- NotificationService ----
    //
    // Phase 7.9 reserves the surface: every RPC returns
    // `NOT_IMPLEMENTED_IN_V1`. No repo, no time source, no storage tables.
    // The proto-driven `AUTH_TABLE` still enforces subject + scope so a
    // misconfigured caller is rejected with `PERMISSION_DENIED` before the
    // handler runs. A future "delivery" doc / phase will replace this stub.
    let notification_svc = NotificationServiceImpl::new();

    // ---- Compose tower stack ----
    let auth_interceptor = AuthInterceptor::new(strategy, Arc::new(ProtoBodyHasher))
        .with_metrics(Arc::clone(&auth_metrics));
    let authorize = AuthorizationLayer::new();
    let trace = tower_http::trace::TraceLayer::new_for_grpc();
    let rpc_metrics_layer = metrics::MetricsLayer::new(Arc::clone(&rpc_metrics));

    // ---- gRPC server ----
    let grpc_addr = bind.grpc_addr;
    let grpc_shutdown = shutdown_signal();
    let grpc_handle = tokio::spawn(async move {
        let server = Server::builder()
            .layer(trace)
            .layer(rpc_metrics_layer)
            .layer(auth_interceptor)
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
        info!(addr = %grpc_addr, "gRPC server bound");
        if let Err(e) = server
            .serve_with_shutdown(grpc_addr, async {
                grpc_shutdown.await;
            })
            .await
        {
            tracing::error!(error = %e, "gRPC server exited with error");
        } else {
            info!("gRPC server stopped");
        }
    });

    // ---- REST gateway ----
    //
    // Wait briefly for the gRPC server to start accepting connections. We
    // poll a short timeout rather than racing the bind.
    let rest_endpoint = match config.server.rest_gateway_target.as_str() {
        "in_process" => format!("http://{}", grpc_addr),
        target => {
            // Allow a fully-qualified URL or `host:port` for split deploys.
            if target.starts_with("http://") || target.starts_with("https://") {
                target.to_owned()
            } else {
                format!("http://{target}")
            }
        }
    };

    let rest_addr = bind.rest_addr;
    let rest_shutdown = shutdown_signal();
    let rest_handle = tokio::spawn(async move {
        // The gRPC server may not be listening yet; the gateway dial retries
        // for a couple of seconds before giving up.
        let app = match wait_for_gateway(&rest_endpoint, Duration::from_secs(5)).await {
            Ok(app) => app,
            Err(e) => {
                tracing::error!(error = %e, "REST gateway failed to connect to gRPC channel; REST disabled");
                return;
            }
        };
        let listener = match tokio::net::TcpListener::bind(rest_addr).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(error = %e, addr = %rest_addr, "REST listener bind failed");
                return;
            }
        };
        info!(addr = %rest_addr, "REST gateway bound");
        if let Err(e) = axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                rest_shutdown.await;
            })
            .await
        {
            tracing::error!(error = %e, "REST gateway exited with error");
        } else {
            info!("REST gateway stopped");
        }
    });

    // Wait for both surfaces to finish (Ctrl-C triggers shutdown_signal which
    // unblocks both servers concurrently).
    let _ = tokio::join!(grpc_handle, rest_handle);
    info!("headlines-server shutdown complete");

    Ok(())
}

fn log_bind_source(bind: &BindAddrs) {
    match bind.source {
        BindSource::Tailscale => info!(host = %bind.grpc_host, "binding to TAILSCALE_IP"),
        BindSource::Config => info!(host = %bind.grpc_host, "binding to configured host"),
    }
}

/// Single shutdown signal future — returns when SIGINT (Ctrl-C) or SIGTERM
/// arrives. Build one per server task; both observe the same kernel signal
/// concurrently.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{SignalKind, signal};
        if let Ok(mut sig) = signal(SignalKind::terminate()) {
            sig.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => info!("received Ctrl-C; shutting down"),
        _ = terminate => info!("received SIGTERM; shutting down"),
    }
}

/// Try to dial the upstream gRPC channel for up to `timeout`, returning
/// the built REST router on success.
async fn wait_for_gateway(endpoint: &str, timeout: Duration) -> anyhow::Result<axum::Router> {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut last_err: Option<anyhow::Error> = None;
    while tokio::time::Instant::now() < deadline {
        match headlines_rest_gateway::build_app(endpoint).await {
            Ok(app) => return Ok(app),
            Err(e) => {
                last_err = Some(e);
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("gateway dial timed out")))
}

/// Translate the `[auth.bootstrap].account_registration` string from config
/// into the typed `BootstrapMode`.
pub(crate) fn parse_bootstrap_mode(s: &str) -> anyhow::Result<BootstrapMode> {
    match s {
        "open" => Ok(BootstrapMode::Open),
        "system_only" => Ok(BootstrapMode::SystemOnly),
        other => anyhow::bail!("invalid auth.bootstrap.account_registration: {other:?}"),
    }
}

/// Build the algorithm registry from `[auth.algorithms].enabled`. Currently
/// only `ed25519` is implemented; unknown names are a fatal error (a typo
/// must not silently disable the only algorithm and boot a server that
/// rejects every signed request). An empty list is also fatal — operators
/// must enable at least one algorithm.
fn build_algorithm_registry(config: &Config) -> anyhow::Result<AlgorithmRegistry> {
    if config.auth.algorithms.enabled.is_empty() {
        anyhow::bail!("[auth.algorithms].enabled must contain at least one algorithm");
    }
    let mut reg = AlgorithmRegistry::new();
    for name in &config.auth.algorithms.enabled {
        match name.as_str() {
            "ed25519" => {
                reg = reg.with(Box::new(headlines_auth::Ed25519));
            }
            other => {
                anyhow::bail!("unknown signature algorithm in [auth.algorithms].enabled: {other}");
            }
        }
    }
    Ok(reg)
}

/// Build the configured `TimeSource`, hidden behind a single
/// `Arc<dyn TimeSource>`-shaped marker via `Arc<DynTimeSource>` — the
/// strategy generic-erases internally so we can hand it any concrete
/// `TimeSource` impl.
async fn build_time_source(config: &Config, db: Db) -> anyhow::Result<TimeSourceArc> {
    match config.auth.time.source.as_str() {
        "in_process_tso" => {
            let store = Arc::new(PostgresTsoStore::new(db));
            let cfg = InProcessTsoConfig {
                horizon_ms: config.auth.time.horizon_seconds.saturating_mul(1_000),
                flush_interval_ms: 1_000,
            };
            let tso = InProcessTso::new(store, cfg)
                .await
                .context("init InProcessTso")?;
            Ok(TimeSourceArc::InProcessTso(Arc::new(tso)))
        }
        "local_clock" => Ok(TimeSourceArc::LocalClock(Arc::new(LocalClock::default()))),
        other => anyhow::bail!("invalid auth.time.source: {other:?}"),
    }
}

/// Owned wrapper that keeps the concrete `TimeSource` impl alive for the
/// process lifetime. Implements `TimeSource` itself by dispatching to the
/// active variant; the strategy generic-erases internally so we can hand it
/// any concrete `TimeSource` impl.
pub(crate) enum TimeSourceArc {
    InProcessTso(Arc<InProcessTso>),
    LocalClock(Arc<LocalClock>),
}

impl TimeSource for TimeSourceArc {
    // The trait declares `fn now(&self) -> impl Future<...> + Send`. We have
    // to mirror that exact signature; an `async fn` desugars to an opaque
    // future without the `+ Send` bound, which fails the trait constraint.
    #[allow(clippy::manual_async_fn)]
    fn now(
        &self,
    ) -> impl std::future::Future<Output = Result<headlines_core::Tso, headlines_core::TimeError>> + Send
    {
        async move {
            match self {
                TimeSourceArc::InProcessTso(t) => TimeSource::now(t.as_ref()).await,
                TimeSourceArc::LocalClock(t) => TimeSource::now(t.as_ref()).await,
            }
        }
    }

    #[allow(clippy::manual_async_fn)]
    fn validate(
        &self,
        ts: headlines_core::Tso,
    ) -> impl std::future::Future<Output = Result<(), headlines_core::TimeError>> + Send {
        async move {
            match self {
                TimeSourceArc::InProcessTso(t) => TimeSource::validate(t.as_ref(), ts).await,
                TimeSourceArc::LocalClock(t) => TimeSource::validate(t.as_ref(), ts).await,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bootstrap_mode_open() {
        // Arrange / Act
        let m = parse_bootstrap_mode("open").unwrap();

        // Assert
        assert_eq!(m, BootstrapMode::Open);
    }

    #[test]
    fn parse_bootstrap_mode_system_only() {
        // Arrange / Act
        let m = parse_bootstrap_mode("system_only").unwrap();

        // Assert
        assert_eq!(m, BootstrapMode::SystemOnly);
    }

    #[test]
    fn parse_bootstrap_mode_rejects_garbage() {
        // Arrange / Act
        let res = parse_bootstrap_mode("invalid-mode");

        // Assert
        assert!(res.is_err());
    }

    #[test]
    fn build_algorithm_registry_registers_ed25519() {
        // Arrange — default config has ed25519 enabled.
        let config = Config::default();

        // Act
        let reg = build_algorithm_registry(&config).expect("default config must build");

        // Assert
        assert!(reg.get("ed25519").is_some());
    }

    #[test]
    fn build_algorithm_registry_bails_on_unknown_name() {
        // Arrange — operator typo: an unknown algorithm name. A swallow-and-warn
        // boot would silently disable signature verification; we require a hard
        // failure.
        let mut config = Config::default();
        config.auth.algorithms.enabled = vec!["ed25519".into(), "rsa-pss".into()];

        // Act
        let res = build_algorithm_registry(&config);

        // Assert — error names the missing/unknown algorithm so an operator
        // can fix the config without grepping.
        let err = res.expect_err("unknown algorithm must be fatal");
        let msg = format!("{err:#}");
        assert!(msg.contains("rsa-pss"), "{msg}");
        assert!(
            msg.contains("[auth.algorithms].enabled"),
            "should name the config key: {msg}"
        );
    }

    #[test]
    fn build_algorithm_registry_bails_when_empty() {
        // Arrange — operator listed nothing, e.g. `enabled = []`. An empty
        // registry would authenticate nothing; we require a hard failure.
        let mut config = Config::default();
        config.auth.algorithms.enabled = Vec::new();

        // Act
        let res = build_algorithm_registry(&config);

        // Assert
        let err = res.expect_err("empty registry must be fatal");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("at least one algorithm"),
            "should name the requirement: {msg}"
        );
    }
}
