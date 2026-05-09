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
    ProtoBodyHasher, SignedRequestStrategy, TrustedSubjectInterceptor,
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

    // ---- Service repos (shared Arcs across both gRPC listeners) ----
    let account_bootstrap = parse_bootstrap_mode(&config.auth.bootstrap.account_registration)?;
    let user_bootstrap = parse_bootstrap_mode(&config.auth.bootstrap.user_registration)?;
    let account_repo = Arc::new(headlines_store::PgAccountRepo::new(db.clone()));
    let key_repo = Arc::new(headlines_store::PgKeyRepo::new(db.clone()));
    let user_repo = Arc::new(headlines_store::PgUserRepo::new(db.clone()));
    let article_account_repo = Arc::new(headlines_store::PgAccountRepo::new(db.clone()));
    let article_repo = Arc::new(headlines_store::PgArticleRepo::new(db.clone()));
    let draft_account_repo = Arc::new(headlines_store::PgAccountRepo::new(db.clone()));
    let draft_repo = Arc::new(headlines_store::PgDraftRepo::new(db.clone()));
    let follow_user_repo = Arc::new(headlines_store::PgUserRepo::new(db.clone()));
    let follow_account_repo = Arc::new(headlines_store::PgAccountRepo::new(db.clone()));
    let follow_repo = Arc::new(headlines_store::PgFollowRepo::new(db.clone()));
    let feed_user_repo = Arc::new(headlines_store::PgUserRepo::new(db.clone()));
    let feed_repo = Arc::new(headlines_store::PgFeedRecommendationRepo::new(db.clone()));
    let feed_follow_user_repo = Arc::new(headlines_store::PgUserRepo::new(db.clone()));
    let feed_follow_repo = Arc::new(headlines_store::PgFeedFollowRepo::new(db.clone()));
    let account_stream_account_repo = Arc::new(headlines_store::PgAccountRepo::new(db.clone()));
    let account_stream_repo = Arc::new(headlines_store::PgAccountStreamRepo::new(db.clone()));
    let event_repo = Arc::new(headlines_store::PgEventRepo::new(db.clone()));

    // ---- Build the 10 services. Built once for the public listener,
    //      then again with the same `Arc` repos for the trusted listener.
    //      Service structs aren't `Clone`, so this is the cheapest way to
    //      hand both `tonic::transport::Server::add_service(...)` calls a
    //      service that owns the same shared state. ----
    let make_account = || {
        AccountServiceImpl::new(
            account_repo.clone(),
            key_repo.clone(),
            algos.clone(),
            account_bootstrap,
        )
    };
    let make_user = || {
        UserServiceImpl::new(
            user_repo.clone(),
            key_repo.clone(),
            algos.clone(),
            user_bootstrap,
        )
    };
    let make_article = || {
        ArticleServiceImpl::new(
            article_account_repo.clone(),
            article_repo.clone(),
            config.articles.content_max_bytes,
        )
        .with_metrics(Arc::clone(&domain_metrics))
    };
    let make_draft = || {
        DraftServiceImpl::new(
            draft_account_repo.clone(),
            draft_repo.clone(),
            config.articles.content_max_bytes,
        )
        .with_metrics(Arc::clone(&domain_metrics))
    };
    let make_follow = || {
        FollowServiceImpl::new(
            follow_user_repo.clone(),
            follow_account_repo.clone(),
            follow_repo.clone(),
        )
    };
    let make_feed_recommendation = || {
        FeedRecommendationServiceImpl::new(
            feed_user_repo.clone(),
            feed_repo.clone(),
            config.feeds.replace_max_items,
        )
        .with_metrics(Arc::clone(&domain_metrics))
    };
    let make_feed_follow =
        || FeedFollowServiceImpl::new(feed_follow_user_repo.clone(), feed_follow_repo.clone());
    let make_account_stream = || {
        AccountStreamServiceImpl::new(
            account_stream_account_repo.clone(),
            account_stream_repo.clone(),
        )
    };
    let make_event = || {
        EventServiceImpl::new(
            event_repo.clone(),
            Arc::clone(&time_source),
            config.events.batch_max_items,
        )
        .with_metrics(Arc::clone(&domain_metrics))
    };
    let make_notification = NotificationServiceImpl::new;

    // ---- Compose tower stack pieces ----
    let auth_interceptor = AuthInterceptor::new(Arc::clone(&strategy), Arc::new(ProtoBodyHasher))
        .with_metrics(Arc::clone(&auth_metrics));
    let trusted_interceptor = TrustedSubjectInterceptor::new();
    let authorize_public = AuthorizationLayer::new();
    let authorize_trusted = AuthorizationLayer::new();
    let trace_public = tower_http::trace::TraceLayer::new_for_grpc();
    let trace_trusted = tower_http::trace::TraceLayer::new_for_grpc();
    let rpc_metrics_public = metrics::MetricsLayer::new(Arc::clone(&rpc_metrics));
    let rpc_metrics_trusted = metrics::MetricsLayer::new(Arc::clone(&rpc_metrics));

    // ---- Public gRPC listener (the one external clients dial) ----
    let grpc_addr = bind.grpc_addr;
    let grpc_shutdown = shutdown_signal();
    let public_account = make_account();
    let public_user = make_user();
    let public_article = make_article();
    let public_draft = make_draft();
    let public_follow = make_follow();
    let public_feed_recommendation = make_feed_recommendation();
    let public_feed_follow = make_feed_follow();
    let public_account_stream = make_account_stream();
    let public_event = make_event();
    let public_notification = make_notification();
    let grpc_handle = tokio::spawn(async move {
        let server = Server::builder()
            .layer(trace_public)
            .layer(rpc_metrics_public)
            .layer(auth_interceptor)
            .layer(authorize_public)
            .add_service(AccountServiceServer::new(public_account))
            .add_service(UserServiceServer::new(public_user))
            .add_service(ArticleServiceServer::new(public_article))
            .add_service(DraftServiceServer::new(public_draft))
            .add_service(FollowServiceServer::new(public_follow))
            .add_service(FeedRecommendationServiceServer::new(
                public_feed_recommendation,
            ))
            .add_service(FeedFollowServiceServer::new(public_feed_follow))
            .add_service(AccountStreamServiceServer::new(public_account_stream))
            .add_service(EventServiceServer::new(public_event))
            .add_service(NotificationServiceServer::new(public_notification));
        info!(addr = %grpc_addr, "public gRPC server bound");
        if let Err(e) = server
            .serve_with_shutdown(grpc_addr, async {
                grpc_shutdown.await;
            })
            .await
        {
            tracing::error!(error = %e, "public gRPC server exited with error");
        } else {
            info!("public gRPC server stopped");
        }
    });

    // ---- Internal trusted gRPC listener (loopback only) ----
    //
    // Bound on `127.0.0.1:0` so the OS picks an ephemeral port we then
    // hand to the REST gateway. External clients cannot reach this
    // listener; trust is conveyed by the layer wrapping it
    // (`TrustedSubjectInterceptor`) lifting the gateway-supplied
    // `Subject` into request extensions without verifying signatures.
    let trusted_listener = std::net::TcpListener::bind("127.0.0.1:0")
        .context("bind internal trusted gRPC listener")?;
    trusted_listener
        .set_nonblocking(true)
        .context("set trusted listener nonblocking")?;
    let trusted_addr = trusted_listener
        .local_addr()
        .context("query trusted listener addr")?;
    let trusted_listener =
        tokio::net::TcpListener::from_std(trusted_listener).context("convert std listener")?;
    let trusted_inc = tokio_stream::wrappers::TcpListenerStream::new(trusted_listener);
    let trusted_shutdown = shutdown_signal();
    let trusted_account = make_account();
    let trusted_user = make_user();
    let trusted_article = make_article();
    let trusted_draft = make_draft();
    let trusted_follow = make_follow();
    let trusted_feed_recommendation = make_feed_recommendation();
    let trusted_feed_follow = make_feed_follow();
    let trusted_account_stream = make_account_stream();
    let trusted_event = make_event();
    let trusted_notification = make_notification();
    let trusted_handle = tokio::spawn(async move {
        let server = Server::builder()
            .layer(trace_trusted)
            .layer(rpc_metrics_trusted)
            .layer(trusted_interceptor)
            .layer(authorize_trusted)
            .add_service(AccountServiceServer::new(trusted_account))
            .add_service(UserServiceServer::new(trusted_user))
            .add_service(ArticleServiceServer::new(trusted_article))
            .add_service(DraftServiceServer::new(trusted_draft))
            .add_service(FollowServiceServer::new(trusted_follow))
            .add_service(FeedRecommendationServiceServer::new(
                trusted_feed_recommendation,
            ))
            .add_service(FeedFollowServiceServer::new(trusted_feed_follow))
            .add_service(AccountStreamServiceServer::new(trusted_account_stream))
            .add_service(EventServiceServer::new(trusted_event))
            .add_service(NotificationServiceServer::new(trusted_notification));
        info!(addr = %trusted_addr, "trusted (internal) gRPC server bound");
        if let Err(e) = server
            .serve_with_incoming_shutdown(trusted_inc, async {
                trusted_shutdown.await;
            })
            .await
        {
            tracing::error!(error = %e, "trusted gRPC server exited with error");
        } else {
            info!("trusted gRPC server stopped");
        }
    });

    // ---- REST gateway ----
    //
    // The gateway dials the **trusted** listener over loopback so the
    // resolved `Subject` from the gateway's auth strategy short-circuits
    // signature verification on the gRPC side.
    //
    // For split deployments the operator can override
    // `[server].rest_gateway_target` with an explicit `host:port`; in that
    // case the gateway falls back to dialing that target directly. In a
    // split deploy the trusted-listener short-circuit doesn't apply over
    // the network — the future mTLS upgrade path mentioned in `auth.md` is
    // the planned solution.
    let rest_endpoint = match config.server.rest_gateway_target.as_str() {
        "in_process" => format!("http://{}", trusted_addr),
        target => {
            if target.starts_with("http://") || target.starts_with("https://") {
                target.to_owned()
            } else {
                format!("http://{target}")
            }
        }
    };

    let rest_addr = bind.rest_addr;
    let rest_shutdown = shutdown_signal();
    let rest_strategy = Arc::clone(&strategy);
    let rest_handle = tokio::spawn(async move {
        let app = match wait_for_gateway(&rest_endpoint, rest_strategy, Duration::from_secs(5))
            .await
        {
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

    // Wait for all three surfaces to finish (Ctrl-C / SIGTERM trigger
    // shutdown_signal which unblocks each server concurrently).
    let _ = tokio::join!(grpc_handle, trusted_handle, rest_handle);
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
async fn wait_for_gateway(
    endpoint: &str,
    strategy: Arc<SignedRequestStrategy>,
    timeout: Duration,
) -> anyhow::Result<axum::Router> {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut last_err: Option<anyhow::Error> = None;
    while tokio::time::Instant::now() < deadline {
        match headlines_rest_gateway::build_app(endpoint, strategy.clone()).await {
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
