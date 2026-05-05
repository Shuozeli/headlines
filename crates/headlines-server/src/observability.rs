//! OpenTelemetry + tracing-subscriber boot.
//!
//! Per `docs/design/architecture.md` (Observability section):
//!
//! - `tracing-subscriber` is the entry point for application logs.
//! - `tracing-opentelemetry` bridges `tracing` spans → OTel spans.
//! - `opentelemetry-otlp` exports spans over OTLP/gRPC to the configured
//!   collector.
//! - Resource attributes: `service.name`, `service.version`,
//!   `deployment.environment`.
//!
//! The OTel exporter is best-effort — if the collector is unreachable at
//! startup we log a warning and continue. The exporter retries internally;
//! spans that can't ship are dropped.

use anyhow::Context;
use opentelemetry::KeyValue;
use opentelemetry::global;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::{SpanExporter, WithExportConfig};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::runtime;
use opentelemetry_sdk::trace::TracerProvider;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::Registry;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use crate::config::ObservabilityConfig;

/// Drops the OTel SDK on `Drop`. Hold this in scope for the lifetime of the
/// process.
pub struct Guard {
    provider: Option<TracerProvider>,
}

impl Drop for Guard {
    fn drop(&mut self) {
        if let Some(provider) = self.provider.take()
            && let Err(e) = provider.shutdown()
        {
            eprintln!("opentelemetry shutdown error: {e}");
        }
        global::shutdown_tracer_provider();
    }
}

/// Initialize the tracing subscriber stack and (best-effort) the OTLP
/// exporter.
pub fn init(config: &ObservabilityConfig) -> anyhow::Result<Guard> {
    let env_filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(&config.log_level))
        .context("build EnvFilter")?;

    // Try to construct the OTLP span exporter + tracer provider. Skip the
    // OTel layer if the exporter setup fails so a missing collector
    // doesn't take the binary down.
    let (otel_layer, provider) = match build_tracer(config) {
        Ok((layer, provider)) => (Some(layer), Some(provider)),
        Err(e) => {
            eprintln!(
                "warning: OTLP exporter init failed at startup; continuing without OTel exports: {e}"
            );
            (None, None)
        }
    };

    // The format-style branch needs to produce a single `Subscriber` type
    // that both arms can `try_init` on. We can't `Box` the layer here
    // because `Layered<Box<dyn Layer>, ...>` doesn't itself satisfy
    // `Layer<...>` for the next `.with(...)` call. So instead we duplicate
    // the assembly path per format choice — short-and-explicit beats clever
    // generic wrappers.
    let json = config.log_format.eq_ignore_ascii_case("json");
    if json {
        let subscriber = Registry::default()
            .with(env_filter)
            .with(otel_layer)
            .with(tracing_subscriber::fmt::layer().json());
        subscriber.try_init().context("init tracing subscriber")?;
    } else {
        let subscriber = Registry::default()
            .with(env_filter)
            .with(otel_layer)
            .with(tracing_subscriber::fmt::layer());
        subscriber.try_init().context("init tracing subscriber")?;
    }

    Ok(Guard { provider })
}

/// Construct an OTLP-backed `TracerProvider` and a `tracing-opentelemetry`
/// layer that feeds spans into it. The returned layer's subscriber type
/// parameter is inferred from the call site.
fn build_tracer<S>(
    config: &ObservabilityConfig,
) -> anyhow::Result<(
    tracing_opentelemetry::OpenTelemetryLayer<S, opentelemetry_sdk::trace::Tracer>,
    TracerProvider,
)>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    let exporter = SpanExporter::builder()
        .with_tonic()
        .with_endpoint(&config.otlp_endpoint)
        .build()
        .context("build OTLP span exporter")?;

    let env = std::env::var("HEADLINES_ENV").unwrap_or_else(|_| "development".into());
    let resource = Resource::new(vec![
        KeyValue::new("service.name", config.service_name.clone()),
        KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
        KeyValue::new("deployment.environment", env),
    ]);

    let provider = TracerProvider::builder()
        .with_batch_exporter(exporter, runtime::Tokio)
        .with_resource(resource)
        .build();

    let tracer = provider.tracer(config.service_name.clone());
    let layer = tracing_opentelemetry::layer().with_tracer(tracer);

    let _ = global::set_tracer_provider(provider.clone());

    Ok((layer, provider))
}
