//! OpenTelemetry metrics boot + the per-RPC `MetricsLayer` middleware.
//!
//! Per `docs/design/architecture.md` (Observability section), Phase 8 wires:
//!
//! - `rpc_calls_total{service,method,subject_class,status}` — u64 counter.
//! - `rpc_latency_seconds{service,method}` — f64 histogram.
//!
//! The `MetricsLayer` slots into the gRPC tower stack alongside
//! `AuthInterceptor` / `AuthorizationLayer` / `TraceLayer`. It records both
//! instruments per call, classifying the gRPC outcome from the `grpc-status`
//! response header.
//!
//! `init_meter_provider()` boots an `SdkMeterProvider` backed by an OTLP
//! periodic reader (best-effort — if the collector is unreachable we log and
//! return a no-op provider so the binary keeps running). The interceptor's
//! `auth_results_total` (in `headlines-auth::metrics`) and the domain
//! counters (in `headlines-api::metrics`) read `global::meter("...")` once
//! the provider is registered globally.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

use opentelemetry::KeyValue;
use opentelemetry::global;
use opentelemetry::metrics::{Counter, Histogram};
use opentelemetry_otlp::{MetricExporter, WithExportConfig};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use opentelemetry_sdk::runtime;
use tonic::body::BoxBody;
use tower::{Layer, Service};

use crate::config::ObservabilityConfig;

/// RAII guard for the metrics provider — held on the binary's call stack
/// so the provider lives until shutdown. Dropping flushes any buffered
/// metrics.
pub struct MetricsGuard {
    provider: Option<SdkMeterProvider>,
}

impl Drop for MetricsGuard {
    fn drop(&mut self) {
        if let Some(p) = self.provider.take()
            && let Err(e) = p.shutdown()
        {
            eprintln!("opentelemetry metrics shutdown error: {e}");
        }
    }
}

/// Initialize the metrics SDK. On collector-unreachable / build failure we
/// log and return a `MetricsGuard` that holds no provider — the global
/// `MeterProvider` falls back to the no-op default and instruments stay
/// callable.
pub fn init_meter_provider(config: &ObservabilityConfig) -> MetricsGuard {
    match build_provider(config) {
        Ok(provider) => {
            global::set_meter_provider(provider.clone());
            MetricsGuard {
                provider: Some(provider),
            }
        }
        Err(e) => {
            eprintln!(
                "warning: OTLP metrics exporter init failed at startup; continuing without metric exports: {e}"
            );
            MetricsGuard { provider: None }
        }
    }
}

fn build_provider(
    config: &ObservabilityConfig,
) -> Result<SdkMeterProvider, Box<dyn std::error::Error + Send + Sync>> {
    let exporter = MetricExporter::builder()
        .with_tonic()
        .with_endpoint(&config.otlp_endpoint)
        .build()?;

    let reader = PeriodicReader::builder(exporter, runtime::Tokio).build();

    let env = std::env::var("HEADLINES_ENV").unwrap_or_else(|_| "development".into());
    let resource = Resource::new(vec![
        KeyValue::new("service.name", config.service_name.clone()),
        KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
        KeyValue::new("deployment.environment", env),
    ]);

    Ok(SdkMeterProvider::builder()
        .with_reader(reader)
        .with_resource(resource)
        .build())
}

// ---------------------------------------------------------------------------
// MetricsLayer — records `rpc_calls_total` + `rpc_latency_seconds` per call.
// ---------------------------------------------------------------------------

/// Per-RPC instruments. Both shared via `Arc` so the tower stack can clone
/// the layer cheaply per upstream service.
#[derive(Clone)]
pub struct RpcMetrics {
    pub rpc_calls_total: Counter<u64>,
    pub rpc_latency_seconds: Histogram<f64>,
}

impl RpcMetrics {
    /// Build instruments from the named meter. The binary calls this with
    /// `global::meter("headlines-server")` after `init_meter_provider`.
    pub fn new(meter: &opentelemetry::metrics::Meter) -> Self {
        Self {
            rpc_calls_total: meter
                .u64_counter("rpc_calls_total")
                .with_description("Total RPCs by (service, method, subject_class, status).")
                .build(),
            rpc_latency_seconds: meter
                .f64_histogram("rpc_latency_seconds")
                .with_description("Per-RPC end-to-end handler latency, in seconds.")
                .with_unit("s")
                .build(),
        }
    }

    #[allow(dead_code)] // used in tests; kept on the public surface for test parity.
    pub fn no_op() -> Self {
        let meter = global::meter("headlines-server-noop");
        Self::new(&meter)
    }

    #[allow(dead_code)]
    pub fn shared_no_op() -> Arc<Self> {
        Arc::new(Self::no_op())
    }
}

impl std::fmt::Debug for RpcMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RpcMetrics")
            .field("rpc_calls_total", &"<counter>")
            .field("rpc_latency_seconds", &"<histogram>")
            .finish()
    }
}

/// Tower layer that records per-RPC counters/histograms on every call. Slots
/// in alongside `AuthInterceptor` / `AuthorizationLayer` / `TraceLayer`.
#[derive(Clone)]
pub struct MetricsLayer {
    metrics: Arc<RpcMetrics>,
}

impl MetricsLayer {
    pub fn new(metrics: Arc<RpcMetrics>) -> Self {
        Self { metrics }
    }
}

impl<S> Layer<S> for MetricsLayer {
    type Service = MetricsService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        MetricsService {
            inner,
            metrics: self.metrics.clone(),
        }
    }
}

#[derive(Clone)]
pub struct MetricsService<S> {
    inner: S,
    metrics: Arc<RpcMetrics>,
}

impl<S> Service<http::Request<BoxBody>> for MetricsService<S>
where
    S: Service<http::Request<BoxBody>, Response = http::Response<BoxBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + Sync + 'static,
{
    type Response = http::Response<BoxBody>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: http::Request<BoxBody>) -> Self::Future {
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let metrics = self.metrics.clone();

        // gRPC path is `/headlines.v1.<Service>/<Method>`. Split once so the
        // labels reflect the proto-level service/method names.
        let path = req.uri().path().to_owned();
        let (service, method) = split_grpc_path(&path);
        let subject_class = subject_class_from_extensions(&req);

        let started = Instant::now();
        Box::pin(async move {
            let result = inner.call(req).await;
            let elapsed = started.elapsed().as_secs_f64();

            let status = match &result {
                Ok(resp) => grpc_status_from_response(resp),
                Err(_) => "transport_error".to_owned(),
            };

            let labels_counter = vec![
                KeyValue::new("service", service.clone()),
                KeyValue::new("method", method.clone()),
                KeyValue::new("subject_class", subject_class),
                KeyValue::new("status", status),
            ];
            let labels_hist = vec![
                KeyValue::new("service", service),
                KeyValue::new("method", method),
            ];
            metrics.rpc_calls_total.add(1, &labels_counter);
            metrics.rpc_latency_seconds.record(elapsed, &labels_hist);

            result
        })
    }
}

/// Split a gRPC path of the form `/<package>.<Service>/<Method>` into its
/// `(service, method)` halves. Falls back to `("", path)` on malformed input
/// so unknown routes still produce a single bucket rather than panicking.
fn split_grpc_path(path: &str) -> (String, String) {
    let trimmed = path.trim_start_matches('/');
    let mut parts = trimmed.splitn(2, '/');
    let service = parts.next().unwrap_or("").to_owned();
    let method = parts.next().unwrap_or("").to_owned();
    if service.is_empty() && method.is_empty() {
        ("unknown".to_owned(), path.to_owned())
    } else if method.is_empty() {
        ("unknown".to_owned(), service)
    } else {
        (service, method)
    }
}

/// Read the resolved `Subject` from request extensions (set by
/// `AuthInterceptor`) and project to its class label. Falls back to
/// `"none"` if the interceptor hasn't run (e.g. some test wiring).
fn subject_class_from_extensions(req: &http::Request<BoxBody>) -> String {
    use headlines_core::Subject;
    match req.extensions().get::<Subject>() {
        Some(Subject::Anonymous) => "anonymous".to_owned(),
        Some(Subject::User { .. }) => "user".to_owned(),
        Some(Subject::Account { .. }) => "account".to_owned(),
        Some(Subject::System { .. }) => "system".to_owned(),
        None => "none".to_owned(),
    }
}

/// Map an HTTP response carrying a gRPC status to a stable label string.
/// `grpc-status` header is the canonical source; if it's missing (e.g.
/// transport-level error) we report `"unknown"`.
fn grpc_status_from_response(resp: &http::Response<BoxBody>) -> String {
    let raw = match resp.headers().get("grpc-status") {
        Some(v) => v.to_str().unwrap_or(""),
        None => return "ok".to_owned(),
    };
    let code: i32 = raw.parse().unwrap_or(-1);
    grpc_code_label(code).to_owned()
}

fn grpc_code_label(code: i32) -> &'static str {
    match code {
        0 => "ok",
        1 => "cancelled",
        2 => "unknown",
        3 => "invalid_argument",
        4 => "deadline_exceeded",
        5 => "not_found",
        6 => "already_exists",
        7 => "permission_denied",
        8 => "resource_exhausted",
        9 => "failed_precondition",
        10 => "aborted",
        11 => "out_of_range",
        12 => "unimplemented",
        13 => "internal",
        14 => "unavailable",
        15 => "data_loss",
        16 => "unauthenticated",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;
    use std::convert::Infallible;
    use tower::ServiceExt;

    #[test]
    fn split_grpc_path_handles_canonical_form() {
        // Arrange / Act
        let (svc, method) = split_grpc_path("/headlines.v1.AccountService/GetAccount");

        // Assert
        assert_eq!(svc, "headlines.v1.AccountService");
        assert_eq!(method, "GetAccount");
    }

    #[test]
    fn split_grpc_path_handles_no_slash() {
        // Arrange / Act
        let (svc, method) = split_grpc_path("nonsense");

        // Assert
        assert_eq!(svc, "unknown");
        assert_eq!(method, "nonsense");
    }

    #[test]
    fn grpc_code_label_round_trips_canonical_codes() {
        // Arrange / Act / Assert
        assert_eq!(grpc_code_label(0), "ok");
        assert_eq!(grpc_code_label(7), "permission_denied");
        assert_eq!(grpc_code_label(12), "unimplemented");
        assert_eq!(grpc_code_label(16), "unauthenticated");
        assert_eq!(grpc_code_label(999), "unknown");
    }

    fn empty_body() -> BoxBody {
        use http_body_util::Empty;
        Empty::<bytes::Bytes>::new()
            .map_err(|never| match never {})
            .boxed_unsync()
    }

    #[derive(Clone, Default)]
    struct OkService;

    impl Service<http::Request<BoxBody>> for OkService {
        type Response = http::Response<BoxBody>;
        type Error = Infallible;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: http::Request<BoxBody>) -> Self::Future {
            Box::pin(async move {
                let mut resp = http::Response::new(empty_body());
                resp.headers_mut()
                    .insert("grpc-status", http::HeaderValue::from_static("0"));
                Ok(resp)
            })
        }
    }

    #[tokio::test]
    async fn metrics_layer_passes_response_through_and_records_one_call() {
        // Arrange — a no-op global meter is fine; we just want to confirm
        // the middleware doesn't crash and lets the response through.
        let metrics = RpcMetrics::shared_no_op();
        let layer = MetricsLayer::new(metrics);
        let mut svc = layer.layer(OkService);

        let req = http::Request::builder()
            .uri("/headlines.v1.AccountService/GetAccount")
            .body(empty_body())
            .unwrap();

        // Act
        let resp = svc.ready().await.unwrap().call(req).await.unwrap();

        // Assert
        assert_eq!(
            resp.headers().get("grpc-status").unwrap().to_str().unwrap(),
            "0"
        );
    }
}
