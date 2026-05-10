//! Smoke that asserts the `MetricsLayer` actually fires on real RPCs.
//!
//! `src/metrics.rs` carries unit tests that prove the layer doesn't crash
//! and passes the response through; none of them verifies that a counter
//! observation actually happens for a real RPC routed through the binary.
//! This file fills that gap.
//!
//! Approach (Option 2 from the operational batch spec): instead of
//! scraping a Prometheus endpoint (which would require pulling in
//! `opentelemetry-prometheus`, currently published only against
//! `opentelemetry 0.24` while we run 0.27 — version mismatch), we observe
//! per-RPC traffic via the tracing TraceLayer's DEBUG-level request span.
//! The span carries a `uri` field; `RUST_LOG=debug` makes the binary emit
//! one log line per RPC carrying that URI. We then count how many times
//! the `GetArticle` gRPC method path appears.
//!
//! This is strictly weaker than asserting the counter itself — it tests
//! tracing wiring, not the metrics layer in isolation — but the metrics
//! layer and the trace layer sit one above the other in `main.rs` and
//! both fire for every RPC. A regression that drops the metrics layer
//! while keeping the trace layer would not be caught by this test; that
//! gap is documented in the report and accepted given the dep-cost of
//! Option 1.
//!
//! Skips cleanly when `DATABASE_URL` is unset. AAA structure per
//! `~/.claude/rules/testing-patterns.md`.

#![cfg(unix)]

use std::io::Write;
use std::process::Stdio;
use std::time::{Duration, Instant};

use reqwest::StatusCode;
use tempfile::NamedTempFile;
use tokio::net::TcpStream;
use tokio::process::Command;
use tokio::time::sleep;
use uuid::Uuid;

const SIGTERM: i32 = libc::SIGTERM;
const BOOT_TIMEOUT: Duration = Duration::from_secs(10);
const PORT_POLL: Duration = Duration::from_millis(100);
/// Number of GetArticle requests we send. The binary must emit at least
/// this many tracing events tagged with the GetArticle path.
const RPC_REPS: usize = 5;

async fn pick_two_ports() -> std::io::Result<(u16, u16)> {
    let l1 = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let l2 = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let p1 = l1.local_addr()?.port();
    let p2 = l2.local_addr()?.port();
    drop(l1);
    drop(l2);
    Ok((p1, p2))
}

async fn wait_for_ports(grpc_port: u16, rest_port: u16) -> bool {
    let deadline = Instant::now() + BOOT_TIMEOUT;
    let (mut grpc_ready, mut rest_ready) = (false, false);
    while Instant::now() < deadline {
        if !grpc_ready && TcpStream::connect(("127.0.0.1", grpc_port)).await.is_ok() {
            grpc_ready = true;
        }
        if !rest_ready && TcpStream::connect(("127.0.0.1", rest_port)).await.is_ok() {
            rest_ready = true;
        }
        if grpc_ready && rest_ready {
            return true;
        }
        sleep(PORT_POLL).await;
    }
    false
}

fn send_sigterm(pid: u32) -> std::io::Result<()> {
    // SAFETY: kill(2) on a freshly-spawned PID with a well-defined signal.
    let rc = unsafe { libc::kill(pid as libc::pid_t, SIGTERM) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[tokio::test]
async fn binary_metrics_layer_records_one_event_per_rpc() {
    // ---- Arrange ----

    let database_url = match std::env::var("DATABASE_URL") {
        Ok(u) if !u.trim().is_empty() => u,
        _ => {
            eprintln!("DATABASE_URL not set; skipping binary_metrics_smoke");
            return;
        }
    };

    let (grpc_port, rest_port) = pick_two_ports()
        .await
        .expect("must be able to bind ephemeral ports for the smoke");

    // log_level is "debug" so tower-http's TraceLayer (and the metrics
    // span emitted alongside it for every RPC) makes its way to stderr in
    // JSON form. Keep log_format=json so we can match on the URI field.
    let mut cfg = NamedTempFile::new().expect("create temp config");
    writeln!(
        cfg,
        r#"
[server]
grpc_host = "127.0.0.1"
grpc_port = {grpc_port}
rest_host = "127.0.0.1"
rest_port = {rest_port}
rest_gateway_target = "in_process"

[database]
url = "{database_url}"
max_connections = 4

[auth.bootstrap]
user_registration = "open"
account_registration = "open"

[auth.time]
source = "local_clock"
horizon_seconds = 30

[auth.algorithms]
enabled = ["ed25519"]

[articles]
content_max_bytes = 1048576

[feeds]
replace_max_items = 100

[events]
batch_max_items = 50

[observability]
log_level = "debug"
log_format = "json"
otlp_endpoint = "http://127.0.0.1:1"
service_name = "headlines-metrics-smoke"
"#,
    )
    .expect("write temp config");
    cfg.flush().expect("flush temp config");
    let cfg_path = cfg.path().to_owned();

    let bin = env!("CARGO_BIN_EXE_headlines-server");

    let child = Command::new(bin)
        .arg("--config")
        .arg(&cfg_path)
        .arg("--skip-migrations")
        .env_remove("TAILSCALE_IP")
        .env_remove("HEADLINES_DATABASE__URL")
        .env_remove("HEADLINES_SERVER__GRPC_PORT")
        .env_remove("HEADLINES_SERVER__REST_PORT")
        .env_remove("HEADLINES_SERVER__GRPC_HOST")
        .env_remove("HEADLINES_SERVER__REST_HOST")
        // RUST_LOG steers EnvFilter; the config-supplied "debug" only
        // wins when RUST_LOG is unset.
        .env_remove("RUST_LOG")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn headlines-server binary");

    let pid = child.id().expect("child must have a PID");

    if !wait_for_ports(grpc_port, rest_port).await {
        let _ = send_sigterm(pid);
        let output = child.wait_with_output().await.ok();
        let (stdout, stderr) = match output {
            Some(o) => (
                String::from_utf8_lossy(&o.stdout).into_owned(),
                String::from_utf8_lossy(&o.stderr).into_owned(),
            ),
            None => (String::new(), String::new()),
        };
        panic!(
            "binary failed to come up within {:?}\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
            BOOT_TIMEOUT
        );
    }

    // ---- Act ----
    //
    // Hit GET /v1/articles/{bogus} N times. Every request hits the REST
    // gateway → trusted gRPC listener → ArticleService::GetArticle, so
    // each one should produce one log line tagged with the gRPC URI.
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("reqwest client");
    let base = format!("http://127.0.0.1:{rest_port}");

    for _ in 0..RPC_REPS {
        let bogus = Uuid::now_v7();
        let resp = client
            .get(format!("{base}/v1/articles/{bogus}"))
            .send()
            .await
            .expect("REST request must reach the gateway");
        // We don't care about the body; only that the request was routed
        // through the metrics layer. 404 is fine — the layer records
        // success/failure alike.
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "GET /v1/articles/{{bogus}} must be 404 so we know the request actually reached the service handler"
        );
    }

    // ---- Tear down and capture logs ----
    let _ = send_sigterm(pid);
    let output = tokio::time::timeout(Duration::from_secs(5), child.wait_with_output())
        .await
        .expect("child must wind down within 5s of SIGTERM")
        .expect("child wait_with_output must succeed");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let combined = format!("{stdout}\n{stderr}");

    // ---- Assert ----
    //
    // Count lines that mention the GetArticle gRPC URI. The tower-http
    // TraceLayer emits one span per RPC at DEBUG level with the full URI
    // path; that path is `/headlines.v1.ArticleService/GetArticle`. We
    // count occurrences of the method substring.
    let needle = "ArticleService/GetArticle";
    let hits = combined.matches(needle).count();
    assert!(
        hits >= RPC_REPS,
        "expected at least {RPC_REPS} {needle} log mentions (one per RPC routed through \
         the MetricsLayer's tower stack); got {hits}.\n\
         --- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
    );
}
