//! Binary-level smoke test for the `headlines-server` executable.
//!
//! Why this file exists: every other tier of tests boots the server
//! *in-process* — they wire `AccountServiceImpl` etc. directly into a
//! `tonic::transport::Server` builder inside the test harness. None of them
//! exercises `crates/headlines-server/src/main.rs` itself: config loading,
//! observability init, Tailscale-binding, "spin up gRPC, then bring up REST,
//! then graceful-shutdown both" end-to-end, in the production code path.
//!
//! This test fills that gap. It:
//!
//! 1. Writes a temporary `config.toml` with random ports + the `local_clock`
//!    TSO source (so the smoke doesn't depend on Postgres TSO machinery).
//! 2. Spawns the *freshly-built* binary via `CARGO_BIN_EXE_headlines-server`,
//!    captures stdout/stderr.
//! 3. Polls both ports for ~10 s.
//! 4. Hits three real REST endpoints to confirm both surfaces are wired
//!    (`/openapi.json`, `/v1/accounts/{nonexistent}`, `/v1/articles/{nonexistent}`).
//! 5. SIGTERMs the child and asserts a clean shutdown within 5 s.
//!
//! Skips cleanly when `DATABASE_URL` is unset — there's no in-memory DB
//! fallback for the binary path. AAA structure per
//! `~/.claude/rules/testing-patterns.md`.

#![cfg(unix)]

use std::io::Write;
use std::process::Stdio;
use std::time::{Duration, Instant};

use reqwest::StatusCode;
use serde_json::Value;
use tempfile::NamedTempFile;
use tokio::net::TcpStream;
use tokio::process::Command;
use tokio::time::sleep;
use uuid::Uuid;

/// SIGTERM constant — pulled from `libc` so the test does not gain `nix` as
/// a new transitive dep.
const SIGTERM: i32 = libc::SIGTERM;

/// Total budget for the child to start serving on both ports.
const BOOT_TIMEOUT: Duration = Duration::from_secs(10);

/// Total budget the child gets to wind down once we send SIGTERM.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// Poll interval while waiting for the ports to come up.
const PORT_POLL: Duration = Duration::from_millis(100);

/// Result of the boot wait. `Ports` means both ports accepted a connection;
/// `Timeout` means at least one didn't and the test should fail with the
/// captured logs.
enum BootOutcome {
    Ready,
    Timeout { grpc_ready: bool, rest_ready: bool },
}

/// Pick two ephemeral TCP ports by binding-and-dropping. The `port = 0`
/// trick doesn't work for this binary because the REST gateway dials the
/// gRPC server using the *configured* port, not the actually-bound one — if
/// we wrote `0` into config, the REST half would try `http://127.0.0.1:0`
/// and never connect. Instead: ask the OS for two real ports, drop the
/// listeners, and trust that nothing else grabs them in the few-millisecond
/// race window before the child binds. (Acceptable for a smoke test;
/// failure mode is a port-in-use boot error, which we'd see in the logs.)
async fn pick_two_ports() -> std::io::Result<(u16, u16)> {
    // Arrange — bind both at once so the OS doesn't hand out the same port
    // twice.
    let l1 = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let l2 = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let p1 = l1.local_addr()?.port();
    let p2 = l2.local_addr()?.port();
    drop(l1);
    drop(l2);
    Ok((p1, p2))
}

/// Wait for both ports to accept a TCP connection, or time out. Polls every
/// `PORT_POLL` until `BOOT_TIMEOUT` elapses.
async fn wait_for_ports(grpc_port: u16, rest_port: u16) -> BootOutcome {
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
            return BootOutcome::Ready;
        }
        sleep(PORT_POLL).await;
    }

    BootOutcome::Timeout {
        grpc_ready,
        rest_ready,
    }
}

/// Send SIGTERM to the child via raw `libc::kill` — `tokio::process::Child::kill`
/// uses SIGKILL, which would not exercise the binary's graceful-shutdown path
/// (the whole point of step 8).
fn send_sigterm(pid: u32) -> std::io::Result<()> {
    // Arrange — narrow the unsafe window to the single FFI call.
    // SAFETY: `kill(2)` is a libc call with no Rust-level invariants; pid
    // is a valid PID we just got from `Child::id()`. SIGTERM is well-defined
    // and the child is the one we spawned.
    let rc = unsafe { libc::kill(pid as libc::pid_t, SIGTERM) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[tokio::test]
async fn binary_smoke_boots_serves_both_surfaces_and_shuts_down() {
    // ---- Arrange ----

    // Skip cleanly without DATABASE_URL — the binary refuses to boot
    // without a real Postgres URL, and a smoke that needs a DB will hide
    // its skip under a connection error otherwise.
    let database_url = match std::env::var("DATABASE_URL") {
        Ok(u) if !u.trim().is_empty() => u,
        _ => {
            eprintln!("DATABASE_URL not set; skipping binary_smoke");
            return;
        }
    };

    // Pick two random high ports. See pick_two_ports() rationale.
    let (grpc_port, rest_port) = pick_two_ports()
        .await
        .expect("must be able to bind ephemeral ports for the smoke");

    // Write the config.toml requested by the smoke spec. Keep the OTLP
    // endpoint pointed at a definitely-unreachable port; the binary's
    // observability::init must "fail open" — that's what step 8's
    // graceful-shutdown coverage actually tests.
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
log_level = "warn"
log_format = "json"
otlp_endpoint = "http://127.0.0.1:1"
service_name = "headlines-smoke"
"#,
    )
    .expect("write temp config");
    cfg.flush().expect("flush temp config");
    let cfg_path = cfg.path().to_owned();

    // Spawn the freshly-built binary. CARGO_BIN_EXE_<name> is injected by
    // Cargo for integration tests and forces a build of the bin first.
    let bin = env!("CARGO_BIN_EXE_headlines-server");

    let mut child = Command::new(bin)
        .arg("--config")
        .arg(&cfg_path)
        .arg("--skip-migrations")
        // Strip the test runner's TAILSCALE_IP if it leaked in — we want
        // the binary to honor the 127.0.0.1 we wrote into config.
        .env_remove("TAILSCALE_IP")
        // Don't let HEADLINES_* env vars from the developer's shell
        // override our temp config. (Iterating env happens at spawn time;
        // we list the ones we know matter and let figment skip the rest.)
        .env_remove("HEADLINES_DATABASE__URL")
        .env_remove("HEADLINES_SERVER__GRPC_PORT")
        .env_remove("HEADLINES_SERVER__REST_PORT")
        .env_remove("HEADLINES_SERVER__GRPC_HOST")
        .env_remove("HEADLINES_SERVER__REST_HOST")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn headlines-server binary");

    let pid = child.id().expect("child must have a PID");

    // ---- Act 1: wait for both surfaces to be listening ----
    let outcome = wait_for_ports(grpc_port, rest_port).await;

    // If boot failed we still want the captured logs in the failure
    // message, so pull stdout/stderr even on the happy path before we hit
    // the surfaces — keeping a single error-dump path.
    if let BootOutcome::Timeout {
        grpc_ready,
        rest_ready,
    } = outcome
    {
        // Send SIGTERM so the child doesn't outlive the test runner.
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
            "binary failed to come up within {:?}: grpc_ready={grpc_ready} rest_ready={rest_ready}\n\
             --- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
            BOOT_TIMEOUT
        );
    }

    // ---- Act 2: hit the three smoke endpoints. ----
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("reqwest client");
    let base = format!("http://127.0.0.1:{rest_port}");

    // 5. /openapi.json — at least 30 routes, valid JSON.
    let openapi = match client.get(format!("{base}/openapi.json")).send().await {
        Ok(r) => r,
        Err(e) => {
            terminate_and_panic(
                child,
                pid,
                format!("GET /openapi.json failed to connect: {e}"),
            )
            .await;
        }
    };
    let openapi_status = openapi.status();
    let openapi_ct = openapi
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_owned())
        .unwrap_or_default();
    let openapi_body: Value = match openapi.json().await {
        Ok(v) => v,
        Err(e) => {
            terminate_and_panic(child, pid, format!("openapi.json body was not JSON: {e}")).await;
        }
    };

    // 6. /v1/accounts/{nonexistent} — 404 + ACCOUNT_NOT_FOUND.
    let bogus_account = Uuid::now_v7();
    let resp_acct = match client
        .get(format!("{base}/v1/accounts/{bogus_account}"))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            terminate_and_panic(
                child,
                pid,
                format!("GET /v1/accounts/{{bogus}} failed: {e}"),
            )
            .await;
        }
    };
    let acct_status = resp_acct.status();
    let acct_body: Value = match resp_acct.json().await {
        Ok(v) => v,
        Err(e) => {
            terminate_and_panic(
                child,
                pid,
                format!("GET /v1/accounts/{{bogus}} body was not JSON: {e}"),
            )
            .await;
        }
    };

    // 7. /v1/articles/{nonexistent} — 404 + ARTICLE_NOT_FOUND.
    let bogus_article = Uuid::now_v7();
    let resp_art = match client
        .get(format!("{base}/v1/articles/{bogus_article}"))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            terminate_and_panic(
                child,
                pid,
                format!("GET /v1/articles/{{bogus}} failed: {e}"),
            )
            .await;
        }
    };
    let art_status = resp_art.status();
    let art_body: Value = match resp_art.json().await {
        Ok(v) => v,
        Err(e) => {
            terminate_and_panic(
                child,
                pid,
                format!("GET /v1/articles/{{bogus}} body was not JSON: {e}"),
            )
            .await;
        }
    };

    // ---- Act 3: graceful shutdown via SIGTERM ----
    if let Err(e) = send_sigterm(pid) {
        // If we can't even signal we just kill (best-effort) and bail.
        let _ = child.start_kill();
        let _ = child.wait_with_output().await;
        panic!("kill(SIGTERM) failed: {e}");
    }

    // Wait up to SHUTDOWN_TIMEOUT for the child to exit. tokio::process
    // doesn't have a direct timed-wait, so race wait_with_output against a
    // sleep.
    let shutdown_result = tokio::time::timeout(SHUTDOWN_TIMEOUT, child.wait_with_output()).await;

    let output = match shutdown_result {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => panic!("waiting on child failed: {e}"),
        Err(_) => {
            // Timed out; SIGKILL it so the test process can exit, then
            // fail loudly. We can't recover stdout/stderr after a kill that
            // raced wait_with_output, so just panic with what we know.
            // SAFETY: same reasoning as send_sigterm; SIGKILL.
            unsafe {
                libc::kill(pid as libc::pid_t, libc::SIGKILL);
            }
            panic!(
                "child did not exit within {:?} of SIGTERM — graceful shutdown regression",
                SHUTDOWN_TIMEOUT
            );
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    // ---- Assert ----

    // Endpoint shape — done after we own the captured output so failures
    // can include it.
    let dump = || format!("--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}");

    assert_eq!(
        openapi_status,
        StatusCode::OK,
        "GET /openapi.json must be 200; got {openapi_status}\n{}",
        dump()
    );
    assert!(
        openapi_ct.contains("application/json"),
        "openapi Content-Type must be application/json; got {openapi_ct}\n{}",
        dump()
    );
    let paths = openapi_body["paths"]
        .as_object()
        .unwrap_or_else(|| panic!("openapi missing `paths` object\n{}", dump()));
    assert!(
        paths.len() >= 30,
        "openapi.json must expose at least 30 routes; got {}\n{}",
        paths.len(),
        dump()
    );

    assert_eq!(
        acct_status,
        StatusCode::NOT_FOUND,
        "GET /v1/accounts/{{bogus}} must be 404; got {acct_status}\n{}",
        dump()
    );
    let acct_details = acct_body["details"]
        .as_array()
        .unwrap_or_else(|| panic!("ACCOUNT_NOT_FOUND envelope missing details\n{}", dump()));
    assert!(
        !acct_details.is_empty(),
        "ACCOUNT_NOT_FOUND envelope must carry an ErrorInfo detail\n{}",
        dump()
    );
    assert_eq!(
        acct_details[0]["reason"],
        "ACCOUNT_NOT_FOUND",
        "ErrorInfo.reason must be ACCOUNT_NOT_FOUND; got {acct_body}\n{}",
        dump()
    );

    assert_eq!(
        art_status,
        StatusCode::NOT_FOUND,
        "GET /v1/articles/{{bogus}} must be 404; got {art_status}\n{}",
        dump()
    );
    let art_details = art_body["details"]
        .as_array()
        .unwrap_or_else(|| panic!("ARTICLE_NOT_FOUND envelope missing details\n{}", dump()));
    assert!(
        !art_details.is_empty(),
        "ARTICLE_NOT_FOUND envelope must carry an ErrorInfo detail\n{}",
        dump()
    );
    assert_eq!(
        art_details[0]["reason"],
        "ARTICLE_NOT_FOUND",
        "ErrorInfo.reason must be ARTICLE_NOT_FOUND; got {art_body}\n{}",
        dump()
    );

    // Graceful shutdown — exit status 0 OR terminated by SIGTERM. Tokio
    // surfaces signals via ExitStatus::signal() on Unix.
    use std::os::unix::process::ExitStatusExt;
    let status = output.status;
    let clean = status.success()
        || status.signal() == Some(SIGTERM)
        // Some Rust runtimes raise the signal back on the process and the
        // ExitStatus reports `signal == SIGTERM` with a `core_dumped == false`
        // — same condition as above. Some platforms instead return code 143
        // (= 128 + SIGTERM); tolerate that too.
        || status.code() == Some(128 + SIGTERM);
    assert!(
        clean,
        "binary did not exit cleanly: {:?}\n{}",
        status,
        dump()
    );
}

/// Best-effort: send SIGTERM, capture output, and panic with the captured
/// logs. Used by mid-test failure paths so the panic message includes the
/// child's logs without leaking the process.
async fn terminate_and_panic(child: tokio::process::Child, pid: u32, msg: String) -> ! {
    let _ = send_sigterm(pid);
    // Race a short timeout against wait_with_output; if SIGTERM didn't take,
    // the kill_on_drop guard on `child` will eventually SIGKILL.
    let output = tokio::time::timeout(Duration::from_secs(2), child.wait_with_output()).await;
    let (stdout, stderr) = match output {
        Ok(Ok(o)) => (
            String::from_utf8_lossy(&o.stdout).into_owned(),
            String::from_utf8_lossy(&o.stderr).into_owned(),
        ),
        _ => (String::new(), String::new()),
    };
    panic!("{msg}\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}");
}
