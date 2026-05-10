//! Smoke around `tailscale::resolve_bind` at the binary level.
//!
//! Asserts that when `TAILSCALE_IP` is set in the environment, the spawned
//! binary actually binds both surfaces to that IP — overriding the
//! configured host. The unit tests in `src/tailscale.rs` cover the resolver
//! function; this is the integration coverage that confirms `main()` honors
//! the resolved bind address end-to-end.
//!
//! Strategy: pick a host that's reachable from the test runner (loopback
//! `127.0.0.1`) and a config host that the binary should NOT bind to
//! (`127.0.0.2`, also loopback under 127.0.0.0/8). If `TAILSCALE_IP`
//! resolution works, the binary listens on `127.0.0.1` only; if the config
//! host won the override race we'd see the inverse. This distinguishes the
//! two without depending on a real Tailscale interface.
//!
//! Skips cleanly when `DATABASE_URL` is unset. AAA structure per
//! `~/.claude/rules/testing-patterns.md`.

#![cfg(unix)]

use std::io::Write;
use std::process::Stdio;
use std::time::{Duration, Instant};

use tempfile::NamedTempFile;
use tokio::net::TcpStream;
use tokio::process::Command;
use tokio::time::sleep;

const SIGTERM: i32 = libc::SIGTERM;
const BOOT_TIMEOUT: Duration = Duration::from_secs(10);
const PORT_POLL: Duration = Duration::from_millis(100);

/// Pick two ephemeral ports. Bind both at once so the OS doesn't hand out
/// the same port twice; drop the listeners and trust the few-ms race window.
async fn pick_two_ports() -> std::io::Result<(u16, u16)> {
    let l1 = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let l2 = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let p1 = l1.local_addr()?.port();
    let p2 = l2.local_addr()?.port();
    drop(l1);
    drop(l2);
    Ok((p1, p2))
}

/// Wait for `(host, port)` to accept a TCP connection until the deadline.
async fn wait_for(host: &str, port: u16, deadline: Instant) -> bool {
    while Instant::now() < deadline {
        if TcpStream::connect((host, port)).await.is_ok() {
            return true;
        }
        sleep(PORT_POLL).await;
    }
    false
}

fn send_sigterm(pid: u32) -> std::io::Result<()> {
    // SAFETY: kill(2) with a valid PID we just spawned and SIGTERM, which
    // is well-defined and matches the binary's graceful-shutdown path.
    let rc = unsafe { libc::kill(pid as libc::pid_t, SIGTERM) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[tokio::test]
async fn binary_binds_to_tailscale_ip_when_env_var_set() {
    // ---- Arrange ----

    let database_url = match std::env::var("DATABASE_URL") {
        Ok(u) if !u.trim().is_empty() => u,
        _ => {
            eprintln!("DATABASE_URL not set; skipping binary_tailscale_smoke");
            return;
        }
    };

    let (grpc_port, rest_port) = pick_two_ports()
        .await
        .expect("must be able to bind ephemeral ports for the smoke");

    // Config host: 127.0.0.2 (loopback under 127.0.0.0/8). If the binary
    // ignored TAILSCALE_IP it would bind here.
    let mut cfg = NamedTempFile::new().expect("create temp config");
    writeln!(
        cfg,
        r#"
[server]
grpc_host = "127.0.0.2"
grpc_port = {grpc_port}
rest_host = "127.0.0.2"
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
log_level = "info"
log_format = "json"
otlp_endpoint = "http://127.0.0.1:1"
service_name = "headlines-tailscale-smoke"
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
        // Override config host with TAILSCALE_IP=127.0.0.1.
        .env("TAILSCALE_IP", "127.0.0.1")
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

    // ---- Act ----
    //
    // Wait for both ports to become reachable on 127.0.0.1 (the
    // Tailscale-supplied host). This is the assertion: if resolve_bind
    // dropped the env var on the floor, we'd never see traffic on .1.
    let deadline = Instant::now() + BOOT_TIMEOUT;
    let grpc_ok = wait_for("127.0.0.1", grpc_port, deadline).await;
    let rest_ok = wait_for("127.0.0.1", rest_port, deadline).await;

    // Capture output for the panic message regardless of outcome. SIGTERM
    // first; on a successful boot the binary's graceful-shutdown path
    // will flush logs and exit within ~5s.
    let _ = send_sigterm(pid);
    let output = tokio::time::timeout(Duration::from_secs(8), child.wait_with_output())
        .await
        .ok()
        .and_then(|r| r.ok());
    let (stdout, stderr) = match output {
        Some(o) => (
            String::from_utf8_lossy(&o.stdout).into_owned(),
            String::from_utf8_lossy(&o.stderr).into_owned(),
        ),
        None => (String::new(), String::new()),
    };

    // ---- Assert ----
    assert!(
        grpc_ok,
        "gRPC surface did not become reachable on 127.0.0.1:{grpc_port} (TAILSCALE_IP host) — \
         resolve_bind override likely failed.\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
    );
    assert!(
        rest_ok,
        "REST surface did not become reachable on 127.0.0.1:{rest_port} (TAILSCALE_IP host) — \
         resolve_bind override likely failed.\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
    );

    // The boot log line emits `binding to TAILSCALE_IP` when the env var
    // wins. Belt-and-braces check on the captured logs so a future
    // refactor that changes the resolver but still happens to listen on
    // 127.0.0.1 (e.g. by accident) doesn't silently pass.
    let combined = format!("{stdout}\n{stderr}");
    assert!(
        combined.contains("TAILSCALE_IP"),
        "boot log must mention TAILSCALE_IP when env override wins:\n{combined}"
    );
}
