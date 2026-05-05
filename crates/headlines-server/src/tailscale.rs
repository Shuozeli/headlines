//! Tailscale-IP binding resolver.
//!
//! Per `~/.claude/rules/infra-defaults.md`: read `TAILSCALE_IP` from the
//! environment at startup. If set and non-empty, override the configured
//! gRPC + REST hosts. Otherwise fall back to whatever the config supplied
//! (which defaults to `0.0.0.0`).
//!
//! Resolved exactly once at boot — `main` calls `resolve_bind` and threads
//! the resulting `BindAddrs` through to both servers.

use std::net::SocketAddr;

use crate::config::ServerConfig;

/// Resolved bind addresses for the two surfaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindAddrs {
    pub grpc_addr: SocketAddr,
    pub rest_addr: SocketAddr,
    pub grpc_host: String,
    pub rest_host: String,
    pub source: BindSource,
}

/// Where the host came from. Useful for the boot log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindSource {
    /// `TAILSCALE_IP` env var was set and non-empty.
    Tailscale,
    /// `TAILSCALE_IP` was unset or empty; we used the config-supplied host.
    Config,
}

/// Read `TAILSCALE_IP` and apply the override rule.
pub fn resolve_bind(server: &ServerConfig) -> anyhow::Result<BindAddrs> {
    let env_value = std::env::var("TAILSCALE_IP").ok();
    resolve_bind_from(server, env_value.as_deref())
}

/// Side-effect-free variant for tests.
pub fn resolve_bind_from(
    server: &ServerConfig,
    tailscale_ip: Option<&str>,
) -> anyhow::Result<BindAddrs> {
    let (grpc_host, rest_host, source) = match tailscale_ip.map(str::trim) {
        Some(ip) if !ip.is_empty() => (ip.to_owned(), ip.to_owned(), BindSource::Tailscale),
        _ => (
            server.grpc_host.clone(),
            server.rest_host.clone(),
            BindSource::Config,
        ),
    };
    let grpc_addr: SocketAddr = format!("{grpc_host}:{}", server.grpc_port)
        .parse()
        .map_err(|e| {
            anyhow::anyhow!(
                "invalid grpc bind address {grpc_host}:{}: {e}",
                server.grpc_port
            )
        })?;
    let rest_addr: SocketAddr = format!("{rest_host}:{}", server.rest_port)
        .parse()
        .map_err(|e| {
            anyhow::anyhow!(
                "invalid rest bind address {rest_host}:{}: {e}",
                server.rest_port
            )
        })?;
    Ok(BindAddrs {
        grpc_addr,
        rest_addr,
        grpc_host,
        rest_host,
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server_cfg(
        grpc_host: &str,
        grpc_port: u16,
        rest_host: &str,
        rest_port: u16,
    ) -> ServerConfig {
        ServerConfig {
            grpc_host: grpc_host.into(),
            grpc_port,
            rest_host: rest_host.into(),
            rest_port,
            rest_gateway_target: "in_process".into(),
        }
    }

    #[test]
    fn unset_env_uses_config_host() {
        // Arrange
        let cfg = server_cfg("0.0.0.0", 50051, "0.0.0.0", 8080);

        // Act
        let bind = resolve_bind_from(&cfg, None).unwrap();

        // Assert
        assert_eq!(bind.grpc_host, "0.0.0.0");
        assert_eq!(bind.rest_host, "0.0.0.0");
        assert_eq!(bind.source, BindSource::Config);
        assert_eq!(bind.grpc_addr.port(), 50051);
        assert_eq!(bind.rest_addr.port(), 8080);
    }

    #[test]
    fn empty_env_uses_config_host() {
        // Arrange
        let cfg = server_cfg("0.0.0.0", 50051, "0.0.0.0", 8080);

        // Act
        let bind = resolve_bind_from(&cfg, Some("")).unwrap();

        // Assert
        assert_eq!(bind.source, BindSource::Config);
    }

    #[test]
    fn whitespace_only_env_uses_config_host() {
        // Arrange
        let cfg = server_cfg("0.0.0.0", 50051, "0.0.0.0", 8080);

        // Act
        let bind = resolve_bind_from(&cfg, Some("   ")).unwrap();

        // Assert
        assert_eq!(bind.source, BindSource::Config);
    }

    #[test]
    fn nonempty_env_overrides_both_hosts() {
        // Arrange
        let cfg = server_cfg("0.0.0.0", 50051, "0.0.0.0", 8080);

        // Act
        let bind = resolve_bind_from(&cfg, Some("100.64.0.1")).unwrap();

        // Assert
        assert_eq!(bind.grpc_host, "100.64.0.1");
        assert_eq!(bind.rest_host, "100.64.0.1");
        assert_eq!(bind.source, BindSource::Tailscale);
        assert_eq!(bind.grpc_addr.to_string(), "100.64.0.1:50051");
        assert_eq!(bind.rest_addr.to_string(), "100.64.0.1:8080");
    }

    #[test]
    fn invalid_host_returns_error() {
        // Arrange — colons inside the host string break parsing.
        let cfg = server_cfg("not a host", 50051, "0.0.0.0", 8080);

        // Act
        let res = resolve_bind_from(&cfg, None);

        // Assert
        assert!(res.is_err());
    }
}
