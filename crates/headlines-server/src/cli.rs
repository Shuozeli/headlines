//! `clap`-derived CLI surface for `headlines-server`.

use std::path::PathBuf;

use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(name = "headlines-server", version)]
pub struct Cli {
    /// Path to a TOML config file. Optional — defaults baked into the binary
    /// suffice for a smoke boot. Missing path passed here is an error;
    /// missing path NOT passed is fine (figment skips the layer).
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Override `[server].grpc_host`. CLI beats env beats file beats default.
    #[arg(long)]
    pub grpc_host: Option<String>,

    /// Override `[server].grpc_port`.
    #[arg(long)]
    pub grpc_port: Option<u16>,

    /// Override `[server].rest_host`.
    #[arg(long)]
    pub rest_host: Option<String>,

    /// Override `[server].rest_port`.
    #[arg(long)]
    pub rest_port: Option<u16>,

    /// Skip running pending migrations on startup. Useful when migrations
    /// are run separately by an operator/CI step.
    #[arg(long, default_value_t = false)]
    pub skip_migrations: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_invocation() {
        // Arrange / Act
        let cli = Cli::try_parse_from(["headlines-server"]).unwrap();

        // Assert
        assert!(cli.config.is_none());
        assert!(cli.grpc_port.is_none());
        assert!(!cli.skip_migrations);
    }

    #[test]
    fn parses_full_invocation() {
        // Arrange / Act
        let cli = Cli::try_parse_from([
            "headlines-server",
            "--config",
            "config.toml",
            "--grpc-host",
            "10.0.0.1",
            "--grpc-port",
            "60061",
            "--rest-host",
            "10.0.0.1",
            "--rest-port",
            "9090",
            "--skip-migrations",
        ])
        .unwrap();

        // Assert
        assert_eq!(cli.config.unwrap().to_string_lossy(), "config.toml");
        assert_eq!(cli.grpc_host.as_deref(), Some("10.0.0.1"));
        assert_eq!(cli.grpc_port, Some(60061));
        assert_eq!(cli.rest_host.as_deref(), Some("10.0.0.1"));
        assert_eq!(cli.rest_port, Some(9090));
        assert!(cli.skip_migrations);
    }
}
