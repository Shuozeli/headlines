//! `clap`-derived CLI surface for `headlines-server`.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

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

    /// Optional subcommand. When omitted the binary boots the server as
    /// usual; when present, the subcommand runs and the binary exits.
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Command {
    /// Demo-data subcommands.
    Demo {
        #[command(subcommand)]
        cmd: DemoCmd,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum DemoCmd {
    /// Seed the database with demo content. Idempotent unless --reset.
    Seed {
        /// Wipe demo data before seeding. Destructive; demo databases only.
        #[arg(long)]
        reset: bool,
        /// Path to the demo data root (defaults to `./demo`).
        #[arg(long, default_value = "demo")]
        path: PathBuf,
        /// Skip publishing articles. Useful for fast iteration.
        #[arg(long)]
        skip_articles: bool,
        /// Deterministic-RNG seed for reproducible event distributions.
        #[arg(long, default_value_t = 42)]
        rng_seed: u64,
        /// gRPC endpoint to dial. Defaults to the bound public listener.
        #[arg(long)]
        grpc_endpoint: Option<String>,
    },
    /// Print copy-pasteable curl commands for the demo flows.
    CurlExamples {
        /// Path to the demo data root (defaults to `./demo`).
        #[arg(long, default_value = "demo")]
        path: PathBuf,
        /// REST gateway base URL. Defaults to http://localhost:8080.
        #[arg(long, default_value = "http://localhost:8080")]
        base_url: String,
    },
    /// Generate any missing keypairs under demo/keys/.
    InitKeys {
        /// Path to the demo data root (defaults to `./demo`).
        #[arg(long, default_value = "demo")]
        path: PathBuf,
    },
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
        assert!(cli.command.is_none());
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

    #[test]
    fn parses_demo_seed_subcommand() {
        // Arrange / Act
        let cli = Cli::try_parse_from(["headlines-server", "demo", "seed", "--reset"]).unwrap();

        // Assert
        match cli.command {
            Some(Command::Demo {
                cmd: DemoCmd::Seed { reset, .. },
            }) => assert!(reset),
            other => panic!("expected demo seed, got {other:?}"),
        }
    }

    #[test]
    fn parses_demo_init_keys_subcommand() {
        // Arrange / Act
        let cli = Cli::try_parse_from(["headlines-server", "demo", "init-keys", "--path", "demo"])
            .unwrap();

        // Assert
        assert!(matches!(
            cli.command,
            Some(Command::Demo {
                cmd: DemoCmd::InitKeys { .. }
            })
        ));
    }
}
