//! Layered configuration loader for `headlines-server`.
//!
//! Per `docs/design/architecture.md` the layering is:
//!
//! 1. Defaults baked into code via `Config::default`.
//! 2. `config.toml` (path supplied by `--config <path>`; missing file is fine
//!    when no explicit path was passed).
//! 3. Environment variables prefixed `HEADLINES_`, double-underscore as the
//!    section delimiter (e.g. `HEADLINES_SERVER__GRPC_PORT=50052`).
//! 4. CLI flag overrides (the most common ones — everything else goes through
//!    env / file).

use std::path::Path;

use anyhow::Context;
use figment::Figment;
use figment::providers::{Env, Format, Serialized, Toml};
use headlines_api::{
    DEFAULT_CONTENT_MAX_BYTES, DEFAULT_EVENTS_BATCH_MAX_ITEMS, DEFAULT_FEEDS_REPLACE_MAX_ITEMS,
};
use serde::{Deserialize, Serialize};

use crate::cli::Cli;

/// Top-level configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub auth: AuthConfig,
    pub articles: ArticlesConfig,
    pub feeds: FeedsConfig,
    pub events: EventsConfig,
    pub observability: ObservabilityConfig,
}

/// `[server]` block.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServerConfig {
    pub grpc_host: String,
    pub grpc_port: u16,
    pub rest_host: String,
    pub rest_port: u16,
    /// `"in_process"` to dial the local gRPC server, or a `"host:port"`
    /// string to point at a remote split deployment. Phase 6 always uses
    /// `in_process`.
    pub rest_gateway_target: String,
}

/// `[database]` block.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: usize,
}

/// `[auth]` block — sub-tables for bootstrap, time, algorithms.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthConfig {
    pub bootstrap: AuthBootstrapConfig,
    pub time: AuthTimeConfig,
    pub algorithms: AuthAlgorithmsConfig,
}

/// `[auth.bootstrap]` — controls who can self-register.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthBootstrapConfig {
    pub user_registration: String,
    pub account_registration: String,
}

/// `[auth.time]` — TSO source choice + horizon.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthTimeConfig {
    /// `"in_process_tso"` (default, prod) or `"local_clock"` (dev fallback).
    pub source: String,
    pub horizon_seconds: u64,
}

/// `[auth.algorithms]`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthAlgorithmsConfig {
    pub enabled: Vec<String>,
}

/// `[articles]`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArticlesConfig {
    /// Maximum encoded body size for `PublishArticle` / `EditArticle` /
    /// `CreateDraft` / `PublishDraft`. Default = `DEFAULT_CONTENT_MAX_BYTES`
    /// (20 MiB) per `articles.md`. `usize` to match the service constructor
    /// signature.
    pub content_max_bytes: usize,
}

/// `[feeds]`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FeedsConfig {
    /// Maximum article count accepted by `ReplaceRecommendationFeed`. Default
    /// = `DEFAULT_FEEDS_REPLACE_MAX_ITEMS` (5000) per `feed-recommendation.md`.
    pub replace_max_items: usize,
}

/// `[events]`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EventsConfig {
    /// Maximum batch size accepted by `RecordEventBatch`. Default =
    /// `DEFAULT_EVENTS_BATCH_MAX_ITEMS` (500) per `events.md`.
    pub batch_max_items: usize,
}

/// `[observability]`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObservabilityConfig {
    pub log_level: String,
    pub log_format: String,
    pub otlp_endpoint: String,
    pub service_name: String,
}

/// Sentinel value baked into `Config::default().database.url`. `Config::load`
/// rejects any merged config whose `database.url` is left as this value (or
/// otherwise empty). Operators must override via `[database].url` in
/// `config.toml` or `HEADLINES_DATABASE__URL`.
pub(crate) const DATABASE_URL_REQUIRED_PLACEHOLDER: &str =
    "REQUIRED: set HEADLINES_DATABASE__URL or [database].url in config.toml";

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                grpc_host: "0.0.0.0".into(),
                grpc_port: 50051,
                rest_host: "0.0.0.0".into(),
                rest_port: 8080,
                rest_gateway_target: "in_process".into(),
            },
            database: DatabaseConfig {
                // No real default — the URL must be provided via config file
                // or env. `Config::load` validates after the figment overlay.
                url: DATABASE_URL_REQUIRED_PLACEHOLDER.into(),
                max_connections: 16,
            },
            auth: AuthConfig {
                bootstrap: AuthBootstrapConfig {
                    user_registration: "open".into(),
                    account_registration: "system_only".into(),
                },
                time: AuthTimeConfig {
                    source: "in_process_tso".into(),
                    horizon_seconds: 30,
                },
                algorithms: AuthAlgorithmsConfig {
                    enabled: vec!["ed25519".into()],
                },
            },
            articles: ArticlesConfig {
                content_max_bytes: DEFAULT_CONTENT_MAX_BYTES,
            },
            feeds: FeedsConfig {
                replace_max_items: DEFAULT_FEEDS_REPLACE_MAX_ITEMS,
            },
            events: EventsConfig {
                batch_max_items: DEFAULT_EVENTS_BATCH_MAX_ITEMS,
            },
            observability: ObservabilityConfig {
                log_level: "info".into(),
                log_format: "json".into(),
                otlp_endpoint: "http://otel-collector.internal:4317".into(),
                service_name: "headlines".into(),
            },
        }
    }
}

/// CLI-flag overrides projected onto the merge stack. Only fields the CLI
/// can override are populated; everything else stays unset.
#[derive(Debug, Default, Serialize)]
struct CliOverrides {
    #[serde(skip_serializing_if = "Option::is_none")]
    server: Option<CliServerOverrides>,
}

#[derive(Debug, Default, Serialize)]
struct CliServerOverrides {
    #[serde(skip_serializing_if = "Option::is_none")]
    grpc_host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    grpc_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rest_host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rest_port: Option<u16>,
}

impl Config {
    /// Public entry point — apply the four overlay layers and deserialize.
    pub fn load(cli: &Cli) -> anyhow::Result<Self> {
        let mut figment = Figment::from(Serialized::defaults(Config::default()));

        if let Some(path) = cli.config.as_deref() {
            figment = figment.merge(Toml::file_exact(path));
        }

        figment = figment.merge(Env::prefixed("HEADLINES_").split("__"));

        let cli_overrides = build_cli_overrides(cli);
        if cli_overrides.server.is_some() {
            figment = figment.merge(Serialized::defaults(cli_overrides));
        }

        let config: Config = figment.extract().context("decode merged config")?;
        validate_required_fields(&config)?;
        Ok(config)
    }

    /// Same as `load` but takes an explicit path rather than the CLI's
    /// `--config` slot. Used by tests.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn load_with_file(path: Option<&Path>, cli: &Cli) -> anyhow::Result<Self> {
        let mut figment = Figment::from(Serialized::defaults(Config::default()));

        if let Some(p) = path {
            figment = figment.merge(Toml::file_exact(p));
        }

        figment = figment.merge(Env::prefixed("HEADLINES_").split("__"));

        let cli_overrides = build_cli_overrides(cli);
        if cli_overrides.server.is_some() {
            figment = figment.merge(Serialized::defaults(cli_overrides));
        }

        let config: Config = figment.extract().context("decode merged config")?;
        validate_required_fields(&config)?;
        Ok(config)
    }
}

/// Reject configs whose required fields haven't been overridden away from the
/// "must be supplied" placeholders we plant in `Config::default`. Today only
/// `database.url` is in this category; future required fields go here too.
fn validate_required_fields(config: &Config) -> anyhow::Result<()> {
    let url = config.database.url.trim();
    if url.is_empty() || url == DATABASE_URL_REQUIRED_PLACEHOLDER {
        anyhow::bail!(
            "database.url is required; set [database].url in config.toml or HEADLINES_DATABASE__URL env var"
        );
    }
    Ok(())
}

fn build_cli_overrides(cli: &Cli) -> CliOverrides {
    let server = if cli.grpc_host.is_some()
        || cli.grpc_port.is_some()
        || cli.rest_host.is_some()
        || cli.rest_port.is_some()
    {
        Some(CliServerOverrides {
            grpc_host: cli.grpc_host.clone(),
            grpc_port: cli.grpc_port,
            rest_host: cli.rest_host.clone(),
            rest_port: cli.rest_port,
        })
    } else {
        None
    };
    CliOverrides { server }
}

#[cfg(test)]
#[allow(clippy::result_large_err)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Test-only stand-in URL. The validator only checks "non-empty" + "not the
    /// REQUIRED placeholder", so any well-formed string serves; tests don't
    /// connect to it.
    const TEST_DB_URL: &str = "postgres://test:test@localhost:5432/test";

    /// Build a minimal CLI with all flags unset. Tests opt-in fields via
    /// pattern-matched updates.
    fn empty_cli() -> Cli {
        Cli {
            config: None,
            grpc_host: None,
            grpc_port: None,
            rest_host: None,
            rest_port: None,
            skip_migrations: false,
        }
    }

    /// Use `figment::Jail` so per-test env mutations don't leak.
    #[test]
    fn defaults_load_when_no_overlay_present() {
        figment::Jail::expect_with(|jail| {
            // Arrange — minimum override is the (newly required) database.url
            // so the validator doesn't reject the placeholder.
            jail.set_env("HEADLINES_DATABASE__URL", TEST_DB_URL);
            let cli = empty_cli();

            // Act
            let cfg = Config::load_with_file(None, &cli).unwrap();

            // Assert — only `database.url` should differ from
            // `Config::default`; everything else is untouched defaults.
            let mut expected = Config::default();
            expected.database.url = TEST_DB_URL.into();
            assert_eq!(cfg, expected);
            Ok(())
        });
    }

    #[test]
    fn toml_file_overrides_defaults() {
        figment::Jail::expect_with(|jail| {
            // Arrange
            let dir = jail.directory().to_owned();
            let path = dir.join("config.toml");
            let mut f = std::fs::File::create(&path).unwrap();
            writeln!(
                f,
                r#"
[server]
grpc_port = 60061
rest_port = 9090

[database]
url = "{TEST_DB_URL}"
max_connections = 32
"#
            )
            .unwrap();
            let cli = empty_cli();

            // Act
            let cfg = Config::load_with_file(Some(&path), &cli).unwrap();

            // Assert
            assert_eq!(cfg.server.grpc_port, 60061);
            assert_eq!(cfg.server.rest_port, 9090);
            assert_eq!(cfg.database.max_connections, 32);
            // Untouched fields keep defaults.
            assert_eq!(cfg.server.grpc_host, "0.0.0.0");
            Ok(())
        });
    }

    #[test]
    fn env_overrides_file_and_defaults() {
        figment::Jail::expect_with(|jail| {
            // Arrange — env is the third layer; env wins over the file.
            let path = jail.directory().join("config.toml");
            let mut f = std::fs::File::create(&path).unwrap();
            writeln!(
                f,
                r#"
[server]
grpc_port = 60061

[database]
url = "{TEST_DB_URL}"
"#
            )
            .unwrap();
            jail.set_env("HEADLINES_SERVER__GRPC_PORT", "60062");
            let cli = empty_cli();

            // Act
            let cfg = Config::load_with_file(Some(&path), &cli).unwrap();

            // Assert
            assert_eq!(cfg.server.grpc_port, 60062);
            Ok(())
        });
    }

    #[test]
    fn cli_overrides_env_and_file() {
        figment::Jail::expect_with(|jail| {
            // Arrange — file=60061, env=60062, CLI=60063 → CLI wins.
            let path = jail.directory().join("config.toml");
            let mut f = std::fs::File::create(&path).unwrap();
            writeln!(
                f,
                r#"
[server]
grpc_port = 60061

[database]
url = "{TEST_DB_URL}"
"#
            )
            .unwrap();
            jail.set_env("HEADLINES_SERVER__GRPC_PORT", "60062");
            let cli = Cli {
                grpc_port: Some(60063),
                ..empty_cli()
            };

            // Act
            let cfg = Config::load_with_file(Some(&path), &cli).unwrap();

            // Assert
            assert_eq!(cfg.server.grpc_port, 60063);
            Ok(())
        });
    }

    #[test]
    fn missing_file_at_explicit_path_is_an_error() {
        figment::Jail::expect_with(|jail| {
            // Arrange — pass a `--config` path that doesn't exist.
            let bogus = jail.directory().join("does_not_exist.toml");
            let cli = empty_cli();

            // Act
            let res = Config::load_with_file(Some(&bogus), &cli);

            // Assert
            assert!(res.is_err(), "expected error for missing config file");
            Ok(())
        });
    }

    #[test]
    fn cli_overrides_only_present_fields() {
        figment::Jail::expect_with(|jail| {
            // Arrange — only set rest_port; the rest must keep defaults.
            jail.set_env("HEADLINES_DATABASE__URL", TEST_DB_URL);
            let cli = Cli {
                rest_port: Some(7777),
                ..empty_cli()
            };

            // Act
            let cfg = Config::load_with_file(None, &cli).unwrap();

            // Assert
            assert_eq!(cfg.server.rest_port, 7777);
            assert_eq!(cfg.server.grpc_port, 50051);
            Ok(())
        });
    }

    #[test]
    fn config_load_fails_with_clear_error_when_database_url_not_set() {
        // Arrange — no override layer for `database.url`. The placeholder in
        // `Config::default` must be detected and converted into a hard error.
        figment::Jail::expect_with(|_jail| {
            let cli = empty_cli();

            // Act
            let res = Config::load_with_file(None, &cli);

            // Assert
            let err = res.expect_err("missing database.url must be fatal");
            let msg = format!("{err:#}");
            assert!(
                msg.contains("database.url"),
                "error must name the missing field: {msg}"
            );
            assert!(
                msg.contains("HEADLINES_DATABASE__URL") || msg.contains("[database].url"),
                "error must name the override path: {msg}"
            );
            Ok(())
        });
    }

    #[test]
    fn config_load_succeeds_when_database_url_provided_via_env() {
        // Arrange — env-only override of the required URL field.
        figment::Jail::expect_with(|jail| {
            let url = "postgres://envonly:envonly@db.example:5432/headlines";
            jail.set_env("HEADLINES_DATABASE__URL", url);
            let cli = empty_cli();

            // Act
            let cfg = Config::load_with_file(None, &cli).expect("env-supplied URL must load");

            // Assert — the env value propagated.
            assert_eq!(cfg.database.url, url);
            Ok(())
        });
    }

    #[test]
    fn config_load_fails_when_database_url_set_to_empty_string() {
        // Arrange — explicit empty string is still rejected (avoids "I set
        // it but it didn't take" footguns).
        figment::Jail::expect_with(|jail| {
            jail.set_env("HEADLINES_DATABASE__URL", "");
            let cli = empty_cli();

            // Act
            let res = Config::load_with_file(None, &cli);

            // Assert
            assert!(res.is_err(), "empty string must still be rejected");
            Ok(())
        });
    }

    #[test]
    fn articles_content_max_bytes_propagates_through_toml() {
        // Arrange — operator overrides `[articles].content_max_bytes`. The
        // server must pick the override up; this test pins the layering, the
        // existing `ContentTooLarge` integration tests cover the behavior.
        figment::Jail::expect_with(|jail| {
            let dir = jail.directory().to_owned();
            let path = dir.join("config.toml");
            let mut f = std::fs::File::create(&path).unwrap();
            writeln!(
                f,
                r#"
[database]
url = "{TEST_DB_URL}"

[articles]
content_max_bytes = 1024

[feeds]
replace_max_items = 10

[events]
batch_max_items = 17
"#
            )
            .unwrap();
            let cli = empty_cli();

            // Act
            let cfg = Config::load_with_file(Some(&path), &cli).unwrap();

            // Assert
            assert_eq!(cfg.articles.content_max_bytes, 1024);
            assert_eq!(cfg.feeds.replace_max_items, 10);
            assert_eq!(cfg.events.batch_max_items, 17);
            Ok(())
        });
    }
}
