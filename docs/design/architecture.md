# Architecture

Status: agreed (v1)
Scope: workspace layout, crate selection, process model, request flow, error model, configuration, database / migration tooling, auth wiring, observability, deployment binding. Per-component RPC contracts live in their own design docs; this doc fixes the system shape that hosts them.

## Goals

- One Rust workspace, gRPC-first service, in-process Rust REST gateway, Postgres storage with Diesel, OpenTelemetry from day one.
- Proto annotations are the single source of truth for both REST mappings and per-RPC authorization requirements.
- Trait-based plug-in seams for auth, time, and signature algorithms (per `auth.md`).

## Workspace layout

```
headlines/
  Cargo.toml                  # workspace root, [workspace] members = ["crates/*"]
  buf.yaml / buf.gen.yaml     # proto toolchain (lint, breaking, codegen)
  proto/headlines/v1/
    options.proto             # custom MethodOptions extension (auth_requirement)
    common.proto              # PublicKey, KeyStatus, Node, NodeElement, Article, ArticleSummary
    account.proto, article.proto, draft.proto, user.proto, follow.proto,
    feed_recommendation.proto, feed_follow.proto, account_stream.proto,
    event.proto, notification.proto
  crates/
    headlines-proto/          # tonic-build / prost output (generated; build.rs)
    headlines-core/           # domain types, error enum, traits, Subject, Tso
    headlines-store/          # diesel + diesel-async repository impls
    headlines-auth/           # AuthStrategy, SignatureAlgorithm, TimeSource, NonceStore, AuthInterceptor
    headlines-api/            # ServiceImpl trait implementations (one struct per service)
    headlines-rest-gateway/   # Rust-native REST → gRPC proxy (axum)
    headlines-server/         # binary: wires gRPC + REST + observability + config
  migrations/                 # diesel-managed SQL migrations
  tests/                      # workspace-level integration tests
```

Workspace lets each layer be tested and linted independently. Only `headlines-server` builds a binary in v1.

## Crate selection

| Concern | Crate(s) | Notes |
|---|---|---|
| Async runtime | `tokio` (full features) | required by tonic |
| gRPC server | `tonic`, `tonic-build`, `prost` | |
| Proto management | `buf` CLI | lint, breaking, `buf generate` orchestrates codegen |
| OpenAPI/Swagger | `protoc-gen-openapiv2` | run via `buf generate`; output to `gen/openapi/` |
| REST gateway | `axum` + `tower`, `pbjson` for proto↔JSON | hand-rolled in `headlines-rest-gateway`; serves alongside gRPC |
| HTTP/JSON encoding | `pbjson`, `pbjson-build` | |
| Postgres | `diesel` + `diesel-async` (`AsyncPgConnection`) | |
| Connection pool | `deadpool-diesel-async` | |
| Migrations | `diesel_migrations` (`embed_migrations!`) + `diesel_cli` for dev | |
| Crypto (Ed25519) | `ed25519-dalek` + `signature` | default `SignatureAlgorithm` |
| Crypto (other algos) | per-algo crate behind `SignatureAlgorithm` trait | not implemented in v1 but slot reserved |
| UUIDs | `uuid` v7 | |
| Errors | `thiserror` | central enum |
| Config | `figment` | layered: defaults → file → env → CLI |
| CLI | `clap` (derive) | |
| Logging | `tracing`, `tracing-subscriber` | json or pretty per config |
| Telemetry | `opentelemetry`, `opentelemetry-sdk`, `opentelemetry-otlp`, `tracing-opentelemetry` | OTLP export day-one |
| Metrics | OpenTelemetry metrics SDK; counters + histograms; OTLP push; optional `opentelemetry-prometheus` scrape endpoint | streaming exports |
| Testing | `tokio-test`, `serial_test`, real Postgres against `docker.yuacx.com` | AAA per `~/.claude/rules/testing-patterns.md` |

## Process model

```
┌─────────────────────────────────────────────────┐
│ headlines-server (single binary, single proc)   │
│                                                 │
│   ┌──────────────────┐    ┌──────────────────┐  │
│   │  REST clients    │    │  gRPC clients    │  │
│   │  (web, mobile)   │    │  (ranker,        │  │
│   │                  │    │   republishers)  │  │
│   └────────┬─────────┘    └────────┬─────────┘  │
│            │ HTTP/JSON              │ HTTP/2     │
│            ▼                        ▼            │
│   ┌──────────────────┐                           │
│   │  axum            │                           │
│   │  (rest-gateway)  │                           │
│   └────────┬─────────┘                           │
│            │ tonic Channel (in-process)          │
│            ▼                                     │
│   ┌────────────────────────────────────────┐     │
│   │  tonic Server                          │     │
│   │   ├─ AuthInterceptor (tower layer)     │     │
│   │   ├─ TraceLayer       (tower layer)    │     │
│   │   └─ ServiceImpl   (per service)       │     │
│   └─────────────────┬──────────────────────┘     │
│                     ▼                            │
│   ┌────────────────────────────────────────┐     │
│   │  headlines-store (diesel-async repos)  │     │
│   └─────────────────┬──────────────────────┘     │
└─────────────────────┼────────────────────────────┘
                      ▼
                Postgres (docker.yuacx.com:5432)
```

The REST gateway lives in the same binary as the gRPC server in v1 and forwards via a local tonic `Channel` (no socket roundtrip required when collocated, but the layering stays clean for future split). Splitting into two processes is a config flip — REST gateway points at a remote `grpc_endpoint` instead of an in-process channel.

Both gRPC and REST handlers ultimately call the **same `ServiceImpl`** instances; the gateway carries no business logic, only encoding translation.

## Request flow

```
Incoming gRPC                      Incoming REST
     │                                  │
     ▼                                  ▼
tonic Server ──┐                axum Router (pbjson decode) ──┐
               │                                              │
   AuthInterceptor (tower)                                     │
   ├─ parse Authorization header                               │
   ├─ verify signature via SignatureAlgorithm registry         │
   ├─ TimeSource::validate(ts) (TSO)                           │
   ├─ NonceStore::record(key_id, nonce)                        │
   ├─ resolve Subject (User/Account/System/Anonymous)          │
   └─ attach Subject to request extensions                     │
               │                                               │
   AuthorizationLayer                                          │
   ├─ look up RPC method in proto-derived AUTH_TABLE           │
   └─ assert Subject ∈ allowed; reject early if not            │
               │                                               │
   TraceLayer (request id, span attributes)                    │
               │                                               │
               └──────────► ServiceImpl trait method ◄─────────┘
                                  │
                                  ▼
                         DomainOps  (headlines-core)
                                  │
                                  ▼
                         RepositoryTraits
                                  │
                                  ▼
                       Postgres impls (headlines-store)
                                  │
                                  ▼
                              diesel-async
```

## Error model

```rust
// headlines-core/src/error.rs
#[derive(thiserror::Error, Debug)]
pub enum HeadlinesError {
    #[error("account not found")]
    AccountNotFound { id: Uuid },
    #[error("article tombstoned")]
    ArticleTombstoned { id: Uuid },
    #[error("invalid public key: {reason}")]
    InvalidPublicKey { reason: String },
    #[error("last active key")]
    LastActiveKey,
    // ... ~50 variants spanning every component doc
    #[error("internal: {0}")]
    Internal(#[from] anyhow::Error),
}

impl From<HeadlinesError> for tonic::Status { ... }
```

- One central enum.
- Each variant maps to a `google.rpc.Code` and a stable `ErrorInfo.reason` string (the strings published in each component doc).
- The REST gateway translates `tonic::Status` → HTTP status + `google.rpc.Status`-shaped JSON envelope (per `api-conventions.md`).

## Configuration (figment, layered)

`figment` overlay order: defaults baked into code → `config.toml` → `HEADLINES_*` env vars → CLI flags. Last write wins.

```toml
[server]
grpc_host = "0.0.0.0"
grpc_port = 50051
rest_host = "0.0.0.0"
rest_port = 8080
rest_gateway_target = "in_process"  # or a "host:port" for split deployment

[database]
url = "postgres://cyuan:cyuan@docker.yuacx.com:5432/headlines"
max_connections = 16

[auth.bootstrap]
user_registration    = "open"
account_registration = "system_only"

[auth.time]
source           = "in_process_tso"   # or "local_clock"
horizon_seconds  = 30

[auth.algorithms]
enabled = ["ed25519"]

[articles]
content_max_bytes = 20971520    # 20 MiB

[feeds]
replace_max_items = 5000

[events]
batch_max_items = 500

[observability]
log_level     = "info"
log_format    = "json"
otlp_endpoint = "http://otel-collector.internal:4317"
service_name  = "headlines"
```

Tailscale binding (per infra-defaults): `headlines-server` reads `TAILSCALE_IP` env var at startup. If set, it overrides `server.grpc_host` and `server.rest_host` with that IP. Resolved once.

## Database

- DSN: `postgres://cyuan:cyuan@docker.yuacx.com:5432/headlines` (per infra-defaults).
- `diesel-async` with `AsyncPgConnection`. Pool: `deadpool-diesel-async`, sized by `database.max_connections`.
- All repository traits live in `headlines-core`; Postgres impls in `headlines-store` use Diesel's query DSL — compile-time-checked schema generated by `diesel print-schema` into `crates/headlines-store/src/schema.rs` (committed).
- Transactions: every write that spans more than one row uses `pool.transaction()` (e.g. `PublishDraft`, `ReplaceRecommendationFeed`, `TombstoneArticle`).
- Migrations:
  - `migrations/<seq>_<name>/up.sql` and `down.sql` — Diesel's standard layout.
  - Authored via `diesel migration generate`.
  - Embedded into the binary with `diesel_migrations::embed_migrations!`. Server runs pending migrations at startup (configurable to off for staged-migration deploys later).
  - Schema cache: `diesel print-schema > crates/headlines-store/src/schema.rs` committed; CI checks for drift.

## Auth pipeline

`headlines-auth` exports:

- `AuthStrategy` trait + `SignedRequestStrategy` impl (default).
- `SignatureAlgorithm` trait + `Ed25519` impl. Registry indexed by `algo` string.
- `TimeSource` trait + `InProcessTso` (default) and `LocalClock` (dev) impls.
- `NonceStore` trait + in-process LRU impl.
- `AuthInterceptor` (tonic-compatible `tower::Layer`).

All composed in `headlines-server::main` from the `[auth.*]` config tree. Any trait slot is swappable without touching service code (per `auth.md` plug-in promise).

### TSO module

In-process module:

```rust
struct InProcessTso {
    last_physical_ms: AtomicU64,
    logical_counter:  AtomicU64,
    pool: deadpool::Pool,                  // for tso_high_water flush
}
```

Crash recovery: on boot, read `tso_high_water.last_physical_ms`, sleep until wall clock exceeds it, then start issuing. Periodic flush (every N timestamps or every M ms) updates the row.

`GetTime` RPC exposes the TSO to clients (anonymous-allowed RPC; see `auth.md`).

## Proto-driven authorization

Per-RPC scope/subject requirements live in proto, not in Rust handlers. A custom MethodOption encodes them; a build-script step extracts them into a Rust table consulted by `AuthorizationLayer`.

```proto
// proto/headlines/v1/options.proto
syntax = "proto3";
package headlines.v1;
import "google/protobuf/descriptor.proto";

extend google.protobuf.MethodOptions {
  optional AuthRequirement auth_requirement = 50001;
}

message AuthRequirement {
  repeated SubjectClass allowed_subjects = 1;   // USER_SELF, ACCOUNT_SELF, ACCOUNT_OWNS_RESOURCE, SYSTEM, ANONYMOUS
  repeated string required_scopes = 2;          // any-of, only when SYSTEM allowed
}

enum SubjectClass {
  SUBJECT_CLASS_UNSPECIFIED = 0;
  SUBJECT_CLASS_ANONYMOUS = 1;
  SUBJECT_CLASS_USER_SELF = 2;
  SUBJECT_CLASS_ACCOUNT_SELF = 3;
  SUBJECT_CLASS_ACCOUNT_OWNS_RESOURCE = 4;
  SUBJECT_CLASS_SYSTEM = 5;
}
```

Each RPC declares (example from articles):

```proto
rpc PublishArticle(PublishArticleRequest) returns (Article) {
  option (google.api.http) = { post: "/v1/accounts/{account_id}/articles" body: "*" };
  option (headlines.v1.auth_requirement) = {
    allowed_subjects: [ACCOUNT_SELF, SYSTEM]
    required_scopes:  ["articles.write"]
  };
}
```

Build-script step in `crates/headlines-proto/build.rs`:
1. Parses proto file descriptor set.
2. For each `Method`, reads `auth_requirement`.
3. Emits a Rust table:

```rust
pub static AUTH_TABLE: phf::Map<&'static str, AuthSpec> = phf::phf_map! {
    "/headlines.v1.ArticleService/PublishArticle" => AuthSpec {
        allowed: &[SubjectClass::AccountSelf, SubjectClass::System],
        scopes:  &["articles.write"],
    },
    // ...
};
```

`AuthorizationLayer` looks up the incoming method (`Request::uri()` for gRPC, mapped equivalent for REST) and asserts the resolved `Subject` matches.

CI lint: every `rpc` in `proto/headlines/v1/*.proto` must have an `auth_requirement` option; missing → build failure. Single source of truth.

## Observability

OpenTelemetry from day one:

- `tracing-subscriber` is the entry point for application logs.
- `tracing-opentelemetry` bridges `tracing` spans → OTel spans.
- `opentelemetry-otlp` exports spans + metrics over OTLP/gRPC to `[observability].otlp_endpoint`.
- Metrics:
  - RPC counter: `rpc_calls_total{service,method,subject_class,status}`.
  - RPC latency histogram: `rpc_latency_seconds{service,method}`.
  - Auth outcomes: `auth_results_total{result}` (`ok`, `bad_signature`, `replay`, `expired`, `unknown_key`, ...).
  - Domain counters: articles published, drafts created, events recorded, feeds replaced.
  - Sampled at all times; streaming export to OTLP collector (push), no scrape endpoint required.
- Optional Prometheus scrape: deferred but trait surface ready (swap in `opentelemetry-prometheus`).
- Resource attributes: `service.name=headlines`, `service.version=<git sha>`, `deployment.environment` from env.

## Build / dev workflow

```bash
# Proto
buf lint
buf breaking --against '.git#branch=main'
buf generate                                         # regenerates crates/headlines-proto/src/gen/

# Schema
diesel migration run                                 # apply pending
diesel print-schema > crates/headlines-store/src/schema.rs

# Build & test
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test --all-targets

# Run
TAILSCALE_IP=$(tailscale ip -4) cargo run --bin headlines-server -- --config config.toml
```

Pre-commit hooks (mirror telesync's `.pre-commit-config.yaml`): `cargo fmt`, `cargo clippy`, `buf lint`.

CI matrix: fmt, clippy, build, test, buf lint, buf breaking, schema-drift check.

## Testing

- **Unit tests**: in each crate, alongside source files. AAA pattern (`// Arrange / // Act / // Assert`).
- **Integration tests**: under `tests/`, against a real Postgres on `docker.yuacx.com`. Each test creates a fresh transactional connection; rolls back at the end.
- **DB-shared tests**: `serial_test::serial` to avoid concurrent schema state.
- No DB mocking — real Postgres only (per `~/.claude/projects/.../feedback_litevikings_mistakes.md`).

## Deployment binding

- Single binary `headlines-server`.
- Reads `TAILSCALE_IP` once at startup; binds gRPC + REST to it. Falls back to configured host if unset.
- Runs migrations on startup (configurable off for staged deploys).
- Single Postgres dependency. No Redis, no message broker for v1.

## Deferred (post-v1)

- Multi-node TSO (Raft-backed leader election; replace `InProcessTso` impl).
- Distributed nonce store (Redis); pluggable behind `NonceStore` trait.
- ClickHouse rollup of `events` for view counts and CTR.
- Notification delivery worker — covered by `delivery.md` when implementation begins.
- Per-tenant rate limiting.
- Standalone `headlines-rest-gateway` binary (in-process today, split when needed).

## Cross-references

- API contracts: `accounts.md`, `articles.md`, `drafts.md`, `users.md`, `follows.md`, `feed-recommendation.md`, `feed-follow.md`, `account-stream.md`, `events.md`, `notifications.md`.
- Schema: `data-model.md`.
- Auth signing details: `auth.md`.
- Wire conventions: `api-conventions.md`.
