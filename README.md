# headlines

Thin Rust API middle layer between a content/ranker pipeline (upstream) and presentation surfaces (downstream — web, mobile, Twitter/YouTube/Toutiao republishers). headlines does **not** rank, score, or compute feed freshness; it stores and serves what is pushed.

## Status

**v1 implementation complete: 10 services, 414 workspace tests, real Postgres.**

- All 13 component designs live under `docs/design/` and are agreed.
- Phased implementation plan at [`docs/implementation-plan.md`](docs/implementation-plan.md). All 9 phases (0–8) complete.
- Walk-through of the full publishing flow at [`docs/codelabs.md`](docs/codelabs.md).
- Design changes that happened during implementation are logged in [`docs/design-patches/`](docs/design-patches/) and applied in-place to the relevant design doc.

| | Doc | Surface | Status |
|---|---|---|---|
| Cross-cutting | [data-model](docs/design/data-model.md) | Postgres schema, identity rules, soft-delete model | [x] |
| | [api-conventions](docs/design/api-conventions.md) | gRPC-first, REST gateway, AIP pagination, error envelope | [x] |
| | [auth](docs/design/auth.md) | Pluggable signed requests, three subjects, in-process TSO | [x] |
| | [architecture](docs/design/architecture.md) | Workspace, crates, request flow, observability, deployment | [x] |
| Identity | [accounts](docs/design/accounts.md) | `AccountService` | [x] |
| | [users](docs/design/users.md) | `UserService` | [x] |
| Content | [articles](docs/design/articles.md) | `ArticleService` (Telegraph-shaped `Node` content, versions, redaction) | [x] |
| | [drafts](docs/design/drafts.md) | `DraftService` (private working space, atomic publish) | [x] |
| Social | [follows](docs/design/follows.md) | `FollowService` | [x] |
| Feeds | [feed-recommendation](docs/design/feed-recommendation.md) | Ranker-pushed PUT-replace per user | [x] |
| | [feed-follow](docs/design/feed-follow.md) | Computed follow-feed | [x] |
| Downstream | [account-stream](docs/design/account-stream.md) | Republisher pull-firehose per account | [x] |
| Activity | [events](docs/design/events.md) | Append-only user-activity log (analytics source) | [x] |
| Reserved | [notifications](docs/design/notifications.md) | 7 RPCs designed, `UNIMPLEMENTED` in v1 | [x] |

| Phase | Status |
|---|---|
| 0. Workspace & tooling foundation | [x] |
| 1. Proto + codegen wiring | [x] |
| 2. Core domain types | [x] |
| 3. Database foundation | [x] |
| 4. Auth foundation | [x] |
| 5. AccountService vertical slice | [x] |
| 6. Server binary + REST gateway shell | [x] |
| 7. Remaining services (9 sub-phases) | [x] |
| 8. Polish & v1 release | [x] |

Design tasks index: [`docs/tasks.md`](docs/tasks.md).

## What it does

- **Three entities**: `account` (publisher) → owns **`articles`** → consumed by **`users`**. Users follow accounts; users have two feeds (recommendation + follow).
- **Three subject classes** for auth: `User` (consumer), `Account` (publisher), `System` (ranker / republisher / admin, scope-gated).
- **Ranker pushes**: articles via `PublishArticle` (or `PublishDraft`), recommendation feed via `ReplaceRecommendationFeed`.
- **Users pull**: `GetRecommendationFeed`, `GetFollowFeed`, `GetArticle`. They post events back via `RecordEvent` / `RecordEventBatch`.
- **Republishers pull** per-account `StreamAccountArticles` (ASC watermark cursor; create / edit / redact / tombstone events).

## What it does not do

- No ranking, scoring, or freshness logic — upstream ranker owns those.
- No notification delivery (proto reserved, returns `UNIMPLEMENTED`).
- No mobile/web/republisher implementations — those are downstream consumers.
- No mapping between our user IDs and external platforms (Twitter, YouTube, etc.).

## Tech stack

- Rust + `tonic` gRPC; Rust-native REST gateway via `axum`
- `diesel` + `diesel-async` + `diesel_migrations` against Postgres
- `ed25519-dalek` (default), pluggable algorithms behind a trait
- In-process TSO (TiDB-PD-shaped) for monotonic time
- `figment` config (layered: defaults → file → env → CLI)
- OpenTelemetry day-one (OTLP push for spans + metrics; `rpc_calls_total`, `rpc_latency_seconds`, `auth_results_total`, plus 4 domain counters)
- Proto-annotation-driven authorization (`auth_requirement` MethodOption → build-script-generated Rust `AUTH_TABLE`; build fails if any RPC lacks the annotation)

## Build / run

```bash
# Lint + test
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
DATABASE_URL=postgres://cyuan:cyuan@docker.yuacx.com:5432/headlines cargo test --workspace

# Build the binary
cargo build --release --bin headlines-server
```

Boot the server (Tailscale-bound):

```bash
TAILSCALE_IP=$(tailscale ip -4) cargo run --release \
    --bin headlines-server -- --config config.toml
```

Defaults: gRPC on `:50051`, REST on `:8080`. Migrations run on startup; pass
`--skip-migrations` to opt out.

Sample REST hits:

```bash
# Anonymous read of an account
curl -sS http://$TAILSCALE_IP:8080/v1/accounts/<known-id>

# OpenAPI/Swagger descriptor (anonymous-readable)
curl -sS http://$TAILSCALE_IP:8080/openapi.json | jq '.info'
```

Sample gRPC hits:

```bash
grpcurl -plaintext $TAILSCALE_IP:50051 list
grpcurl -plaintext -d '{"id":"<known-id>"}' \
    $TAILSCALE_IP:50051 headlines.v1.AccountService/GetAccount
```

A full end-to-end walk-through is in [`docs/codelabs.md`](docs/codelabs.md).

## Deployment

The server is a single binary; one Postgres dependency, no Redis or message
broker for v1. Smoke deploy on Tailscale:

```bash
# 1. Build for release
cargo build --release --bin headlines-server

# 2. Start, bound to Tailscale interface
TAILSCALE_IP=$(tailscale ip -4) ./target/release/headlines-server \
    --config config.toml

# 3. Verify gRPC services reachable from any Tailscale node
grpcurl -plaintext $TAILSCALE_IP:50051 list

# 4. Verify REST surface
curl -sS http://$TAILSCALE_IP:8080/openapi.json | jq '.swagger'
curl -sS http://$TAILSCALE_IP:8080/v1/accounts/<known-id>
```

If Tailscale isn't available, `TAILSCALE_IP=127.0.0.1` works for a localhost
loopback smoke. Production deployments should set
`[auth.bootstrap].account_registration = "system_only"` and grant the
`accounts.write` system scope to whoever bootstraps publisher identities.

## Repository

Local-only at `/home/cyuan/projects/headlines/`. Not yet pushed to a GitHub remote.
