# headlines — Implementation Plan

Phased build-out of v1, executing the agreed designs under `docs/design/`. Each phase has a clear scope and exit criterion. Status markers: `[ ]` not started, `[~]` in progress, `[x]` done.

## Status

- All 13 component design docs agreed (`docs/tasks.md`).
- All 9 phases (0–8) complete. v1 cut: 10 services live (9 implemented, NotificationService reserved at `UNIMPLEMENTED`), 414 workspace tests passing against `docker.yuacx.com:5432`, both gRPC + REST surfaces serving, OpenTelemetry spans + metrics shipping, CI schema-drift + cargo-audit jobs wired, OpenAPI served at `/openapi.json`.

## Cross-phase conventions

- **No commits until explicitly told.** All work is local until the user says "commit".
- **Real Postgres for tests** (`docker.yuacx.com:5432`, user `cyuan`, password `cyuan`, db `headlines`). No mocked DB, per `~/.claude/projects/-home-cyuan-projects/memory/feedback_litevikings_mistakes.md`.
- **Tailscale binding** via `TAILSCALE_IP` env var, fallback to configured host.
- **AAA test pattern** (`// Arrange / // Act / // Assert`) per `~/.claude/rules/testing-patterns.md`.
- **Design-patch process**: when implementation surfaces a gap or needed change in any design doc, the patch lives in **two places**:
  1. The relevant `docs/design/<doc>.md` is updated in place (always current).
  2. A patch log entry is added to `docs/design-patches/<YYYY-MM-DD>_<short-name>.md` explaining what changed, why (typically a phase or RPC that surfaced the issue), and which docs were touched.

## Phase 0 — Workspace & tooling foundation

**Scope:** workspace compiles cleanly, tooling is wired, CI green on a no-op PR. No application code yet.

- [x] Workspace `Cargo.toml` with `[workspace.dependencies]` registry
- [x] `.gitignore`
- [x] 7 crate stubs (`headlines-proto`, `-core`, `-store`, `-auth`, `-api`, `-rest-gateway`, `-server`) — 7/7 done
- [x] `buf.yaml` + `buf.gen.yaml` (deps include `buf.build/googleapis/googleapis`)
- [x] `.pre-commit-config.yaml` mirroring telesync (`cargo fmt`, `cargo clippy --all-targets -- -D warnings`, `buf lint`)
- [x] `.github/workflows/ci.yml` running on push: fmt, clippy, build, test, `buf lint`, `buf breaking` against `main` (schema-drift check deferred to Phase 3/8)
- [x] `README.md` build/run instructions kept current

**Exit:** `cargo check --all-targets` passes; `buf lint` passes; CI green on a trivial PR.

## Phase 1 — Proto + codegen wiring

**Scope:** proto files for the cross-cutting types and the custom `auth_requirement` MethodOption; tonic-build integrated.

- [x] `proto/headlines/v1/options.proto` — custom `auth_requirement` MethodOption + `SubjectClass` enum + `AuthRequirement` message
- [x] `proto/headlines/v1/common.proto` — `PublicKey`, `KeyStatus`, `Node`, `NodeElement`, `Article`, `ArticleSummary`, `ArticleLive`, `ArticleLiveSummary`, `ArticleTombstone`, `ArticleTombstoneSummary`, `ArticleEdit`, `ArticleState`
- [x] `crates/headlines-proto/build.rs` invoking `tonic-build` over `/proto`
- [x] Build-script extension that parses the file descriptor set and emits a Rust `AUTH_TABLE` (`phf::Map` keyed by full RPC method name → `AuthSpec`); the build fails if any RPC on a `headlines.*` service is missing the annotation

**Exit:** `cargo build -p headlines-proto` produces compiled types; `AUTH_TABLE` is generated (initially empty until services are added).

## Phase 2 — Core domain types

**Scope:** central error enum and trait surfaces frozen.

- [x] Full `HeadlinesError` enum — every `ErrorInfo.reason` from all 13 design docs as a variant
- [x] Central `Into<tonic::Status>` impl with `google.rpc.Status` + `ErrorInfo` (via `tonic-types`; no `headlines-proto` dependency needed for this)
- [x] `Subject` enum + `SubjectClass` enum (already stubbed; expand with serde + helpers)
- [x] `Tso` value type (`u64` with constructor + `Display`)
- [x] `TimeSource`, `SignatureAlgorithm`, `NonceStore`, `AuthStrategy` traits (no impls yet)
- [x] Repository traits in `headlines-core::repo`: `AccountRepo`, `ArticleRepo`, `DraftRepo`, `UserRepo`, `FollowRepo`, `FeedRecommendationRepo`, `EventRepo`, `SystemRepo`, `KeyRepo`

**Exit:** `cargo check -p headlines-core` passes; trait surfaces frozen unless a future phase justifies a design patch.

## Phase 3 — Database foundation

**Scope:** schema as a source of truth + version-based migration scripts. Diesel pool wired.

### Schema strategy

- **Source-of-truth:** `db/schema.sql` — single hand-written DDL file describing the **complete current** schema (every table, index, FK, comment).
- **Migrations:** `migrations/<NNNN>_<name>/up.sql` + `down.sql` — Diesel-style numbered migrations. Each is a delta from the previous state to the new state.
- **Invariant (CI-enforced in Phase 8):** applying all migrations in order against a fresh DB produces output structurally equivalent to `db/schema.sql`. A drift-check step compares.
- **Process for changes:**
  1. Edit `db/schema.sql` to the desired new state.
  2. Generate / hand-write a numbered migration that takes the DB from the previous state to the new state (`up.sql`) and the inverse (`down.sql`).
  3. Both files committed together; CI verifies they agree.

### Phase 3 deliverables

- [x] `db/schema.sql` — complete v1 schema covering every table from `data-model.md` (`accounts`, `account_keys`, `articles`, `articles_live`, `articles_tombstone`, `article_versions`, `drafts`, `users`, `user_keys`, `follows`, `feed_recommendation`, `systems`, `system_scopes`, `system_keys`, `tso_high_water`, `events`)
- [x] `migrations/00000000000000_initial/{up,down}.sql` — single initial migration that creates everything in `schema.sql`
- [x] `diesel.toml` config + `crates/headlines-store/src/schema.rs` regenerated via `diesel print-schema`
- [x] `deadpool-diesel-async` connection pool wiring in `headlines-store`
- [x] Embedded migrations runner via `diesel_migrations::embed_migrations!`

**Exit:** `diesel migration run` succeeds against `docker.yuacx.com:5432`. Smoke test in `headlines-store` connects + runs migrations + executes `SELECT 1`.

## Phase 4 — Auth foundation

**Scope:** signing and time-source primitives. No service handlers yet.

- [x] `TimeSource` impls: `InProcessTso` (with `tso_high_water` flush + crash-recovery wait) and `LocalClock` (dev only)
- [x] `SignatureAlgorithm` impls: `Ed25519` (via `ed25519-dalek`) + algorithm registry
- [x] `NonceStore` impls: in-process LRU
- [x] `AuthStrategy` impl: `SignedRequestStrategy` — canonicalization per `auth.md`
- [x] `AuthInterceptor` (tonic `tower::Layer`)
- [x] `AuthorizationLayer` consulting the (empty) `AUTH_TABLE`
- [x] Unit tests: round-trip sign/verify, replay rejection, expired-timestamp rejection, monotonic TSO across restart, in-process LRU eviction

**Exit:** `cargo test -p headlines-auth` passes; signing protocol matches `auth.md` exactly.

## Phase 5 — First vertical slice: AccountService

**Scope:** end-to-end implementation of one service to validate the full stack.

- [x] `proto/headlines/v1/account.proto` with `auth_requirement` annotation on every RPC
- [x] `AccountRepo` Diesel impl in `headlines-store`
- [x] `AccountService` impl in `headlines-api` — all 6 RPCs from `accounts.md`
- [x] Lockout protection on `RevokeAccountKey` (with `admin.*` override)
- [x] Integration tests against real Postgres covering: create → get → update → add-key → revoke-key → delete; error paths for invalid key, last-active-key, non-self caller
- [x] Auth pipeline wired: every RPC's `auth_requirement` is enforced via `AUTH_TABLE`

**Exit:** `cargo test -p headlines-api --test accounts` exercises the full RPC matrix and passes.

## Phase 6 — Server binary + REST gateway shell

**Scope:** the binary runs, both surfaces serve a real account.

- [x] `headlines-server` main: figment config loading (`config.toml` + `HEADLINES_*` env + CLI flags); CLI parsed via `clap`
- [x] OpenTelemetry init: OTLP exporter, resource attributes, tracing-opentelemetry bridge
- [x] gRPC server with `AuthInterceptor` + `AuthorizationLayer` + `TraceLayer`
- [x] `headlines-rest-gateway`: axum router with a single hand-written route forwarding `GetAccount` to the gRPC service via local tonic `Channel`; hand-rolled JSON encoding (pbjson deferred to Phase 7)
- [x] Tailscale-IP binding logic (read `TAILSCALE_IP`, override `[server]` host)
- [x] Migrations run on startup (configurable off via `--skip-migrations`)
- [x] Smoke: `grpcurl GetAccount` and `curl GET /v1/accounts/<id>` both return identical content

**Exit:** server starts on Tailscale IP, both surfaces serve a real account end-to-end.

## Phase 7 — Remaining services (one sub-phase each)

Order chosen for dependency minimization:

1. [x] **7.1 `UserService`** — parallel to AccountService, no new deps
2. [x] **7.2 `ArticleService`** — depends on accounts; introduces `articles_live` / `articles_tombstone` / `article_versions` tables; redaction; account-stream `updated_at` bump
3. [x] **7.3 `DraftService`** — depends on articles; atomic publish tx
4. [x] **7.4 `FollowService`** — depends on users + accounts
5. [x] **7.5 `FeedRecommendationService`** — depends on users + articles
6. [x] **7.6 `FeedFollowService`** — depends on follows + articles
7. [x] **7.7 `AccountStreamService`** — depends on articles, watermark cursor
8. [x] **7.8 `EventService`** — independent
9. [x] **7.9 `NotificationService`** — full proto + all 7 RPCs wired into the service registry, every handler returns `UNIMPLEMENTED` (`NOT_IMPLEMENTED_IN_V1` reason). No storage tables created. Surface ships even though delivery is post-v1.

Per sub-phase deliverables: proto file with `auth_requirement` annotations, migration delta if any (and corresponding `db/schema.sql` update), repository impl, service impl, REST gateway route(s), AAA-pattern integration tests, design-patch entry if any design adjustment was needed.

**Exit per sub-phase:** all RPCs in that doc pass integration tests against real Postgres; both gRPC and REST surfaces serve them.

## Phase 8 — Polish & v1 release

- [x] Full proto-driven `AUTH_TABLE` enforcement: build-script fails if any RPC lacks `auth_requirement` (verified by removing CreateAccount's annotation and confirming the build error)
- [x] OpenAPI/Swagger generation via `protoc-gen-openapiv2`; served at `/openapi.json` by the REST gateway (hand-rolled placeholder pending `buf generate`; see `docs/implementation-issues.md` `[8]`)
- [x] OpenTelemetry metrics: `rpc_calls_total`, `rpc_latency_seconds`, `auth_results_total`, domain counters
- [x] CI schema-drift check: applying migrations matches `crates/headlines-store/src/schema.rs`
- [x] CI dependency audit (`cargo audit`). Strict; advisories ignored via `.cargo/audit.toml` with justification.
- [x] `docs/codelabs.md` walk-through for one full publishing flow (account → draft → publish → feed → user reads → tombstone)
- [x] README updates: real build/run, deployment notes
- [x] Smoke deploy on Tailscale; documented in README under "Deployment"

**Exit:** v1 cut.

## Design-patch process (recap)

When implementing a phase reveals a design issue:

1. Update the relevant `docs/design/<doc>.md` to reflect the new decision.
2. Add a log entry at `docs/design-patches/<YYYY-MM-DD>_<short-name>.md` with:
   - Date
   - Phase / RPC that surfaced the issue
   - Summary of the change
   - Which design docs were touched
   - Rationale
3. Mention the patch in the relevant phase's commit message when it lands.

This keeps the design docs always-current while preserving an audit trail of how the design evolved during implementation.

## Out of scope (for v1, regardless of phase)

- Multi-node TSO (Raft-backed)
- Distributed nonce store (Redis or DB-backed)
- ClickHouse rollup of `events`
- Notification delivery worker (`delivery.md` will live alongside this doc when implementation begins)
- Per-tenant rate limiting
- Standalone REST gateway binary (split from `headlines-server`)
