# Implementation Issues

Append-only log of issues surfaced during implementation that weren't fully
resolved in the original sub-phase. Pattern: `- [<phase>] <issue> — <follow-up>`.

- [7.2] `articles.md` does not pin which of `ARTICLE_NOT_FOUND` /
  `PERMISSION_DENIED` a non-owner Account caller receives on
  `TombstoneArticle` and `EditArticle`. The handler returns
  `PERMISSION_DENIED` (since the article is publicly readable, and hiding
  its existence from a different Account doesn't help privacy). Worth a
  one-line clarification in `articles.md` if the choice is load-bearing.
- [7.3] Sub-phase agent hit an upstream rate limit before flipping its
  checklist box; manual cleanup applied. 264 workspace tests pass, all 6
  `DraftService` RPCs in `AUTH_TABLE`. No code regressions. Future agents
  could flip checklist boxes early so mid-task rate limits don't strand
  bookkeeping.
- [7.4] `follow.proto` collides on the bare `Follow` symbol — `protoc`
  cannot disambiguate the message type from the RPC method name. Worked
  around by fully-qualifying the return type on the three RPCs that
  return the message (`returns (headlines.v1.Follow)`). Renaming the
  message would diverge from `follows.md`'s wire shape, so we kept it.
- [7.4] Pre-existing rust-1.95 clippy lint
  (`unnecessary_unwrap` on `r1.unwrap_err()` after `r1.is_err()`) in
  `tests/drafts.rs` was tripping `cargo clippy --all-targets -- -D
  warnings`. Replaced the `is_err`/`unwrap_err` pattern with `if let
  Err(e) = r1` in the publish-race test. No behavior change.
- [7.4] `headlines_core::repo::FollowRepo::get` returns
  `Result<Follow, _>` (not `Option<Follow>`). The handler relies on the
  trait surfacing `FollowNotFound` directly. Task spec mentioned an
  `Option`-shaped repo return; adopting the existing trait kept the
  service layer simpler. No design change.
- [7.5] The feed-recommendation join is implemented via raw
  `diesel::sql_query` rather than the typed query DSL. The four-way
  inner join across `feed_recommendation` + `articles` + `articles_live`
  + `article_versions` is awkward to express with Diesel's typed joins
  for `article_versions` (composite PK keyed on `(article_id, version)`,
  not a simple FK), and the SQL in the design doc maps 1-to-1 to the
  raw form. The `JoinedFeedRow` `QueryableByName` shape covers the
  column types. If the join expands further we should reconsider.
- [7.5] Article-summary hydration is mostly inline in the new repo —
  the join produces all the columns directly into a single row shape and
  `row_to_feed_item` converts to `ArticleSummary`. The article repo's
  own `version_to_summary_pieces` helper isn't reused because the feed
  repo's row shape is wider (it includes `position`, the join-flattened
  state, and a precomputed `redacted` boolean). Extracting a shared
  hydration helper would force a domain-shape detour through the
  store crate; left as duplication for now.
- [7.5] The proto `Replace` symbol does not collide the way Phase 7.4's
  `Follow` did because the request/response messages use the verbose
  `ReplaceRecommendationFeed*` form. Worth documenting the convention:
  prefer verbose message names whose stem matches the RPC method when
  the bare verb (`Replace`, `Follow`, `Get`) is too generic.
- [7.5] `feeds_replace_max_items` is configurable per-instance via the
  service constructor; the binary pins it to `DEFAULT_FEEDS_REPLACE_MAX_ITEMS = 5000`.
  No `[feeds]` config block yet; mirroring the article `content_max_bytes`
  decision in Phase 7.2. Phase 8 will surface a `[feeds]` config block.
- [7.6] The follow-feed JOIN is also raw `diesel::sql_query` (not the typed
  DSL), reusing the rationale from 7.5: the four-way join across
  `follows`, `articles`, `articles_live`, `article_versions` (composite PK
  on `(article_id, version)`) doesn't map cleanly onto Diesel's typed
  joins, and the SQL in `feed-follow.md` translates 1-to-1 to the raw
  form. The `JoinedFeedRow` `QueryableByName` shape is a near-clone of the
  recommendation feed's row shape, minus `position` and with no
  `feed_recommendation` table on the FROM side. Extracting a shared
  hydration helper would require pushing a domain-shape detour through
  the store crate; left as duplication for now (same disposition as 7.5).
- [7.6] `FollowFeedItem` is intentionally a distinct proto message rather
  than a reuse of `FeedItem`, per `feed-follow.md` Q1 — there is no
  `position` field because ordering is data-driven by
  `articles.created_at` and is not server-assigned. The two services are
  different surfaces; sharing a wire type would smuggle `position=0`
  semantics into the follow feed.
- [7.6] Test ordering is pinned by stamping `articles.created_at` to a
  known ISO-8601 value via a direct UPDATE; `now()` and UUIDv7 timestamps
  on a busy DB can drift in microseconds, which made the
  `created_at DESC` assertion flaky on a first pass. Timestamps are kept
  inside a tight 2024-01 / 2024-02 window so they don't conflict with
  any real seeded fixtures.
- [7.6] Cross-user `GetFollowFeed` is rejected as `USER_NOT_FOUND`
  (NOT_FOUND), not `PERMISSION_DENIED` — mirrors `feed-recommendation.md`
  Q4: a different User caller learning that a target user exists is a
  privacy leak. System callers with `feeds.follow.read` bypass the
  self-check.
- [7.7] The account-stream JOIN is also raw `diesel::sql_query` (not the
  typed DSL), reusing the rationale from 7.5 and 7.6: a four-way LEFT
  JOIN against `articles_live`, `articles_tombstone`, and the composite-PK
  `article_versions` doesn't map cleanly onto Diesel's typed joins, and the
  SQL in `account-stream.md` translates 1-to-1 to the raw form. The
  `AccountStreamRow` `QueryableByName` shape is wider than the recommendation
  / follow rows because LIVE and TOMBSTONE rows hydrate disjoint subsets of
  columns — every Live-side and Tombstone-side column is `Nullable<_>` and
  the converter dispatches on `articles.state`. Same disposition: extracting
  a shared hydration helper would force a domain-shape detour through the
  store crate.
- [7.7] Anonymous calls on `StreamAccountArticles` may surface as either
  `PERMISSION_DENIED` (proto AUTH_TABLE rejection) or `UNAUTHENTICATED`
  (interceptor rejection) depending on how the request is shaped. The
  integration test accepts either code — both close the door. Worth a
  one-line clarification in `auth.md` if a concrete code is load-bearing
  for clients.
- [7.7] The cursor binds the `event_at` value as `timestamptz` (RFC3339 in
  the JSON payload, decoded back to `chrono::DateTime<Utc>` before binding).
  Round-tripping through RFC3339 preserves second-and-nanosecond resolution,
  but Postgres' microsecond column resolution means clients must treat
  successive cursors as opaque (don't strip-and-reconstruct) — already
  required by `api-conventions.md` but worth re-mentioning since the
  `account-stream.md` spec shows the inner JSON shape.
- [7.7] `AccountStreamItem` is a distinct proto message even though it's
  trivially `{ ArticleSummary article = 1; }`. Wrapper shape preserves room
  for stream-level metadata (e.g., a `delivery_token` or `sequence_id`) in
  a future minor version without re-flowing every consumer. Same disposition
  as 7.6's `FollowFeedItem`.
- [7.8] The `events.type` column collides with the Rust keyword `type`, so
  the Diesel `schema.rs` already exposes it as the field `type_`. The Diesel
  insertable struct uses `#[diesel(column_name = type_)]` which works for
  the typed insert path. For `QueryableByName` the SQL keyword still bites:
  raw `SELECT ... type ...` returns a column named `type` but the row shape
  reads from `type_`. Aliased the column as `type AS type_` in the `list`
  SQL to bridge the gap. A typed `Queryable` shape over `events::table`
  would avoid the alias, but the `list` query has dynamic filters that map
  more cleanly to `sql_query`.
- [7.8] `properties` storage shape is hand-rolled JSON, not pbjson — each
  event type maps to a tiny known JSON object whose keys mirror the proto
  field names (`feed_kind`, `position`, `dwell_ms`, `target`). LIKE/UNLIKE
  store an empty `{}`. The service has matching write-side (validate +
  emit JSON) and read-side (parse JSON back into the proto oneof) helpers;
  any mismatch surfaces as `Internal` rather than client-attributable
  because the storage layer never emits a shape the service didn't write.
- [7.8] `RecordEventBatch` atomicity is delivered by a single Diesel
  multi-row INSERT inside one DB roundtrip. PostgreSQL guarantees a single
  statement is atomic, which matches the all-or-none requirement. A wider
  `conn.transaction(...)` wrap would buy nothing because there's only one
  statement; revisit if a future per-row hook gets added.
- [7.8] The `occurred_at` window check pulls `now` from the configured
  `TimeSource` (TSO via `physical_ms()` projected to `DateTime<Utc>`)
  rather than calling `Utc::now()` directly. This matches the spec's
  "now (from TSO)" wording and keeps the validation anchored to the same
  monotonic clock the rest of the auth pipeline uses.
- [7.8] `events.batch_max_items` is configurable per-instance via the
  service constructor; the binary pins it to `DEFAULT_EVENTS_BATCH_MAX_ITEMS`
  (= 500). No `[events]` config block yet; mirroring the
  `feeds_replace_max_items` decision in 7.5 and the article
  `content_max_bytes` decision in 7.2. Phase 8 will surface a top-level
  `[events]` config block.
- [7.8] `ListEvents` rejects `EventType::Unspecified` in the filter list
  rather than silently dropping it. Spec doesn't pin the behavior, but
  forwarding the unspecified marker into the keyset filter would mask a
  client-side enum-encoding bug. Worth a one-line clarification in
  `events.md` if the choice is load-bearing.
- [7.8] User-self with mixed `user_id`s in a batch is rejected with the
  first event's mismatch — `UNAUTHORIZED_USER_ID` carries the offending
  `expected`/`got` pair as `ErrorInfo` metadata, but the wire only sees
  one rejection per call (per `events.md`). A System caller bypasses the
  per-event id check entirely so cross-user backfills work.
- [7.9] `NotificationService` ships as **reserved-but-not-implemented**:
  the proto, REST routes, AUTH_TABLE entries, and service registration
  are all live; every handler returns `HeadlinesError::NotImplementedInV1`
  → `UNIMPLEMENTED` with `ErrorInfo.reason = "NOT_IMPLEMENTED_IN_V1"`.
  This ships ahead of the delivery layer so clients (ranker, web/mobile,
  republishers) can integrate against the URLs today with no breaking
  proto change when implementation lands.
- [7.9] **Storage is intentionally NOT created in this phase.** Per
  `notifications.md` § Storage, the `notifications` and
  `notification_preferences` tables (and their indexes) are deferred —
  no migration, no `db/schema.sql` delta, no repo trait. The sketch in
  `notifications.md` is the to-be-implemented schema, not the current
  one.
- [7.9] Delivery worker, channel adapters (push, SMTP, SMS), retry
  policy, idempotency-key TTL store, and quiet-hours queueing are out
  of scope for v1 and will live under a future `docs/design/delivery.md`
  + dedicated phase. The `idempotency_key` field is on the proto today
  so clients can populate it, but the server discards it (returns 501
  before reading any field).
- [7.9] `NotificationServiceImpl` is a unit struct with no state — no
  repo, no time source, no idempotency cache. When the delivery phase
  begins, this struct gains `Arc<dyn NotificationRepo>`,
  `Arc<dyn IdempotencyStore>`, and `Arc<TimeSource>`; the constructor
  wiring in `headlines-server/src/main.rs` will need updating then.
- [7.9] REST gateway handlers parse a minimal request body (the same
  parser shape as the EventService routes) so a real client can send a
  request and get a 501 from the handler — not from the gateway's body
  parser. No JSON converters for `Notification` /
  `NotificationPreferences` are written in this phase since every
  response is an error envelope; they land alongside the implementation.
- [7.9] Integration tests are 14 = 7 RPCs × 2 (correct-auth → 501 with
  `NOT_IMPLEMENTED_IN_V1`; wrong-auth → `PERMISSION_DENIED` from the
  AUTH_TABLE gate). They confirm: (a) the AUTH_TABLE wiring is correct,
  (b) the handler chain reaches the impl when authorization passes,
  (c) the 501 envelope carries the documented stable reason. They do
  NOT validate notification semantics — there are none yet.
- [7.9] The `MarkNotificationRead` AUTH_TABLE entry has empty
  `required_scopes` because the spec gates it on **User self only** (the
  recipient marks their own notification read; no System path). This is
  the only Notification RPC without a System fallback, mirroring the
  `notifications.md` § Authorization table.
- [7.9] The `notifications.send`, `notifications.read`, and
  `notifications.admin` scopes are pre-existing in the
  `auth.md` § "Suggested initial scope vocabulary" table; no new scope
  values needed to land Phase 7.9. When the delivery phase begins,
  initial system identities can be granted these scopes without a
  schema or auth-config change.
- [8] `gen/openapi/headlines.v1.swagger.json` is hand-rolled in this
  phase — `buf` is not installed in the workstation environment and the
  task constraints noted that we shouldn't get stuck on generation if
  the toolchain isn't present. The descriptor covers AccountService
  illustratively (every documented surface follows the same shape per
  `api-conventions.md` and the per-service design docs). Replace with
  the `buf generate`-emitted spec from
  `buf.build/grpc-ecosystem/openapiv2` once `buf` is available; the
  REST route at `/openapi.json` is `include_str!`-backed so swapping
  the file alone is enough.
  RESOLVED (v1-review/4): swapped the hand-rolled descriptor for the
  `buf generate`-emitted `gen/openapi/headlines.swagger.json` (33 routes
  across all 10 services). `buf.gen.yaml` adds `allow_merge=true` plus
  Mfile mappings to satisfy the openapiv2 plugin's protoc-gen-go
  requirement. REST gateway `include_str!` path updated. New CI job
  `openapi-drift` reruns `buf generate` and `git diff --exit-code
  gen/openapi/` to gate drift.
- [8] AUTH_TABLE guard verification: temporarily deleted the
  `auth_requirement` option block on `AccountService.CreateAccount` in
  `proto/headlines/v1/account.proto`, ran `cargo build -p headlines-proto`,
  and confirmed the build failed with the documented error
  ("method /headlines.v1.AccountService/CreateAccount is missing the
  headlines.v1.auth_requirement MethodOption..."), then reverted. The
  guard remains active.
- [8] OpenTelemetry metrics ship as four instrument bundles:
  `RpcMetrics` (rpc_calls_total + rpc_latency_seconds, in
  `headlines-server::metrics`), `AuthMetrics` (auth_results_total, in
  `headlines-auth::metrics`), `DomainMetrics`
  (articles_published_total + drafts_created_total +
  events_recorded_total + feeds_replaced_total, in
  `headlines-api::metrics`). Each has a `shared_no_op()` constructor
  that uses the global no-op meter so tests construct without OTel
  boot. The binary calls `metrics::init_meter_provider(...)` once at
  startup and re-builds every bundle from `global::meter("...")` so
  all three crates pick up the SDK-backed provider.
- [8] The `auth_results_total` classifier (`classify_auth_error`) maps
  `AuthError` variants to a stable label vocabulary — `bad_signature`,
  `replay`, `expired`, `non_monotonic`, `unknown_key`,
  `algo_mismatch`, `subject_mismatch`, `malformed_key`,
  `malformed_signature`, `internal_time`, `internal_nonce`,
  `unauthenticated_other` — plus `malformed_header` and
  `body_read_failed` emitted from the interceptor itself. Anonymous
  calls (no `Authorization` header) do not increment the counter.
- [8] The metrics middleware (`MetricsLayer`) is wired between the
  `TraceLayer` and `AuthInterceptor` in the gRPC stack so it observes
  the resolved `Subject` (set by AuthInterceptor) on the way back, and
  reads the `grpc-status` response header to derive the `status`
  label. Test coverage in `headlines-server::metrics::tests` confirms
  the layer passes responses through and records one call per request
  via the no-op meter (no panic / no double-record). Full
  OTLP-shipping integration is left to operational verification —
  `tests/smoke.rs` doesn't assert on metric exports.
- [8] Domain counters use a builder-style `with_metrics(...)` setter
  on each service impl rather than a constructor argument, so the
  existing test corpus continues to compile unchanged. The default
  is the global no-op meter.
- [8] Schema-drift CI compares `diesel print-schema` output against
  the committed `crates/headlines-store/src/schema.rs`. The
  `pg_dump`-vs-`db/schema.sql` check is included as an
  `continue-on-error: true` informational step that compares the
  table-name set (not the full DDL — `pg_dump` output is too verbose
  and version-sensitive for byte equality). The diesel check is the
  mandatory one; the pg_dump check surfaces drift as a CI warning.
- [8] `cargo audit` job is `continue-on-error: true` for v1 per the
  task spec — security advisories are useful signal but shouldn't
  block merges. Tighten in v1.1 by removing `continue-on-error`.
- [fix-security] [v1-review/1] `PostgresKeyResolver` resolved any row
  whose `status` was not literally `"revoked"` — relying solely on the
  `*_keys.status` CHECK constraint. Fixed by adding a positive
  `status = 'active'` filter to each of the three resolve paths
  (account/user/system) and probing for non-active rows separately to
  surface them as `Revoked`. Added trait-level contract tests
  (`fake_resolver_with_*_status_*` in
  `crates/headlines-auth/src/postgres_resolver.rs`) plus three
  DB-gated end-to-end tests (`postgres_resolver_*`).
- [fix-security] [v1-review/2] `InMemoryNonceStore` allowed an
  attacker who could sustain `>capacity/horizon` qps to flush a
  captured victim nonce out of the LRU and replay it. Added
  `NonceError::Capacity` (in `headlines-core::auth`) and rejected
  inserts that would otherwise evict a still-live entry. Mapped to
  `Unauthenticated("nonce_store_full")` and added the
  `nonce_store_full` label to `classify_auth_error`. Replaced the
  misleading `lru_eviction_when_capacity_exceeded` test with two
  focused tests in `crates/headlines-auth/src/nonce.rs`.
- [fix-security] [v1-review/3] `InProcessTso` could re-issue logical
  slots after a crash within the flush interval because
  `new_with_clock` only waited for `wall_clock > stored`. Fixed by
  seeding `last` at `max(stored + flush_interval_ms, wall_now)` —
  guarantees the first issued TSO post-recovery strictly exceeds
  every value the previous process could have emitted in the
  unflushed window. Regression test
  `crash_recovery_after_unflushed_issues_emits_strictly_greater_logical`
  in `crates/headlines-auth/src/time/tso.rs`.
- [fix-security] [v1-review/4] `AuthInterceptor` passed the raw URI
  query directly into `canonical_query` instead of the
  spec-mandated sorted form — a dormant bug since today's
  authenticated REST endpoints carry no querystring fields, but a
  silent signature-mismatch waiting to happen. Added
  `canonicalize_query` (exported from `headlines-auth`), used in the
  interceptor before constructing `SignedRequestParts`. Five
  contract tests in `crates/headlines-auth/src/strategy.rs` plus a
  round-trip integration test
  (`unsorted_query_string_authenticates_against_canonical_signature`)
  in `crates/headlines-auth/src/interceptor.rs`.
- [fix-security] [v1-review/5] `ProtoBodyHasher` silently hashed the
  full frame buffer (including the gRPC frame header) when the
  compressed flag was set, which would have caused signature
  mismatches the moment an operator enabled gRPC compression — and
  it had no test pinning the byte-equivalence with
  `hash_proto_request`. Changed `BodyHasher::hash` to return
  `Result<[u8;32], BodyHashError>`; the production hasher now
  rejects compressed frames with `BodyHashError::CompressedFrame`
  and the interceptor maps the error to UNAUTHENTICATED
  (`compressed_frame` metric label). Added the load-bearing
  equivalence test
  `proto_body_hasher_matches_hash_proto_request_for_framed_body`
  plus `proto_body_hasher_rejects_compressed_frames` and an
  end-to-end interceptor test in
  `crates/headlines-auth/src/interceptor.rs`.
- [fix-hygiene] [v1-review/A] `Config::default` baked
  `postgres://cyuan:cyuan@docker.yuacx.com:5432/headlines` into the
  binary as a fallback, leaking creds and silently shipping a "default
  config" that violates the user's "no default configs" rule. Removed
  the credential default; `Config::default` now plants the sentinel
  `DATABASE_URL_REQUIRED_PLACEHOLDER` in `database.url` and a new
  `validate_required_fields` step rejects any merged config whose URL
  is empty or still equal to the placeholder. Operators must supply
  `[database].url` via config file, env var, or CLI; missing field →
  `database.url is required; set [database].url in config.toml or
  HEADLINES_DATABASE__URL env var`. Tests:
  `config_load_fails_with_clear_error_when_database_url_not_set`,
  `config_load_succeeds_when_database_url_provided_via_env`,
  `config_load_fails_when_database_url_set_to_empty_string` in
  `crates/headlines-server/src/config.rs`. Existing layering tests
  updated to provide an explicit URL via Jail.
- [fix-hygiene] [v1-review/B] `build_algorithm_registry` swallowed
  unknown algorithm names with `tracing::warn!` and accepted an empty
  `enabled` list, both of which boot a server that rejects every signed
  request. Replaced both with `anyhow::bail!`: unknown name →
  `unknown signature algorithm in [auth.algorithms].enabled: <name>`,
  empty list → `[auth.algorithms].enabled must contain at least one
  algorithm`. Function signature now returns `anyhow::Result<...>`;
  call site in `main` propagates with `?`. Tests:
  `build_algorithm_registry_registers_ed25519`,
  `build_algorithm_registry_bails_on_unknown_name`,
  `build_algorithm_registry_bails_when_empty` in
  `crates/headlines-server/src/main.rs`.
- [fix-hygiene] [v1-review/C] `[articles].content_max_bytes`,
  `[feeds].replace_max_items`, `[events].batch_max_items` were
  deserialized but ignored — `main.rs` constructed every service with
  `DEFAULT_*` constants from the api crate. Wired `config.articles.*` /
  `config.feeds.*` / `config.events.*` through to
  `ArticleServiceImpl::new`, `DraftServiceImpl::new`,
  `FeedRecommendationServiceImpl::new`, `EventServiceImpl::new`. The
  api-crate `DEFAULT_*` constants stay as the documented defaults and
  are now consumed by `Config::default` (rather than each service
  constructor) — single source of truth for the figment fallback.
  Config field types tightened to `usize` to match constructor
  signatures and avoid casts. Test:
  `articles_content_max_bytes_propagates_through_toml` in
  `crates/headlines-server/src/config.rs`. Behavior is already covered
  by the existing `ContentTooLarge` integration tests, which build the
  service with a small constructor cap.
- [fix-design] [v1-review/D] `RevokeAccountKey` accepted writes on a
  soft-deleted account — the lockout-protection block ran even though
  `accounts.md` says all writes on a deleted account return
  `FAILED_PRECONDITION` `ACCOUNT_DELETED`. Mirrored the existing
  `add_account_key` pre-check: fetch the account row, bail on
  `Deleted` status before the lockout count. Test:
  `revoke_account_key_on_deleted_account_returns_account_deleted` in
  `crates/headlines-api/tests/accounts.rs` (covers the post-tombstone
  state — controlling reason is `AccountDeleted`, not `LastActiveKey`).
- [fix-design] [v1-review/E] `PgArticleRepo::list_by_account` clamped
  to `page_size = 20` default / `100` max, contradicting
  `api-conventions.md` (default 50, max 200, server-side clamp
  `[1, 200]`). Updated the constants and replaced the inline clamp
  with a `clamp_page_size` helper that mirrors the same shape used by
  `events.rs`, `account_stream.rs`, and friends. Tests:
  `list_account_articles_default_page_size_is_50`,
  `list_account_articles_clamps_page_size_to_200`,
  `list_account_articles_clamps_page_size_keeps_in_range_values` in
  `crates/headlines-store/src/repo/articles.rs`.
- [fix-review] [v1-review/1] Documented `PERMISSION_DENIED` for non-owner
  `EditArticle` / `TombstoneArticle`. `docs/design/articles.md`
  Authorization section now includes the rationale (article existence is
  publicly readable via anonymous `GetArticle`, so no privacy carve-out
  is needed). Test:
  `edit_article_by_non_owner_account_is_permission_denied` in
  `crates/headlines-api/tests/articles.rs` (mirrors the existing
  Tombstone analogue).
- [fix-review] [v1-review/2] Pinned `PERMISSION_DENIED` for Anonymous on
  system-only RPC. Tightened
  `account_stream::anonymous_call_is_rejected` from
  `matches!(... | Unauthenticated)` to `assert_eq!(...PermissionDenied)`.
  Added sibling test `malformed_authorization_returns_unauthenticated`
  asserting `Unauthenticated` for a presented-but-bad credential. Doc:
  `docs/design/auth.md` "Layer-vs-code mapping" subsection (added under
  Fix 7) clarifies the layering rule.
- [fix-review] [v1-review/3] `ListEvents` rejection of
  `EVENT_TYPE_UNSPECIFIED` in the `types` filter is now documented in
  `docs/design/events.md` "List filters" section. The handler already
  rejects with `INVALID_ARGUMENT` (`event.rs:599`); test
  `list_events_rejects_unspecified_in_types_filter` in
  `crates/headlines-api/tests/events.rs` pins the wire surface.
- [fix-review] [v1-review/4] `gen/openapi/headlines.swagger.json` is now
  generated by `buf generate` (plugin
  `buf.build/grpc-ecosystem/openapiv2`). Replaced the hand-rolled spec.
  Added the `openapi-drift` CI job. `buf.gen.yaml` includes Mfile
  mappings for every proto and `allow_merge=true`. REST gateway
  `include_str!` path updated to the new filename
  (`headlines.swagger.json` — the plugin doesn't honor
  `merge_file_name` for the output basename, so we matched the path to
  what the plugin emits rather than rename post-generate). See `[8]`
  RESOLVED entry above.
- [fix-review] [v1-review/5] `cargo audit` is now a strict CI gate.
  Removed `continue-on-error: true` from the `cargo-audit` job in
  `.github/workflows/ci.yml`. Added `.cargo/audit.toml` with empty
  `[advisories].ignore` and `[advisories].informational_warnings = []`;
  every ignore entry in the future must carry a justification comment +
  expiry date. `docs/implementation-plan.md` Phase 8 line updated.
  Local `cargo audit` exit 0 (two unsound warnings on `diesel`/`lru` are
  informational, not gated). No advisories required adding to the
  ignore list.
- [fix-review] [v1-review/6] Trimmed workspace `tokio` features from
  `["full"]` to a curated set: `macros`, `rt-multi-thread`, `net`,
  `signal`, `sync`, `time`. Removed the `["full"]` override on
  `crates/headlines-auth/Cargo.toml` (now inherits the curated set).
  No additional features needed beyond the curated list — full
  workspace builds and 447 tests pass without `process`, `fs`, `io-*`,
  or `parking_lot` features that `["full"]` ships.
- [fix-review] [v1-review/7] `PostgresKeyResolver` cross-table `key_id`
  collision detection. Replaced first-match-wins with exactly-one-active
  semantics: scan all three `*_keys` tables, error with
  `ResolveError::Internal` and `tracing::error!` on multi-match. Tests:
  `fake_resolver_with_cross_table_collision_returns_internal` (contract,
  always runs) and `postgres_resolver_returns_internal_on_cross_table_collision`
  (DB-gated). Doc: `docs/design/auth.md` adds the "Cross-table `key_id`
  collision" + "Layer-vs-code mapping" subsections.
- [fix-review] [v1-review/8] Hybrid byte/char length validation. Human-display
  fields (`short_name`, `account.author_name`, `article.title`,
  `article.author_name`) now count Unicode chars; opaque fields
  (`author_url`, `tombstone_reason`, `redaction_reason`) stay on bytes.
  Validators in `crates/headlines-api/src/services/account.rs` and
  `crates/headlines-api/src/services/article.rs` updated. Tests:
  `validate_short_name_counts_chars_not_bytes`,
  `validate_author_name_counts_chars_not_bytes` (account),
  `validate_title_counts_chars_not_bytes`,
  `validate_author_name_counts_chars_not_bytes` (article). Docs updated:
  `docs/design/accounts.md`, `docs/design/articles.md`,
  `docs/design/drafts.md` validation tables now annotate each row with
  **chars** vs **bytes**.
- [fix-bug2] [v1-review/bug2] REST clients had to sign with the **gRPC
  fully-qualified method path** (e.g.
  `/headlines.v1.AccountService/CreateAccount`) instead of the **REST
  URL** because the gateway forwarded the inbound `Authorization`
  header verbatim and the gRPC `AuthInterceptor` re-derived the
  canonical string from the gRPC path it saw. Fix (Position A): the
  REST gateway now runs `SignedRequestStrategy` on the inbound REST
  request (canonical built from REST URL) and forwards the resolved
  `Subject` to a **trusted** in-process gRPC listener via the
  `x-headlines-trusted-subject` metadata header. The trusted listener
  is bound on `127.0.0.1:<auto>` and wrapped with
  `TrustedSubjectInterceptor`, which lifts the `Subject` into request
  extensions and skips signature verification. The **public** listener
  is bound on `[server].grpc_host:grpc_port` and still wrapped with
  the signature-verifying `AuthInterceptor`, which strips the
  trusted-subject header on entry to prevent forgery. The
  `AuthorizationLayer` runs on both listeners. Same `KeyResolver` /
  `TimeSource` / `NonceStore` / `AlgorithmRegistry` instances are
  shared across the gateway-side strategy and the public listener so
  replay/TSO state stays single-source. Tests:
  `rest_create_account_signed_path` (now asserts REST-URL signing
  passes), `gateway_rejects_forged_trusted_subject_header_on_public_listener`
  (forged System subject on the public surface is rejected), plus
  four `TrustedSubjectInterceptor` /
  `AuthInterceptor.strip_trusted_header` unit tests in
  `crates/headlines-auth/src/interceptor.rs` and three
  `attach_auth` unit tests in
  `crates/headlines-rest-gateway/src/lib.rs`. Docs:
  `docs/design/auth.md` "Canonicalization" pinned to "the public URL
  the client called" and a new "Gateway trust" subsection covers the
  loopback-listener mechanism + future mTLS upgrade path;
  `docs/design/api-conventions.md` adds a worked
  `POST /v1/articles/{id}/tombstone` example.
- [workflow-bug] [W5] `ArticleServiceImpl::edit_article` was missing the
  account-state precondition that `publish_article` already enforces. A
  soft-deleted account could continue editing its previously-published
  articles even though `accounts.md` says writes on a deleted account
  should fail with `FAILED_PRECONDITION` `ACCOUNT_DELETED`. Fixed by
  reading the owning account via `self.accounts.get(owner)` after the
  auth gate and returning `HeadlinesError::AccountDeleted` on
  `status == Deleted`. Surfaced and pinned by the W5 workflow test
  (`crates/headlines-api/tests/workflow.rs::account_lifecycle_publish_then_delete_keeps_articles_visible_but_blocks_new_writes`).
