# headlines — Design Tasks

This is the design-phase task list. Each component below gets its own design doc under `docs/design/<component>.md`. No code is written until per-component designs are agreed.

## Project recap

`headlines` is a thin Rust API middle layer between a ranker/crawler pipeline (upstream) and presentation surfaces (downstream — our web app, mobile, Twitter/YouTube/Toutiao republishers). It does not compute ranking, scoring, or freshness; it stores and serves what is pushed.

Three entities: **account** (publisher) → owns **articles** (Telegraph-shaped content) → consumed by **users**. Users follow accounts and have two feeds (recommendation, follow).

## Settled decisions (carry into per-component docs)

- Stack: Rust. Specific framework / DB driver / crates: **deferred to `architecture.md`**.
- Protocol: gRPC first-class; REST/Swagger generated from `google.api.http` annotations. `headlines.v1` proto package.
- Article content shape: Telegraph-style recursive `Node` proto (defined in `articles.md`). Routes are ours, not wire-compatible with Telegraph.
- IDs: UUIDv7 for all entities (accounts, articles, users, drafts, keys, events). No slugs — article URLs use `articles.id` directly.
- All entities use `snake_case` proto field names; JSON also `snake_case` (override the proto3 lowerCamelCase default).
- Soft-delete model: tombstone for articles (`articles_live` / `articles_tombstone` split), `status='deleted'` for accounts/users, hard-delete for drafts and follows-on-revoke.
- Auth: pluggable signing-trait. Default = signed requests with versioned keypair (`{user,account,system}_keys`). Three subjects (`User`, `Account`, `System`) plus `Anonymous`. System scopes are dotted strings; vocabulary lives in `auth.md`.
- Time source: in-process TSO (TiDB-PD-shaped, single-node v1). Replay horizon 30s.
- Recommendation feed write semantics: `PUT` replace (full ordered list).
- List vs view rule: list responses return `*Summary` messages (no content nodes); single-item reads return the full message.
- Pagination: AIP-158 (`page_size` hint, `page_token` opaque base64 cursor).
- Notifications: 7-RPC surface reserved; returns `UNIMPLEMENTED` in v1.

## Component design docs

Each is a separate doc. Status: `[ ]` not started, `[~]` in draft, `[x]` agreed.

### Core API surfaces

- [x] `docs/design/auth.md` — Pluggable signing strategy, three subjects (User/Account/System with dotted scopes), canonical-proto hashing, in-process TSO time source, replay protection, key rotation, bootstrap modes via config.
- [x] `docs/design/accounts.md` — `AccountService` (Create/Get/Update/Delete + Add/Revoke key), UUIDv7 IDs, anonymous reads, scope-gated cross-account ops (`accounts.write` / `accounts.admin` / `accounts.delete`), lockout protection.
- [x] `docs/design/articles.md` — `ArticleService` (Publish/Get/ListByAccount/Edit/Tombstone/RedactVersion), recursive `Node` proto, no slug (URL = UUIDv7), version history private (no API), default 20 MiB content cap, dedicated `articles.redact` scope.
- [x] `docs/design/drafts.md` — `DraftService` (Create/Get/Update/Delete/List/Publish), strict validation on every draft write, hard-delete, list ordered by `updated_at DESC`, atomic publish with same-UUID continuity.
- [x] `docs/design/users.md` — `UserService` (Create/Get/Update/Delete + Add/Revoke key), private `GetUser` (not anonymous), no soft-delete cascade, parallels accounts.md.
- [x] `docs/design/follows.md` — `FollowService` (Follow/Unfollow/Get/ListUserFollows/ListAccountFollowers), idempotent follow with `created_at=now` on re-activate, `FOLLOW_NOT_FOUND` on unfollow of missing edge, self-follow rejected, no deleted-user filtering, no counts in v1.
- [x] `docs/design/feed-recommendation.md` — `FeedRecommendationService` (Replace/Get), tx-replace per user, soft article refs filtered via inner join to `articles_live`, AIP-158 pagination, 5000-item cap, `FeedItem` carries `ArticleSummary`.
- [x] `docs/design/feed-follow.md` — `FeedFollowService.GetFollowFeed`, computed via `follows ⨝ articles_live`, keyset cursor on `(created_at, id)`, deleted-account articles included, no "since I followed" cutoff, new `feeds.follow.read` scope.
- [x] `docs/design/account-stream.md` — `AccountStreamService.StreamAccountArticles`, ASC watermark cursor on `event_at`, returns `ArticleSummary`, includes create/edit/redact/tombstone events, closes on account delete, new `articles.stream` scope.
- [x] `docs/design/events.md` — `EventService` (RecordEvent / RecordEventBatch / ListEvents), 6 v1 types (IMPRESSION/OPEN/DWELL/LIKE/UNLIKE/SHARE), typed oneof properties, soft refs, no dedup, all-or-none batches (cap 500), occurred_at window ±24h/+60s.
- [x] `docs/design/notifications.md` — `NotificationService` (7 RPCs, all return `UNIMPLEMENTED` in v1): Send/Batch/List/MarkRead/MarkAllRead + Get/Update preferences. 7 kinds, 4 channels, idempotency_key reserved, storage tables sketched but not added to data-model yet.

### Cross-cutting

- [x] `docs/design/data-model.md` — Tables, columns, indexes, UUIDv7 strategy, foreign keys, tombstone-vs-soft-delete-vs-hard-delete rules, events table, system tables, TSO high-water table.
- [x] `docs/design/api-conventions.md` — gRPC-first protocol, REST gateway from proto annotations, `/v1/` versioning, error envelope (`google.rpc.Status` + `ErrorInfo`), AIP pagination, auth header shape, snake_case fields.
- [x] `docs/design/architecture.md` — Cargo workspace (7 crates), `tonic` + Rust-native REST gateway via axum, `diesel` + `diesel-async` + `diesel_migrations`, `figment` config, `ed25519-dalek`, OpenTelemetry day-one (OTLP push), proto-driven `auth_requirement` annotation → Rust `AUTH_TABLE`, in-process TSO module.

## Recommended drafting order (historical)

1. `data-model.md` and `api-conventions.md` first — most other docs depend on these.
2. `auth.md` next — gates every other endpoint.
3. Then content surfaces in dependency order: `accounts.md` → `articles.md` → `drafts.md` → `users.md` → `follows.md`.
4. Feeds: `feed-recommendation.md` → `feed-follow.md`.
5. Downstream: `account-stream.md`.
6. Late: `events.md`, `notifications.md`, `architecture.md`.

All but `architecture.md` are agreed.

## Out of scope (v1)

- Ranking / scoring / freshness logic
- Notification delivery (only API surface reserved)
- Web/mobile/republisher implementations (consumers, not part of headlines)
- Real user identity mapping to external platforms
