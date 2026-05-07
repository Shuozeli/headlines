# EventService

Status: agreed (v1)
Scope: append-only user-activity log used by the ranker / analytics. Events are the source of truth; counts and rolled-up metrics derive from this table via background jobs (eventually ClickHouse). Wire shape: `api-conventions.md`. Auth: `auth.md`. Schema: `data-model.md`.

## Event types (v1)

| Type | Properties | Meaning |
|---|---|---|
| `IMPRESSION` | `feed_kind`, `position` | Article shown in a feed |
| `OPEN` | `feed_kind`, `position` | User opened the article detail view |
| `DWELL` | `dwell_ms` | Time spent reading (caller can emit multiple per session) |
| `LIKE` | — | User liked an article |
| `UNLIKE` | — | User reverted a like |
| `SHARE` | `target` | User shared (e.g. `twitter`, `copy_link`) |

`feed_kind` ∈ `{recommendation, follow, account, direct}` — where the article was encountered.

No state tables for likes / shares in v1 — counts and "liked-by-me" derive from events later. Follow / unfollow are tracked in `follows` (not as events).

## Messages

```proto
message Event {
  string id = 1;                                 // UUIDv7, server-assigned
  string user_id = 2;                            // soft ref
  string article_id = 3;                         // soft ref
  EventType type = 4;
  google.protobuf.Timestamp occurred_at = 5;     // client-supplied
  google.protobuf.Timestamp received_at = 6;     // server-assigned (TSO)
  string surface = 7;                            // 'web', 'mobile', 'twitter-bot', ...
  oneof properties {
    ImpressionProperties impression = 100;
    OpenProperties open = 101;
    DwellProperties dwell = 102;
    LikeProperties like = 103;
    UnlikeProperties unlike = 104;
    ShareProperties share = 105;
  }
}

enum EventType {
  EVENT_TYPE_UNSPECIFIED = 0;
  EVENT_TYPE_IMPRESSION = 1;
  EVENT_TYPE_OPEN = 2;
  EVENT_TYPE_DWELL = 3;
  EVENT_TYPE_LIKE = 4;
  EVENT_TYPE_UNLIKE = 5;
  EVENT_TYPE_SHARE = 6;
}

message ImpressionProperties { string feed_kind = 1; int32 position = 2; }
message OpenProperties       { string feed_kind = 1; int32 position = 2; }
message DwellProperties      { int64 dwell_ms = 1; }
message LikeProperties       {}
message UnlikeProperties     {}
message ShareProperties      { string target = 1; }
```

`type` and the `properties` oneof must agree; mismatch is an `INVALID_ARGUMENT`.

## Storage

```sql
events
  id            uuid PRIMARY KEY
  user_id       uuid NOT NULL                  -- soft ref (no FK)
  article_id    uuid                            -- soft ref, nullable
  type          text NOT NULL
  occurred_at   timestamptz NOT NULL
  received_at   timestamptz NOT NULL
  surface       text NOT NULL
  properties    jsonb NOT NULL                  -- typed payload as JSON

CREATE INDEX events_by_received_at      ON events (received_at);
CREATE INDEX events_by_user_received    ON events (user_id, received_at);
CREATE INDEX events_by_article_received ON events (article_id, received_at);
```

Rows are append-only. No update / delete from API. `data-model.md` is patched accordingly.

## Service

```proto
service EventService {
  rpc RecordEvent(RecordEventRequest) returns (Event) {
    option (google.api.http) = { post: "/v1/events" body: "*" };
  }
  rpc RecordEventBatch(RecordEventBatchRequest) returns (RecordEventBatchResponse) {
    option (google.api.http) = { post: "/v1/events:batch" body: "*" };
  }
  rpc ListEvents(ListEventsRequest) returns (ListEventsResponse) {
    option (google.api.http) = { get: "/v1/events" };
  }
}

message RecordEventRequest {
  string user_id = 1;
  string article_id = 2;
  EventType type = 3;
  google.protobuf.Timestamp occurred_at = 4;
  string surface = 5;
  oneof properties {
    ImpressionProperties impression = 100;
    OpenProperties open = 101;
    DwellProperties dwell = 102;
    LikeProperties like = 103;
    UnlikeProperties unlike = 104;
    ShareProperties share = 105;
  }
}

message RecordEventBatchRequest {
  repeated RecordEventRequest events = 1;
}
message RecordEventBatchResponse {
  repeated Event recorded = 1;                  // same order as request, populated with id + received_at
  int32 stored_count = 2;
}

message ListEventsRequest {
  int32 page_size = 1;
  string page_token = 2;                        // opaque base64 cursor on (received_at, id)
  string user_id = 3;                           // optional filter
  string article_id = 4;                        // optional filter
  repeated EventType types = 5;                 // optional filter
  google.protobuf.Timestamp received_after = 6;
  google.protobuf.Timestamp received_before = 7;
}
message ListEventsResponse {
  repeated Event items = 1;
  string next_page_token = 2;
}
```

`RecordEvent` and `RecordEventBatch` return the persisted `Event` records (with server-assigned `id` and `received_at`) so clients can correlate.

## Authorization

| RPC | Allowed subject |
|---|---|
| `RecordEvent` | `User` whose `user_id == request.user_id` **or** `System` with scope `events.write` |
| `RecordEventBatch` | Same rule, applied to **every** event in the batch — a user-self batch with any `user_id != subject.user_id` is rejected with `UNAUTHORIZED_USER_ID` (no partial commit) |
| `ListEvents` | `System` with scope `events.read` only |

User-self writes let a web/mobile client (already signing as the user) post their own events. System path is for trusted aggregators / backfills.

## Behaviors

### Server-set fields

`id` (UUIDv7) and `received_at` (TSO time) are server-assigned. If the request supplies them they are silently ignored — never an error.

### Soft references

`user_id` and `article_id` are not FK-enforced. Events for deleted users or tombstoned articles are recorded normally. Analytics keeps the trail.

### `occurred_at` window

Server clamps `occurred_at` to `[now - 24h, now + 60s]` (now from TSO). Outside → `EVENT_TIMESTAMP_OUT_OF_RANGE`. Prevents far-future or ancient backfill via the user-write path.

### No dedup

The same `(user_id, article_id, type, occurred_at)` recorded twice yields two rows. Rollup jobs dedupe per their own rules.

### Batch atomicity

`RecordEventBatch` is **all-or-none**. Validation runs over the whole batch first; on any failure the entire batch is rejected with the first failing reason. On success the batch is inserted in a single tx.

Cap: `events.batch_max_items` (default **500**). Exceeding → `BATCH_TOO_LARGE`.

### Type / properties consistency

The `properties` oneof selector must match `type` (e.g. `type = OPEN` ⇒ `properties.open` set). Otherwise `EVENT_TYPE_MISMATCH`.

### List filters

All `ListEventsRequest` filters are AND-combined. Filterable: `user_id`, `article_id`, any subset of `types`, `received_at` bounds. Cursor encodes `(received_at, id)` for stable forward iteration; results in ASC order so the ranker can drain incrementally.

`types` filter: `EVENT_TYPE_UNSPECIFIED` in the list is rejected with `INVALID_ARGUMENT` (same rule as the write-side `type` validation). Clients constructing the filter dynamically must omit unspecified entries client-side; silently dropping the marker would mask a client-side enum-encoding bug.

## Validation

| Field | Rule |
|---|---|
| `user_id` | well-formed UUID; required |
| `article_id` | well-formed UUID; required for all v1 types |
| `type` | one of the v1 enum values; `UNSPECIFIED` rejected |
| `occurred_at` | within `[now − 24h, now + 60s]` |
| `surface` | non-empty, ≤32 chars, `[a-z0-9_-]` |
| `properties.position` | ≥ 0 |
| `properties.dwell_ms` | in `[0, 24h]` (86_400_000) |
| `properties.feed_kind` | in `{recommendation, follow, account, direct}` |
| `properties.share.target` | non-empty, ≤32 chars |
| `RecordEventBatch.events` | size in `[1, events.batch_max_items]` |

## Configuration

```toml
[events]
batch_max_items = 500
```

## Errors

| Reason | Code | When |
|---|---|---|
| `INVALID_ARGUMENT` | `INVALID_ARGUMENT` | malformed UUID, bad surface, etc. |
| `EVENT_TYPE_MISMATCH` | `INVALID_ARGUMENT` | `type` and `properties` oneof disagree |
| `EVENT_TIMESTAMP_OUT_OF_RANGE` | `INVALID_ARGUMENT` | `occurred_at` outside the allowed window |
| `BATCH_TOO_LARGE` | `RESOURCE_EXHAUSTED` | `RecordEventBatch` exceeds `batch_max_items` |
| `UNAUTHORIZED_USER_ID` | `PERMISSION_DENIED` | user-self caller posted an event with a different `user_id` |

## Cross-references

- Schema: `data-model.md` — `events` table (added by this doc).
- Auth scopes: `auth.md` — `events.read`, `events.write`.
- Wire envelope, AIP pagination, error format: `api-conventions.md`.
- Article references: `articles.md`. User references: `users.md`.
- Future: ClickHouse rollup of this table for view counts and CTR — out of scope for v1.
