# headlines — Codelab: end-to-end publishing flow

This walk-through wires every concept in `docs/design/` together against a
running `headlines-server`. Read once, then run the commands top-to-bottom
to see the full lifecycle: account creation → first key → user → follow →
draft → publish → reads → events → tombstone.

The IDs in this doc are illustrative UUIDv7s. When you run it yourself,
substitute the values returned by each step into the next.

## Prerequisites

- `docker.yuacx.com:5432` Postgres reachable, with database `headlines` and
  the migrations applied. The server runs them on boot unless
  `--skip-migrations` is set.
- `headlines-server` running on the Tailscale IP (or `127.0.0.1` for a local
  loopback run):

  ```bash
  TAILSCALE_IP=$(tailscale ip -4) cargo run --release \
      --bin headlines-server -- --config config.toml
  ```

  Defaults: gRPC on `:50051`, REST on `:8080`. The base URL below assumes
  `http://$TAILSCALE_IP:8080` — substitute as needed.

- `[auth.bootstrap].account_registration = "open"` and
  `user_registration = "open"` in `config.toml` for the codelab. Production
  flips one or both to `"system_only"`.

- `curl`, optionally `grpcurl`, and an Ed25519 keypair generator. For the
  body of this doc we'll handwave the canonical-string construction; in
  practice the [auth.md](design/auth.md) algorithm is implemented in your
  client SDK or in a small signing helper.

## Variables we'll re-use

```bash
BASE_URL="http://$TAILSCALE_IP:8080"
GRPC_ADDR="$TAILSCALE_IP:50051"
```

Throughout, when we sign requests, the `Authorization` header carries:

```
Signature key_id=<uuid>, algo=ed25519, ts=<u64>, nonce=<base64>, sig=<base64>
```

See [auth.md § Canonical String](design/auth.md) for the canonical-string
construction. The interceptor enforces ±30s replay horizon and de-dupes
`(key_id, nonce)` within that window.

---

## Step 1 — Create an account

Open registration is anonymous — no `Authorization` header. Provide an
initial Ed25519 public key (raw 32-byte key, base64-encoded):

```bash
curl -sS -X POST "$BASE_URL/v1/accounts" \
  -H 'Content-Type: application/json' \
  -d '{
    "short_name": "demo_pub",
    "author_name": "Demo Publisher",
    "author_url": "https://example.com",
    "initial_key": {
      "algo": "ed25519",
      "public_key": "<base64-32-byte-key>"
    }
  }'
```

Response:

```json
{
  "account": {
    "id": "01934c00-7a8e-7c00-8000-aaaaaaaaaaaa",
    "short_name": "demo_pub",
    "status": "ACCOUNT_STATUS_ACTIVE",
    ...
  },
  "initial_key": {
    "key_id": "01934c00-7a8e-7c00-8000-bbbbbbbbbbbb",
    "algo": "ed25519",
    "status": "KEY_STATUS_ACTIVE",
    ...
  }
}
```

```bash
ACCOUNT_ID="01934c00-7a8e-7c00-8000-aaaaaaaaaaaa"
ACCOUNT_KEY_ID="01934c00-7a8e-7c00-8000-bbbbbbbbbbbb"
```

## Step 2 — Sign subsequent requests as that account

From now on, every Account-self request signs the canonical string with the
private half of `initial_key`. The header form is the same one shown above;
your client must:

1. Build the canonical string per [auth.md](design/auth.md) (method, path,
   sorted query, request-body SHA-256, key_id, algo, ts, nonce).
2. Sign with the private key.
3. Send `Authorization: Signature key_id=..., algo=ed25519, ts=..., nonce=..., sig=...`.

Verify the signing pipeline by reading the account back as ourselves:

```bash
curl -sS -H "Authorization: $AUTH" "$BASE_URL/v1/accounts/$ACCOUNT_ID"
```

(`GetAccount` is anonymously readable too — the signature only matters
for write paths.)

## Step 3 — Create a user

Same shape as `CreateAccount`:

```bash
curl -sS -X POST "$BASE_URL/v1/users" \
  -H 'Content-Type: application/json' \
  -d '{
    "display_name": "Reader Alice",
    "initial_key": {
      "algo": "ed25519",
      "public_key": "<another-base64-32-byte-key>"
    }
  }'
```

```bash
USER_ID="01934c00-7a8e-7c00-8000-cccccccccccc"
USER_KEY_ID="01934c00-7a8e-7c00-8000-dddddddddddd"
```

## Step 4 — User follows the account

User-self only:

```bash
curl -sS -X POST "$BASE_URL/v1/users/$USER_ID/follows" \
  -H "Authorization: $USER_AUTH" \
  -H 'Content-Type: application/json' \
  -d "{\"account_id\": \"$ACCOUNT_ID\"}"
```

Idempotent: re-following an already-followed account stamps `created_at = now`
and returns the existing edge in `FOLLOW_STATUS_ACTIVE` (per
[follows.md](design/follows.md)).

## Step 5 — Account creates a draft

Drafts are private to the owning account (or System with `drafts.write`).
The strict article rules apply on every draft write — title length,
content cap, etc.

```bash
curl -sS -X POST "$BASE_URL/v1/accounts/$ACCOUNT_ID/drafts" \
  -H "Authorization: $ACCOUNT_AUTH" \
  -H 'Content-Type: application/json' \
  -d '{
    "title": "Hello, headlines",
    "author_name": "Demo Publisher",
    "author_url": "https://example.com",
    "content": [
      {"text": "Welcome to the demo."}
    ]
  }'
```

```bash
DRAFT_ID="01934c00-7a8e-7c00-8000-eeeeeeeeeeee"
```

## Step 6 — Account publishes the draft

`PublishDraft` is atomic: same UUIDv7 between draft and article (the draft
row is consumed in a single transaction). The published `Article` carries
the same id as the draft, so any client that already linked the draft id
keeps a stable handle.

```bash
curl -sS -X POST "$BASE_URL/v1/drafts/$DRAFT_ID/publish" \
  -H "Authorization: $ACCOUNT_AUTH"
```

Response: a full `Article` message with `state = ARTICLE_STATE_LIVE`,
`current_version = 1`, the supplied content nodes, and timestamps.

```bash
ARTICLE_ID="$DRAFT_ID"   # same UUID — see drafts.md
```

## Step 7 — User reads the article

`GetArticle` is anonymously readable:

```bash
curl -sS "$BASE_URL/v1/articles/$ARTICLE_ID"
```

`GetFollowFeed` is User-self (or System with `feeds.follow.read`). The feed
is computed at read-time as `follows ⨝ articles_live` ordered by
`articles.created_at DESC`:

```bash
curl -sS -H "Authorization: $USER_AUTH" \
  "$BASE_URL/v1/users/$USER_ID/feed/follow?page_size=20"
```

The just-published article appears at the top.

## Step 8 — User records events

`RecordEvent` is User-self for that user_id (or System with `events.write`).
The `occurred_at` window check is ±24h / +60s relative to the TSO clock.

```bash
curl -sS -X POST "$BASE_URL/v1/events" \
  -H "Authorization: $USER_AUTH" \
  -H 'Content-Type: application/json' \
  -d "{
    \"user_id\": \"$USER_ID\",
    \"article_id\": \"$ARTICLE_ID\",
    \"type\": \"EVENT_TYPE_OPEN\",
    \"occurred_at\": \"2026-04-30T12:00:00Z\",
    \"properties\": {
      \"open\": {\"feed_kind\": \"follow\", \"position\": 0}
    }
  }"
```

For analytics workloads, batch via `POST /v1/events:batch` (cap = 500;
all-or-none atomic per [events.md](design/events.md)).

## Step 9 — System pushes a recommendation feed (optional)

System-only with `feeds.recommendation.write`:

```bash
curl -sS -X PUT "$BASE_URL/v1/users/$USER_ID/feed/recommendation" \
  -H "Authorization: $SYSTEM_AUTH" \
  -H 'Content-Type: application/json' \
  -d "{\"article_ids\": [\"$ARTICLE_ID\"]}"
```

User reads back their feed (User-self):

```bash
curl -sS -H "Authorization: $USER_AUTH" \
  "$BASE_URL/v1/users/$USER_ID/feed/recommendation?page_size=20"
```

The `Replace` is full-list semantics — any previous list is gone.

## Step 10 — Republisher streams the account

System-only with `articles.stream`. The cursor is opaque base64 over
`(event_at, id)` — opaque, ASC. Pull-style (paged):

```bash
curl -sS -H "Authorization: $SYSTEM_AUTH" \
  "$BASE_URL/v1/accounts/$ACCOUNT_ID/article-stream?page_size=10"
```

The first page contains the `ARTICLE_STATE_LIVE` event for our just-published
article. The republisher persists `next_page_token` and resumes from there
on subsequent polls.

```bash
# Or via grpcurl:
grpcurl -plaintext \
  -H "Authorization: $SYSTEM_AUTH" \
  -d "{\"account_id\": \"$ACCOUNT_ID\"}" \
  $GRPC_ADDR headlines.v1.AccountStreamService/StreamAccountArticles
```

## Step 11 — Account tombstones the article

`TombstoneArticle` is Account-self for the owning account, or System with
`articles.write`. The article moves from `articles_live` to
`articles_tombstone`; the row in `articles` is preserved (soft-tombstone).

```bash
curl -sS -X POST "$BASE_URL/v1/articles/$ARTICLE_ID/tombstone" \
  -H "Authorization: $ACCOUNT_AUTH"
```

Subsequent `GetArticle` returns the tombstone shape (no `current_version`
content, `state = ARTICLE_STATE_TOMBSTONE`).

The republisher's next stream poll observes a new
`ARTICLE_STATE_TOMBSTONE` event for the same `ARTICLE_ID`. The follow-feed
no longer surfaces the article (the join filters on `articles_live`).

```bash
curl -sS -H "Authorization: $SYSTEM_AUTH" \
  "$BASE_URL/v1/accounts/$ACCOUNT_ID/article-stream?page_token=$NEXT_TOKEN"
```

---

## Recap

Eleven steps, four entities, ten services (NotificationService deliberately
returns `UNIMPLEMENTED` in v1). The auth pipeline gates every write; the
proto-level `AUTH_TABLE` enforces subject + scope before the handler runs;
the metrics middleware records `rpc_calls_total` / `rpc_latency_seconds` /
`auth_results_total` / domain counters around each handler.

For the full RPC surface:

- gRPC: `grpcurl -plaintext $GRPC_ADDR list` enumerates every service.
- REST: `curl $BASE_URL/openapi.json` returns the OpenAPI/Swagger
  descriptor (currently a hand-rolled placeholder per
  `docs/implementation-issues.md` `[8]` — full
  `protoc-gen-openapiv2`-emitted spec is a near-term follow-up).
