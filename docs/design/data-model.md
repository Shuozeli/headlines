# Data Model

Status: agreed (v1)
Scope: Postgres schema for headlines v1. Defines tables, columns, indexes, and lifecycle invariants. Does **not** cover API routes, auth signing, event payloads, or Rust types — those live in their own design docs.

## Targets

- Postgres for v1.
- Schema written so it ports to Spanner without restructuring (composite PKs, no DB-specific features in core layout, soft references where Spanner can't enforce cross-tree FKs).
- ClickHouse later for analytics on top of `events`; not in this doc.

## Entities

```
accounts        -- publisher identity (long-lived)
  account_keys  -- signing keys (key_id is the handle, no version field)

articles        -- key-only identity (immutable id)
  articles_live       -- live state (1:1 with articles where state='live')
  articles_tombstone  -- tombstone placeholder (1:1 with articles where state='tombstone')
  article_versions    -- immutable edit history per article

drafts          -- separate working space; not in articles until published

users           -- consumer identity
  user_keys     -- signing keys

follows         -- (user, account) edge

feed_recommendation  -- ranker-pushed ordered list per user

systems         -- elevated callers (ranker, analytics, admin)
  system_scopes -- dotted-string scopes per system
  system_keys   -- signing keys

tso_high_water  -- monotonic time source persistence (single row)

events          -- DEFERRED — schema in docs/design/events.md
```

## Identity rules

- All ids are UUID, globally unique.
- `articles.id` is the public reference. `GET /articles/{id}` resolves without account context.
- **Draft id continuity**: the UUID minted for a draft becomes `articles.id` on publish. The same UUID is never present in `drafts` and `articles` simultaneously (publish deletes the draft row in the same tx that inserts the article rows).
- `current_version` is a monotonic int per article, starting at 1, incremented on every edit after publish.
- `key_id` (UUID) is the public handle for a signing key. There is no `version` integer on keys; multiple active keys per parent are allowed.
- No human-readable slugs. Article URLs use the `articles.id` UUIDv7 directly; tombstoned articles resolve at the same URL since the id never changes.

## Schema

### accounts

```sql
accounts
  id              uuid PRIMARY KEY
  short_name      text NOT NULL
  author_name     text NOT NULL
  author_url      text
  status          text NOT NULL              -- 'active' | 'deleted'
  deleted_at      timestamptz
  created_at      timestamptz NOT NULL
  updated_at      timestamptz NOT NULL

account_keys
  account_id      uuid NOT NULL REFERENCES accounts(id)
  key_id          uuid NOT NULL
  algo            text NOT NULL              -- 'ed25519'
  public_key      text NOT NULL              -- pem or base64
  status          text NOT NULL              -- 'active' | 'revoked'
  created_at      timestamptz NOT NULL
  revoked_at      timestamptz
  PRIMARY KEY (account_id, key_id)
```

Notes:
- Account `status='deleted'` + `deleted_at` is set when the account is marked deleted; rows remain.
- Account deletion does **not** cascade to articles. Articles persist; tombstoning is independent.

### articles (identity + state split)

```sql
articles
  id              uuid PRIMARY KEY
  account_id      uuid NOT NULL REFERENCES accounts(id)
  state           text NOT NULL              -- 'live' | 'tombstone'
  created_at      timestamptz NOT NULL

CREATE INDEX articles_by_account_created
  ON articles (account_id, created_at DESC);

articles_live
  article_id      uuid PRIMARY KEY REFERENCES articles(id)
  current_version int NOT NULL
  published_at    timestamptz NOT NULL
  updated_at      timestamptz NOT NULL

articles_tombstone
  article_id      uuid PRIMARY KEY REFERENCES articles(id)
  reason          text
  tombstoned_at   timestamptz NOT NULL

article_versions
  article_id      uuid NOT NULL REFERENCES articles(id)
  version         int NOT NULL               -- 1, 2, 3, ...
  title           text NOT NULL
  author_name     text
  author_url      text
  content         jsonb                      -- nullable: redacted for compliance
  redacted_at     timestamptz
  redaction_reason text
  created_at      timestamptz NOT NULL
  PRIMARY KEY (article_id, version)
```

Invariants:
- `articles.state='live'` → exactly one row in `articles_live`, none in `articles_tombstone`.
- `articles.state='tombstone'` → exactly one row in `articles_tombstone`, none in `articles_live`.
- `articles_live.current_version` always points at an existing `article_versions` row for that article.
- `article_versions` is append-only. Edit creates a new version; existing rows are never mutated except for compliance redaction.

### drafts

```sql
drafts
  id              uuid PRIMARY KEY
  account_id      uuid NOT NULL REFERENCES accounts(id)
  title           text NOT NULL
  author_name     text
  author_url      text
  content         jsonb NOT NULL
  created_at      timestamptz NOT NULL
  updated_at      timestamptz NOT NULL

CREATE INDEX drafts_by_account
  ON drafts (account_id, created_at DESC);
```

- Drafts are mutable in place (no version table).
- Draft delete is **hard delete**, not tombstoned (drafts were never public).
- Draft `id` is the UUID that will become `articles.id` if/when published.

### users

```sql
users
  id              uuid PRIMARY KEY
  display_name    text
  status          text NOT NULL              -- 'active' | 'deleted'
  deleted_at      timestamptz
  created_at      timestamptz NOT NULL

user_keys
  user_id         uuid NOT NULL REFERENCES users(id)
  key_id          uuid NOT NULL
  algo            text NOT NULL
  public_key      text NOT NULL
  status          text NOT NULL              -- 'active' | 'revoked'
  created_at      timestamptz NOT NULL
  revoked_at      timestamptz
  PRIMARY KEY (user_id, key_id)
```

### follows

```sql
follows
  user_id         uuid NOT NULL REFERENCES users(id)
  account_id      uuid NOT NULL REFERENCES accounts(id)
  status          text NOT NULL              -- 'active' | 'unfollowed'
  created_at      timestamptz NOT NULL
  unfollowed_at   timestamptz
  PRIMARY KEY (user_id, account_id)

CREATE INDEX follows_by_account_active
  ON follows (account_id)
  WHERE status = 'active';
```

- Soft-deleted on unfollow (preserves history; cheap to re-follow).

### systems (elevated callers)

```sql
systems
  id              uuid PRIMARY KEY
  name            text NOT NULL UNIQUE       -- 'ranker', 'analytics', 'admin'
  status          text NOT NULL              -- 'active' | 'disabled'
  created_at      timestamptz NOT NULL
  disabled_at     timestamptz

system_scopes
  system_id       uuid NOT NULL REFERENCES systems(id)
  scope           text NOT NULL              -- dotted: 'articles.write', 'admin.*'
  PRIMARY KEY (system_id, scope)

system_keys
  system_id       uuid NOT NULL REFERENCES systems(id)
  key_id          uuid NOT NULL
  algo            text NOT NULL
  public_key      text NOT NULL
  status          text NOT NULL              -- 'active' | 'revoked'
  created_at      timestamptz NOT NULL
  revoked_at      timestamptz
  PRIMARY KEY (system_id, key_id)
```

- System identities are seeded out-of-band (DB seed at deploy time). No public registration RPC.
- Wildcard scopes (`admin.*`, `*`) are matched at authorization time; storage is plain strings.
- An "acts-as-itself" model: when a System creates an article, the audit trail records the system identity, not the account.

### tso_high_water

```sql
tso_high_water
  id              text PRIMARY KEY DEFAULT 'singleton' CHECK (id = 'singleton')
  last_physical_ms bigint NOT NULL
  updated_at      timestamptz NOT NULL
```

- Single-row table holding the highest physical timestamp the in-process TSO has issued.
- Flushed periodically by the TSO module; on boot the server waits for wall clock to exceed `last_physical_ms` before issuing new timestamps.
- Replaces wall-clock + tolerance for auth replay protection. See `docs/design/auth.md`.

### feed_recommendation

```sql
feed_recommendation
  user_id         uuid NOT NULL REFERENCES users(id)
  position        int NOT NULL
  article_id      uuid NOT NULL              -- soft ref to articles.id
  PRIMARY KEY (user_id, position)
```

- `article_id` is a soft reference (no FK). Ranker may push references to articles; reads filter out tombstoned/missing articles at serve time.
- Replace semantics: `PUT` deletes all rows for the user and inserts the new ordered list, atomically in a single tx.

### events

```sql
events
  id            uuid PRIMARY KEY
  user_id       uuid NOT NULL                  -- soft ref (no FK)
  article_id    uuid                            -- soft ref, nullable
  type          text NOT NULL                  -- 'IMPRESSION' | 'OPEN' | 'DWELL' | 'LIKE' | 'UNLIKE' | 'SHARE'
  occurred_at   timestamptz NOT NULL           -- client-supplied, clamped to [now-24h, now+60s]
  received_at   timestamptz NOT NULL           -- server-assigned (TSO)
  surface       text NOT NULL                  -- 'web', 'mobile', etc.
  properties    jsonb NOT NULL                 -- typed payload (see events.md)

CREATE INDEX events_by_received_at      ON events (received_at);
CREATE INDEX events_by_user_received    ON events (user_id, received_at);
CREATE INDEX events_by_article_received ON events (article_id, received_at);
```

- Append-only. No update / delete via API.
- Soft references (no FK): events for deleted users or tombstoned articles are recorded normally — analytics keeps the trail.
- Counts and views derive from this table via background jobs; ClickHouse rollup later.

## Article lifecycle

```
   create draft
        |
        v
     drafts (mutable)
        |
        | publish (same UUID)
        v
   tx: delete drafts row
       insert articles (state='live')
       insert articles_live (current_version=1)
       insert article_versions (version=1)
        |
        | edit
        v
   tx: insert article_versions (version=N+1)
       update articles_live (current_version=N+1, updated_at)
        |
        | tombstone
        v
   tx: update articles (state='tombstone')
       insert articles_tombstone (slug copied from articles_live)
       delete articles_live
   article_versions retained.

   Compliance redaction (any version):
   update article_versions
     set content=null, redacted_at=now(), redaction_reason=...
```

## Cross-tree references

| From → To | Enforcement | Reason |
|---|---|---|
| `articles.account_id` → `accounts.id` | FK | same tree |
| `article_versions.article_id` → `articles.id` | FK | same tree |
| `articles_live.article_id` → `articles.id` | FK | same tree |
| `articles_tombstone.article_id` → `articles.id` | FK | same tree |
| `drafts.account_id` → `accounts.id` | FK | same tree |
| `follows.user_id` → `users.id` | FK | same tree |
| `follows.account_id` → `accounts.id` | FK | acceptable — Postgres can enforce |
| `feed_recommendation.user_id` → `users.id` | FK | same tree |
| `feed_recommendation.article_id` → `articles.id` | **soft (no FK)** | cross-tree; Spanner-portable; ranker can push ahead |
| `system_scopes.system_id` → `systems.id` | FK | same tree |
| `system_keys.system_id` → `systems.id` | FK | same tree |

## Spanner portability notes

- Composite PKs on child tables (parent_id, child_id) — drop-in for `INTERLEAVE IN PARENT`.
- Cross-tree references kept soft (no FK) to match Spanner constraint.
- No Postgres-specific types in core columns; `jsonb` maps to Spanner `JSON`.
- Partial indexes (e.g. `follows_by_account_active`) need rewrite on Spanner — track in migration plan.

## Open items deferred to other docs

- Auth: signing details, request canonicalization, replay protection — `docs/design/auth.md`
- API routes, error format, pagination cursors — `docs/design/api-conventions.md`
- Event payload + ingestion shape — `docs/design/events.md`
- Notification payload — `docs/design/notifications.md`
- Module layout, Rust crate selection — `docs/design/architecture.md`
