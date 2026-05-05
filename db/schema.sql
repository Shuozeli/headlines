-- headlines v1 — source-of-truth Postgres schema.
--
-- Hand-written DDL describing the complete current schema for headlines v1.
-- Tables are listed in dependency order so `psql -f db/schema.sql` succeeds
-- against a fresh, empty database.
--
-- Authoritative spec: docs/design/data-model.md (with cross-references to
-- docs/design/auth.md for tso_high_water and docs/design/events.md for events).
--
-- Conventions
--   - All ids are UUID (Postgres native), no slugs.
--   - All timestamps are timestamptz; created_at defaults to now().
--   - Composite primary keys on child tables to keep Spanner-portability open.
--   - Hard FKs only within an entity's tree; cross-tree refs are kept soft
--     (no FK) per docs/design/data-model.md "Cross-tree references".
--   - Status / type discriminators are text columns guarded by CHECK
--     constraints with the values listed in the corresponding doc.

-- =============================================================================
-- accounts (publisher identity)
-- =============================================================================

CREATE TABLE accounts (
    id          uuid PRIMARY KEY,
    short_name  text        NOT NULL,
    author_name text        NOT NULL,
    author_url  text,
    status      text        NOT NULL CHECK (status IN ('active', 'deleted')),
    deleted_at  timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

COMMENT ON COLUMN accounts.status     IS 'lifecycle: active | deleted (soft delete; rows retained)';
COMMENT ON COLUMN accounts.deleted_at IS 'set when status transitions to deleted';

CREATE TABLE account_keys (
    account_id uuid        NOT NULL REFERENCES accounts(id),
    key_id     uuid        NOT NULL,
    algo       text        NOT NULL,
    public_key text        NOT NULL,
    status     text        NOT NULL CHECK (status IN ('active', 'revoked')),
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    PRIMARY KEY (account_id, key_id)
);

COMMENT ON COLUMN account_keys.algo       IS 'signature algorithm identifier (e.g. ed25519)';
COMMENT ON COLUMN account_keys.public_key IS 'PEM or base64-encoded public key bytes';

-- =============================================================================
-- articles (identity + state split)
-- =============================================================================

CREATE TABLE articles (
    id         uuid PRIMARY KEY,
    account_id uuid        NOT NULL REFERENCES accounts(id),
    state      text        NOT NULL CHECK (state IN ('live', 'tombstone')),
    created_at timestamptz NOT NULL DEFAULT now()
);

COMMENT ON COLUMN articles.state IS 'live | tombstone — exactly one row in the matching child table';

CREATE INDEX articles_by_account_created
    ON articles (account_id, created_at DESC);

CREATE TABLE articles_live (
    article_id      uuid PRIMARY KEY REFERENCES articles(id),
    current_version integer     NOT NULL CHECK (current_version >= 1),
    published_at    timestamptz NOT NULL,
    updated_at      timestamptz NOT NULL
);

COMMENT ON COLUMN articles_live.current_version IS 'monotonic; always points at an existing article_versions row';

CREATE TABLE articles_tombstone (
    article_id    uuid PRIMARY KEY REFERENCES articles(id),
    reason        text,
    tombstoned_at timestamptz NOT NULL
);

CREATE TABLE article_versions (
    article_id       uuid        NOT NULL REFERENCES articles(id),
    version          integer     NOT NULL CHECK (version >= 1),
    title            text        NOT NULL,
    author_name      text,
    author_url       text,
    content          jsonb,
    redacted_at      timestamptz,
    redaction_reason text,
    created_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (article_id, version)
);

COMMENT ON COLUMN article_versions.content     IS 'Node-tree document; nullable when redacted for compliance';
COMMENT ON COLUMN article_versions.redacted_at IS 'set when content is nulled for compliance';

-- =============================================================================
-- drafts (mutable working space; same UUID is reused as articles.id on publish)
-- =============================================================================

CREATE TABLE drafts (
    id          uuid PRIMARY KEY,
    account_id  uuid        NOT NULL REFERENCES accounts(id),
    title       text        NOT NULL,
    author_name text,
    author_url  text,
    content     jsonb       NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

COMMENT ON COLUMN drafts.id IS 'becomes articles.id on publish (same UUID; never coexist)';

CREATE INDEX drafts_by_account
    ON drafts (account_id, created_at DESC);

-- =============================================================================
-- users (consumer identity)
-- =============================================================================

CREATE TABLE users (
    id           uuid PRIMARY KEY,
    display_name text,
    status       text        NOT NULL CHECK (status IN ('active', 'deleted')),
    deleted_at   timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE user_keys (
    user_id    uuid        NOT NULL REFERENCES users(id),
    key_id     uuid        NOT NULL,
    algo       text        NOT NULL,
    public_key text        NOT NULL,
    status     text        NOT NULL CHECK (status IN ('active', 'revoked')),
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    PRIMARY KEY (user_id, key_id)
);

-- =============================================================================
-- follows ((user, account) edge; soft-delete on unfollow)
-- =============================================================================

CREATE TABLE follows (
    user_id       uuid        NOT NULL REFERENCES users(id),
    account_id    uuid        NOT NULL REFERENCES accounts(id),
    status        text        NOT NULL CHECK (status IN ('active', 'unfollowed')),
    created_at    timestamptz NOT NULL DEFAULT now(),
    unfollowed_at timestamptz,
    PRIMARY KEY (user_id, account_id)
);

CREATE INDEX follows_by_account_active
    ON follows (account_id)
    WHERE status = 'active';

-- =============================================================================
-- feed_recommendation (ranker-pushed ordered list per user)
-- =============================================================================

CREATE TABLE feed_recommendation (
    user_id    uuid    NOT NULL REFERENCES users(id),
    position   integer NOT NULL,
    article_id uuid    NOT NULL,                          -- soft ref (no FK)
    PRIMARY KEY (user_id, position)
);

COMMENT ON COLUMN feed_recommendation.article_id
    IS 'soft reference to articles.id; no FK so ranker can push ahead and tombstones are filtered at read time';

-- =============================================================================
-- systems (elevated callers)
-- =============================================================================

CREATE TABLE systems (
    id          uuid PRIMARY KEY,
    name        text        NOT NULL UNIQUE,
    status      text        NOT NULL CHECK (status IN ('active', 'disabled')),
    created_at  timestamptz NOT NULL DEFAULT now(),
    disabled_at timestamptz
);

COMMENT ON COLUMN systems.name IS 'logical name (e.g. ranker, analytics, admin) — seeded at deploy';

CREATE TABLE system_scopes (
    system_id uuid NOT NULL REFERENCES systems(id),
    scope     text NOT NULL,
    PRIMARY KEY (system_id, scope)
);

COMMENT ON COLUMN system_scopes.scope IS 'dotted scope string (e.g. articles.write, admin.*) — wildcards matched at auth time';

CREATE TABLE system_keys (
    system_id  uuid        NOT NULL REFERENCES systems(id),
    key_id     uuid        NOT NULL,
    algo       text        NOT NULL,
    public_key text        NOT NULL,
    status     text        NOT NULL CHECK (status IN ('active', 'revoked')),
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    PRIMARY KEY (system_id, key_id)
);

-- =============================================================================
-- tso_high_water (singleton TSO persistence row)
-- =============================================================================

CREATE TABLE tso_high_water (
    id               text PRIMARY KEY DEFAULT 'singleton' CHECK (id = 'singleton'),
    last_physical_ms bigint      NOT NULL,
    updated_at       timestamptz NOT NULL DEFAULT now()
);

COMMENT ON COLUMN tso_high_water.last_physical_ms
    IS 'highest physical millisecond the in-process TSO has issued; flushed periodically, used at boot to wait out crash recovery';

-- =============================================================================
-- events (append-only behavioural events; soft refs on user_id / article_id)
-- =============================================================================

CREATE TABLE events (
    id          uuid PRIMARY KEY,
    user_id     uuid        NOT NULL,                  -- soft ref (no FK)
    article_id  uuid,                                   -- soft ref (no FK), nullable
    type        text        NOT NULL CHECK (type IN ('IMPRESSION', 'OPEN', 'DWELL', 'LIKE', 'UNLIKE', 'SHARE')),
    occurred_at timestamptz NOT NULL,
    received_at timestamptz NOT NULL,
    surface     text        NOT NULL,
    properties  jsonb       NOT NULL
);

COMMENT ON COLUMN events.user_id     IS 'soft reference to users.id; preserved for analytics even after user deletion';
COMMENT ON COLUMN events.article_id  IS 'soft reference to articles.id; nullable for non-article events';
COMMENT ON COLUMN events.occurred_at IS 'client-supplied; clamped to [now-24h, now+60s] at ingestion';
COMMENT ON COLUMN events.received_at IS 'server-assigned via TSO';

CREATE INDEX events_by_received_at      ON events (received_at);
CREATE INDEX events_by_user_received    ON events (user_id, received_at);
CREATE INDEX events_by_article_received ON events (article_id, received_at);
