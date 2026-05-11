# headlines demo

This directory ships a runnable demo of the `headlines` server.

```
docker compose up --build
```

After the postgres + headlines containers come up, the server runs
its boot-time auto-seed (gated on `HEADLINES_DEMO_SEED_ON_BOOT=1`)
and bootstraps a fully-populated instance:

- 5 publisher **accounts**: `techblog`, `worldnews`, `tutorials`, `opinion`, `videos`
- 7 reader **users**: `alice`, `bob`, `carol`, `dave`, `eve`, `frank`, `grace`
- 2 **systems**: `demo-ranker` (recommendation feeds + analytics scopes) and `demo-admin` (broad scope)
- ~140 articles spread over the past 14 days, including 2 tombstones and 1 redaction
- ~30 drafts (5-ish per account)
- A hardcoded follow graph
- Per-user recommendation feeds (~15 articles each), populated by `demo-ranker`
- ~3000 user activity events

## Endpoints

After `docker compose up`:

- gRPC: `localhost:50051`
- REST: `http://localhost:8080`
- Postgres: `localhost:5433` (mapped off the container's 5432 to avoid colliding with a host postgres)

## Demo keypairs

Ed25519 keypairs are committed in plaintext under `demo/keys/`:

```
keys/
├── system/   demo-ranker, demo-admin
├── account/  techblog, worldnews, tutorials, opinion, videos
└── user/     alice, bob, carol, dave, eve, frank, grace
```

Each identity has a `<name>.public` and `<name>.private` file containing
base64-encoded raw 32-byte Ed25519 key material.

> **DO NOT REUSE THESE KEYS FOR ANYTHING REAL.** They live in the public
> repository. They authenticate the demo flow only.

To regenerate any missing pairs (the canonical 14 identities listed
above):

```
headlines-server demo init-keys --path demo
```

## Try it

The simplest read paths are anonymous-readable. Once the seed completes:

```bash
# Get a copy-pasteable list of curls scoped to the seeded ids
headlines-server demo curl-examples --path demo

# Or directly: list techblog's articles (replace the UUID below with one
# from the seed-state.json or the curl-examples output)
curl http://localhost:8080/v1/accounts/<techblog-account-uuid>/articles
```

For signed requests (publishing, follows, events, etc.), you build an
`Authorization: Signature key_id=…, algo=ed25519, ts=…, nonce=…, sig=…`
header per the canonical form documented in `docs/design/auth.md`. The
private keys under `demo/keys/` are the signing material; the public
key id (`key_id`) for each demo identity is recorded in
`demo/seed-state.json` after the seed runs.

## Re-running the seed

The seed is idempotent: it consults `demo/seed-state.json` and the
`accounts` / `systems` tables before creating new rows, so re-runs after
a partial run pick up where they left off. To wipe demo data and start
fresh:

```bash
headlines-server demo seed --reset
```

## Source

- `articles/<account>/*.md`: the article markdown bodies. Frontmatter
  (`title`, `author_name`, `created_at`, `state`, …) is YAML.
- `drafts/<account>/*.md`: the draft markdown bodies (smaller / sketchier).
- `keys/<kind>/<name>.{public,private}`: keypairs.
- `seed-state.json`: gitignored — produced by the seed run; maps demo
  identity names back to the UUIDs the server actually assigned.
