# Auth

Status: agreed (v1)
Scope: authentication only — who is the caller. Authorization (what can the caller do) is declared per endpoint in each component's design doc. This doc fixes the wire shape, signing rules, time source, key lifecycle, and plug-in seams.

## Subjects

A request resolves to exactly one subject:

```rust
enum Subject {
    User      { user_id:    Uuid, key_id: Uuid },
    Account   { account_id: Uuid, key_id: Uuid },
    System    { system_id:  Uuid, key_id: Uuid, scopes: Vec<String> },
    Anonymous,
}
```

- `Anonymous` is allowed only on explicit allow-listed RPCs (registration, public reads).
- `System` is the elevated tier. Scope strings (dotted, e.g. `articles.write`, `feeds.write`, `admin.*`) gate which RPCs it may invoke. Accounts and Users have implicit self-scope only.
- A request signs with one key; the key table the `key_id` resolves in determines the subject class.

## Strategy plug-in

```rust
trait AuthStrategy: Send + Sync {
    async fn authenticate(&self, req: &SignedRequestParts) -> Result<Subject, AuthError>;
}
```

The auth pipeline holds an ordered registry of strategies; first success wins, otherwise `UNAUTHENTICATED`. Default registry: `[SignedRequestStrategy]`. Replacing the default (mTLS, OIDC, JWT, etc.) means swapping the registry — no other code changes.

## Default strategy: signed requests

### Wire format (per `api-conventions.md`)

```
Authorization: Signature key_id=<uuid>, algo=<algo>, ts=<u64>, nonce=<base64>, sig=<base64>
```

- gRPC: `authorization` metadata key.
- REST: `Authorization` header.
- `ts` is a TSO value (see *Time source* below), not a wall-clock unix second.

### Canonicalization

The signed string is independent of transport (gRPC binary or REST JSON):

```
HEADLINES-SIGN-V1
<HTTP method uppercase>            -- "POST"
<path>                             -- "/v1/articles/{id}/tombstone"  OR  "/headlines.v1.ArticleService/TombstoneArticle"
<canonical query string>           -- sorted "k1=v1&k2=v2", empty otherwise
<request_hash>                     -- see "Hashing strategy" below
<key_id>
<ts>
<nonce>
```

`signature = sign(private_key, sha256(canonical_string))`.

### Hashing strategy

**Default:** `request_hash = sha256_hex(canonical_proto_encode(request_message))`.

- `canonical_proto_encode` produces deterministic bytes (sorted fields, no unknown fields, no map-iteration nondeterminism). Same hash whether the wire was gRPC binary or REST JSON.
- Never hash raw HTTP/2 body or REST JSON bytes — encoding differences would break cross-surface signatures.

**Per-RPC override** via proto option:
- Streaming RPCs (none in v1) can sign initial-metadata only or hash a digest of a specific field.
- Large content fields (e.g. an article body) can declare a sub-field hash strategy if full re-encoding is expensive.
- Override mechanism (annotation name, registry shape) sketched in `architecture.md`; defaults are sufficient for v1 RPCs.

### Algorithms (pluggable)

```rust
trait SignatureAlgorithm: Send + Sync {
    fn name(&self) -> &'static str;       // "ed25519", "ecdsa-p256", "rsa-pss-2048"
    fn verify(&self, public_key: &[u8], canonical: &[u8], sig: &[u8]) -> Result<(), VerifyError>;
}
```

- Default registry: `Ed25519`. Optional: `EcdsaP256`, `RsaPss2048+`.
- A key's `algo` column must match the registered algorithm; mismatch → reject.
- Adding an algorithm = registering one more `SignatureAlgorithm` impl at startup.

## Time source

Clock skew is solved by a **central monotonic time source**, not by a wall-clock tolerance window. Inspired by TiDB PD's TSO:

- 64-bit timestamp: high bits = physical milliseconds, low 18 bits = logical counter.
- Monotonically increases across the cluster; never goes backwards across server restarts.
- Persisted high-water mark in Postgres; on boot, wait until wall clock exceeds persisted value before issuing new timestamps.

### Plug-in trait

```rust
trait TimeSource: Send + Sync {
    async fn now(&self) -> Result<Tso, TimeError>;
    async fn validate(&self, ts: Tso) -> Result<(), TimeError>;
}
```

### v1 deployment: in-process TSO

```rust
struct InProcessTso {
    last_physical_ms: AtomicU64,
    logical_counter:  AtomicU64,
    high_water_table: PostgresClient,    // periodic flush
}
```

- Single-node: TSO is a module inside the headlines server process. No standalone service.
- Server exposes a public RPC `GetTime` (anonymous-allowed) so clients can fetch a fresh TSO before signing.
- Persists high-water mark every N ms (configurable). On crash recovery, waits for wall clock to advance past persisted value.

Multi-node deployment (out of scope for v1): replace `InProcessTso` with a Raft-backed implementation or a remote TSO client; nothing else changes.

### Auth flow with TSO

1. Client calls `GetTime` (anonymous), receives `tso_now`.
2. Client signs request with `ts = tso_now` (or a value within the horizon).
3. Server `time_source.validate(ts)` checks:
   - `ts <= time_source.now()` (no future-dated requests, modulo a small forward slack for in-flight latency).
   - `time_source.now() - ts <= horizon` (replay horizon, default **30 seconds**).
4. Outside horizon → `UNAUTHENTICATED`.

## Replay protection

- `(key_id, nonce)` recorded in an in-process LRU for the horizon window.
- Duplicate within the window → reject.
- Window is 30s in TSO time; LRU sized to `horizon × peak_qps × headroom`.
- Distributed replay store (Redis or table) deferred — single-instance v1.

Nonce: at least 16 random bytes, base64-encoded.

## Key registration & rotation

| Operation | RPC | Auth | Notes |
|---|---|---|---|
| First user key | `CreateUser` | Anonymous *or* `System.users.write` | Mode picked by config. |
| First account key | `CreateAccount` | Anonymous *or* `System.accounts.write` | Mode picked by config. |
| First system key | DB seed | Out-of-band | No public RPC; ops-only bootstrap. |
| Add user key | `AddUserKey` | `User` (self) with an existing active key | Returns new `key_id`. |
| Add account key | `AddAccountKey` | `Account` (self) | |
| Add system key | `AddSystemKey` | `System.admin.*` | |
| Revoke key | `RevokeKey` | Owner subject | Flips status to `revoked`, sets `revoked_at`. |

- Multiple active keys per parent are allowed.
- No protocol-level grace period; rotation is "add new, then revoke old when ready".
- Revoked keys reject immediately on the next request.

## Bootstrap modes (config)

```toml
[auth.bootstrap]
user_registration    = "open"         # or "system_only"
account_registration = "system_only"  # or "open"

[auth.time]
source           = "in_process_tso"   # or "remote_tso", "local_clock" (dev only)
horizon_seconds  = 30

[auth.algorithms]
enabled = ["ed25519"]                 # add "ecdsa-p256", "rsa-pss-2048" as needed

[auth.signing]
hash_default = "canonical_proto_sha256"
```

## System identities & scopes

- One `systems` row per logical caller (`ranker`, `analytics`, `admin`).
- Scopes are **dotted strings**: `articles.write`, `feeds.write`, `users.read`, `admin.*`.
- Wildcard suffix `.*` matches any scope under that prefix; `*` alone matches everything.
- Authorization for elevated operations is the union: an endpoint requires *either* a matching account/user self-scope *or* a System with the required scope. Audit log records the actual subject (System acts as itself; never impersonates).
- First system identity (seeded at deploy) gets scope `*`. Operators carve narrower scopes for application callers like the ranker.

Suggested initial scope vocabulary:

```
accounts.read         accounts.write       accounts.admin       accounts.delete
articles.read         articles.write       articles.tombstone   articles.redact      articles.stream
drafts.read           drafts.write
users.read            users.write          users.admin          users.delete
follows.read          follows.write
feeds.recommendation.read   feeds.recommendation.write
feeds.follow.read
events.write          events.read
notifications.send    notifications.read    notifications.admin
admin.*
```

Scope semantics (recurring pattern across resources):
- `<resource>.read` / `<resource>.write` — basic operations on the resource.
- `<resource>.write` is for **bootstrap / create-on-behalf** flows when public registration is gated.
- `<resource>.admin` — cross-tenant modification of existing rows (escalated; rare).
- `<resource>.delete` — soft-delete cross-tenant.
- `admin.*` is the operator-rescue scope; matches anything under `admin.` and is used as the lockout-override in component docs.

## Anonymous-allowed RPCs (v1)

- `GetTime` (TSO fetch).
- `GetArticle`, `ListAccountArticles`, `GetAccount` — public reads.
- `CreateUser`, `CreateAccount` — only if config sets corresponding `*_registration = "open"`.
- All other RPCs require a non-`Anonymous` subject.

Per-article visibility flag (private/public switch) is deferred. v1: all live articles publicly readable.

## Out of scope

- Authorization rules per endpoint → each component doc.
- mTLS, OIDC, JWT alternative strategies (slot reserved via plug-in trait).
- Distributed nonce store, multi-leader TSO.
- Per-tenant rate limiting and abuse handling.

## Cross-references

- Wire format: `docs/design/api-conventions.md`.
- `system_*` and key tables: `docs/design/data-model.md`.
- TSO module placement, hashing-strategy registry: `docs/design/architecture.md`.
