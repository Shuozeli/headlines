# DraftService

Status: agreed (v1)
Scope: per-account working space for articles. Drafts are mutable, private to the owning account, and convert to articles via `PublishDraft` (preserving UUID). Wire shape: `api-conventions.md`. Auth: `auth.md`. Schema: `data-model.md`. Article surface: `articles.md`.

## Messages

```proto
message Draft {
  string id = 1;                        // UUIDv7; becomes articles.id on publish
  string account_id = 2;
  string title = 3;
  string author_name = 4;
  string author_url = 5;
  repeated Node content = 6;            // Node from articles.md
  google.protobuf.Timestamp created_at = 7;
  google.protobuf.Timestamp updated_at = 8;
}

message DraftSummary {
  string id = 1;
  string account_id = 2;
  string title = 3;
  google.protobuf.Timestamp created_at = 4;
  google.protobuf.Timestamp updated_at = 5;
}
```

## Service

```proto
service DraftService {
  rpc CreateDraft(CreateDraftRequest) returns (Draft) {
    option (google.api.http) = {
      post: "/v1/accounts/{account_id}/drafts"
      body: "*"
    };
  }
  rpc GetDraft(GetDraftRequest) returns (Draft) {
    option (google.api.http) = { get: "/v1/drafts/{id}" };
  }
  rpc UpdateDraft(UpdateDraftRequest) returns (Draft) {
    option (google.api.http) = {
      patch: "/v1/drafts/{draft.id}"
      body: "*"
    };
  }
  rpc DeleteDraft(DeleteDraftRequest) returns (google.protobuf.Empty) {
    option (google.api.http) = { delete: "/v1/drafts/{id}" };
  }
  rpc ListAccountDrafts(ListAccountDraftsRequest) returns (ListAccountDraftsResponse) {
    option (google.api.http) = { get: "/v1/accounts/{account_id}/drafts" };
  }
  rpc PublishDraft(PublishDraftRequest) returns (Article) {
    option (google.api.http) = {
      post: "/v1/drafts/{id}/publish"
      body: "*"
    };
  }
}

message CreateDraftRequest {
  string account_id = 1;
  string title = 2;
  string author_name = 3;
  string author_url = 4;
  repeated Node content = 5;
}

message GetDraftRequest { string id = 1; }

message UpdateDraftRequest {
  Draft draft = 1;
  google.protobuf.FieldMask update_mask = 2;
}

message DeleteDraftRequest { string id = 1; }

message ListAccountDraftsRequest {
  string account_id = 1;
  int32 page_size = 2;
  string page_token = 3;
}
message ListAccountDraftsResponse {
  repeated DraftSummary items = 1;
  string next_page_token = 2;
}

message PublishDraftRequest { string id = 1; }
```

## Authorization

| RPC | Allowed subject |
|---|---|
| `CreateDraft` | `Account` whose `account_id == request.account_id` **or** `System` with scope `drafts.write` |
| `GetDraft` | `Account` who owns the draft **or** `System` with scope `drafts.read` |
| `UpdateDraft` | `Account` who owns the draft **or** `System` with scope `drafts.write` |
| `DeleteDraft` | `Account` who owns the draft **or** `System` with scope `drafts.write` |
| `ListAccountDrafts` | `Account` whose `account_id == request.account_id` **or** `System` with scope `drafts.read` |
| `PublishDraft` | `Account` who owns the draft **or** `System` with scope `articles.write` |

No anonymous reads — drafts are private working space. Unauthorized callers receive `DRAFT_NOT_FOUND` (not `PERMISSION_DENIED`) to avoid existence leaks.

## Validation (strict on every write)

Drafts are always required to be valid articles in our system. The same rules from `articles.md` apply on `CreateDraft` and `UpdateDraft`. Iteration happens by mutating an already-valid draft, not by storing partial state.

| Field | Rule |
|---|---|
| `title` | 1–256 chars, trimmed (non-empty) |
| `author_name` | empty or ≤128 chars |
| `author_url` | empty or valid `http(s)://` URL, ≤512 chars |
| `content` | non-empty; serialized size ≤ `articles.content_max_bytes` (default 20 MiB) |
| Node `tag` | from the Telegraph allow-list (see `articles.md`) |
| Node `attrs` | per-tag allow-list (see `articles.md`) |
| `update_mask` paths | only `title`, `author_name`, `author_url`, `content` |

`PublishDraft` re-checks the strict rules at publish time (cheap, since the draft is already valid) and additionally requires the owning account to be `status='active'`.

## Behaviors

### Create

- Mints UUIDv7 for `drafts.id`. Caller cannot specify the id.
- Validates strictly; rejects on any failure.
- Inserts the row; returns the full `Draft`.
- Owning account must exist and be `status='active'`. Otherwise `ACCOUNT_NOT_FOUND` / `ACCOUNT_DELETED`.

### Update

- Mutates the row in place — no version history (drafts are deliberately mutable working state).
- For each masked field, applies the new value to the existing row. Empty `update_mask` → `INVALID_ARGUMENT`.
- Re-validates the resulting record strictly. Failure → reject; row remains as it was.
- Sets `updated_at = now()`.

### Delete

- **Hard delete** — drafts were never public; no tombstone.
- Returns `google.protobuf.Empty`. Missing draft → `DRAFT_NOT_FOUND`.

### List

- Default order: **`updated_at DESC`** — most recently edited first, matches working-state UX.
- Cursor encodes `(updated_at, id)`.
- Returns `DraftSummary` (no content nodes).
- No filter parameters in v1.

### Publish (atomic tx)

```
BEGIN
  SELECT * FROM drafts WHERE id = $1 FOR UPDATE        -- serialize concurrent publishes
  -- re-validate strict article rules
  -- assert owning account.status='active'
  INSERT INTO articles          (id=$1, account_id, state='live', created_at=now);
  INSERT INTO articles_live     (article_id=$1, current_version=1, published_at=now, updated_at=now);
  INSERT INTO article_versions  (article_id=$1, version=1, title, author_name, author_url, content, created_at=now);
  DELETE FROM drafts WHERE id = $1;
COMMIT
```

- Returns the new `Article` with `state = LIVE`.
- Concurrent publishes on the same draft serialize via `FOR UPDATE`; the loser sees `DRAFT_NOT_FOUND`.
- After publish, `GetDraft(id)` → `DRAFT_NOT_FOUND`; `GetArticle(id)` → the new live article. UUID continuity preserved.

### Lifecycle policies (v1)

- **No per-account draft cap** in v1.
- **No auto-purge** of old drafts; they live until the owning account explicitly deletes or publishes them.

## Errors

| Reason | Code | When |
|---|---|---|
| `DRAFT_NOT_FOUND` | `NOT_FOUND` | id does not exist; or unauthorized non-owner caller |
| `ACCOUNT_NOT_FOUND` | `NOT_FOUND` | create references missing account |
| `ACCOUNT_DELETED` | `FAILED_PRECONDITION` | create or publish on a deleted account |
| `CONTENT_TOO_LARGE` | `RESOURCE_EXHAUSTED` | content exceeds cap |
| `INVALID_NODE_TAG` | `INVALID_ARGUMENT` | tag outside allow-list |
| `INVALID_NODE_ATTR` | `INVALID_ARGUMENT` | attr outside per-tag allow-list |
| `EMPTY_UPDATE_MASK` | `INVALID_ARGUMENT` | update with no mask paths |
| `UNALLOWED_MASK_PATH` | `INVALID_ARGUMENT` | mask path outside whitelist |
| `INVALID_ARGUMENT` | `INVALID_ARGUMENT` | other validation failures |

## Cross-references

- Schema: `data-model.md` — `drafts`, `articles`, `articles_live`, `article_versions`.
- Article shape, `Node` type, validation rules, content cap: `articles.md`.
- Auth scopes: `auth.md` — `drafts.read`, `drafts.write`; `articles.write` for `PublishDraft`.
- Wire envelope, AIP pagination: `api-conventions.md`.
- Account ownership: `accounts.md`.
