# ArticleService

Status: agreed (v1)
Scope: live & tombstoned articles, edits, version history, redaction. Drafts are a separate working space defined in `drafts.md`. Wire shape: `api-conventions.md`. Auth: `auth.md`. Schema: `data-model.md`.

## Telegraph Node payload

Recursive proto message for the article body:

```proto
message Node {
  oneof kind {
    string text = 1;
    NodeElement element = 2;
  }
}
message NodeElement {
  string tag = 1;
  map<string, string> attrs = 2;
  repeated Node children = 3;
}
```

Article content = `repeated Node`.

## Messages

```proto
message Article {
  string id = 1;                        // UUIDv7; also used as the public URL identifier
  string account_id = 2;
  ArticleState state = 3;
  google.protobuf.Timestamp created_at = 4;
  oneof state_data {
    ArticleLive live = 5;
    ArticleTombstone tombstone = 6;
  }
}

enum ArticleState {
  ARTICLE_STATE_UNSPECIFIED = 0;
  ARTICLE_STATE_LIVE = 1;
  ARTICLE_STATE_TOMBSTONE = 2;
}

message ArticleLive {
  int32 current_version = 1;
  string title = 2;
  string author_name = 3;
  string author_url = 4;
  repeated Node content = 5;            // empty when current version is redacted
  bool redacted = 6;                    // true when current version content is redacted
  google.protobuf.Timestamp published_at = 7;
  google.protobuf.Timestamp updated_at = 8;
}

message ArticleTombstone {
  string reason = 1;
  google.protobuf.Timestamp tombstoned_at = 2;
}

message ArticleEdit {
  string title = 1;
  string author_name = 2;
  string author_url = 3;
  repeated Node content = 4;
}

// Compact view for list endpoints. Identical structure to Article minus the
// content nodes. Used wherever a list of articles is returned (List endpoints,
// feed reads, account stream).
message ArticleSummary {
  string id = 1;
  string account_id = 2;
  ArticleState state = 3;
  google.protobuf.Timestamp created_at = 4;
  oneof state_data {
    ArticleLiveSummary live = 5;
    ArticleTombstoneSummary tombstone = 6;
  }
}

message ArticleLiveSummary {
  int32 current_version = 1;
  string title = 2;
  string author_name = 3;
  string author_url = 4;
  bool redacted = 5;                    // current version content is redacted
  google.protobuf.Timestamp published_at = 6;
  google.protobuf.Timestamp updated_at = 7;
}

message ArticleTombstoneSummary {
  string reason = 1;
  google.protobuf.Timestamp tombstoned_at = 2;
}
```

**List vs. view:** list/feed endpoints return `ArticleSummary` (no content nodes). Clients call `GetArticle` for the full `Article` with content when they need to render. This keeps list responses small.

No `slug` field. The URL identifier is the article's UUIDv7 (`article.id`); there is no separate human-readable slug.

## Service

```proto
service ArticleService {
  rpc PublishArticle(PublishArticleRequest) returns (Article) {
    option (google.api.http) = {
      post: "/v1/accounts/{account_id}/articles"
      body: "*"
    };
  }
  rpc GetArticle(GetArticleRequest) returns (Article) {
    option (google.api.http) = { get: "/v1/articles/{id}" };
  }
  rpc ListAccountArticles(ListAccountArticlesRequest) returns (ListAccountArticlesResponse) {
    option (google.api.http) = { get: "/v1/accounts/{account_id}/articles" };
  }
  rpc EditArticle(EditArticleRequest) returns (Article) {
    option (google.api.http) = {
      patch: "/v1/articles/{id}"
      body: "*"
    };
  }
  rpc TombstoneArticle(TombstoneArticleRequest) returns (Article) {
    option (google.api.http) = {
      post: "/v1/articles/{id}/tombstone"
      body: "*"
    };
  }
  rpc RedactArticleVersion(RedactArticleVersionRequest) returns (google.protobuf.Empty) {
    option (google.api.http) = {
      post: "/v1/articles/{article_id}/versions/{version}/redact"
      body: "*"
    };
  }
}

message PublishArticleRequest {
  string account_id = 1;
  string title = 2;
  string author_name = 3;
  string author_url = 4;
  repeated Node content = 5;
}

message GetArticleRequest { string id = 1; }

message ListAccountArticlesRequest {
  string account_id = 1;
  int32 page_size = 2;
  string page_token = 3;
  bool include_tombstoned = 4;        // default false
}
message ListAccountArticlesResponse {
  repeated ArticleSummary items = 1;  // no content nodes; clients call GetArticle for full body
  string next_page_token = 2;
}

message EditArticleRequest {
  string id = 1;
  ArticleEdit edit = 2;
  google.protobuf.FieldMask update_mask = 3;
}

message TombstoneArticleRequest {
  string id = 1;
  string reason = 2;                  // optional, ≤512 chars
}

message RedactArticleVersionRequest {
  string article_id = 1;
  int32 version = 2;
  string redaction_reason = 3;        // required, ≤512 chars
}
```

Article creation paths:
- **Direct**: `PublishArticle` — one-shot create with full content.
- **Via draft**: `PublishDraft` (in `drafts.md`) — uses the draft's UUID as the new article's id.

Both produce identical rows in `articles` + `articles_live` + `article_versions` (version 1).

Version history is **not exposed** in v1. No `GetArticleVersion` / `ListArticleVersions` RPCs. Operators with DB access discover version numbers when targeting `RedactArticleVersion`.

## Authorization

| RPC | Allowed subject |
|---|---|
| `PublishArticle` | `Account` whose id == `request.account_id` **or** `System` with scope `articles.write` |
| `GetArticle` | `Anonymous` (always) |
| `ListAccountArticles` | `Anonymous` (always) |
| `EditArticle` | `Account` who owns the article (`articles.account_id == subject.account_id`) **or** `System` with scope `articles.write` |
| `TombstoneArticle` | `Account` who owns the article **or** `System` with scope `articles.tombstone` |
| `RedactArticleVersion` | `System` with scope `articles.redact` only — no account self-redaction (compliance owner makes the call) |

`include_tombstoned=true` on `ListAccountArticles` is allowed for any subject; tombstones are public reads.

Cross-account `EditArticle` / `TombstoneArticle` returns `PERMISSION_DENIED` (not `NOT_FOUND`) because article existence is already public via anonymous `GetArticle`. Privacy-style `NOT_FOUND` carve-outs are reserved for resources whose existence is non-public (see `users.md`).

## Identity

- `article.id`: UUIDv7. Server-generated.
- Public URL identifier is `article.id` directly. No slug.

## Validation

| Field | Rule |
|---|---|
| `title` | 1–256 **chars** (Unicode), trimmed |
| `author_name` | empty or ≤128 **chars** (Unicode) |
| `author_url` | empty or valid `http(s)://` URL, ≤512 **bytes** (URL is opaque) |
| `content` | non-empty; serialized size ≤ `articles.content_max_bytes` (default **20 MB**, configurable) |
| Node `tag` | allow-list: `p`, `h3`, `h4`, `a`, `img`, `figure`, `figcaption`, `blockquote`, `aside`, `pre`, `code`, `em`, `strong`, `s`, `u`, `iframe`, `video`, `br`, `hr`, `ul`, `ol`, `li` |
| Node `attrs` | per-tag allow-list: `a` → `href`; `img`, `iframe`, `video` → `src`; `img` → `alt` (others rejected with `INVALID_NODE_ATTR`) |
| `update_mask` paths | only `title`, `author_name`, `author_url`, `content` |
| `redaction_reason` | 1–512 **bytes** (operator/system note, not user-facing) |
| `tombstone reason` | empty or ≤512 **bytes** (operator/system note, not user-facing) |

Configuration block (deployment-level):

```toml
[articles]
content_max_bytes = 20971520    # 20 MiB default; raise/lower per environment
```

## Behaviors

### Publish (direct)

`PublishArticle` runs as a single tx:
1. Verify `account_id` exists, status='active'.
2. Mint UUIDv7 for `articles.id`.
3. Insert `articles (id, account_id, state='live', created_at)`.
4. Insert `articles_live (article_id, current_version=1, published_at, updated_at)`.
5. Insert `article_versions (article_id, version=1, title, author_name, author_url, content, created_at)`.

Returns the new `Article` with `state=LIVE`.

### Edit

`EditArticle`:
- Validates article exists and `state=LIVE`. Tombstoned → `FAILED_PRECONDITION` `ARTICLE_TOMBSTONED`.
- Authorization: account owns article, or System with `articles.write`.
- For each masked field, apply to a copy of the live record.
- Single tx: insert `article_versions (version = current_version + 1, ...)`, bump `articles_live.current_version`, set `articles_live.updated_at = now()`. The fields stored on the new version row are the full new title/author/content (immutable snapshot, not a diff).

Empty `update_mask` → `INVALID_ARGUMENT`. Mask paths outside the whitelist → `INVALID_ARGUMENT`.

### Tombstone

`TombstoneArticle`:
- Validates article exists and `state=LIVE`. Already tombstoned → `FAILED_PRECONDITION` `ARTICLE_TOMBSTONED`.
- Single tx: update `articles.state='tombstone'`, insert `articles_tombstone (article_id, reason, tombstoned_at=now())`, delete `articles_live` row.
- `article_versions` retained.

One-way; no `UntombstoneArticle` in v1.

### Redact a version

`RedactArticleVersion`:
- Validates article exists, version exists, version not already redacted.
- Single tx: update `article_versions` set `content = NULL, redacted_at = now(), redaction_reason = ?`. **If the redacted version equals `articles_live.current_version`**, also bump `articles_live.updated_at = now()` in the same tx — this surfaces the redaction as an event in `account-stream.md`'s watermark feed so downstream republishers can update their mirrors.
- If the redacted version was the current version of a live article, subsequent `GetArticle` returns `ArticleLive.content = []` and `ArticleLive.redacted = true`. URL still resolves.
- Irreversible. No un-redact.

### Get / List

- `GetArticle` of a live article: returns `Article.live`. If `current_version` is redacted: `live.content = []`, `live.redacted = true`.
- `GetArticle` of a tombstoned article: returns `Article.tombstone`. HTTP 200, never 410.
- `ListAccountArticles` order: `created_at DESC`. Default excludes tombstones; `include_tombstoned=true` includes them in the same order.
- Pagination cursor encodes `(created_at, id)` (per `api-conventions.md`).

## Errors

| Reason | Code | When |
|---|---|---|
| `ARTICLE_NOT_FOUND` | `NOT_FOUND` | id does not exist |
| `ARTICLE_TOMBSTONED` | `FAILED_PRECONDITION` | edit/tombstone on a tombstoned article |
| `ACCOUNT_NOT_FOUND` | `NOT_FOUND` | publish references a missing account |
| `ACCOUNT_DELETED` | `FAILED_PRECONDITION` | publish references a deleted account |
| `INVALID_ARGUMENT` | `INVALID_ARGUMENT` | validation failure |
| `INVALID_NODE_TAG` | `INVALID_ARGUMENT` | tag outside allow-list |
| `INVALID_NODE_ATTR` | `INVALID_ARGUMENT` | attr outside per-tag allow-list |
| `CONTENT_TOO_LARGE` | `RESOURCE_EXHAUSTED` | serialized content > `articles.content_max_bytes` |
| `VERSION_NOT_FOUND` | `NOT_FOUND` | redact targets nonexistent version |
| `VERSION_ALREADY_REDACTED` | `ALREADY_EXISTS` | version already redacted |
| `EMPTY_UPDATE_MASK` | `INVALID_ARGUMENT` | edit with no mask paths |
| `UNALLOWED_MASK_PATH` | `INVALID_ARGUMENT` | mask path outside whitelist |

## Cross-references

- Schema: `data-model.md` — `articles`, `articles_live`, `articles_tombstone`, `article_versions`.
- Draft → publish flow: `drafts.md`.
- Auth header / scopes / time source: `auth.md`.
- URL & error envelope conventions: `api-conventions.md`.
- Account-level firehose for downstream republishers: `account-stream.md`.
