# AccountStreamService

Status: agreed (v1)
Scope: pull-based per-account article event stream for downstream republishers (Twitter, YouTube, Toutiao bots, etc.). No user awareness; watermark-driven; system-only auth. Wire shape: `api-conventions.md`. Auth: `auth.md`. Schema: `data-model.md`.

## Use case

A republisher operates per account: it consumes one stream per account it republishes, dedupes by `article_id` (last-write-wins), and mirrors `state` to the target platform (create on `LIVE`, delete on `TOMBSTONE`). It calls `GetArticle` for each item to fetch full content nodes when it needs to render.

## Messages

```proto
message AccountStreamItem {
  ArticleSummary article = 1;            // from articles.md; no content nodes
}
```

`AccountStreamItem` carries `ArticleSummary` (not full `Article`) to honor the list-vs-view rule. Republishers fetch full bodies with `GetArticle`.

## Service

```proto
service AccountStreamService {
  rpc StreamAccountArticles(StreamAccountArticlesRequest)
      returns (StreamAccountArticlesResponse) {
    option (google.api.http) = { get: "/v1/accounts/{account_id}/article-stream" };
  }
}

message StreamAccountArticlesRequest {
  string account_id = 1;
  int32 page_size = 2;
  string page_token = 3;                 // opaque, base64-encoded cursor on (event_at, article_id)
}
message StreamAccountArticlesResponse {
  repeated AccountStreamItem items = 1;
  string next_page_token = 2;
}
```

Unary RPC. Server-streaming variant deferred post-v1.

## Authorization

| RPC | Allowed subject |
|---|---|
| `StreamAccountArticles` | `System` with scope `articles.stream` |

`articles.stream` is a new dedicated scope — granted per-republisher so a Twitter bot's credentials don't double as full read access. Added to `auth.md` vocabulary.

## Stream semantics

**Keyset cursor on `event_at = COALESCE(articles_live.updated_at, articles_tombstone.tombstoned_at)`**, ascending.

Indicative SQL:

```sql
SELECT a.id, a.account_id, a.state, a.created_at,
       COALESCE(l.updated_at, t.tombstoned_at) AS event_at,
       l.current_version, l.published_at, l.updated_at,
       v.title, v.author_name, v.author_url,
       (v.content IS NULL) AS redacted,
       t.reason AS tombstone_reason, t.tombstoned_at
FROM   articles a
LEFT   JOIN articles_live l       ON l.article_id = a.id
LEFT   JOIN articles_tombstone t  ON t.article_id = a.id
LEFT   JOIN article_versions v    ON v.article_id = a.id AND v.version = l.current_version
WHERE  a.account_id = $account_id
   AND (COALESCE(l.updated_at, t.tombstoned_at), a.id) > ($cursor_event_at, $cursor_id)
ORDER  BY event_at ASC, a.id ASC
LIMIT  $page_size;
```

Event delivery:

- **Created** → emitted once with `state=LIVE`, `event_at = published_at` (publish sets `updated_at = published_at`).
- **Edited** → re-emitted with bumped `event_at` (`articles_live.updated_at` after edit).
- **Redacted (current version)** → re-emitted: `RedactArticleVersion` bumps `articles_live.updated_at` when the redacted version equals `articles_live.current_version`, so the stream surfaces the change with `redacted=true` on the summary. (See `articles.md` redaction behavior.)
- **Tombstoned** → emitted with `state=TOMBSTONE`, `event_at = tombstoned_at`.
- **Drafts** never appear (not in `articles`).

Republisher contract: consume in order; for each `article_id`, the latest emitted `state` is authoritative.

## Pagination

- AIP-158: `page_size` is a hint (default 50, clamped `[1, 200]`).
- `page_token` is **opaque, base64-encoded** — internally `{event_at, article_id}` JSON. Clients treat it as a black box.
- Empty `page_token` → start from the beginning of the account's history.
- Empty `next_page_token` → caller is caught up; resume later with the last cursor.
- ASC order — designed for sequential watermark consumption.

## Account lifecycle interaction

- **Account deleted** → `StreamAccountArticles` returns `ACCOUNT_DELETED`. The stream **closes** on account deletion; the republisher's contract is to remove all content from that account on its target platform when it sees this error. Pending tombstones inside the stream are not delivered after deletion.
- **Account does not exist** → `ACCOUNT_NOT_FOUND`.

## Validation

| Field | Rule |
|---|---|
| `account_id` | well-formed UUID; existing; `status=active` |
| `page_size` | clamped `[1, 200]`, default 50 |
| `page_token` | base64-decoded JSON `{event_at, article_id}`; malformed → `INVALID_ARGUMENT` `INVALID_CURSOR` |

## Errors

| Reason | Code | When |
|---|---|---|
| `ACCOUNT_NOT_FOUND` | `NOT_FOUND` | account id does not exist |
| `ACCOUNT_DELETED` | `FAILED_PRECONDITION` | account has been deleted; stream is closed |
| `INVALID_CURSOR` | `INVALID_ARGUMENT` | `page_token` malformed or expired |
| `INVALID_ARGUMENT` | `INVALID_ARGUMENT` | malformed UUID or page params |

## Cross-references

- Schema: `data-model.md` — `articles`, `articles_live`, `articles_tombstone`, `article_versions`.
- Article messages, summary shape, redaction's `updated_at` bump: `articles.md`.
- Auth scopes: `auth.md` — `articles.stream`.
- Wire envelope, AIP pagination: `api-conventions.md`.
- Per-user feeds (parallel surfaces with different consumers): `feed-recommendation.md`, `feed-follow.md`.
