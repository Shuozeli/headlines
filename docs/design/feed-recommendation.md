# FeedRecommendationService

Status: agreed (v1)
Scope: ranker-pushed ordered list per user, plus user pull. The follow-derived feed lives in `feed-follow.md`. Wire shape: `api-conventions.md`. Auth: `auth.md`. Schema: `data-model.md`.

## Messages

```proto
message FeedItem {
  int32 position = 1;
  ArticleSummary article = 2;            // from articles.md; no content nodes
}
```

`FeedItem` carries `ArticleSummary` rather than full `Article` (per the list-vs-view convention in `articles.md`). Clients render summaries directly and call `GetArticle` for the body when the user opens an item.

## Service

```proto
service FeedRecommendationService {
  rpc ReplaceRecommendationFeed(ReplaceRecommendationFeedRequest)
      returns (ReplaceRecommendationFeedResponse) {
    option (google.api.http) = {
      put: "/v1/users/{user_id}/feed/recommendation"
      body: "*"
    };
  }
  rpc GetRecommendationFeed(GetRecommendationFeedRequest)
      returns (GetRecommendationFeedResponse) {
    option (google.api.http) = { get: "/v1/users/{user_id}/feed/recommendation" };
  }
}

message ReplaceRecommendationFeedRequest {
  string user_id = 1;
  repeated string article_ids = 2;        // order is the feed order; position = index
}
message ReplaceRecommendationFeedResponse {
  int32 stored_count = 1;
}

message GetRecommendationFeedRequest {
  string user_id = 1;
  int32 page_size = 2;
  string page_token = 3;
}
message GetRecommendationFeedResponse {
  repeated FeedItem items = 1;
  string next_page_token = 2;
}
```

No append / partial-delete / per-position update RPCs. The ranker is the only writer and always pushes a complete ordered list.

## Authorization

| RPC | Allowed subject |
|---|---|
| `ReplaceRecommendationFeed` | `System` with scope `feeds.recommendation.write` (only) |
| `GetRecommendationFeed` | `User` whose `user_id == request.user_id` **or** `System` with scope `feeds.recommendation.read` |

Accounts and users cannot push feeds. Users can read only their own feed.

## Behaviors

### Replace (atomic per user)

Single tx:

```sql
DELETE FROM feed_recommendation WHERE user_id = $1;
INSERT INTO feed_recommendation (user_id, position, article_id)
VALUES ($1, 0, $2), ($1, 1, $3), ...;
```

- Empty `article_ids` clears the feed (still succeeds; `stored_count = 0`).
- User must exist and be `status=active`. Deleted user → `USER_DELETED`. Nonexistent → `USER_NOT_FOUND`.
- `article_ids` are stored as **soft references** (no FK). The ranker may push references ahead of article ingestion; reads handle absent articles via JOIN (see *Get* below). This matches the cross-tree rule in `data-model.md`.
- Cap: `feeds.replace_max_items` (default **5000**). Larger → `FEED_TOO_LARGE`.
- Duplicates rejected: `DUPLICATE_ARTICLE_ID`. Ranker is responsible for dedup.

### Get

Reads use an **inner join against `articles_live`**, which automatically excludes tombstones and missing articles — no application-side filtering needed. Indicative shape:

```sql
SELECT r.position,
       a.id, a.account_id, a.state, a.created_at,
       l.current_version, l.published_at, l.updated_at,
       v.title, v.author_name, v.author_url,
       (v.content IS NULL) AS redacted
FROM   feed_recommendation r
JOIN   articles_live l       ON l.article_id = r.article_id
JOIN   articles a            ON a.id = r.article_id
JOIN   article_versions v    ON v.article_id = a.id AND v.version = l.current_version
WHERE  r.user_id = $1
   AND r.position >= $2
ORDER  BY r.position ASC
LIMIT  $3;
```

- Tombstones: `articles_tombstone` rows are not in `articles_live`, so the inner join drops them.
- Missing article ids: no row in `articles`, the inner join drops them.
- Redacted current version: `article_versions.content IS NULL` surfaces as `ArticleLiveSummary.redacted = true`.
- Order: `position ASC`.

### Pagination (Google AIP-aligned)

- `page_size` is the requested *maximum* items per page; **the server may return fewer** (rows scanned but filtered, or end of feed). Default 50, clamped to `[1, 200]`.
- Cursor (`page_token`) encodes the last `position` returned.
- Clients paginate until `next_page_token` is empty. A non-empty token with fewer than `page_size` items is normal mid-feed (filtering caused gaps).

This follows AIP-158 — `page_size` is a hint, not a guarantee.

### Behavior on user delete

Per `users.md`, soft-delete leaves `feed_recommendation` rows untouched. But:

- `ReplaceRecommendationFeed` for a deleted user → `USER_DELETED` (ranker stops writing).
- `GetRecommendationFeed` for a deleted user → `USER_DELETED` (no feed serving for tombstoned users).

The ranker is expected to drop deleted users from its writer set.

### Audit / raw view

No API endpoint surfaces the raw stored `(position, article_id)` rows including filtered ids. Operators use direct DB access for audit.

## Validation

| Field | Rule |
|---|---|
| `user_id` | well-formed UUID; existing; `status=active` |
| `article_ids` | size 0..`feeds.replace_max_items`; each well-formed UUID; no duplicates |
| `page_size` | clamped `[1, 200]`, default 50 |

## Configuration

```toml
[feeds]
replace_max_items = 5000
```

## Errors

| Reason | Code | When |
|---|---|---|
| `USER_NOT_FOUND` | `NOT_FOUND` | user id does not exist; or unauthorized non-self caller on `Get` |
| `USER_DELETED` | `FAILED_PRECONDITION` | replace or get on a deleted user |
| `FEED_TOO_LARGE` | `RESOURCE_EXHAUSTED` | replace exceeds `replace_max_items` |
| `DUPLICATE_ARTICLE_ID` | `INVALID_ARGUMENT` | replace contains duplicate ids |
| `INVALID_ARGUMENT` | `INVALID_ARGUMENT` | malformed UUIDs or page params |

## Cross-references

- Schema: `data-model.md` — `feed_recommendation`, `articles_live`, `article_versions`.
- Article messages, summary shape, redaction marker: `articles.md`.
- Auth scopes: `auth.md` — `feeds.recommendation.read`, `feeds.recommendation.write`.
- Wire envelope, pagination, error format: `api-conventions.md`.
- Follow-derived feed (parallel surface): `feed-follow.md`.
