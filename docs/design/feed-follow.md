# FeedFollowService

Status: agreed (v1)
Scope: follow-derived feed — articles from accounts the user currently follows, ordered by article creation time. Recommendation feed lives in `feed-recommendation.md`. Wire shape: `api-conventions.md`. Auth: `auth.md`. Schema: `data-model.md`.

## Messages

```proto
message FollowFeedItem {
  ArticleSummary article = 1;            // from articles.md; no content nodes
}
```

`FollowFeedItem` is distinct from `FeedItem` (recommendation) — there is no `position`, ordering is data-driven by `article.created_at`.

## Service

```proto
service FeedFollowService {
  rpc GetFollowFeed(GetFollowFeedRequest) returns (GetFollowFeedResponse) {
    option (google.api.http) = { get: "/v1/users/{user_id}/feed/follow" };
  }
}

message GetFollowFeedRequest {
  string user_id = 1;
  int32 page_size = 2;
  string page_token = 3;
}
message GetFollowFeedResponse {
  repeated FollowFeedItem items = 1;
  string next_page_token = 2;
}
```

No write RPC — feed is fully computed from `follows ⨝ articles_live` at read time.

## Authorization

| RPC | Allowed subject |
|---|---|
| `GetFollowFeed` | `User` whose `user_id == request.user_id` **or** `System` with scope `feeds.follow.read` |

New scope `feeds.follow.read` added to the auth vocabulary; parallel to `feeds.recommendation.read`.

## Computation

Indicative SQL (keyset pagination on `(article.created_at, article.id)`):

```sql
SELECT a.id, a.account_id, a.state, a.created_at,
       l.current_version, l.published_at, l.updated_at,
       v.title, v.author_name, v.author_url,
       (v.content IS NULL) AS redacted
FROM   follows f
JOIN   articles a            ON a.account_id = f.account_id
JOIN   articles_live l       ON l.article_id = a.id
JOIN   article_versions v    ON v.article_id = a.id AND v.version = l.current_version
WHERE  f.user_id = $user_id
  AND  f.status = 'active'
  AND  (a.created_at, a.id) < ($cursor_created_at, $cursor_id)
ORDER  BY a.created_at DESC, a.id DESC
LIMIT  $page_size;
```

Filter rules (all enforced by the JOIN, not application code):

- Tombstoned articles → excluded (not in `articles_live`).
- Missing articles → excluded (no row in `articles`).
- Unfollowed edges → excluded (`f.status = 'unfollowed'`).
- Articles from **deleted accounts**: **included**. The article is still live; the user explicitly followed the account at some point. Clients can resolve `account.status` via `GetAccount` if they want to render a deleted-account marker.
- Redacted current version → surfaces with `ArticleLiveSummary.redacted = true`.

**No "since I followed" cutoff.** Articles published before the user followed the account are included. `follows.created_at` does not affect this query.

## Pagination (keyset, AIP-158-aligned)

- Cursor (`page_token`) encodes `(article.created_at, article.id)`.
- `page_size` is a hint; default 50, clamped to `[1, 200]`. Server may return fewer items (filtering or end of stream).
- Empty follow set → empty page with empty `next_page_token`.
- Mid-scroll mutations:
  - User follows a new account: its older articles may be missed (already past cursor); newer ones surface in subsequent pages.
  - User unfollows an account: its articles vanish from subsequent pages.
  - These are accepted side effects of keyset pagination on a live dataset.

## Behavior on user delete

- `GetFollowFeed` for a deleted user → `USER_DELETED`. Per `users.md`, follow rows themselves are not cleaned up; only the read path rejects.

## Performance

- Required index (already in `data-model.md`): `articles (account_id, created_at DESC)`.
- For users following many accounts, the join spans many `articles` partitions; cost grows with `|follows × articles_per_account|` within the page window. v1 accepts the latency. Future: precomputed follow-feed materialization (table or cache) — out of scope for this doc.

## Validation

| Field | Rule |
|---|---|
| `user_id` | well-formed UUID; existing; `status=active` |
| `page_size` | clamped `[1, 200]`, default 50 |

## Errors

| Reason | Code | When |
|---|---|---|
| `USER_NOT_FOUND` | `NOT_FOUND` | user id does not exist; or unauthorized non-self caller |
| `USER_DELETED` | `FAILED_PRECONDITION` | get on a deleted user |
| `INVALID_ARGUMENT` | `INVALID_ARGUMENT` | malformed UUID or page params |

## Cross-references

- Schema: `data-model.md` — `follows`, `articles`, `articles_live`, `article_versions`.
- Article messages and summary shape: `articles.md`.
- Follow edge semantics, status transitions: `follows.md`.
- User soft-delete: `users.md`.
- Auth scopes: `auth.md` — `feeds.follow.read`.
- Wire envelope, pagination: `api-conventions.md`.
- Parallel feed surface: `feed-recommendation.md`.
