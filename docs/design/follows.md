# FollowService

Status: agreed (v1)
Scope: `(user, account)` follow edges. Feed semantics for follows live in `feed-follow.md`. Wire shape: `api-conventions.md`. Auth: `auth.md`. Schema: `data-model.md`.

## Messages

```proto
message Follow {
  string user_id = 1;
  string account_id = 2;
  FollowStatus status = 3;
  google.protobuf.Timestamp created_at = 4;
  google.protobuf.Timestamp unfollowed_at = 5;
}

enum FollowStatus {
  FOLLOW_STATUS_UNSPECIFIED = 0;
  FOLLOW_STATUS_ACTIVE = 1;
  FOLLOW_STATUS_UNFOLLOWED = 2;
}
```

## Service

```proto
service FollowService {
  rpc Follow(FollowRequest) returns (Follow) {
    option (google.api.http) = {
      post: "/v1/users/{user_id}/follows"
      body: "*"
    };
  }
  rpc Unfollow(UnfollowRequest) returns (Follow) {
    option (google.api.http) = {
      delete: "/v1/users/{user_id}/follows/{account_id}"
    };
  }
  rpc GetFollow(GetFollowRequest) returns (Follow) {
    option (google.api.http) = {
      get: "/v1/users/{user_id}/follows/{account_id}"
    };
  }
  rpc ListUserFollows(ListUserFollowsRequest) returns (ListUserFollowsResponse) {
    option (google.api.http) = { get: "/v1/users/{user_id}/follows" };
  }
  rpc ListAccountFollowers(ListAccountFollowersRequest) returns (ListAccountFollowersResponse) {
    option (google.api.http) = { get: "/v1/accounts/{account_id}/followers" };
  }
}

message FollowRequest    { string user_id = 1; string account_id = 2; }
message UnfollowRequest  { string user_id = 1; string account_id = 2; }
message GetFollowRequest { string user_id = 1; string account_id = 2; }

message ListUserFollowsRequest {
  string user_id = 1;
  int32 page_size = 2;
  string page_token = 3;
  bool include_unfollowed = 4;          // default false
}
message ListUserFollowsResponse {
  repeated Follow items = 1;
  string next_page_token = 2;
}

message ListAccountFollowersRequest {
  string account_id = 1;
  int32 page_size = 2;
  string page_token = 3;
  bool include_unfollowed = 4;          // default false
}
message ListAccountFollowersResponse {
  repeated Follow items = 1;
  string next_page_token = 2;
}
```

No follower / following counts in v1. Block/mute out of scope.

## Authorization

| RPC | Allowed subject |
|---|---|
| `Follow` | `User` whose `user_id == request.user_id` **or** `System.follows.write` |
| `Unfollow` | `User` whose `user_id == request.user_id` **or** `System.follows.write` |
| `GetFollow` | `User` whose `user_id == request.user_id` **or** `System.follows.read` |
| `ListUserFollows` | `User` whose `user_id == request.user_id` **or** `System.follows.read` |
| `ListAccountFollowers` | `Account` whose `account_id == request.account_id` **or** `System.follows.read` |

No anonymous reads. Unauthorized callers receive `NOT_FOUND` to avoid leaking existence.

## State machine

```
   (no row)
       |
       | Follow
       v
     active <----+
       |        |
   Unfollow   Follow (re-activate; created_at = now)
       v        |
   unfollowed --+
```

- **Self-follow rejected**: `user_id == account_id` (cross-namespace UUID collision, astronomically unlikely) → `INVALID_ARGUMENT` `SELF_FOLLOW_FORBIDDEN`.
- **`Follow` is idempotent in the active direction**:
  - No row → insert (`status=active`, `created_at=now`).
  - Existing `active` row → no-op (returns existing row unchanged).
  - Existing `unfollowed` row → update `status=active`, clear `unfollowed_at`, **set `created_at=now`** so list ordering reflects the new relationship.
- **`Unfollow` requires an existing edge**:
  - No row → `FOLLOW_NOT_FOUND`.
  - Existing `active` row → update `status=unfollowed`, set `unfollowed_at=now`.
  - Existing `unfollowed` row → no-op success (already unfollowed).

## Deletion interactions

- `Follow` targeting a deleted user → `USER_DELETED`. Targeting a deleted account → `ACCOUNT_DELETED`.
- `Unfollow` is allowed regardless of either side's deletion status (lets `System` paths clean up; user-self path is gated by signing-key revocation upstream of this RPC).
- `GetFollow` returns the row regardless of either side's deletion status.

## List behaviors

- Default order: `created_at DESC`.
- Cursor (per `api-conventions.md`) encodes `(created_at, account_id)` for `ListUserFollows`, `(created_at, user_id)` for `ListAccountFollowers`.
- `include_unfollowed=false` (default) → only `status=active` rows.
- `ListUserFollows` surfaces follows targeting accounts in any state; the response carries the `account_id` and the caller can resolve `account.status` separately if needed.
- `ListAccountFollowers` returns all rows matching the filter — **no special filtering for deleted users**. Deleted users' follows remain visible to the account owner / system.

## Validation

| Field | Rule |
|---|---|
| `user_id`, `account_id` | well-formed UUIDs; resolvable rows; otherwise `USER_NOT_FOUND` / `ACCOUNT_NOT_FOUND` |
| `user_id` ≠ `account_id` | else `SELF_FOLLOW_FORBIDDEN` |
| `page_size` | clamped to `[1, 200]`, default 50 |

## Errors

| Reason | Code | When |
|---|---|---|
| `USER_NOT_FOUND` | `NOT_FOUND` | user id does not exist; or unauthorized non-self caller |
| `ACCOUNT_NOT_FOUND` | `NOT_FOUND` | account id does not exist |
| `USER_DELETED` | `FAILED_PRECONDITION` | `Follow` targets a deleted user |
| `ACCOUNT_DELETED` | `FAILED_PRECONDITION` | `Follow` targets a deleted account |
| `FOLLOW_NOT_FOUND` | `NOT_FOUND` | `GetFollow` / `Unfollow` on a missing edge |
| `SELF_FOLLOW_FORBIDDEN` | `INVALID_ARGUMENT` | `user_id == account_id` |
| `INVALID_ARGUMENT` | `INVALID_ARGUMENT` | malformed UUIDs or page params |

## Cross-references

- Schema: `data-model.md` — `follows`.
- Auth: `auth.md` — `Subject::User`, `Subject::Account`, `follows.read`/`follows.write` scopes.
- Wire: `api-conventions.md` — pagination, error envelope.
- Feed derived from follows: `feed-follow.md` — defines how an account's articles are surfaced to users that follow it.
- User soft-delete behavior: `users.md`.
- Account soft-delete behavior: `accounts.md`.
