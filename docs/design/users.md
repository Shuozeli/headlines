# UserService

Status: agreed (v1)
Scope: user identity + per-user key management. Follows live in `follows.md`; feeds in `feed-recommendation.md` / `feed-follow.md`; events in `events.md`. Wire shape: `api-conventions.md`. Auth: `auth.md`. Schema: `data-model.md`.

## Messages

```proto
message User {
  string id = 1;                                  // UUIDv7
  string display_name = 2;
  UserStatus status = 3;
  google.protobuf.Timestamp deleted_at = 4;
  google.protobuf.Timestamp created_at = 5;
}

enum UserStatus {
  USER_STATUS_UNSPECIFIED = 0;
  USER_STATUS_ACTIVE = 1;
  USER_STATUS_DELETED = 2;
}

message UserKey {
  string user_id = 1;
  string key_id = 2;
  string algo = 3;
  string public_key = 4;
  KeyStatus status = 5;
  google.protobuf.Timestamp created_at = 6;
  google.protobuf.Timestamp revoked_at = 7;
}
```

`PublicKey` and `KeyStatus` are shared with `accounts.md` (same definitions; expected to live in a shared `common.proto` — placement decided in `architecture.md`).

## Service

```proto
service UserService {
  rpc CreateUser(CreateUserRequest) returns (CreateUserResponse) {
    option (google.api.http) = { post: "/v1/users" body: "*" };
  }
  rpc GetUser(GetUserRequest) returns (User) {
    option (google.api.http) = { get: "/v1/users/{id}" };
  }
  rpc UpdateUser(UpdateUserRequest) returns (User) {
    option (google.api.http) = {
      patch: "/v1/users/{user.id}"
      body: "user"
    };
  }
  rpc DeleteUser(DeleteUserRequest) returns (User) {
    option (google.api.http) = { delete: "/v1/users/{id}" };
  }
  rpc AddUserKey(AddUserKeyRequest) returns (UserKey) {
    option (google.api.http) = {
      post: "/v1/users/{user_id}/keys"
      body: "*"
    };
  }
  rpc RevokeUserKey(RevokeUserKeyRequest) returns (UserKey) {
    option (google.api.http) = {
      post: "/v1/users/{user_id}/keys/{key_id}/revoke"
      body: "*"
    };
  }
}

message CreateUserRequest {
  string display_name = 1;
  PublicKey initial_key = 2;     // required: user is unusable without a key
}
message CreateUserResponse {
  User user = 1;
  string key_id = 2;             // server-minted UUIDv7 for the initial key
}

message GetUserRequest { string id = 1; }

message UpdateUserRequest {
  User user = 1;
  google.protobuf.FieldMask update_mask = 2;
}

message DeleteUserRequest { string id = 1; }

message AddUserKeyRequest {
  string user_id = 1;
  PublicKey key = 2;
}
message RevokeUserKeyRequest {
  string user_id = 1;
  string key_id = 2;
}
```

No `ListUsers`, no `ListUserKeys` in v1. Clients track `key_id`s returned at creation/add time.

## Authorization

| RPC | Allowed subject |
|---|---|
| `CreateUser` | `Anonymous` (when `auth.bootstrap.user_registration = "open"`) **or** `System` with scope `users.write` |
| `GetUser` | `User` whose `user_id == request.id` **or** `System` with scope `users.read` |
| `UpdateUser` | `User` whose `user_id == request.user.id` **or** `System` with scope `users.admin` |
| `DeleteUser` | `User` whose `user_id == request.id` (self-delete allowed) **or** `System` with scope `users.delete` |
| `AddUserKey` | `User` whose `user_id == request.user_id` **or** `System` with scope `users.admin` |
| `RevokeUserKey` | `User` whose `user_id == request.user_id` **or** `System` with scope `users.admin` |

Privacy note: `GetUser` is **not anonymous**. Unauthorized callers receive `NOT_FOUND` (not `PERMISSION_DENIED`), so the API does not leak user existence.

## Identity

- `user.id`: UUIDv7. Server-generated; clients cannot specify.
- `key_id`: UUIDv7. Server-generated.

## Validation

| Field | Rule |
|---|---|
| `display_name` | empty or 1–64 chars (Unicode permitted, no charset restriction); trimmed; no leading/trailing whitespace |
| `PublicKey.algo` | must be in the auth layer's registered algorithm set |
| `PublicKey.public_key` | format validated by algorithm impl (e.g. Ed25519 = 32 raw bytes base64) |
| `update_mask` paths | only `display_name` |

## Behaviors

### Tombstone reads

`GetUser` of a deleted user (by self or `System.users.read`) returns 200 with `status = USER_STATUS_DELETED` and `deleted_at` set.

### Soft delete (no cascade)

Per data-model rules: deleting a user sets `status='deleted'`, `deleted_at=now()`. **Related rows are kept as-is.**

- `follows` rows authored by the user: untouched (`status='active'` stays). `ListAccountFollowers` does **not** filter them out — deleted users continue to show up in follower lists (per `follows.md`).
- `feed_recommendation` rows for the user: untouched. Ranker may still write; reads against a deleted user return `FAILED_PRECONDITION` `USER_DELETED` (defined in `feed-recommendation.md`).
- `events` posted by the user: retained for analytics.
- `user_keys`: untouched. Subsequent signed requests resolve `Subject::User` but every authorized RPC rejects with `USER_DELETED`.

### Update field whitelist

Only `display_name` is mutable. Other mask paths → `INVALID_ARGUMENT`. No rate limiting on updates in v1.

### Lockout protection on key revoke

- `RevokeUserKey` rejects with `FAILED_PRECONDITION` `LAST_ACTIVE_KEY` if it would leave zero active keys.
- Override: `System` with `admin.*` scope.
- A user revoking the very key currently signing the request is allowed unless it would trigger the last-active-key check.

### Idempotency

Not implemented in v1; same plan as accounts.

## Errors

| Reason | Code | When |
|---|---|---|
| `USER_NOT_FOUND` | `NOT_FOUND` | id does not exist; or `GetUser` requested by a non-self, non-`users.read` caller |
| `USER_DELETED` | `FAILED_PRECONDITION` | write attempted on a deleted user |
| `INVALID_PUBLIC_KEY` | `INVALID_ARGUMENT` | key bytes don't match algo format |
| `UNSUPPORTED_ALGORITHM` | `INVALID_ARGUMENT` | `algo` not in registered set |
| `KEY_NOT_FOUND` | `NOT_FOUND` | revoke targets a missing key |
| `KEY_ALREADY_REVOKED` | `ALREADY_EXISTS` | key already in `revoked` status |
| `LAST_ACTIVE_KEY` | `FAILED_PRECONDITION` | revoke would leave zero active keys (non-admin) |
| `REGISTRATION_DISABLED` | `PERMISSION_DENIED` | anonymous `CreateUser` when config is `system_only` |
| `INVALID_ARGUMENT` | `INVALID_ARGUMENT` | validation failure (length, mask path) |

## Cross-references

- Schema: `data-model.md` — `users`, `user_keys`.
- Auth: `auth.md` — signing scheme, `Subject::User`, scope vocabulary.
- Wire: `api-conventions.md` — error envelope, pagination shape.
- Follows authored by users: `follows.md`.
- User feeds: `feed-recommendation.md`, `feed-follow.md`.
- Events posted by users: `events.md`.
