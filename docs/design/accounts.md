# AccountService

Status: agreed (v1)
Scope: account identity + per-account key management. Article authorship lives in `articles.md`. Auth signing rules live in `auth.md`. Wire conventions in `api-conventions.md`. Schema in `data-model.md`.

## Messages

```proto
syntax = "proto3";
package headlines.v1;

import "google/api/annotations.proto";
import "google/protobuf/field_mask.proto";
import "google/protobuf/timestamp.proto";

message Account {
  string id = 1;                                  // UUIDv7
  string short_name = 2;
  string author_name = 3;
  string author_url = 4;
  AccountStatus status = 5;
  google.protobuf.Timestamp deleted_at = 6;
  google.protobuf.Timestamp created_at = 7;
  google.protobuf.Timestamp updated_at = 8;
}

enum AccountStatus {
  ACCOUNT_STATUS_UNSPECIFIED = 0;
  ACCOUNT_STATUS_ACTIVE = 1;
  ACCOUNT_STATUS_DELETED = 2;
}

message PublicKey {
  string algo = 1;        // "ed25519"
  string public_key = 2;  // base64, format defined by algo
}

message AccountKey {
  string account_id = 1;
  string key_id = 2;                              // UUIDv7
  string algo = 3;
  string public_key = 4;
  KeyStatus status = 5;
  google.protobuf.Timestamp created_at = 6;
  google.protobuf.Timestamp revoked_at = 7;
}

enum KeyStatus {
  KEY_STATUS_UNSPECIFIED = 0;
  KEY_STATUS_ACTIVE = 1;
  KEY_STATUS_REVOKED = 2;
}
```

## Service

```proto
service AccountService {
  rpc CreateAccount(CreateAccountRequest) returns (CreateAccountResponse) {
    option (google.api.http) = { post: "/v1/accounts" body: "*" };
  }
  rpc GetAccount(GetAccountRequest) returns (Account) {
    option (google.api.http) = { get: "/v1/accounts/{id}" };
  }
  rpc UpdateAccount(UpdateAccountRequest) returns (Account) {
    option (google.api.http) = {
      patch: "/v1/accounts/{account.id}"
      body: "account"
    };
  }
  rpc DeleteAccount(DeleteAccountRequest) returns (Account) {
    option (google.api.http) = { delete: "/v1/accounts/{id}" };
  }
  rpc AddAccountKey(AddAccountKeyRequest) returns (AccountKey) {
    option (google.api.http) = {
      post: "/v1/accounts/{account_id}/keys"
      body: "*"
    };
  }
  rpc RevokeAccountKey(RevokeAccountKeyRequest) returns (AccountKey) {
    option (google.api.http) = {
      post: "/v1/accounts/{account_id}/keys/{key_id}/revoke"
      body: "*"
    };
  }
}

message CreateAccountRequest {
  string short_name = 1;
  string author_name = 2;
  string author_url = 3;
  PublicKey initial_key = 4;     // required: account is unusable without a key
}
message CreateAccountResponse {
  Account account = 1;
  string key_id = 2;             // server-minted UUID for the initial key
}

message GetAccountRequest { string id = 1; }

message UpdateAccountRequest {
  Account account = 1;                            // body
  google.protobuf.FieldMask update_mask = 2;
}

message DeleteAccountRequest { string id = 1; }

message AddAccountKeyRequest {
  string account_id = 1;
  PublicKey key = 2;
}

message RevokeAccountKeyRequest {
  string account_id = 1;
  string key_id = 2;
}
```

No `ListAccounts`, no `ListAccountKeys` in v1. Clients track `key_id`s returned at creation/add time. Operator dashboards use direct DB access.

## Authorization

| RPC | Allowed subject |
|---|---|
| `CreateAccount` | `Anonymous` (when `auth.bootstrap.account_registration = "open"`) **or** `System` with scope `accounts.write` |
| `GetAccount` | `Anonymous` (always) |
| `UpdateAccount` | `Account` whose `account_id == request.account.id` **or** `System` with scope `accounts.admin` |
| `DeleteAccount` | `Account` whose `account_id == request.id` (self-delete allowed) **or** `System` with scope `accounts.delete` |
| `AddAccountKey` | `Account` whose `account_id == request.account_id` **or** `System` with scope `accounts.admin` |
| `RevokeAccountKey` | `Account` whose `account_id == request.account_id` **or** `System` with scope `accounts.admin` |

`System` scope distinctions:
- `accounts.write` — bootstrap creation only (system-only registration mode).
- `accounts.admin` — modify or rotate keys on existing accounts (cross-account writes).
- `accounts.delete` — soft-delete any account.

## Identity

- `account.id` is **UUIDv7** (time-ordered). Server-generated; clients cannot specify.
- `key_id` is **UUIDv7**. Server-generated.

## Validation

| Field | Rule |
|---|---|
| `short_name` | 1–32 chars; `[A-Za-z0-9 _-]`; trimmed; `INVALID_ARGUMENT` otherwise |
| `author_name` | 1–128 chars; non-empty after trim |
| `author_url` | empty or valid `http(s)://` URL, ≤512 chars |
| `PublicKey.algo` | must be in the auth layer's registered algorithm set; else `UNSUPPORTED_ALGORITHM` |
| `PublicKey.public_key` | format validated by algorithm impl (e.g. Ed25519 = 32 raw bytes, base64-encoded → 44 chars); else `INVALID_PUBLIC_KEY` |
| `update_mask` paths | only `short_name`, `author_name`, `author_url`; other paths → `INVALID_ARGUMENT` |

## Behaviors

### Tombstone reads

`GetAccount` of a deleted account returns **200** with `status = ACCOUNT_STATUS_DELETED` and `deleted_at` set, never `NOT_FOUND`.

### Soft delete

- Deletion sets `status='deleted'`, `deleted_at=now()`. Row stays.
- **No cascade**: articles remain readable, `articles.account_id` still resolves. (Per `data-model.md`.)
- Subsequent writes (`UpdateAccount`, `AddAccountKey`, etc.) on a deleted account → `FAILED_PRECONDITION` `ACCOUNT_DELETED`.
- Re-creating with the same id is impossible (UUIDv7 is unique). Operators must use a new account.

### Update field whitelist

`UpdateAccount` accepts only `short_name`, `author_name`, `author_url` in the field mask. `status`, `id`, timestamps cannot be updated through the API.

### Lockout protection on key revoke

- `RevokeAccountKey` rejects with `FAILED_PRECONDITION` `LAST_ACTIVE_KEY` if it would leave zero active keys.
- Override: `System` with `admin.*` (operator rescue path).

### Idempotency

- Not implemented in v1. `CreateAccount` and `AddAccountKey` may produce duplicates if retried. Future global idempotency-key plan covers them.

## Errors

`google.rpc.Code` + `google.rpc.ErrorInfo.reason`:

| Reason | Code | When |
|---|---|---|
| `ACCOUNT_NOT_FOUND` | `NOT_FOUND` | account id does not exist |
| `ACCOUNT_DELETED` | `FAILED_PRECONDITION` | write attempted on a deleted account |
| `INVALID_PUBLIC_KEY` | `INVALID_ARGUMENT` | key bytes don't match algo format |
| `UNSUPPORTED_ALGORITHM` | `INVALID_ARGUMENT` | `algo` not in registered set |
| `KEY_NOT_FOUND` | `NOT_FOUND` | revoke targets a missing key |
| `KEY_ALREADY_REVOKED` | `ALREADY_EXISTS` | key already in `revoked` status |
| `LAST_ACTIVE_KEY` | `FAILED_PRECONDITION` | revoke would leave zero active keys (non-admin) |
| `REGISTRATION_DISABLED` | `PERMISSION_DENIED` | anonymous CreateAccount when config is `system_only` |
| `INVALID_ARGUMENT` | `INVALID_ARGUMENT` | validation failure (charset, length, URL) |

## Cross-references

- Schema: `data-model.md` — `accounts`, `account_keys`.
- Auth header / time source / scopes: `auth.md`.
- URL conventions, pagination, errors: `api-conventions.md`.
- Article ownership and per-account article listing: `articles.md`.
