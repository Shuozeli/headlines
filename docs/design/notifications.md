# NotificationService

Status: **reserved (designed, not implemented in v1)**
Scope: design the proto surface and authorization model for notifications so callers can integrate against the API today. All RPCs return gRPC `UNIMPLEMENTED` (REST 501) in v1. Storage tables are not added to `data-model.md` until implementation begins.

## Why reserve now

Pinning the proto + URLs early lets the ranker, the web/mobile clients, and any republisher integrate the notification surface as soon as it ships, with no breaking proto change. Returning `UNIMPLEMENTED` is the explicit "not yet" signal.

## Messages

```proto
message Notification {
  string id = 1;                                 // UUIDv7, server-assigned
  string user_id = 2;                            // recipient
  string article_id = 3;                         // optional subject article
  NotificationKind kind = 4;
  repeated NotificationChannel channels = 5;     // delivery channels requested
  NotificationPayload payload = 6;
  NotificationStatus status = 7;
  google.protobuf.Timestamp created_at = 8;
  google.protobuf.Timestamp delivered_at = 9;
  google.protobuf.Timestamp read_at = 10;
}

enum NotificationKind {
  NOTIFICATION_KIND_UNSPECIFIED = 0;
  NOTIFICATION_KIND_NEW_ARTICLE = 1;             // followed account published / ranker recommendation
  NOTIFICATION_KIND_NEW_FOLLOWER = 2;            // someone followed an account (account-side delivery)
  NOTIFICATION_KIND_ARTICLE_TOMBSTONED = 3;      // an article the user interacted with was removed
  NOTIFICATION_KIND_ARTICLE_EDITED = 4;          // an article the user interacted with was updated
  NOTIFICATION_KIND_MENTION = 5;                 // user was mentioned (future content feature)
  NOTIFICATION_KIND_REPLY = 6;                   // someone replied (future content feature)
  NOTIFICATION_KIND_SYSTEM = 7;                  // generic
}

enum NotificationChannel {
  NOTIFICATION_CHANNEL_UNSPECIFIED = 0;
  NOTIFICATION_CHANNEL_PUSH = 1;
  NOTIFICATION_CHANNEL_EMAIL = 2;
  NOTIFICATION_CHANNEL_SMS = 3;
  NOTIFICATION_CHANNEL_IN_APP = 4;
}

enum NotificationStatus {
  NOTIFICATION_STATUS_UNSPECIFIED = 0;
  NOTIFICATION_STATUS_PENDING = 1;
  NOTIFICATION_STATUS_DELIVERED = 2;
  NOTIFICATION_STATUS_FAILED = 3;
  NOTIFICATION_STATUS_READ = 4;
}

message NotificationPayload {
  string title = 1;
  string body = 2;
  string image_url = 3;
  map<string, string> data = 4;                  // client-side action hints
}

message NotificationPreferences {
  string user_id = 1;
  repeated NotificationChannel disabled_channels = 2;   // default: all enabled
  repeated NotificationKind disabled_kinds = 3;         // default: all enabled
  QuietHours quiet_hours = 4;
  google.protobuf.Timestamp updated_at = 5;
}

message QuietHours {
  bool enabled = 1;
  string timezone = 2;                                  // IANA, e.g. 'America/Los_Angeles'
  int32 start_hour = 3;                                 // 0..23 in local timezone
  int32 end_hour = 4;                                   // 0..23 in local timezone
}
```

## Service

```proto
service NotificationService {
  rpc SendNotification(SendNotificationRequest) returns (Notification) {
    option (google.api.http) = { post: "/v1/notifications" body: "*" };
  }
  rpc SendNotificationBatch(SendNotificationBatchRequest) returns (SendNotificationBatchResponse) {
    option (google.api.http) = { post: "/v1/notifications:batch" body: "*" };
  }
  rpc ListUserNotifications(ListUserNotificationsRequest) returns (ListUserNotificationsResponse) {
    option (google.api.http) = { get: "/v1/users/{user_id}/notifications" };
  }
  rpc MarkNotificationRead(MarkNotificationReadRequest) returns (Notification) {
    option (google.api.http) = { post: "/v1/notifications/{id}/read" body: "*" };
  }
  rpc MarkAllUserNotificationsRead(MarkAllUserNotificationsReadRequest)
      returns (MarkAllUserNotificationsReadResponse) {
    option (google.api.http) = { post: "/v1/users/{user_id}/notifications:mark-all-read" body: "*" };
  }
  rpc GetUserNotificationPreferences(GetUserNotificationPreferencesRequest)
      returns (NotificationPreferences) {
    option (google.api.http) = { get: "/v1/users/{user_id}/notification-preferences" };
  }
  rpc UpdateUserNotificationPreferences(UpdateUserNotificationPreferencesRequest)
      returns (NotificationPreferences) {
    option (google.api.http) = {
      patch: "/v1/users/{preferences.user_id}/notification-preferences"
      body: "preferences"
    };
  }
}

message SendNotificationRequest {
  string idempotency_key = 1;                  // optional; same key returns the same Notification
  string user_id = 2;
  string article_id = 3;
  NotificationKind kind = 4;
  repeated NotificationChannel channels = 5;
  NotificationPayload payload = 6;
}

message SendNotificationBatchRequest {
  repeated SendNotificationRequest notifications = 1;
}
message SendNotificationBatchResponse {
  repeated Notification recorded = 1;
  int32 stored_count = 2;
}

message ListUserNotificationsRequest {
  string user_id = 1;
  int32 page_size = 2;
  string page_token = 3;
  bool unread_only = 4;
}
message ListUserNotificationsResponse {
  repeated Notification items = 1;
  string next_page_token = 2;
}

message MarkNotificationReadRequest { string id = 1; }

message MarkAllUserNotificationsReadRequest { string user_id = 1; }
message MarkAllUserNotificationsReadResponse { int32 marked_count = 1; }

message GetUserNotificationPreferencesRequest { string user_id = 1; }
message UpdateUserNotificationPreferencesRequest {
  NotificationPreferences preferences = 1;
  google.protobuf.FieldMask update_mask = 2;     // 'disabled_channels', 'disabled_kinds', 'quiet_hours'
}
```

7 RPCs total — all return `UNIMPLEMENTED` in v1.

## Authorization (planned)

| RPC | Allowed subject |
|---|---|
| `SendNotification` | `System` with scope `notifications.send` |
| `SendNotificationBatch` | `System` with scope `notifications.send` |
| `ListUserNotifications` | `User` self **or** `System` with scope `notifications.read` |
| `MarkNotificationRead` | `User` self (the recipient) |
| `MarkAllUserNotificationsRead` | `User` self **or** `System` with scope `notifications.admin` |
| `GetUserNotificationPreferences` | `User` self **or** `System` with scope `notifications.read` |
| `UpdateUserNotificationPreferences` | `User` self **or** `System` with scope `notifications.admin` |

New scopes added to `auth.md` vocabulary: `notifications.read`, `notifications.admin` (alongside the existing `notifications.send`).

## Idempotency

`SendNotificationRequest.idempotency_key` is included in the proto today, ahead of the global idempotency-key plan deferred elsewhere. Semantics when implemented:

- Optional. Empty string → no idempotency check.
- If provided, server stores `(scope=SendNotification, key=idempotency_key, response=Notification)` for 24h.
- Replay with the same key returns the original `Notification` (not a duplicate).
- Different request body with the same key (within TTL) → `INVALID_ARGUMENT` `IDEMPOTENCY_KEY_MISMATCH`.

`SendNotificationBatch` does **not** carry a top-level idempotency key — each member request can carry its own.

## Storage (deferred)

Sketch (added to `data-model.md` at implementation time):

```sql
notifications
  id              uuid PRIMARY KEY
  user_id         uuid NOT NULL                  -- soft ref
  article_id      uuid
  kind            text NOT NULL
  channels        text[]                         -- requested channels
  payload         jsonb NOT NULL
  status          text NOT NULL                  -- 'pending' | 'delivered' | 'failed' | 'read'
  idempotency_key text                           -- nullable; (sender, key) unique within TTL
  created_at      timestamptz NOT NULL
  delivered_at    timestamptz
  read_at         timestamptz

CREATE INDEX notifications_by_user_created
  ON notifications (user_id, created_at DESC);

CREATE INDEX notifications_by_user_unread
  ON notifications (user_id, created_at DESC)
  WHERE read_at IS NULL;

notification_preferences
  user_id            uuid PRIMARY KEY REFERENCES users(id)
  disabled_channels  text[] NOT NULL DEFAULT '{}'
  disabled_kinds     text[] NOT NULL DEFAULT '{}'
  quiet_hours_enabled    boolean NOT NULL DEFAULT false
  quiet_hours_timezone   text
  quiet_hours_start_hour int
  quiet_hours_end_hour   int
  updated_at         timestamptz NOT NULL
```

Delivery worker, channel adapters (push providers, SMTP, SMS gateway), retry policy, and quiet-hours queueing — out of scope for this doc; will live under a separate `delivery.md` when implementation begins.

## v1 behavior

- Proto compiled and shipped in `proto/headlines/v1/notification.proto`.
- Service registered with the gRPC server and gateway; routes appear in OpenAPI/Swagger output.
- All RPC handlers return `UNIMPLEMENTED` with `ErrorInfo.reason = "NOT_IMPLEMENTED_IN_V1"`.
- No table created; no rows persisted.

## Cross-references

- Wire envelope, error format: `api-conventions.md`.
- Auth scopes: `auth.md` — `notifications.send`, `notifications.read` (new), `notifications.admin` (new).
- Article references: `articles.md`. User references: `users.md`.
- Future implementation doc (TBD): `docs/design/delivery.md`.
