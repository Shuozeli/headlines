# API Conventions

Status: agreed (v1)
Scope: protocol, naming, errors, pagination, auth header shape, field conventions. Per-component docs (`accounts.md`, `articles.md`, ...) define specific RPCs/messages and rely on the conventions here.

## Protocol

**gRPC is the first-class surface.** REST/JSON is a secondary surface generated from proto.

- gRPC server (Rust, tonic-class implementation — concrete crate selection deferred to `architecture.md`).
- REST/JSON via `google.api.http` annotations on each RPC. The bridging mechanism (in-process axum bridge vs external grpc-gateway) is an architecture decision deferred to `architecture.md`.
- OpenAPI/Swagger JSON generated from the same proto definitions (e.g. `protoc-gen-openapiv2` or equivalent). Served at a stable path (e.g. `/openapi.json`); exact path deferred.

## Versioning

- Proto package: `headlines.v1`.
- gRPC service names: `headlines.v1.AccountService`, `headlines.v1.ArticleService`, etc.
- REST URL prefix: `/v1/...` via `google.api.http` annotations.
- Bumping to `v2` means a new proto package, new URL prefix, and new service definitions; v1 and v2 coexist during migration. No silent breaking changes inside `v1`.

## Service & RPC naming

- One service per logical surface (`AccountService`, `ArticleService`, `DraftService`, `UserService`, `FollowService`, `FeedService`, `EventService`, `NotificationService`).
- RPC names are verbs in `PascalCase`: `CreateAccount`, `GetAccount`, `ListAccountArticles`, `PublishDraft`, `TombstoneArticle`, `ReplaceRecommendationFeed`.
- Standard verbs (Google AIP-style): `Create`, `Get`, `List`, `Update`, `Delete`, plus domain verbs (`Publish`, `Tombstone`, `Follow`, `Unfollow`, `Replace*Feed`, `Redact*`).
- Each service lives in its own proto file under `proto/headlines/v1/`.

## REST mapping

Generated from `google.api.http` annotations on RPCs.

```proto
service ArticleService {
  rpc GetArticle(GetArticleRequest) returns (Article) {
    option (google.api.http) = { get: "/v1/articles/{id}" };
  }
  rpc ListAccountArticles(ListAccountArticlesRequest) returns (ListAccountArticlesResponse) {
    option (google.api.http) = { get: "/v1/accounts/{account_id}/articles" };
  }
  rpc TombstoneArticle(TombstoneArticleRequest) returns (Article) {
    option (google.api.http) = { post: "/v1/articles/{id}/tombstone" body: "*" };
  }
}
```

REST URL conventions:
- Plural nouns: `/v1/accounts`, `/v1/articles`, `/v1/drafts`, `/v1/users`, `/v1/follows`.
- Sub-resources for parent-scoped lists: `/v1/accounts/{account_id}/articles`, `/v1/users/{user_id}/feed/recommendation`.
- Action endpoints for non-CRUD verbs: `POST /v1/articles/{id}/tombstone`, `POST /v1/drafts/{id}/publish`, `POST /v1/accounts/{id}/keys`.

## Errors

gRPC: `google.rpc.Status` with standard `google.rpc.Code`. Domain-specific detail attached via `google.rpc.ErrorInfo`:

```
status.code:    NOT_FOUND
status.message: "Article not found"
details: [
  ErrorInfo {
    reason: "ARTICLE_NOT_FOUND"
    domain: "headlines.v1"
    metadata: { "article_id": "0192a-..." }
  }
]
```

REST mapping (standard grpc-gateway):

| gRPC code | HTTP status |
|---|---|
| `OK` | 200 |
| `INVALID_ARGUMENT` | 400 |
| `UNAUTHENTICATED` | 401 |
| `PERMISSION_DENIED` | 403 |
| `NOT_FOUND` | 404 |
| `ALREADY_EXISTS` | 409 |
| `FAILED_PRECONDITION` | 400 |
| `RESOURCE_EXHAUSTED` | 429 |
| `UNIMPLEMENTED` | 501 |
| `INTERNAL` | 500 |
| `UNAVAILABLE` | 503 |

REST error JSON body mirrors `google.rpc.Status`:

```json
{
  "code": 5,
  "message": "Article not found",
  "details": [
    {
      "@type": "type.googleapis.com/google.rpc.ErrorInfo",
      "reason": "ARTICLE_NOT_FOUND",
      "domain": "headlines.v1",
      "metadata": { "article_id": "0192a-..." }
    }
  ]
}
```

## Pagination

Google AIP style: `page_size` + `page_token` in requests, `next_page_token` in responses.

```proto
message ListAccountArticlesRequest {
  string account_id = 1;
  int32 page_size = 2;       // default 50, max 200
  string page_token = 3;     // empty for first page
}

message ListAccountArticlesResponse {
  repeated Article items = 1;
  string next_page_token = 2;  // empty when no more pages
}
```

- `page_token` is server-issued, opaque to clients. Internally encodes the stable sort key `(created_at, id)` (or equivalent per endpoint).
- `page_size` clamped server-side to `[1, 200]`; default 50.
- A response with empty `next_page_token` indicates end of stream.

## Auth header

gRPC metadata key `authorization`; REST `Authorization` header. Same value:

```
Signature key_id=<uuid>, algo=<algo>, ts=<unix>, nonce=<base64>, sig=<base64>
```

Full canonicalization, signed payload, and replay-protection rules live in `docs/design/auth.md`. This doc only fixes the wire shape so other docs can reference it.

## Field naming & types

- **All proto field names: `snake_case`** (matches proto3 default).
- **JSON output keeps `snake_case`**, not the proto3-default lowerCamelCase. Configure the proto-to-JSON layer accordingly (`preserve_proto_field_names` or equivalent).
- Telegraph `Node` content (article body) is carried as a structured proto message (defined in `articles.md`); we do **not** preserve Telegraph's camelCase wire format inside our payloads.
- Timestamps: `google.protobuf.Timestamp` in proto; RFC 3339 UTC string in JSON (`2026-04-30T12:34:56Z`). All timestamps are UTC; we reject TZ-naive values from clients.
- IDs: UUID canonical hex string (8-4-4-4-12). Proto type: `string` (not `bytes`).
- Slugs: lowercase ASCII `[a-z0-9-]`, max length defined in `articles.md`.

## Tombstone & soft-delete representation

- `GetArticle` for a tombstoned article: returns `Article` with `state = TOMBSTONE`, `slug`, `tombstoned_at`, no content. HTTP **200**, not 410.
- `GetAccount` for a deleted account: returns `Account` with `status = DELETED`, `deleted_at` set. HTTP **200**.
- `ListAccountArticles` filters tombstoned by default; opt-in flag `include_tombstoned` to surface them.
- Drafts: hard-deleted, so `GetDraft` of a deleted draft returns `NOT_FOUND`.

## Content-Type (REST)

- Request and response: `application/json; charset=utf-8`.
- Other types: HTTP 415 (`UNSUPPORTED_MEDIA_TYPE`).
- gRPC uses `application/grpc` per spec; not negotiated.

## Idempotency

**Deferred.** Recommendation feed `Replace` is naturally idempotent. If/when a non-idempotent writer needs it, add an `Idempotency-Key` REST header / `idempotency-key` gRPC metadata, store `(key, response)` for 24h, replay returns cached response. Not implemented in v1.

## Rate limiting

**Out of scope for v1.** No `X-RateLimit-*` headers, no `RESOURCE_EXHAUSTED` shaping. Revisit when traffic warrants.

## Tooling

Concrete proto toolchain choices (`buf`, `tonic-build`, `protoc-gen-openapiv2`, etc.) deferred to `docs/design/architecture.md`. This doc is protocol-shape only.
