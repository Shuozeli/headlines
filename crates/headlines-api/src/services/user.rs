//! `UserServiceImpl` — gRPC handler for `headlines.v1.UserService`.
//!
//! Authoritative spec: `docs/design/users.md`. Parallels
//! `services::account` — same dependency-injection shape, same lockout
//! protection, same bootstrap-mode handling. The notable differences are:
//!
//! - `GetUser` is **not** anonymous. Unauthorized callers receive
//!   `USER_NOT_FOUND` (NOT_FOUND) instead of PERMISSION_DENIED so the API
//!   does not leak user existence.
//! - There is no `AccountOwnsResource` analog: a `User` subject is the only
//!   non-System self class.

use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use prost_types::Timestamp;
use tonic::{Request, Response, Status};
use uuid::Uuid;

use headlines_auth::AlgorithmRegistry;
use headlines_core::HeadlinesError;
use headlines_core::Subject;
use headlines_core::repo::keys::{KeyKind, KeyRepo, KeyStatus, NewKey, StoredKey};
use headlines_core::repo::users::{NewUser, User as DomainUser, UserRepo, UserStatus, UserUpdate};
use headlines_proto::v1::{
    AddUserKeyRequest, CreateUserRequest, CreateUserResponse, DeleteUserRequest, GetUserRequest,
    KeyStatus as ProtoKeyStatus, RevokeUserKeyRequest, UpdateUserRequest, User as ProtoUser,
    UserKey as ProtoUserKey, UserStatus as ProtoUserStatus, user_service_server::UserService,
};

use crate::services::account::BootstrapMode;

/// Concrete `UserService` impl.
pub struct UserServiceImpl<U, K> {
    pub users: Arc<U>,
    pub keys: Arc<K>,
    pub algorithms: Arc<AlgorithmRegistry>,
    pub bootstrap: BootstrapMode,
}

impl<U, K> UserServiceImpl<U, K> {
    pub fn new(
        users: Arc<U>,
        keys: Arc<K>,
        algorithms: Arc<AlgorithmRegistry>,
        bootstrap: BootstrapMode,
    ) -> Self {
        Self {
            users,
            keys,
            algorithms,
            bootstrap,
        }
    }
}

// ---------------------------------------------------------------------------
// Validation helpers (per users.md "Validation" table)
// ---------------------------------------------------------------------------

const DISPLAY_NAME_MAX_CHARS: usize = 64;

/// `display_name`: empty allowed; otherwise 1..=64 *characters* (Unicode
/// permitted, no charset restriction); trimmed; no leading/trailing
/// whitespace.
fn validate_display_name(raw: &str) -> Result<String, HeadlinesError> {
    let trimmed = raw.trim().to_owned();
    if trimmed.is_empty() {
        // Empty is permitted per the spec.
        return Ok(String::new());
    }
    let char_count = trimmed.chars().count();
    if char_count > DISPLAY_NAME_MAX_CHARS {
        return Err(HeadlinesError::InvalidArgument {
            field: "display_name".into(),
            reason: format!("length must be <= {DISPLAY_NAME_MAX_CHARS} characters"),
        });
    }
    Ok(trimmed)
}

/// Validate a `PublicKey` per `users.md` (same shape as accounts):
///   - `algo` must be in the auth registry.
///   - `public_key` (base64) must decode into bytes accepted by the algo's
///     own format check.
fn validate_public_key(
    algos: &AlgorithmRegistry,
    pk: &headlines_proto::v1::PublicKey,
) -> Result<(String, String), HeadlinesError> {
    if pk.algo.is_empty() {
        return Err(HeadlinesError::InvalidArgument {
            field: "initial_key.algo".into(),
            reason: "algo is required".into(),
        });
    }
    if algos.get(&pk.algo).is_none() {
        return Err(HeadlinesError::UnsupportedAlgorithm {
            algo: pk.algo.clone(),
        });
    }
    let decoded =
        B64.decode(pk.public_key.as_bytes())
            .map_err(|e| HeadlinesError::InvalidPublicKey {
                reason: format!("base64 decode: {e}"),
            })?;
    if pk.algo == "ed25519" && decoded.len() != 32 {
        return Err(HeadlinesError::InvalidPublicKey {
            reason: format!("ed25519 key must be 32 bytes, got {}", decoded.len()),
        });
    }
    Ok((pk.algo.clone(), pk.public_key.clone()))
}

fn parse_uuid(field: &str, raw: &str) -> Result<Uuid, HeadlinesError> {
    Uuid::parse_str(raw).map_err(|e| HeadlinesError::InvalidArgument {
        field: field.into(),
        reason: format!("invalid uuid: {e}"),
    })
}

// ---------------------------------------------------------------------------
// Domain ↔ proto mapping
// ---------------------------------------------------------------------------

fn ts_to_proto(t: chrono::DateTime<chrono::Utc>) -> Timestamp {
    Timestamp {
        seconds: t.timestamp(),
        nanos: t.timestamp_subsec_nanos() as i32,
    }
}

fn user_to_proto(u: DomainUser) -> ProtoUser {
    let status = match u.status {
        UserStatus::Active => ProtoUserStatus::Active,
        UserStatus::Deleted => ProtoUserStatus::Deleted,
    } as i32;
    ProtoUser {
        id: u.id.to_string(),
        display_name: u.display_name,
        status,
        deleted_at: u.deleted_at.map(ts_to_proto),
        created_at: Some(ts_to_proto(u.created_at)),
    }
}

fn key_to_proto(k: StoredKey) -> ProtoUserKey {
    let status = match k.status {
        KeyStatus::Active => ProtoKeyStatus::Active,
        KeyStatus::Revoked => ProtoKeyStatus::Revoked,
    } as i32;
    ProtoUserKey {
        user_id: k.parent_id.to_string(),
        key_id: k.key_id.to_string(),
        algo: k.algo,
        public_key: k.public_key,
        status,
        created_at: Some(ts_to_proto(k.created_at)),
        revoked_at: k.revoked_at.map(ts_to_proto),
    }
}

fn current_subject<T>(req: &Request<T>) -> Subject {
    req.extensions()
        .get::<Subject>()
        .cloned()
        .unwrap_or(Subject::Anonymous)
}

// ---------------------------------------------------------------------------
// Service impl
// ---------------------------------------------------------------------------

#[async_trait]
impl<U, K> UserService for UserServiceImpl<U, K>
where
    U: UserRepo + 'static,
    K: KeyRepo + 'static,
{
    async fn create_user(
        &self,
        request: Request<CreateUserRequest>,
    ) -> Result<Response<CreateUserResponse>, Status> {
        let subject = current_subject(&request);
        let req = request.into_inner();

        // Bootstrap-mode check. The proto allows ANONYMOUS + SYSTEM, so
        // anything else is already rejected by `AuthorizationLayer`.
        if matches!(subject, Subject::Anonymous) && self.bootstrap == BootstrapMode::SystemOnly {
            return Err(HeadlinesError::RegistrationDisabled {
                surface: "users".into(),
            }
            .into());
        }

        let display_name = validate_display_name(&req.display_name).map_err(Status::from)?;

        let initial_key = req.initial_key.ok_or_else(|| {
            Status::from(HeadlinesError::InvalidArgument {
                field: "initial_key".into(),
                reason: "required".into(),
            })
        })?;
        let (algo, public_key) =
            validate_public_key(&self.algorithms, &initial_key).map_err(Status::from)?;

        let user_id = Uuid::now_v7();
        let key_id = Uuid::now_v7();

        let user = self
            .users
            .create(NewUser {
                id: user_id,
                display_name,
            })
            .await
            .map_err(Status::from)?;

        self.keys
            .create(NewKey {
                kind: KeyKind::User,
                parent_id: user_id,
                key_id,
                algo,
                public_key,
            })
            .await
            .map_err(Status::from)?;

        Ok(Response::new(CreateUserResponse {
            user: Some(user_to_proto(user)),
            key_id: key_id.to_string(),
        }))
    }

    async fn get_user(
        &self,
        request: Request<GetUserRequest>,
    ) -> Result<Response<ProtoUser>, Status> {
        let subject = current_subject(&request);
        let req = request.into_inner();
        let id = parse_uuid("id", &req.id).map_err(Status::from)?;

        // Privacy: only self or System with `users.read` may read a user.
        // The proto-level gate already requires UserSelf or System, but
        // a User subject reading a *different* user's row must still get
        // USER_NOT_FOUND — not a 200 — so we recheck self-ness here.
        let allowed = match &subject {
            Subject::User { user_id, .. } => *user_id == id,
            Subject::System { .. } => subject.has_scope("users.read"),
            _ => false,
        };
        if !allowed {
            return Err(HeadlinesError::UserNotFound { id }.into());
        }

        // Tombstone reads return 200 with status=DELETED — repo returns the
        // soft-deleted row exactly as written.
        let user = self.users.get(id).await.map_err(Status::from)?;
        Ok(Response::new(user_to_proto(user)))
    }

    async fn update_user(
        &self,
        request: Request<UpdateUserRequest>,
    ) -> Result<Response<ProtoUser>, Status> {
        let subject = current_subject(&request);
        let req = request.into_inner();

        let user_proto = req.user.ok_or_else(|| {
            Status::from(HeadlinesError::InvalidArgument {
                field: "user".into(),
                reason: "required".into(),
            })
        })?;
        let id = parse_uuid("user.id", &user_proto.id).map_err(Status::from)?;

        // Authorization: user self OR System with users.admin.
        let allowed = match &subject {
            Subject::User { user_id, .. } => *user_id == id,
            Subject::System { .. } => subject.has_scope("users.admin"),
            _ => false,
        };
        if !allowed {
            // Per users.md, cross-user writes use UserNotFound to avoid
            // leaking existence to a different User caller.
            return Err(HeadlinesError::UserNotFound { id }.into());
        }

        let mask = req
            .update_mask
            .ok_or_else(|| Status::from(HeadlinesError::EmptyUpdateMask))?;
        if mask.paths.is_empty() {
            return Err(HeadlinesError::EmptyUpdateMask.into());
        }

        let mut update = UserUpdate::default();
        for path in &mask.paths {
            match path.as_str() {
                "display_name" => {
                    update.display_name = Some(
                        validate_display_name(&user_proto.display_name).map_err(Status::from)?,
                    );
                }
                other => {
                    return Err(HeadlinesError::UnallowedMaskPath {
                        path: other.to_owned(),
                    }
                    .into());
                }
            }
        }

        let updated = self.users.update(id, update).await.map_err(Status::from)?;
        Ok(Response::new(user_to_proto(updated)))
    }

    async fn delete_user(
        &self,
        request: Request<DeleteUserRequest>,
    ) -> Result<Response<ProtoUser>, Status> {
        let subject = current_subject(&request);
        let req = request.into_inner();
        let id = parse_uuid("id", &req.id).map_err(Status::from)?;

        let allowed = match &subject {
            Subject::User { user_id, .. } => *user_id == id,
            Subject::System { .. } => subject.has_scope("users.delete"),
            _ => false,
        };
        if !allowed {
            return Err(HeadlinesError::UserNotFound { id }.into());
        }

        let deleted = self.users.soft_delete(id).await.map_err(Status::from)?;
        Ok(Response::new(user_to_proto(deleted)))
    }

    async fn add_user_key(
        &self,
        request: Request<AddUserKeyRequest>,
    ) -> Result<Response<ProtoUserKey>, Status> {
        let subject = current_subject(&request);
        let req = request.into_inner();
        let user_id = parse_uuid("user_id", &req.user_id).map_err(Status::from)?;

        let allowed = match &subject {
            Subject::User { user_id: uid, .. } => *uid == user_id,
            Subject::System { .. } => subject.has_scope("users.admin"),
            _ => false,
        };
        if !allowed {
            return Err(HeadlinesError::UserNotFound { id: user_id }.into());
        }

        // Refuse writes on a deleted user.
        let user = self.users.get(user_id).await.map_err(Status::from)?;
        if user.status == UserStatus::Deleted {
            return Err(HeadlinesError::UserDeleted { id: user_id }.into());
        }

        let pk = req.key.ok_or_else(|| {
            Status::from(HeadlinesError::InvalidArgument {
                field: "key".into(),
                reason: "required".into(),
            })
        })?;
        let (algo, public_key) =
            validate_public_key(&self.algorithms, &pk).map_err(Status::from)?;

        let key_id = Uuid::now_v7();
        let stored = self
            .keys
            .create(NewKey {
                kind: KeyKind::User,
                parent_id: user_id,
                key_id,
                algo,
                public_key,
            })
            .await
            .map_err(Status::from)?;
        Ok(Response::new(key_to_proto(stored)))
    }

    async fn revoke_user_key(
        &self,
        request: Request<RevokeUserKeyRequest>,
    ) -> Result<Response<ProtoUserKey>, Status> {
        let subject = current_subject(&request);
        let req = request.into_inner();
        let user_id = parse_uuid("user_id", &req.user_id).map_err(Status::from)?;
        let key_id = parse_uuid("key_id", &req.key_id).map_err(Status::from)?;

        let allowed = match &subject {
            Subject::User { user_id: uid, .. } => *uid == user_id,
            Subject::System { .. } => subject.has_scope("users.admin"),
            _ => false,
        };
        if !allowed {
            return Err(HeadlinesError::UserNotFound { id: user_id }.into());
        }

        // Lockout protection: counting BEFORE revoke. If revoking would
        // leave zero active keys, only `admin.*` (operator rescue) may
        // proceed.
        let active = self
            .keys
            .list_active(KeyKind::User, user_id)
            .await
            .map_err(Status::from)?;
        let target_active = active.iter().any(|k| k.key_id == key_id);
        if target_active && active.len() == 1 && !subject.has_scope("admin.*") {
            return Err(HeadlinesError::LastActiveKey.into());
        }

        let revoked = self
            .keys
            .revoke(KeyKind::User, user_id, key_id)
            .await
            .map_err(Status::from)?;
        Ok(Response::new(key_to_proto(revoked)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_display_name_accepts_empty() {
        // Arrange / Act / Assert
        assert_eq!(validate_display_name("").unwrap(), "");
        assert_eq!(validate_display_name("   ").unwrap(), "");
    }

    #[test]
    fn validate_display_name_accepts_unicode() {
        // Arrange / Act / Assert
        assert_eq!(validate_display_name("Renée 🦊").unwrap(), "Renée 🦊");
    }

    #[test]
    fn validate_display_name_rejects_overlength() {
        // Arrange — 65 ASCII chars
        let s = "x".repeat(65);

        // Act
        let res = validate_display_name(&s);

        // Assert
        assert!(matches!(
            res,
            Err(HeadlinesError::InvalidArgument { ref field, .. }) if field == "display_name"
        ));
    }

    #[test]
    fn validate_display_name_counts_chars_not_bytes() {
        // Arrange — 64 fox emoji = 64 chars but ~256 bytes; must be allowed.
        let s: String = "🦊".repeat(64);

        // Act
        let res = validate_display_name(&s);

        // Assert
        assert_eq!(res.unwrap().chars().count(), 64);
    }
}
