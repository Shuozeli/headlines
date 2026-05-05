//! `AccountServiceImpl` — gRPC handler for `headlines.v1.AccountService`.
//!
//! Authoritative spec: `docs/design/accounts.md`.
//!
//! Validation, error mapping, and per-RPC authorization rules implemented per
//! that doc. The proto-driven `AUTH_TABLE` (consumed by
//! `AuthorizationLayer`) enforces the **subject class** + **system scope**
//! gate before this handler runs; the handler enforces resource-ownership
//! (`AccountOwnsResource`), bootstrap-mode rejections, and the lockout
//! protection on key revocation.

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
use headlines_core::repo::accounts::{
    Account as DomainAccount, AccountRepo, AccountStatus, AccountUpdate, NewAccount,
};
use headlines_core::repo::keys::{KeyKind, KeyRepo, KeyStatus, NewKey, StoredKey};
use headlines_proto::v1::{
    Account as ProtoAccount, AccountKey as ProtoAccountKey, AccountStatus as ProtoAccountStatus,
    AddAccountKeyRequest, CreateAccountRequest, CreateAccountResponse, DeleteAccountRequest,
    GetAccountRequest, KeyStatus as ProtoKeyStatus, RevokeAccountKeyRequest, UpdateAccountRequest,
    account_service_server::AccountService,
};

/// Bootstrap mode picked from `[auth.bootstrap].account_registration` (Phase 6
/// will load this from figment; Phase 5 lets the constructor pick it
/// directly).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapMode {
    /// Anonymous CreateAccount allowed.
    Open,
    /// Anonymous CreateAccount rejected with `REGISTRATION_DISABLED`; only
    /// systems with `accounts.write` may create.
    SystemOnly,
}

/// Concrete `AccountService` impl.
pub struct AccountServiceImpl<A, K> {
    pub accounts: Arc<A>,
    pub keys: Arc<K>,
    pub algorithms: Arc<AlgorithmRegistry>,
    pub bootstrap: BootstrapMode,
}

impl<A, K> AccountServiceImpl<A, K> {
    pub fn new(
        accounts: Arc<A>,
        keys: Arc<K>,
        algorithms: Arc<AlgorithmRegistry>,
        bootstrap: BootstrapMode,
    ) -> Self {
        Self {
            accounts,
            keys,
            algorithms,
            bootstrap,
        }
    }
}

// ---------------------------------------------------------------------------
// Validation helpers (per accounts.md "Validation" table)
// ---------------------------------------------------------------------------

const SHORT_NAME_MIN: usize = 1;
const SHORT_NAME_MAX: usize = 32;
const AUTHOR_NAME_MIN: usize = 1;
const AUTHOR_NAME_MAX: usize = 128;
const AUTHOR_URL_MAX: usize = 512;

fn validate_short_name(raw: &str) -> Result<String, HeadlinesError> {
    let trimmed = raw.trim().to_owned();
    if trimmed.len() < SHORT_NAME_MIN || trimmed.len() > SHORT_NAME_MAX {
        return Err(HeadlinesError::InvalidArgument {
            field: "short_name".into(),
            reason: format!("length must be {SHORT_NAME_MIN}..={SHORT_NAME_MAX}"),
        });
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == ' ' || c == '_' || c == '-')
    {
        return Err(HeadlinesError::InvalidArgument {
            field: "short_name".into(),
            reason: "must match [A-Za-z0-9 _-]".into(),
        });
    }
    Ok(trimmed)
}

fn validate_author_name(raw: &str) -> Result<String, HeadlinesError> {
    let trimmed = raw.trim().to_owned();
    if trimmed.len() < AUTHOR_NAME_MIN || trimmed.len() > AUTHOR_NAME_MAX {
        return Err(HeadlinesError::InvalidArgument {
            field: "author_name".into(),
            reason: format!("length must be {AUTHOR_NAME_MIN}..={AUTHOR_NAME_MAX}"),
        });
    }
    Ok(trimmed)
}

fn validate_author_url(raw: &str) -> Result<String, HeadlinesError> {
    if raw.is_empty() {
        return Ok(String::new());
    }
    if raw.len() > AUTHOR_URL_MAX {
        return Err(HeadlinesError::InvalidArgument {
            field: "author_url".into(),
            reason: format!("length must be <= {AUTHOR_URL_MAX}"),
        });
    }
    let parsed = url::Url::parse(raw).map_err(|e| HeadlinesError::InvalidArgument {
        field: "author_url".into(),
        reason: format!("invalid URL: {e}"),
    })?;
    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(HeadlinesError::InvalidArgument {
            field: "author_url".into(),
            reason: "scheme must be http or https".into(),
        });
    }
    Ok(raw.to_owned())
}

/// Validate a `PublicKey` per `accounts.md`:
///   - `algo` must be in the auth registry.
///   - `public_key` (base64) must decode into bytes accepted by the algo's
///     own format check. We don't run the algorithm's `verify` here — the
///     key isn't meant to verify anything yet; we just spot-check the
///     length expectations the algo documents (Ed25519 = 32 raw bytes).
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
    // For ed25519 the only supported algo today, the key is exactly 32 raw
    // bytes. Other algos plug their length checks in here as they're added.
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

fn account_to_proto(a: DomainAccount) -> ProtoAccount {
    let status = match a.status {
        AccountStatus::Active => ProtoAccountStatus::Active,
        AccountStatus::Deleted => ProtoAccountStatus::Deleted,
    } as i32;
    ProtoAccount {
        id: a.id.to_string(),
        short_name: a.short_name,
        author_name: a.author_name,
        author_url: a.author_url,
        status,
        deleted_at: a.deleted_at.map(ts_to_proto),
        created_at: Some(ts_to_proto(a.created_at)),
        updated_at: Some(ts_to_proto(a.updated_at)),
    }
}

fn key_to_proto(k: StoredKey) -> ProtoAccountKey {
    let status = match k.status {
        KeyStatus::Active => ProtoKeyStatus::Active,
        KeyStatus::Revoked => ProtoKeyStatus::Revoked,
    } as i32;
    ProtoAccountKey {
        account_id: k.parent_id.to_string(),
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
impl<A, K> AccountService for AccountServiceImpl<A, K>
where
    A: AccountRepo + 'static,
    K: KeyRepo + 'static,
{
    async fn create_account(
        &self,
        request: Request<CreateAccountRequest>,
    ) -> Result<Response<CreateAccountResponse>, Status> {
        let subject = current_subject(&request);
        let req = request.into_inner();

        // Bootstrap-mode check. The proto allows ANONYMOUS + SYSTEM, so
        // anything else is already rejected by `AuthorizationLayer`.
        if matches!(subject, Subject::Anonymous) && self.bootstrap == BootstrapMode::SystemOnly {
            return Err(HeadlinesError::RegistrationDisabled {
                surface: "accounts".into(),
            }
            .into());
        }

        let short_name = validate_short_name(&req.short_name).map_err(Status::from)?;
        let author_name = validate_author_name(&req.author_name).map_err(Status::from)?;
        let author_url = validate_author_url(&req.author_url).map_err(Status::from)?;

        let initial_key = req.initial_key.ok_or_else(|| {
            Status::from(HeadlinesError::InvalidArgument {
                field: "initial_key".into(),
                reason: "required".into(),
            })
        })?;
        let (algo, public_key) =
            validate_public_key(&self.algorithms, &initial_key).map_err(Status::from)?;

        // Mint UUIDv7 ids. The handler is the single mint point; the repo
        // never generates ids.
        let account_id = Uuid::now_v7();
        let key_id = Uuid::now_v7();

        let account = self
            .accounts
            .create(NewAccount {
                id: account_id,
                short_name,
                author_name,
                author_url,
            })
            .await
            .map_err(Status::from)?;

        self.keys
            .create(NewKey {
                kind: KeyKind::Account,
                parent_id: account_id,
                key_id,
                algo,
                public_key,
            })
            .await
            .map_err(Status::from)?;

        Ok(Response::new(CreateAccountResponse {
            account: Some(account_to_proto(account)),
            key_id: key_id.to_string(),
        }))
    }

    async fn get_account(
        &self,
        request: Request<GetAccountRequest>,
    ) -> Result<Response<ProtoAccount>, Status> {
        let req = request.into_inner();
        let id = parse_uuid("id", &req.id).map_err(Status::from)?;

        // Tombstone reads return 200 with status=DELETED — repo returns the
        // soft-deleted row exactly as written.
        let account = self.accounts.get(id).await.map_err(Status::from)?;
        Ok(Response::new(account_to_proto(account)))
    }

    async fn update_account(
        &self,
        request: Request<UpdateAccountRequest>,
    ) -> Result<Response<ProtoAccount>, Status> {
        let subject = current_subject(&request);
        let req = request.into_inner();

        let account_proto = req.account.ok_or_else(|| {
            Status::from(HeadlinesError::InvalidArgument {
                field: "account".into(),
                reason: "required".into(),
            })
        })?;
        let id = parse_uuid("account.id", &account_proto.id).map_err(Status::from)?;

        // Authorization: account self OR System with accounts.admin.
        let allowed = match &subject {
            Subject::Account { account_id, .. } => *account_id == id,
            Subject::System { .. } => subject.has_scope("accounts.admin"),
            _ => false,
        };
        if !allowed {
            // Per accounts.md, cross-account writes use AccountNotFound to
            // avoid leaking existence to a different Account caller.
            return Err(HeadlinesError::AccountNotFound { id }.into());
        }

        let mask = req
            .update_mask
            .ok_or_else(|| Status::from(HeadlinesError::EmptyUpdateMask))?;
        if mask.paths.is_empty() {
            return Err(HeadlinesError::EmptyUpdateMask.into());
        }

        let mut update = AccountUpdate::default();
        for path in &mask.paths {
            match path.as_str() {
                "short_name" => {
                    update.short_name =
                        Some(validate_short_name(&account_proto.short_name).map_err(Status::from)?);
                }
                "author_name" => {
                    update.author_name = Some(
                        validate_author_name(&account_proto.author_name).map_err(Status::from)?,
                    );
                }
                "author_url" => {
                    update.author_url =
                        Some(validate_author_url(&account_proto.author_url).map_err(Status::from)?);
                }
                other => {
                    return Err(HeadlinesError::UnallowedMaskPath {
                        path: other.to_owned(),
                    }
                    .into());
                }
            }
        }

        let updated = self
            .accounts
            .update(id, update)
            .await
            .map_err(Status::from)?;
        Ok(Response::new(account_to_proto(updated)))
    }

    async fn delete_account(
        &self,
        request: Request<DeleteAccountRequest>,
    ) -> Result<Response<ProtoAccount>, Status> {
        let subject = current_subject(&request);
        let req = request.into_inner();
        let id = parse_uuid("id", &req.id).map_err(Status::from)?;

        let allowed = match &subject {
            Subject::Account { account_id, .. } => *account_id == id,
            Subject::System { .. } => subject.has_scope("accounts.delete"),
            _ => false,
        };
        if !allowed {
            return Err(HeadlinesError::AccountNotFound { id }.into());
        }

        let deleted = self.accounts.soft_delete(id).await.map_err(Status::from)?;
        Ok(Response::new(account_to_proto(deleted)))
    }

    async fn add_account_key(
        &self,
        request: Request<AddAccountKeyRequest>,
    ) -> Result<Response<ProtoAccountKey>, Status> {
        let subject = current_subject(&request);
        let req = request.into_inner();
        let account_id = parse_uuid("account_id", &req.account_id).map_err(Status::from)?;

        let allowed = match &subject {
            Subject::Account {
                account_id: aid, ..
            } => *aid == account_id,
            Subject::System { .. } => subject.has_scope("accounts.admin"),
            _ => false,
        };
        if !allowed {
            return Err(HeadlinesError::AccountNotFound { id: account_id }.into());
        }

        // Refuse writes on a deleted account.
        let acct = self.accounts.get(account_id).await.map_err(Status::from)?;
        if acct.status == AccountStatus::Deleted {
            return Err(HeadlinesError::AccountDeleted { id: account_id }.into());
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
                kind: KeyKind::Account,
                parent_id: account_id,
                key_id,
                algo,
                public_key,
            })
            .await
            .map_err(Status::from)?;
        Ok(Response::new(key_to_proto(stored)))
    }

    async fn revoke_account_key(
        &self,
        request: Request<RevokeAccountKeyRequest>,
    ) -> Result<Response<ProtoAccountKey>, Status> {
        let subject = current_subject(&request);
        let req = request.into_inner();
        let account_id = parse_uuid("account_id", &req.account_id).map_err(Status::from)?;
        let key_id = parse_uuid("key_id", &req.key_id).map_err(Status::from)?;

        let allowed = match &subject {
            Subject::Account {
                account_id: aid, ..
            } => *aid == account_id,
            Subject::System { .. } => subject.has_scope("accounts.admin"),
            _ => false,
        };
        if !allowed {
            return Err(HeadlinesError::AccountNotFound { id: account_id }.into());
        }

        // Refuse writes on a deleted account, matching `add_account_key` and
        // `accounts.md`: every write on a deleted account is `ACCOUNT_DELETED`.
        // Runs BEFORE the lockout-protection block so the post-tombstone state
        // is the controlling reason — operators can't "rescue" a tombstoned
        // account by revoking its last key.
        let acct = self.accounts.get(account_id).await.map_err(Status::from)?;
        if acct.status == AccountStatus::Deleted {
            return Err(HeadlinesError::AccountDeleted { id: account_id }.into());
        }

        // Lockout protection: counting BEFORE revoke. If revoking would leave
        // zero active keys, only `admin.*` (operator rescue) may proceed.
        let active = self
            .keys
            .list_active(KeyKind::Account, account_id)
            .await
            .map_err(Status::from)?;
        let target_active = active.iter().any(|k| k.key_id == key_id);
        if target_active && active.len() == 1 && !subject.has_scope("admin.*") {
            return Err(HeadlinesError::LastActiveKey.into());
        }

        let revoked = self
            .keys
            .revoke(KeyKind::Account, account_id, key_id)
            .await
            .map_err(Status::from)?;
        Ok(Response::new(key_to_proto(revoked)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_short_name_accepts_alnum_with_separators() {
        // Arrange / Act / Assert
        assert!(validate_short_name("Cool_Pub-1").is_ok());
        assert!(validate_short_name("ab").is_ok());
    }

    #[test]
    fn validate_short_name_rejects_empty_after_trim() {
        // Arrange / Act
        let res = validate_short_name("   ");

        // Assert
        assert!(matches!(
            res,
            Err(HeadlinesError::InvalidArgument { ref field, .. }) if field == "short_name"
        ));
    }

    #[test]
    fn validate_short_name_rejects_overlength() {
        // Arrange
        let s = "x".repeat(33);

        // Act
        let res = validate_short_name(&s);

        // Assert
        assert!(matches!(res, Err(HeadlinesError::InvalidArgument { .. })));
    }

    #[test]
    fn validate_author_url_accepts_empty() {
        // Arrange / Act / Assert
        assert_eq!(validate_author_url("").unwrap(), "");
    }

    #[test]
    fn validate_author_url_rejects_overlength() {
        // Arrange
        let url = format!("https://example.com/{}", "a".repeat(600));

        // Act
        let res = validate_author_url(&url);

        // Assert
        assert!(matches!(res, Err(HeadlinesError::InvalidArgument { .. })));
    }

    #[test]
    fn validate_author_url_rejects_non_http_scheme() {
        // Arrange / Act
        let res = validate_author_url("ftp://example.com/x");

        // Assert
        assert!(matches!(res, Err(HeadlinesError::InvalidArgument { .. })));
    }
}
