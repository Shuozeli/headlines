//! Authenticated identity types per `docs/design/auth.md`.
//!
//! `Subject` is what `headlines-auth` produces from a verified signed request;
//! the rest of the system reads it from request extensions to make
//! authorization decisions. `SubjectClass` is the coarse classification used
//! by the proto-driven `AUTH_TABLE` to express which classes an RPC accepts.

use uuid::Uuid;

/// The authenticated identity of a request, resolved by `headlines-auth`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Subject {
    User {
        user_id: Uuid,
        key_id: Uuid,
    },
    Account {
        account_id: Uuid,
        key_id: Uuid,
    },
    System {
        system_id: Uuid,
        key_id: Uuid,
        scopes: Vec<String>,
    },
    Anonymous,
}

/// Coarse class used by the proto-driven `AUTH_TABLE` to express which
/// subject classes an RPC accepts. Mirrors `headlines.v1.SubjectClass`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum SubjectClass {
    Anonymous,
    UserSelf,
    AccountSelf,
    AccountOwnsResource,
    System,
}

impl Subject {
    /// Map this concrete subject to the coarse `SubjectClass` consulted by
    /// the authorization layer. `AccountOwnsResource` is intentionally **not**
    /// produced here: distinguishing self-vs-owns-resource is a per-RPC
    /// concern that can't be derived from the subject alone.
    pub fn class(&self) -> SubjectClass {
        match self {
            Subject::Anonymous => SubjectClass::Anonymous,
            Subject::User { .. } => SubjectClass::UserSelf,
            Subject::Account { .. } => SubjectClass::AccountSelf,
            Subject::System { .. } => SubjectClass::System,
        }
    }

    /// True iff this subject is the User/Account whose ids are passed in.
    /// Used by service handlers to enforce `*_self` authorization rules.
    ///
    /// Both `target_user_id` and `target_account_id` are optional so callers
    /// can compare against whichever id their request carries:
    ///
    /// - A `Subject::User` matches when its `user_id` equals
    ///   `target_user_id`.
    /// - A `Subject::Account` matches when its `account_id` equals
    ///   `target_account_id`.
    /// - System and Anonymous never match — system access is gated by
    ///   `has_scope` instead, and Anonymous has no self-identity.
    pub fn is_self_for(
        &self,
        target_user_id: Option<Uuid>,
        target_account_id: Option<Uuid>,
    ) -> bool {
        match self {
            Subject::User { user_id, .. } => target_user_id == Some(*user_id),
            Subject::Account { account_id, .. } => target_account_id == Some(*account_id),
            Subject::System { .. } | Subject::Anonymous => false,
        }
    }

    /// True iff this is a `System` subject and its scopes grant `scope`,
    /// per the dotted-string vocabulary in `auth.md`.
    ///
    /// Wildcard rules:
    ///
    /// - `*` (alone) matches everything.
    /// - `prefix.*` matches any scope whose dotted-prefix equals `prefix`.
    ///   `articles.*` matches `articles.write` and `articles.redact`, but
    ///   does **not** match `articles` (no segment under the prefix).
    /// - Otherwise the scope must match exactly.
    ///
    /// Non-`System` subjects always return false. An empty `scope` argument
    /// likewise returns false — only an explicit `*` grants the empty scope.
    pub fn has_scope(&self, scope: &str) -> bool {
        let Subject::System { scopes, .. } = self else {
            return false;
        };
        if scope.is_empty() {
            // The empty scope name is meaningless; only a literal `*` blanket
            // grants it.
            return scopes.iter().any(|s| s == "*");
        }
        for granted in scopes {
            if scope_matches(granted, scope) {
                return true;
            }
        }
        false
    }
}

/// Returns true when `granted` covers `target` per the wildcard rules above.
fn scope_matches(granted: &str, target: &str) -> bool {
    if granted == "*" {
        return true;
    }
    if granted == target {
        return true;
    }
    if let Some(prefix) = granted.strip_suffix(".*") {
        // `articles.*` matches `articles.write` (one or more segments below
        // `prefix`); does not match `articles` itself.
        return target.len() > prefix.len()
            && target.starts_with(prefix)
            && target.as_bytes()[prefix.len()] == b'.';
    }
    false
}

impl TryFrom<i32> for SubjectClass {
    type Error = i32;

    /// Map a `headlines.v1.SubjectClass` proto integer to the Rust enum.
    /// `SUBJECT_CLASS_UNSPECIFIED` (0) is rejected; callers should treat it
    /// as a misconfigured `auth_requirement`.
    fn try_from(value: i32) -> Result<Self, Self::Error> {
        // These integer values are pinned by the proto enum (see
        // `proto/headlines/v1/options.proto`).
        match value {
            1 => Ok(SubjectClass::Anonymous),
            2 => Ok(SubjectClass::UserSelf),
            3 => Ok(SubjectClass::AccountSelf),
            4 => Ok(SubjectClass::AccountOwnsResource),
            5 => Ok(SubjectClass::System),
            other => Err(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(id: u128) -> Subject {
        Subject::User {
            user_id: Uuid::from_u128(id),
            key_id: Uuid::from_u128(id ^ 1),
        }
    }

    fn account(id: u128) -> Subject {
        Subject::Account {
            account_id: Uuid::from_u128(id),
            key_id: Uuid::from_u128(id ^ 1),
        }
    }

    fn system(scopes: &[&str]) -> Subject {
        Subject::System {
            system_id: Uuid::from_u128(7),
            key_id: Uuid::from_u128(8),
            scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    #[test]
    fn class_returns_expected_value_for_each_variant() {
        // Arrange / Act / Assert
        assert_eq!(Subject::Anonymous.class(), SubjectClass::Anonymous);
        assert_eq!(user(1).class(), SubjectClass::UserSelf);
        assert_eq!(account(2).class(), SubjectClass::AccountSelf);
        assert_eq!(system(&[]).class(), SubjectClass::System);
    }

    #[test]
    fn user_subject_is_self_for_matching_user_id() {
        // Arrange
        let id = Uuid::from_u128(42);
        let subj = Subject::User {
            user_id: id,
            key_id: Uuid::nil(),
        };

        // Act / Assert
        assert!(subj.is_self_for(Some(id), None));
        assert!(!subj.is_self_for(Some(Uuid::from_u128(1)), None));
        // Account-id slot is irrelevant for a User subject.
        assert!(!subj.is_self_for(None, Some(id)));
    }

    #[test]
    fn account_subject_is_self_for_matching_account_id() {
        // Arrange
        let id = Uuid::from_u128(99);
        let subj = Subject::Account {
            account_id: id,
            key_id: Uuid::nil(),
        };

        // Act / Assert
        assert!(subj.is_self_for(None, Some(id)));
        assert!(!subj.is_self_for(None, Some(Uuid::from_u128(1))));
        assert!(!subj.is_self_for(Some(id), None));
    }

    #[test]
    fn system_and_anonymous_subjects_are_never_self() {
        // Arrange
        let target = Uuid::from_u128(123);

        // Act / Assert
        assert!(!system(&["*"]).is_self_for(Some(target), Some(target)));
        assert!(!Subject::Anonymous.is_self_for(Some(target), Some(target)));
    }

    #[test]
    fn has_scope_exact_match_returns_true() {
        // Arrange
        let subj = system(&["articles.write"]);

        // Act / Assert
        assert!(subj.has_scope("articles.write"));
        assert!(!subj.has_scope("articles.read"));
    }

    #[test]
    fn has_scope_prefix_wildcard_matches_descendants() {
        // Arrange
        let subj = system(&["articles.*"]);

        // Act / Assert
        assert!(subj.has_scope("articles.write"));
        assert!(subj.has_scope("articles.tombstone"));
        assert!(subj.has_scope("articles.read"));
        // Doesn't match the bare prefix or unrelated scopes.
        assert!(!subj.has_scope("articles"));
        assert!(!subj.has_scope("accounts.write"));
    }

    #[test]
    fn has_scope_root_wildcard_matches_anything() {
        // Arrange
        let subj = system(&["*"]);

        // Act / Assert
        assert!(subj.has_scope("articles.write"));
        assert!(subj.has_scope("admin.delete"));
        assert!(subj.has_scope("anything"));
    }

    #[test]
    fn has_scope_empty_input_only_matches_root_wildcard() {
        // Arrange
        let any = system(&["*"]);
        let narrow = system(&["articles.write"]);

        // Act / Assert
        assert!(any.has_scope(""));
        assert!(!narrow.has_scope(""));
    }

    #[test]
    fn has_scope_returns_false_for_non_system_subjects() {
        // Arrange / Act / Assert
        assert!(!user(1).has_scope("articles.write"));
        assert!(!account(2).has_scope("articles.write"));
        assert!(!Subject::Anonymous.has_scope("articles.write"));
    }

    #[test]
    fn try_from_proto_subject_class_accepts_valid_values() {
        // Arrange / Act / Assert
        assert_eq!(SubjectClass::try_from(1).unwrap(), SubjectClass::Anonymous);
        assert_eq!(SubjectClass::try_from(2).unwrap(), SubjectClass::UserSelf);
        assert_eq!(
            SubjectClass::try_from(3).unwrap(),
            SubjectClass::AccountSelf
        );
        assert_eq!(
            SubjectClass::try_from(4).unwrap(),
            SubjectClass::AccountOwnsResource
        );
        assert_eq!(SubjectClass::try_from(5).unwrap(), SubjectClass::System);
    }

    #[test]
    fn try_from_proto_subject_class_rejects_unspecified_and_unknown() {
        // Arrange / Act
        let unspecified = SubjectClass::try_from(0);
        let unknown = SubjectClass::try_from(99);

        // Assert
        assert_eq!(unspecified, Err(0));
        assert_eq!(unknown, Err(99));
    }

    #[test]
    fn scope_matches_helper_requires_dotted_segment_under_prefix() {
        // Arrange / Act / Assert
        // `articles.*` matches `articles.x` but **not** the bare prefix
        // `articles` itself. (`articles.` with an empty suffix is not a
        // sensible scope and is tolerated as matching — exercised
        // separately if it ever becomes load-bearing.)
        assert!(scope_matches("articles.*", "articles.x"));
        assert!(!scope_matches("articles.*", "articles"));
        assert!(!scope_matches("articles.*", "articlesx"));
    }
}
