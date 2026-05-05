//! Repository trait surfaces for every aggregate in the data model.
//!
//! These traits define the **storage seam** between the service layer
//! (`headlines-api`) and the persistence layer (`headlines-store`, Phase 3).
//! They use only Rust-side domain types — `Uuid`, `Tso`, `chrono::DateTime`,
//! and the small dedicated DTOs declared in submodules — so callers don't
//! transitively depend on Diesel or its postgres backend.
//!
//! Method signatures only. No impls live here; `headlines-store` will pick
//! these up in Phase 3 with a Diesel-async backend.
//!
//! All methods return `Result<T, HeadlinesError>` directly. Storage layers
//! map their internal errors (Diesel, deadpool, IO) into `HeadlinesError`
//! before returning — the boundary stays narrow and the central error mapper
//! handles wire conversion from there. (No separate `RepoError`: every
//! storage-layer failure is either a domain error already covered by a
//! `HeadlinesError` variant or wraps as `HeadlinesError::Internal(_)`.)

pub mod account_stream;
pub mod accounts;
pub mod articles;
pub mod drafts;
pub mod events;
pub mod feed_follow;
pub mod feed_recommendation;
pub mod follows;
pub mod keys;
pub mod systems;
pub mod users;

pub use account_stream::{AccountStreamItem, AccountStreamPage, AccountStreamRepo};
pub use accounts::{AccountRepo, AccountUpdate, NewAccount};
pub use articles::{ArticleEdit, ArticleRepo, ListArticlesPage, NewArticle};
pub use drafts::{DraftRepo, DraftUpdate, NewDraft};
pub use events::{EventRecord, EventRepo, ListEventsFilter};
pub use feed_follow::FeedFollowRepo;
pub use feed_recommendation::FeedRecommendationRepo;
pub use follows::FollowRepo;
pub use keys::{KeyKind, KeyRepo, NewKey, StoredKey};
pub use systems::SystemRepo;
pub use users::{NewUser, UserRepo, UserUpdate};

/// Opaque pagination token. Repos mint and consume the inner string; the
/// service layer never inspects it.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct PageToken(pub String);

impl PageToken {
    pub fn empty() -> Self {
        PageToken(String::new())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_page_token_is_empty_and_has_empty_str() {
        // Arrange / Act
        let token = PageToken::empty();

        // Assert
        assert!(token.is_empty());
        assert_eq!(token.as_str(), "");
    }

    #[test]
    fn non_empty_page_token_round_trips_through_as_str() {
        // Arrange
        let token = PageToken("opaque-cursor".to_owned());

        // Act / Assert
        assert!(!token.is_empty());
        assert_eq!(token.as_str(), "opaque-cursor");
    }
}
