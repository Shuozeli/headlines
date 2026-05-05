//! Diesel-async repository implementations of the `headlines-core::repo`
//! trait surfaces.
//!
//! Each module in here provides one impl of one trait, parameterised by a
//! shared `Db` pool. Rows are mapped between Diesel `Queryable`/`Insertable`
//! structs and the domain types in `headlines-core::repo::*` at the trait
//! boundary so callers never see Diesel types.

pub mod account_stream;
pub mod accounts;
pub mod articles;
pub mod drafts;
pub mod events;
pub mod feed_follow;
pub mod feed_recommendation;
pub mod follows;
pub mod keys;
pub mod users;

pub use account_stream::PgAccountStreamRepo;
pub use accounts::PgAccountRepo;
pub use articles::PgArticleRepo;
pub use drafts::PgDraftRepo;
pub use events::PgEventRepo;
pub use feed_follow::PgFeedFollowRepo;
pub use feed_recommendation::PgFeedRecommendationRepo;
pub use follows::PgFollowRepo;
pub use keys::PgKeyRepo;
pub use users::PgUserRepo;
