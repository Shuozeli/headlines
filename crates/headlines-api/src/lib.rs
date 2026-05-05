//! `headlines-api` — gRPC service implementations.
//!
//! One module per logical service, all sharing the proto-generated traits
//! from `headlines-proto::v1`. Service impls consume repository traits from
//! `headlines-core::repo` and pull authenticated subjects from request
//! extensions populated by `headlines-auth::AuthInterceptor`.

pub mod metrics;
pub mod services;

pub use metrics::DomainMetrics;
pub use services::account::{AccountServiceImpl, BootstrapMode};
pub use services::account_stream::AccountStreamServiceImpl;
pub use services::article::{ArticleServiceImpl, DEFAULT_CONTENT_MAX_BYTES};
pub use services::draft::DraftServiceImpl;
pub use services::event::{DEFAULT_EVENTS_BATCH_MAX_ITEMS, EventServiceImpl};
pub use services::feed_follow::FeedFollowServiceImpl;
pub use services::feed_recommendation::{
    DEFAULT_FEEDS_REPLACE_MAX_ITEMS, FeedRecommendationServiceImpl,
};
pub use services::follow::FollowServiceImpl;
pub use services::notification::NotificationServiceImpl;
pub use services::user::UserServiceImpl;
