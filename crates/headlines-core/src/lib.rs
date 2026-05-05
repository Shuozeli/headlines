//! `headlines-core` — domain types, error enum, trait surfaces.
//!
//! This crate is **logic only**: no I/O, no Diesel, no tonic interceptors.
//! Concrete impls live downstream:
//!   - `headlines-store` (Phase 3) provides repository implementations.
//!   - `headlines-auth` (Phase 4) provides `TimeSource`, `SignatureAlgorithm`,
//!     `NonceStore`, and `AuthStrategy` impls.
//!
//! Coverage policy: aim for **100% line coverage** on this crate. Pure logic,
//! no external state, so unit tests can fully exercise it.

pub mod auth;
pub mod error;
pub mod repo;
pub mod subject;
pub mod tso;

pub use auth::{
    AuthError, AuthStrategy, NonceError, NonceStore, SignatureAlgorithm, SignedRequestParts,
    TimeError, TimeSource, VerifyError,
};
pub use error::{ERROR_DOMAIN, HeadlinesError};
pub use subject::{Subject, SubjectClass};
pub use tso::Tso;
