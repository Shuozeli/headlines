//! `headlines-auth` — concrete auth pipeline implementations.
//!
//! Phase 4 surface (per `docs/implementation-plan.md`):
//!
//! - [`algo`]   : `SignatureAlgorithm` impls + registry (`Ed25519`).
//! - [`time`]   : `TimeSource` impls (`InProcessTso`, `LocalClock`) plus the
//!   `tso_high_water` storage trait + impls.
//! - [`nonce`]  : in-memory LRU `NonceStore`.
//! - [`strategy`]: canonicalization, header parsing, and the
//!   `SignedRequestStrategy` that drives the whole authenticate flow.
//! - [`interceptor`]: tonic `tower::Layer` that pulls the header, calls the
//!   strategy, and attaches `Subject` to the request extensions.
//! - [`authorize`]  : downstream `tower::Layer` that consults the proto-driven
//!   `AUTH_TABLE` to authorize the request.
//!
//! All interfaces are object-safe so they can be plugged in via
//! `Arc<dyn Trait>` from `headlines-server`'s startup wiring.

pub mod algo;
pub mod authorize;
pub mod interceptor;
pub mod metrics;
pub mod nonce;
pub mod postgres_resolver;
pub mod strategy;
pub mod time;

pub use algo::{AlgorithmRegistry, Ed25519};
pub use authorize::AuthorizationLayer;
pub use interceptor::{AuthInterceptor, BodyHashError, BodyHasher, NoopBodyHasher, ProtoBodyHasher};
pub use metrics::{AuthMetrics, classify_auth_error};
pub use nonce::InMemoryNonceStore;
pub use postgres_resolver::PostgresKeyResolver;
pub use strategy::{
    InMemoryKeyResolver, KeyResolver, ParseError, ResolveError, ResolvedKey, SignedRequestStrategy,
    build_canonical_string, canonicalize_query, hash_proto_request, parse_authorization_header,
};
pub use time::{
    InMemoryTsoStore, InProcessTso, InProcessTsoConfig, LocalClock, PostgresTsoStore,
    TsoHighWaterStore,
};
