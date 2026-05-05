//! Auth trait surfaces — the seams that `headlines-auth` (Phase 4) plugs
//! implementations into.
//!
//! All four traits are I/O-shaped and so use **native async fn in trait**
//! (Rust 1.75+, fully stable in the 2024 edition this workspace targets).
//! The returns are written `impl Future + Send` so each impl can avoid
//! boxing — the alternative `async fn` desugaring is hostile to
//! cross-task usage in tonic services because the resulting opaque future is
//! `?Send` by default. With the explicit `Send` bound here, all impls must
//! satisfy it; this matches how every concrete impl in `headlines-auth` will
//! actually be used (inside tonic interceptors that require `Send` futures).
//!
//! The traits are intentionally minimal — they own only the auth pipeline's
//! plug-in seams. Concrete types (`InProcessTso`, `Ed25519`, the in-memory
//! nonce LRU, the `SignedRequestStrategy`) live in `headlines-auth`.

use std::future::Future;

use uuid::Uuid;

use crate::{subject::Subject, tso::Tso};

// ---------------------------------------------------------------------------
// Time source
// ---------------------------------------------------------------------------

/// Yields and validates `Tso` values. Implementations include an in-process
/// hybrid-logical clock (default), a wall-clock fallback for dev, and any
/// future remote-TSO client.
pub trait TimeSource: Send + Sync {
    /// Allocate a fresh timestamp. Each call must produce a value strictly
    /// greater than every prior call (across restarts, per the high-water
    /// invariant in `data-model.md`).
    fn now(&self) -> impl Future<Output = Result<Tso, TimeError>> + Send;

    /// Validate a timestamp seen on the wire. Per `auth.md`:
    ///   - reject if it's in the future beyond a small forward slack;
    ///   - reject if it's older than the configured horizon (default 30s).
    fn validate(&self, ts: Tso) -> impl Future<Output = Result<(), TimeError>> + Send;
}

/// Errors a `TimeSource` may surface.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum TimeError {
    /// `validate` saw a TSO outside the replay horizon (too old or too far in
    /// the future).
    #[error("timestamp out of horizon")]
    OutsideHorizon,
    /// `now` would produce a TSO not strictly greater than the recorded
    /// high-water mark — typically because the server hasn't waited long
    /// enough after a crash recovery.
    #[error("timestamp not monotonic")]
    NonMonotonic,
    /// Catch-all for transport / persistence failures inside the time source
    /// (e.g. the `tso_high_water` flush failed).
    #[error("internal time source error: {0}")]
    Internal(String),
}

// ---------------------------------------------------------------------------
// Signature algorithms
// ---------------------------------------------------------------------------

/// Algorithm-agnostic signature verifier. The auth registry holds one impl
/// per supported `algo` string; lookup is exact-match on the wire `algo`
/// field.
pub trait SignatureAlgorithm: Send + Sync {
    /// The wire-level algorithm name (e.g. `"ed25519"`). Must be unique
    /// across the registry.
    fn name(&self) -> &'static str;

    /// Verify `signature` over `canonical` using the parsed `public_key`.
    /// Returns `Ok(())` only on a clean cryptographic success.
    fn verify(
        &self,
        public_key: &[u8],
        canonical: &[u8],
        signature: &[u8],
    ) -> Result<(), VerifyError>;
}

/// Errors a `SignatureAlgorithm::verify` may surface. All three are
/// caller-attributable; `BadSignature` is always returned without further
/// detail to avoid a cryptographic side-channel.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    #[error("malformed key: {0}")]
    MalformedKey(String),
    #[error("malformed signature")]
    MalformedSignature,
    #[error("verification failed")]
    BadSignature,
}

// ---------------------------------------------------------------------------
// Nonce store (replay protection)
// ---------------------------------------------------------------------------

/// Tracks `(key_id, nonce)` pairs seen within the replay horizon. Default
/// in-process LRU; future Redis-backed impl swaps in here for multi-node.
pub trait NonceStore: Send + Sync {
    /// Record a `(key_id, nonce, ts)` triple. Returns `Err(Replay)` if the
    /// pair has already been seen within the horizon.
    fn record(
        &self,
        key_id: Uuid,
        nonce: Vec<u8>,
        ts: Tso,
    ) -> impl Future<Output = Result<(), NonceError>> + Send;
}

/// Errors a `NonceStore` may surface.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum NonceError {
    #[error("replay detected")]
    Replay,
    /// The nonce store cannot accept the new entry without evicting another
    /// entry that is still inside the replay horizon. Returned by capacity-
    /// bounded stores under a flood that would otherwise let an attacker
    /// flush a captured victim nonce out of the window. Treat as a hard
    /// failure — better to reject than silently lose replay protection.
    #[error("nonce store at capacity within horizon")]
    Capacity,
    #[error("internal nonce store error: {0}")]
    Internal(String),
}

// ---------------------------------------------------------------------------
// Auth strategy
// ---------------------------------------------------------------------------

/// Inputs every auth strategy receives. The auth interceptor pulls these
/// fields from request metadata and the canonicalised proto body before
/// invoking `authenticate`.
#[derive(Debug, Clone)]
pub struct SignedRequestParts {
    /// HTTP-style method ("POST" for gRPC unary).
    pub method: String,
    /// Full RPC path: REST URL or gRPC `/headlines.v1.<Service>/<Rpc>`.
    pub path: String,
    /// Sorted, urlencoded `k=v&k=v` for the REST surface; empty for gRPC.
    pub canonical_query: String,
    /// SHA-256 of the canonical proto encoding of the request message.
    pub request_hash: [u8; 32],
    /// Signing key handle from the `Authorization` header.
    pub key_id: Uuid,
    /// Algorithm name from the header (`"ed25519"`, ...).
    pub algo: String,
    /// TSO timestamp from the header.
    pub ts: Tso,
    /// Random nonce from the header (≥16 bytes per `auth.md`).
    pub nonce: Vec<u8>,
    /// Detached signature bytes from the header.
    pub signature: Vec<u8>,
}

/// Resolves a request's signature material to a `Subject`. The pipeline
/// holds an ordered registry; first success wins. `SignedRequestStrategy`
/// (Phase 4) is the v1 default; mTLS / OIDC / JWT impls slot in later
/// without code changes elsewhere.
pub trait AuthStrategy: Send + Sync {
    fn authenticate(
        &self,
        parts: &SignedRequestParts,
    ) -> impl Future<Output = Result<Subject, AuthError>> + Send;
}

/// Errors an `AuthStrategy` may surface.
///
/// Each variant maps to `HeadlinesError::Unauthenticated` at the wire layer
/// (a strategy never returns `INTERNAL` — internal failures inside a strategy
/// implementation should be wrapped in `Unauthenticated` at the boundary
/// before reaching the central error mapper).
#[derive(thiserror::Error, Debug, Clone)]
pub enum AuthError {
    #[error("unauthenticated: {0}")]
    Unauthenticated(String),
    #[error("verify error: {0}")]
    Verify(#[from] VerifyError),
    #[error("time error: {0}")]
    Time(#[from] TimeError),
    #[error("nonce error: {0}")]
    Nonce(#[from] NonceError),
}
