//! `SignedRequestStrategy` — canonicalize, verify, validate timestamp,
//! enforce replay protection, and resolve the caller's `Subject`.
//!
//! All wire-shape decisions match `docs/design/auth.md` to the letter:
//!
//! - Canonical string layout: `HEADLINES-SIGN-V1\n<METHOD>\n<PATH>\n<QUERY>\n<HASH_HEX>\n<KEY_ID>\n<TS>\n<NONCE_B64>`.
//! - Default request hash: SHA-256 of canonical proto encoding (callers
//!   produce this; the strategy receives `[u8; 32]`).
//! - Authorization header format: `Signature key_id=…, algo=…, ts=…,
//!   nonce=…, sig=…` (per `api-conventions.md`).

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use prost::Message;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use headlines_core::{
    AuthError, AuthStrategy, NonceStore, SignedRequestParts, Subject, TimeError, TimeSource, Tso,
    VerifyError,
};

use crate::algo::AlgorithmRegistry;

// ---------------------------------------------------------------------------
// Key resolver
// ---------------------------------------------------------------------------

/// Resolves a `key_id` to its public key, algorithm, and the `Subject` it
/// authenticates as.
#[async_trait]
pub trait KeyResolver: Send + Sync {
    async fn resolve(&self, key_id: Uuid) -> Result<ResolvedKey, ResolveError>;
}

/// What `KeyResolver::resolve` returns on success.
#[derive(Debug, Clone)]
pub struct ResolvedKey {
    pub algo: String,
    pub public_key: Vec<u8>,
    pub subject: Subject,
}

/// Errors `KeyResolver` may surface.
#[derive(thiserror::Error, Debug, Clone)]
pub enum ResolveError {
    #[error("key not found")]
    NotFound,
    #[error("key revoked")]
    Revoked,
    #[error("internal: {0}")]
    Internal(String),
}

/// In-memory `KeyResolver` for tests. Phase 5 ships a Postgres-backed impl in
/// `headlines-store`.
#[derive(Debug, Default, Clone)]
pub struct InMemoryKeyResolver {
    keys: HashMap<Uuid, KeyEntry>,
}

#[derive(Debug, Clone)]
struct KeyEntry {
    algo: String,
    public_key: Vec<u8>,
    subject: Subject,
    revoked: bool,
}

impl InMemoryKeyResolver {
    /// Empty resolver — every `resolve` call returns `NotFound`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an active key.
    pub fn insert(
        mut self,
        key_id: Uuid,
        algo: impl Into<String>,
        public_key: Vec<u8>,
        subject: Subject,
    ) -> Self {
        self.keys.insert(
            key_id,
            KeyEntry {
                algo: algo.into(),
                public_key,
                subject,
                revoked: false,
            },
        );
        self
    }

    /// Register a key already in the revoked state — used to test the reject
    /// path.
    pub fn insert_revoked(
        mut self,
        key_id: Uuid,
        algo: impl Into<String>,
        public_key: Vec<u8>,
        subject: Subject,
    ) -> Self {
        self.keys.insert(
            key_id,
            KeyEntry {
                algo: algo.into(),
                public_key,
                subject,
                revoked: true,
            },
        );
        self
    }
}

#[async_trait]
impl KeyResolver for InMemoryKeyResolver {
    async fn resolve(&self, key_id: Uuid) -> Result<ResolvedKey, ResolveError> {
        let entry = self.keys.get(&key_id).ok_or(ResolveError::NotFound)?;
        if entry.revoked {
            return Err(ResolveError::Revoked);
        }
        Ok(ResolvedKey {
            algo: entry.algo.clone(),
            public_key: entry.public_key.clone(),
            subject: entry.subject.clone(),
        })
    }
}

// ---------------------------------------------------------------------------
// Canonicalization
// ---------------------------------------------------------------------------

/// Build the canonical signing string per `auth.md`.
///
/// ```text
/// HEADLINES-SIGN-V1
/// <METHOD>
/// <PATH>
/// <CANONICAL_QUERY>
/// <REQUEST_HASH_HEX>
/// <KEY_ID>
/// <TS>
/// <NONCE_BASE64>
/// ```
pub fn build_canonical_string(parts: &SignedRequestParts) -> String {
    let hash_hex = hex_encode(&parts.request_hash);
    let nonce_b64 = B64.encode(&parts.nonce);
    format!(
        "HEADLINES-SIGN-V1\n{method}\n{path}\n{query}\n{hash}\n{key_id}\n{ts}\n{nonce}",
        method = parts.method,
        path = parts.path,
        query = parts.canonical_query,
        hash = hash_hex,
        key_id = parts.key_id,
        ts = parts.ts.as_u64(),
        nonce = nonce_b64,
    )
}

/// SHA-256 of the canonical proto encoding of `msg`. Used by the wire layer
/// to populate `SignedRequestParts::request_hash`.
///
/// Determinism note: prost's default encoder writes fields in tag order, so
/// the byte output is stable for the same logical message — including the
/// "all-defaults" case (an empty `*Request` proto encodes to zero bytes,
/// hashing to the well-known SHA-256 of the empty string).
pub fn hash_proto_request<M: Message>(msg: &M) -> [u8; 32] {
    let bytes = msg.encode_to_vec();
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    hasher.finalize().into()
}

/// Canonicalize a raw URI query string per `auth.md`: keys sorted
/// lexicographically, values for the same key kept in their original
/// per-key order, joined as `k1=v1&k1=v2&k2=v3`. Percent-encoding is
/// preserved verbatim (we never decode the bytes — the canonical form
/// must round-trip whatever the client signed).
///
/// An empty input yields an empty string. A pair without `=` is kept as
/// `k=` (key only). This shape is consumed both by the server-side
/// interceptor (when constructing `SignedRequestParts`) and by any
/// client-side signer building the canonical string.
pub fn canonicalize_query(raw: &str) -> String {
    if raw.is_empty() {
        return String::new();
    }

    // Walk the input once, recording each pair as `(key, value)` while
    // preserving the original per-key value order. Sorting is stable, so
    // the resulting iterator order over a sorted `Vec` keeps that
    // per-key ordering intact.
    let mut pairs: Vec<(&str, &str)> = Vec::new();
    for raw_pair in raw.split('&') {
        if raw_pair.is_empty() {
            continue;
        }
        match raw_pair.split_once('=') {
            Some((k, v)) => pairs.push((k, v)),
            None => pairs.push((raw_pair, "")),
        }
    }
    pairs.sort_by(|a, b| a.0.cmp(b.0));

    let mut out = String::with_capacity(raw.len());
    for (i, (k, v)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        out.push_str(k);
        out.push('=');
        out.push_str(v);
    }
    out
}

/// Lower-case hex encoding without external deps.
fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(*b >> 4) as usize] as char);
        out.push(HEX[(*b & 0x0F) as usize] as char);
    }
    out
}

// ---------------------------------------------------------------------------
// Authorization header parsing
// ---------------------------------------------------------------------------

/// Subset of `SignedRequestParts` that comes from the `Authorization` header
/// alone — the wire-only fields. Method, path, query, and request hash are
/// filled in by the interceptor before the strategy is invoked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedAuthHeader {
    pub key_id: Uuid,
    pub algo: String,
    pub ts: Tso,
    pub nonce: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Errors `parse_authorization_header` may surface. Each variant covers a
/// distinct rejection branch; tests assert one per branch.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    #[error("missing scheme prefix `Signature `")]
    MissingScheme,
    #[error("malformed pair: {0}")]
    MalformedPair(String),
    #[error("unknown field: {0}")]
    UnknownField(String),
    #[error("missing field: {0}")]
    MissingField(&'static str),
    #[error("malformed key_id: {0}")]
    MalformedKeyId(String),
    #[error("malformed ts: {0}")]
    MalformedTs(String),
    #[error("malformed base64 in field {field}")]
    MalformedBase64 { field: &'static str },
    #[error("non-utf8 input")]
    NonUtf8,
}

const KNOWN_FIELDS: &[&str] = &["key_id", "algo", "ts", "nonce", "sig"];

/// Strict parser for the `Signature key_id=…, algo=…, ts=…, nonce=…, sig=…`
/// header.
pub fn parse_authorization_header(value: &str) -> Result<ParsedAuthHeader, ParseError> {
    if !value.is_ascii() {
        return Err(ParseError::NonUtf8);
    }

    let body = value
        .strip_prefix("Signature ")
        .ok_or(ParseError::MissingScheme)?;

    let mut key_id: Option<Uuid> = None;
    let mut algo: Option<String> = None;
    let mut ts: Option<Tso> = None;
    let mut nonce: Option<Vec<u8>> = None;
    let mut sig: Option<Vec<u8>> = None;

    for raw in body.split(',') {
        let pair = raw.trim();
        if pair.is_empty() {
            return Err(ParseError::MalformedPair("empty pair".into()));
        }
        let (k, v) = pair
            .split_once('=')
            .ok_or_else(|| ParseError::MalformedPair(pair.to_owned()))?;
        let k = k.trim();
        let v = v.trim();
        if !KNOWN_FIELDS.contains(&k) {
            return Err(ParseError::UnknownField(k.to_owned()));
        }
        match k {
            "key_id" => {
                let parsed =
                    Uuid::parse_str(v).map_err(|e| ParseError::MalformedKeyId(e.to_string()))?;
                key_id = Some(parsed);
            }
            "algo" => {
                algo = Some(v.to_owned());
            }
            "ts" => {
                let raw_u64: u64 = v
                    .parse()
                    .map_err(|e: std::num::ParseIntError| ParseError::MalformedTs(e.to_string()))?;
                ts = Some(Tso::from_raw(raw_u64));
            }
            "nonce" => {
                let bytes = B64
                    .decode(v)
                    .map_err(|_| ParseError::MalformedBase64 { field: "nonce" })?;
                nonce = Some(bytes);
            }
            "sig" => {
                let bytes = B64
                    .decode(v)
                    .map_err(|_| ParseError::MalformedBase64 { field: "sig" })?;
                sig = Some(bytes);
            }
            _ => unreachable!("KNOWN_FIELDS gate"),
        }
    }

    Ok(ParsedAuthHeader {
        key_id: key_id.ok_or(ParseError::MissingField("key_id"))?,
        algo: algo.ok_or(ParseError::MissingField("algo"))?,
        ts: ts.ok_or(ParseError::MissingField("ts"))?,
        nonce: nonce.ok_or(ParseError::MissingField("nonce"))?,
        signature: sig.ok_or(ParseError::MissingField("sig"))?,
    })
}

// ---------------------------------------------------------------------------
// Strategy
// ---------------------------------------------------------------------------

/// Object-safe shims around `TimeSource` / `NonceStore`. The core traits use
/// native `async fn in trait` (per `headlines-core::auth`), which makes them
/// not dyn-compatible. We store boxed-future adapters internally so the
/// strategy is non-generic and ergonomic to plug into `Arc<dyn AuthStrategy>`
/// without leaking type parameters everywhere.
mod object_safety {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;

    use headlines_core::{NonceError, NonceStore, TimeError, TimeSource, Tso};
    use uuid::Uuid;

    pub trait DynTimeSource: Send + Sync {
        fn validate<'a>(
            &'a self,
            ts: Tso,
        ) -> Pin<Box<dyn Future<Output = Result<(), TimeError>> + Send + 'a>>;
    }

    impl<T: TimeSource> DynTimeSource for T {
        fn validate<'a>(
            &'a self,
            ts: Tso,
        ) -> Pin<Box<dyn Future<Output = Result<(), TimeError>> + Send + 'a>> {
            Box::pin(TimeSource::validate(self, ts))
        }
    }

    pub trait DynNonceStore: Send + Sync {
        fn record<'a>(
            &'a self,
            key_id: Uuid,
            nonce: Vec<u8>,
            ts: Tso,
        ) -> Pin<Box<dyn Future<Output = Result<(), NonceError>> + Send + 'a>>;
    }

    impl<T: NonceStore> DynNonceStore for T {
        fn record<'a>(
            &'a self,
            key_id: Uuid,
            nonce: Vec<u8>,
            ts: Tso,
        ) -> Pin<Box<dyn Future<Output = Result<(), NonceError>> + Send + 'a>> {
            Box::pin(NonceStore::record(self, key_id, nonce, ts))
        }
    }

    pub fn erase_time<T: TimeSource + 'static>(t: Arc<T>) -> Arc<dyn DynTimeSource> {
        t
    }

    pub fn erase_nonce<T: NonceStore + 'static>(t: Arc<T>) -> Arc<dyn DynNonceStore> {
        t
    }
}

use object_safety::{DynNonceStore, DynTimeSource};

/// Default `AuthStrategy` for v1 — signed requests per `auth.md`.
pub struct SignedRequestStrategy {
    resolver: Arc<dyn KeyResolver>,
    algos: Arc<AlgorithmRegistry>,
    time_source: Arc<dyn DynTimeSource>,
    nonce_store: Arc<dyn DynNonceStore>,
}

impl SignedRequestStrategy {
    /// Build the strategy from its plug-in parts.
    pub fn new<T, N>(
        resolver: Arc<dyn KeyResolver>,
        algos: Arc<AlgorithmRegistry>,
        time_source: Arc<T>,
        nonce_store: Arc<N>,
    ) -> Self
    where
        T: TimeSource + 'static,
        N: NonceStore + 'static,
    {
        Self {
            resolver,
            algos,
            time_source: object_safety::erase_time(time_source),
            nonce_store: object_safety::erase_nonce(nonce_store),
        }
    }
}

impl SignedRequestStrategy {
    async fn authenticate_inner(&self, parts: &SignedRequestParts) -> Result<Subject, AuthError> {
        // 1. Resolve the key id → (algo, public_key, subject).
        let resolved = match self.resolver.resolve(parts.key_id).await {
            Ok(k) => k,
            Err(ResolveError::NotFound) => {
                return Err(AuthError::Unauthenticated("unknown_key".into()));
            }
            Err(ResolveError::Revoked) => {
                return Err(AuthError::Unauthenticated("key revoked".into()));
            }
            Err(ResolveError::Internal(e)) => {
                return Err(AuthError::Unauthenticated(format!("resolver: {e}")));
            }
        };

        // 2. Algo on the wire must match the algo recorded on the key.
        if parts.algo != resolved.algo {
            return Err(AuthError::Unauthenticated("algo_mismatch".into()));
        }

        // 3. Look up the named algorithm impl.
        let algo = self
            .algos
            .get(&parts.algo)
            .ok_or_else(|| AuthError::Unauthenticated("unsupported_algo".into()))?;

        // 4. Build canonical string.
        let canonical = build_canonical_string(parts);

        // 5. Verify signature.
        if let Err(e) = algo.verify(&resolved.public_key, canonical.as_bytes(), &parts.signature) {
            return Err(match e {
                VerifyError::BadSignature => AuthError::Unauthenticated("bad_signature".into()),
                VerifyError::MalformedKey(_) => AuthError::Unauthenticated("malformed_key".into()),
                VerifyError::MalformedSignature => {
                    AuthError::Unauthenticated("malformed_signature".into())
                }
            });
        }

        // 6. Validate timestamp against the time source.
        if let Err(e) = self.time_source.validate(parts.ts).await {
            return Err(match e {
                TimeError::OutsideHorizon => AuthError::Unauthenticated("expired".into()),
                TimeError::NonMonotonic => AuthError::Unauthenticated("future_ts".into()),
                TimeError::Internal(s) => AuthError::Unauthenticated(format!("time: {s}")),
            });
        }

        // 7. Replay protection.
        if let Err(e) = self
            .nonce_store
            .record(parts.key_id, parts.nonce.clone(), parts.ts)
            .await
        {
            return Err(match e {
                headlines_core::NonceError::Replay => AuthError::Unauthenticated("replay".into()),
                headlines_core::NonceError::Capacity => {
                    AuthError::Unauthenticated("nonce_store_full".into())
                }
                headlines_core::NonceError::Internal(s) => {
                    AuthError::Unauthenticated(format!("nonce: {s}"))
                }
            });
        }

        Ok(resolved.subject)
    }
}

impl AuthStrategy for SignedRequestStrategy {
    fn authenticate(
        &self,
        parts: &SignedRequestParts,
    ) -> impl Future<Output = Result<Subject, AuthError>> + Send {
        self.authenticate_inner(parts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nonce::InMemoryNonceStore;
    use crate::time::{InMemoryTsoStore, InProcessTso, InProcessTsoConfig, MockClock};
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    // ----- helpers -----------------------------------------------------------

    fn signing_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn account_subject() -> Subject {
        Subject::Account {
            account_id: Uuid::from_u128(0xACC),
            key_id: Uuid::from_u128(0xBEEF),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn make_parts(
        method: &str,
        path: &str,
        query: &str,
        request_hash: [u8; 32],
        key_id: Uuid,
        algo: &str,
        ts: Tso,
        nonce: Vec<u8>,
        signature: Vec<u8>,
    ) -> SignedRequestParts {
        SignedRequestParts {
            method: method.to_owned(),
            path: path.to_owned(),
            canonical_query: query.to_owned(),
            request_hash,
            key_id,
            algo: algo.to_owned(),
            ts,
            nonce,
            signature,
        }
    }

    /// Build a clock-driven InProcessTso whose wall-clock can be advanced.
    async fn fixed_tso(now_ms: u64) -> (InProcessTso<Arc<MockClock>>, Arc<MockClock>) {
        let clock = Arc::new(MockClock::new(now_ms));
        let store = Arc::new(InMemoryTsoStore::new());
        let cfg = InProcessTsoConfig {
            horizon_ms: 30_000,
            flush_interval_ms: 0,
        };
        let tso = InProcessTso::new_with_clock(store, cfg, clock.clone())
            .await
            .unwrap();
        (tso, clock)
    }

    fn signed_parts_for(
        sk: &SigningKey,
        key_id: Uuid,
        ts: Tso,
        nonce: Vec<u8>,
    ) -> SignedRequestParts {
        let mut parts = make_parts(
            "POST",
            "/headlines.v1.AccountService/CreateAccount",
            "",
            [0u8; 32],
            key_id,
            "ed25519",
            ts,
            nonce,
            Vec::new(),
        );
        let canonical = build_canonical_string(&parts);
        parts.signature = sk.sign(canonical.as_bytes()).to_bytes().to_vec();
        parts
    }

    // ----- canonicalization & hashing ---------------------------------------

    #[test]
    fn build_canonical_string_matches_documented_layout() {
        // Arrange
        let parts = make_parts(
            "POST",
            "/headlines.v1.ArticleService/PublishArticle",
            "",
            [0xAB; 32],
            Uuid::from_u128(0x1234),
            "ed25519",
            Tso::from_parts(1_000_000, 7),
            b"nonce-bytes".to_vec(),
            Vec::new(),
        );

        // Act
        let s = build_canonical_string(&parts);

        // Assert
        let lines: Vec<&str> = s.split('\n').collect();
        assert_eq!(lines.len(), 8);
        assert_eq!(lines[0], "HEADLINES-SIGN-V1");
        assert_eq!(lines[1], "POST");
        assert_eq!(lines[2], "/headlines.v1.ArticleService/PublishArticle");
        assert_eq!(lines[3], ""); // empty query
        assert_eq!(
            lines[4],
            "abababababababababababababababababababababababababababababababab"
        );
        assert_eq!(lines[5], parts.key_id.to_string());
        assert_eq!(lines[6], parts.ts.as_u64().to_string());
        assert_eq!(lines[7], B64.encode(&parts.nonce));
    }

    #[test]
    fn hash_proto_request_is_deterministic_for_equal_messages() {
        // Arrange — `prost_types::Timestamp` is a built-in `prost::Message` we
        // can construct without a `.proto` file. Two equal messages must hash
        // to the same bytes.
        let a = prost_types::Timestamp {
            seconds: 12345,
            nanos: 678,
        };
        let b = prost_types::Timestamp {
            seconds: 12345,
            nanos: 678,
        };
        let c = prost_types::Timestamp {
            seconds: 99,
            nanos: 0,
        };

        // Act
        let h1 = hash_proto_request(&a);
        let h2 = hash_proto_request(&b);
        let h3 = hash_proto_request(&c);

        // Assert
        assert_eq!(h1, h2, "equal messages hash equally");
        assert_ne!(h1, h3, "different messages hash differently");
    }

    #[test]
    fn hash_proto_request_for_default_message_hashes_empty_bytes() {
        // Arrange — defaults serialize to zero bytes.
        let m = prost_types::Timestamp::default();

        // Act
        let h = hash_proto_request(&m);

        // Assert
        let expected = Sha256::digest(b"");
        assert_eq!(h.as_slice(), expected.as_slice());
    }

    // ----- canonicalize_query ----------------------------------------------

    #[test]
    fn canonicalize_query_orders_keys_lexicographically() {
        // Arrange
        let raw = "z=1&a=2&m=3";

        // Act
        let got = canonicalize_query(raw);

        // Assert
        assert_eq!(got, "a=2&m=3&z=1");
    }

    #[test]
    fn canonicalize_query_preserves_per_key_value_order() {
        // Arrange — same key with multiple values; per-key order must be
        // preserved (stable sort), but the *keys* are still ordered
        // lexicographically against other keys.
        let raw = "b=second&a=alpha&b=first";

        // Act
        let got = canonicalize_query(raw);

        // Assert
        assert_eq!(got, "a=alpha&b=second&b=first");
    }

    #[test]
    fn canonicalize_query_handles_empty_input() {
        // Arrange / Act / Assert
        assert_eq!(canonicalize_query(""), "");
    }

    #[test]
    fn canonicalize_query_preserves_percent_encoding() {
        // Arrange — values are kept as-is; we never decode/re-encode, so
        // the canonical form round-trips whatever the client signed.
        let raw = "q=hello%20world&filter=a%2Bb";

        // Act
        let got = canonicalize_query(raw);

        // Assert
        assert_eq!(got, "filter=a%2Bb&q=hello%20world");
    }

    #[test]
    fn canonicalize_query_keeps_keys_without_value_as_empty() {
        // Arrange
        let raw = "flag&a=1";

        // Act
        let got = canonicalize_query(raw);

        // Assert
        assert_eq!(got, "a=1&flag=");
    }

    #[test]
    fn hex_encode_round_trips_known_value() {
        // Arrange / Act / Assert
        assert_eq!(hex_encode(&[0x00, 0x0F, 0xF0, 0xFF]), "000ff0ff");
    }

    // ----- header parsing ---------------------------------------------------

    #[test]
    fn parse_authorization_header_accepts_valid_full_header() {
        // Arrange
        let h = format!(
            "Signature key_id={kid}, algo=ed25519, ts={ts}, nonce={nonce}, sig={sig}",
            kid = Uuid::from_u128(7),
            ts = 12345u64,
            nonce = B64.encode(b"abcd"),
            sig = B64.encode(b"sig!"),
        );

        // Act
        let p = parse_authorization_header(&h).unwrap();

        // Assert
        assert_eq!(p.key_id, Uuid::from_u128(7));
        assert_eq!(p.algo, "ed25519");
        assert_eq!(p.ts.as_u64(), 12345);
        assert_eq!(p.nonce, b"abcd");
        assert_eq!(p.signature, b"sig!");
    }

    #[test]
    fn parse_authorization_header_rejects_missing_scheme() {
        // Arrange
        let h = "key_id=foo, algo=ed25519, ts=1, nonce=AA==, sig=AA==";

        // Act / Assert
        assert_eq!(
            parse_authorization_header(h),
            Err(ParseError::MissingScheme)
        );
    }

    #[test]
    fn parse_authorization_header_rejects_missing_field() {
        // Arrange — drop `sig`.
        let h = format!(
            "Signature key_id={kid}, algo=ed25519, ts=1, nonce={nonce}",
            kid = Uuid::nil(),
            nonce = B64.encode(b"x"),
        );

        // Act / Assert
        assert_eq!(
            parse_authorization_header(&h),
            Err(ParseError::MissingField("sig"))
        );
    }

    #[test]
    fn parse_authorization_header_rejects_unknown_field() {
        // Arrange
        let h = format!(
            "Signature key_id={kid}, algo=ed25519, ts=1, nonce=AA==, sig=AA==, extra=stuff",
            kid = Uuid::nil()
        );

        // Act
        let r = parse_authorization_header(&h);

        // Assert
        assert_eq!(r, Err(ParseError::UnknownField("extra".to_owned())));
    }

    #[test]
    fn parse_authorization_header_rejects_malformed_uuid() {
        // Arrange
        let h = "Signature key_id=not-a-uuid, algo=ed25519, ts=1, nonce=AA==, sig=AA==";

        // Act / Assert
        assert!(matches!(
            parse_authorization_header(h),
            Err(ParseError::MalformedKeyId(_))
        ));
    }

    #[test]
    fn parse_authorization_header_rejects_malformed_base64() {
        // Arrange — `nonce` value with an invalid base64 character.
        let h = format!(
            "Signature key_id={kid}, algo=ed25519, ts=1, nonce=!!!, sig=AA==",
            kid = Uuid::nil()
        );

        // Act / Assert
        assert_eq!(
            parse_authorization_header(&h),
            Err(ParseError::MalformedBase64 { field: "nonce" })
        );
    }

    #[test]
    fn parse_authorization_header_rejects_malformed_sig_base64() {
        // Arrange
        let h = format!(
            "Signature key_id={kid}, algo=ed25519, ts=1, nonce=AA==, sig=!!!",
            kid = Uuid::nil()
        );

        // Act / Assert
        assert_eq!(
            parse_authorization_header(&h),
            Err(ParseError::MalformedBase64 { field: "sig" })
        );
    }

    #[test]
    fn parse_authorization_header_rejects_malformed_ts() {
        // Arrange
        let h = format!(
            "Signature key_id={kid}, algo=ed25519, ts=notnum, nonce=AA==, sig=AA==",
            kid = Uuid::nil()
        );

        // Act / Assert
        assert!(matches!(
            parse_authorization_header(&h),
            Err(ParseError::MalformedTs(_))
        ));
    }

    #[test]
    fn parse_authorization_header_rejects_non_utf8() {
        // Arrange
        let h = "Signature key_id=00000000-0000-0000-0000-000000000000, algo=ed25519, ts=1, nonce=AA==, sig=AA==\u{FFFD}";

        // Act / Assert
        assert_eq!(parse_authorization_header(h), Err(ParseError::NonUtf8));
    }

    #[test]
    fn parse_authorization_header_rejects_malformed_pair() {
        // Arrange — pair without `=`.
        let h = "Signature key_idfoo, algo=ed25519, ts=1, nonce=AA==, sig=AA==";

        // Act / Assert
        assert!(matches!(
            parse_authorization_header(h),
            Err(ParseError::MalformedPair(_))
        ));
    }

    #[test]
    fn parse_authorization_header_rejects_empty_pair_after_comma() {
        // Arrange — trailing comma → empty pair.
        let h = "Signature key_id=00000000-0000-0000-0000-000000000000, algo=ed25519, ts=1, nonce=AA==, sig=AA==,";

        // Act / Assert
        assert!(matches!(
            parse_authorization_header(h),
            Err(ParseError::MalformedPair(_))
        ));
    }

    #[test]
    fn parse_error_display_smoke_test() {
        // Arrange / Act / Assert — exercise the Display format for each variant
        // so the implementation stays exercised even if it never reaches users.
        let _ = ParseError::MissingScheme.to_string();
        let _ = ParseError::MalformedPair("x".into()).to_string();
        let _ = ParseError::UnknownField("x".into()).to_string();
        let _ = ParseError::MissingField("x").to_string();
        let _ = ParseError::MalformedKeyId("x".into()).to_string();
        let _ = ParseError::MalformedTs("x".into()).to_string();
        let _ = ParseError::MalformedBase64 { field: "x" }.to_string();
        let _ = ParseError::NonUtf8.to_string();
    }

    // ----- strategy: round-trip --------------------------------------------

    fn fixed_subject(account_id: u128, key_id: u128) -> Subject {
        Subject::Account {
            account_id: Uuid::from_u128(account_id),
            key_id: Uuid::from_u128(key_id),
        }
    }

    #[tokio::test]
    async fn authenticate_round_trip_returns_subject() {
        // Arrange
        let sk = signing_key();
        let key_id = Uuid::from_u128(1);
        let subject = fixed_subject(0xACC, 1);
        let resolver = Arc::new(InMemoryKeyResolver::new().insert(
            key_id,
            "ed25519",
            sk.verifying_key().as_bytes().to_vec(),
            subject.clone(),
        ));
        let algos = Arc::new(AlgorithmRegistry::new().with_default());
        let (tso, _clock) = fixed_tso(50_000).await;
        let tso = Arc::new(tso);
        let nonces = Arc::new(InMemoryNonceStore::new());
        let strategy = SignedRequestStrategy::new(resolver, algos, tso, nonces);

        let parts = signed_parts_for(
            &sk,
            key_id,
            Tso::from_parts(50_000, 0),
            b"nonce-bytes-1234".to_vec(),
        );

        // Act
        let got = strategy.authenticate_inner(&parts).await.unwrap();

        // Assert
        assert_eq!(got, subject);
    }

    #[tokio::test]
    async fn authenticate_rejects_tampered_request_hash() {
        // Arrange
        let sk = signing_key();
        let key_id = Uuid::from_u128(1);
        let resolver = Arc::new(InMemoryKeyResolver::new().insert(
            key_id,
            "ed25519",
            sk.verifying_key().as_bytes().to_vec(),
            fixed_subject(1, 1),
        ));
        let algos = Arc::new(AlgorithmRegistry::new().with_default());
        let (tso, _clock) = fixed_tso(50_000).await;
        let nonces = Arc::new(InMemoryNonceStore::new());
        let strategy = SignedRequestStrategy::new(resolver, algos, Arc::new(tso), nonces);

        let mut parts =
            signed_parts_for(&sk, key_id, Tso::from_parts(50_000, 0), b"nonce-1".to_vec());
        // Tamper with the request hash *after* signing.
        parts.request_hash = [0xFF; 32];

        // Act
        let res = strategy.authenticate_inner(&parts).await;

        // Assert
        match res {
            Err(AuthError::Unauthenticated(s)) => assert_eq!(s, "bad_signature"),
            other => panic!("expected bad_signature, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn authenticate_rejects_unknown_key() {
        // Arrange — resolver has no entry for the key id.
        let sk = signing_key();
        let key_id = Uuid::from_u128(99);
        let resolver = Arc::new(InMemoryKeyResolver::new());
        let algos = Arc::new(AlgorithmRegistry::new().with_default());
        let (tso, _clock) = fixed_tso(50_000).await;
        let nonces = Arc::new(InMemoryNonceStore::new());
        let strategy = SignedRequestStrategy::new(resolver, algos, Arc::new(tso), nonces);

        let parts = signed_parts_for(&sk, key_id, Tso::from_parts(50_000, 0), b"nonce-2".to_vec());

        // Act
        let res = strategy.authenticate_inner(&parts).await;

        // Assert
        match res {
            Err(AuthError::Unauthenticated(s)) => assert_eq!(s, "unknown_key"),
            other => panic!("got {other:?}"),
        }
    }

    #[tokio::test]
    async fn authenticate_rejects_revoked_key() {
        // Arrange
        let sk = signing_key();
        let key_id = Uuid::from_u128(1);
        let resolver = Arc::new(InMemoryKeyResolver::new().insert_revoked(
            key_id,
            "ed25519",
            sk.verifying_key().as_bytes().to_vec(),
            fixed_subject(1, 1),
        ));
        let algos = Arc::new(AlgorithmRegistry::new().with_default());
        let (tso, _clock) = fixed_tso(50_000).await;
        let nonces = Arc::new(InMemoryNonceStore::new());
        let strategy = SignedRequestStrategy::new(resolver, algos, Arc::new(tso), nonces);

        let parts = signed_parts_for(&sk, key_id, Tso::from_parts(50_000, 0), b"nonce-3".to_vec());

        // Act
        let res = strategy.authenticate_inner(&parts).await;

        // Assert
        match res {
            Err(AuthError::Unauthenticated(s)) => assert_eq!(s, "key revoked"),
            other => panic!("got {other:?}"),
        }
    }

    #[tokio::test]
    async fn authenticate_rejects_algo_mismatch() {
        // Arrange — resolver claims ecdsa-p256 but caller signs with ed25519.
        let sk = signing_key();
        let key_id = Uuid::from_u128(1);
        let resolver = Arc::new(InMemoryKeyResolver::new().insert(
            key_id,
            "ecdsa-p256",
            sk.verifying_key().as_bytes().to_vec(),
            fixed_subject(1, 1),
        ));
        let algos = Arc::new(AlgorithmRegistry::new().with_default());
        let (tso, _clock) = fixed_tso(50_000).await;
        let nonces = Arc::new(InMemoryNonceStore::new());
        let strategy = SignedRequestStrategy::new(resolver, algos, Arc::new(tso), nonces);

        let parts = signed_parts_for(&sk, key_id, Tso::from_parts(50_000, 0), b"nonce-4".to_vec());

        // Act
        let res = strategy.authenticate_inner(&parts).await;

        // Assert
        match res {
            Err(AuthError::Unauthenticated(s)) => assert_eq!(s, "algo_mismatch"),
            other => panic!("got {other:?}"),
        }
    }

    #[tokio::test]
    async fn authenticate_rejects_unsupported_algo_not_in_registry() {
        // Arrange — resolver and parts both say `ecdsa-p256`, but registry
        // only has ed25519.
        let sk = signing_key();
        let key_id = Uuid::from_u128(1);
        let resolver = Arc::new(InMemoryKeyResolver::new().insert(
            key_id,
            "ecdsa-p256",
            sk.verifying_key().as_bytes().to_vec(),
            fixed_subject(1, 1),
        ));
        let algos = Arc::new(AlgorithmRegistry::new().with_default());
        let (tso, _clock) = fixed_tso(50_000).await;
        let nonces = Arc::new(InMemoryNonceStore::new());
        let strategy = SignedRequestStrategy::new(resolver, algos, Arc::new(tso), nonces);

        let mut parts =
            signed_parts_for(&sk, key_id, Tso::from_parts(50_000, 0), b"nonce-5".to_vec());
        parts.algo = "ecdsa-p256".to_owned();

        // Act
        let res = strategy.authenticate_inner(&parts).await;

        // Assert
        match res {
            Err(AuthError::Unauthenticated(s)) => assert_eq!(s, "unsupported_algo"),
            other => panic!("got {other:?}"),
        }
    }

    #[tokio::test]
    async fn authenticate_rejects_expired_timestamp() {
        // Arrange — TSO clock at 100s, request ts at 0 (more than horizon ago).
        let sk = signing_key();
        let key_id = Uuid::from_u128(1);
        let resolver = Arc::new(InMemoryKeyResolver::new().insert(
            key_id,
            "ed25519",
            sk.verifying_key().as_bytes().to_vec(),
            fixed_subject(1, 1),
        ));
        let algos = Arc::new(AlgorithmRegistry::new().with_default());
        let (tso, _clock) = fixed_tso(100_000).await;
        let nonces = Arc::new(InMemoryNonceStore::new());
        let strategy = SignedRequestStrategy::new(resolver, algos, Arc::new(tso), nonces);

        let parts = signed_parts_for(
            &sk,
            key_id,
            Tso::from_parts(0, 0), // way too old
            b"nonce-6".to_vec(),
        );

        // Act
        let res = strategy.authenticate_inner(&parts).await;

        // Assert
        match res {
            Err(AuthError::Unauthenticated(s)) => assert_eq!(s, "expired"),
            other => panic!("got {other:?}"),
        }
    }

    #[tokio::test]
    async fn authenticate_rejects_future_timestamp() {
        // Arrange — TSO clock at 0, request ts in the future.
        let sk = signing_key();
        let key_id = Uuid::from_u128(1);
        let resolver = Arc::new(InMemoryKeyResolver::new().insert(
            key_id,
            "ed25519",
            sk.verifying_key().as_bytes().to_vec(),
            fixed_subject(1, 1),
        ));
        let algos = Arc::new(AlgorithmRegistry::new().with_default());
        let (tso, _clock) = fixed_tso(0).await;
        let nonces = Arc::new(InMemoryNonceStore::new());
        let strategy = SignedRequestStrategy::new(resolver, algos, Arc::new(tso), nonces);

        let parts = signed_parts_for(
            &sk,
            key_id,
            Tso::from_parts(1_000_000, 0),
            b"nonce-7".to_vec(),
        );

        // Act
        let res = strategy.authenticate_inner(&parts).await;

        // Assert
        match res {
            Err(AuthError::Unauthenticated(s)) => assert_eq!(s, "future_ts"),
            other => panic!("got {other:?}"),
        }
    }

    #[tokio::test]
    async fn authenticate_rejects_replay() {
        // Arrange — same nonce twice.
        let sk = signing_key();
        let key_id = Uuid::from_u128(1);
        let resolver = Arc::new(InMemoryKeyResolver::new().insert(
            key_id,
            "ed25519",
            sk.verifying_key().as_bytes().to_vec(),
            fixed_subject(1, 1),
        ));
        let algos = Arc::new(AlgorithmRegistry::new().with_default());
        let (tso, _clock) = fixed_tso(50_000).await;
        let tso = Arc::new(tso);
        let nonces = Arc::new(InMemoryNonceStore::new());
        let strategy = SignedRequestStrategy::new(resolver, algos, tso.clone(), nonces.clone());

        let parts = signed_parts_for(
            &sk,
            key_id,
            Tso::from_parts(50_000, 0),
            b"nonce-replay".to_vec(),
        );

        // Act
        strategy.authenticate_inner(&parts).await.unwrap();
        let res = strategy.authenticate_inner(&parts).await;

        // Assert
        match res {
            Err(AuthError::Unauthenticated(s)) => assert_eq!(s, "replay"),
            other => panic!("got {other:?}"),
        }
    }

    #[tokio::test]
    async fn in_memory_key_resolver_returns_not_found_for_unknown_id() {
        // Arrange
        let r = InMemoryKeyResolver::new();

        // Act
        let res = r.resolve(Uuid::from_u128(0xDEAD)).await;

        // Assert
        assert!(matches!(res, Err(ResolveError::NotFound)));
    }

    #[tokio::test]
    async fn in_memory_key_resolver_returns_revoked() {
        // Arrange
        let r = InMemoryKeyResolver::new().insert_revoked(
            Uuid::from_u128(1),
            "ed25519",
            vec![0u8; 32],
            account_subject(),
        );

        // Act
        let res = r.resolve(Uuid::from_u128(1)).await;

        // Assert
        assert!(matches!(res, Err(ResolveError::Revoked)));
    }

    #[tokio::test]
    async fn in_memory_key_resolver_returns_resolved_key_for_active_entry() {
        // Arrange
        let subject = account_subject();
        let r = InMemoryKeyResolver::new().insert(
            Uuid::from_u128(1),
            "ed25519",
            vec![1, 2, 3],
            subject.clone(),
        );

        // Act
        let got = r.resolve(Uuid::from_u128(1)).await.unwrap();

        // Assert
        assert_eq!(got.algo, "ed25519");
        assert_eq!(got.public_key, vec![1, 2, 3]);
        assert_eq!(got.subject, subject);
    }

    #[test]
    fn resolve_error_display_smoke_test() {
        // Arrange / Act / Assert
        let _ = ResolveError::NotFound.to_string();
        let _ = ResolveError::Revoked.to_string();
        let _ = ResolveError::Internal("x".into()).to_string();
    }

    /// Fake resolver whose `resolve` always returns Internal.
    struct InternalResolver;
    #[async_trait]
    impl KeyResolver for InternalResolver {
        async fn resolve(&self, _key_id: Uuid) -> Result<ResolvedKey, ResolveError> {
            Err(ResolveError::Internal("disk on fire".into()))
        }
    }

    #[tokio::test]
    async fn authenticate_maps_resolver_internal_error_to_unauthenticated() {
        // Arrange
        let sk = signing_key();
        let key_id = Uuid::from_u128(1);
        let resolver: Arc<dyn KeyResolver> = Arc::new(InternalResolver);
        let algos = Arc::new(AlgorithmRegistry::new().with_default());
        let (tso, _clock) = fixed_tso(0).await;
        let nonces = Arc::new(InMemoryNonceStore::new());
        let strategy = SignedRequestStrategy::new(resolver, algos, Arc::new(tso), nonces);

        let parts = signed_parts_for(
            &sk,
            key_id,
            Tso::from_parts(0, 0),
            b"nonce-internal".to_vec(),
        );

        // Act
        let res = strategy.authenticate_inner(&parts).await;

        // Assert
        match res {
            Err(AuthError::Unauthenticated(s)) => assert!(s.starts_with("resolver: ")),
            other => panic!("got {other:?}"),
        }
    }

    /// Fake `TimeSource` that returns `TimeError::Internal` for `validate`.
    struct InternalTime;
    #[allow(clippy::manual_async_fn)]
    impl TimeSource for InternalTime {
        fn now(&self) -> impl Future<Output = Result<Tso, TimeError>> + Send {
            async { Err(TimeError::Internal("clock dead".into())) }
        }
        fn validate(&self, _ts: Tso) -> impl Future<Output = Result<(), TimeError>> + Send {
            async { Err(TimeError::Internal("clock dead".into())) }
        }
    }

    #[tokio::test]
    async fn authenticate_maps_time_internal_error_to_unauthenticated() {
        // Arrange
        let sk = signing_key();
        let key_id = Uuid::from_u128(1);
        let resolver = Arc::new(InMemoryKeyResolver::new().insert(
            key_id,
            "ed25519",
            sk.verifying_key().as_bytes().to_vec(),
            fixed_subject(1, 1),
        ));
        let algos = Arc::new(AlgorithmRegistry::new().with_default());
        let nonces = Arc::new(InMemoryNonceStore::new());
        let strategy = SignedRequestStrategy::new(resolver, algos, Arc::new(InternalTime), nonces);

        let parts = signed_parts_for(
            &sk,
            key_id,
            Tso::from_parts(50_000, 0),
            b"nonce-time".to_vec(),
        );

        // Act
        let res = strategy.authenticate_inner(&parts).await;

        // Assert
        match res {
            Err(AuthError::Unauthenticated(s)) => assert!(s.starts_with("time: ")),
            other => panic!("got {other:?}"),
        }
    }

    /// Fake `NonceStore` that returns `NonceError::Internal`.
    struct InternalNonce;
    #[allow(clippy::manual_async_fn)]
    impl NonceStore for InternalNonce {
        fn record(
            &self,
            _key_id: Uuid,
            _nonce: Vec<u8>,
            _ts: Tso,
        ) -> impl Future<Output = Result<(), headlines_core::NonceError>> + Send {
            async { Err(headlines_core::NonceError::Internal("bus".into())) }
        }
    }

    #[tokio::test]
    async fn authenticate_maps_nonce_internal_error_to_unauthenticated() {
        // Arrange
        let sk = signing_key();
        let key_id = Uuid::from_u128(1);
        let resolver = Arc::new(InMemoryKeyResolver::new().insert(
            key_id,
            "ed25519",
            sk.verifying_key().as_bytes().to_vec(),
            fixed_subject(1, 1),
        ));
        let algos = Arc::new(AlgorithmRegistry::new().with_default());
        let (tso, _clock) = fixed_tso(50_000).await;
        let strategy =
            SignedRequestStrategy::new(resolver, algos, Arc::new(tso), Arc::new(InternalNonce));

        let parts = signed_parts_for(
            &sk,
            key_id,
            Tso::from_parts(50_000, 0),
            b"nonce-nonce".to_vec(),
        );

        // Act
        let res = strategy.authenticate_inner(&parts).await;

        // Assert
        match res {
            Err(AuthError::Unauthenticated(s)) => assert!(s.starts_with("nonce: ")),
            other => panic!("got {other:?}"),
        }
    }

    use headlines_core::SignatureAlgorithm;

    /// Fake algorithm whose `verify` always returns MalformedKey.
    struct MalformedKeyAlgo;
    impl SignatureAlgorithm for MalformedKeyAlgo {
        fn name(&self) -> &'static str {
            "test-malformed-key"
        }
        fn verify(
            &self,
            _public_key: &[u8],
            _canonical: &[u8],
            _sig: &[u8],
        ) -> Result<(), VerifyError> {
            Err(VerifyError::MalformedKey("nope".into()))
        }
    }

    /// Fake algorithm whose `verify` always returns MalformedSignature.
    struct MalformedSigAlgo;
    impl SignatureAlgorithm for MalformedSigAlgo {
        fn name(&self) -> &'static str {
            "test-malformed-sig"
        }
        fn verify(
            &self,
            _public_key: &[u8],
            _canonical: &[u8],
            _sig: &[u8],
        ) -> Result<(), VerifyError> {
            Err(VerifyError::MalformedSignature)
        }
    }

    #[tokio::test]
    async fn authenticate_maps_verify_malformed_key_to_unauthenticated() {
        // Arrange
        let key_id = Uuid::from_u128(1);
        let resolver = Arc::new(InMemoryKeyResolver::new().insert(
            key_id,
            "test-malformed-key",
            vec![0u8; 32],
            fixed_subject(1, 1),
        ));
        let algos = Arc::new(AlgorithmRegistry::new().with(Box::new(MalformedKeyAlgo)));
        let (tso, _clock) = fixed_tso(50_000).await;
        let nonces = Arc::new(InMemoryNonceStore::new());
        let strategy = SignedRequestStrategy::new(resolver, algos, Arc::new(tso), nonces);

        let parts = SignedRequestParts {
            method: "POST".into(),
            path: "/x".into(),
            canonical_query: String::new(),
            request_hash: [0u8; 32],
            key_id,
            algo: "test-malformed-key".into(),
            ts: Tso::from_parts(50_000, 0),
            nonce: b"n".to_vec(),
            signature: vec![0u8; 64],
        };

        // Act
        let res = strategy.authenticate_inner(&parts).await;

        // Assert
        match res {
            Err(AuthError::Unauthenticated(s)) => assert_eq!(s, "malformed_key"),
            other => panic!("got {other:?}"),
        }
    }

    #[tokio::test]
    async fn authenticate_maps_verify_malformed_signature_to_unauthenticated() {
        // Arrange
        let key_id = Uuid::from_u128(1);
        let resolver = Arc::new(InMemoryKeyResolver::new().insert(
            key_id,
            "test-malformed-sig",
            vec![0u8; 32],
            fixed_subject(1, 1),
        ));
        let algos = Arc::new(AlgorithmRegistry::new().with(Box::new(MalformedSigAlgo)));
        let (tso, _clock) = fixed_tso(50_000).await;
        let nonces = Arc::new(InMemoryNonceStore::new());
        let strategy = SignedRequestStrategy::new(resolver, algos, Arc::new(tso), nonces);

        let parts = SignedRequestParts {
            method: "POST".into(),
            path: "/x".into(),
            canonical_query: String::new(),
            request_hash: [0u8; 32],
            key_id,
            algo: "test-malformed-sig".into(),
            ts: Tso::from_parts(50_000, 0),
            nonce: b"n".to_vec(),
            signature: vec![0u8; 64],
        };

        // Act
        let res = strategy.authenticate_inner(&parts).await;

        // Assert
        match res {
            Err(AuthError::Unauthenticated(s)) => assert_eq!(s, "malformed_signature"),
            other => panic!("got {other:?}"),
        }
    }
}
