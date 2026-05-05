//! `AuthInterceptor` — tonic `tower::Layer` that authenticates incoming
//! requests via an `AuthStrategy` and attaches the resolved `Subject` to
//! request extensions.
//!
//! ## Body hashing
//!
//! When an `Authorization` header is present the interceptor buffers the
//! request body, runs it through a `BodyHasher`, then reconstructs the body
//! so the inner service can decode it normally. For gRPC unary the on-wire
//! body is `[1-byte compressed flag][4-byte BE message length][proto bytes]`
//! — `ProtoBodyHasher` strips the 5-byte gRPC frame header and hashes the
//! inner proto bytes, which is the **canonical proto encoding** signed by
//! the client per `auth.md`.
//!
//! Tests that exercise the canonicalization without going through tonic's
//! frame layer can fall back to `NoopBodyHasher` (returns 32 zero bytes —
//! signers and verifiers must use the same hash for the round-trip to work).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_trait::async_trait;
use http::Request;
use http_body_util::{BodyExt, Full};
use sha2::{Digest, Sha256};
use tonic::body::BoxBody;
use tower::{Layer, Service};

use headlines_core::{AuthError, AuthStrategy, SignedRequestParts, Subject};

use crate::metrics::AuthMetrics;
use crate::strategy::{canonicalize_query, parse_authorization_header};

/// Errors a `BodyHasher` may surface.
///
/// Distinct from `AuthError` because the body-hash step happens **before**
/// the strategy is invoked — a hash failure is a refusal to even attempt
/// authentication, classified separately in `auth_results_total`. The
/// interceptor maps every variant to an `UNAUTHENTICATED` response.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum BodyHashError {
    /// The gRPC frame's compressed flag was set. We don't enable
    /// compression for any signed RPC because the canonical bytes a client
    /// signs are the *uncompressed* proto encoding — hashing the
    /// compressed bytes would silently break signature verification.
    #[error("compressed gRPC frames are not supported for signed requests")]
    CompressedFrame,
}

/// Body hashing seam. The interceptor calls `hash` with the entire buffered
/// body bytes (including any gRPC frame header); the impl decides what to
/// hash — see `ProtoBodyHasher` for the production strategy.
///
/// Returns `Result` so impls can refuse to authenticate a body they can't
/// canonically hash (e.g. a compressed gRPC frame). The interceptor maps
/// errors to `UNAUTHENTICATED` and bumps a metric — never silently passes
/// the request through.
#[async_trait]
pub trait BodyHasher: Send + Sync {
    async fn hash(&self, body_bytes: &[u8]) -> Result<[u8; 32], BodyHashError>;
}

/// Test stub — always returns `[0u8; 32]`. Useful when the test produces and
/// verifies the same all-zero hash on both sides.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopBodyHasher;

#[async_trait]
impl BodyHasher for NoopBodyHasher {
    async fn hash(&self, _body_bytes: &[u8]) -> Result<[u8; 32], BodyHashError> {
        Ok([0u8; 32])
    }
}

/// Production hasher — strips the 5-byte gRPC frame header and SHA-256s the
/// canonical proto encoding inside. Matches `hash_proto_request` from
/// `crate::strategy` byte-for-byte, so a client that signs
/// `hash_proto_request(&msg)` round-trips through this verifier.
///
/// gRPC unary frame layout (per the gRPC HTTP/2 spec):
///
/// ```text
///   byte 0       : compressed flag (0 = uncompressed; 1 = compressed)
///   bytes 1..=4  : big-endian u32 message length
///   bytes 5..    : encoded proto message
/// ```
///
/// **Compressed frames are rejected.** If `flag != 0` the hasher returns
/// `BodyHashError::CompressedFrame`. Hashing the compressed bytes would
/// silently disagree with the client's signature over the uncompressed
/// proto encoding, so the interceptor must reject the request rather
/// than allow a false negative.
#[derive(Debug, Default, Clone, Copy)]
pub struct ProtoBodyHasher;

#[async_trait]
impl BodyHasher for ProtoBodyHasher {
    async fn hash(&self, body_bytes: &[u8]) -> Result<[u8; 32], BodyHashError> {
        // A well-formed gRPC unary body always has a 5-byte frame header.
        // Bodies shorter than 5 bytes can't be a frame at all — fall back
        // to hashing them verbatim so non-gRPC paths (e.g. raw REST POST
        // with an empty body) still produce a stable hash.
        if body_bytes.len() < 5 {
            let digest = Sha256::digest(body_bytes);
            return Ok(digest.into());
        }
        match body_bytes[0] {
            0 => {
                // Uncompressed: skip flag + length and hash the proto
                // payload only. Length isn't validated against
                // `body_bytes.len()` because tonic's body framing is
                // well-formed at this layer; if it weren't, the inner
                // service would already reject the call with an INTERNAL.
                let digest = Sha256::digest(&body_bytes[5..]);
                Ok(digest.into())
            }
            _ => Err(BodyHashError::CompressedFrame),
        }
    }
}

/// Object-safe wrapper around `AuthStrategy` so the interceptor can hold an
/// `Arc<dyn DynAuthStrategy>` without leaking generics into every layer.
#[doc(hidden)]
pub trait DynAuthStrategy: Send + Sync + 'static {
    fn authenticate<'a>(
        &'a self,
        parts: &'a SignedRequestParts,
    ) -> Pin<Box<dyn Future<Output = Result<Subject, AuthError>> + Send + 'a>>;
}

impl<T: AuthStrategy + 'static> DynAuthStrategy for T {
    fn authenticate<'a>(
        &'a self,
        parts: &'a SignedRequestParts,
    ) -> Pin<Box<dyn Future<Output = Result<Subject, AuthError>> + Send + 'a>> {
        Box::pin(AuthStrategy::authenticate(self, parts))
    }
}

/// `tower::Layer` that wraps every tonic service with auth.
#[derive(Clone)]
pub struct AuthInterceptor {
    strategy: Arc<dyn DynAuthStrategy>,
    body_hasher: Arc<dyn BodyHasher>,
    metrics: Arc<AuthMetrics>,
}

impl AuthInterceptor {
    pub fn new<S: AuthStrategy + 'static>(
        strategy: Arc<S>,
        body_hasher: Arc<dyn BodyHasher>,
    ) -> Self {
        Self {
            strategy,
            body_hasher,
            metrics: AuthMetrics::shared_no_op(),
        }
    }

    /// Override the default no-op `AuthMetrics`. The binary calls this
    /// after registering the global `MeterProvider`.
    pub fn with_metrics(mut self, metrics: Arc<AuthMetrics>) -> Self {
        self.metrics = metrics;
        self
    }
}

impl<S> Layer<S> for AuthInterceptor {
    type Service = AuthInterceptorService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthInterceptorService {
            inner,
            strategy: self.strategy.clone(),
            body_hasher: self.body_hasher.clone(),
            metrics: self.metrics.clone(),
        }
    }
}

#[derive(Clone)]
pub struct AuthInterceptorService<S> {
    inner: S,
    strategy: Arc<dyn DynAuthStrategy>,
    body_hasher: Arc<dyn BodyHasher>,
    metrics: Arc<AuthMetrics>,
}

impl<S> Service<Request<BoxBody>> for AuthInterceptorService<S>
where
    S: Service<Request<BoxBody>, Response = http::Response<BoxBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + Sync + 'static,
{
    type Response = http::Response<BoxBody>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<BoxBody>) -> Self::Future {
        // Cloning ourselves to avoid holding `&mut self` across await points
        // is the standard pattern for tower middleware.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let strategy = self.strategy.clone();
        let hasher = self.body_hasher.clone();
        let metrics = self.metrics.clone();

        Box::pin(async move {
            let header_val = req
                .headers()
                .get(http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_owned());

            match header_val {
                None => {
                    // Anonymous: pass through with `Subject::Anonymous` in
                    // extensions; the AuthorizationLayer downstream will
                    // reject if the RPC requires a non-anonymous subject.
                    // No `auth_results_total` increment — there was no auth
                    // attempt.
                    req.extensions_mut().insert(Subject::Anonymous);
                    inner.call(req).await
                }
                Some(value) => {
                    let method = req.method().as_str().to_owned();
                    let path = req.uri().path().to_owned();
                    // Canonicalize the query string so the server hashes the
                    // same `k1=v1&k2=v2` form the client signed. Today every
                    // authenticated REST endpoint is read-only and has no
                    // querystring fields, but the canonicalization is part
                    // of the spec invariant — do it here so the moment a
                    // query-bearing endpoint lands, signatures still match.
                    let query = canonicalize_query(req.uri().query().unwrap_or(""));

                    let parsed = match parse_authorization_header(&value) {
                        Ok(p) => p,
                        Err(_) => {
                            metrics.record_label("malformed_header");
                            return Ok(unauth_response("malformed_authorization_header"));
                        }
                    };

                    // Buffer the request body so we can hash it AND still let
                    // the inner service decode the proto. tonic's BoxBody is
                    // unconditionally `Bytes`-shaped at this layer.
                    let (parts_head, body) = req.into_parts();
                    let collected = match body.collect().await {
                        Ok(c) => c.to_bytes(),
                        Err(_) => {
                            metrics.record_label("body_read_failed");
                            return Ok(unauth_response("body_read_failed"));
                        }
                    };

                    let request_hash = match hasher.hash(&collected).await {
                        Ok(h) => h,
                        Err(BodyHashError::CompressedFrame) => {
                            metrics.record_label("compressed_frame");
                            return Ok(unauth_response("compressed_frame_not_supported"));
                        }
                    };

                    // Reconstruct the request with a buffered body. `Full`
                    // emits the bytes in one chunk; the inner service decodes
                    // them exactly as if they had streamed normally.
                    let new_body: BoxBody = Full::new(collected)
                        .map_err(|never: std::convert::Infallible| match never {})
                        .map_err(|_: std::convert::Infallible| -> tonic::Status { unreachable!() })
                        .boxed_unsync();
                    let mut req = Request::from_parts(parts_head, new_body);

                    let signed_parts = SignedRequestParts {
                        method,
                        path,
                        canonical_query: query,
                        request_hash,
                        key_id: parsed.key_id,
                        algo: parsed.algo,
                        ts: parsed.ts,
                        nonce: parsed.nonce,
                        signature: parsed.signature,
                    };

                    match strategy.authenticate(&signed_parts).await {
                        Ok(subject) => {
                            metrics.record_ok();
                            req.extensions_mut().insert(subject);
                            inner.call(req).await
                        }
                        Err(e) => {
                            metrics.record_err(&e);
                            tracing::debug!(error = %e, "auth strategy rejected request");
                            Ok(unauth_response(&e.to_string()))
                        }
                    }
                }
            }
        })
    }
}

/// Construct a synthetic `UNAUTHENTICATED` HTTP response with a tonic-shaped
/// gRPC status. We intentionally don't bubble the error up the tower chain
/// because tonic's `Status` → response conversion expects a particular
/// shape; building one here keeps the interceptor self-contained.
fn unauth_response(msg: &str) -> http::Response<BoxBody> {
    let status = tonic::Status::unauthenticated(msg.to_owned());
    status.into_http()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algo::{AlgorithmRegistry, Ed25519};
    use crate::nonce::InMemoryNonceStore;
    use crate::strategy::{InMemoryKeyResolver, SignedRequestStrategy, build_canonical_string};
    use crate::time::{InMemoryTsoStore, InProcessTso, InProcessTsoConfig, MockClock};
    use ed25519_dalek::{Signer, SigningKey};
    use http::HeaderValue;
    use rand::rngs::OsRng;
    use std::convert::Infallible;
    use std::sync::Mutex;
    use tower::ServiceExt;
    use uuid::Uuid;

    use headlines_core::{Subject, Tso};

    #[derive(Clone, Default)]
    struct CapturingService {
        captured: Arc<Mutex<Option<Subject>>>,
    }

    impl Service<Request<BoxBody>> for CapturingService {
        type Response = http::Response<BoxBody>;
        type Error = Infallible;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: Request<BoxBody>) -> Self::Future {
            let captured = self.captured.clone();
            let subj = req.extensions().get::<Subject>().cloned();
            Box::pin(async move {
                *captured.lock().unwrap() = subj;
                Ok(http::Response::new(empty_body()))
            })
        }
    }

    fn empty_body() -> BoxBody {
        use http_body_util::{BodyExt, Empty};
        Empty::<bytes::Bytes>::new()
            .map_err(|never| match never {})
            .boxed_unsync()
    }

    async fn build_strategy() -> (Arc<SignedRequestStrategy>, SigningKey, Uuid, Subject) {
        let sk = SigningKey::generate(&mut OsRng);
        let key_id = Uuid::from_u128(1);
        let subject = Subject::Account {
            account_id: Uuid::from_u128(0xACC),
            key_id,
        };
        let resolver = Arc::new(InMemoryKeyResolver::new().insert(
            key_id,
            "ed25519",
            sk.verifying_key().as_bytes().to_vec(),
            subject.clone(),
        ));
        let algos = Arc::new(AlgorithmRegistry::new().with(Box::new(Ed25519)));
        let store = Arc::new(InMemoryTsoStore::new());
        let clock = Arc::new(MockClock::new(50_000));
        let cfg = InProcessTsoConfig {
            horizon_ms: 30_000,
            flush_interval_ms: 0,
        };
        let tso = Arc::new(
            InProcessTso::new_with_clock(store, cfg, clock)
                .await
                .unwrap(),
        );
        let nonces = Arc::new(InMemoryNonceStore::new());
        let strategy = Arc::new(SignedRequestStrategy::new(resolver, algos, tso, nonces));
        (strategy, sk, key_id, subject)
    }

    fn build_authorization(
        sk: &SigningKey,
        key_id: Uuid,
        method: &str,
        path: &str,
        query: &str,
        ts: Tso,
    ) -> String {
        use base64::Engine;
        use base64::engine::general_purpose::STANDARD as B64;

        let parts = SignedRequestParts {
            method: method.to_owned(),
            path: path.to_owned(),
            canonical_query: query.to_owned(),
            request_hash: [0u8; 32],
            key_id,
            algo: "ed25519".into(),
            ts,
            nonce: b"interceptor-nonce".to_vec(),
            signature: Vec::new(),
        };
        let canonical = build_canonical_string(&parts);
        let sig = sk.sign(canonical.as_bytes()).to_bytes().to_vec();
        format!(
            "Signature key_id={kid}, algo=ed25519, ts={ts}, nonce={nonce}, sig={sig}",
            kid = key_id,
            ts = ts.as_u64(),
            nonce = B64.encode(&parts.nonce),
            sig = B64.encode(&sig),
        )
    }

    #[tokio::test]
    async fn missing_authorization_passes_through_with_anonymous_subject() {
        // Arrange
        let (strategy, _sk, _kid, _subj) = build_strategy().await;
        let layer = AuthInterceptor::new(strategy, Arc::new(NoopBodyHasher));
        let svc = CapturingService::default();
        let captured = svc.captured.clone();
        let mut svc = layer.layer(svc);

        let req = Request::builder().uri("/x/y").body(empty_body()).unwrap();

        // Act
        let _ = svc.ready().await.unwrap().call(req).await.unwrap();

        // Assert
        let got = captured.lock().unwrap().clone().unwrap();
        assert_eq!(got, Subject::Anonymous);
    }

    #[tokio::test]
    async fn valid_authorization_attaches_concrete_subject() {
        // Arrange
        let (strategy, sk, kid, subject) = build_strategy().await;
        let layer = AuthInterceptor::new(strategy, Arc::new(NoopBodyHasher));
        let svc = CapturingService::default();
        let captured = svc.captured.clone();
        let mut svc = layer.layer(svc);

        let auth = build_authorization(
            &sk,
            kid,
            "POST",
            "/headlines.v1.AccountService/CreateAccount",
            "",
            Tso::from_parts(50_000, 0),
        );

        let mut req = Request::builder()
            .method("POST")
            .uri("/headlines.v1.AccountService/CreateAccount")
            .body(empty_body())
            .unwrap();
        req.headers_mut().insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_str(&auth).unwrap(),
        );

        // Act
        let _ = svc.ready().await.unwrap().call(req).await.unwrap();

        // Assert
        let got = captured.lock().unwrap().clone().unwrap();
        assert_eq!(got, subject);
    }

    #[tokio::test]
    async fn rejected_authorization_returns_unauthenticated_response() {
        // Arrange — supply a header with an unknown key so the strategy
        // rejects.
        let (strategy, sk, _kid, _subj) = build_strategy().await;
        let layer = AuthInterceptor::new(strategy, Arc::new(NoopBodyHasher));
        let svc = CapturingService::default();
        let mut svc = layer.layer(svc);

        let unknown_kid = Uuid::from_u128(0xDEAD);
        let auth = build_authorization(
            &sk,
            unknown_kid,
            "POST",
            "/x/y",
            "",
            Tso::from_parts(50_000, 0),
        );

        let mut req = Request::builder()
            .method("POST")
            .uri("/x/y")
            .body(empty_body())
            .unwrap();
        req.headers_mut().insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_str(&auth).unwrap(),
        );

        // Act
        let resp = svc.ready().await.unwrap().call(req).await.unwrap();

        // Assert — tonic encodes UNAUTHENTICATED via the `grpc-status` header
        // on a 200 response.
        assert_eq!(resp.status(), 200);
        let status_hdr = resp
            .headers()
            .get("grpc-status")
            .expect("grpc-status header present")
            .to_str()
            .unwrap()
            .to_owned();
        assert_eq!(
            status_hdr,
            (tonic::Code::Unauthenticated as u8).to_string(),
            "expected UNAUTHENTICATED"
        );
    }

    #[tokio::test]
    async fn malformed_authorization_header_returns_unauthenticated() {
        // Arrange — header doesn't start with `Signature `.
        let (strategy, _sk, _kid, _subj) = build_strategy().await;
        let layer = AuthInterceptor::new(strategy, Arc::new(NoopBodyHasher));
        let svc = CapturingService::default();
        let mut svc = layer.layer(svc);

        let mut req = Request::builder()
            .method("POST")
            .uri("/x/y")
            .body(empty_body())
            .unwrap();
        req.headers_mut().insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer not-our-format"),
        );

        // Act
        let resp = svc.ready().await.unwrap().call(req).await.unwrap();

        // Assert
        assert_eq!(
            resp.headers().get("grpc-status").unwrap().to_str().unwrap(),
            (tonic::Code::Unauthenticated as u8).to_string()
        );
    }

    #[tokio::test]
    async fn unsorted_query_string_authenticates_against_canonical_signature() {
        // Arrange — sender signs over the canonicalized query (`a=1&b=2`)
        // but the wire URI carries the keys in reverse order (`b=2&a=1`).
        // The interceptor must canonicalize before constructing
        // SignedRequestParts, so signature verification still passes.
        let (strategy, sk, kid, subject) = build_strategy().await;
        let layer = AuthInterceptor::new(strategy, Arc::new(NoopBodyHasher));
        let svc = CapturingService::default();
        let captured = svc.captured.clone();
        let mut svc = layer.layer(svc);

        let auth = build_authorization(
            &sk,
            kid,
            "GET",
            "/x",
            // Canonical form — sorted.
            "a=1&b=2",
            Tso::from_parts(50_000, 0),
        );

        let mut req = Request::builder()
            .method("GET")
            // Wire form — unsorted.
            .uri("/x?b=2&a=1")
            .body(empty_body())
            .unwrap();
        req.headers_mut().insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_str(&auth).unwrap(),
        );

        // Act
        let _ = svc.ready().await.unwrap().call(req).await.unwrap();

        // Assert
        let got = captured.lock().unwrap().clone().unwrap();
        assert_eq!(got, subject);
    }

    #[tokio::test]
    async fn noop_body_hasher_returns_zero_bytes() {
        // Arrange
        let h = NoopBodyHasher;

        // Act
        let got = h.hash(b"anything").await.unwrap();

        // Assert
        assert_eq!(got, [0u8; 32]);
    }

    #[tokio::test]
    async fn proto_body_hasher_matches_hash_proto_request_for_framed_body() {
        // Arrange — pick a representative `prost::Message` and compute the
        // client-side hash via `hash_proto_request`. Then wrap the encoded
        // bytes in a 5-byte gRPC unary frame header (flag=0, len=BE u32) and
        // run them through the server-side `ProtoBodyHasher`. The two
        // hashes are the byte-level invariant the whole signing scheme
        // depends on.
        use crate::strategy::hash_proto_request;
        use prost::Message as _;
        let msg = prost_types::Timestamp {
            seconds: 1_700_000_000,
            nanos: 42,
        };
        let client_hash = hash_proto_request(&msg);

        let encoded = msg.encode_to_vec();
        let mut framed = Vec::with_capacity(5 + encoded.len());
        framed.push(0u8); // uncompressed flag
        framed.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
        framed.extend_from_slice(&encoded);

        // Act
        let server_hash = ProtoBodyHasher.hash(&framed).await.unwrap();

        // Assert
        assert_eq!(
            client_hash, server_hash,
            "client `hash_proto_request` and server `ProtoBodyHasher` must \
             agree byte-for-byte; otherwise every signed RPC fails"
        );
    }

    #[tokio::test]
    async fn proto_body_hasher_rejects_compressed_frames() {
        // Arrange — frame with the compressed flag set. The hasher cannot
        // canonically hash compressed bytes (the client signs the
        // *uncompressed* proto encoding) so it must reject rather than
        // silently produce a hash that won't match.
        let mut framed = vec![1u8]; // compressed flag
        framed.extend_from_slice(&0u32.to_be_bytes());

        // Act
        let res = ProtoBodyHasher.hash(&framed).await;

        // Assert
        assert_eq!(res, Err(BodyHashError::CompressedFrame));
    }

    #[tokio::test]
    async fn proto_body_hasher_passes_short_bodies_through_sha256() {
        // Arrange — bodies shorter than the 5-byte gRPC frame header are
        // hashed verbatim (covers raw REST paths with empty bodies).
        let raw = b"abc";
        let expected: [u8; 32] = Sha256::digest(raw).into();

        // Act
        let got = ProtoBodyHasher.hash(raw).await.unwrap();

        // Assert
        assert_eq!(got, expected);
    }

    #[tokio::test]
    async fn interceptor_rejects_compressed_frames_with_unauthenticated() {
        // Arrange — wire body has the compressed flag set; the hasher
        // refuses, the interceptor must return UNAUTHENTICATED rather than
        // letting the request through.
        let (strategy, sk, kid, _subj) = build_strategy().await;
        let layer = AuthInterceptor::new(strategy, Arc::new(ProtoBodyHasher));
        let svc = CapturingService::default();
        let mut svc = layer.layer(svc);

        let auth = build_authorization(
            &sk,
            kid,
            "POST",
            "/x",
            "",
            Tso::from_parts(50_000, 0),
        );

        // Compressed-flag gRPC frame with zero payload.
        let mut framed = vec![1u8];
        framed.extend_from_slice(&0u32.to_be_bytes());

        use http_body_util::Full;
        let body: BoxBody = Full::new(bytes::Bytes::from(framed))
            .map_err(|never: std::convert::Infallible| match never {})
            .boxed_unsync();
        let mut req = Request::builder()
            .method("POST")
            .uri("/x")
            .body(body)
            .unwrap();
        req.headers_mut().insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_str(&auth).unwrap(),
        );

        // Act
        let resp = svc.ready().await.unwrap().call(req).await.unwrap();

        // Assert
        assert_eq!(
            resp.headers().get("grpc-status").unwrap().to_str().unwrap(),
            (tonic::Code::Unauthenticated as u8).to_string(),
            "compressed body must surface as UNAUTHENTICATED"
        );
    }
}
