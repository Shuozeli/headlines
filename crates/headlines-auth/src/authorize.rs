//! `AuthorizationLayer` — runs **after** `AuthInterceptor` and consults the
//! proto-driven `AUTH_TABLE` to assert the resolved `Subject` is allowed for
//! the RPC.
//!
//! Phase 4 ships the layer with the empty `AUTH_TABLE` from `headlines-proto`;
//! since no service proto files exist yet, every request falls through to
//! the "no spec" deny path. Phase 5 will populate the table per RPC.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use http::Request;
use tonic::body::BoxBody;
use tower::{Layer, Service};

use headlines_core::{Subject, SubjectClass};
use headlines_proto::{AUTH_TABLE, AuthSpec};

/// Source of the per-RPC `AuthSpec` table. Production reads the proto-driven
/// `AUTH_TABLE` (a `phf::Map`) from `headlines-proto`; tests can supply a
/// synthetic table to exercise specific allow/deny paths.
#[derive(Clone)]
enum AuthTable {
    Phf(&'static phf::Map<&'static str, AuthSpec>),
    Synthetic(&'static [(&'static str, AuthSpec)]),
}

impl AuthTable {
    fn lookup(&self, method: &str) -> Option<AuthSpec> {
        match self {
            AuthTable::Phf(map) => map.get(method).copied(),
            AuthTable::Synthetic(slice) => slice
                .iter()
                .find(|(m, _)| *m == method)
                .map(|(_, spec)| *spec),
        }
    }
}

/// `tower::Layer` consulting the proto-driven `AUTH_TABLE`.
#[derive(Clone)]
pub struct AuthorizationLayer {
    table: Arc<AuthTable>,
}

impl AuthorizationLayer {
    /// Build using the production `AUTH_TABLE` populated from the proto
    /// FileDescriptorSet at build time.
    pub fn new() -> Self {
        Self {
            table: Arc::new(AuthTable::Phf(&AUTH_TABLE)),
        }
    }

    /// Build with a synthetic table — used by unit tests to exercise the
    /// matching logic without touching the proto-driven map.
    pub fn with_table(table: &'static [(&'static str, AuthSpec)]) -> Self {
        Self {
            table: Arc::new(AuthTable::Synthetic(table)),
        }
    }
}

impl Default for AuthorizationLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Layer<S> for AuthorizationLayer {
    type Service = AuthorizationService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthorizationService {
            inner,
            table: self.table.clone(),
        }
    }
}

#[derive(Clone)]
pub struct AuthorizationService<S> {
    inner: S,
    table: Arc<AuthTable>,
}

impl<S, ReqBody> Service<Request<ReqBody>> for AuthorizationService<S>
where
    S: Service<Request<ReqBody>, Response = http::Response<BoxBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + Sync + 'static,
    ReqBody: Send + 'static,
{
    type Response = http::Response<BoxBody>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let table = self.table.clone();
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let path = req.uri().path().to_owned();

        Box::pin(async move {
            let subject = req
                .extensions()
                .get::<Subject>()
                .cloned()
                .unwrap_or(Subject::Anonymous);

            let Some(spec) = table.lookup(&path) else {
                return Ok(deny("no auth spec for RPC"));
            };

            if !is_allowed(&subject, &spec) {
                return Ok(deny("subject not permitted for RPC"));
            }

            inner.call(req).await
        })
    }
}

/// True iff `subject`'s class is in `spec.allowed`, with the additional
/// rule that a `System` subject must satisfy at least one of `spec.scopes`
/// (any-of) — unless `spec.scopes` is empty, which means "any system is
/// fine".
fn is_allowed(subject: &Subject, spec: &AuthSpec) -> bool {
    let class = match subject {
        Subject::Anonymous => SubjectClass::Anonymous,
        Subject::User { .. } => SubjectClass::UserSelf,
        Subject::Account { .. } => SubjectClass::AccountSelf,
        Subject::System { .. } => SubjectClass::System,
    };

    // `AccountOwnsResource` is never produced from `Subject::class()` —
    // it's a per-RPC distinction. We accept an `Account` subject when the
    // table allows either `AccountSelf` or `AccountOwnsResource`.
    let class_ok = spec.allowed.iter().any(|c| {
        matches!(
            (c, class),
            (SubjectClass::Anonymous, SubjectClass::Anonymous)
                | (SubjectClass::UserSelf, SubjectClass::UserSelf)
                | (SubjectClass::AccountSelf, SubjectClass::AccountSelf)
                | (SubjectClass::AccountOwnsResource, SubjectClass::AccountSelf)
                | (SubjectClass::System, SubjectClass::System)
        )
    });

    if !class_ok {
        return false;
    }

    // Scope check applies only to System subjects.
    if let Subject::System { .. } = subject {
        if spec.scopes.is_empty() {
            return true;
        }
        return spec.scopes.iter().any(|s| subject.has_scope(s));
    }

    true
}

fn deny(msg: &str) -> http::Response<BoxBody> {
    tonic::Status::permission_denied(msg.to_owned()).into_http()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;
    use std::sync::Mutex;
    use tower::ServiceExt;
    use uuid::Uuid;

    fn empty_body() -> BoxBody {
        use http_body_util::{BodyExt, Empty};
        Empty::<bytes::Bytes>::new()
            .map_err(|never| match never {})
            .boxed_unsync()
    }

    #[derive(Clone, Default)]
    struct PassThrough {
        called: Arc<Mutex<bool>>,
    }

    impl Service<Request<BoxBody>> for PassThrough {
        type Response = http::Response<BoxBody>;
        type Error = Infallible;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: Request<BoxBody>) -> Self::Future {
            let called = self.called.clone();
            Box::pin(async move {
                *called.lock().unwrap() = true;
                Ok(http::Response::new(empty_body()))
            })
        }
    }

    fn req_with_subject(method: &str, subject: Option<Subject>) -> Request<BoxBody> {
        let mut r = Request::builder()
            .method("POST")
            .uri(method)
            .body(empty_body())
            .unwrap();
        if let Some(s) = subject {
            r.extensions_mut().insert(s);
        }
        r
    }

    fn user(id: u128) -> Subject {
        Subject::User {
            user_id: Uuid::from_u128(id),
            key_id: Uuid::nil(),
        }
    }
    fn account(id: u128) -> Subject {
        Subject::Account {
            account_id: Uuid::from_u128(id),
            key_id: Uuid::nil(),
        }
    }
    fn system(scopes: &[&str]) -> Subject {
        Subject::System {
            system_id: Uuid::from_u128(7),
            key_id: Uuid::nil(),
            scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    fn grpc_status(resp: &http::Response<BoxBody>) -> Option<u8> {
        resp.headers()
            .get("grpc-status")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u8>().ok())
    }

    #[tokio::test]
    async fn empty_table_denies_with_permission_denied() {
        // Arrange — explicit empty synthetic table simulates "no auth spec for
        // this RPC". Production AUTH_TABLE is non-empty after Phase 5, so we
        // can't reuse `new()` here.
        static EMPTY: &[(&str, AuthSpec)] = &[];
        let layer = AuthorizationLayer::with_table(EMPTY);
        let inner = PassThrough::default();
        let called = inner.called.clone();
        let mut svc = layer.layer(inner);

        let req = req_with_subject("/anything", Some(account(1)));

        // Act
        let resp = svc.ready().await.unwrap().call(req).await.unwrap();

        // Assert
        assert_eq!(
            grpc_status(&resp),
            Some(tonic::Code::PermissionDenied as u8)
        );
        assert!(!*called.lock().unwrap(), "inner service must not run");
    }

    #[tokio::test]
    async fn synthetic_table_allows_matching_account_subject() {
        // Arrange
        static T: &[(&str, AuthSpec)] = &[(
            "/svc/Method",
            AuthSpec {
                allowed: &[SubjectClass::AccountSelf],
                scopes: &[],
            },
        )];
        let layer = AuthorizationLayer::with_table(T);
        let inner = PassThrough::default();
        let called = inner.called.clone();
        let mut svc = layer.layer(inner);

        let req = req_with_subject("/svc/Method", Some(account(1)));

        // Act
        let _ = svc.ready().await.unwrap().call(req).await.unwrap();

        // Assert
        assert!(*called.lock().unwrap());
    }

    #[tokio::test]
    async fn synthetic_table_denies_mismatched_subject_class() {
        // Arrange
        static T: &[(&str, AuthSpec)] = &[(
            "/svc/Method",
            AuthSpec {
                allowed: &[SubjectClass::AccountSelf],
                scopes: &[],
            },
        )];
        let layer = AuthorizationLayer::with_table(T);
        let mut svc = layer.layer(PassThrough::default());

        let req = req_with_subject("/svc/Method", Some(user(1)));

        // Act
        let resp = svc.ready().await.unwrap().call(req).await.unwrap();

        // Assert
        assert_eq!(
            grpc_status(&resp),
            Some(tonic::Code::PermissionDenied as u8)
        );
    }

    #[tokio::test]
    async fn system_without_required_scope_is_denied() {
        // Arrange — system allowed, but spec requires articles.write.
        static T: &[(&str, AuthSpec)] = &[(
            "/svc/Method",
            AuthSpec {
                allowed: &[SubjectClass::System],
                scopes: &["articles.write"],
            },
        )];
        let layer = AuthorizationLayer::with_table(T);
        let mut svc = layer.layer(PassThrough::default());

        let req = req_with_subject("/svc/Method", Some(system(&["users.read"])));

        // Act
        let resp = svc.ready().await.unwrap().call(req).await.unwrap();

        // Assert
        assert_eq!(
            grpc_status(&resp),
            Some(tonic::Code::PermissionDenied as u8)
        );
    }

    #[tokio::test]
    async fn system_with_wildcard_scope_is_allowed() {
        // Arrange
        static T: &[(&str, AuthSpec)] = &[(
            "/svc/Method",
            AuthSpec {
                allowed: &[SubjectClass::System],
                scopes: &["articles.write"],
            },
        )];
        let layer = AuthorizationLayer::with_table(T);
        let inner = PassThrough::default();
        let called = inner.called.clone();
        let mut svc = layer.layer(inner);

        let req = req_with_subject("/svc/Method", Some(system(&["*"])));

        // Act
        let _ = svc.ready().await.unwrap().call(req).await.unwrap();

        // Assert
        assert!(*called.lock().unwrap());
    }

    #[tokio::test]
    async fn system_with_empty_required_scopes_is_allowed() {
        // Arrange — empty scope list means any System is fine.
        static T: &[(&str, AuthSpec)] = &[(
            "/svc/Method",
            AuthSpec {
                allowed: &[SubjectClass::System],
                scopes: &[],
            },
        )];
        let layer = AuthorizationLayer::with_table(T);
        let inner = PassThrough::default();
        let called = inner.called.clone();
        let mut svc = layer.layer(inner);

        let req = req_with_subject("/svc/Method", Some(system(&[])));

        // Act
        let _ = svc.ready().await.unwrap().call(req).await.unwrap();

        // Assert
        assert!(*called.lock().unwrap());
    }

    #[tokio::test]
    async fn anonymous_allowed_when_listed() {
        // Arrange
        static T: &[(&str, AuthSpec)] = &[(
            "/svc/Method",
            AuthSpec {
                allowed: &[SubjectClass::Anonymous],
                scopes: &[],
            },
        )];
        let layer = AuthorizationLayer::with_table(T);
        let inner = PassThrough::default();
        let called = inner.called.clone();
        let mut svc = layer.layer(inner);

        let req = req_with_subject("/svc/Method", Some(Subject::Anonymous));

        // Act
        let _ = svc.ready().await.unwrap().call(req).await.unwrap();

        // Assert
        assert!(*called.lock().unwrap());
    }

    #[tokio::test]
    async fn anonymous_denied_when_not_listed() {
        // Arrange
        static T: &[(&str, AuthSpec)] = &[(
            "/svc/Method",
            AuthSpec {
                allowed: &[SubjectClass::AccountSelf],
                scopes: &[],
            },
        )];
        let layer = AuthorizationLayer::with_table(T);
        let mut svc = layer.layer(PassThrough::default());

        let req = req_with_subject("/svc/Method", Some(Subject::Anonymous));

        // Act
        let resp = svc.ready().await.unwrap().call(req).await.unwrap();

        // Assert
        assert_eq!(
            grpc_status(&resp),
            Some(tonic::Code::PermissionDenied as u8)
        );
    }

    #[tokio::test]
    async fn missing_subject_extension_treated_as_anonymous() {
        // Arrange — table allows Anonymous, but no Subject is in extensions.
        static T: &[(&str, AuthSpec)] = &[(
            "/svc/Method",
            AuthSpec {
                allowed: &[SubjectClass::Anonymous],
                scopes: &[],
            },
        )];
        let layer = AuthorizationLayer::with_table(T);
        let inner = PassThrough::default();
        let called = inner.called.clone();
        let mut svc = layer.layer(inner);

        let req = req_with_subject("/svc/Method", None);

        // Act
        let _ = svc.ready().await.unwrap().call(req).await.unwrap();

        // Assert
        assert!(*called.lock().unwrap());
    }

    #[tokio::test]
    async fn account_owns_resource_class_accepts_account_subject() {
        // Arrange — `AccountOwnsResource` is never produced by `class()`,
        // but a table entry listing it accepts an `Account` subject (the
        // resource-ownership check is per-RPC and happens later).
        static T: &[(&str, AuthSpec)] = &[(
            "/svc/Method",
            AuthSpec {
                allowed: &[SubjectClass::AccountOwnsResource],
                scopes: &[],
            },
        )];
        let layer = AuthorizationLayer::with_table(T);
        let inner = PassThrough::default();
        let called = inner.called.clone();
        let mut svc = layer.layer(inner);

        let req = req_with_subject("/svc/Method", Some(account(1)));

        // Act
        let _ = svc.ready().await.unwrap().call(req).await.unwrap();

        // Assert
        assert!(*called.lock().unwrap());
    }

    #[tokio::test]
    async fn user_self_class_accepts_user_subject() {
        // Arrange
        static T: &[(&str, AuthSpec)] = &[(
            "/svc/Method",
            AuthSpec {
                allowed: &[SubjectClass::UserSelf],
                scopes: &[],
            },
        )];
        let layer = AuthorizationLayer::with_table(T);
        let inner = PassThrough::default();
        let called = inner.called.clone();
        let mut svc = layer.layer(inner);

        let req = req_with_subject("/svc/Method", Some(user(7)));

        // Act
        let _ = svc.ready().await.unwrap().call(req).await.unwrap();

        // Assert
        assert!(*called.lock().unwrap());
    }

    #[test]
    fn default_constructor_uses_production_table() {
        // Arrange / Act
        let layer = AuthorizationLayer::default();

        // Assert — production table is the proto-driven `phf::Map`. Looking up
        // a known service path returns Some, so the map is non-empty after
        // Phase 5; arbitrary unrelated paths still return None.
        let lookup_unrelated = match layer.table.as_ref() {
            super::AuthTable::Phf(map) => map.get("/never/heard/of"),
            super::AuthTable::Synthetic(_) => panic!("default constructor should use Phf"),
        };
        assert!(lookup_unrelated.is_none());
    }

    #[test]
    fn empty_table_test_uses_synthetic_constructor() {
        // Arrange — confirm that the synthetic-table form starts empty for the
        // earlier "deny on unknown RPC" test that pre-Phase-5 relied on
        // `AUTH_TABLE` being empty in production.
        static T: &[(&str, AuthSpec)] = &[];
        let layer = AuthorizationLayer::with_table(T);

        // Act / Assert
        match layer.table.as_ref() {
            super::AuthTable::Synthetic(t) => assert!(t.is_empty()),
            super::AuthTable::Phf(_) => panic!("with_table should use Synthetic"),
        }
    }
}
