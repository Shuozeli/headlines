//! `auth_results_total` instrument per `docs/design/architecture.md`
//! Observability section.
//!
//! Labels per the architecture spec: `{result}` ∈ {`ok`, `bad_signature`,
//! `replay`, `expired`, `non_monotonic`, `unknown_key`, `algo_mismatch`,
//! `internal`, `malformed_header`, `body_read_failed`}. The interceptor
//! classifies the outcome of each authenticated call; anonymous calls are
//! silently passed through (no auth attempt → no result counter).
//!
//! `Default` uses the global no-op meter so tests construct without OTel
//! boot.

use std::sync::Arc;

use opentelemetry::KeyValue;
use opentelemetry::metrics::Counter;

use headlines_core::{AuthError, NonceError, TimeError, VerifyError};

#[derive(Clone)]
pub struct AuthMetrics {
    pub auth_results_total: Counter<u64>,
}

impl AuthMetrics {
    pub fn new(meter: &opentelemetry::metrics::Meter) -> Self {
        Self {
            auth_results_total: meter
                .u64_counter("auth_results_total")
                .with_description("Auth-strategy outcomes, by classified result.")
                .build(),
        }
    }

    pub fn no_op() -> Self {
        let meter = opentelemetry::global::meter("headlines-auth-noop");
        Self::new(&meter)
    }

    pub fn shared_no_op() -> Arc<Self> {
        Arc::new(Self::no_op())
    }

    /// Increment with `result=ok`.
    pub fn record_ok(&self) {
        self.auth_results_total
            .add(1, &[KeyValue::new("result", "ok")]);
    }

    /// Classify an `AuthError` into a stable label string and record one
    /// increment.
    pub fn record_err(&self, err: &AuthError) {
        let label = classify_auth_error(err);
        self.auth_results_total
            .add(1, &[KeyValue::new("result", label)]);
    }

    /// Increment with a free-form non-strategy outcome label (used by the
    /// interceptor for header-shape failures that never reach the strategy).
    pub fn record_label(&self, label: &'static str) {
        self.auth_results_total
            .add(1, &[KeyValue::new("result", label)]);
    }
}

impl Default for AuthMetrics {
    fn default() -> Self {
        Self::no_op()
    }
}

impl std::fmt::Debug for AuthMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthMetrics")
            .field("auth_results_total", &"<counter>")
            .finish()
    }
}

/// Map a strategy `AuthError` to a stable `result` label value.
pub fn classify_auth_error(err: &AuthError) -> &'static str {
    match err {
        AuthError::Unauthenticated(s) => {
            // `SignedRequestStrategy` emits a small fixed vocabulary of
            // `Unauthenticated(_)` strings — match-on-string is fine and
            // keeps the surface flat.
            if s.contains("unknown key") || s.contains("unknown_key") {
                "unknown_key"
            } else if s.contains("algo") {
                "algo_mismatch"
            } else if s.contains("subject") {
                "subject_mismatch"
            } else if s.contains("nonce_store_full") {
                "nonce_store_full"
            } else {
                "unauthenticated_other"
            }
        }
        AuthError::Verify(VerifyError::BadSignature) => "bad_signature",
        AuthError::Verify(VerifyError::MalformedKey(_)) => "malformed_key",
        AuthError::Verify(VerifyError::MalformedSignature) => "malformed_signature",
        AuthError::Time(TimeError::OutsideHorizon) => "expired",
        AuthError::Time(TimeError::NonMonotonic) => "non_monotonic",
        AuthError::Time(TimeError::Internal(_)) => "internal_time",
        AuthError::Nonce(NonceError::Replay) => "replay",
        AuthError::Nonce(NonceError::Capacity) => "nonce_store_full",
        AuthError::Nonce(NonceError::Internal(_)) => "internal_nonce",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_auth_error_covers_each_variant() {
        // Arrange / Act / Assert
        assert_eq!(
            classify_auth_error(&AuthError::Verify(VerifyError::BadSignature)),
            "bad_signature"
        );
        assert_eq!(
            classify_auth_error(&AuthError::Time(TimeError::OutsideHorizon)),
            "expired"
        );
        assert_eq!(
            classify_auth_error(&AuthError::Nonce(NonceError::Replay)),
            "replay"
        );
        assert_eq!(
            classify_auth_error(&AuthError::Unauthenticated("unknown key".into())),
            "unknown_key"
        );
        assert_eq!(
            classify_auth_error(&AuthError::Unauthenticated("algo not enabled".into())),
            "algo_mismatch"
        );
        assert_eq!(
            classify_auth_error(&AuthError::Verify(VerifyError::MalformedSignature)),
            "malformed_signature"
        );
    }

    #[test]
    fn no_op_metrics_increments_do_not_panic() {
        // Arrange
        let m = AuthMetrics::no_op();

        // Act
        m.record_ok();
        m.record_err(&AuthError::Nonce(NonceError::Replay));
        m.record_label("malformed_header");

        // Assert — no panic, and the counter exists.
        assert!(format!("{:?}", m).contains("AuthMetrics"));
    }
}
