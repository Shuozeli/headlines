//! `LocalClock` — dev/test-only `TimeSource` that just reads the system
//! clock. No persistence, no logical counter, no monotonic guarantees across
//! restarts.
//!
//! Production deployments should use `InProcessTso`; this exists so dev
//! environments without Postgres can still sign requests.

use std::future::Future;

use chrono::Utc;
use headlines_core::{TimeError, TimeSource, Tso};

/// Wall-clock backed `TimeSource`. `now()` returns `Tso::from_parts(now_ms, 0)`.
/// `validate()` accepts anything within `±horizon_ms` of the current wall
/// clock.
#[derive(Debug, Clone)]
pub struct LocalClock {
    horizon_ms: u64,
}

impl LocalClock {
    /// New with a given horizon. `30_000` is the default per `auth.md`.
    pub fn new(horizon_ms: u64) -> Self {
        Self { horizon_ms }
    }

    fn now_ms(&self) -> u64 {
        Utc::now().timestamp_millis().max(0) as u64
    }
}

impl Default for LocalClock {
    fn default() -> Self {
        Self::new(30_000)
    }
}

impl TimeSource for LocalClock {
    fn now(&self) -> impl Future<Output = Result<Tso, TimeError>> + Send {
        let ms = self.now_ms();
        async move { Ok(Tso::from_parts(ms, 0)) }
    }

    fn validate(&self, ts: Tso) -> impl Future<Output = Result<(), TimeError>> + Send {
        let now_ms = self.now_ms();
        let horizon = self.horizon_ms;
        async move {
            let ts_ms = ts.physical_ms();
            // Allow `ts` to be slightly in the future (clock skew slack).
            if ts_ms > now_ms.saturating_add(horizon) {
                return Err(TimeError::NonMonotonic);
            }
            if now_ms.saturating_sub(ts_ms) > horizon {
                return Err(TimeError::OutsideHorizon);
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn now_returns_tso_with_logical_zero_and_recent_physical_ms() {
        // Arrange
        let clock = LocalClock::default();
        let before = Utc::now().timestamp_millis() as u64;

        // Act
        let ts = clock.now().await.unwrap();

        // Assert
        let after = Utc::now().timestamp_millis() as u64;
        assert_eq!(ts.logical(), 0);
        assert!(ts.physical_ms() >= before && ts.physical_ms() <= after);
    }

    #[tokio::test]
    async fn validate_accepts_current_tso() {
        // Arrange
        let clock = LocalClock::default();

        // Act
        let now = clock.now().await.unwrap();
        let res = clock.validate(now).await;

        // Assert
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn validate_rejects_far_future_as_non_monotonic() {
        // Arrange
        let clock = LocalClock::new(30_000);

        // Act
        let future = Tso::from_parts(u64::MAX >> 18, 0);
        let res = clock.validate(future).await;

        // Assert
        assert_eq!(res, Err(TimeError::NonMonotonic));
    }

    #[tokio::test]
    async fn validate_rejects_far_past_as_outside_horizon() {
        // Arrange
        let clock = LocalClock::new(30_000);

        // Act
        let stale = Tso::from_parts(0, 0);
        let res = clock.validate(stale).await;

        // Assert
        assert_eq!(res, Err(TimeError::OutsideHorizon));
    }

    #[tokio::test]
    async fn validate_accepts_within_horizon_past() {
        // Arrange
        let clock = LocalClock::new(60_000);
        let now_ms = Utc::now().timestamp_millis() as u64;

        // Act — 5 seconds ago, well within 60s horizon.
        let recent = Tso::from_parts(now_ms.saturating_sub(5_000), 0);
        let res = clock.validate(recent).await;

        // Assert
        assert!(res.is_ok());
    }
}
