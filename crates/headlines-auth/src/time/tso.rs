//! `InProcessTso` — the v1 in-process hybrid TSO.
//!
//! Layout matches `Tso::from_parts`: high 46 bits = physical ms since epoch,
//! low 18 bits = logical counter. Monotonically increases across calls and
//! across restarts (via the `tso_high_water` row).

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use headlines_core::{TimeError, TimeSource, Tso};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use super::TsoHighWaterStore;

/// Wall-clock provider — abstracted so tests can drive the TSO without
/// sleeping. The default `SystemClock` reads `SystemTime`.
pub trait Clock: Send + Sync + 'static {
    fn now_ms(&self) -> u64;
}

/// Production wall-clock impl.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }
}

/// Test-only `Clock` whose value is set explicitly via `set` / `advance`.
#[derive(Debug, Default)]
pub struct MockClock {
    now: AtomicU64,
}

impl MockClock {
    pub fn new(initial_ms: u64) -> Self {
        Self {
            now: AtomicU64::new(initial_ms),
        }
    }
    pub fn set(&self, ms: u64) {
        self.now.store(ms, Ordering::SeqCst);
    }
    pub fn advance(&self, by_ms: u64) {
        self.now.fetch_add(by_ms, Ordering::SeqCst);
    }
}

impl Clock for MockClock {
    fn now_ms(&self) -> u64 {
        self.now.load(Ordering::SeqCst)
    }
}

impl Clock for Arc<MockClock> {
    fn now_ms(&self) -> u64 {
        self.as_ref().now_ms()
    }
}

/// Configuration for `InProcessTso::new`.
#[derive(Debug, Clone, Copy)]
pub struct InProcessTsoConfig {
    /// Replay window in milliseconds. Default 30_000 (30s) per `auth.md`.
    pub horizon_ms: u64,
    /// How often the periodic flush task writes the high water mark to the
    /// `TsoHighWaterStore`. `0` disables the flush task entirely (useful for
    /// tests that want to control persistence explicitly).
    pub flush_interval_ms: u64,
}

impl Default for InProcessTsoConfig {
    fn default() -> Self {
        Self {
            horizon_ms: 30_000,
            flush_interval_ms: 100,
        }
    }
}

/// In-process hybrid TSO.
///
/// The packed `last` `AtomicU64` is the highest `Tso::as_u64()` ever issued.
/// `now()` advances it via a CAS loop:
///
/// - if the wall-clock physical_ms exceeds the stored physical_ms, we move to
///   the new physical_ms with logical=0;
/// - otherwise we increment the logical counter inside the stored physical_ms.
///
/// This guarantees strict monotonicity even when wall clock stalls or jumps
/// backwards.
pub struct InProcessTso<C: Clock = SystemClock> {
    last: Arc<AtomicU64>,
    horizon_ms: u64,
    clock: C,
    /// Shared with the flush task so we can stop it cleanly on `stop()`.
    shutdown: Option<oneshot::Sender<()>>,
    flush_handle: Option<JoinHandle<()>>,
}

impl<C: Clock + Clone> InProcessTso<C> {
    /// Build a TSO with an explicit clock. Used by tests to inject a
    /// `MockClock`. Production callers should use `new` (which uses
    /// `SystemClock`).
    pub async fn new_with_clock(
        store: Arc<dyn TsoHighWaterStore>,
        config: InProcessTsoConfig,
        clock: C,
    ) -> anyhow::Result<Self> {
        let stored = store.read().await?;

        // Crash-recovery padding. The flush task only persists the high
        // water *physical_ms* on a periodic interval, so after a crash the
        // stored value lags every TSO issued in the last `flush_interval_ms`
        // window. If we boot back at a wall-clock still inside that window
        // and seed `last = (stored, 0)`, we would re-issue values that
        // collide with TSOs the previous process already emitted. Pad
        // forward by `flush_interval_ms` so the first issued TSO is
        // guaranteed strictly greater than anything previously issued.
        //
        // For `flush_interval_ms == 0` (tests with explicit persistence)
        // there is no crash window, so no padding is needed.
        let crash_floor = stored.saturating_add(config.flush_interval_ms);

        // Wait for wall clock to catch up to the crash-recovery floor. The
        // CAS loop in `issue` already guarantees monotonicity even when
        // wall clock is behind, but waiting up front means the first TSO
        // emitted by this process has a physical_ms that genuinely matches
        // the wall clock, which keeps `validate`'s horizon math intuitive.
        // We only spin when we actually have a non-zero floor to honor —
        // otherwise a fresh boot with `MockClock(0)` would loop forever.
        if crash_floor > 0 {
            loop {
                let now = clock.now_ms();
                if now > crash_floor {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }

        // Seed `last` at the higher of the crash-recovery floor and the
        // current wall clock so the next `issue` is strictly greater than
        // every value the previous process could have emitted within the
        // unflushed window.
        let seed_ms = crash_floor.max(clock.now_ms());
        let last = Arc::new(AtomicU64::new(Tso::from_parts(seed_ms, 0).as_u64()));

        let (shutdown, flush_handle) = if config.flush_interval_ms > 0 {
            let (tx, rx) = oneshot::channel();
            let handle = spawn_flush(
                last.clone(),
                store.clone(),
                Duration::from_millis(config.flush_interval_ms),
                rx,
            );
            (Some(tx), Some(handle))
        } else {
            (None, None)
        };

        Ok(Self {
            last,
            horizon_ms: config.horizon_ms,
            clock,
            shutdown,
            flush_handle,
        })
    }

    /// Issue the next TSO. Synchronous-friendly helper exposed for tests; the
    /// async `now()` wrapper just delegates here.
    pub fn issue(&self) -> Result<Tso, TimeError> {
        let wall_now_ms = self.clock.now_ms();
        loop {
            let prev = self.last.load(Ordering::SeqCst);
            let prev_tso = Tso::from_raw(prev);
            let prev_ms = prev_tso.physical_ms();
            let prev_logical = prev_tso.logical();

            let next_tso = if wall_now_ms > prev_ms {
                Tso::from_parts(wall_now_ms, 0)
            } else {
                // Logical counter overflow guard: 2^18-1 logical slots per ms.
                if prev_logical == (1u32 << 18) - 1 {
                    return Err(TimeError::Internal(
                        "logical counter exhausted within the same physical_ms".to_owned(),
                    ));
                }
                Tso::from_parts(prev_ms, prev_logical + 1)
            };
            let next = next_tso.as_u64();

            if self
                .last
                .compare_exchange(prev, next, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return Ok(next_tso);
            }
            // CAS lost — another thread won the race. Retry.
        }
    }

    /// Synchronous validation helper. Used directly by tests; the trait impl
    /// wraps it.
    pub fn validate_sync(&self, ts: Tso) -> Result<(), TimeError> {
        // Compute `now` non-destructively: peek at `last`'s physical_ms or
        // wall-clock, whichever is larger. We don't `issue` here since
        // validate must not consume a logical slot.
        let wall_ms = self.clock.now_ms();
        let stored_ms = Tso::from_raw(self.last.load(Ordering::SeqCst)).physical_ms();
        let now_ms = wall_ms.max(stored_ms);

        let ts_ms = ts.physical_ms();
        if ts_ms > now_ms {
            // Future-dated relative to the cluster TSO.
            return Err(TimeError::NonMonotonic);
        }
        if now_ms.saturating_sub(ts_ms) > self.horizon_ms {
            return Err(TimeError::OutsideHorizon);
        }
        Ok(())
    }

    /// Cleanly stop the flush task. Returns once the task has flushed its
    /// last value and exited. Idempotent.
    pub async fn stop(mut self) {
        if let Some(tx) = self.shutdown.take() {
            // It's fine if the task has already exited — we just want it to
            // observe the channel close.
            let _ = tx.send(());
        }
        if let Some(handle) = self.flush_handle.take() {
            let _ = handle.await;
        }
    }
}

impl InProcessTso<SystemClock> {
    /// Build a TSO using the wall clock.
    pub async fn new(
        store: Arc<dyn TsoHighWaterStore>,
        config: InProcessTsoConfig,
    ) -> anyhow::Result<Self> {
        Self::new_with_clock(store, config, SystemClock).await
    }
}

impl<C: Clock + Clone> TimeSource for InProcessTso<C> {
    fn now(&self) -> impl Future<Output = Result<Tso, TimeError>> + Send {
        let result = self.issue();
        async move { result }
    }

    fn validate(&self, ts: Tso) -> impl Future<Output = Result<(), TimeError>> + Send {
        let result = self.validate_sync(ts);
        async move { result }
    }
}

fn spawn_flush(
    last: Arc<AtomicU64>,
    store: Arc<dyn TsoHighWaterStore>,
    interval: Duration,
    mut shutdown: oneshot::Receiver<()>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // Skip the first immediate tick.
        ticker.tick().await;

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    let cur = Tso::from_raw(last.load(Ordering::SeqCst)).physical_ms();
                    if let Err(e) = store.write(cur).await {
                        tracing::warn!(error = %e, "tso_high_water flush failed");
                    }
                }
                _ = &mut shutdown => {
                    // Final flush before exit.
                    let cur = Tso::from_raw(last.load(Ordering::SeqCst)).physical_ms();
                    let _ = store.write(cur).await;
                    return;
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::InMemoryTsoStore;

    fn cfg_no_flush(horizon_ms: u64) -> InProcessTsoConfig {
        InProcessTsoConfig {
            horizon_ms,
            flush_interval_ms: 0,
        }
    }

    fn arc_clock(initial: u64) -> Arc<MockClock> {
        Arc::new(MockClock::new(initial))
    }

    #[tokio::test]
    async fn now_returns_strictly_increasing_tsos_in_same_ms() {
        // Arrange
        let store = Arc::new(InMemoryTsoStore::new());
        let clock = arc_clock(1_000);
        let tso = InProcessTso::new_with_clock(store, cfg_no_flush(30_000), clock.clone())
            .await
            .unwrap();

        // Act
        let a = tso.now().await.unwrap();
        let b = tso.now().await.unwrap();
        let c = tso.now().await.unwrap();

        // Assert
        assert!(a < b);
        assert!(b < c);
        assert_eq!(a.physical_ms(), 1_000);
        assert_eq!(b.physical_ms(), 1_000);
        assert_eq!(c.physical_ms(), 1_000);
        assert!(a.logical() < b.logical());
    }

    #[tokio::test]
    async fn now_advances_to_new_physical_ms_when_clock_moves_forward() {
        // Arrange
        let store = Arc::new(InMemoryTsoStore::new());
        let clock = arc_clock(2_000);
        let tso = InProcessTso::new_with_clock(store, cfg_no_flush(30_000), clock.clone())
            .await
            .unwrap();

        // Act
        let a = tso.now().await.unwrap();
        clock.advance(5);
        let b = tso.now().await.unwrap();

        // Assert
        assert_eq!(a.physical_ms(), 2_000);
        assert_eq!(b.physical_ms(), 2_005);
        assert_eq!(b.logical(), 0);
    }

    #[tokio::test]
    async fn now_clamps_when_clock_jumps_backwards() {
        // Arrange — clock goes backwards; TSO must still increase.
        let store = Arc::new(InMemoryTsoStore::new());
        let clock = arc_clock(5_000);
        let tso = InProcessTso::new_with_clock(store, cfg_no_flush(30_000), clock.clone())
            .await
            .unwrap();
        let a = tso.now().await.unwrap();

        // Act
        clock.set(1_000); // jump back
        let b = tso.now().await.unwrap();

        // Assert
        assert!(b > a, "monotonic across backwards-jumping wall clock");
        assert_eq!(b.physical_ms(), 5_000);
    }

    #[tokio::test]
    async fn validate_rejects_far_future_tso_as_non_monotonic() {
        // Arrange
        let store = Arc::new(InMemoryTsoStore::new());
        let clock = arc_clock(10_000);
        let tso = InProcessTso::new_with_clock(store, cfg_no_flush(30_000), clock.clone())
            .await
            .unwrap();

        // Act
        let future_ts = Tso::from_parts(20_000, 0);
        let res = tso.validate(future_ts).await;

        // Assert
        assert_eq!(res, Err(TimeError::NonMonotonic));
    }

    #[tokio::test]
    async fn validate_rejects_far_past_tso_as_outside_horizon() {
        // Arrange
        let store = Arc::new(InMemoryTsoStore::new());
        let clock = arc_clock(50_000);
        let tso = InProcessTso::new_with_clock(store, cfg_no_flush(30_000), clock.clone())
            .await
            .unwrap();

        // Act
        let stale_ts = Tso::from_parts(10_000, 0); // 40s ago, horizon 30s
        let res = tso.validate(stale_ts).await;

        // Assert
        assert_eq!(res, Err(TimeError::OutsideHorizon));
    }

    #[tokio::test]
    async fn validate_accepts_recent_tso_within_horizon() {
        // Arrange
        let store = Arc::new(InMemoryTsoStore::new());
        let clock = arc_clock(50_000);
        let tso = InProcessTso::new_with_clock(store, cfg_no_flush(30_000), clock.clone())
            .await
            .unwrap();

        // Act
        let recent = Tso::from_parts(45_000, 0);
        let res = tso.validate(recent).await;

        // Assert
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn restart_with_persisted_high_water_refuses_lower_values() {
        // Arrange — simulate a server restart at a wall-clock that's behind
        // the persisted high water. Construction should wait, then issue a
        // value strictly greater than the persisted floor.
        let store = Arc::new(InMemoryTsoStore::with_value(8_000));
        let clock = arc_clock(7_000);
        let started = tokio::spawn({
            let store = store.clone();
            let clock = clock.clone();
            async move {
                InProcessTso::new_with_clock(store, cfg_no_flush(30_000), clock)
                    .await
                    .unwrap()
            }
        });
        // Hand the clock forward past the high water so `new_with_clock`'s
        // crash-recovery loop can break out.
        for _ in 0..10 {
            tokio::task::yield_now().await;
            clock.advance(200);
        }
        let tso = started.await.unwrap();

        // Act
        let issued = tso.now().await.unwrap();

        // Assert
        assert!(
            issued.physical_ms() >= 8_000,
            "first issued TSO must be >= persisted high water (got {})",
            issued.physical_ms()
        );
    }

    #[tokio::test]
    async fn flush_task_persists_high_water_and_stops_cleanly() {
        // Arrange
        let store = Arc::new(InMemoryTsoStore::new());
        let cfg = InProcessTsoConfig {
            horizon_ms: 30_000,
            flush_interval_ms: 5,
        };
        let clock = arc_clock(123_456);
        let tso = InProcessTso::new_with_clock(store.clone(), cfg, clock.clone())
            .await
            .unwrap();

        // Act
        let _ = tso.now().await.unwrap();
        // Wait a couple of flush ticks.
        tokio::time::sleep(Duration::from_millis(20)).await;
        tso.stop().await;

        // Assert
        assert!(store.current() >= 123_456, "flush task wrote high water");
    }

    #[tokio::test]
    async fn stop_is_idempotent_when_no_flush_task() {
        // Arrange
        let store = Arc::new(InMemoryTsoStore::new());
        let clock = arc_clock(0);
        let tso = InProcessTso::new_with_clock(store, cfg_no_flush(30_000), clock)
            .await
            .unwrap();

        // Act / Assert — must not hang or panic.
        tso.stop().await;
    }

    #[tokio::test]
    async fn issue_errors_when_logical_counter_exhausted() {
        // Arrange — pre-load `last` with a packed value whose logical slot is
        // already at the max so the next call must error.
        let store = Arc::new(InMemoryTsoStore::new());
        let clock = arc_clock(1_000);
        let tso = InProcessTso::new_with_clock(store, cfg_no_flush(30_000), clock.clone())
            .await
            .unwrap();
        let max_logical = (1u32 << 18) - 1;
        tso.last.store(
            Tso::from_parts(1_000, max_logical).as_u64(),
            Ordering::SeqCst,
        );

        // Act
        let res = tso.issue();

        // Assert
        assert!(matches!(res, Err(TimeError::Internal(_))));
    }

    #[tokio::test]
    async fn system_clock_returns_nonzero_now_ms() {
        // Arrange / Act
        let ms = SystemClock.now_ms();

        // Assert
        assert!(ms > 0);
    }

    /// `TsoHighWaterStore` whose `write` always errors. Used to exercise the
    /// flush-task error branch.
    #[derive(Default)]
    struct FailingStore;
    #[async_trait::async_trait]
    impl crate::time::TsoHighWaterStore for FailingStore {
        async fn read(&self) -> anyhow::Result<u64> {
            Ok(0)
        }
        async fn write(&self, _last_physical_ms: u64) -> anyhow::Result<()> {
            anyhow::bail!("simulated flush failure")
        }
    }

    #[tokio::test]
    async fn flush_task_logs_warning_when_store_write_fails() {
        // Arrange
        let store: Arc<dyn crate::time::TsoHighWaterStore> = Arc::new(FailingStore);
        let cfg = InProcessTsoConfig {
            horizon_ms: 30_000,
            flush_interval_ms: 5,
        };
        let clock = arc_clock(1_000);
        let tso = InProcessTso::new_with_clock(store, cfg, clock)
            .await
            .unwrap();

        // Act — give the flush task a tick, then stop.
        let _ = tso.now().await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        tso.stop().await;

        // Assert — no panic; the warn! arm has been exercised.
    }

    #[tokio::test]
    async fn config_default_has_documented_horizon_and_flush() {
        // Arrange / Act
        let cfg = InProcessTsoConfig::default();

        // Assert
        assert_eq!(cfg.horizon_ms, 30_000);
        assert_eq!(cfg.flush_interval_ms, 100);
    }

    #[tokio::test]
    async fn boot_waits_for_wall_clock_to_pass_persisted_high_water_then_proceeds() {
        // Arrange — `stored=10`, clock starts at 5; the constructor must
        // observe wall clock advancing past the high water mark.
        let store = Arc::new(InMemoryTsoStore::with_value(10));
        let clock = arc_clock(5);

        // Act — kick off construction and concurrently advance the clock past
        // the high water value.
        let advance = {
            let clock = clock.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(2)).await;
                clock.set(20);
            })
        };
        let tso = InProcessTso::new_with_clock(store, cfg_no_flush(30_000), clock.clone())
            .await
            .unwrap();
        advance.await.unwrap();

        // Assert
        let issued = tso.now().await.unwrap();
        assert!(issued.physical_ms() >= 10);
    }

    #[tokio::test]
    async fn system_clock_constructs_tso_without_explicit_clock() {
        // Arrange
        let store = Arc::new(InMemoryTsoStore::new());

        // Act
        let tso = InProcessTso::new(
            store,
            InProcessTsoConfig {
                horizon_ms: 30_000,
                flush_interval_ms: 0,
            },
        )
        .await
        .unwrap();

        // Assert — must issue at least one TSO.
        let _ = tso.now().await.unwrap();
        tso.stop().await;
    }

    #[tokio::test]
    async fn crash_recovery_after_unflushed_issues_emits_strictly_greater_logical() {
        // Arrange — simulate a process that flushed `stored=stale_ms` to the
        // store, then advanced wall clock and issued more TSOs at later
        // physical_ms values without flushing (the next flush tick would
        // have caught up, but the process crashed first). The persisted
        // high water lags by up to one `flush_interval_ms`.
        //
        // After reconstruction at a wall clock still within that lost
        // window, the next issued TSO must be strictly greater than every
        // value the first run could have emitted — otherwise an attacker
        // could observe two distinct TSOs colliding across a restart.
        let store = Arc::new(InMemoryTsoStore::new());
        let stale_ms = 1_000u64;
        let crash_ms = 1_050u64; // 50ms past stale, inside 100ms flush window
        let flush_interval_ms = 100;
        let clock = arc_clock(stale_ms);
        let cfg = InProcessTsoConfig {
            horizon_ms: 30_000,
            flush_interval_ms,
        };

        // First boot: persist `stale_ms`, then advance the clock and issue
        // several TSOs at `crash_ms` without flushing again.
        let highest_pre_crash = {
            let tso = InProcessTso::new_with_clock(store.clone(), cfg, clock.clone())
                .await
                .unwrap();
            store.write(stale_ms).await.unwrap();
            clock.set(crash_ms);
            let _ = tso.now().await.unwrap();
            let _ = tso.now().await.unwrap();
            let last = tso.now().await.unwrap();
            // Drop without `stop()` — the flush task never gets a chance to
            // write a value newer than `stale_ms`. The store still reflects
            // `stale_ms`.
            assert_eq!(store.current(), stale_ms);
            last
        };

        // Act — second boot at the *same* wall-clock (still inside the
        // unflushed window). Without crash-recovery padding, the new TSO
        // would re-issue logical=0 at `crash_ms` and collide with
        // `highest_pre_crash`. With the padding, construction must wait
        // until wall clock has advanced past the crash-recovery floor;
        // hand the clock forward in a side task to let it proceed.
        let tick = {
            let clock = clock.clone();
            tokio::spawn(async move {
                for _ in 0..50 {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                    clock.advance(50);
                }
            })
        };
        let tso = InProcessTso::new_with_clock(store, cfg, clock.clone())
            .await
            .unwrap();
        let post_crash = tso.now().await.unwrap();
        tick.abort();

        // Assert
        assert!(
            post_crash > highest_pre_crash,
            "post-crash TSO ({:?}) must be strictly greater than the highest \
             pre-crash TSO ({:?}) — otherwise the same packed value could \
             be reused after a crash within the flush interval",
            post_crash,
            highest_pre_crash,
        );
    }

    #[test]
    fn mock_clock_set_and_advance_round_trip() {
        // Arrange
        let c = MockClock::new(100);

        // Act
        c.set(500);
        c.advance(50);

        // Assert
        assert_eq!(c.now_ms(), 550);
    }
}
