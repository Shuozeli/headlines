//! Concrete `TimeSource` impls — the in-process hybrid TSO and the dev-only
//! `LocalClock`.
//!
//! Wire layout, crash recovery, and validation rules all match
//! `docs/design/auth.md` and `docs/design/architecture.md` (TSO module).

mod local_clock;
mod postgres_store;
mod tso;

pub use local_clock::LocalClock;
pub use postgres_store::{InMemoryTsoStore, PostgresTsoStore, TsoHighWaterStore};
pub use tso::{Clock, InProcessTso, InProcessTsoConfig, MockClock, SystemClock};
