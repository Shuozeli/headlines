//! `Tso` — the hybrid logical timestamp value type.
//!
//! Layout (per `docs/design/auth.md` + `data-model.md` `tso_high_water`):
//!
//! ```text
//! bit 63 .... 18 | bit 17 .... 0
//!  physical_ms     logical_counter
//!     (46 bits)       (18 bits)
//! ```
//!
//! `physical_ms` is wall-clock milliseconds since the Unix epoch. The 46-bit
//! field comfortably reaches well past the year 4000. The low 18 bits are a
//! per-physical-tick logical counter (≤ 262_143 timestamps per ms). The full
//! `u64` is the wire-level token that signers carry as `ts=<u64>` in the
//! Authorization header.
//!
//! This crate only defines the value type. Generation logic (the actual
//! `InProcessTso`) lives in `headlines-store` (Phase 4).

use std::fmt;

/// Number of bits reserved for the logical counter. 18 bits → 262_144 logical
/// ticks per physical millisecond — safely above any plausible single-node
/// QPS.
pub const LOGICAL_BITS: u32 = 18;

/// Bit-mask isolating the logical counter portion of a TSO.
pub const LOGICAL_MASK: u64 = (1u64 << LOGICAL_BITS) - 1;

/// Hybrid-logical TSO timestamp; opaque `u64` on the wire.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(transparent)]
pub struct Tso(u64);

impl Tso {
    /// Sentinel zero TSO. Useful as a "not yet initialised" marker; never
    /// returned by `TimeSource::now`.
    pub const ZERO: Tso = Tso(0);

    /// Build a TSO directly from the raw `u64` representation. Used by the
    /// time source after assembling `(physical_ms, logical)`, and by
    /// deserialisers that receive the wire value.
    pub const fn from_raw(raw: u64) -> Self {
        Tso(raw)
    }

    /// Compose from `(physical_ms, logical)`. Higher bits of `physical_ms`
    /// beyond 46 bits and higher bits of `logical` beyond 18 bits are
    /// silently masked off — callers that require defensive checks should
    /// validate before calling.
    pub const fn from_parts(physical_ms: u64, logical: u32) -> Self {
        let p = physical_ms << LOGICAL_BITS;
        let l = (logical as u64) & LOGICAL_MASK;
        Tso(p | l)
    }

    /// The raw 64-bit token (wire form).
    pub const fn as_u64(&self) -> u64 {
        self.0
    }

    /// `(physical_ms, logical)` decomposition per the doc layout.
    pub const fn parts(&self) -> (u64, u32) {
        let physical = self.0 >> LOGICAL_BITS;
        let logical = (self.0 & LOGICAL_MASK) as u32;
        (physical, logical)
    }

    /// Convenience accessor for the physical-milliseconds half.
    pub const fn physical_ms(&self) -> u64 {
        self.parts().0
    }

    /// Convenience accessor for the logical-counter half.
    pub const fn logical(&self) -> u32 {
        self.parts().1
    }
}

impl fmt::Display for Tso {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Display the raw u64 — that's what clients put on the wire as
        // `ts=<value>` and what we log for correlation. A more elaborate
        // representation (e.g. `<phys_ms>+<logical>`) is debug-time only.
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_raw_round_trips_through_as_u64() {
        // Arrange
        let raw: u64 = 0x0123_4567_89AB_CDEF;

        // Act
        let tso = Tso::from_raw(raw);

        // Assert
        assert_eq!(tso.as_u64(), raw);
    }

    #[test]
    fn from_parts_round_trips_through_parts() {
        // Arrange
        let physical: u64 = 1_700_000_000_123;
        let logical: u32 = 42;

        // Act
        let tso = Tso::from_parts(physical, logical);
        let (got_physical, got_logical) = tso.parts();

        // Assert
        assert_eq!(got_physical, physical);
        assert_eq!(got_logical, logical);
        assert_eq!(tso.physical_ms(), physical);
        assert_eq!(tso.logical(), logical);
    }

    #[test]
    fn ordering_follows_physical_then_logical() {
        // Arrange
        let earlier = Tso::from_parts(100, 5);
        let same_ms_later_logical = Tso::from_parts(100, 6);
        let later_ms = Tso::from_parts(101, 0);

        // Act / Assert
        assert!(earlier < same_ms_later_logical);
        assert!(same_ms_later_logical < later_ms);
        assert!(earlier < later_ms);
    }

    #[test]
    fn zero_constant_has_zero_physical_and_zero_logical() {
        // Arrange / Act
        let zero = Tso::ZERO;

        // Assert
        assert_eq!(zero.as_u64(), 0);
        assert_eq!(zero.parts(), (0, 0));
    }

    #[test]
    fn display_writes_raw_u64() {
        // Arrange
        let tso = Tso::from_raw(123_456);

        // Act
        let s = tso.to_string();

        // Assert
        assert_eq!(s, "123456");
    }

    #[test]
    fn logical_overflow_in_from_parts_is_masked() {
        // Arrange
        let physical = 7u64;
        // 18-bit field; 0x4_0000 == 1 << 18 — exactly one bit too many.
        let logical_overflow: u32 = 0x4_0000;

        // Act
        let tso = Tso::from_parts(physical, logical_overflow);

        // Assert: low 18 bits are zero, physical not corrupted.
        assert_eq!(tso.physical_ms(), physical);
        assert_eq!(tso.logical(), 0);
    }

    #[test]
    fn serde_round_trips_as_transparent_u64() {
        // Arrange
        let tso = Tso::from_raw(987_654_321);

        // Act
        let json = serde_json::to_string(&tso).expect("serialize");
        let back: Tso = serde_json::from_str(&json).expect("deserialize");

        // Assert
        assert_eq!(json, "987654321");
        assert_eq!(back, tso);
    }
}
