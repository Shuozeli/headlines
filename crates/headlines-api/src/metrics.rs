//! Domain counters per `docs/design/architecture.md` (Observability section).
//!
//! Phase 8 wires four domain instruments per the architecture spec:
//!
//! - `articles_published_total` — incremented by `ArticleService.PublishArticle`
//!   on success.
//! - `drafts_created_total` — incremented by `DraftService.CreateDraft` on
//!   success.
//! - `events_recorded_total` — incremented by `EventService.RecordEvent` and
//!   `RecordEventBatch` (the batch handler increments by `len(events)`).
//! - `feeds_replaced_total` — incremented by
//!   `FeedRecommendationService.ReplaceRecommendationFeed` on success.
//!
//! All four are u64 counters built from a single `opentelemetry::Meter`. The
//! `Default` impl uses `opentelemetry::global::meter(...)`, which returns a
//! no-op `Meter` if no provider has been registered globally — making this
//! safe to construct in tests without any OTel boot. The server binary calls
//! `init_global_meter_provider(...)` once during startup and the same global
//! `Meter` is then handed out to every service.

use std::sync::Arc;

use opentelemetry::KeyValue;
use opentelemetry::metrics::Counter;

/// Domain-level success counters. Holds u64 counters whose underlying
/// `Meter` can be either the no-op global meter (default for tests) or the
/// real `SdkMeterProvider`-backed one wired in `headlines-server`.
#[derive(Clone)]
pub struct DomainMetrics {
    pub articles_published: Counter<u64>,
    pub drafts_created: Counter<u64>,
    pub events_recorded: Counter<u64>,
    pub feeds_replaced: Counter<u64>,
}

impl DomainMetrics {
    /// Build counters from the supplied named meter. The server binary calls
    /// this with `global::meter("headlines-server")` once the
    /// `SdkMeterProvider` is registered globally.
    pub fn new(meter: &opentelemetry::metrics::Meter) -> Self {
        Self {
            articles_published: meter
                .u64_counter("articles_published_total")
                .with_description("Articles successfully published (via PublishArticle or PublishDraft).")
                .build(),
            drafts_created: meter
                .u64_counter("drafts_created_total")
                .with_description("Drafts successfully created (via CreateDraft).")
                .build(),
            events_recorded: meter
                .u64_counter("events_recorded_total")
                .with_description("Events successfully recorded (via RecordEvent or RecordEventBatch — incremented by batch length).")
                .build(),
            feeds_replaced: meter
                .u64_counter("feeds_replaced_total")
                .with_description("Recommendation feeds successfully replaced (via ReplaceRecommendationFeed).")
                .build(),
        }
    }

    /// Convenience constructor for tests + tests that bypass OTel boot —
    /// uses the global no-op meter, so increments are silently dropped.
    pub fn no_op() -> Self {
        let meter = opentelemetry::global::meter("headlines-noop");
        Self::new(&meter)
    }

    /// Wraps `Self::no_op` in an `Arc` for the common service-impl shape.
    pub fn shared_no_op() -> Arc<Self> {
        Arc::new(Self::no_op())
    }
}

impl Default for DomainMetrics {
    fn default() -> Self {
        Self::no_op()
    }
}

impl std::fmt::Debug for DomainMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DomainMetrics")
            .field("articles_published", &"<counter>")
            .field("drafts_created", &"<counter>")
            .field("events_recorded", &"<counter>")
            .field("feeds_replaced", &"<counter>")
            .finish()
    }
}

/// Common attribute set used by domain counters. Currently empty (the four
/// counters in v1 are unlabeled), but the helper survives if a future
/// labelling decision lands without rewriting every increment site.
pub fn no_attrs() -> Vec<KeyValue> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_op_metrics_construct_without_meter_provider() {
        // Arrange / Act
        let m = DomainMetrics::no_op();

        // Assert — incrementing a no-op counter is a no-panic no-op.
        m.articles_published.add(1, &no_attrs());
        m.drafts_created.add(1, &no_attrs());
        m.events_recorded.add(7, &no_attrs());
        m.feeds_replaced.add(1, &no_attrs());
    }

    #[test]
    fn default_impl_returns_no_op() {
        // Arrange / Act
        let m = DomainMetrics::default();

        // Assert
        m.articles_published.add(0, &no_attrs());
    }
}
