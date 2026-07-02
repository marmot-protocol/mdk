use serde::{Deserialize, Serialize};
use transport_nostr_adapter::{
    DurationHistogramSnapshot, NostrAdapterMetrics, RelayDeliverySpread, RelaySyncSnapshot,
};

use super::RelayPlaneHealth;

/// Device-local relay telemetry bundled for local inspection.
///
/// This is the read model behind `dm relay-stats`: it surfaces the adapter's
/// existing aggregate, privacy-safe snapshots (lifecycle counters, cross-relay
/// arrival spread, subscription sync timing) alongside redacted relay health.
///
/// Per-relay attribution stays behind opaque [`transport_nostr_adapter::RelayIndex`]
/// values here — resolving an index to a relay URL is reserved for the opt-in
/// export boundary, never for this local read path.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct RelayTelemetrySnapshot {
    /// Adapter lifecycle counters (accounts, subscriptions, inbound, publish).
    pub metrics: NostrAdapterMetrics,
    /// Cross-relay arrival spread and per-relay first-deliverer attribution.
    pub delivery_spread: RelayDeliverySpread,
    /// First-event / EOSE subscription sync timing, aggregate and per relay.
    pub sync: RelaySyncSnapshot,
    /// Redacted relay-pool and directory health.
    pub health: RelayPlaneHealth,
}

/// Export-ready rollup of device-local relay telemetry.
///
/// This is the aggregation home for the export path. There is a single shared
/// adapter per device, so the per-relay series are already merged across every
/// local account; this rollup reorganizes them into the export shape and is the
/// one place additional per-account dedup would live if telemetry ever became
/// per-account. It stays keyed by the opaque [`transport_nostr_adapter::RelayIndex`];
/// resolving an index to a relay URL is the exporter's job, behind opt-in.
///
/// Privacy-safe: counts, fixed-bucket millisecond histograms, and opaque relay
/// indices only — no account, group, subscription, or URL fields.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct RelayTelemetryRollup {
    /// Per-relay export records, ascending by opaque relay index.
    pub relays: Vec<RelayRollupEntry>,
    /// Population-level cross-relay arrival spread (inherently no relay label).
    pub cross_relay_spread: DurationHistogramSnapshot,
    /// Distinct logical messages observed within the tracking window.
    pub messages_observed: u64,
    /// Messages corroborated by at least a second distinct relay.
    pub messages_corroborated: u64,
    /// Messages seen on exactly one relay within the window.
    pub messages_single_source: u64,
    /// Device-wide relay connection attempts (for connection success rate).
    pub connection_attempts: u64,
    /// Device-wide successful relay connections.
    pub connection_successes: u64,
    /// Device-wide publish attempts (aggregate; per-relay/per-kind publish
    /// attribution is a future adapter enhancement, see `relay-observability.md`).
    pub publish_attempts: u64,
    /// Device-wide accepted publishes.
    pub publish_successes: u64,
    /// Device-wide failed publishes.
    pub publish_failures: u64,
    /// Optional engine-side reorg metrics, folded in once the parallel
    /// `observed_reorg_rate` workstream lands. `None` until then.
    pub engine: Option<EngineReorgMetrics>,
}

impl RelayTelemetryRollup {
    /// Derived `observed_reorg_rate = post_settle_reorgs / settles` from the
    /// folded-in engine metrics, if present and non-empty.
    pub fn observed_reorg_rate(&self) -> Option<f64> {
        let engine = self.engine.as_ref()?;
        (engine.settles > 0).then(|| engine.post_settle_reorgs as f64 / engine.settles as f64)
    }
}

/// One relay's export-ready record, keyed by opaque device-local index.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct RelayRollupEntry {
    /// Opaque device-local relay index (resolved to a URL only at export).
    pub relay_index: u32,
    /// First-event latency from subscribe time, in local-time milliseconds.
    pub first_event_latency: DurationHistogramSnapshot,
    /// EOSE latency from subscribe time, in local-time milliseconds.
    pub eose_latency: DurationHistogramSnapshot,
    /// Copies this relay surfaced first (delivery + first-deliverer signal).
    pub delivered_first: u64,
    /// Copies this relay corroborated after another relay surfaced first.
    pub delivered_later: u64,
}

impl RelayRollupEntry {
    /// Total copies this relay delivered (`relay_delivery_count`).
    pub fn delivery_count(&self) -> u64 {
        self.delivered_first + self.delivered_later
    }

    /// Copies that corroborated a message another relay surfaced first
    /// (`relay_redundant_count`).
    pub fn redundant_count(&self) -> u64 {
        self.delivered_later
    }

    /// Fraction of this relay's copies that arrived first, in `0.0..=1.0`.
    /// `None` when the relay has delivered nothing.
    pub fn first_deliverer_rate(&self) -> Option<f64> {
        let total = self.delivery_count();
        (total > 0).then(|| self.delivered_first as f64 / total as f64)
    }
}

/// Engine-side relay-tuning metrics folded into the export rollup.
///
/// Owned by the engine (the parallel `observed_reorg_rate` workstream), not the
/// adapter. This is the seam: [`MarmotRelayPlane::telemetry_rollup`] accepts it
/// as an optional input and the exporter ships it over the same OTLP path.
/// `None` until the engine metric lands. Shapes mirror `relay-delivery-telemetry.md`
/// "Validation: post-settle reorg rate"; the engine session may extend it
/// (for example with `reorg_rewind_depth`) without disturbing the seam.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct EngineReorgMetrics {
    /// Settle episodes, summed across groups (denominator).
    pub settles: u64,
    /// Settles later superseded by a diverging branch (numerator).
    pub post_settle_reorgs: u64,
    /// Local time from a superseded settle to the reorg, in milliseconds — the
    /// extra quiescence that would have avoided each reorg.
    pub reorg_lateness_ms: DurationHistogramSnapshot,
}

/// Reshape the adapter snapshots into the export-ready rollup. Pure so the
/// aggregation is unit-testable without a live relay plane.
pub(crate) fn rollup_from_snapshots(
    spread: RelayDeliverySpread,
    sync: RelaySyncSnapshot,
    metrics: NostrAdapterMetrics,
    health: RelayPlaneHealth,
    engine: Option<EngineReorgMetrics>,
) -> RelayTelemetryRollup {
    let mut indices: Vec<u32> = spread
        .per_relay
        .iter()
        .map(|stats| stats.relay_index)
        .chain(sync.per_relay.iter().map(|stats| stats.relay_index))
        .collect();
    indices.sort_unstable();
    indices.dedup();

    let relays = indices
        .into_iter()
        .map(|relay_index| {
            let delivery = spread
                .per_relay
                .iter()
                .find(|stats| stats.relay_index == relay_index);
            let latency = sync
                .per_relay
                .iter()
                .find(|stats| stats.relay_index == relay_index);
            RelayRollupEntry {
                relay_index,
                first_event_latency: latency
                    .map(|stats| stats.first_event.clone())
                    .unwrap_or_default(),
                eose_latency: latency.map(|stats| stats.eose.clone()).unwrap_or_default(),
                delivered_first: delivery
                    .map(|stats| stats.delivered_first)
                    .unwrap_or_default(),
                delivered_later: delivery
                    .map(|stats| stats.delivered_later)
                    .unwrap_or_default(),
            }
        })
        .collect();

    RelayTelemetryRollup {
        relays,
        cross_relay_spread: spread.spread,
        messages_observed: spread.observed,
        messages_corroborated: spread.corroborated,
        messages_single_source: spread.single_source,
        connection_attempts: health.connection_attempts as u64,
        connection_successes: health.connection_successes as u64,
        publish_attempts: metrics.publish_attempts as u64,
        publish_successes: metrics.publish_successes as u64,
        publish_failures: metrics.publish_failures as u64,
        engine,
    }
}
