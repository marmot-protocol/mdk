//! Relay delivery telemetry: cross-relay arrival spread and subscription sync
//! timing, with per-relay attribution behind opaque local indices.
//!
//! Implements phases 1 and 2 of the measurement model in
//! `docs/marmot-architecture/relay-delivery-telemetry.md`, plus the per-relay
//! attribution that `docs/marmot-architecture/relay-observability.md` needs:
//!
//! - [`RelayDeliveryTelemetry`] records, per logical message seen on more than
//!   one relay, the local-time delta between the first copy and each later
//!   distinct-relay copy (cross-relay arrival spread), and per relay how often
//!   it delivered a copy first vs. later (first-deliverer rate).
//! - [`RelaySyncTelemetry`] records, per subscription, when each relay
//!   delivered its first event and its EOSE relative to subscribe time, whether
//!   every subscribed relay has reached EOSE (the initial-sync gate), and the
//!   first-event / EOSE latency histograms both in aggregate and per relay.
//!
//! Relays are identified inside this module only by an opaque [`RelayIndex`].
//! The endpoint-to-index mapping ([`RelayIndexRegistry`]) is held by the adapter
//! and stays device-local, so per-relay telemetry never puts a relay URL in a
//! snapshot. Resolving an index back to a relay is the export layer's job.
//!
//! Privacy: all timing uses a local monotonic clock, never Nostr `created_at`
//! (which is identical across copies of an event and publisher-controlled).
//! Snapshots expose only opaque relay indices, aggregate histogram buckets, and
//! counts.

use std::collections::HashMap;
use std::collections::HashSet;

use cgka_traits::MessageId;
use cgka_traits::TransportEndpoint;
use serde::{Deserialize, Serialize};

/// Upper bounds, in milliseconds, of the duration histogram buckets shared by
/// spread and sync-timing measurements.
///
/// A delta is counted in the first bucket whose bound it does not exceed.
/// Deltas above the last bound fall in a dedicated overflow bucket.
///
/// Deliberately fine-grained: the collected data is only as precise as the
/// bucket edges, and we want high-resolution percentiles for both relay ranking
/// and quiescence tuning, with the densest resolution across the 10ms-2s
/// delivery-jitter range that matters most. Memory is a handful of `u64`
/// counters per histogram, so finer buckets are cheap.
const BUCKET_BOUNDS_MS: [u64; 24] = [
    1, 2, 5, 10, 20, 30, 50, 75, 100, 150, 200, 300, 500, 750, 1000, 1500, 2000, 3000, 5000, 7500,
    10000, 15000, 20000, 30000,
];

/// Default retention window for the per-message first-sighting table.
///
/// A message first seen longer ago than this is pruned. If it was only ever
/// seen on one relay it is counted as single-source. The window should be
/// comfortably larger than the largest histogram bucket so that genuine laggard
/// copies are still corroborated rather than pruned.
const DEFAULT_TRACKING_WINDOW_MS: u64 = 60_000;

/// Opaque, device-local relay identifier, stable within a process.
///
/// Never a relay URL. The endpoint-to-index mapping lives in
/// [`RelayIndexRegistry`] and stays on the device, so per-relay telemetry can
/// exist without exporting relay URLs.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
pub struct RelayIndex(pub u32);

/// Device-local assignment of stable opaque indices to relay endpoints.
#[derive(Clone, Debug, Default)]
pub struct RelayIndexRegistry {
    indices: HashMap<TransportEndpoint, RelayIndex>,
    next: u32,
}

impl RelayIndexRegistry {
    /// Stable index for `endpoint`, assigning a new one on first sighting.
    pub fn index_for(&mut self, endpoint: &TransportEndpoint) -> RelayIndex {
        if let Some(index) = self.indices.get(endpoint) {
            return *index;
        }
        let index = RelayIndex(self.next);
        self.next += 1;
        self.indices.insert(endpoint.clone(), index);
        index
    }

    /// Resolve an opaque index back to its relay endpoint, if one is assigned.
    ///
    /// This is the only reverse mapping in the module. It exists solely for the
    /// opt-in export label boundary; the adapter gates access behind
    /// [`RelayExportConsent`], so callers cannot reach a populated registry
    /// without one.
    pub fn resolve(&self, index: RelayIndex) -> Option<&TransportEndpoint> {
        self.indices
            .iter()
            .find_map(|(endpoint, candidate)| (*candidate == index).then_some(endpoint))
    }

    /// Every assigned `(index, endpoint)` pair, ascending by index.
    pub fn resolutions(&self) -> Vec<(RelayIndex, TransportEndpoint)> {
        let mut pairs: Vec<(RelayIndex, TransportEndpoint)> = self
            .indices
            .iter()
            .map(|(endpoint, index)| (*index, endpoint.clone()))
            .collect();
        pairs.sort_by_key(|(index, _)| index.0);
        pairs
    }
}

/// Capability that authorizes resolving opaque [`RelayIndex`] values back to
/// relay endpoints for the opt-in telemetry export boundary.
///
/// Relay identity is the sole identifier permitted to leave the device, and
/// only as the subject being measured (see
/// `docs/marmot-architecture/relay-observability.md`). Turning a device-local
/// index into a relay URL therefore requires one of these tokens, and a token
/// MUST be minted only where the user has explicitly opted in to export. There
/// is deliberately no other path from an index to a relay URL.
#[derive(Clone, Copy, Debug)]
pub struct RelayExportConsent {
    _seal: (),
}

impl RelayExportConsent {
    /// Affirm the relay-telemetry export opt-in.
    ///
    /// Call ONLY from the opt-in export boundary, after confirming the user has
    /// enabled export. Minting a consent token anywhere else violates the
    /// privacy contract in `relay-observability.md`.
    pub fn affirm() -> Self {
        Self { _seal: () }
    }
}

/// Resolved relay-identity labels for the export boundary.
///
/// Maps opaque device-local [`RelayIndex`] values to their relay endpoints.
/// Produced only behind [`RelayExportConsent`]; this is the one place a relay
/// URL is attached to telemetry, and only for first-party export.
#[derive(Clone, Debug, Default)]
pub struct RelayLabelResolution {
    labels: HashMap<RelayIndex, TransportEndpoint>,
}

impl RelayLabelResolution {
    /// Build a resolution from `(index, endpoint)` pairs.
    pub fn from_pairs(pairs: impl IntoIterator<Item = (RelayIndex, TransportEndpoint)>) -> Self {
        Self {
            labels: pairs.into_iter().collect(),
        }
    }

    /// Relay endpoint label for an index, if known.
    pub fn label_for(&self, index: RelayIndex) -> Option<&TransportEndpoint> {
        self.labels.get(&index)
    }

    /// Number of resolved relay labels.
    pub fn len(&self) -> usize {
        self.labels.len()
    }

    /// Whether no relay labels are resolved.
    pub fn is_empty(&self) -> bool {
        self.labels.is_empty()
    }
}

/// Internal fixed-bucket duration histogram in milliseconds.
#[derive(Clone, Debug, Default)]
struct DurationHistogram {
    buckets: [u64; BUCKET_BOUNDS_MS.len()],
    overflow: u64,
}

impl DurationHistogram {
    fn record(&mut self, delta_ms: u64) {
        for (idx, bound) in BUCKET_BOUNDS_MS.iter().enumerate() {
            if delta_ms <= *bound {
                self.buckets[idx] += 1;
                return;
            }
        }
        self.overflow += 1;
    }

    fn snapshot(&self) -> DurationHistogramSnapshot {
        let buckets = BUCKET_BOUNDS_MS
            .iter()
            .zip(self.buckets.iter())
            .map(|(bound, count)| HistogramBucket {
                upper_bound_ms: *bound,
                count: *count,
            })
            .collect();
        DurationHistogramSnapshot {
            buckets,
            overflow_count: self.overflow,
        }
    }
}

/// Sum a set of histograms into one aggregate snapshot.
fn aggregate_histograms<'a>(
    histograms: impl Iterator<Item = &'a DurationHistogram>,
) -> DurationHistogramSnapshot {
    let mut buckets = [0u64; BUCKET_BOUNDS_MS.len()];
    let mut overflow = 0;
    for histogram in histograms {
        for (idx, count) in histogram.buckets.iter().enumerate() {
            buckets[idx] += count;
        }
        overflow += histogram.overflow;
    }
    DurationHistogramSnapshot {
        buckets: BUCKET_BOUNDS_MS
            .iter()
            .zip(buckets.iter())
            .map(|(bound, count)| HistogramBucket {
                upper_bound_ms: *bound,
                count: *count,
            })
            .collect(),
        overflow_count: overflow,
    }
}

/// One histogram bucket of a duration distribution.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistogramBucket {
    /// Inclusive upper bound of the bucket, in milliseconds.
    pub upper_bound_ms: u64,
    /// Number of samples whose duration fell in this bucket.
    pub count: u64,
}

/// Aggregate duration histogram snapshot.
///
/// Contains only counts and millisecond bucket bounds: no message ids, relay
/// endpoints, subscription ids, or payload-derived values.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurationHistogramSnapshot {
    /// Histogram by ascending upper bound.
    pub buckets: Vec<HistogramBucket>,
    /// Samples whose duration exceeded the largest bucket bound.
    pub overflow_count: u64,
}

impl DurationHistogramSnapshot {
    /// Total number of samples across all buckets and the overflow.
    pub fn sample_count(&self) -> u64 {
        self.buckets.iter().map(|bucket| bucket.count).sum::<u64>() + self.overflow_count
    }

    /// Approximate `percentile` (0.0..=1.0), returned as the upper bound of the
    /// bucket the percentile falls in. Returns `None` when there are no samples,
    /// and `None` for the overflow region (the value is only known to exceed the
    /// largest bound), so callers treat an overflow-dominated distribution as
    /// "wider than the histogram measures."
    ///
    /// This is the primary input to a quiescence value: take a high percentile
    /// and add margin.
    pub fn approx_percentile_ms(&self, percentile: f64) -> Option<u64> {
        let total = self.sample_count();
        if total == 0 {
            return None;
        }
        let target = ((percentile.clamp(0.0, 1.0) * total as f64).ceil() as u64).max(1);
        let mut cumulative = 0;
        for bucket in &self.buckets {
            cumulative += bucket.count;
            if cumulative >= target {
                return Some(bucket.upper_bound_ms);
            }
        }
        // Remaining samples are in the overflow region: wider than measured.
        None
    }
}

/// First local-time sighting of a logical message and the relays that have
/// delivered it so far.
#[derive(Clone, Debug)]
struct FirstSighting {
    first_seen_ms: u64,
    relays: HashSet<RelayIndex>,
}

/// Per-relay delivery tallies for the first-deliverer rate.
#[derive(Clone, Debug, Default)]
struct DeliveryTally {
    delivered_first: u64,
    delivered_later: u64,
}

/// Local, aggregate cross-relay arrival-spread recorder.
///
/// Diagnostic only. Like [`crate::NostrAdapterMetrics`], it must never feed
/// convergence or branch selection.
#[derive(Clone, Debug)]
pub struct RelayDeliveryTelemetry {
    tracking_window_ms: u64,
    pending: HashMap<MessageId, FirstSighting>,
    spread: DurationHistogram,
    per_relay: HashMap<RelayIndex, DeliveryTally>,
    observed: u64,
    corroborated: u64,
    single_source: u64,
}

impl Default for RelayDeliveryTelemetry {
    fn default() -> Self {
        Self::with_window(DEFAULT_TRACKING_WINDOW_MS)
    }
}

impl RelayDeliveryTelemetry {
    pub fn with_window(tracking_window_ms: u64) -> Self {
        Self {
            tracking_window_ms,
            pending: HashMap::new(),
            spread: DurationHistogram::default(),
            per_relay: HashMap::new(),
            observed: 0,
            corroborated: 0,
            single_source: 0,
        }
    }

    /// Record one local-time sighting of `message_id` from `relay`.
    ///
    /// `now_ms` is a local monotonic timestamp in milliseconds. The same relay
    /// re-delivering a message is ignored; only the first sighting from each
    /// distinct relay contributes a spread sample. Pruning of the tracking
    /// window happens here so the table stays bounded without a timer.
    pub fn record_sighting(&mut self, message_id: &MessageId, relay: RelayIndex, now_ms: u64) {
        self.prune(now_ms);

        match self.pending.get_mut(message_id) {
            None => {
                self.observed += 1;
                self.per_relay.entry(relay).or_default().delivered_first += 1;
                let mut relays = HashSet::new();
                relays.insert(relay);
                self.pending.insert(
                    message_id.clone(),
                    FirstSighting {
                        first_seen_ms: now_ms,
                        relays,
                    },
                );
            }
            Some(sighting) => {
                if sighting.relays.insert(relay) {
                    // First time this distinct relay corroborates the message.
                    if sighting.relays.len() == 2 {
                        self.corroborated += 1;
                    }
                    self.per_relay.entry(relay).or_default().delivered_later += 1;
                    let delta = now_ms.saturating_sub(sighting.first_seen_ms);
                    self.spread.record(delta);
                }
            }
        }
    }

    /// Drop first-sighting entries older than the tracking window, counting any
    /// that never reached a second relay as single-source.
    fn prune(&mut self, now_ms: u64) {
        let window = self.tracking_window_ms;
        let mut newly_single = 0;
        self.pending.retain(|_, sighting| {
            let expired = now_ms.saturating_sub(sighting.first_seen_ms) > window;
            if expired && sighting.relays.len() == 1 {
                newly_single += 1;
            }
            !expired
        });
        self.single_source += newly_single;
    }

    /// Aggregate, privacy-safe snapshot for diagnostics and quiescence tuning.
    pub fn snapshot(&self) -> RelayDeliverySpread {
        let mut per_relay: Vec<RelayDeliveryStats> = self
            .per_relay
            .iter()
            .map(|(relay, tally)| RelayDeliveryStats {
                relay_index: relay.0,
                delivered_first: tally.delivered_first,
                delivered_later: tally.delivered_later,
            })
            .collect();
        per_relay.sort_by_key(|stats| stats.relay_index);
        RelayDeliverySpread {
            observed: self.observed,
            corroborated: self.corroborated,
            single_source: self.single_source,
            spread: self.spread.snapshot(),
            per_relay,
        }
    }
}

/// Per-relay delivery attribution for one relay.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayDeliveryStats {
    /// Opaque device-local relay index.
    pub relay_index: u32,
    /// Times this relay was the first to surface a message.
    pub delivered_first: u64,
    /// Times this relay corroborated a message another relay surfaced first.
    pub delivered_later: u64,
}

impl RelayDeliveryStats {
    /// Fraction of this relay's copies that arrived first, in `0.0..=1.0`.
    /// `None` when the relay has delivered nothing.
    pub fn first_deliverer_rate(&self) -> Option<f64> {
        let total = self.delivered_first + self.delivered_later;
        (total > 0).then(|| self.delivered_first as f64 / total as f64)
    }
}

/// Aggregate cross-relay arrival-spread snapshot.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct RelayDeliverySpread {
    /// Distinct logical messages observed within the tracking window.
    pub observed: u64,
    /// Messages corroborated by at least a second distinct relay.
    pub corroborated: u64,
    /// Messages pruned having been seen on exactly one relay.
    pub single_source: u64,
    /// Histogram of first-to-later-relay spread, in local-time milliseconds.
    pub spread: DurationHistogramSnapshot,
    /// Per-relay first-deliverer attribution, ascending by index.
    pub per_relay: Vec<RelayDeliveryStats>,
}

/// Per-relay subscription progress relative to subscribe time.
#[derive(Clone, Debug)]
struct RelayProgress {
    started_ms: u64,
    first_event_seen: bool,
    eose_seen: bool,
}

/// Progress of one subscription across the relays it was issued to.
#[derive(Clone, Debug, Default)]
struct SubscriptionProgress {
    relays: HashMap<RelayIndex, RelayProgress>,
}

/// Local recorder for subscription sync timing and the initial-sync gate.
///
/// Diagnostic only; must never feed convergence or branch selection.
#[derive(Clone, Debug, Default)]
pub struct RelaySyncTelemetry {
    subscriptions: HashMap<String, SubscriptionProgress>,
    first_event: HashMap<RelayIndex, DurationHistogram>,
    eose: HashMap<RelayIndex, DurationHistogram>,
}

impl RelaySyncTelemetry {
    /// Record that `subscription_id` was (re)issued to `relays` at `now_ms`.
    ///
    /// Resets per-relay progress so a resubscribe is measured from its new
    /// start. Relays dropped from the subscription stop being tracked.
    pub fn record_subscription_start(
        &mut self,
        subscription_id: &str,
        relays: &[RelayIndex],
        now_ms: u64,
    ) {
        let progress = self
            .subscriptions
            .entry(subscription_id.to_string())
            .or_default();
        progress.relays = relays
            .iter()
            .map(|relay| {
                (
                    *relay,
                    RelayProgress {
                        started_ms: now_ms,
                        first_event_seen: false,
                        eose_seen: false,
                    },
                )
            })
            .collect();
    }

    /// Record the first event from `relay` for `subscription_id`. Later events
    /// and unknown subscription/relay pairs are ignored.
    pub fn record_first_event(&mut self, subscription_id: &str, relay: RelayIndex, now_ms: u64) {
        if let Some(progress) = self
            .subscriptions
            .get_mut(subscription_id)
            .and_then(|sub| sub.relays.get_mut(&relay))
            && !progress.first_event_seen
        {
            progress.first_event_seen = true;
            self.first_event
                .entry(relay)
                .or_default()
                .record(now_ms.saturating_sub(progress.started_ms));
        }
    }

    /// Record EOSE from `relay` for `subscription_id`. Repeat EOSE and unknown
    /// subscription/relay pairs are ignored.
    pub fn record_eose(&mut self, subscription_id: &str, relay: RelayIndex, now_ms: u64) {
        if let Some(progress) = self
            .subscriptions
            .get_mut(subscription_id)
            .and_then(|sub| sub.relays.get_mut(&relay))
            && !progress.eose_seen
        {
            progress.eose_seen = true;
            self.eose
                .entry(relay)
                .or_default()
                .record(now_ms.saturating_sub(progress.started_ms));
        }
    }

    /// Whether every relay of `subscription_id` has reached EOSE.
    ///
    /// Returns `None` for an unknown subscription, `Some(false)` while any
    /// relay is still draining, `Some(true)` once all have completed. This is
    /// the initial-sync gate signal.
    pub fn subscription_synced(&self, subscription_id: &str) -> Option<bool> {
        self.subscriptions
            .get(subscription_id)
            .map(subscription_is_synced)
    }

    /// Aggregate, privacy-safe snapshot of subscription sync timing.
    pub fn snapshot(&self) -> RelaySyncSnapshot {
        let synced = self
            .subscriptions
            .values()
            .filter(|sub| subscription_is_synced(sub))
            .count() as u64;

        let mut relays: Vec<RelayIndex> = self
            .first_event
            .keys()
            .chain(self.eose.keys())
            .copied()
            .collect();
        relays.sort_unstable();
        relays.dedup();
        let per_relay = relays
            .into_iter()
            .map(|relay| RelayLatencyStats {
                relay_index: relay.0,
                first_event: self
                    .first_event
                    .get(&relay)
                    .map(DurationHistogram::snapshot)
                    .unwrap_or_default(),
                eose: self
                    .eose
                    .get(&relay)
                    .map(DurationHistogram::snapshot)
                    .unwrap_or_default(),
            })
            .collect();

        RelaySyncSnapshot {
            tracked_subscriptions: self.subscriptions.len() as u64,
            synced_subscriptions: synced,
            first_event: aggregate_histograms(self.first_event.values()),
            eose: aggregate_histograms(self.eose.values()),
            per_relay,
        }
    }
}

fn subscription_is_synced(sub: &SubscriptionProgress) -> bool {
    !sub.relays.is_empty() && sub.relays.values().all(|relay| relay.eose_seen)
}

/// Per-relay first-event and EOSE latency for one relay.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayLatencyStats {
    /// Opaque device-local relay index.
    pub relay_index: u32,
    /// First-event latency from subscribe time, in local-time milliseconds.
    pub first_event: DurationHistogramSnapshot,
    /// EOSE latency from subscribe time, in local-time milliseconds.
    pub eose: DurationHistogramSnapshot,
}

/// Aggregate subscription sync-timing snapshot.
///
/// Counts, opaque relay indices, and millisecond histograms only: no
/// subscription ids or relay endpoints.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelaySyncSnapshot {
    /// Subscriptions currently tracked.
    pub tracked_subscriptions: u64,
    /// Tracked subscriptions whose every relay has reached EOSE.
    pub synced_subscriptions: u64,
    /// Aggregate first-event latency across all relays.
    pub first_event: DurationHistogramSnapshot,
    /// Aggregate EOSE latency across all relays.
    pub eose: DurationHistogramSnapshot,
    /// Per-relay first-event / EOSE latency, ascending by index.
    pub per_relay: Vec<RelayLatencyStats>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(byte: u8) -> MessageId {
        MessageId::new(vec![byte; 32])
    }

    const A: RelayIndex = RelayIndex(0);
    const B: RelayIndex = RelayIndex(1);
    const C: RelayIndex = RelayIndex(2);

    #[test]
    fn registry_assigns_stable_indices() {
        let mut registry = RelayIndexRegistry::default();
        let a = TransportEndpoint("wss://a".into());
        let b = TransportEndpoint("wss://b".into());
        let first = registry.index_for(&a);
        assert_eq!(registry.index_for(&b), RelayIndex(1));
        assert_eq!(registry.index_for(&a), first, "stable across calls");
    }

    #[test]
    fn registry_resolves_indices_back_to_endpoints() {
        let mut registry = RelayIndexRegistry::default();
        let a = TransportEndpoint("wss://a".into());
        let b = TransportEndpoint("wss://b".into());
        let ia = registry.index_for(&a);
        let ib = registry.index_for(&b);

        assert_eq!(registry.resolve(ia), Some(&a));
        assert_eq!(registry.resolve(ib), Some(&b));
        assert_eq!(registry.resolve(RelayIndex(99)), None);
        assert_eq!(registry.resolutions(), vec![(ia, a), (ib, b)]);
    }

    #[test]
    fn relay_label_resolution_maps_indices_to_endpoints() {
        let resolution = RelayLabelResolution::from_pairs([
            (RelayIndex(0), TransportEndpoint("wss://a".into())),
            (RelayIndex(1), TransportEndpoint("wss://b".into())),
        ]);
        assert_eq!(resolution.len(), 2);
        assert!(!resolution.is_empty());
        assert_eq!(
            resolution.label_for(RelayIndex(1)),
            Some(&TransportEndpoint("wss://b".into()))
        );
        assert_eq!(resolution.label_for(RelayIndex(2)), None);
        assert!(RelayLabelResolution::default().is_empty());
    }

    #[test]
    fn single_relay_sighting_records_no_spread() {
        let mut telem = RelayDeliveryTelemetry::default();
        telem.record_sighting(&msg(1), A, 0);

        let snap = telem.snapshot();
        assert_eq!(snap.observed, 1);
        assert_eq!(snap.corroborated, 0);
        assert_eq!(snap.spread.sample_count(), 0);
        // The first (and only) deliverer is relay A.
        assert_eq!(snap.per_relay.len(), 1);
        assert_eq!(snap.per_relay[0].relay_index, 0);
        assert_eq!(snap.per_relay[0].delivered_first, 1);
        assert_eq!(snap.per_relay[0].first_deliverer_rate(), Some(1.0));
    }

    #[test]
    fn second_distinct_relay_records_spread_in_local_time() {
        let mut telem = RelayDeliveryTelemetry::default();
        telem.record_sighting(&msg(1), A, 100);
        // Same message, later, from a different relay: 40ms spread.
        telem.record_sighting(&msg(1), B, 140);

        let snap = telem.snapshot();
        assert_eq!(snap.observed, 1);
        assert_eq!(snap.corroborated, 1);
        assert_eq!(snap.spread.sample_count(), 1);
        let bucket = snap
            .spread
            .buckets
            .iter()
            .find(|b| b.upper_bound_ms == 50)
            .expect("50ms bucket");
        assert_eq!(bucket.count, 1);
        // A delivered first, B delivered later.
        let a = &snap.per_relay[0];
        let b = &snap.per_relay[1];
        assert_eq!((a.delivered_first, a.delivered_later), (1, 0));
        assert_eq!((b.delivered_first, b.delivered_later), (0, 1));
        assert_eq!(b.first_deliverer_rate(), Some(0.0));
    }

    #[test]
    fn same_relay_redelivery_is_ignored() {
        let mut telem = RelayDeliveryTelemetry::default();
        telem.record_sighting(&msg(1), A, 0);
        telem.record_sighting(&msg(1), A, 500);

        let snap = telem.snapshot();
        assert_eq!(snap.corroborated, 0);
        assert_eq!(snap.spread.sample_count(), 0);
        assert_eq!(snap.per_relay[0].delivered_later, 0);
    }

    #[test]
    fn third_relay_adds_a_second_sample_but_not_a_second_corroboration() {
        let mut telem = RelayDeliveryTelemetry::default();
        telem.record_sighting(&msg(1), A, 0);
        telem.record_sighting(&msg(1), B, 20);
        telem.record_sighting(&msg(1), C, 300);

        let snap = telem.snapshot();
        assert_eq!(snap.corroborated, 1);
        assert_eq!(snap.spread.sample_count(), 2);
    }

    #[test]
    fn first_deliverer_rate_reflects_mixed_races() {
        let mut telem = RelayDeliveryTelemetry::default();
        // msg 1: A first, B later. msg 2: B first, A later.
        telem.record_sighting(&msg(1), A, 0);
        telem.record_sighting(&msg(1), B, 10);
        telem.record_sighting(&msg(2), B, 0);
        telem.record_sighting(&msg(2), A, 10);

        let snap = telem.snapshot();
        assert_eq!(snap.per_relay[0].first_deliverer_rate(), Some(0.5));
        assert_eq!(snap.per_relay[1].first_deliverer_rate(), Some(0.5));
    }

    #[test]
    fn expired_single_source_message_is_counted_on_prune() {
        let mut telem = RelayDeliveryTelemetry::with_window(1_000);
        telem.record_sighting(&msg(1), A, 0);
        telem.record_sighting(&msg(2), A, 2_000);

        let snap = telem.snapshot();
        assert_eq!(snap.single_source, 1);
    }

    #[test]
    fn percentile_reads_the_bucket_the_target_falls_in() {
        let mut telem = RelayDeliveryTelemetry::default();
        for byte in 0..9u8 {
            telem.record_sighting(&msg(byte), A, 0);
            telem.record_sighting(&msg(byte), B, 5);
        }
        telem.record_sighting(&msg(200), A, 0);
        telem.record_sighting(&msg(200), B, 2_000);

        let snap = telem.snapshot();
        assert_eq!(snap.spread.sample_count(), 10);
        // p50 sits among the fast 5ms samples; p100 reaches the 2000ms laggard.
        assert_eq!(snap.spread.approx_percentile_ms(0.5), Some(5));
        assert_eq!(snap.spread.approx_percentile_ms(1.0), Some(2000));
    }

    #[test]
    fn percentile_is_none_without_samples() {
        let telem = RelayDeliveryTelemetry::default();
        assert_eq!(telem.snapshot().spread.approx_percentile_ms(0.99), None);
    }

    #[test]
    fn spread_beyond_largest_bucket_counts_as_overflow() {
        let mut telem = RelayDeliveryTelemetry::default();
        telem.record_sighting(&msg(1), A, 0);
        telem.record_sighting(&msg(1), B, 40_000);

        let snap = telem.snapshot();
        assert_eq!(snap.spread.overflow_count, 1);
        assert_eq!(snap.spread.sample_count(), 1);
        assert_eq!(snap.spread.approx_percentile_ms(1.0), None);
    }

    #[test]
    fn unknown_subscription_has_no_sync_state() {
        let telem = RelaySyncTelemetry::default();
        assert_eq!(telem.subscription_synced("sub"), None);
    }

    #[test]
    fn subscription_is_synced_only_when_all_relays_eose() {
        let mut telem = RelaySyncTelemetry::default();
        telem.record_subscription_start("sub", &[A, B], 0);
        assert_eq!(telem.subscription_synced("sub"), Some(false));

        telem.record_eose("sub", A, 30);
        assert_eq!(telem.subscription_synced("sub"), Some(false));

        telem.record_eose("sub", B, 70);
        assert_eq!(telem.subscription_synced("sub"), Some(true));

        let snap = telem.snapshot();
        assert_eq!(snap.tracked_subscriptions, 1);
        assert_eq!(snap.synced_subscriptions, 1);
        assert_eq!(snap.eose.sample_count(), 2);
        // Per-relay EOSE latency is attributed to both relays.
        assert_eq!(snap.per_relay.len(), 2);
        assert_eq!(snap.per_relay[0].eose.sample_count(), 1);
        assert_eq!(snap.per_relay[1].eose.sample_count(), 1);
    }

    #[test]
    fn first_event_latency_recorded_once_per_relay() {
        let mut telem = RelaySyncTelemetry::default();
        telem.record_subscription_start("sub", &[A], 100);
        telem.record_first_event("sub", A, 140);
        telem.record_first_event("sub", A, 900);

        let snap = telem.snapshot();
        assert_eq!(snap.first_event.sample_count(), 1);
        assert_eq!(snap.per_relay[0].relay_index, 0);
        assert_eq!(snap.per_relay[0].first_event.sample_count(), 1);
        let bucket = snap
            .first_event
            .buckets
            .iter()
            .find(|b| b.upper_bound_ms == 50)
            .expect("50ms bucket");
        assert_eq!(bucket.count, 1);
    }

    #[test]
    fn events_for_untracked_subscription_are_ignored() {
        let mut telem = RelaySyncTelemetry::default();
        telem.record_first_event("ghost", A, 10);
        telem.record_eose("ghost", A, 20);

        let snap = telem.snapshot();
        assert_eq!(snap.tracked_subscriptions, 0);
        assert_eq!(snap.first_event.sample_count(), 0);
        assert_eq!(snap.eose.sample_count(), 0);
        assert!(snap.per_relay.is_empty());
    }

    #[test]
    fn resubscribe_resets_relay_progress() {
        let mut telem = RelaySyncTelemetry::default();
        telem.record_subscription_start("sub", &[A], 0);
        telem.record_eose("sub", A, 10);
        assert_eq!(telem.subscription_synced("sub"), Some(true));

        // Reissued: the prior EOSE no longer counts.
        telem.record_subscription_start("sub", &[A], 100);
        assert_eq!(telem.subscription_synced("sub"), Some(false));
    }
}
