//! `relay-stats` command namespace handlers and aggregate telemetry rendering.

use marmot_app::{
    DurationHistogramSnapshot, MarmotApp, MarmotAppRuntime, RelayDeliverySpread,
    RelayDeliveryStats, RelayLatencyStats, RelaySyncSnapshot, RelayTelemetrySnapshot,
};

use crate::{CommandOutput, DmError};

pub(crate) async fn relay_stats_command(app: &MarmotApp) -> Result<CommandOutput, DmError> {
    relay_stats_output(app.relay_telemetry().await)
}

pub(crate) async fn relay_stats_command_with_runtime(
    runtime: &MarmotAppRuntime,
) -> Result<CommandOutput, DmError> {
    relay_stats_output(
        runtime
            .shared_services()
            .relay_plane()
            .relay_telemetry()
            .await,
    )
}

pub(crate) fn relay_stats_output(
    snapshot: RelayTelemetrySnapshot,
) -> Result<CommandOutput, DmError> {
    let json = serde_json::to_value(&snapshot)?;
    Ok(CommandOutput {
        plain: relay_stats_plain(&snapshot),
        json,
    })
}

/// Render a percentile of a duration histogram for the human view.
///
/// `n/a` when there are no samples; `>Nms` when the percentile falls in the
/// overflow region above the largest bucket bound.
fn relay_stats_percentile(hist: &DurationHistogramSnapshot, percentile: f64) -> String {
    if hist.sample_count() == 0 {
        return "n/a".to_owned();
    }
    match hist.approx_percentile_ms(percentile) {
        Some(ms) => format!("{ms}ms"),
        None => match hist.buckets.last() {
            Some(bucket) => format!(">{}ms", bucket.upper_bound_ms),
            None => "n/a".to_owned(),
        },
    }
}

pub(crate) fn relay_stats_plain(snapshot: &RelayTelemetrySnapshot) -> String {
    let metrics = &snapshot.metrics;
    let spread = &snapshot.delivery_spread;
    let sync = &snapshot.sync;
    let health = &snapshot.health;

    let mut lines = vec!["relay telemetry (device-local, aggregate, no relay URLs)".to_owned()];
    lines.push(format!(
        "accounts={} group_subscriptions={} created={} removed={}",
        metrics.active_accounts,
        metrics.active_group_subscriptions,
        metrics.subscriptions_created,
        metrics.subscriptions_removed,
    ));
    lines.push(format!(
        "inbound: seen={} delivered={} dropped={}",
        metrics.inbound_events_seen,
        metrics.inbound_events_delivered,
        metrics.inbound_events_dropped,
    ));
    lines.push(format!(
        "publish: attempts={} successes={} failures={}",
        metrics.publish_attempts, metrics.publish_successes, metrics.publish_failures,
    ));
    lines.push(format!(
        "delivery spread: observed={} corroborated={} single_source={} samples={} p50={} p99={}",
        spread.observed,
        spread.corroborated,
        spread.single_source,
        spread.spread.sample_count(),
        relay_stats_percentile(&spread.spread, 0.5),
        relay_stats_percentile(&spread.spread, 0.99),
    ));
    lines.push(format!(
        "sync: tracked_subscriptions={} synced={} first_event_p50={} eose_p50={}",
        sync.tracked_subscriptions,
        sync.synced_subscriptions,
        relay_stats_percentile(&sync.first_event, 0.5),
        relay_stats_percentile(&sync.eose, 0.5),
    ));

    let per_relay = relay_stats_per_relay_rows(spread, sync);
    if per_relay.is_empty() {
        lines.push("per-relay: none observed yet".to_owned());
    } else {
        lines.push("per-relay (opaque device-local index):".to_owned());
        lines.extend(per_relay);
    }

    lines.push(format!(
        "relay health: sdk_backed={} total={} connected={} connecting={} disconnected={} attempts={} successes={}",
        health.sdk_backed,
        health.total_relays,
        health.connected,
        health.connecting,
        health.disconnected,
        health.connection_attempts,
        health.connection_successes,
    ));
    lines.join("\n")
}

/// Join the per-relay delivery attribution and sync-timing rows by opaque relay
/// index into one line per relay.
fn relay_stats_per_relay_rows(
    spread: &RelayDeliverySpread,
    sync: &RelaySyncSnapshot,
) -> Vec<String> {
    let mut indices: Vec<u32> = spread
        .per_relay
        .iter()
        .map(|stats| stats.relay_index)
        .chain(sync.per_relay.iter().map(|stats| stats.relay_index))
        .collect();
    indices.sort_unstable();
    indices.dedup();

    indices
        .into_iter()
        .map(|index| {
            let delivery = spread
                .per_relay
                .iter()
                .find(|stats| stats.relay_index == index);
            let latency = sync
                .per_relay
                .iter()
                .find(|stats| stats.relay_index == index);
            relay_stats_per_relay_line(index, delivery, latency)
        })
        .collect()
}

fn relay_stats_per_relay_line(
    index: u32,
    delivery: Option<&RelayDeliveryStats>,
    latency: Option<&RelayLatencyStats>,
) -> String {
    let mut parts = vec![format!("  relay#{index}")];
    if let Some(delivery) = delivery {
        let rate = delivery
            .first_deliverer_rate()
            .map(|rate| format!("{:.0}%", rate * 100.0))
            .unwrap_or_else(|| "n/a".to_owned());
        parts.push(format!(
            "first_deliverer={rate} delivered_first={} delivered_later={}",
            delivery.delivered_first, delivery.delivered_later,
        ));
    }
    if let Some(latency) = latency {
        parts.push(format!(
            "first_event_p50={} eose_p50={}",
            relay_stats_percentile(&latency.first_event, 0.5),
            relay_stats_percentile(&latency.eose, 0.5),
        ));
    }
    parts.join(" ")
}
