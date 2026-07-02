use cgka_traits::TransportEndpoint;
use transport_nostr_adapter::HistogramBucket;

use crate::app_telemetry::{AppPerformanceOperationSnapshot, AppPerformanceSnapshot};
use crate::config::{RelayTelemetryResource, RelayTelemetryRuntimeConfig};
use crate::relay_plane::{EngineReorgMetrics, RelayRollupEntry, RelayTelemetryRollup};

use super::*;

fn hist(count: u64) -> DurationHistogramSnapshot {
    DurationHistogramSnapshot {
        buckets: vec![HistogramBucket {
            upper_bound_ms: 50,
            count,
        }],
        overflow_count: 0,
    }
}

fn runtime_config() -> RelayTelemetryRuntimeConfig {
    RelayTelemetryRuntimeConfig {
        otlp_endpoint: Some("https://otlp.example.org/v1/metrics".to_owned()),
        authorization_bearer_token: Some("token".to_owned()),
        resource: Some(RelayTelemetryResource {
            service_version: "1.4.2".to_owned(),
            service_instance_id: "8e1ca50b-05a2-4c31-a31c-1e69c75a9366".to_owned(),
            deployment_environment: "staging".to_owned(),
            tenant: "darkmatter-ios".to_owned(),
            os_type: "ios".to_owned(),
            os_version: "17.5".to_owned(),
            device_model_identifier: None,
        }),
    }
}

#[test]
fn build_export_batch_labels_only_resolved_relays() {
    let rollup = RelayTelemetryRollup {
        relays: vec![
            RelayRollupEntry {
                relay_index: 0,
                first_event_latency: hist(2),
                eose_latency: hist(1),
                delivered_first: 3,
                delivered_later: 1,
            },
            // Index 1 has no resolved label, so it must be skipped entirely.
            RelayRollupEntry {
                relay_index: 1,
                delivered_first: 9,
                ..Default::default()
            },
        ],
        cross_relay_spread: hist(5),
        messages_observed: 5,
        connection_attempts: 4,
        connection_successes: 3,
        publish_attempts: 2,
        publish_successes: 2,
        ..Default::default()
    };
    let resolution = RelayLabelResolution::from_pairs([(
        RelayIndex(0),
        TransportEndpoint("wss://a.example".into()),
    )]);

    let batch = build_export_batch(&rollup, &resolution);

    // Only the resolved relay appears, and only as a `relay` label.
    assert_eq!(batch.relay_labels(), vec!["wss://a.example"]);

    let relay_points: Vec<_> = batch
        .points
        .iter()
        .filter(|point| point.relay.is_some())
        .collect();
    assert!(
        relay_points
            .iter()
            .all(|point| point.relay.as_deref() == Some("wss://a.example")),
        "every per-relay point carries the single resolved relay label",
    );
    assert!(
        relay_points
            .iter()
            .any(|point| point.name == metric_names::FIRST_EVENT_LATENCY)
    );
    assert!(relay_points.iter().any(|point| {
        point.name == metric_names::DELIVERY_COUNT && point.value == ExportMetricValue::Counter(4)
    }));
    assert!(relay_points.iter().any(|point| {
        point.name == metric_names::FIRST_DELIVERER_RATE
            && point.value == ExportMetricValue::Gauge(0.75)
    }));

    // Population points carry no label, and the cross-relay spread is one.
    assert!(
        batch.points.iter().any(|point| {
            point.name == metric_names::CROSS_RELAY_SPREAD && point.relay.is_none()
        })
    );
    // No publish/connection/population point ever carries a relay label.
    assert!(
        batch
            .points
            .iter()
            .filter(|point| point.name != metric_names::FIRST_EVENT_LATENCY
                && point.name != metric_names::EOSE_LATENCY
                && point.name != metric_names::DELIVERY_COUNT
                && point.name != metric_names::REDUNDANT_COUNT
                && point.name != metric_names::FIRST_DELIVERER_RATE)
            .all(|point| point.relay.is_none())
    );
}

#[test]
fn build_export_batch_forwards_histogram_bucket_edges() {
    let rollup = RelayTelemetryRollup {
        cross_relay_spread: DurationHistogramSnapshot {
            buckets: vec![
                HistogramBucket {
                    upper_bound_ms: 10,
                    count: 1,
                },
                HistogramBucket {
                    upper_bound_ms: 50,
                    count: 2,
                },
            ],
            overflow_count: 4,
        },
        ..Default::default()
    };
    let batch = build_export_batch(&rollup, &RelayLabelResolution::default());
    let spread = batch
        .points
        .iter()
        .find(|point| point.name == metric_names::CROSS_RELAY_SPREAD)
        .expect("cross relay spread point");
    match &spread.value {
        ExportMetricValue::Histogram(histogram) => {
            assert_eq!(histogram.bounds_ms, vec![10, 50]);
            assert_eq!(histogram.bucket_counts, vec![1, 2]);
            assert_eq!(histogram.overflow_count, 4);
            assert_eq!(histogram.total(), 7);
        }
        other => panic!("expected histogram, got {other:?}"),
    }
}

#[test]
fn build_export_batch_folds_in_engine_metrics_when_present() {
    let rollup = RelayTelemetryRollup {
        engine: Some(EngineReorgMetrics {
            settles: 4,
            post_settle_reorgs: 1,
            reorg_lateness_ms: hist(1),
        }),
        ..Default::default()
    };
    let batch = build_export_batch(&rollup, &RelayLabelResolution::default());
    assert!(batch.points.iter().any(|point| {
        point.name == metric_names::OBSERVED_REORG_RATE
            && point.value == ExportMetricValue::Gauge(0.25)
    }));
    assert!(
        batch
            .points
            .iter()
            .any(|point| point.name == metric_names::REORG_LATENESS)
    );
    // Engine metrics are population-level: no relay label.
    assert!(
        batch
            .points
            .iter()
            .filter(|point| point.name == metric_names::SETTLES
                || point.name == metric_names::POST_SETTLE_REORGS
                || point.name == metric_names::OBSERVED_REORG_RATE
                || point.name == metric_names::REORG_LATENESS)
            .all(|point| point.relay.is_none())
    );
}

#[test]
fn build_export_batch_includes_unlabeled_message_counters() {
    let rollup = RelayTelemetryRollup {
        messages_observed: 5,
        messages_corroborated: 4,
        messages_single_source: 1,
        ..Default::default()
    };
    let batch = build_export_batch(&rollup, &RelayLabelResolution::default());

    for (name, value) in [
        (metric_names::MESSAGE_OBSERVED, 5),
        (metric_names::MESSAGE_CORROBORATED, 4),
        (metric_names::MESSAGE_SINGLE_SOURCE, 1),
    ] {
        assert!(batch.points.iter().any(|point| {
            point.name == name
                && point.relay.is_none()
                && point.value == ExportMetricValue::Counter(value)
        }));
        assert!(!name.ends_with("_total"));
    }
}

#[test]
fn build_export_batch_appends_unlabeled_app_performance_metrics() {
    let app_performance = AppPerformanceSnapshot {
        app_start: AppPerformanceOperationSnapshot {
            attempts: 3,
            successes: 2,
            failures: 1,
            duration_ms: hist(2),
        },
        group_invite_engine_publish: AppPerformanceOperationSnapshot {
            attempts: 1,
            successes: 1,
            failures: 0,
            duration_ms: hist(4),
        },
        group_details_read: AppPerformanceOperationSnapshot {
            attempts: 2,
            successes: 2,
            failures: 0,
            duration_ms: hist(1),
        },
        ..Default::default()
    };
    let batch = build_export_batch_with_app_performance(
        &RelayTelemetryRollup::default(),
        &RelayLabelResolution::default(),
        Some(&app_performance),
    );

    assert!(batch.points.iter().all(|point| point.relay.is_none()));
    assert!(batch.points.iter().any(|point| {
        point.name == metric_names::APP_START_ATTEMPTS
            && point.value == ExportMetricValue::Counter(3)
    }));
    assert!(batch.points.iter().any(|point| {
        point.name == metric_names::APP_START_SUCCESSES
            && point.value == ExportMetricValue::Counter(2)
    }));
    assert!(batch.points.iter().any(|point| {
        point.name == metric_names::APP_START_FAILURES
            && point.value == ExportMetricValue::Counter(1)
    }));
    assert!(batch.points.iter().any(|point| {
        point.name == metric_names::APP_GROUP_INVITE_ENGINE_PUBLISH_ATTEMPTS
            && point.value == ExportMetricValue::Counter(1)
    }));
    assert!(batch.points.iter().any(|point| {
        point.name == metric_names::APP_GROUP_DETAILS_READ_ATTEMPTS
            && point.value == ExportMetricValue::Counter(2)
    }));

    let duration = batch
        .points
        .iter()
        .find(|point| point.name == metric_names::APP_START_DURATION)
        .expect("app start duration metric");
    match &duration.value {
        ExportMetricValue::Histogram(histogram) => {
            assert_eq!(histogram.bounds_ms, vec![50]);
            assert_eq!(histogram.bucket_counts, vec![2]);
        }
        other => panic!("expected histogram, got {other:?}"),
    }
}

#[tokio::test]
async fn telemetry_exporter_is_gated_and_builds_population_only_batch() {
    let relay_plane = MarmotRelayPlane::full_history();

    // Off by default, and enabled-without-endpoint is still inert.
    assert!(
        relay_plane
            .telemetry_exporter(RelayTelemetryExportConfig::disabled())
            .is_none()
    );
    assert!(
        relay_plane
            .telemetry_exporter(RelayTelemetryExportConfig {
                enabled: true,
                endpoint: None,
                ..Default::default()
            })
            .is_none()
    );

    let exporter = relay_plane
        .telemetry_exporter(
            RelayTelemetryExportConfig::enabled("https://otlp.example/v1/metrics")
                .with_runtime_config(runtime_config()),
        )
        .expect("opted-in exporter is constructed");
    let batch = exporter.build_batch(None).await;

    // No relay traffic yet: population points only, no relay labels leak.
    assert!(batch.relay_labels().is_empty());
    assert!(
        batch
            .points
            .iter()
            .any(|point| point.name == metric_names::CROSS_RELAY_SPREAD)
    );
    assert!(batch.points.iter().all(|point| point.relay.is_none()));
}
