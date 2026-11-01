//! Product-analytics tests that need a real `MarmotApp`, its runtime or `AppError`: consent
//! persistence, the runtime's host timing and shutdown drain, and how storage errors count. They
//! reach the collector through `wiring`, `Observer`'s views and the collector's test hooks.

#[cfg(feature = "product-analytics-export")]
use std::collections::BTreeMap;
#[cfg(feature = "product-analytics-export")]
use std::sync::atomic::Ordering;
#[cfg(feature = "product-analytics-export")]
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(feature = "product-analytics-export")]
use crate::{
    AppError, ProductAnalyticsActivity, ProductEvent, ProductEventMode, ProductEventSchema,
    ProductPropertyRule, ProductPropertySchema, ProductRecordResult, UsageDiagnosticsSettings,
};
use crate::{
    DiagnosticsExporterStatus, MarmotApp, ProductAnalyticsRuntimeConfig, ProductFamily,
    ProductUnit, UsageDiagnosticsDecision,
};
use marmot_observability::configured;
#[cfg(feature = "product-analytics-export")]
use marmot_observability::grant;
use marmot_observability::permit_valid;
#[cfg(feature = "product-analytics-export")]
use marmot_observability::wiring;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg(feature = "product-analytics-export")]
async fn custom_host_timing_events() {
    use crate::HostPerformanceOutcome::{Failure, Success};

    let (collector, _) = configured();
    let mut config = collector.config_for_test();
    config.registry.push(ProductEventSchema {
        name: "app_inbox_layout".into(),
        mode: ProductEventMode::Aggregate,
        properties: vec![
            ProductPropertySchema {
                name: "elapsed".into(),
                rule: ProductPropertyRule::DurationBucket,
            },
            ProductPropertySchema {
                name: "outcome".into(),
                rule: ProductPropertyRule::Enum(vec!["success".into(), "failure".into()]),
            },
        ],
    });
    wiring::configure(&collector, config, "http://127.0.0.1:9876".into()).unwrap();
    let root = tempfile::tempdir().unwrap();
    let mut app = MarmotApp::with_relay(root.path(), "wss://relay.example");
    app.product_analytics = collector.clone().into();
    let runtime = app.runtime();
    let elapsed = Duration::from_millis(250);
    assert_eq!(
        runtime
            .record_host_timing("app_inbox_layout".into(), elapsed, Success)
            .unwrap(),
        ProductRecordResult::IgnoredDisabled
    );
    grant(&collector);
    for name in ["app_unregistered", "app_test_view"] {
        assert!(
            runtime
                .record_host_timing(name.into(), elapsed, Success)
                .is_err()
        );
    }
    for (duration, outcome) in [
        (elapsed, Success),
        (elapsed + Duration::from_nanos(1), Failure),
    ] {
        assert_eq!(
            runtime
                .record_host_timing("app_inbox_layout".into(), duration, outcome)
                .unwrap(),
            ProductRecordResult::Recorded
        );
    }
    let rows = collector.test_payloads();
    let timings: Vec<_> = rows
        .iter()
        .filter(|row| row["eventName"] == "app_inbox_layout")
        .collect();
    assert_eq!(timings.len(), 2);
    for (outcome, bucket) in [("success", "le_250ms"), ("failure", "le_500ms")] {
        let row = timings
            .iter()
            .find(|row| row["props"]["outcome"] == outcome)
            .unwrap();
        assert_eq!(row["props"]["elapsed"], bucket);
        assert_eq!(row["props"]["count_bucket"], "1");
        assert!(collector.valid_payload_for_test(row));
    }
    wiring::set_receipt(
        &collector,
        UsageDiagnosticsSettings::default(),
        String::new(),
    );
    assert_eq!(
        runtime
            .record_host_timing("app_inbox_layout".into(), elapsed, Success)
            .unwrap(),
        ProductRecordResult::IgnoredDisabled
    );
    assert!(collector.test_payloads().is_empty());
}

#[test]
fn persistent_consent_revoke_and_reaccept_rotate_only_diagnostic_identity() {
    let tmp = tempfile::tempdir().unwrap();
    let app = crate::MarmotApp::with_relay(tmp.path(), "wss://relay.example");
    assert!(app.telemetry_install_id().is_err());
    assert_eq!(
        app.usage_diagnostics_settings().unwrap().decision,
        UsageDiagnosticsDecision::AcceptanceRequired
    );
    app.set_usage_diagnostics_consent(true).unwrap();
    let first = app.telemetry_install_id().unwrap();
    app.set_usage_diagnostics_consent(true).unwrap();
    assert_eq!(first, app.telemetry_install_id().unwrap());
    let permit = app.usage_diagnostics_permit().unwrap();
    app.set_usage_diagnostics_consent(false).unwrap();
    assert!(!permit_valid(&permit));
    assert!(app.telemetry_install_id().is_err());
    app.set_usage_diagnostics_consent(true).unwrap();
    assert_ne!(first, app.telemetry_install_id().unwrap());
    assert!(!permit_valid(&permit));
}

#[test]
fn failed_persistence_cannot_restore_a_grant_in_process() {
    let tmp = tempfile::tempdir().unwrap();
    let app = crate::MarmotApp::with_relay(tmp.path(), "wss://relay.example");
    app.set_usage_diagnostics_consent(true).unwrap();
    let permit = app.usage_diagnostics_permit().unwrap();
    app.close_storage().unwrap();
    assert!(app.set_usage_diagnostics_consent(false).is_err());
    assert!(!permit_valid(&permit));
    assert!(app.usage_diagnostics_permit().is_err());
    assert!(app.restore_usage_diagnostics().is_err());
}

#[cfg(feature = "product-analytics-export")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn terminal_shutdown_closes_storage_before_analytics_drain() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (c, clock) = configured();
    clock.wall.store(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        Ordering::Relaxed,
    );
    let home = tempfile::tempdir().unwrap();
    let mut app = MarmotApp::with_relay(home.path(), "wss://relay.example");
    app.product_analytics = c.clone().into();
    let runtime = app.runtime();
    let mut config = c.config_for_test();
    config.events_endpoint = Some(format!(
        "http://{}/api/v0/events",
        listener.local_addr().unwrap()
    ));
    runtime
        .set_product_analytics_runtime_config(config)
        .unwrap();
    runtime.set_usage_diagnostics_consent(true).unwrap();
    runtime
        .set_product_analytics_activity(ProductAnalyticsActivity::Foreground)
        .await;
    let server = async {
        let (mut stream, _) = tokio::time::timeout(Duration::from_secs(2), listener.accept())
            .await
            .unwrap()
            .unwrap();
        assert!(
            app.storage_is_closed(),
            "no database lease may survive until the analytics request"
        );
        let mut bytes = [0; 4096];
        let _ = stream.read(&mut bytes).await.unwrap();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
    };
    let (_, closed) = tokio::join!(server, runtime.shutdown_and_close());
    closed.unwrap();
    assert!(matches!(
        runtime.set_usage_diagnostics_consent(true),
        Err(AppError::RuntimeStopping)
    ));
    assert_eq!(
        runtime
            .record_product_event(ProductEvent {
                name: "app_screen_viewed".into(),
                properties: BTreeMap::from([("screen".into(), "inbox".into())])
            })
            .unwrap(),
        ProductRecordResult::IgnoredDisabled
    );
}

#[cfg(feature = "product-analytics-export")]
#[test]
fn storage_failures_are_classified_without_raw_causes_or_sync_fanout_duplicates() {
    let (c, clock) = configured();
    grant(&c);
    let permit = c.permit_for_test().unwrap();
    let error = AppError::Storage(cgka_traits::StorageError::Corruption(
        "private database contents".into(),
    ));
    assert_eq!(
        error.sync_error_class(),
        crate::SyncErrorClass::StorageCorruption
    );
    c.storage_failure_for_test(Some(&permit), &error);
    clock.mono.store(100, Ordering::Relaxed);
    let failure = crate::SyncFailureClassification::new(
        crate::SyncFailureStage::StatePersist,
        crate::SyncErrorClass::StorageBusy,
    );
    c.observe_sync_for_test("background", Duration::from_millis(20), Some(failure));
    for _ in 0..10 {
        c.storage_failure_for_test(
            Some(&permit),
            &AppError::AccountCatchUp(crate::AccountCatchUpFailure::new(
                "private raw cause".into(),
                failure,
            )),
        );
    }
    let rows = c.test_payloads();
    let storage: Vec<_> = rows
        .iter()
        .filter(|row| row["eventName"] == "mdk_storage_summary")
        .collect();
    assert_eq!(storage.len(), 2);
    assert!(
        storage
            .iter()
            .all(|row| row["props"]["count_bucket"] == "1")
    );
    assert!(!serde_json::to_string(&rows).unwrap().contains("private"));
}

#[test]
fn saved_permission_is_inspectable_without_loading_the_export_destination() {
    let tmp = tempfile::tempdir().unwrap();
    let app = crate::MarmotApp::with_relay(tmp.path(), "wss://relay.example");
    let runtime = app.runtime();
    let (configured, _) = configured();
    runtime
        .set_product_analytics_runtime_config(configured.config_for_test())
        .unwrap();
    let granted = runtime.set_usage_diagnostics_consent(true).unwrap();
    let standalone = crate::MarmotApp::with_relay(tmp.path(), "wss://relay.example").runtime();
    assert_eq!(
        standalone.stored_usage_diagnostics_settings().unwrap(),
        granted
    );
    assert_eq!(
        standalone.usage_diagnostics_settings().unwrap().decision,
        UsageDiagnosticsDecision::AcceptanceRequired
    );
    assert!(
        standalone
            .begin_product_operation(ProductFamily::Runtime, "startup", ProductUnit::Attempt)
            .is_none()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unreadable_optional_consent_does_not_abort_runtime_start() {
    let root = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relays(root.path(), vec![]);
    app.set_usage_diagnostics_consent(true).unwrap();
    let old_permit = app.usage_diagnostics_permit().unwrap();
    let connection = rusqlite::Connection::open(app.shared_storage_path()).unwrap();
    connection
        .execute(
            "UPDATE usage_diagnostics_settings SET updated_at_ms = 'invalid' WHERE id = 1",
            [],
        )
        .unwrap();
    let runtime = app.runtime();
    runtime.start().await.unwrap();
    assert!(!permit_valid(&old_permit));
    assert!(app.usage_diagnostics_permit().is_err());
    assert_eq!(
        runtime.usage_diagnostics_status().telemetry,
        DiagnosticsExporterStatus::Disabled
    );
    assert_eq!(
        runtime.usage_diagnostics_status().product_analytics,
        DiagnosticsExporterStatus::Disabled
    );
    assert!(runtime.usage_diagnostics_settings().is_err());
    assert!(
        runtime
            .set_product_analytics_runtime_config(ProductAnalyticsRuntimeConfig::default())
            .is_err(),
        "explicit reconfiguration must report the unreadable consent record"
    );
    assert!(app.usage_diagnostics_permit().is_err());
    runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn synchronous_consent_setters_use_the_started_runtime_executor() {
    let root = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relays(root.path(), vec![]);
    let runtime = app.runtime();
    runtime.start().await.unwrap();
    let host = runtime.clone();
    std::thread::spawn(move || {
        assert!(tokio::runtime::Handle::try_current().is_err());
        host.set_usage_diagnostics_consent(true).unwrap();
        host.set_product_analytics_runtime_config(ProductAnalyticsRuntimeConfig::default())
            .unwrap();
        host.set_usage_diagnostics_consent(false).unwrap();
        host.set_usage_diagnostics_consent(true).unwrap();
    })
    .join()
    .expect("synchronous host calls must not require a Tokio context");
    assert!(app.usage_diagnostics_permit().is_ok());
    runtime.shutdown_and_close().await.unwrap();
}

#[test]
fn legacy_settings_document_the_active_runtime_state_before_restore() {
    let root = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relays(root.path(), vec![]);
    app.set_usage_diagnostics_consent(true).unwrap();
    let unopened = MarmotApp::with_relays(root.path(), vec![]);
    assert_eq!(
        unopened.usage_diagnostics_settings().unwrap().decision,
        UsageDiagnosticsDecision::Granted
    );
    assert!(!unopened.relay_telemetry_settings().unwrap().export_enabled);
    unopened.restore_usage_diagnostics().unwrap();
    assert!(unopened.relay_telemetry_settings().unwrap().export_enabled);
}
