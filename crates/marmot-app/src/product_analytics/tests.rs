use super::*;
#[derive(Default)]
pub(super) struct FakeClock {
    wall: AtomicU64,
    mono: AtomicU64,
    ids: AtomicU64,
}
impl AnalyticsClock for FakeClock {
    fn wall_seconds(&self) -> u64 {
        self.wall.load(Ordering::Relaxed)
    }
    fn monotonic(&self) -> Duration {
        Duration::from_millis(self.mono.load(Ordering::Relaxed))
    }
    fn uuid(&self) -> String {
        format!(
            "00000000-0000-4000-8000-{:012}",
            self.ids.fetch_add(1, Ordering::Relaxed)
        )
    }
}
pub(super) fn configured() -> (ProductAnalytics, Arc<FakeClock>) {
    let clock = Arc::new(FakeClock::default());
    clock.wall.store(1800, Ordering::Relaxed);
    let collector = ProductAnalytics {
        clock: clock.clone(),
        ..Default::default()
    };
    collector
        .configure(
            ProductAnalyticsRuntimeConfig {
                events_endpoint: Some("http://127.0.0.1:9876/api/v0/events".into()),
                app_key: Some("A-SH-123456".into()),
                allow_loopback: true,
                operator: "test_operator".into(),
                metadata: ProductAnalyticsMetadata {
                    app_version: "1.0".into(),
                    os_family: "linux".into(),
                    os_major_version: "6".into(),
                    device_class: "desktop".into(),
                    host_surface: "native".into(),
                    environment: "development".into(),
                    is_debug: true,
                },
                registry: vec![ProductEventSchema {
                    name: "app_test_view".into(),
                    mode: ProductEventMode::Journey,
                    properties: vec![],
                }],
            },
            "http://127.0.0.1:9876".into(),
        )
        .unwrap();
    (collector, clock)
}
fn grant(c: &ProductAnalytics) {
    c.set_receipt(
        UsageDiagnosticsSettings {
            decision: UsageDiagnosticsDecision::Granted,
            ..Default::default()
        },
        crate::generate_telemetry_install_id(),
    );
}
#[test]
fn count_bucket_edges() {
    for (n, v) in [
        (0, "0"),
        (1, "1"),
        (2, "2"),
        (3, "3_5"),
        (5, "3_5"),
        (6, "6_10"),
        (10, "6_10"),
        (11, "11_20"),
        (20, "11_20"),
        (21, "21_50"),
        (50, "21_50"),
        (51, "51_100"),
        (100, "51_100"),
        (101, "101_250"),
        (250, "101_250"),
        (251, "251_1000"),
        (1000, "251_1000"),
        (1001, "1001_plus"),
        (u64::MAX, "1001_plus"),
    ] {
        assert_eq!(product_count_bucket(n), v);
    }
}
#[test]
fn duration_boundaries_are_inclusive() {
    for (i, b) in PRODUCT_DURATION_BOUNDS_MS.iter().enumerate() {
        let d = Duration::from_millis(*b);
        assert_eq!(
            product_duration_bucket(d),
            product_duration_bucket(d - Duration::from_nanos(1))
        );
        assert_ne!(
            product_duration_bucket(d),
            product_duration_bucket(d + Duration::from_nanos(1)),
            "boundary {i}"
        );
    }
}
#[test]
fn generation_never_revives() {
    let (c, _) = configured();
    assert!(c.permit().is_none());
    grant(&c);
    let p = c.permit().unwrap();
    assert!(p.valid());
    c.revoke_memory();
    assert!(!p.valid());
    grant(&c);
    assert!(!p.valid());
    assert!(c.permit().unwrap().valid());
}
#[test]
fn keys_are_redacted_and_reserved_properties_rejected() {
    let (c, _) = configured();
    let mut config = c.lock().config.clone();
    assert!(!format!("{config:?}").contains("A-SH-123456"));
    config.registry[0].properties.push(ProductPropertySchema {
        name: "environment".into(),
        rule: ProductPropertyRule::Boolean,
    });
    assert!(config.validate().is_err());
}
#[cfg(feature = "product-analytics-export")]
#[test]
fn no_preconsent_backlog_and_idempotent_background() {
    let (c, _) = configured();
    c.observe(
        ProductFamily::Maintenance,
        "retention",
        "success",
        ProductUnit::Attempt,
        None,
    );
    assert!(c.lock().cells.is_empty());
    grant(&c);
    c.activity(ProductAnalyticsActivity::Foreground);
    c.observe(
        ProductFamily::Maintenance,
        "retention",
        "success",
        ProductUnit::Attempt,
        None,
    );
    c.activity(ProductAnalyticsActivity::Background);
    let count = c.lock().queue.len();
    c.activity(ProductAnalyticsActivity::Background);
    assert_eq!(count, c.lock().queue.len());
    c.revoke_memory();
    assert!(c.lock().queue.is_empty());
    assert!(c.lock().cells.is_empty());
}
#[cfg(feature = "product-analytics-export")]
#[test]
fn session_expiry_queue_bounds_and_clock_jump() {
    let (c, clock) = configured();
    grant(&c);
    c.activity(ProductAnalyticsActivity::Foreground);
    let id = c.lock().session.clone().unwrap().0;
    clock.mono.store(1_800_000, Ordering::Relaxed);
    clock.wall.store(3600, Ordering::Relaxed);
    c.activity(ProductAnalyticsActivity::Foreground);
    assert_ne!(c.lock().session.clone().unwrap().0, id);
    {
        let mut s = c.lock();
        for _ in 0..700 {
            c.enqueue(
                &mut s,
                "mdk_session_started",
                BTreeMap::from([("launch_reason".into(), "ordinary".into())]),
                "00000000-0000-4000-8000-000000000000",
                3600,
            );
        }
        assert!(s.queue.len() <= MAX_EVENTS);
        assert!(s.queue_bytes <= MAX_QUEUE_BYTES);
    }
    clock.mono.store(5_400_000, Ordering::Relaxed);
    clock.wall.store(100, Ordering::Relaxed);
    {
        let mut s = c.lock();
        c.advance(&mut s);
        assert!(
            s.queue
                .iter()
                .all(|e| clock.monotonic().saturating_sub(e.created) < EVENT_TTL)
        );
    }
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
    assert!(!permit.valid());
    assert!(app.telemetry_install_id().is_err());
    app.set_usage_diagnostics_consent(true).unwrap();
    assert_ne!(first, app.telemetry_install_id().unwrap());
    assert!(!permit.valid());
}
#[test]
fn failed_persistence_cannot_restore_a_grant_in_process() {
    let tmp = tempfile::tempdir().unwrap();
    let app = crate::MarmotApp::with_relay(tmp.path(), "wss://relay.example");
    app.set_usage_diagnostics_consent(true).unwrap();
    let permit = app.usage_diagnostics_permit().unwrap();
    app.close_storage().unwrap();
    assert!(app.set_usage_diagnostics_consent(false).is_err());
    assert!(!permit.valid());
    assert!(app.usage_diagnostics_permit().is_err());
    assert!(app.restore_usage_diagnostics().is_err());
}
#[cfg(feature = "product-analytics-export")]
#[tokio::test]
async fn stock_wire_batch_preserves_prefix_and_never_contains_diagnostic_identity() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (c, clock) = configured();
    clock.wall.store(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        Ordering::Relaxed,
    );
    let mut config = c.lock().config.clone();
    config.events_endpoint = Some(format!("http://{address}/prefix/api/v0/events"));
    c.configure(config, String::new()).unwrap();
    c.activity(ProductAnalyticsActivity::Foreground);
    c.flush().await;
    assert!(
        tokio::time::timeout(Duration::from_millis(30), listener.accept())
            .await
            .is_err()
    );
    grant(&c);
    c.activity(ProductAnalyticsActivity::Foreground);
    for _ in 0..5 {
        c.observe(
            ProductFamily::Maintenance,
            "retention",
            "performed",
            ProductUnit::Attempt,
            None,
        );
    }
    c.seal_partial();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut bytes = Vec::new();
        let (header_end, content_length) = loop {
            let mut buf = [0u8; 4096];
            let len = socket.read(&mut buf).await.unwrap();
            assert!(len > 0);
            bytes.extend_from_slice(&buf[..len]);
            if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                let headers = std::str::from_utf8(&bytes[..end]).unwrap();
                assert!(headers.starts_with("POST /prefix/api/v0/events HTTP/1.1"));
                assert!(
                    headers
                        .to_ascii_lowercase()
                        .contains("app-key: a-sh-123456")
                );
                let length = headers
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .map(|v| v.parse::<usize>().unwrap())
                    })
                    .unwrap();
                break (end + 4, length);
            }
        };
        while bytes.len() < header_end + content_length {
            let mut buf = [0u8; 4096];
            let n = socket.read(&mut buf).await.unwrap();
            assert!(n > 0);
            bytes.extend_from_slice(&buf[..n]);
        }
        let value: serde_json::Value =
            serde_json::from_slice(&bytes[header_end..header_end + content_length]).unwrap();
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        value
    });
    c.flush().await;
    let payload = tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap();
    let rows = payload.as_array().unwrap();
    assert!(rows.len() <= 25);
    assert!(rows.iter().any(
        |v| v["eventName"] == "mdk_maintenance_summary" && v["props"]["count_bucket"] == "3_5"
    ));
    for row in rows {
        assert_eq!(row["sessionId"].as_str().unwrap().len(), 36);
        assert!(row["systemProps"].get("deviceModel").is_none());
        assert!(row["systemProps"].get("locale").is_none());
        assert!(row["props"].get("install_id").is_none());
        assert!(row["props"].get("account_id").is_none());
    }
    assert_eq!(c.status().accepted_batches, 1);
}
#[cfg(feature = "product-analytics-export")]
#[test]
fn backlog_aggregates_sources_without_counting_scheduler_ticks() {
    let (c, _) = configured();
    grant(&c);
    let a = c.backlog_source();
    let b = c.backlog_source();
    for _ in 0..60 {
        a.sample(
            &c.permit().unwrap(),
            ProductFamily::Maintenance,
            "pending",
            2,
        );
        b.sample(
            &c.permit().unwrap(),
            ProductFamily::Maintenance,
            "pending",
            3,
        );
    }
    c.seal_partial();
    let s = c.lock();
    let rows: Vec<_> = s
        .queue
        .iter()
        .filter(|r| r.payload["eventName"] == "mdk_maintenance_summary")
        .collect();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].payload["props"]["count_bucket"], "3_5");
    assert_eq!(rows[0].payload["props"]["unit"], "backlog");
}

#[test]
fn machine_catalogue_matches_builtins_and_buckets() {
    let catalogue: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../docs/marmot-architecture/product-event-catalogue.json"
    ))
    .unwrap();
    let events = catalogue["events"].as_array().unwrap();
    for family in ProductFamily::ALL {
        let event = events
            .iter()
            .find(|e| e["name"] == family.as_str())
            .unwrap();
        assert_eq!(
            event["properties"]["operation"],
            serde_json::json!(family.operations())
        );
        assert_eq!(
            event["properties"]["outcome"],
            serde_json::json!(PRODUCT_OUTCOMES)
        );
    }
    for schema in approved_host_product_schemas() {
        let event = events.iter().find(|e| e["name"] == schema.name).unwrap();
        for property in schema.properties {
            if let ProductPropertyRule::Enum(values) = property.rule {
                assert_eq!(
                    event["properties"][&property.name],
                    serde_json::json!(values)
                );
            }
        }
    }
    assert_eq!(
        catalogue["duration_upper_bounds_ms"],
        serde_json::json!(PRODUCT_DURATION_BOUNDS_MS)
    );
    assert_eq!(
        catalogue["duration_buckets"],
        serde_json::json!(
            PRODUCT_DURATION_BOUNDS_MS
                .iter()
                .copied()
                .chain([3600001])
                .map(|n| product_duration_bucket(Duration::from_millis(n)))
                .collect::<Vec<_>>()
        )
    );
}

#[cfg(feature = "product-analytics-export")]
#[test]
fn stale_operation_completion_after_regrant_is_discarded() {
    let (c, clock) = configured();
    grant(&c);
    let ticket = c
        .begin(
            ProductFamily::Maintenance,
            "self_update",
            ProductUnit::Attempt,
        )
        .unwrap();
    clock.mono.store(100, Ordering::Relaxed);
    c.revoke_memory();
    grant(&c);
    clock.mono.store(1000, Ordering::Relaxed);
    ticket.finish("failure");
    assert!(c.lock().cells.is_empty());
}

#[cfg(feature = "product-analytics-export")]
#[test]
fn launch_reason_account_boundary_and_idle_rotation_are_finite() {
    let (c, clock) = configured();
    grant(&c);
    c.activity(ProductAnalyticsActivity::ForegroundNotification);
    assert_eq!(
        c.lock().queue.back().unwrap().payload["props"]["launch_reason"],
        "notification"
    );
    let first = c.lock().session.as_ref().unwrap().0.clone();
    c.activity(ProductAnalyticsActivity::AccountChanged);
    c.activity(ProductAnalyticsActivity::ForegroundDeepLink);
    assert_ne!(c.lock().session.as_ref().unwrap().0, first);
    let second = c.lock().session.as_ref().unwrap().0.clone();
    clock.mono.store(1800000, Ordering::Relaxed);
    clock.wall.store(3600, Ordering::Relaxed);
    c.activity(ProductAnalyticsActivity::Foreground);
    assert_ne!(c.lock().session.as_ref().unwrap().0, second);
}

#[cfg(feature = "product-analytics-export")]
#[tokio::test]
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
    app.product_analytics = c.clone();
    let runtime = app.runtime();
    let mut config = c.lock().config.clone();
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

#[test]
#[cfg(feature = "product-analytics-export")]
fn serialization_rechecks_closed_schema_and_uuid() {
    let (collector, _) = configured();
    grant(&collector);
    collector.activity(ProductAnalyticsActivity::Foreground);
    let state = collector.lock();
    let payload = state.queue.front().unwrap().payload.clone();
    assert!(collector.valid_payload(&state.config, &payload));
    for (field, value) in [
        ("launch_reason", "unreviewed"),
        ("raw_error", "sensitive"),
        ("environment", "unexpected"),
    ] {
        let mut invalid = payload.clone();
        invalid["props"][field] = serde_json::json!(value);
        assert!(!collector.valid_payload(&state.config, &invalid));
    }
    let mut invalid = payload.clone();
    invalid["systemProps"]["deviceModel"] = serde_json::json!("unreviewed");
    assert!(!collector.valid_payload(&state.config, &invalid));
    invalid = payload.clone();
    invalid["extra"] = serde_json::json!("unreviewed");
    assert!(!collector.valid_payload(&state.config, &invalid));
    let mut invalid = payload.clone();
    invalid["sessionId"] = serde_json::json!("zzzzzzzz-zzzz-4zzz-8zzz-zzzzzzzzzzzz");
    assert!(!collector.valid_payload(&state.config, &invalid));
    invalid = payload;
    invalid["eventName"] = serde_json::json!("mdk_unreviewed_event");
    assert!(!collector.valid_payload(&state.config, &invalid));
}

#[cfg(feature = "product-analytics-export")]
#[test]
fn stale_backlog_sample_cannot_enter_new_grant() {
    let (c, _) = configured();
    grant(&c);
    let source = c.backlog_source();
    let permit = c.permit().unwrap();
    c.revoke_memory();
    grant(&c);
    source.sample(&permit, ProductFamily::Maintenance, "pending", 50);
    assert!(c.lock().backlog.is_empty());
}

#[cfg(feature = "product-analytics-export")]
#[tokio::test]
async fn rejection_suspends_only_product_and_ambiguous_failure_is_not_retried() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    for (status, expire_during_retry) in [(401u16, false), (500, false), (429, false), (429, true)]
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (c, clock) = configured();
        clock.wall.store(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            Ordering::Relaxed,
        );
        let mut config = c.lock().config.clone();
        config.events_endpoint = Some(format!(
            "http://{}/api/v0/events",
            listener.local_addr().unwrap()
        ));
        c.configure(config, String::new()).unwrap();
        grant(&c);
        let permit = c.permit().unwrap();
        c.activity(ProductAnalyticsActivity::Foreground);
        let requests = Arc::new(AtomicU64::new(0));
        let accepted = requests.clone();
        let server = tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut bytes = Vec::new();
                loop {
                    let mut buffer = [0u8; 4096];
                    let n = socket.read(&mut buffer).await.unwrap();
                    assert!(n > 0);
                    bytes.extend_from_slice(&buffer[..n]);
                    if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                        let headers = std::str::from_utf8(&bytes[..end]).unwrap();
                        let length: usize = headers
                            .lines()
                            .find_map(|line| {
                                line.to_ascii_lowercase()
                                    .strip_prefix("content-length: ")
                                    .map(|v| v.parse().unwrap())
                            })
                            .unwrap();
                        if bytes.len() >= end + 4 + length {
                            break;
                        }
                    }
                }
                let index = accepted.fetch_add(1, Ordering::Relaxed);
                if expire_during_retry {
                    clock
                        .mono
                        .store(EVENT_TTL.as_millis() as u64, Ordering::Relaxed);
                }
                let code = if status == 429 && index > 0 {
                    200
                } else {
                    status
                };
                socket.write_all(format!("HTTP/1.1 {code} Test\r\nRetry-After: 1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
            }
        });
        tokio::time::timeout(Duration::from_secs(4), c.send_pending())
            .await
            .unwrap();
        assert_eq!(
            requests.load(Ordering::Relaxed),
            if status == 429 && !expire_during_retry {
                2
            } else {
                1
            }
        );
        assert!(permit.valid()); // A product rejection never revokes the OTLP grant.
        assert!(!c.telemetry_rejected.load(Ordering::Acquire));
        let report = c.status();
        if status == 401 {
            assert_eq!(
                report.product_analytics,
                DiagnosticsExporterStatus::ConfigurationRejected
            );
            assert!(
                c.begin(ProductFamily::Runtime, "startup", ProductUnit::Attempt)
                    .is_none()
            );
            c.send_pending().await;
            assert_eq!(requests.load(Ordering::Relaxed), 1);
        } else if status == 500 || expire_during_retry {
            assert_eq!(report.failed_batches, 1);
            assert_eq!(report.accepted_batches, 0);
            assert!(report.dropped_events > 0);
        } else {
            assert_eq!(report.accepted_batches, 1);
            assert_eq!(report.failed_batches, 0);
        }
        server.abort();
    }
}

#[cfg(feature = "product-analytics-export")]
#[tokio::test]
async fn bounded_flush_drains_multiple_batches_without_reviving_old_senders() {
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
    let mut config = c.lock().config.clone();
    config.events_endpoint = Some(format!(
        "http://{}/api/v0/events",
        listener.local_addr().unwrap()
    ));
    c.configure(config, String::new()).unwrap();
    grant(&c);
    let old = c.permit().unwrap();
    c.activity(ProductAnalyticsActivity::Foreground);
    for _ in 0..50 {
        assert_eq!(
            c.record(ProductEvent {
                name: "app_test_view".into(),
                properties: BTreeMap::new()
            })
            .unwrap(),
            ProductRecordResult::Recorded
        );
    }
    let server = tokio::spawn(async move {
        let mut batch_sizes = Vec::new();
        for _ in 0..3 {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            let batch = loop {
                let mut buffer = [0u8; 4096];
                let n = socket.read(&mut buffer).await.unwrap();
                assert!(n > 0);
                bytes.extend_from_slice(&buffer[..n]);
                if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = std::str::from_utf8(&bytes[..end]).unwrap();
                    let length: usize = headers
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length: ")
                                .map(|v| v.parse().unwrap())
                        })
                        .unwrap();
                    if bytes.len() >= end + 4 + length {
                        break serde_json::from_slice::<Vec<serde_json::Value>>(
                            &bytes[end + 4..end + 4 + length],
                        )
                        .unwrap();
                    }
                }
            };
            batch_sizes.push(batch.len());
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
        }
        batch_sizes
    });
    c.flush().await;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap(),
        [25, 25, 1]
    );
    assert_eq!(c.status().accepted_batches, 3);
    assert_eq!(c.status().queued_events, 0);
    c.revoke_memory();
    grant(&c);
    c.activity(ProductAnalyticsActivity::Foreground);
    let queued = c.status().queued_events;
    assert!(queued > 0);
    c.send_pending_with_permit(&old).await;
    assert_eq!(c.status().queued_events, queued);
}

#[test]
fn product_reconfiguration_does_not_resume_rejected_otlp_credentials() {
    let (c, _) = configured();
    grant(&c);
    c.telemetry_rejected.store(true, Ordering::Release);
    let (config, receipt) = {
        let state = c.lock();
        (state.config.clone(), state.settings.clone())
    };
    c.configure(config, String::new()).unwrap();
    c.set_receipt(receipt, crate::generate_telemetry_install_id());
    assert!(c.telemetry_rejected.load(Ordering::Acquire));
    c.revoke_memory();
    grant(&c);
    assert!(!c.telemetry_rejected.load(Ordering::Acquire));
}

#[cfg(feature = "otlp-export")]
#[test]
fn stale_otlp_authentication_failure_cannot_suspend_new_generation() {
    let (c, _) = configured();
    grant(&c);
    let old = c.permit().unwrap();
    c.revoke_memory();
    grant(&c);
    old.reject_telemetry();
    assert!(!c.telemetry_rejected.load(Ordering::Acquire));
    c.permit().unwrap().reject_telemetry();
    assert!(c.telemetry_rejected.load(Ordering::Acquire));
}

#[cfg(feature = "product-analytics-export")]
#[test]
fn storage_failures_are_classified_without_raw_causes_or_sync_fanout_duplicates() {
    let (c, clock) = configured();
    grant(&c);
    let observation = c.storage_observation().unwrap();
    let error = AppError::Storage(cgka_traits::StorageError::Corruption(
        "private database contents".into(),
    ));
    assert_eq!(
        error.sync_error_class(),
        crate::SyncErrorClass::StorageCorruption
    );
    observation.storage_failure(&Err::<(), _>(error));
    clock.mono.store(100, Ordering::Relaxed);
    let failure = crate::SyncFailureClassification::new(
        crate::SyncFailureStage::StatePersist,
        crate::SyncErrorClass::StorageBusy,
    );
    c.observe_sync("background", Duration::from_millis(20), Some(failure));
    for _ in 0..10 {
        observation.storage_failure(&Err::<(), _>(crate::AccountCatchUpFailure::new(
            "private raw cause".into(),
            failure,
        )));
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

#[cfg(feature = "product-analytics-export")]
#[test]
fn directory_sources_are_closed_and_stale_resolution_results_are_discarded() {
    let (collector, _) = configured();
    grant(&collector);
    let observation = collector
        .begin(ProductFamily::Directory, "profile", ProductUnit::Attempt)
        .unwrap()
        .counts_only();
    observation.directory_sample("success", "cache", 2);
    observation.directory_sample("empty", "network", 1);
    observation.directory_sample("success", "https://private.example", 1);
    collector.set_receipt(UsageDiagnosticsSettings::default(), String::new());
    grant(&collector);
    observation.directory_sample("success", "cache", 100);
    assert!(collector.lock().cells.is_empty());
    let observation = collector
        .begin(ProductFamily::Directory, "profile", ProductUnit::Attempt)
        .unwrap()
        .counts_only();
    observation.directory_sample("success", "cache", 2);
    observation.directory_sample("empty", "network", 1);
    observation.directory_sample("success", "https://private.example", 1);
    let rows = collector.test_payloads();
    let rows: Vec<_> = rows
        .iter()
        .filter(|r| r["eventName"] == "mdk_directory_summary")
        .collect();
    assert_eq!(rows.len(), 2);
    assert!(
        rows.iter()
            .all(|row| collector.valid_payload(&collector.lock().config, row))
    );
    assert!(
        !serde_json::to_string(&rows)
            .unwrap()
            .contains("private.example")
    );
}

#[test]
fn registry_limits_accept_boundaries_and_reject_one_past_without_echoing_values() {
    let (collector, _) = configured();
    let mut config = collector.lock().config.clone();
    config.registry = (0..32)
        .map(|index| ProductEventSchema {
            name: format!("app_{}_{index}", "n".repeat(53)),
            mode: ProductEventMode::Aggregate,
            properties: (0..8)
                .map(|index| ProductPropertySchema {
                    name: format!("{}_{index}", "p".repeat(38)),
                    rule: ProductPropertyRule::Enum(
                        (0..16)
                            .map(|index| format!("{}_{index}", "v".repeat(177)))
                            .collect(),
                    ),
                })
                .collect(),
        })
        .collect();
    assert!(config.validate().is_ok());
    let revision = config.registry_revision();
    let mut rotation = config.clone();
    rotation.app_key = Some("A-SH-rotated".into());
    rotation.metadata.app_version = "2.0".into();
    assert_eq!(revision, rotation.registry_revision());
    for case in 0..6 {
        let mut invalid = config.clone();
        match case {
            0 => invalid.registry.push(ProductEventSchema {
                name: "app_extra".into(),
                mode: ProductEventMode::Journey,
                properties: vec![],
            }),
            1 => invalid.registry[0].properties.push(ProductPropertySchema {
                name: "extra".into(),
                rule: ProductPropertyRule::Boolean,
            }),
            2 => invalid.registry[0].name = format!("app_{}", "n".repeat(57)),
            3 => invalid.registry[0].properties[0].name = "p".repeat(41),
            4 => {
                invalid.registry[0].properties[0].rule =
                    ProductPropertyRule::Enum(vec!["v".repeat(181)])
            }
            5 => {
                invalid.registry[0].properties[0].rule =
                    ProductPropertyRule::Enum((0..17).map(|i| format!("v_{i}")).collect())
            }
            _ => unreachable!(),
        }
        let error = invalid.validate().unwrap_err();
        assert!(!error.to_string().contains(&"v".repeat(30)));
    }
    config.registry[0].properties[0].rule = ProductPropertyRule::Boolean;
    assert_ne!(revision, config.registry_revision());
}
