use super::fixtures::{configured, grant};
use super::*;
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
    let (collector, _) = configured();
    let config = collector.lock().config.clone();
    grant(&collector);
    let permit = collector.permit().unwrap();
    for debug in [format!("{config:?}"), format!("{collector:?}")] {
        assert!(!debug.contains("A-SH-123456"));
        assert!(!debug.contains("127.0.0.1:9876"));
    }
    for name in ["account_id", "text", "environment"] {
        let mut invalid = config.clone();
        invalid.registry[0].properties.push(ProductPropertySchema {
            name: name.into(),
            rule: ProductPropertyRule::Boolean,
        });
        assert!(
            matches!(
                collector.configure(invalid, String::new()),
                Err(ProductAnalyticsError::InvalidConfiguration)
            ),
            "reserved property {name}"
        );
        assert_eq!(collector.lock().config, config);
        assert!(
            permit.valid(),
            "an invalid optional configuration must preserve consent"
        );
    }
}

#[test]
fn configuration_admission_is_closed_and_failed_changes_preserve_the_grant() {
    let (collector, _) = configured();
    let config = collector.lock().config.clone();
    grant(&collector);
    let permit = collector.permit().unwrap();
    for case in [
        "built_in_override",
        "unprefixed_event",
        "invalid_event_label",
        "duplicate_event",
        "duplicate_property",
        "invalid_property_label",
        "empty_choices",
        "duplicate_choices",
        "invalid_choice_label",
        "endpoint_query",
        "loopback_without_opt_in",
        "bad_endpoint",
        "empty_key",
        "long_key",
        "invalid_key",
        "operator",
        "app_version",
        "long_app_version",
        "os_family",
        "os_major_version",
        "device_class",
        "host_surface",
        "environment",
    ] {
        let mut invalid = config.clone();
        match case {
            "built_in_override" => invalid.registry[0] = approved_host_product_schemas()[0].clone(),
            "unprefixed_event" => invalid.registry[0].name = "event".into(),
            "invalid_event_label" => invalid.registry[0].name = "app_Personal".into(),
            "duplicate_event" => invalid.registry.push(invalid.registry[0].clone()),
            "duplicate_property" => {
                let property = ProductPropertySchema {
                    name: "visible".into(),
                    rule: ProductPropertyRule::Boolean,
                };
                invalid.registry[0].properties = vec![property.clone(), property];
            }
            "invalid_property_label" => {
                invalid.registry[0].properties.push(ProductPropertySchema {
                    name: "raw value".into(),
                    rule: ProductPropertyRule::Boolean,
                })
            }
            "empty_choices" | "duplicate_choices" | "invalid_choice_label" => {
                let choices = match case {
                    "empty_choices" => vec![],
                    "duplicate_choices" => vec!["visible".into(), "visible".into()],
                    _ => vec!["raw value".into()],
                };
                invalid.registry[0].properties.push(ProductPropertySchema {
                    name: "choice".into(),
                    rule: ProductPropertyRule::Enum(choices),
                });
            }
            "endpoint_query" => {
                invalid.events_endpoint =
                    Some("https://analytics.example/events?token=private".into())
            }
            "loopback_without_opt_in" => invalid.allow_loopback = false,
            "bad_endpoint" => invalid.events_endpoint = Some("file:///tmp/private".into()),
            "empty_key" => invalid.app_key = Some(String::new()),
            "long_key" => invalid.app_key = Some("a".repeat(129)),
            "invalid_key" => invalid.app_key = Some("private\nheader".into()),
            "operator" => invalid.operator = String::new(),
            "app_version" => invalid.metadata.app_version = "private-version".into(),
            "long_app_version" => invalid.metadata.app_version = "1".repeat(51),
            "os_family" => invalid.metadata.os_family = "private-os".into(),
            "os_major_version" => invalid.metadata.os_major_version = "12345".into(),
            "device_class" => invalid.metadata.device_class = "private-device".into(),
            "host_surface" => invalid.metadata.host_surface = "private-host".into(),
            "environment" => invalid.metadata.environment = "private-deployment".into(),
            _ => unreachable!(),
        }
        let error = collector.configure(invalid, String::new()).unwrap_err();
        assert!(
            matches!(error, ProductAnalyticsError::InvalidConfiguration),
            "{case}"
        );
        assert!(!error.to_string().contains("private"), "{case}");
        assert_eq!(collector.lock().config, config, "{case}");
        assert!(permit.valid(), "{case}");
    }
    let mut valid = config;
    valid.events_endpoint = Some("https://analytics.example/prefix/events".into());
    valid.app_key = Some("a".repeat(128));
    collector.configure(valid.clone(), String::new()).unwrap();
    assert_eq!(collector.lock().config, valid);
    assert!(
        !permit.valid(),
        "an accepted configuration replaces its old grant generation"
    );
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
    assert!(c.lock().queue.iter().any(|row| {
        row.payload["eventName"] == "mdk_maintenance_summary"
            && row.payload["props"]["count_bucket"] == "1"
    }));
    c.activity(ProductAnalyticsActivity::Background);
    assert_eq!(count, c.lock().queue.len());
    c.revoke_memory();
    assert!(c.lock().queue.is_empty());
    assert!(c.lock().cells.is_empty());
}
#[cfg(feature = "product-analytics-export")]
#[test]
fn session_expiry_queue_bounds_and_clock_jump() {
    for large in [false, true] {
        let (collector, clock) = configured();
        let mut config = collector.lock().config.clone();
        config.registry[0].properties = (0..if large { 8 } else { 1 })
            .map(|index| ProductPropertySchema {
                name: format!("value_{index}"),
                rule: ProductPropertyRule::Enum(
                    (0..16)
                        .map(|value| {
                            format!("v_{value:02}_{}", "x".repeat(if large { 175 } else { 0 }))
                        })
                        .collect(),
                ),
            })
            .collect();
        collector.configure(config, String::new()).unwrap();
        grant(&collector);
        collector.activity(ProductAnalyticsActivity::Foreground);
        for index in 0..700 {
            let value = format!(
                "v_{:02}_{}",
                index % 16,
                "x".repeat(if large { 175 } else { 0 })
            );
            assert_eq!(
                collector
                    .record(ProductEvent {
                        name: "app_test_view".into(),
                        properties: (0..if large { 8 } else { 1 })
                            .map(|property| (format!("value_{property}"), value.clone()))
                            .collect(),
                    })
                    .unwrap(),
                ProductRecordResult::Recorded
            );
            if index == 0 {
                assert_eq!(
                    collector.status().queued_events,
                    2,
                    "positive control: session plus first event"
                );
            }
        }
        let state = collector.lock();
        let retained = state.queue.len();
        let bytes: usize = state.queue.iter().map(|event| event.bytes).sum();
        assert_eq!(state.queue_bytes, bytes);
        assert_eq!(state.status.dropped_events, 701 - retained as u64);
        if large {
            assert!(
                retained > 0 && retained < MAX_EVENTS,
                "the byte limit must act before the event limit"
            );
            assert!(bytes <= MAX_QUEUE_BYTES);
            assert!(bytes + state.queue.front().unwrap().bytes > MAX_QUEUE_BYTES);
        } else {
            assert_eq!(retained, MAX_EVENTS);
            assert!(bytes < MAX_QUEUE_BYTES);
        }
        assert_eq!(
            state.queue.front().unwrap().payload["props"]["value_0"],
            format!(
                "v_{:02}_{}",
                (700 - retained) % 16,
                "x".repeat(if large { 175 } else { 0 })
            )
        );
        assert_eq!(
            state.queue.back().unwrap().payload["props"]["value_0"],
            format!(
                "v_{:02}_{}",
                699 % 16,
                "x".repeat(if large { 175 } else { 0 })
            )
        );
        drop(state);
        clock
            .mono
            .store(EVENT_TTL.as_millis() as u64 - 1, Ordering::Relaxed);
        clock.wall.store(5399, Ordering::Relaxed);
        let remaining = {
            let mut state = collector.lock();
            collector.advance(&mut state);
            let remaining = state
                .queue
                .iter()
                .filter(|event| event.payload["eventName"] == "app_test_view")
                .count();
            // Sealing the elapsed window may evict one oldest row, but none is expired yet.
            assert!(remaining >= retained - 1);
            remaining
        };
        let before = collector.status().dropped_events;
        clock
            .mono
            .store(EVENT_TTL.as_millis() as u64, Ordering::Relaxed);
        clock.wall.store(5400, Ordering::Relaxed);
        let mut state = collector.lock();
        collector.advance(&mut state);
        assert!(
            state
                .queue
                .iter()
                .all(|event| event.payload["eventName"] != "app_test_view")
        );
        assert_eq!(state.status.dropped_events - before, remaining as u64);
    }
    let (collector, clock) = configured();
    grant(&collector);
    collector.observe(
        ProductFamily::Maintenance,
        "retention",
        "success",
        ProductUnit::Attempt,
        None,
    );
    clock.mono.store(1000, Ordering::Relaxed);
    clock.wall.store(1900, Ordering::Relaxed); // Same 15-minute window, but a wall-clock jump.
    collector.observe(
        ProductFamily::Maintenance,
        "retention",
        "success",
        ProductUnit::Attempt,
        None,
    );
    let state = collector.lock();
    let rows: Vec<_> = state
        .queue
        .iter()
        .filter(|event| event.payload["eventName"] == "mdk_maintenance_summary")
        .collect();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].payload["props"]["partial"], "true");
    assert_eq!(rows[0].payload["props"]["count_bucket"], "1");
    assert_eq!(rows[0].payload["timestamp"], "1970-01-01T00:30:00Z");
    assert_eq!(
        state.cells.values().sum::<u64>(),
        1,
        "the new observation belongs to the new window"
    );
}

#[cfg(feature = "product-analytics-export")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stock_wire_batch_preserves_prefix_and_never_contains_diagnostic_identity() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    crate::collector_host_safety::hand_in_direct_http_builder();
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
    drop(s);
    drop(b);
    a.sample(
        &c.permit().unwrap(),
        ProductFamily::Maintenance,
        "pending",
        2,
    );
    c.seal_partial();
    let buckets: Vec<_> = c
        .lock()
        .queue
        .iter()
        .filter(|row| row.payload["eventName"] == "mdk_maintenance_summary")
        .map(|row| {
            row.payload["props"]["count_bucket"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    assert_eq!(
        buckets,
        ["3_5", "2"],
        "a departed worker must stop contributing backlog"
    );
    drop(a);
    c.observe(
        ProductFamily::Runtime,
        "startup",
        "success",
        ProductUnit::Attempt,
        None,
    );
    c.seal_partial();
    assert_eq!(
        c.lock()
            .queue
            .iter()
            .filter(|row| row.payload["eventName"] == "mdk_maintenance_summary")
            .count(),
        2
    );
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
        for property in &schema.properties {
            if let ProductPropertyRule::Enum(values) = &property.rule {
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
    let hourly = c.lock().session.as_ref().unwrap().0.clone();
    for seconds in [2700, 3600, 4500] {
        clock.mono.store(seconds * 1000, Ordering::Relaxed);
        clock.wall.store(seconds + 1800, Ordering::Relaxed);
        c.activity(ProductAnalyticsActivity::Foreground);
        assert_eq!(
            c.lock().session.as_ref().unwrap().0,
            hourly,
            "activity prevents idle expiry"
        );
    }
    clock.mono.store(5_400_000, Ordering::Relaxed);
    clock.wall.store(7200, Ordering::Relaxed);
    c.activity(ProductAnalyticsActivity::Foreground);
    assert_ne!(
        c.lock().session.as_ref().unwrap().0,
        hourly,
        "a session expires after an hour even while active"
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
    invalid = payload.clone();
    invalid["eventName"] = serde_json::json!("mdk_unreviewed_event");
    assert!(!collector.valid_payload(&state.config, &invalid));
    for case in [
        "not_object",
        "missing_envelope",
        "missing_launch_reason",
        "missing_common",
        "non_string_property",
        "invalid_stamp",
        "negative_stamp",
        "future_stamp",
        "not_uuid_v4",
        "not_uuid_variant",
    ] {
        let mut invalid = payload.clone();
        match case {
            "not_object" => invalid = serde_json::json!([]),
            "missing_envelope" => {
                invalid.as_object_mut().unwrap().remove("timestamp");
            }
            "missing_launch_reason" => {
                invalid["props"]
                    .as_object_mut()
                    .unwrap()
                    .remove("launch_reason");
            }
            "missing_common" => {
                invalid["props"]
                    .as_object_mut()
                    .unwrap()
                    .remove("schema_version");
            }
            "non_string_property" => invalid["props"]["launch_reason"] = serde_json::json!(true),
            "invalid_stamp" => invalid["timestamp"] = serde_json::json!("not-a-date"),
            "negative_stamp" => invalid["timestamp"] = serde_json::json!("1969-12-31T23:59:59Z"),
            "future_stamp" => invalid["timestamp"] = serde_json::json!("1970-01-01T00:40:01Z"),
            "not_uuid_v4" => {
                invalid["sessionId"] = serde_json::json!("00000000-0000-1000-8000-000000000000")
            }
            "not_uuid_variant" => {
                invalid["sessionId"] = serde_json::json!("00000000-0000-4000-c000-000000000000")
            }
            _ => unreachable!(),
        }
        assert!(!collector.valid_payload(&state.config, &invalid), "{case}");
    }
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejection_suspends_only_product_and_ambiguous_failure_is_not_retried() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    crate::collector_host_safety::hand_in_direct_http_builder();
    for (status, expire_during_retry) in [
        (400u16, false),
        (401, false),
        (403, false),
        (404, false),
        (422, false),
        (500, false),
        (503, false),
        (408, false),
        (302, false),
        (202, false),
        (204, false),
        (429, false),
        (429, true),
    ] {
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
        if matches!(status, 400 | 401 | 403 | 404 | 422) {
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
        } else if matches!(status, 500 | 503 | 408 | 302) || expire_during_retry {
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bounded_flush_drains_multiple_batches_without_reviving_old_senders() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    crate::collector_host_safety::hand_in_direct_http_builder();
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
    let mut observations: Vec<_> = rows
        .iter()
        .map(|row| {
            let props = &row["props"];
            (
                props["source"].as_str().unwrap(),
                props["outcome"].as_str().unwrap(),
                props["unit"].as_str().unwrap(),
                props["count_bucket"].as_str().unwrap(),
            )
        })
        .collect();
    observations.sort_unstable();
    assert_eq!(
        observations,
        [
            ("cache", "success", "attempt", "2"),
            ("network", "empty", "attempt", "1")
        ]
    );
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
        assert!(matches!(error, ProductAnalyticsError::InvalidConfiguration));
        assert!(!error.to_string().contains(&"v".repeat(30)));
    }
    config.registry[0].properties[0].rule = ProductPropertyRule::Boolean;
    assert_ne!(revision, config.registry_revision());
}

#[cfg(feature = "product-analytics-export")]
#[test]
fn consent_preserves_lifecycle_without_replaying_preconsent_activity() {
    let (c, _) = configured();
    let event = || ProductEvent {
        name: "app_screen_viewed".into(),
        properties: BTreeMap::from([("screen".into(), "inbox".into())]),
    };
    c.activity(ProductAnalyticsActivity::ForegroundNotification);
    assert_eq!(
        c.record(event()).unwrap(),
        ProductRecordResult::IgnoredDisabled
    );
    assert!(c.lock().session.is_none());
    assert!(c.lock().queue.is_empty());
    grant(&c);
    assert_eq!(c.record(event()).unwrap(), ProductRecordResult::Recorded);
    let first = c.lock().session.clone().unwrap().0;
    assert_eq!(c.lock().queue.len(), 2);
    // The launch before consent is not replayed as a notification journey.
    assert_eq!(
        c.lock().queue[0].payload["props"]["launch_reason"],
        "ordinary"
    );
    c.revoke_memory();
    assert!(c.lock().queue.is_empty());
    grant(&c);
    assert_eq!(c.record(event()).unwrap(), ProductRecordResult::Recorded);
    assert_ne!(c.lock().session.clone().unwrap().0, first);
    c.revoke_memory();
    c.activity(ProductAnalyticsActivity::Background);
    grant(&c);
    assert_eq!(
        c.record(event()).unwrap(),
        ProductRecordResult::IgnoredDisabled
    );
    assert!(c.lock().session.is_none());
}

#[test]
fn non_media_measurements_do_not_depend_on_optional_product_analytics() {
    use crate::app_telemetry::{AppPerformanceOperation, AppPerformanceTelemetry};
    let plain = AppPerformanceTelemetry::default();
    let attached = AppPerformanceTelemetry::with_product_analytics(ProductAnalytics::default());
    for telemetry in [&plain, &attached] {
        telemetry.record_media(
            AppPerformanceOperation::AppStart,
            Duration::from_millis(42),
            true,
            "other",
        );
    }
    for telemetry in [&plain, &attached] {
        let start = telemetry.snapshot().app_start;
        assert_eq!((start.attempts, start.successes, start.failures), (1, 1, 0));
        assert_eq!(start.duration_ms.sample_count(), 1);
        assert_eq!(start.duration_ms.sum_ms, 42);
    }
}

#[cfg(not(feature = "product-analytics-export"))]
#[test]
fn consent_without_product_feature_cannot_collect_activity() {
    let (collector, _) = configured();
    grant(&collector);
    assert!(collector.permit().is_some());
    assert_eq!(
        collector.status().product_analytics,
        DiagnosticsExporterStatus::UnsupportedBuild
    );
    assert!(
        collector
            .begin(ProductFamily::Account, "local_ready", ProductUnit::Attempt)
            .is_none()
    );
    collector.observe(
        ProductFamily::Notification,
        "local_enable",
        "success",
        ProductUnit::Action,
        None,
    );
    collector.activity(ProductAnalyticsActivity::Foreground);
    collector.activity(ProductAnalyticsActivity::Background);
    let state = collector.lock();
    assert!(state.cells.is_empty());
    assert!(state.queue.is_empty());
    assert!(state.session.is_none());
    assert!(state.window.is_none());
}

#[cfg(feature = "product-analytics-export")]
#[test]
fn notification_setting_operations_remain_separate_aggregate_cells() {
    let (collector, _) = configured();
    grant(&collector);
    for operation in [
        "local_enable",
        "native_enable",
        "local_disable",
        "native_disable",
    ] {
        collector.observe(
            ProductFamily::Notification,
            operation,
            "success",
            ProductUnit::Action,
            None,
        );
    }
    let state = collector.lock();
    let operations: BTreeSet<_> = state
        .cells
        .keys()
        .filter(|(event, props)| {
            event == "mdk_notification_summary" && props.get("unit").is_some_and(|v| v == "action")
        })
        .map(|(_, props)| props["operation"].as_str())
        .collect();
    assert_eq!(
        operations,
        BTreeSet::from([
            "local_enable",
            "native_enable",
            "local_disable",
            "native_disable"
        ])
    );
    assert!(state.cells.values().all(|count| *count == 1));
}

#[cfg(feature = "product-analytics-export")]
#[test]
fn local_ready_handoff_does_not_duplicate_the_complete_phase_observation() {
    use crate::app_telemetry::{AppPerformanceOperation, AppPerformanceTelemetry};
    let (collector, _) = configured();
    grant(&collector);
    let telemetry = AppPerformanceTelemetry::with_product_analytics(collector.clone());
    collector
        .begin(ProductFamily::Account, "local_ready", ProductUnit::Attempt)
        .unwrap()
        .finish("success");
    telemetry.record(
        AppPerformanceOperation::AccountSetupLocalReadyHandoff,
        Duration::from_millis(10),
        true,
    );
    let state = collector.lock();
    let attempts: u64 = state
        .cells
        .iter()
        .filter(|((event, props), _)| {
            event == "mdk_account_summary"
                && props.get("operation").is_some_and(|v| v == "local_ready")
                && props.get("unit").is_some_and(|v| v == "attempt")
        })
        .map(|(_, count)| *count)
        .sum();
    assert_eq!(attempts, 1);
}

#[cfg(feature = "product-analytics-export")]
#[test]
fn host_event_admission_checks_each_rule_before_queueing() {
    let (collector, _) = configured();
    let mut config = collector.lock().config.clone();
    config.registry[0].properties = vec![
        ProductPropertySchema {
            name: "choice".into(),
            rule: ProductPropertyRule::Enum(vec!["visible".into()]),
        },
        ProductPropertySchema {
            name: "visible".into(),
            rule: ProductPropertyRule::Boolean,
        },
        ProductPropertySchema {
            name: "amount".into(),
            rule: ProductPropertyRule::CountBucket,
        },
        ProductPropertySchema {
            name: "elapsed".into(),
            rule: ProductPropertyRule::DurationBucket,
        },
    ];
    let event = ProductEvent {
        name: "app_test_view".into(),
        properties: BTreeMap::from([
            ("choice".into(), "visible".into()),
            ("visible".into(), "true".into()),
            ("amount".into(), "1".into()),
            ("elapsed".into(), "le_10ms".into()),
        ]),
    };
    let mut incomplete = config.clone();
    incomplete.events_endpoint = None;
    collector.configure(incomplete, String::new()).unwrap();
    grant(&collector);
    assert_eq!(
        collector.record(event.clone()).unwrap(),
        ProductRecordResult::IgnoredUnconfigured
    );
    assert_eq!(
        collector.status().product_analytics,
        DiagnosticsExporterStatus::Unconfigured
    );
    assert_eq!(collector.status().queued_events, 0);
    collector.configure(config, String::new()).unwrap();
    grant(&collector);
    collector.activity(ProductAnalyticsActivity::Foreground);
    assert_eq!(
        collector.record(event.clone()).unwrap(),
        ProductRecordResult::Recorded
    );
    let queued = collector.status().queued_events;
    for case in [
        "unknown_event",
        "missing_property",
        "extra_property",
        "wrong_property",
        "choice",
        "visible",
        "amount",
        "elapsed",
    ] {
        let mut invalid = event.clone();
        match case {
            "unknown_event" => invalid.name = "app_unregistered".into(),
            "missing_property" => {
                invalid.properties.remove("choice");
            }
            "extra_property" => {
                invalid.properties.insert("extra".into(), "private".into());
            }
            "wrong_property" => {
                invalid.properties.remove("choice");
                invalid.properties.insert("other".into(), "private".into());
            }
            key => {
                invalid.properties.insert(key.into(), "private".into());
            }
        }
        assert!(
            matches!(
                collector.record(invalid),
                Err(ProductAnalyticsError::InvalidEvent)
            ),
            "{case}"
        );
        assert_eq!(collector.status().queued_events, queued, "{case}");
    }
    let state = collector.lock();
    let payload = &state.queue.back().unwrap().payload;
    assert_eq!(payload["props"]["choice"], "visible");
    assert_eq!(payload["props"]["visible"], "true");
    assert_eq!(payload["props"]["amount"], "1");
    assert_eq!(payload["props"]["elapsed"], "le_10ms");
    let mut config = state.config.clone();
    drop(state);
    config.registry[0].properties = (0..8)
        .map(|index| ProductPropertySchema {
            name: format!("field_{index}{}", "p".repeat(33)),
            rule: ProductPropertyRule::Enum(vec!["v".repeat(180)]),
        })
        .collect();
    let oversized = ProductEvent {
        name: "app_test_view".into(),
        properties: config.registry[0]
            .properties
            .iter()
            .map(|property| (property.name.clone(), "v".repeat(180)))
            .collect(),
    };
    collector.configure(config, String::new()).unwrap();
    grant(&collector);
    collector.activity(ProductAnalyticsActivity::Foreground);
    let before = collector.status();
    collector.record(oversized).unwrap();
    let after = collector.status();
    assert_eq!(after.queued_events, before.queued_events);
    assert_eq!(after.dropped_events, before.dropped_events + 1);
    assert!(
        collector
            .lock()
            .queue
            .iter()
            .all(|row| row.payload["eventName"] != "app_test_view")
    );
}

#[cfg(feature = "product-analytics-export")]
#[test]
fn journey_duplicates_are_suppressed_until_the_session_changes() {
    let (collector, _) = configured();
    grant(&collector);
    collector.activity(ProductAnalyticsActivity::Foreground);
    let events = [
        ProductEvent {
            name: "app_screen_viewed".into(),
            properties: BTreeMap::from([("screen".into(), "inbox".into())]),
        },
        ProductEvent {
            name: "mdk_onboarding_step".into(),
            properties: BTreeMap::from([
                ("step".into(), "start".into()),
                ("path".into(), "create".into()),
                ("outcome".into(), "success".into()),
            ]),
        },
        ProductEvent {
            name: "mdk_runtime_ready".into(),
            properties: BTreeMap::from([
                ("outcome".into(), "success".into()),
                ("duration_bucket".into(), "le_10ms".into()),
            ]),
        },
    ];
    let mut sessions = BTreeSet::new();
    for round in 0..2 {
        for event in &events {
            assert_eq!(
                collector.record(event.clone()).unwrap(),
                ProductRecordResult::Recorded
            );
            assert_eq!(
                collector.record(event.clone()).unwrap(),
                ProductRecordResult::IgnoredDuplicate
            );
            let state = collector.lock();
            let rows: Vec<_> = state
                .queue
                .iter()
                .filter(|row| row.payload["eventName"] == event.name)
                .collect();
            assert_eq!(rows.len(), round + 1);
            sessions.insert(
                rows.last().unwrap().payload["sessionId"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
            );
        }
        for mut duplicate in [events[1].clone(), events[2].clone()] {
            duplicate
                .properties
                .insert("outcome".into(), "failure".into());
            assert_eq!(
                collector.record(duplicate).unwrap(),
                ProductRecordResult::IgnoredDuplicate
            );
        }
        collector.activity(ProductAnalyticsActivity::AccountChanged);
        collector.activity(ProductAnalyticsActivity::ForegroundDeepLink);
    }
    assert_eq!(sessions.len(), 2);
}

#[cfg(feature = "product-analytics-export")]
#[test]
fn aggregate_capacity_reserves_coverage_and_counts_overflow_without_losing_existing_cells() {
    for with_backlog in [false, true] {
        let (collector, _) = configured();
        let mut config = collector.lock().config.clone();
        config.registry = vec![ProductEventSchema {
            name: "app_capacity".into(),
            mode: ProductEventMode::Aggregate,
            properties: ["first", "second"]
                .into_iter()
                .map(|name| ProductPropertySchema {
                    name: name.into(),
                    rule: ProductPropertyRule::Enum(
                        (0..16).map(|index| format!("v_{index}")).collect(),
                    ),
                })
                .collect(),
        }];
        collector.configure(config, String::new()).unwrap();
        grant(&collector);
        let source = collector.backlog_source();
        if with_backlog {
            source.sample(
                &collector.permit().unwrap(),
                ProductFamily::Maintenance,
                "pending",
                2,
            );
        }
        let event = |index: usize| ProductEvent {
            name: "app_capacity".into(),
            properties: BTreeMap::from([
                ("first".into(), format!("v_{}", index / 16)),
                ("second".into(), format!("v_{}", index % 16)),
            ]),
        };
        for index in 0..256 {
            assert_eq!(
                collector.record(event(index)).unwrap(),
                ProductRecordResult::Recorded
            );
        }
        assert_eq!(
            collector.record(event(0)).unwrap(),
            ProductRecordResult::Recorded
        );
        let rows = collector.test_payloads();
        let aggregates: Vec<_> = rows
            .iter()
            .filter(|row| row["eventName"] == "app_capacity")
            .collect();
        assert_eq!(aggregates.len(), MAX_CELLS - 3 - usize::from(with_backlog));
        let first = aggregates
            .iter()
            .find(|row| row["props"]["first"] == "v_0" && row["props"]["second"] == "v_0")
            .unwrap();
        assert_eq!(
            first["props"]["count_bucket"], "2",
            "capacity must not block an existing cell"
        );
        let overflow = rows
            .iter()
            .find(|row| row["props"]["operation"] == "overflow")
            .unwrap();
        assert_eq!(overflow["props"]["count_bucket"], "3_5");
        assert_eq!(overflow["props"]["outcome"], "capacity");
        assert!(rows.iter().any(|row| row["props"]["unit"] == "coverage"));
        if with_backlog {
            assert!(rows.iter().any(
                |row| row["props"]["unit"] == "backlog" && row["props"]["count_bucket"] == "2"
            ));
        }
    }
}

#[cfg(feature = "product-analytics-export")]
#[test]
fn backlog_sources_are_bounded_and_existing_sources_can_update_at_capacity() {
    let (collector, _) = configured();
    grant(&collector);
    let permit = collector.permit().unwrap();
    let sources: Vec<_> = (0..=MAX_CELLS)
        .map(|_| collector.backlog_source())
        .collect();
    for source in &sources[..MAX_CELLS] {
        source.sample(&permit, ProductFamily::Maintenance, "pending", 0);
    }
    sources[MAX_CELLS].sample(&permit, ProductFamily::Maintenance, "pending", 1001);
    sources[0].sample(&permit, ProductFamily::Maintenance, "pending", 2);
    let rows = collector.test_payloads();
    let backlog: Vec<_> = rows
        .iter()
        .filter(|row| row["eventName"] == "mdk_maintenance_summary")
        .collect();
    assert_eq!(backlog.len(), 1);
    assert_eq!(backlog[0]["props"]["unit"], "backlog");
    assert_eq!(backlog[0]["props"]["count_bucket"], "2");
}

#[cfg(feature = "product-analytics-export")]
async fn read_product_batch(stream: &mut tokio::net::TcpStream) -> Vec<serde_json::Value> {
    use tokio::io::AsyncReadExt;
    let mut bytes = Vec::new();
    loop {
        let mut buffer = [0; 4096];
        let length = stream.read(&mut buffer).await.unwrap();
        assert!(length > 0, "request ended before its body");
        bytes.extend_from_slice(&buffer[..length]);
        if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            let headers = std::str::from_utf8(&bytes[..end]).unwrap();
            let content_length: usize = headers
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length: ")
                        .map(|value| value.parse().unwrap())
                })
                .unwrap();
            if bytes.len() >= end + 4 + content_length {
                return serde_json::from_slice(&bytes[end + 4..end + 4 + content_length]).unwrap();
            }
        }
    }
}

#[cfg(feature = "product-analytics-export")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delivery_retry_budget_and_long_cooldowns_drop_an_unaccepted_batch_once() {
    use tokio::io::AsyncWriteExt;
    crate::collector_host_safety::hand_in_direct_http_builder();
    for (retry_after, expected_attempts) in [("0", 4), ("301", 1)] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (collector, clock) = configured();
        clock.wall.store(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            Ordering::Relaxed,
        );
        let mut config = collector.lock().config.clone();
        config.events_endpoint = Some(format!(
            "http://{}/api/v0/events",
            listener.local_addr().unwrap()
        ));
        collector.configure(config, String::new()).unwrap();
        grant(&collector);
        collector.activity(ProductAnalyticsActivity::Foreground);
        let attempts = Arc::new(Mutex::new(Vec::new()));
        let observed = attempts.clone();
        let server = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                assert_eq!(read_product_batch(&mut stream).await.len(), 1);
                observed.lock().unwrap().push(Instant::now());
                stream.write_all(format!("HTTP/1.1 429 Limited\r\nRetry-After: {retry_after}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
            }
        });
        tokio::time::timeout(Duration::from_secs(10), collector.send_pending())
            .await
            .unwrap();
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
        let attempts = attempts.lock().unwrap();
        assert_eq!(attempts.len(), expected_attempts);
        for pair in attempts.windows(2) {
            assert!(
                pair[1].duration_since(pair[0]) >= Duration::from_secs(1),
                "zero Retry-After still has a one-second minimum"
            );
        }
        let status = collector.status();
        assert_eq!(status.queued_events, 0);
        assert_eq!(status.failed_batches, 1);
        assert_eq!(status.dropped_events, 1);
        assert_eq!(status.accepted_batches, 0);
        assert_eq!(status.product_analytics, DiagnosticsExporterStatus::Ready);
    }
}

#[cfg(feature = "product-analytics-export")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn detached_delivery_cancellation_and_flush_deadline_preserve_generation_accounting() {
    crate::collector_host_safety::hand_in_direct_http_builder();
    for stop in ["revoke", "abort", "flush_deadline"] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (collector, clock) = configured();
        clock.wall.store(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            Ordering::Relaxed,
        );
        let mut config = collector.lock().config.clone();
        config.events_endpoint = Some(format!(
            "http://{}/api/v0/events",
            listener.local_addr().unwrap()
        ));
        collector.configure(config, String::new()).unwrap();
        grant(&collector);
        let old = collector.permit().unwrap();
        collector.activity(ProductAnalyticsActivity::Foreground);
        let (received, request_received) = tokio::sync::oneshot::channel();
        let (release, hold_response) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let batch = read_product_batch(&mut stream).await;
            received.send(batch.len()).unwrap();
            hold_response.await.unwrap();
            drop(stream);
        });
        let sending = collector.clone();
        let task = tokio::spawn(async move {
            if stop == "flush_deadline" {
                sending.flush().await;
            } else {
                sending.send_pending().await;
            }
        });
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(10), request_received)
                .await
                .unwrap()
                .unwrap(),
            1
        );
        if stop == "revoke" {
            collector.revoke_memory();
            grant(&collector);
            collector.activity(ProductAnalyticsActivity::Foreground);
        } else if stop == "abort" {
            task.abort();
        }
        let result = tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .unwrap();
        if stop == "abort" {
            assert!(result.unwrap_err().is_cancelled());
        } else {
            result.unwrap();
        }
        release.send(()).unwrap();
        server.await.unwrap();
        let status = collector.status();
        assert_eq!(status.accepted_batches, 0);
        assert_eq!(status.product_analytics, DiagnosticsExporterStatus::Ready);
        if stop == "revoke" {
            assert!(!old.valid());
            assert!(collector.permit().unwrap().valid());
            assert_eq!(
                status.queued_events, 1,
                "the new generation keeps its own session event"
            );
            assert_eq!(status.failed_batches, 0);
            assert_eq!(status.dropped_events, 0);
        } else {
            assert!(old.valid());
            assert_eq!(status.queued_events, 0);
            assert_eq!(status.failed_batches, 1);
            assert_eq!(status.dropped_events, 1);
        }
    }
}
