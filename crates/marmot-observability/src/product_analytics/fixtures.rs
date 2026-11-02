//! Collector fixtures for the product collector's own tests and for `marmot-app`'s (#2627).
//! Gated `cfg(any(test, feature = "test-support"))`; `marmot-app`'s tests reach them through the
//! crate root's gated re-exports.

use super::*;

/// A clock tests set by hand: wall seconds, monotonic milliseconds and sequential UUIDs.
#[derive(Default)]
pub struct FakeClock {
    pub wall: AtomicU64,
    pub mono: AtomicU64,
    pub ids: AtomicU64,
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
pub fn configured() -> (ProductAnalytics, Arc<FakeClock>) {
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
pub fn grant(c: &ProductAnalytics) {
    c.set_receipt(
        UsageDiagnosticsSettings {
            decision: UsageDiagnosticsDecision::Granted,
            ..Default::default()
        },
        generate_telemetry_install_id(),
    );
}

/// A configured collector, as the recorder an app holds.
#[cfg(feature = "product-analytics-export")]
pub fn test_product_collector() -> crate::observer::ProductRecorder {
    configured().0.into()
}
