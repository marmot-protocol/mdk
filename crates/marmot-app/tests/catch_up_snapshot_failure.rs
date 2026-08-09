//! Regression for explicit catch-up when the concurrent-read snapshot cannot
//! be captured. Snapshot failure must defer reads, not suppress synchronization.
#![cfg(feature = "test-policy-overrides")]

use std::time::{Duration, Instant};

use marmot_account::AccountHome;
use marmot_app::{MarmotApp, MarmotAppConfig, MarmotAppRuntime};
use nostr_relay_builder::MockRelay;

#[tokio::test]
async fn explicit_catch_up_syncs_when_group_read_snapshot_fails() {
    let relay = MockRelay::run().await.unwrap();
    let relay_url = relay.url().await.to_string();
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("snapshot-failure")
        .unwrap();

    let config = MarmotAppConfig::default()
        .with_allow_loopback_relay_endpoints(true)
        .with_dev_force_group_read_snapshot_failure(true);
    let app = MarmotApp::with_relay_and_config(dir.path(), relay_url, config);
    let runtime = MarmotAppRuntime::new(app);
    runtime.start().await.unwrap();

    let telemetry = runtime.shared_services().app_performance_telemetry();
    let deadline = Instant::now() + Duration::from_secs(10);
    while telemetry.snapshot().account_sync.attempts == 0 {
        assert!(
            Instant::now() < deadline,
            "startup catch-up did not complete before the deadline"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let sync_attempts_before = telemetry.snapshot().account_sync.attempts;

    runtime
        .catch_up_accounts()
        .await
        .expect("snapshot failure must not suppress explicit synchronization");

    let after = telemetry.snapshot();
    assert!(
        after.account_sync.attempts > sync_attempts_before,
        "explicit catch-up must run a new sync after snapshot capture fails"
    );
    assert_eq!(
        after.account_sync.successes, after.account_sync.attempts,
        "the injected snapshot failure must not turn a successful sync into a catch-up failure"
    );

    runtime.shutdown().await;
}
