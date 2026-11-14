//! The hydration request (mdk#3273 PR 4): a group read whose version of A
//! shows a named group awaiting hydration asks the worker to hydrate it and
//! answers from the version the worker acknowledges with. Groups await
//! hydration only while startup's hydration pipeline runs, so these tests
//! hold that pipeline with its batch-delay knob and read through the host
//! wrappers of a real account worker.
use super::*;
use cgka_traits::storage::GroupStorage;

/// Long enough that no hydration batch completes while a test runs.
const BATCH_HOLD_MS: u64 = 30_000;

fn held_app(dir: &tempfile::TempDir, relay: Arc<ScriptedPushRelayClient>) -> MarmotApp {
    MarmotApp::with_relay_and_config(
        dir.path(),
        "wss://relay.example",
        crate::MarmotAppConfig::white_noise()
            .with_dev_startup_hydration_batch_delay_ms(BATCH_HOLD_MS),
    )
    .with_test_relay_client(relay)
}

/// How many hydration requests and fallback commands of class R3 the worker
/// has taken.
fn r3_worker_waits(runtime: &crate::MarmotAppRuntime) -> u64 {
    runtime
        .shared_services()
        .observer
        .performance()
        .snapshot()
        .runtime_operations
        .into_iter()
        .find(|sample| sample.operation == RuntimeOp::ReadQueueR3)
        .map_or(0, |sample| sample.successes)
}

fn is_unknown_group(result: &Result<impl std::fmt::Debug, AppError>) -> bool {
    matches!(result, Err(AppError::UnknownGroup(_)))
        || matches!(
            result.as_ref().err().and_then(AppError::as_engine_error),
            Some(cgka_traits::error::EngineError::UnknownGroup(_))
        )
}

async fn within_hold<T>(read: &str, call: impl std::future::Future<Output = T>) -> T {
    timeout(Duration::from_millis(BATCH_HOLD_MS / 2), call)
        .await
        .unwrap_or_else(|_| panic!("{read} must not wait out the held hydration pipeline"))
}

/// A read answers from the acknowledging version: live for a group that
/// hydrates, `UnknownGroup` for one its hydration quarantines. Each asks
/// the worker once, and a read of a group already hydrated asks nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hydration_is_acknowledged_as_live_and_quarantined() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let fixture = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    let mut groups = Vec::new();
    {
        let mut client = fixture.client("alice").await.unwrap();
        for name in ["live", "damaged"] {
            groups.push(
                client
                    .create_group(name, &[])
                    .await
                    .unwrap()
                    .operation
                    .expect("a group with no other members"),
            );
        }
    }
    let [live, damaged] = groups.try_into().unwrap();
    // A protocol profile the stored MLS group does not carry fails its
    // hydration, which quarantines it.
    let storage = fixture.account_storage("alice").unwrap();
    let mut record = storage.get_group(&damaged).unwrap();
    assert_ne!(
        record.protocol_profile,
        cgka_traits::group::ProtocolProfile::Legacy
    );
    record.protocol_profile = cgka_traits::group::ProtocolProfile::Legacy;
    storage.put_group(&record).unwrap();
    drop(storage);

    let runtime = crate::MarmotAppRuntime::new(held_app(&dir, relay));
    runtime.reconcile_accounts().await.unwrap();

    let before = r3_worker_waits(&runtime);
    let members = within_hold("a live group's read", runtime.group_members("alice", &live))
        .await
        .unwrap();
    assert_eq!(members.len(), 1, "the live group answers its roster");
    assert_eq!(
        r3_worker_waits(&runtime),
        before + 1,
        "the read asked the worker to hydrate its group"
    );

    let quarantined = within_hold(
        "a quarantined group's read",
        runtime.group_members("alice", &damaged),
    )
    .await;
    assert!(
        is_unknown_group(&quarantined),
        "a group its hydration quarantined answers UnknownGroup: {quarantined:?}"
    );
    assert_eq!(
        r3_worker_waits(&runtime),
        before + 2,
        "the quarantined group awaited hydration until the read asked"
    );
    assert_eq!(
        runtime
            .quarantined_groups("alice")
            .await
            .unwrap()
            .into_iter()
            .map(|group| group.group_id_hex)
            .collect::<Vec<_>>(),
        vec![hex::encode(damaged.as_slice())],
        "the acknowledged version holds the quarantine"
    );

    // Both groups are settled now: reads answer from A with no request.
    within_hold(
        "a hydrated group's read",
        runtime.group_members("alice", &live),
    )
    .await
    .unwrap();
    let page = within_hold(
        "a page naming a quarantined group",
        runtime.group_member_ids_page("alice", &[live.clone(), damaged.clone()]),
    )
    .await;
    assert!(
        is_unknown_group(&page),
        "the page is all-or-error: {page:?}"
    );
    assert_eq!(
        r3_worker_waits(&runtime),
        before + 2,
        "a group that no longer awaits hydration asks the worker nothing"
    );

    assert_eq!(
        runtime
            .shared_services()
            .app_performance_telemetry()
            .snapshot()
            .account_group_hydration
            .attempts,
        1,
        "the hydration pipeline is still held"
    );
    runtime.shutdown().await;
}
