//! mdk#1161 regression: with group hydration deliberately held, the account
//! runtime still signals readiness and the persisted chat-list projection is
//! fully readable, while a group read issued during the hold waits for
//! exactly the group it names. A later unheld boot proves the pipeline
//! completes and every group serves details.
//!
//! The hold uses the `dev_startup_hydration_batch_delay_ms` test knob
//! (honored only with `test-policy-overrides`), which delays each hydration
//! batch while the worker keeps serving commands — so this file is compiled
//! only under that feature, matching how CI runs the integration matrix.
#![cfg(feature = "test-policy-overrides")]

use std::time::{Duration, Instant};

use cgka_traits::types::GroupId;
use marmot_account::AccountHome;
use marmot_app::{
    AppError, MAX_GROUP_MEMBER_IDS_PAGE_SIZE, MarmotApp, MarmotAppConfig, MarmotAppRuntime,
    SelfMembership,
};
use nostr_relay_builder::MockRelay;

const BENCH_ACCOUNT: &str = "held";
const GROUP_COUNT: usize = 6;
/// Long enough that no hydration batch completes during the held boot's
/// assertions, short enough that worker shutdown remains prompt.
const BATCH_HOLD_MS: u64 = 30_000;

fn open_store(dir: &tempfile::TempDir, relay_url: &str, hold_ms: Option<u64>) -> MarmotApp {
    let mut config = MarmotAppConfig::default().with_allow_loopback_relay_endpoints(true);
    if let Some(ms) = hold_ms {
        config = config.with_dev_startup_hydration_batch_delay_ms(ms);
    }
    MarmotApp::with_relay_and_config(dir.path(), relay_url.to_owned(), config)
}

#[test]
fn sustained_command_traffic_does_not_starve_the_hydration_pipeline() {
    let thread = std::thread::Builder::new()
        .name("startup-hydration-flood".to_owned())
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let test_runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            test_runtime.block_on(sustained_traffic_body());
        })
        .unwrap();
    thread.join().unwrap();
}

/// The pipeline serves a bounded command budget between batches (mdk#1161
/// review): a host hammering worker-routed reads from the moment `start()`
/// returns must not defer hydration indefinitely. A per-batch hold keeps the
/// pipeline slow enough that the read flood genuinely overlaps it; the
/// pipeline's completion telemetry sample proves it finished under load.
async fn sustained_traffic_body() {
    let relay = MockRelay::run().await.unwrap();
    let url = relay.url().await.to_string();

    let dir_donor = tempfile::tempdir().unwrap();
    let home_donor = AccountHome::open(dir_donor.path());
    home_donor.create_account("donor").unwrap();
    let donor_id = home_donor.account("donor").unwrap().account_id_hex;
    {
        let app_donor = open_store(&dir_donor, &url, None);
        let mut donor = app_donor.client("donor").await.unwrap();
        donor.publish_key_package().await.unwrap();
    }

    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account(BENCH_ACCOUNT).unwrap();
    let mut group_ids = Vec::new();
    {
        let app_fixture = open_store(&dir, &url, None);
        let mut client = app_fixture.client(BENCH_ACCOUNT).await.unwrap();
        for group in 0..GROUP_COUNT {
            group_ids.push(
                client
                    .create_group(&format!("flooded group {group}"), &[donor_id.as_str()])
                    .await
                    .unwrap(),
            );
        }
    }

    // Slow the pipeline down (200ms per batch, GROUP_COUNT groups over
    // batches of 4 => >= 2 batches) so the flood overlaps it.
    let app = open_store(&dir, &url, Some(200));
    let runtime = MarmotAppRuntime::new(app.clone());
    runtime.start().await.unwrap();

    // Continuous worker-routed reads: every one either answers from live
    // state or promotes its group; the budget guarantees the pipeline still
    // advances between them.
    let telemetry = runtime.shared_services().app_performance_telemetry();
    let flooded = group_ids.first().unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut flood_reads = 0u64;
    loop {
        // The pipeline records its own AccountGroupHydration sample when it
        // completes (sample 2; sample 1 is the seed pass inside open).
        if telemetry.snapshot().account_group_hydration.attempts >= 2 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "hydration pipeline starved by sustained reads ({flood_reads} served)"
        );
        runtime.group_members(BENCH_ACCOUNT, flooded).await.unwrap();
        flood_reads += 1;
    }
    assert!(
        flood_reads > 0,
        "flood must overlap the pipeline for this regression to mean anything"
    );
    // Every group finished hydrating despite the traffic.
    for group_id in &group_ids {
        assert!(
            !runtime
                .group_members(BENCH_ACCOUNT, group_id)
                .await
                .unwrap()
                .is_empty()
        );
    }
    runtime.shutdown().await;
}

#[test]
fn chat_list_is_readable_and_group_reads_wait_per_group_while_hydration_is_held() {
    let thread = std::thread::Builder::new()
        .name("startup-hydration-hold".to_owned())
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let test_runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            test_runtime.block_on(held_hydration_body());
        })
        .unwrap();
    thread.join().unwrap();
}

async fn held_hydration_body() {
    let relay = MockRelay::run().await.unwrap();
    let url = relay.url().await.to_string();

    // --- one member key-package donor in its own store ---
    let dir_donor = tempfile::tempdir().unwrap();
    let home_donor = AccountHome::open(dir_donor.path());
    home_donor.create_account("donor").unwrap();
    let donor_id = home_donor.account("donor").unwrap().account_id_hex;
    {
        let app_donor = open_store(&dir_donor, &url, None);
        let mut donor = app_donor.client("donor").await.unwrap();
        donor.publish_key_package().await.unwrap();
    }

    // --- fixture store with GROUP_COUNT groups ---
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account(BENCH_ACCOUNT).unwrap();
    let mut group_ids = Vec::new();
    {
        let app_fixture = open_store(&dir, &url, None);
        let mut client = app_fixture.client(BENCH_ACCOUNT).await.unwrap();
        for group in 0..GROUP_COUNT {
            group_ids.push(
                client
                    .create_group(&format!("held group {group}"), &[donor_id.as_str()])
                    .await
                    .unwrap(),
            );
        }
    }

    // --- boot 1: hydration held; readiness and the chat list must not wait ---
    let app = open_store(&dir, &url, Some(BATCH_HOLD_MS));
    let runtime = MarmotAppRuntime::new(app.clone());
    let start_started = Instant::now();
    runtime.start().await.unwrap();
    let ready_elapsed = start_started.elapsed();
    assert!(
        ready_elapsed < Duration::from_millis(BATCH_HOLD_MS / 2),
        "readiness must not wait on the held hydration pipeline (took {ready_elapsed:?})"
    );

    let rows = app.chat_list(BENCH_ACCOUNT, false).unwrap();
    assert_eq!(
        rows.len(),
        GROUP_COUNT,
        "persisted chat list must hold every group while hydration is held"
    );

    // The identifier-only roster page is the bounded companion read for that
    // chat projection (mdk#1314). One worker command promotes only the named
    // groups from durable state and returns every roster without waiting for
    // the held background pipeline or doing profile enrichment.
    let page_started = Instant::now();
    let member_ids_page = tokio::time::timeout(
        Duration::from_millis(BATCH_HOLD_MS / 2),
        runtime.group_member_ids_page(BENCH_ACCOUNT, &group_ids),
    )
    .await
    .expect("bounded membership read must not wait out the hydration hold")
    .unwrap();
    assert_eq!(member_ids_page.len(), GROUP_COUNT);
    for (row, group_id) in member_ids_page.iter().zip(&group_ids) {
        assert_eq!(row.group_id_hex, hex::encode(group_id.as_slice()));
        assert_eq!(row.member_ids_hex.len(), 2);
        assert!(row.member_ids_hex.contains(&donor_id));
    }
    assert!(
        page_started.elapsed() < Duration::from_millis(BATCH_HOLD_MS / 2),
        "bounded membership read must not wait out the pipeline hold"
    );

    // A page is all-or-error: an unknown (including quarantine-hidden) group
    // cannot produce a partial response containing the preceding safe row.
    let unknown = GroupId::new(vec![0xff; 16]);
    assert!(matches!(
        runtime
            .group_member_ids_page(BENCH_ACCOUNT, &[group_ids[0].clone(), unknown])
            .await,
        Err(AppError::UnknownGroup(_))
            | Err(AppError::Session(cgka_session::SessionError::Engine(
                cgka_traits::error::EngineError::UnknownGroup(_)
            )))
    ));

    let oversized = vec![group_ids[0].clone(); MAX_GROUP_MEMBER_IDS_PAGE_SIZE + 1];
    assert!(matches!(
        runtime
            .group_member_ids_page(BENCH_ACCOUNT, &oversized)
            .await,
        Err(AppError::InvalidGroupMembershipPage(_))
    ));

    // A group read issued during the hold hydrates exactly the group it
    // names and answers from live state — it must not wait out the hold.
    let probed: &GroupId = group_ids.last().unwrap();
    let read_started = Instant::now();
    let members = tokio::time::timeout(
        Duration::from_millis(BATCH_HOLD_MS / 2),
        runtime.group_members(BENCH_ACCOUNT, probed),
    )
    .await
    .expect("group read during the hold must wait for its group only")
    .unwrap();
    assert!(
        !members.is_empty(),
        "per-group hydration must produce the real roster"
    );
    assert!(
        read_started.elapsed() < Duration::from_millis(BATCH_HOLD_MS / 2),
        "group read must not wait out the pipeline hold"
    );
    let roster = tokio::time::timeout(
        Duration::from_millis(BATCH_HOLD_MS / 2),
        runtime.group_roster(BENCH_ACCOUNT, probed),
    )
    .await
    .expect("roster read during the hold must wait for its group only")
    .unwrap();
    assert_eq!(roster.self_membership, SelfMembership::Member);
    assert_eq!(roster.roster_revision, roster.epoch.saturating_mul(3));
    assert_eq!(roster.members.len(), members.len());

    // The pipeline itself is still held: only the session-open stage sample
    // exists (the pipeline records its own AccountGroupHydration sample when
    // it completes).
    let hydration_attempts = runtime
        .shared_services()
        .app_performance_telemetry()
        .snapshot()
        .account_group_hydration
        .attempts;
    assert_eq!(
        hydration_attempts, 1,
        "hydration pipeline must still be held while assertions run"
    );
    runtime.shutdown().await;

    // --- boot 2: unheld; the pipeline completes and every group serves ---
    let app = open_store(&dir, &url, None);
    let runtime = MarmotAppRuntime::new(app.clone());
    runtime.start().await.unwrap();
    for group_id in &group_ids {
        let members = runtime
            .group_members(BENCH_ACCOUNT, group_id)
            .await
            .unwrap();
        assert!(!members.is_empty());
    }
    runtime.shutdown().await;
}
