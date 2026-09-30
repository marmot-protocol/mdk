//! Create-DM scaling benchmark: how long does starting a new DM take for an
//! account that already has N chats?
//!
//! Each case builds an on-disk store holding one account with N existing
//! one-peer chats, cold-starts a `MarmotAppRuntime` on it, waits for command
//! readiness and a short settle, then times back-to-back `create_group_detailed`
//! calls for fresh DMs the way a host app starts one (empty name, one member).
//! Stage attribution comes from the runtime's `AppPerformanceSnapshot`
//! group-create metrics.
//!
//! Results print as stable `MDK_BENCH create_dm_scaling ...` lines. Only the
//! small smoke case runs in the normal suite; run the matrix with
//! `just bench-create-direct-message`.
//!
//! The fixture reuses one peer for every existing chat: the scaling input is
//! the number of stored groups, not the number of distinct peers, and a
//! 1000-donor key-package fixture would dominate the build time.

use std::time::{Duration, Instant};

use marmot_account::AccountHome;
use marmot_app::{AppPerformanceOperationSnapshot, MarmotApp, MarmotAppConfig, MarmotAppRuntime};
use nostr_relay_builder::MockRelay;

const BENCH_ACCOUNT: &str = "bench";

/// Fresh DMs timed per case after readiness.
const TIMED_DMS: usize = 3;

/// Idle time between readiness and the first timed create.
const STARTUP_SETTLE: Duration = Duration::from_secs(5);

fn open_store(dir: &tempfile::TempDir, relay_url: &str) -> MarmotApp {
    MarmotApp::with_relay_and_config(
        dir.path(),
        relay_url.to_owned(),
        MarmotAppConfig::default().with_allow_loopback_relay_endpoints(true),
    )
}

/// Publish one key package per donor and return their account ids.
async fn publish_donors(dir: &tempfile::TempDir, url: &str, count: usize) -> Vec<String> {
    let home = AccountHome::open(dir.path());
    let app = open_store(dir, url);
    let mut ids = Vec::with_capacity(count);
    for donor in 0..count {
        let label = format!("d{donor}");
        home.create_account(&label).unwrap();
        ids.push(home.account(&label).unwrap().account_id_hex);
        let mut client = app.client(&label).await.unwrap();
        client.publish_key_package().await.unwrap();
    }
    ids
}

fn sum_ms(stage: &AppPerformanceOperationSnapshot) -> u64 {
    stage.duration_ms.sum_ms
}

async fn run_case(case: &str, existing_chats: usize) {
    let relay = MockRelay::run().await.unwrap();
    let url = relay.url().await.to_string();

    // Donor store: one peer for the existing chats, one per timed DM.
    let dir_donors = tempfile::tempdir().unwrap();
    let donors = publish_donors(&dir_donors, &url, 1 + TIMED_DMS).await;
    let (existing_peer, fresh_peers) = donors.split_first().unwrap();

    // Bench store: one account with `existing_chats` one-peer chats.
    let dir_bench = tempfile::tempdir().unwrap();
    AccountHome::open(dir_bench.path())
        .create_account(BENCH_ACCOUNT)
        .unwrap();
    let fixture_started = Instant::now();
    {
        let app = open_store(&dir_bench, &url);
        let mut client = app.client(BENCH_ACCOUNT).await.unwrap();
        for _ in 0..existing_chats {
            client.create_group("", &[existing_peer]).await.unwrap();
        }
    }
    let fixture = fixture_started.elapsed();

    // Cold start, then prove command readiness with a worker round trip.
    let runtime = MarmotAppRuntime::new(open_store(&dir_bench, &url));
    let ready_started = Instant::now();
    runtime.start().await.unwrap();
    runtime.group_co_members(BENCH_ACCOUNT).await.unwrap();
    let ready = ready_started.elapsed();

    // A user starts a DM well after launch: let startup recovery settle so
    // the timed creates measure the steady state, not the startup job.
    tokio::time::sleep(STARTUP_SETTLE).await;
    runtime.drain_in_flight_work().await.unwrap();

    // `create` is the caller-visible return; `open` is the next worker round
    // trip (the host opening the new chat), which queues behind any
    // post-create work the worker still runs.
    let mut timings = Vec::with_capacity(TIMED_DMS);
    let mut opens = Vec::with_capacity(TIMED_DMS);
    for peer in fresh_peers {
        let started = Instant::now();
        let created = runtime
            .create_group_detailed(BENCH_ACCOUNT, "", std::slice::from_ref(peer), None)
            .await
            .unwrap();
        timings.push(started.elapsed());
        runtime
            .group_members(BENCH_ACCOUNT, &created.group_id)
            .await
            .unwrap();
        opens.push(started.elapsed());
    }

    let snapshot = runtime
        .shared_services()
        .app_performance_telemetry()
        .snapshot();
    runtime.shutdown().await;

    let join_ms = |values: &[Duration]| {
        values
            .iter()
            .map(|value| value.as_millis().to_string())
            .collect::<Vec<_>>()
            .join("/")
    };
    let dms = TIMED_DMS as u64;
    println!(
        "MDK_BENCH create_dm_scaling case={case} existing_chats={existing_chats} \
         fixture_ms={} ready_ms={} create_dm_ms={} create_then_open_ms={} \
         avg_queue_wait_ms={} avg_key_package_ms={} avg_mls_prepare_persist_ms={} \
         avg_welcome_index_ms={} avg_local_projection_ms={} avg_response_handoff_ms={} \
         avg_welcome_publish_ms={} avg_catch_up_ms={}",
        fixture.as_millis(),
        ready.as_millis(),
        join_ms(&timings),
        join_ms(&opens),
        sum_ms(&snapshot.group_create_queue_wait) / dms,
        sum_ms(&snapshot.group_create_key_package_lookup) / dms,
        sum_ms(&snapshot.group_create_mls_prepare_persist) / dms,
        sum_ms(&snapshot.group_create_pending_welcome_index) / dms,
        sum_ms(&snapshot.group_create_local_projection_save) / dms,
        sum_ms(&snapshot.group_create_response_handoff) / dms,
        sum_ms(&snapshot.group_create_welcome_publish) / dms,
        sum_ms(&snapshot.group_create_post_mutation_catch_up) / dms,
    );
}

/// Bench bodies compose many app boots and MLS commits; debug builds need
/// more than libtest's default 2 MiB stack (same shape as `startup_scaling`).
fn run_bench(name: &'static str, existing_chats: usize) {
    std::thread::Builder::new()
        .name(name.to_owned())
        .stack_size(8 * 1024 * 1024)
        .spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(run_case(name, existing_chats));
        })
        .unwrap()
        .join()
        .unwrap();
}

/// Keeps the harness compiling and working in every CI run.
#[test]
fn create_dm_scaling_smoke() {
    run_bench("smoke", 2);
}

#[test]
#[ignore = "create-DM scaling benchmark; run via `just bench-create-direct-message`"]
fn create_dm_scaling_chats_300() {
    run_bench("chats_300", 300);
}

#[test]
#[ignore = "create-DM scaling benchmark; run via `just bench-create-direct-message`"]
fn create_dm_scaling_chats_1000() {
    run_bench("chats_1000", 1000);
}
