//! Startup scaling benchmarks for the account-open critical path (mdk#1161).
//!
//! Each case builds an on-disk store with N groups (and M invited members per
//! group), tears everything down, then measures a cold reopen the way a host
//! app boots:
//!
//! 1. `MarmotApp::chat_list` on a fresh app instance, **before** any runtime
//!    exists — the persisted chat-projection read a host renders first.
//! 2. `MarmotAppRuntime::start()` — full account-worker command readiness.
//!
//! The two are reported separately because the issue's acceptance criterion is
//! that (1) stays flat while (2) is allowed to scale until the hydration work
//! is bounded. Stage attribution (session open, group hydration, profile load,
//! read-snapshot capture) comes from the `AppPerformanceTelemetry` stage
//! metrics added alongside this benchmark.
//!
//! Results are printed as stable `MDK_BENCH ...` lines so CI can grep and
//! archive them; there are no timing assertions (except the smoke case's
//! sanity checks) because shared runners make wall-clock bounds flaky. Run
//! the full matrix with `just bench-startup`; only the small smoke case runs
//! in the normal test suite.
//!
//! # Harness shape
//!
//! Member key-package donors live in their own store: `MarmotAppRuntime`
//! reconciles every local-signing account in a store, so donor accounts in the
//! bench store would multiply the measured worker count. Donors publish one
//! cached key package each to the mock relay and are referenced by account id
//! when the bench account creates groups.

use std::time::{Duration, Instant};

use marmot_account::AccountHome;
use marmot_app::{MarmotApp, MarmotAppConfig, MarmotAppRuntime};
use nostr_relay_builder::MockRelay;

const BENCH_ACCOUNT: &str = "bench";

fn open_store(dir: &tempfile::TempDir, relay_url: &str) -> MarmotApp {
    MarmotApp::with_relay_and_config(
        dir.path(),
        relay_url.to_owned(),
        MarmotAppConfig::default().with_allow_loopback_relay_endpoints(true),
    )
}

struct BenchReport {
    groups: usize,
    roster: usize,
    /// Cold `MarmotApp::chat_list` read on a fresh app, before any runtime.
    chat_list: Duration,
    /// `MarmotAppRuntime::start()` wall clock on the same cold store.
    start_ready: Duration,
    /// Stage sums from the runtime's `AppPerformanceSnapshot` (one account,
    /// so each stage holds exactly one startup sample).
    account_open_wait_ms: u64,
    session_open_ms: u64,
    group_hydration_ms: u64,
    profile_load_ms: u64,
    read_snapshot_ms: u64,
}

impl BenchReport {
    fn print(&self, case: &str) {
        println!(
            "MDK_BENCH startup_scaling case={case} groups={} roster={} \
             chat_list_ms={} ready_ms={} account_open_wait_ms={} session_open_ms={} \
             group_hydration_ms={} profile_load_ms={} read_snapshot_ms={}",
            self.groups,
            self.roster,
            self.chat_list.as_millis(),
            self.start_ready.as_millis(),
            self.account_open_wait_ms,
            self.session_open_ms,
            self.group_hydration_ms,
            self.profile_load_ms,
            self.read_snapshot_ms,
        );
    }
}

/// Build the fixture store, then cold-reopen it and measure. See module docs.
async fn run_case(groups: usize, roster: usize) -> BenchReport {
    let relay = MockRelay::run().await.unwrap();
    let url = relay.url().await.to_string();

    // --- donor store: `roster` member accounts, one published key package each ---
    let dir_donors = tempfile::tempdir().unwrap();
    let home_donors = AccountHome::open(dir_donors.path());
    let app_donors = open_store(&dir_donors, &url);
    let mut member_ids = Vec::with_capacity(roster);
    for member in 0..roster {
        let label = format!("m{member}");
        home_donors.create_account(&label).unwrap();
        member_ids.push(home_donors.account(&label).unwrap().account_id_hex);
        let mut donor = app_donors.client(&label).await.unwrap();
        donor.publish_key_package().await.unwrap();
    }

    // --- bench store: one account, N groups over the donor roster ---
    let dir_bench = tempfile::tempdir().unwrap();
    let home_bench = AccountHome::open(dir_bench.path());
    home_bench.create_account(BENCH_ACCOUNT).unwrap();
    {
        let app_fixture = open_store(&dir_bench, &url);
        let mut client = app_fixture.client(BENCH_ACCOUNT).await.unwrap();
        let member_refs: Vec<&str> = member_ids.iter().map(String::as_str).collect();
        for group in 0..groups {
            client
                .create_group(&format!("bench group {group}"), &member_refs)
                .await
                .unwrap();
        }
    }

    // --- cold reopen: durable chat projection first, then full readiness ---
    let app = open_store(&dir_bench, &url);
    let chat_list_started = Instant::now();
    let rows = app.chat_list(BENCH_ACCOUNT, false).unwrap();
    let chat_list = chat_list_started.elapsed();
    assert_eq!(rows.len(), groups, "cold chat list must hold every group");

    let runtime = MarmotAppRuntime::new(app);
    let start_started = Instant::now();
    runtime.start().await.unwrap();
    let start_ready = start_started.elapsed();

    let snapshot = runtime
        .shared_services()
        .app_performance_telemetry()
        .snapshot();
    let report = BenchReport {
        groups,
        roster,
        chat_list,
        start_ready,
        account_open_wait_ms: snapshot.account_open.duration_ms.sum_ms,
        session_open_ms: snapshot.account_session_open.duration_ms.sum_ms,
        group_hydration_ms: snapshot.account_group_hydration.duration_ms.sum_ms,
        profile_load_ms: snapshot.account_profile_load.duration_ms.sum_ms,
        read_snapshot_ms: snapshot.account_group_read_snapshot.duration_ms.sum_ms,
    };
    runtime.shutdown().await;
    report
}

/// Bench bodies compose many app boots and MLS commits; debug builds need
/// more than libtest's default 2 MiB stack (same shape as
/// `cursor_persistence.rs`).
fn run_bench(name: &'static str, groups: usize, roster: usize) {
    let thread = std::thread::Builder::new()
        .name(name.to_owned())
        .stack_size(8 * 1024 * 1024)
        .spawn(move || {
            let test_runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let report = test_runtime.block_on(run_case(groups, roster));
            report.print(name);
        })
        .unwrap();
    thread.join().unwrap();
}

/// Small un-ignored smoke case: keeps the harness itself compiling and
/// working in every CI run without the full matrix's cost.
#[test]
fn startup_scaling_smoke() {
    run_bench("smoke", 3, 1);
}

#[test]
#[ignore = "startup scaling benchmark; run via `just bench-startup`"]
fn startup_scaling_groups_0() {
    run_bench("groups_0", 0, 0);
}

#[test]
#[ignore = "startup scaling benchmark; run via `just bench-startup`"]
fn startup_scaling_groups_10() {
    run_bench("groups_10", 10, 1);
}

#[test]
#[ignore = "startup scaling benchmark; run via `just bench-startup`"]
fn startup_scaling_groups_100() {
    run_bench("groups_100", 100, 1);
}

#[test]
#[ignore = "startup scaling benchmark; run via `just bench-startup`"]
fn startup_scaling_groups_1000() {
    run_bench("groups_1000", 1000, 1);
}

#[test]
#[ignore = "startup scaling benchmark; run via `just bench-startup`"]
fn startup_scaling_roster_8() {
    run_bench("roster_8", 10, 8);
}

#[test]
#[ignore = "startup scaling benchmark; run via `just bench-startup`"]
fn startup_scaling_roster_64() {
    run_bench("roster_64", 10, 64);
}
