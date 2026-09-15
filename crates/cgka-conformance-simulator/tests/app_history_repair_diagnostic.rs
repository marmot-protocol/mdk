//! Explicit diagnosis, not a family acceptance run. Keep original input and
//! stopped private fixtures so subsequent probes need not repeat setup.
use cgka_conformance_simulator::{
    AppRuntimeHarness, GeneratedScenarioInputV1, ScenarioStep, run_scenario_report_with_subject,
};

/// Retain an exact saved app run, including a semantic failure, for investigation.
/// A passing libtest result means evidence was captured, not that the scenario passed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "explicit saved-input diagnosis; retains private participant roots and relay history"]
async fn saved_app_recovery_diagnostic() {
    assert!(!AppRuntimeHarness::honors_maintenance_timing_override());
    let input = std::fs::read(std::env::var_os("MDK_APP_DIAGNOSTIC_INPUT").unwrap()).unwrap();
    let generated: GeneratedScenarioInputV1 = serde_json::from_slice(&input).unwrap();
    let output = std::path::PathBuf::from(std::env::var_os("MDK_APP_JOURNEY_ARTIFACTS").unwrap());
    assert!(!output.exists(), "preserve prior evidence");
    fs_private::create_dir_all_private(&output).unwrap();
    fs_private::write_private(&output.join("original-generated-input.json"), &input).unwrap();
    let scenario = generated.case.scenario;
    let mut subject = AppRuntimeHarness::new(&scenario.clients).await.unwrap();
    fs_private::write_private(
        &output.join("execution-layout.json"),
        &serde_json::to_vec_pretty(&subject.process_layout()).unwrap(),
    )
    .unwrap();
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(900),
        run_scenario_report_with_subject(
            &scenario,
            None,
            generated.case.expected_outcomes,
            &mut subject,
        ),
    )
    .await;
    if let Ok(Ok(report)) = &result {
        fs_private::write_private(
            &output.join("report.json"),
            &serde_json::to_vec_pretty(report).unwrap(),
        )
        .unwrap();
        diagnostic_public_snapshot(&mut subject, &scenario.clients, &output, "after-scenario")
            .await;
        if report.campaign_measurements.first_failing_action.is_some()
            && let Ok(client) = std::env::var("MDK_APP_DIAGNOSTIC_RECOVERY_CLIENT")
        {
            assert!(scenario.clients.contains(&client));
            let clients = vec![client.clone()];
            // These probes follow the preserved failed report; they cannot turn
            // its failed assertion into a pass or change the original workload.
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            diagnostic_public_snapshot(&mut subject, &scenario.clients, &output, "after-wait")
                .await;
            let repair = subject.repair_full_history(&clients).await;
            fs_private::write_private(
                &output.join("extra-repair-result.json"),
                &serde_json::to_vec_pretty(&serde_json::json!({
                    "passed": repair.is_ok(), "error": repair.err().map(|e| e.to_string())
                }))
                .unwrap(),
            )
            .unwrap();
            diagnostic_public_snapshot(&mut subject, &scenario.clients, &output, "after-repair")
                .await;
            let reopen = subject.reopen(&client).await;
            let repair = if reopen.is_ok() {
                subject.repair_full_history(&clients).await
            } else {
                reopen
            };
            fs_private::write_private(
                &output.join("reopen-repair-result.json"),
                &serde_json::to_vec_pretty(&serde_json::json!({
                    "passed": repair.is_ok(), "error": repair.err().map(|e| e.to_string())
                }))
                .unwrap(),
            )
            .unwrap();
            diagnostic_public_snapshot(&mut subject, &scenario.clients, &output, "after-reopen")
                .await;
        }
    }
    let cleanup =
        tokio::time::timeout(std::time::Duration::from_secs(60), subject.shutdown()).await;
    assert!(matches!(&cleanup, Ok(Ok(()))));
    subject
        .retain_stopped_diagnostic_fixture(&output.join("retained-fixture"))
        .await
        .unwrap();
    let report = result.expect("saved-input diagnostic deadline").unwrap();
    fs_private::write_private(
        &output.join("result.json"),
        &serde_json::to_vec_pretty(&serde_json::json!({
            "evidence_captured": true,
            "scenario_passed": report.campaign_measurements.first_failing_action.is_none()
                && report.expectation_failures.is_empty() && report.invariant_failures.is_empty(),
            "steps": report.step_log.len(),
        }))
        .unwrap(),
    )
    .unwrap();
}

async fn diagnostic_public_snapshot(
    subject: &mut AppRuntimeHarness,
    clients: &[String],
    output: &std::path::Path,
    phase: &str,
) {
    let observations = subject.observations(clients).await;
    let snapshot = match observations {
        Ok(observations) => serde_json::json!({"observations": observations}),
        Err(error) => serde_json::json!({"error": error.to_string()}),
    };
    fs_private::write_private(
        &output.join(format!("{phase}.json")),
        &serde_json::to_vec_pretty(&snapshot).unwrap(),
    )
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "saved large-app input, unique artifacts, production policy; retains private roots"]
async fn large_app_history_prefix_diagnostic() {
    assert!(!AppRuntimeHarness::honors_maintenance_timing_override());
    tracing_subscriber::fmt()
        .with_env_filter("off,cgka_engine::replay_slice=debug,cgka_conformance_simulator::progress=debug,marmot_app::history_repair=debug")
        .with_ansi(false)
        .with_writer(std::io::stderr)
        .try_init().unwrap();
    let input = std::fs::read(std::env::var_os("MDK_APP_DIAGNOSTIC_INPUT").unwrap()).unwrap();
    let generated: GeneratedScenarioInputV1 = serde_json::from_slice(&input).unwrap();
    let mut scenario = generated.case.scenario;
    assert!(matches!(
        scenario.steps.get(254),
        Some(ScenarioStep::SyncRelayHistory { .. })
    ));
    scenario.steps.truncate(255);
    let output = std::path::PathBuf::from(std::env::var_os("MDK_APP_JOURNEY_ARTIFACTS").unwrap());
    assert!(!output.exists(), "preserve prior evidence");
    fs_private::create_dir_all_private(&output).unwrap();
    fs_private::write_private(&output.join("original-generated-input.json"), &input).unwrap();
    fs_private::write_private(
        &output.join("selected-scenario.json"),
        &serde_json::to_vec_pretty(&scenario).unwrap(),
    )
    .unwrap();
    let mut subject = AppRuntimeHarness::new(&scenario.clients).await.unwrap();
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(1800),
        run_scenario_report_with_subject(&scenario, None, vec![], &mut subject),
    )
    .await;
    if let Ok(Ok(report)) = &result {
        fs_private::write_private(
            &output.join("report.json"),
            &serde_json::to_vec_pretty(report).unwrap(),
        )
        .unwrap();
    }
    fs_private::write_private(
        &output.join("performance-before-cleanup.json"),
        &serde_json::to_vec_pretty(
            &subject
                .performance_snapshots()
                .expect("performance snapshots"),
        )
        .unwrap(),
    )
    .unwrap();
    let cleanup =
        tokio::time::timeout(std::time::Duration::from_secs(60), subject.shutdown()).await;
    if matches!(&cleanup, Ok(Ok(()))) {
        subject
            .retain_stopped_diagnostic_fixture(&output.join("retained-fixture"))
            .await
            .unwrap();
    }
    assert!(matches!(&cleanup, Ok(Ok(()))));
    let report = result.expect("diagnostic prefix deadline").unwrap();
    // The prefix retains every original step assertion. Final family oracles
    // are deliberately absent: their later mutations have not been executed.
    assert_eq!(report.step_log.len(), 255);
    assert!(
        report
            .assertion_observations
            .iter()
            .all(|observation| observation.passed)
    );
    assert!(
        report.campaign_measurements.first_failing_action.is_none(),
        "diagnostic prefix failed: {:?}",
        report.campaign_measurements.limiting_resource
    );
}

/// Reopen one COPY of a retained participant against its saved relay history.
/// This tests a new repair attempt after restart, not the original scheduling.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "private marked root copy and retained relay fixture; original relay port must be free"]
async fn retained_history_repair_diagnostic() {
    assert!(!AppRuntimeHarness::honors_maintenance_timing_override());
    use nostr_relay_builder::prelude::{
        Event, MemoryDatabase, MemoryDatabaseOptions, NostrDatabase,
    };
    let root = std::path::PathBuf::from(std::env::var_os("MDK_RETAINED_APP_ROOT").unwrap());
    assert!(
        root.join("replay-diagnostic-fixture").is_file(),
        "use a marked private copy"
    );
    let fixture = std::path::PathBuf::from(std::env::var_os("MDK_RETAINED_RELAY_FIXTURE").unwrap());
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(fixture.join("manifest.json")).unwrap()).unwrap();
    let endpoint = manifest["relay_url"].as_str().unwrap();
    let port: u16 = endpoint
        .strip_prefix("ws://127.0.0.1:")
        .expect("synthetic loopback relay only")
        .trim_end_matches('/')
        .parse()
        .unwrap();
    let events: Vec<Event> =
        serde_json::from_slice(&std::fs::read(fixture.join("relay-publications.json")).unwrap())
            .unwrap();
    let database = MemoryDatabase::with_opts(MemoryDatabaseOptions {
        events: true,
        max_events: Some(75_000),
    });
    for event in events {
        database.save_event(&event).await.unwrap();
    }
    tracing_subscriber::fmt()
        .with_env_filter("off,marmot_app::history_repair=debug,cgka_engine::replay_slice=debug")
        .with_ansi(false)
        .with_writer(std::io::stderr)
        .try_init()
        .unwrap();
    let relay = nostr_relay_builder::LocalRelay::new(
        nostr_relay_builder::RelayBuilder::default()
            .port(port)
            .database(database),
    );
    relay.run().await.unwrap();
    let app = marmot_app::MarmotApp::with_relay_and_config(
        &root,
        endpoint.to_owned(),
        marmot_app::MarmotAppConfig::default().with_allow_loopback_relay_endpoints(true),
    );
    let runtime = marmot_app::MarmotAppRuntime::new(app);
    runtime.start().await.unwrap();
    let accounts = runtime.accounts().managed_accounts().unwrap();
    assert_eq!(accounts.len(), 1);
    let mut results = Vec::new();
    for attempt in 0..3 {
        let started = std::time::Instant::now();
        let result = runtime
            .repair_full_history(&accounts[0].account_id_hex)
            .await;
        results.push(serde_json::json!({"attempt": attempt, "success": result.is_ok(), "duration_ms": started.elapsed().as_millis(), "error_kind": result.as_ref().err().map(|error| match error { marmot_app::AppError::AccountCatchUp(_) => "account_catch_up", marmot_app::AppError::AccountWorkerResponseTimedOut => "account_worker_timeout", _ => "other" })}));
        if result.is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    let output = root.join("history-repair-attempts.json");
    assert!(!output.exists(), "use a fresh copy");
    fs_private::write_private(&output, &serde_json::to_vec_pretty(&results).unwrap()).unwrap();
    tokio::time::timeout(
        std::time::Duration::from_secs(60),
        runtime.shutdown_and_close(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        results.iter().any(|result| result["success"] == true),
        "all bounded repair attempts remained incomplete"
    );
}
