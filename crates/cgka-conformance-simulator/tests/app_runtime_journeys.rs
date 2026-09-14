//! Public-runtime acceptance tests: real local Nostr relay and per-client SQLCipher.
//! Run serially in release mode for production-policy evidence; see APP_PATH_COVERAGE.md.

use std::{collections::BTreeMap, error::Error, path::Path, time::Duration};

use cgka_conformance_simulator::{
    AppRuntimeHarness, AppRuntimeObservationV1, ConvergenceSubject, ScenarioStep,
    SubjectCreateGroup, SubjectInviteMembers, SubjectRemoveMembers, SubjectSendApplication,
    SubjectUpdateGroupData, resolve_scenario_input_bytes,
};
use serde_json::json;
use sha2::{Digest, Sha256};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
const SETTLEMENT: Duration = Duration::from_secs(60);
#[path = "support/offline_catchup.rs"]
mod offline_catchup;

#[derive(Clone, Copy, Debug)]
enum Journey {
    Messaging,
    Profile,
    Invite,
    Removal,
    Restart,
    Offline,
    LargeBacklog,
    LargeBacklogExtraEpochs,
}

#[derive(Debug, Default, serde::Serialize)]
struct RecoveryProgress {
    phase: &'static str,
    pass: Option<usize>,
    completed_pass: Option<usize>,
    expected: usize,
    observed: BTreeMap<String, usize>,
    restarts: usize,
}

fn save(out: &Path, name: &str, value: &impl serde::Serialize) -> TestResult {
    fs_private::write_private(&out.join(name), &serde_json::to_vec_pretty(value)?)?;
    Ok(())
}

fn save_recovery_checkpoint(
    out: &Path,
    progress: &RecoveryProgress,
    observations: &impl serde::Serialize,
    recovered: bool,
) -> TestResult {
    save(out, "recovery-progress.json", progress)?;
    // Keep a bounded checkpoint set even when the watchdog permits hundreds
    // of passes. The terminal observation is also retained by check().
    if progress
        .completed_pass
        .is_some_and(|pass| pass.is_multiple_of(10))
        || recovered
    {
        save(
            out,
            "recovery-checkpoint.json",
            &json!({ "progress": progress, "complete": recovered, "observations": observations }),
        )?;
    }
    Ok(())
}

fn multiset(payloads: &[String]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for payload in payloads {
        *counts.entry(payload.clone()).or_default() += 1;
    }
    counts
}

fn complete(
    observations: &[AppRuntimeObservationV1],
    expected: &BTreeMap<String, Vec<String>>,
    members: usize,
) -> bool {
    observations.len() == expected.len()
        && !observations.is_empty()
        && observations.iter().all(|o| {
            expected.get(&o.participant).is_some_and(|payloads| {
                multiset(&o.application.visible_plaintexts) == multiset(payloads)
            }) && !o.application.pending_confirmation
                && o.protocol.member_count == members
                && o.protocol.state_commitment_sha256
                    == observations[0].protocol.state_commitment_sha256
                && o.local.database_exists
                && o.local.database_encrypted
        })
}

async fn send(subject: &mut AppRuntimeHarness, sender: &str, payload: &str) -> TestResult {
    subject
        .send_application(SubjectSendApplication {
            action_id: payload,
            sender,
            payload,
        })
        .await?;
    Ok(())
}

async fn expect_timeline(
    subject: &mut AppRuntimeHarness,
    expected: &BTreeMap<String, Vec<String>>,
    out: &Path,
    checkpoint: &str,
) -> TestResult {
    let clients = expected.keys().cloned().collect::<Vec<_>>();
    let deadline = tokio::time::Instant::now() + SETTLEMENT;
    loop {
        subject.catch_up(&clients).await?;
        let observations = subject.observations(&clients).await?;
        if complete(&observations, expected, clients.len()) {
            save(out, checkpoint, &observations)?;
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            save(out, checkpoint, &observations)?;
            return Err(format!("public payload/state mismatch at {checkpoint}").into());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn exercise(
    subject: &mut AppRuntimeHarness,
    clients: &[String],
    journey: Journey,
    out: &Path,
    recovery_progress: &mut RecoveryProgress,
) -> TestResult {
    let founders = if matches!(journey, Journey::Invite) {
        &clients[..2]
    } else {
        clients
    };
    subject.select_scenario_group("main", true)?;
    let admins = if matches!(
        journey,
        Journey::LargeBacklog | Journey::LargeBacklogExtraEpochs
    ) {
        clients
    } else {
        &clients[..1]
    };
    subject
        .create_group(SubjectCreateGroup {
            action_id: "create",
            creator: "alice",
            name: "public runtime journey",
            invitees: &founders[1..],
            required_features: &[],
            initial_admins: admins,
            pending: "create",
        })
        .await?;
    subject.tick(founders).await?;
    subject
        .await_observable_settlement(founders, SETTLEMENT)
        .await?;
    if matches!(
        journey,
        Journey::LargeBacklog | Journey::LargeBacklogExtraEpochs
    ) {
        let prelude_updates = if matches!(journey, Journey::LargeBacklogExtraEpochs) {
            2
        } else {
            0
        };
        return large_backlog(subject, clients, out, prelude_updates, recovery_progress).await;
    }

    let mut expected = founders
        .iter()
        .map(|client| (client.clone(), vec!["before change".into()]))
        .collect::<BTreeMap<_, Vec<String>>>();
    send(subject, "alice", "before change").await?;
    expect_timeline(subject, &expected, out, "before-change.json").await?;
    let mut active = clients.to_vec();
    match journey {
        Journey::Messaging => {}
        Journey::Profile => {
            subject
                .update_group_data(SubjectUpdateGroupData {
                    action_id: "profile",
                    client: "alice",
                    name: Some("updated public group"),
                    description: Some("updated public description"),
                    pending: "profile",
                })
                .await?;
            let observations = subject
                .await_observable_settlement(clients, SETTLEMENT)
                .await?;
            save(out, "profile.json", &observations)?;
            if observations.iter().any(|o| {
                o.protocol.group_name != "updated public group"
                    || o.protocol.group_description != "updated public description"
            }) {
                return Err("public group profile did not update everywhere".into());
            }
        }
        Journey::Invite => {
            subject
                .invite_members(SubjectInviteMembers {
                    action_id: "invite",
                    inviter: "alice",
                    invitees: &clients[2..],
                    pending: "invite",
                })
                .await?;
            subject.tick(clients).await?;
            subject
                .await_observable_settlement(clients, SETTLEMENT)
                .await?;
            // A late joiner is entitled to messages sent after admission only.
            expected.insert("carol".into(), Vec::new());
        }
        Journey::Removal => {
            subject
                .remove_members(SubjectRemoveMembers {
                    action_id: "remove",
                    remover: "alice",
                    members: &clients[2..],
                    pending: "remove",
                })
                .await?;
            subject.tick(clients).await?;
            active = clients[..2].to_vec();
            subject
                .await_observable_settlement(&active, SETTLEMENT)
                .await?;
            expected.remove("carol");
        }
        Journey::Restart => subject.reopen("bob").await?,
        Journey::Offline => {
            subject.set_online("bob", false).await?;
            for index in 0..12 {
                let payload = format!("offline-{index:02}");
                send(subject, "alice", &payload).await?;
                for payloads in expected.values_mut() {
                    payloads.push(payload.clone());
                }
            }
            subject
                .update_group_data(SubjectUpdateGroupData {
                    action_id: "offline-profile",
                    client: "alice",
                    name: Some("offline update"),
                    description: None,
                    pending: "offline-profile",
                })
                .await?;
            subject
                .await_observable_settlement(&clients[..1], SETTLEMENT)
                .await?;
            subject.set_online("bob", true).await?;
            subject.repair_full_history(&["bob".into()]).await?;
        }
        Journey::LargeBacklog | Journey::LargeBacklogExtraEpochs => unreachable!(),
    }
    expect_timeline(subject, &expected, out, "after-change.json").await?;
    // Every remaining member must both send and receive in the recovered epoch.
    for client in &active {
        let payload = format!("fresh-from-{client}");
        send(subject, client, &payload).await?;
        for payloads in expected.values_mut() {
            payloads.push(payload.clone());
        }
    }
    expect_timeline(subject, &expected, out, "fresh-messages.json").await?;
    if matches!(journey, Journey::Removal) {
        let removed = subject.observations(&["carol".into()]).await?;
        save(out, "removed-member.json", &removed)?;
        if removed[0]
            .application
            .visible_plaintexts
            .iter()
            .any(|p| p.starts_with("fresh-from-"))
        {
            return Err("removed member received a post-removal message".into());
        }
    }
    subject.reopen("bob").await?;
    expect_timeline(subject, &expected, out, "after-restart.json").await
}

async fn large_backlog(
    subject: &mut AppRuntimeHarness,
    clients: &[String],
    out: &Path,
    prelude_updates: usize,
    recovery_progress: &mut RecoveryProgress,
) -> TestResult {
    recovery_progress.phase = "publishing_backlog";
    recovery_progress.expected = 1024;
    let input = resolve_scenario_input_bytes(&offline_catchup::bytes(1024))?;
    let online = clients
        .iter()
        .filter(|c| c.as_str() != "bob")
        .cloned()
        .collect::<Vec<_>>();
    subject.set_online("bob", false).await?;
    // Extra legitimate epoch activity can cross the deferred retry boundary;
    // released raw objects must remain replayable through the public app.
    let prelude = (0..prelude_updates)
        .map(|index| format!("recovery-prelude-{index}"))
        .collect::<Vec<_>>();
    save(
        out,
        "prelude.json",
        &json!({ "version": 1, "sender": "alice", "profile_names": prelude }),
    )?;
    for name in prelude {
        subject
            .update_group_data(SubjectUpdateGroupData {
                action_id: &name,
                client: "alice",
                name: Some(&name),
                description: None,
                pending: &name,
            })
            .await?;
        subject
            .await_observable_settlement(&online, SETTLEMENT)
            .await?;
    }
    let mut payloads = Vec::new();
    let mut rounds = 0;
    // Deliberate public workload companion, not an adapter override of private IR:
    // preserve every original send/update in order, with native relay ordering.
    for (index, step) in input.scenario.steps.iter().enumerate() {
        match step {
            ScenarioStep::SendAppMessage { sender, payload } => {
                send(subject, sender, payload).await?;
                payloads.push(payload.clone());
            }
            ScenarioStep::UpdateGroupData { client, name, .. } => {
                let id = format!("source-step-{index}");
                subject
                    .update_group_data(SubjectUpdateGroupData {
                        action_id: &id,
                        client,
                        name: Some(name),
                        description: None,
                        pending: &id,
                    })
                    .await?;
                subject
                    .await_observable_settlement(&online, SETTLEMENT)
                    .await?;
                rounds += 1;
                eprintln!("backlog round={rounds} sent={}", payloads.len());
            }
            ScenarioStep::ReconnectClient { .. } => break,
            _ => {}
        }
    }
    if payloads.len() != 1024 || rounds != 16 {
        return Err("saved backlog workload changed; expected 1024 sends and 16 updates".into());
    }
    let offline = subject.observations(&["bob".into()]).await?;
    save(out, "before-reconnect.json", &offline)?;
    if !offline[0].application.visible_plaintexts.is_empty() {
        return Err("offline recipient already observed backlog".into());
    }
    let mut expected = clients
        .iter()
        .map(|c| (c.clone(), payloads.clone()))
        .collect::<BTreeMap<_, _>>();
    save(out, "expected.json", &expected)?;
    recovery_progress.phase = "reconnect";
    subject
        .set_online("bob", true)
        .await
        .map_err(|error| format!("reconnecting recipient: {error}"))?;
    let mut previous = None;
    let mut unchanged = 0;
    let mut restarts = 0;
    // Production slices are bounded by elapsed time, so a repair call has no
    // minimum message throughput. Keep driving within check()'s existing
    // 900-second watchdog instead of declaring failure after 30 calls.
    for pass in 0_usize.. {
        recovery_progress.pass = Some(pass);
        recovery_progress.phase = "full_history_repair";
        subject
            .repair_full_history(&["bob".into()])
            .await
            .map_err(|error| format!("repair pass {pass}, full-history repair: {error}"))?;
        recovery_progress.phase = "catch_up";
        subject
            .catch_up(clients)
            .await
            .map_err(|error| format!("repair pass {pass}, catch-up: {error}"))?;
        recovery_progress.phase = "observations";
        let observations = subject
            .observations(clients)
            .await
            .map_err(|error| format!("repair pass {pass}, public observations: {error}"))?;
        let bob = observations
            .iter()
            .find(|o| o.participant == "bob")
            .ok_or("missing bob")?;
        let recovered = complete(&observations, &expected, clients.len());
        recovery_progress.completed_pass = Some(pass);
        recovery_progress.observed = observations
            .iter()
            .map(|o| {
                (
                    o.participant.clone(),
                    o.application.visible_plaintexts.len(),
                )
            })
            .collect();
        save_recovery_checkpoint(out, recovery_progress, &observations, recovered)?;
        eprintln!(
            "repair_pass={pass} observed={} expected=1024 complete={recovered}",
            bob.application.visible_plaintexts.len()
        );
        if recovered {
            break;
        }
        let progress = (bob.protocol.epoch, bob.application.visible_plaintexts.len());
        unchanged = if previous == Some(progress) {
            unchanged + 1
        } else {
            0
        };
        if unchanged >= 6 {
            if restarts >= 3 {
                return Err(
                    "large backlog stopped progressing after three recovery restarts".into(),
                );
            }
            recovery_progress.phase = "reopen";
            subject.reopen("bob").await?;
            restarts += 1;
            recovery_progress.restarts = restarts;
            unchanged = 0;
        }
        previous = Some(progress);
        recovery_progress.phase = "backoff";
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    recovery_progress.phase = "post_recovery_messaging";
    for client in clients {
        let payload = format!("post-recovery-{client}");
        send(subject, client, &payload).await?;
        for messages in expected.values_mut() {
            messages.push(payload.clone());
        }
    }
    expect_timeline(subject, &expected, out, "post-recovery-messaging.json").await?;
    recovery_progress.phase = "restart_persistence";
    subject.reopen("bob").await?;
    subject.repair_full_history(&["bob".into()]).await?;
    expect_timeline(subject, &expected, out, "after-restart.json").await
}

async fn check(journey: Journey) {
    if std::env::var_os("MDK_BACKLOG_TRACE").is_some() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter("cgka_engine::message_processor=debug,marmot_app::relay_plane=info")
            .with_ansi(false)
            .with_writer(std::io::stderr)
            .try_init();
    }
    let label = format!("{journey:?}").to_lowercase();
    let mut builder = tempfile::Builder::new();
    let prefix = format!("app-journey-{label}-");
    builder.prefix(&prefix);
    let artifacts = if let Some(root) = std::env::var_os("MDK_APP_JOURNEY_ARTIFACTS") {
        fs_private::create_dir_all_private(Path::new(&root)).unwrap();
        builder.tempdir_in(root).unwrap()
    } else {
        builder.tempdir().unwrap()
    };
    fs_private::create_dir_all_private(artifacts.path()).unwrap();
    let labels: &[&str] = match journey {
        Journey::Invite | Journey::Removal => &["alice", "bob", "carol"],
        Journey::LargeBacklog | Journey::LargeBacklogExtraEpochs => {
            &["alice", "bob", "carol", "david"]
        }
        _ => &["alice", "bob"],
    };
    let clients = labels.iter().map(|c| (*c).to_owned()).collect::<Vec<_>>();
    let backlog_source = matches!(
        journey,
        Journey::LargeBacklog | Journey::LargeBacklogExtraEpochs
    )
    .then(|| offline_catchup::bytes(1024));
    if let Some(bytes) = &backlog_source {
        fs_private::write_private(&artifacts.path().join("backlog-input.json"), bytes).unwrap();
    }
    save(
        artifacts.path(),
        "input.json",
        &json!({
            "journey": label, "version": 1, "clients": clients,
            "adapter": "marmot_app_runtime", "storage": "sqlcipher_per_participant",
            "relay_order": "native local Nostr relay", "debug_assertions": cfg!(debug_assertions),
            "settlement_policy": "default production policy; no test override requested",
            "backlog_source_sha256": backlog_source.as_ref().map(|bytes| format!("{:x}", Sha256::digest(bytes))),
        }),
    )
    .unwrap();
    let mut subject = AppRuntimeHarness::new(&clients)
        .await
        .expect("public runtime setup");
    let mut recovery_progress = RecoveryProgress {
        phase: "setup",
        ..RecoveryProgress::default()
    };
    let mut result = match tokio::time::timeout(
        Duration::from_secs(900),
        exercise(&mut subject, &clients, journey, artifacts.path(), &mut recovery_progress),
    )
    .await
    {
        Ok(result) => result,
        Err(_) if backlog_source.is_some() => Err(format!(
            "public journey exceeded 900-second watchdog; last recovery progress: {recovery_progress:?}"
        ).into()),
        Err(_) => Err("public journey exceeded 900-second watchdog".into()),
    };
    if backlog_source.is_some() {
        if result.is_ok() {
            recovery_progress.phase = "complete";
        }
        if let Err(error) = save(
            artifacts.path(),
            "recovery-progress.json",
            &recovery_progress,
        ) {
            result = Err(format!(
                "saving recovery progress failed: {error}; journey result: {result:?}"
            )
            .into());
        }
    }
    if let Ok(observations) = subject.observations(&clients).await {
        save(artifacts.path(), "terminal.json", &observations).unwrap();
    }
    // Close every runtime before asserting. Never exit the process while a
    // SQLCipher worker may still be writing (see APP_PATH_COVERAGE.md).
    let mut close_errors = Vec::new();
    for client in &clients {
        if let Err(error) = subject.set_online(client, false).await {
            close_errors.push(error.to_string());
        }
    }
    subject.shutdown().await;
    drop(subject);
    save(
        artifacts.path(),
        "result.json",
        &json!({
            "passed": result.is_ok() && close_errors.is_empty(),
            "error": result.as_ref().err().map(ToString::to_string), "close_errors": close_errors,
        }),
    )
    .unwrap();
    if result.is_err() || std::env::var_os("MDK_APP_JOURNEY_ARTIFACTS").is_some() {
        eprintln!("public journey evidence: {}", artifacts.keep().display());
    }
    assert!(
        close_errors.is_empty(),
        "runtime close failed: {close_errors:?}"
    );
    assert!(result.is_ok(), "{label}: {}", result.unwrap_err());
}

#[test]
fn recovery_checkpoints_bound_artifacts_and_preserve_final_state() {
    let out = tempfile::tempdir().unwrap();
    let mut progress = RecoveryProgress {
        phase: "observations",
        expected: 1024,
        ..RecoveryProgress::default()
    };
    for pass in 0..=103 {
        progress.pass = Some(pass);
        progress.completed_pass = Some(pass);
        progress.observed.insert("bob".into(), pass);
        save_recovery_checkpoint(
            out.path(),
            &progress,
            &json!({ "last_pass": pass }),
            pass == 103,
        )
        .unwrap();
    }
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 2);
    let checkpoint: serde_json::Value = serde_json::from_slice(
        &std::fs::read(out.path().join("recovery-checkpoint.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(checkpoint["progress"]["completed_pass"], 103);
    assert_eq!(checkpoint["observations"]["last_pass"], 103);
    assert_eq!(checkpoint["complete"], true);
    let latest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out.path().join("recovery-progress.json")).unwrap())
            .unwrap();
    assert_eq!(latest["observed"]["bob"], 103);
}

macro_rules! journey_test {
    ($name:ident, $journey:ident) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn $name() {
            check(Journey::$journey).await;
        }
    };
}

journey_test!(public_app_01_bidirectional_messaging, Messaging);
journey_test!(public_app_02_profile_update_and_messaging, Profile);
journey_test!(public_app_03_late_join_and_messaging, Invite);
journey_test!(
    public_app_04_removal_and_remaining_member_messaging,
    Removal
);
journey_test!(public_app_05_restart_and_continue_messaging, Restart);
journey_test!(public_app_06_small_offline_backlog, Offline);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "explicit slow recovery gate; see APP_PATH_COVERAGE.md"]
async fn public_app_1024_message_backlog_recovers_completely() {
    check(Journey::LargeBacklog).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "explicit slow recovery gate; covers resource release and replay"]
async fn public_app_1024_message_backlog_with_extra_epochs_recovers_completely() {
    check(Journey::LargeBacklogExtraEpochs).await;
}
