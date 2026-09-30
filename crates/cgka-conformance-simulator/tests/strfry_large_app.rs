//! Explicit public-app scale probe against the repo's local strfry relay.
//! Run one population at a time with a fresh private artifact root.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use cgka_traits::{GroupId, TransportEndpoint};
use marmot_app::{
    AccountSetupRequest, AppMessageQuery, MarmotApp, MarmotAppConfig, MarmotAppRuntime,
};

struct Participant {
    root: PathBuf,
    app: MarmotApp,
    runtime: MarmotAppRuntime,
    account: String,
    online: bool,
}

fn app(root: &Path, relay: &str) -> MarmotApp {
    MarmotApp::with_relays_and_config(
        root,
        vec![relay.to_owned()],
        MarmotAppConfig::default().with_allow_loopback_relay_endpoints(true),
    )
}

fn milestone(root: &Path, stage: &str, elapsed: Duration, members: usize) {
    let path = root.join(format!("milestone-{stage}.json"));
    fs_private::write_private(
        &path,
        serde_json::to_string_pretty(&serde_json::json!({
            "stage": stage,
            "members": members,
            "elapsed_ms": elapsed.as_millis(),
        }))
        .unwrap()
        .as_bytes(),
    )
    .unwrap();
    eprintln!(
        "STRFRY_APP_STAGE {stage} members={members} elapsed_ms={}",
        elapsed.as_millis()
    );
}

async fn catch_up_all(participants: &[Participant]) {
    let width = std::env::var("MDK_STRFRY_CATCH_UP_PARALLELISM")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| (1..=8).contains(value))
        .unwrap_or(8);
    for (batch_index, batch) in participants.chunks(width).enumerate() {
        let mut tasks = tokio::task::JoinSet::new();
        for (offset, participant) in batch.iter().enumerate() {
            if !participant.online {
                continue;
            }
            let runtime = participant.runtime.clone();
            let index = batch_index * width + offset;
            tasks.spawn(async move {
                let started = Instant::now();
                (index, started, runtime.catch_up_accounts().await)
            });
        }
        while let Some(result) = tasks.join_next().await {
            let (index, started, outcome) = result.expect("catch-up task");
            if started.elapsed() > Duration::from_secs(10) || outcome.is_err() {
                eprintln!(
                    "STRFRY_APP_CATCH_UP index={index} elapsed_ms={} success={}",
                    started.elapsed().as_millis(),
                    outcome.is_ok()
                );
            }
            outcome.unwrap_or_else(|error| panic!("catch-up at index {index}: {error}"));
        }
    }
}

fn has_message(participant: &Participant, group: &GroupId, expected: &str) -> bool {
    participant
        .app
        .messages_with_query(
            &participant.account,
            AppMessageQuery {
                group_id_hex: Some(hex::encode(group.as_slice())),
                kinds: None,
                limit: None,
            },
        )
        .expect("read app messages")
        .iter()
        .any(|message| !message.invalidated && message.plaintext == expected)
}

async fn wait_for_message(participants: &[Participant], group: &GroupId, expected: &str) {
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        catch_up_all(participants).await;
        let missing = participants
            .iter()
            .filter(|participant| participant.online && !has_message(participant, group, expected))
            .count();
        if missing == 0 {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "message absent from {missing} participants"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "manual 25/50/100/200-member app probe; requires local strfry and private artifacts"]
async fn large_group_through_strfry() {
    let count = std::env::var("MDK_STRFRY_GROUP_MEMBERS")
        .expect("set MDK_STRFRY_GROUP_MEMBERS")
        .parse::<usize>()
        .unwrap();
    assert!((25..=200).contains(&count));
    let relay = std::env::var("MDK_STRFRY_URL").expect("set MDK_STRFRY_URL");
    assert!(relay.starts_with("ws://127.0.0.1:"));
    let root = PathBuf::from(std::env::var("MDK_STRFRY_APP_ARTIFACTS").unwrap());
    assert!(!root.exists(), "use a new artifact directory");
    fs_private::create_dir_all_private(&root).unwrap();
    let started = Instant::now();

    let mut participants = Vec::with_capacity(count);
    for index in 0..count {
        let member_root = root.join(format!("member-{index:03}"));
        fs_private::create_dir_all_private(&member_root).unwrap();
        let app = app(&member_root, &relay);
        let runtime = MarmotAppRuntime::new(app.clone());
        runtime.start().await.expect("start app runtime");
        let endpoints = vec![TransportEndpoint::from(relay.clone())];
        let account = runtime
            .create_identity(AccountSetupRequest {
                default_relays: endpoints.clone(),
                bootstrap_relays: endpoints,
                publish_missing_relay_lists: true,
                publish_initial_key_package: true,
                ..Default::default()
            })
            .await
            .expect("create app identity")
            .account
            .account_id_hex;
        participants.push(Participant {
            root: member_root,
            app,
            runtime,
            account,
            online: true,
        });
        if (index + 1) % 25 == 0 || index + 1 == count {
            milestone(&root, "identities", started.elapsed(), index + 1);
        }
    }

    let invitees: Vec<_> = participants[1..]
        .iter()
        .map(|participant| participant.account.clone())
        .collect();
    let group = participants[0]
        .runtime
        .create_group(
            &participants[0].account,
            "Strfry scale probe",
            &invitees,
            None,
        )
        .await
        .expect("create 200-member group");
    assert!(
        participants[0]
            .runtime
            .pending_welcome_deliveries(&participants[0].account)
            .await
            .unwrap()
            .is_empty(),
        "founder has undelivered Welcomes"
    );
    milestone(&root, "created", started.elapsed(), count);

    for (index, participant) in participants.iter().enumerate().skip(1) {
        let deadline = Instant::now() + Duration::from_secs(90);
        loop {
            participant
                .runtime
                .catch_up_accounts()
                .await
                .expect("catch up invitee");
            let pending = participant
                .app
                .group(&participant.account, &hex::encode(group.as_slice()))
                .unwrap()
                .is_some_and(|record| record.pending_confirmation);
            if pending {
                match participant
                    .runtime
                    .accept_group_invite(&participant.account, &group)
                    .await
                {
                    Ok(_) => break,
                    Err(marmot_app::AppError::AccountWorkerBusy) => {}
                    Err(error) => panic!("accept invite at index {index}: {error}"),
                }
            }
            assert!(Instant::now() < deadline, "invite absent at index {index}");
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
        if (index + 1) % 25 == 0 || index + 1 == count {
            milestone(&root, "joined", started.elapsed(), index + 1);
        }
    }

    catch_up_all(&participants).await;
    let expected_roster = participants
        .iter()
        .map(|participant| participant.account.clone())
        .collect::<BTreeSet<_>>();
    let expected_epoch = participants[0]
        .runtime
        .group_mls_state(&participants[0].account, &group)
        .await
        .expect("founder MLS state")
        .epoch;
    for (index, participant) in participants.iter().enumerate() {
        let state = participant
            .runtime
            .group_mls_state(&participant.account, &group)
            .await
            .unwrap_or_else(|error| panic!("MLS state at index {index}: {error}"));
        assert_eq!(state.member_count, count, "roster size at index {index}");
        assert_eq!(state.epoch, expected_epoch, "epoch at index {index}");
        assert_eq!(
            state.protocol_profile,
            marmot_app::AppProtocolProfile::Current
        );
        let roster = participant
            .runtime
            .group_members(&participant.account, &group)
            .await
            .unwrap_or_else(|error| panic!("roster at index {index}: {error}"))
            .into_iter()
            .map(|member| member.member_id_hex)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            roster, expected_roster,
            "roster identities at index {index}"
        );
    }
    milestone(&root, "roster", started.elapsed(), count);

    let founder_message = "strfry-scale-founder-message";
    participants[0]
        .runtime
        .send_message(
            &participants[0].account,
            &group,
            founder_message.as_bytes().to_vec(),
        )
        .await
        .expect("founder send");
    wait_for_message(&participants, &group, founder_message).await;
    milestone(&root, "founder-fanout", started.elapsed(), count);

    let offline = [1, count / 2, count - 1];
    for index in offline {
        participants[index]
            .runtime
            .shutdown_and_close()
            .await
            .expect("close offline participant");
        participants[index].online = false;
    }
    milestone(&root, "offline", started.elapsed(), offline.len());

    let peer_message = "strfry-scale-peer-message";
    participants[count - 2]
        .runtime
        .send_message(
            &participants[count - 2].account,
            &group,
            peer_message.as_bytes().to_vec(),
        )
        .await
        .expect("peer send");
    wait_for_message(&participants, &group, peer_message).await;
    milestone(&root, "peer-fanout", started.elapsed(), count);

    for index in offline {
        let reopened_app = app(&participants[index].root, &relay);
        let reopened_runtime = MarmotAppRuntime::new(reopened_app.clone());
        reopened_runtime.start().await.expect("reopen app runtime");
        participants[index].app = reopened_app;
        participants[index].runtime = reopened_runtime;
        participants[index].online = true;
    }
    catch_up_all(&participants).await;
    for index in offline {
        assert!(has_message(&participants[index], &group, founder_message));
        let deadline = Instant::now() + Duration::from_secs(120);
        while !has_message(&participants[index], &group, peer_message) {
            assert!(
                Instant::now() < deadline,
                "offline peer failed catch-up at index {index}"
            );
            participants[index]
                .runtime
                .catch_up_accounts()
                .await
                .expect("offline catch-up");
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        let state = participants[index]
            .runtime
            .group_mls_state(&participants[index].account, &group)
            .await
            .expect("reopened MLS state");
        assert_eq!(state.member_count, count);
    }
    milestone(&root, "offline-recovered", started.elapsed(), offline.len());

    participants[0]
        .runtime
        .shutdown_and_close()
        .await
        .expect("close founder");
    let reopened_app = app(&participants[0].root, &relay);
    let reopened_runtime = MarmotAppRuntime::new(reopened_app.clone());
    reopened_runtime.start().await.expect("reopen founder");
    participants[0].app = reopened_app;
    participants[0].runtime = reopened_runtime;
    participants[0]
        .runtime
        .catch_up_accounts()
        .await
        .expect("founder catch-up");
    assert!(has_message(&participants[0], &group, founder_message));
    assert!(has_message(&participants[0], &group, peer_message));
    milestone(&root, "reopened", started.elapsed(), count);

    for participant in &participants {
        participant
            .runtime
            .shutdown_and_close()
            .await
            .expect("shutdown app runtime");
    }
    milestone(&root, "complete", started.elapsed(), count);
}

/// Diagnose the retained roots after a failed full probe. The original failure
/// remains a failure even if a fresh process can subsequently repair history.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "manual recovery diagnostic for a retained strfry large-app fixture"]
async fn resume_large_group_after_failure() {
    let count = std::env::var("MDK_STRFRY_GROUP_MEMBERS")
        .unwrap()
        .parse::<usize>()
        .unwrap();
    let relay = std::env::var("MDK_STRFRY_URL").unwrap();
    let root = PathBuf::from(std::env::var("MDK_STRFRY_APP_ARTIFACTS").unwrap());
    assert!(root.is_dir(), "fixture missing");
    let started = Instant::now();
    let mut participants = Vec::with_capacity(count);
    for index in 0..count {
        let member_root = root.join(format!("member-{index:03}"));
        let app = app(&member_root, &relay);
        let runtime = MarmotAppRuntime::new(app.clone());
        runtime.start().await.expect("reopen app runtime");
        let account = runtime
            .accounts()
            .managed_accounts()
            .expect("read account")
            .into_iter()
            .next()
            .expect("account missing")
            .account_id_hex;
        participants.push(Participant {
            root: member_root,
            app,
            runtime,
            account,
            online: true,
        });
    }
    milestone(&root, "resumed-runtimes", started.elapsed(), count);
    let group_id_hex = participants[0]
        .app
        .groups(&participants[0].account)
        .expect("founder groups")
        .into_iter()
        .next()
        .expect("founder group missing")
        .group_id_hex;
    let group = GroupId::new(hex::decode(group_id_hex).unwrap());
    catch_up_all(&participants).await;
    milestone(&root, "resumed-catch-up", started.elapsed(), count);
    wait_for_message(&participants, &group, "strfry-scale-founder-message").await;
    milestone(&root, "resumed-founder-fanout", started.elapsed(), count);
    for participant in &participants {
        participant
            .runtime
            .shutdown_and_close()
            .await
            .expect("close resumed runtime");
    }
    milestone(&root, "resumed-complete", started.elapsed(), count);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "diagnose one copied founder root after the 200-member catch-up timeout"]
async fn resume_founder_only() {
    tracing_subscriber::fmt()
        .with_env_filter("off,cgka_engine::replay_slice=debug,marmot_app::history_repair=debug")
        .with_ansi(false)
        .with_writer(std::io::stderr)
        .try_init()
        .unwrap();
    let relay = std::env::var("MDK_STRFRY_URL").unwrap();
    let root = PathBuf::from(std::env::var("MDK_STRFRY_FOUNDER_ROOT").unwrap());
    let started = Instant::now();
    let app = app(&root, &relay);
    let runtime = MarmotAppRuntime::new(app.clone());
    runtime.start().await.expect("start founder");
    let account = runtime
        .accounts()
        .managed_accounts()
        .unwrap()
        .into_iter()
        .next()
        .unwrap()
        .account_id_hex;
    eprintln!(
        "STRFRY_FOUNDER_STAGE started elapsed_ms={}",
        started.elapsed().as_millis()
    );
    let catch_up_started = Instant::now();
    runtime.catch_up_accounts().await.expect("founder catch-up");
    eprintln!(
        "STRFRY_FOUNDER_STAGE caught-up elapsed_ms={}",
        catch_up_started.elapsed().as_millis()
    );
    let group_id =
        GroupId::new(hex::decode(app.groups(&account).unwrap()[0].group_id_hex.clone()).unwrap());
    assert_eq!(
        runtime
            .group_mls_state(&account, &group_id)
            .await
            .unwrap()
            .member_count,
        200
    );
    assert!(has_message(
        &Participant {
            root: root.clone(),
            app,
            runtime: runtime.clone(),
            account,
            online: true,
        },
        &group_id,
        "strfry-scale-founder-message"
    ));
    runtime.shutdown_and_close().await.unwrap();
}
