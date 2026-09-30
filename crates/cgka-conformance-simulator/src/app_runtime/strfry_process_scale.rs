//! Manual scale probe: one public app process per participant, real strfry socket.
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use cgka_traits::GroupId;
use marmot_app::{
    AppGroupMemberRecord, AppGroupMlsState, AppGroupRecord, AppMessageRecord, AppStatus,
};
use serde_json::json;

use super::process_backend::Init;
use super::process_io::ProcessClient;

struct Participant {
    root: PathBuf,
    client: ProcessClient,
    account: String,
    online: bool,
}

fn milestone(root: &Path, stage: &str, elapsed: Duration, count: usize) {
    fs_private::write_private(
        &root.join(format!("milestone-{stage}.json")),
        serde_json::to_string_pretty(&json!({
            "stage":stage,"members":count,"elapsed_ms":elapsed.as_millis()
        }))
        .unwrap()
        .as_bytes(),
    )
    .unwrap();
    tracing::info!(
        target: "cgka_conformance_simulator::strfry_process_scale",
        method = "milestone",
        stage,
        member_count = count,
        elapsed_ms = elapsed.as_millis() as u64,
        "manual scale probe milestone"
    );
}

async fn launch(root: PathBuf, relay: &str, create_identity: bool) -> Participant {
    fs_private::create_dir_all_private(&root).unwrap();
    let client = ProcessClient::spawn("participant", &root).expect("spawn app participant");
    let account: String = client
        .call_async(
            "initialize",
            serde_json::to_value(Init {
                root: root.clone(),
                relay_url: relay.to_owned(),
                extra_relay_urls: Vec::new(),
                settlement_ms: None,
                immediate_maintenance: false,
                create_identity,
            })
            .unwrap(),
        )
        .await
        .expect("initialize app participant");
    Participant {
        root,
        client,
        account,
        online: true,
    }
}

async fn close(participant: &Participant) {
    participant
        .client
        .call_async::<()>("close", json!([]))
        .await
        .expect("close app participant");
    participant.client.reap().expect("reap app participant");
}

async fn catch_up_all(participants: &[Participant]) {
    let width = std::env::var("MDK_STRFRY_PROCESS_CATCH_UP_PARALLELISM")
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
            let client = participant.client.clone();
            let index = batch_index * width + offset;
            tasks.spawn(async move {
                let started = Instant::now();
                (
                    index,
                    started,
                    client
                        .call_async::<()>("catch_up_accounts", json!([]))
                        .await,
                )
            });
        }
        while let Some(result) = tasks.join_next().await {
            let (index, started, outcome) = result.expect("catch-up task");
            if started.elapsed() > Duration::from_secs(10) || outcome.is_err() {
                tracing::info!(
                    target: "cgka_conformance_simulator::strfry_process_scale",
                    method = "catch_up_all",
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    success = outcome.is_ok(),
                    "manual scale probe catch-up completed"
                );
            }
            outcome.unwrap_or_else(|error| panic!("catch-up at index {index}: {error}"));
        }
    }
}

async fn has_message(participant: &Participant, group: &GroupId, expected: &str) -> bool {
    let messages: Vec<AppMessageRecord> = participant
        .client
        .call_async(
            "messages",
            json!([
                participant.account,
                hex::encode(group.as_slice()),
                null,
                null
            ]),
        )
        .await
        .expect("read participant messages");
    messages
        .iter()
        .any(|message| !message.invalidated && message.plaintext == expected)
}

async fn wait_for_message(participants: &[Participant], group: &GroupId, expected: &str) {
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        catch_up_all(participants).await;
        let mut missing = 0;
        for participant in participants.iter().filter(|participant| participant.online) {
            if !has_message(participant, group, expected).await {
                missing += 1;
            }
        }
        if missing == 0 {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "message missing at {missing} online participants"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "manual process-isolated 25/50/100/200-member app probe against local strfry"]
async fn app_group_through_strfry_processes() {
    let count = std::env::var("MDK_STRFRY_GROUP_MEMBERS")
        .unwrap()
        .parse::<usize>()
        .unwrap();
    assert!((25..=200).contains(&count));
    let relay = std::env::var("MDK_STRFRY_URL").unwrap();
    assert!(relay.starts_with("ws://127.0.0.1:"));
    let root = PathBuf::from(std::env::var("MDK_STRFRY_APP_ARTIFACTS").unwrap());
    assert!(!root.exists(), "use a fresh artifact directory");
    fs_private::create_dir_all_private(&root).unwrap();
    let started = Instant::now();

    let mut participants = Vec::with_capacity(count);
    for index in 0..count {
        participants.push(launch(root.join(format!("member-{index:03}")), &relay, true).await);
        if (index + 1) % 25 == 0 || index + 1 == count {
            milestone(&root, "identities", started.elapsed(), index + 1);
        }
    }

    let invitees = participants[1..]
        .iter()
        .map(|participant| participant.account.clone())
        .collect::<Vec<_>>();
    let group: GroupId = participants[0]
        .client
        .call_async(
            "create_group",
            json!([
                participants[0].account,
                "Strfry process scale",
                invitees,
                null
            ]),
        )
        .await
        .expect("create group");
    milestone(&root, "created", started.elapsed(), count);

    let group_hex = hex::encode(group.as_slice());
    for (index, participant) in participants.iter().enumerate().skip(1) {
        let deadline = Instant::now() + Duration::from_secs(90);
        loop {
            participant
                .client
                .call_async::<()>("catch_up_accounts", json!([]))
                .await
                .unwrap_or_else(|error| panic!("invite catch-up at index {index}: {error}"));
            let record: Option<AppGroupRecord> = participant
                .client
                .call_async("group", json!([participant.account, group_hex]))
                .await
                .expect("read pending invite");
            if record.is_some_and(|record| record.pending_confirmation) {
                participant
                    .client
                    .call_async::<()>(
                        "accept_group_invite_retrying_busy",
                        json!([participant.account, group]),
                    )
                    .await
                    .unwrap_or_else(|error| panic!("accept at index {index}: {error}"));
                break;
            }
            assert!(Instant::now() < deadline, "invite missing at index {index}");
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
    let founder_state: AppGroupMlsState = participants[0]
        .client
        .call_async("group_mls_state", json!([participants[0].account, group]))
        .await
        .expect("founder MLS state");
    for (index, participant) in participants.iter().enumerate() {
        let state: AppGroupMlsState = participant
            .client
            .call_async("group_mls_state", json!([participant.account, group]))
            .await
            .unwrap_or_else(|error| panic!("MLS state at index {index}: {error}"));
        assert_eq!(state.member_count, count, "member count at index {index}");
        assert_eq!(state.epoch, founder_state.epoch, "epoch at index {index}");
        assert_eq!(
            state.protocol_profile,
            marmot_app::AppProtocolProfile::Current
        );
        let roster: Vec<AppGroupMemberRecord> = participant
            .client
            .call_async("group_members", json!([participant.account, group]))
            .await
            .unwrap_or_else(|error| panic!("members at index {index}: {error}"));
        assert_eq!(
            roster
                .into_iter()
                .map(|member| member.member_id_hex)
                .collect::<BTreeSet<_>>(),
            expected_roster,
            "roster at index {index}"
        );
    }
    milestone(&root, "roster", started.elapsed(), count);

    let founder_message = "strfry-process-founder-message";
    let _: serde_json::Value = participants[0]
        .client
        .call_async(
            "send_message",
            json!([participants[0].account, group, founder_message.as_bytes()]),
        )
        .await
        .expect("founder send");
    wait_for_message(&participants, &group, founder_message).await;
    milestone(&root, "founder-fanout", started.elapsed(), count);

    let offline = [1, count / 2, count - 1];
    for index in offline {
        close(&participants[index]).await;
        participants[index].online = false;
    }
    milestone(&root, "offline", started.elapsed(), offline.len());
    let peer_message = "strfry-process-peer-message";
    let _: serde_json::Value = participants[count - 2]
        .client
        .call_async(
            "send_message",
            json!([
                participants[count - 2].account,
                group,
                peer_message.as_bytes()
            ]),
        )
        .await
        .expect("peer send");
    wait_for_message(&participants, &group, peer_message).await;
    milestone(&root, "peer-fanout", started.elapsed(), count);

    for index in offline {
        let previous_account = participants[index].account.clone();
        let replacement = launch(participants[index].root.clone(), &relay, false).await;
        assert_eq!(replacement.account, previous_account);
        participants[index] = replacement;
    }
    wait_for_message(&participants, &group, peer_message).await;
    milestone(&root, "offline-recovered", started.elapsed(), offline.len());

    for participant in &participants {
        close(participant).await;
    }
    milestone(&root, "complete", started.elapsed(), count);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "resume a retained 200-member app fixture after local strfry restarts"]
async fn resumed_group_after_strfry_restart() {
    let count = std::env::var("MDK_STRFRY_GROUP_MEMBERS")
        .unwrap()
        .parse::<usize>()
        .unwrap();
    let relay = std::env::var("MDK_STRFRY_URL").unwrap();
    assert!(relay.starts_with("ws://127.0.0.1:"));
    let root = PathBuf::from(std::env::var("MDK_STRFRY_APP_ARTIFACTS").unwrap());
    assert!(root.is_dir(), "retained app fixture missing");
    let started = Instant::now();

    let mut participants = Vec::with_capacity(count);
    for index in 0..count {
        let member_root = root.join(format!("member-{index:03}"));
        assert!(member_root.is_dir());
        participants.push(launch(member_root, &relay, false).await);
        if (index + 1) % 25 == 0 || index + 1 == count {
            let batch_start = (index / 25) * 25;
            catch_up_all(&participants[batch_start..]).await;
            milestone(&root, "resumed-identities", started.elapsed(), index + 1);
        }
    }
    let status: AppStatus = participants[0]
        .client
        .call_async("status", json!([participants[0].account]))
        .await
        .expect("founder status");
    assert_eq!(status.groups.len(), 1);
    let group = GroupId::new(hex::decode(&status.groups[0].group_id_hex).unwrap());

    let expected_roster = participants
        .iter()
        .map(|participant| participant.account.clone())
        .collect::<BTreeSet<_>>();
    let founder_state: AppGroupMlsState = participants[0]
        .client
        .call_async("group_mls_state", json!([participants[0].account, group]))
        .await
        .expect("founder MLS state");
    for (index, participant) in participants.iter().enumerate() {
        let state: AppGroupMlsState = participant
            .client
            .call_async("group_mls_state", json!([participant.account, group]))
            .await
            .unwrap_or_else(|error| panic!("resumed MLS state at index {index}: {error}"));
        assert_eq!(state.member_count, count, "member count at index {index}");
        assert_eq!(state.epoch, founder_state.epoch, "epoch at index {index}");
        let roster: Vec<AppGroupMemberRecord> = participant
            .client
            .call_async("group_members", json!([participant.account, group]))
            .await
            .unwrap_or_else(|error| panic!("resumed roster at index {index}: {error}"));
        assert_eq!(
            roster
                .into_iter()
                .map(|member| member.member_id_hex)
                .collect::<BTreeSet<_>>(),
            expected_roster,
            "roster at index {index}"
        );
        assert!(has_message(participant, &group, "strfry-process-founder-message").await);
        assert!(has_message(participant, &group, "strfry-process-peer-message").await);
    }
    milestone(&root, "resumed-roster", started.elapsed(), count);

    let after_restart = "strfry-process-after-relay-restart";
    let sender = count / 3;
    let _: serde_json::Value = participants[sender]
        .client
        .call_async(
            "send_message",
            json!([
                participants[sender].account,
                group,
                after_restart.as_bytes()
            ]),
        )
        .await
        .expect("send after relay restart");
    wait_for_message(&participants, &group, after_restart).await;
    milestone(&root, "resumed-fanout", started.elapsed(), count);

    for participant in &participants {
        close(participant).await;
    }
    milestone(&root, "resumed-complete", started.elapsed(), count);
}
