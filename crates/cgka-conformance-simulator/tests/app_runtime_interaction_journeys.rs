//! Public-runtime interaction journeys: several groups, concurrent admins, a
//! member removed while offline, a voluntary leave with several remaining
//! auto-committers, and a manual self-update. Same production shape as
//! `app_runtime_journeys.rs`: real local Nostr relay, one SQLCipher database
//! per participant, public app commands and projections only.

use std::{collections::BTreeMap, error::Error, path::Path, time::Duration};

use cgka_conformance_simulator::{
    AppRuntimeHarness, AppRuntimeObservationV1, ConcurrentMutation, ConcurrentMutationReport,
    ConvergenceSubject, SubjectCreateGroup, SubjectFailureCategory, SubjectRemoveMembers,
    SubjectSelfUpdate, SubjectSendApplication,
};
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
const SETTLEMENT: Duration = Duration::from_secs(60);
/// A manual self-update publishes only after the protocol's real-time quiet
/// window and sampled jitter (60 s plus up to 30 s); the public runtime has no
/// virtual clock, so this budget is wall-clock by necessity.
const MAINTENANCE_PUBLICATION_BUDGET: Duration = Duration::from_secs(150);
/// How long the survivors of a voluntary leave may take to apply it. The
/// engine schedules the SelfRemove auto-commit within 50 ms of the proposal,
/// so the strict form allows a generous 30 s. The default form allows three
/// minutes because today the app worker only reaches that auto-commit when
/// some other commit or timer runs convergence for the group; see
/// APP_PATH_COVERAGE.md.
const STRICT_LEAVE_APPLICATION_BUDGET: Duration = Duration::from_secs(30);
const EVENTUAL_LEAVE_APPLICATION_BUDGET: Duration = Duration::from_secs(180);

type Timeline = BTreeMap<String, Vec<String>>;

#[derive(Clone, Copy, Debug)]
enum Journey {
    TwoGroups,
    ConcurrentProfileEdits { strict: bool },
    ConcurrentInviteAndRename { strict: bool },
    RemovedWhileOffline,
    LeaveWithSeveralRemaining { strict: bool },
    ManualSelfUpdate,
}

impl Journey {
    fn label(self) -> &'static str {
        match self {
            Self::TwoGroups => "two_groups",
            Self::LeaveWithSeveralRemaining { strict: false } => "leave_with_several_remaining",
            Self::LeaveWithSeveralRemaining { strict: true } => {
                "leave_with_several_remaining_strict"
            }
            Self::ConcurrentProfileEdits { strict: false } => "concurrent_profile_edits",
            Self::ConcurrentProfileEdits { strict: true } => "concurrent_profile_edits_strict",
            Self::ConcurrentInviteAndRename { strict: false } => "concurrent_invite_and_rename",
            Self::ConcurrentInviteAndRename { strict: true } => {
                "concurrent_invite_and_rename_strict"
            }
            Self::RemovedWhileOffline => "removed_while_offline",
            Self::ManualSelfUpdate => "manual_self_update",
        }
    }
}

fn save(out: &Path, name: &str, value: &impl serde::Serialize) -> TestResult {
    fs_private::write_private(&out.join(name), &serde_json::to_vec_pretty(value)?)?;
    Ok(())
}

fn multiset(payloads: &[String]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for payload in payloads {
        *counts.entry(payload.clone()).or_default() += 1;
    }
    counts
}

fn labels(clients: &[&str]) -> Vec<String> {
    clients.iter().map(|client| (*client).to_owned()).collect()
}

fn push_all(expected: &mut Timeline, payload: &str) {
    for payloads in expected.values_mut() {
        payloads.push(payload.to_owned());
    }
}

/// Every named participant exposes exactly the expected visible chat history,
/// the same public group commitment, the expected roster size, no pending
/// confirmation, and an encrypted on-disk database.
fn complete(observations: &[AppRuntimeObservationV1], expected: &Timeline, members: usize) -> bool {
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

async fn send(
    subject: &mut AppRuntimeHarness,
    group: &str,
    sender: &str,
    payload: &str,
) -> TestResult {
    subject.select_scenario_group(group, false)?;
    subject
        .send_application(SubjectSendApplication {
            action_id: payload,
            sender,
            payload,
        })
        .await?;
    Ok(())
}

/// Drive public catch-up until the named group's members all expose the
/// expected timeline and shared state, or fail with the last observations.
async fn expect_timeline(
    subject: &mut AppRuntimeHarness,
    group: &str,
    expected: &Timeline,
    out: &Path,
    checkpoint: &str,
) -> TestResult<Vec<AppRuntimeObservationV1>> {
    let clients = expected.keys().cloned().collect::<Vec<_>>();
    let deadline = tokio::time::Instant::now() + SETTLEMENT;
    loop {
        subject.select_scenario_group(group, false)?;
        subject.catch_up(&clients).await?;
        let observations = subject.observations(&clients).await?;
        if complete(&observations, expected, clients.len()) {
            save(out, checkpoint, &observations)?;
            return Ok(observations);
        }
        if tokio::time::Instant::now() >= deadline {
            save(out, checkpoint, &observations)?;
            return Err(
                format!("public payload/state mismatch at {checkpoint} in group {group}").into(),
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn create_group(
    subject: &mut AppRuntimeHarness,
    group: &str,
    invitees: &[String],
    admins: &[String],
) -> TestResult {
    subject.select_scenario_group(group, true)?;
    subject
        .create_group(SubjectCreateGroup {
            action_id: group,
            creator: "alice",
            name: &format!("{group} group"),
            invitees,
            required_features: &[],
            initial_admins: admins,
            pending: group,
        })
        .await?;
    let mut members = vec!["alice".to_owned()];
    members.extend(invitees.iter().cloned());
    subject.tick(&members).await?;
    subject
        .await_observable_settlement(&members, SETTLEMENT)
        .await?;
    Ok(())
}

/// Every remaining member both sends and receives in the current epoch, then
/// one recipient reopens and must still hold the complete history.
async fn fresh_traffic_and_reopen(
    subject: &mut AppRuntimeHarness,
    group: &str,
    expected: &mut Timeline,
    reopen: &str,
    out: &Path,
    prefix: &str,
) -> TestResult {
    let members = expected.keys().cloned().collect::<Vec<_>>();
    for member in &members {
        let payload = format!("{prefix}-fresh-from-{member}");
        send(subject, group, member, &payload).await?;
        push_all(expected, &payload);
    }
    expect_timeline(
        subject,
        group,
        expected,
        out,
        &format!("{prefix}-fresh.json"),
    )
    .await?;
    subject.reopen(reopen).await?;
    expect_timeline(
        subject,
        group,
        expected,
        out,
        &format!("{prefix}-after-reopen.json"),
    )
    .await?;
    Ok(())
}

/// Alice runs a three-member work group and a two-member pair group with the
/// same device. Traffic, a removal in one group, and a reopen must never leak
/// history or membership across groups. Inviting Bob into the second group
/// also exercises fetching a fresh KeyPackage after the first one was used.
async fn two_groups(subject: &mut AppRuntimeHarness, out: &Path) -> TestResult {
    create_group(
        subject,
        "work",
        &labels(&["bob", "carol"]),
        &labels(&["alice"]),
    )
    .await?;
    create_group(subject, "pair", &labels(&["bob"]), &labels(&["alice"])).await?;

    let mut work = labels(&["alice", "bob", "carol"])
        .into_iter()
        .map(|client| (client, Vec::new()))
        .collect::<Timeline>();
    let mut pair = labels(&["alice", "bob"])
        .into_iter()
        .map(|client| (client, Vec::new()))
        .collect::<Timeline>();
    send(subject, "work", "alice", "work-1").await?;
    push_all(&mut work, "work-1");
    send(subject, "pair", "bob", "pair-1").await?;
    push_all(&mut pair, "pair-1");
    send(subject, "work", "carol", "work-2").await?;
    push_all(&mut work, "work-2");
    expect_timeline(subject, "work", &work, out, "work-initial.json").await?;
    expect_timeline(subject, "pair", &pair, out, "pair-initial.json").await?;

    // Carol was never invited to the pair group: after catching up on
    // everything the relay holds for her, her device must have no projection
    // of it at all, not an empty one.
    subject.select_scenario_group("work", false)?;
    subject.catch_up(&labels(&["carol"])).await?;
    subject.select_scenario_group("pair", false)?;
    match subject.observations(&labels(&["carol"])).await {
        Ok(observation) => {
            save(out, "carol-pair-leak.json", &observation)?;
            return Err("non-member carol holds a projection of the pair group".into());
        }
        Err(error)
            if error.category == SubjectFailureCategory::ExpectedRefusal
                && error.message.contains("unknown_group") => {}
        Err(error) => {
            return Err(format!("unexpected pair-group read failure for carol: {error}").into());
        }
    }

    subject.select_scenario_group("work", false)?;
    subject
        .remove_members(SubjectRemoveMembers {
            action_id: "remove-carol",
            remover: "alice",
            members: &labels(&["carol"]),
            pending: "remove-carol",
        })
        .await?;
    subject.tick(&labels(&["alice", "bob", "carol"])).await?;
    subject
        .await_observable_settlement(&labels(&["alice", "bob"]), SETTLEMENT)
        .await?;
    let carol_history = work.remove("carol").expect("carol was a work member");

    send(subject, "work", "alice", "work-after-remove").await?;
    push_all(&mut work, "work-after-remove");
    send(subject, "pair", "bob", "pair-after-remove").await?;
    push_all(&mut pair, "pair-after-remove");
    expect_timeline(subject, "work", &work, out, "work-after-remove.json").await?;
    expect_timeline(subject, "pair", &pair, out, "pair-after-remove.json").await?;

    subject.select_scenario_group("work", false)?;
    subject.catch_up(&labels(&["carol"])).await?;
    let carol = subject.observations(&labels(&["carol"])).await?;
    save(out, "carol-after-remove.json", &carol)?;
    if multiset(&carol[0].application.visible_plaintexts) != multiset(&carol_history) {
        return Err("removed member's work history changed after removal".into());
    }

    fresh_traffic_and_reopen(subject, "work", &mut work, "bob", out, "work").await?;
    // Bob's reopen must also have preserved the other group completely.
    expect_timeline(subject, "pair", &pair, out, "pair-after-reopen.json").await?;
    fresh_traffic_and_reopen(subject, "pair", &mut pair, "alice", out, "pair").await?;
    expect_timeline(subject, "work", &work, out, "work-terminal.json")
        .await
        .map(|_| ())
}

/// Which racing profile edits the runtime reported as saved but the settled
/// public state does not contain. Convergence keeps one branch and parks the
/// other; the parked committer's intent is not re-issued today, so a losing
/// admin edit is dropped after its caller was told it succeeded. The strict
/// journeys fail on this; the default journeys record it as evidence.
fn dropped_accepted_edits(
    report: &ConcurrentMutationReport,
    observations: &[AppRuntimeObservationV1],
    edits: &[(&str, &str, &str)],
) -> Vec<String> {
    edits
        .iter()
        .filter(|(client, _, _)| {
            report
                .outcomes
                .iter()
                .any(|outcome| outcome.client == *client && outcome.accepted)
        })
        .filter(|(_, field, value)| {
            !observations.iter().all(|o| match *field {
                "name" => o.protocol.group_name == *value,
                _ => o.protocol.group_description == *value,
            })
        })
        .map(|(client, field, _)| format!("{client}:{field}"))
        .collect()
}

fn require_edits_retained(dropped: &[String], strict: bool) -> TestResult {
    if strict && !dropped.is_empty() {
        return Err(format!(
            "edits reported as saved are missing from the settled public state: {dropped:?}"
        )
        .into());
    }
    Ok(())
}

/// Two admins save different profile fields at the same instant. Whatever the
/// commit race decides, every member must settle on one state that contains at
/// least one of the edits, and messaging plus reopen persistence must hold.
/// The strict form also requires that no edit reported as saved is lost.
async fn concurrent_profile_edits(
    subject: &mut AppRuntimeHarness,
    out: &Path,
    strict: bool,
) -> TestResult {
    let clients = labels(&["alice", "bob", "carol"]);
    create_group(
        subject,
        "main",
        &labels(&["bob", "carol"]),
        &labels(&["alice", "bob"]),
    )
    .await?;
    let mut expected = clients
        .iter()
        .map(|client| (client.clone(), vec!["before".to_owned()]))
        .collect::<Timeline>();
    send(subject, "main", "alice", "before").await?;
    expect_timeline(subject, "main", &expected, out, "before.json").await?;

    let report = subject
        .race_mutations(
            "race-profile",
            &[
                ConcurrentMutation::UpdateGroupProfile {
                    client: "alice",
                    name: Some("alice renamed it"),
                    description: None,
                },
                ConcurrentMutation::UpdateGroupProfile {
                    client: "bob",
                    name: None,
                    description: Some("bob described it"),
                },
            ],
        )
        .await?;
    save(out, "race-report.json", &report)?;
    subject.tick(&clients).await?;
    let observations = subject
        .await_observable_settlement(&clients, SETTLEMENT)
        .await?;
    let edits = [
        ("alice", "name", "alice renamed it"),
        ("bob", "description", "bob described it"),
    ];
    let dropped = dropped_accepted_edits(&report, &observations, &edits);
    save(
        out,
        "after-race.json",
        &json!({ "dropped_accepted_edits": dropped, "observations": observations }),
    )?;
    let landed = edits.len() - dropped.len();
    if landed == 0 {
        return Err("neither concurrent profile edit reached the settled public state".into());
    }
    require_edits_retained(&dropped, strict)?;
    fresh_traffic_and_reopen(subject, "main", &mut expected, "carol", out, "main").await
}

/// One admin invites a fourth member while another admin renames the group at
/// the same instant. The founders must settle on one state, the invitee must
/// either become a full member who sends and receives or hold no membership
/// at all, and at least one of the two edits must have landed. The strict form
/// also requires that an invite or rename reported as saved is not lost.
async fn concurrent_invite_and_rename(
    subject: &mut AppRuntimeHarness,
    out: &Path,
    strict: bool,
) -> TestResult {
    let founders = labels(&["alice", "bob", "carol"]);
    create_group(
        subject,
        "main",
        &labels(&["bob", "carol"]),
        &labels(&["alice", "bob"]),
    )
    .await?;
    let mut expected = founders
        .iter()
        .map(|client| (client.clone(), vec!["before".to_owned()]))
        .collect::<Timeline>();
    send(subject, "main", "alice", "before").await?;
    expect_timeline(subject, "main", &expected, out, "before.json").await?;

    let report = subject
        .race_mutations(
            "race-invite-rename",
            &[
                ConcurrentMutation::InviteMembers {
                    inviter: "alice",
                    invitees: &labels(&["david"]),
                },
                ConcurrentMutation::UpdateGroupProfile {
                    client: "bob",
                    name: Some("renamed during invite"),
                    description: None,
                },
            ],
        )
        .await?;
    save(out, "race-report.json", &report)?;
    let invite_accepted = report
        .outcomes
        .iter()
        .any(|outcome| outcome.client == "alice" && outcome.accepted);
    // Ticks accept the pending Welcome on the invitee's device once it arrives.
    // Membership is decided by the founders' settled roster, not by the
    // inviter's success report.
    subject
        .tick(&labels(&["alice", "bob", "carol", "david"]))
        .await?;
    let founders_state = subject
        .await_observable_settlement(&founders, SETTLEMENT)
        .await?;
    let david_joined = founders_state[0]
        .protocol
        .member_identities
        .iter()
        .any(|member| member == "david");
    let mut members = founders.clone();
    if david_joined {
        members.push("david".to_owned());
        // A late joiner is entitled to messages sent after admission only.
        expected.insert("david".into(), Vec::new());
    }
    let observations = subject
        .await_observable_settlement(&members, SETTLEMENT)
        .await?;
    let mut dropped = dropped_accepted_edits(
        &report,
        &observations,
        &[("bob", "name", "renamed during invite")],
    );
    if invite_accepted && !david_joined {
        dropped.push("alice:invite".into());
    }
    let david_stranded = subject.observations(&labels(&["david"])).await.ok();
    save(
        out,
        "after-race.json",
        &json!({
            "dropped_accepted_edits": dropped, "david_joined": david_joined,
            "observations": observations,
            "david_when_not_a_member": if david_joined { None } else { david_stranded },
        }),
    )?;
    if dropped.len() == 2 {
        return Err(
            "neither the concurrent invite nor the rename reached the settled state".into(),
        );
    }
    require_edits_retained(&dropped, strict)?;
    let reopen = if david_joined { "david" } else { "carol" };
    fresh_traffic_and_reopen(subject, "main", &mut expected, reopen, out, "main").await
}

/// Carol's device is closed when the admin removes her. When it comes back it
/// must learn the removal from relay history alone: no post-removal plaintext
/// may ever appear on it, its own sends must be refused, and the remaining
/// members' timelines must stay exact.
async fn removed_while_offline(subject: &mut AppRuntimeHarness, out: &Path) -> TestResult {
    let clients = labels(&["alice", "bob", "carol"]);
    create_group(
        subject,
        "main",
        &labels(&["bob", "carol"]),
        &labels(&["alice"]),
    )
    .await?;
    let mut expected = clients
        .iter()
        .map(|client| (client.clone(), vec!["before".to_owned()]))
        .collect::<Timeline>();
    send(subject, "main", "alice", "before").await?;
    expect_timeline(subject, "main", &expected, out, "before.json").await?;

    subject.set_online("carol", false).await?;
    subject
        .remove_members(SubjectRemoveMembers {
            action_id: "remove-carol",
            remover: "alice",
            members: &labels(&["carol"]),
            pending: "remove-carol",
        })
        .await?;
    let remaining = labels(&["alice", "bob"]);
    subject.tick(&remaining).await?;
    subject
        .await_observable_settlement(&remaining, SETTLEMENT)
        .await?;
    let carol_history = expected.remove("carol").expect("carol was a member");
    send(subject, "main", "alice", "after-removal-1").await?;
    push_all(&mut expected, "after-removal-1");
    send(subject, "main", "bob", "after-removal-2").await?;
    push_all(&mut expected, "after-removal-2");
    expect_timeline(subject, "main", &expected, out, "after-removal.json").await?;

    // Carol reconnects and repairs from the retained relay history.
    subject.set_online("carol", true).await?;
    let deadline = tokio::time::Instant::now() + SETTLEMENT;
    let carol = loop {
        subject.repair_full_history(&labels(&["carol"])).await?;
        subject.catch_up(&labels(&["carol"])).await?;
        let carol = subject.observations(&labels(&["carol"])).await?.remove(0);
        if carol
            .application
            .visible_plaintexts
            .iter()
            .any(|payload| payload.starts_with("after-removal"))
        {
            save(out, "carol-leak.json", &carol)?;
            return Err("member removed while offline decrypted post-removal traffic".into());
        }
        // Public evidence that the device processed its own removal: it no
        // longer counts itself among the group's members.
        let knows_removed = !carol
            .protocol
            .member_identities
            .iter()
            .any(|m| m == "carol")
            && carol.protocol.member_count == remaining.len();
        if knows_removed {
            break carol;
        }
        if tokio::time::Instant::now() >= deadline {
            save(out, "carol-stale.json", &carol)?;
            return Err("reconnected member never learned it had been removed".into());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    };
    save(out, "carol-after-reconnect.json", &carol)?;
    if multiset(&carol.application.visible_plaintexts) != multiset(&carol_history) {
        return Err("removed member's pre-removal history changed".into());
    }

    // A removed device must be refused when it tries to send, and nothing it
    // attempts may reach the remaining members.
    let refusal = send(subject, "main", "carol", "stale-from-carol").await;
    save(
        out,
        "carol-send-refusal.json",
        &json!({ "refused": refusal.is_err(), "error": refusal.as_ref().err().map(ToString::to_string) }),
    )?;
    match refusal {
        Ok(()) => return Err("removed member's send was accepted by its own runtime".into()),
        Err(error) if error.to_string().contains("group_removed") => {}
        Err(error) => {
            return Err(
                format!("removed member's send failed for the wrong reason: {error}").into(),
            );
        }
    }
    fresh_traffic_and_reopen(subject, "main", &mut expected, "bob", out, "main").await?;
    subject.reopen("carol").await?;
    subject.catch_up(&labels(&["carol"])).await?;
    let carol = subject.observations(&labels(&["carol"])).await?.remove(0);
    save(out, "carol-after-reopen.json", &carol)?;
    if multiset(&carol.application.visible_plaintexts) != multiset(&carol_history) {
        return Err("removed member's history changed after reopen".into());
    }
    Ok(())
}

/// David leaves a four-member group. Every remaining device is entitled to
/// auto-commit the same `Leave` proposal by reference, so rival commits can
/// race for one epoch on a real-world departure. The survivors must settle on
/// one state and keep exchanging decryptable traffic in both directions, and
/// the leaver's device must keep exactly its pre-departure history. The strict
/// form also requires the survivors to apply the leave promptly.
async fn leave_with_several_remaining(
    subject: &mut AppRuntimeHarness,
    out: &Path,
    strict: bool,
) -> TestResult {
    let clients = labels(&["alice", "bob", "carol", "david"]);
    create_group(
        subject,
        "main",
        &labels(&["bob", "carol", "david"]),
        &labels(&["alice"]),
    )
    .await?;
    let mut expected = clients
        .iter()
        .map(|client| (client.clone(), vec!["before".to_owned()]))
        .collect::<Timeline>();
    send(subject, "main", "alice", "before").await?;
    send(subject, "main", "david", "before-from-david").await?;
    push_all(&mut expected, "before-from-david");
    expect_timeline(subject, "main", &expected, out, "before.json").await?;

    subject.select_scenario_group("main", false)?;
    let admitted_before_leave = subject.relay_admitted_events().await;
    subject.leave("leave-david", "david").await?;
    let admitted_after_leave = subject.relay_admitted_events().await;
    let remaining = labels(&["alice", "bob", "carol"]);
    // The survivors' runtimes learn the proposal from their live subscriptions;
    // the engine schedules the auto-commit within 50 ms. Poll slowly so the
    // harness itself is not what keeps the worker busy.
    let budget = if strict {
        STRICT_LEAVE_APPLICATION_BUDGET
    } else {
        EVENTUAL_LEAVE_APPLICATION_BUDGET
    };
    let left_at = tokio::time::Instant::now();
    let deadline = left_at + budget;
    let mut rounds = 0_u32;
    let settled = loop {
        tokio::time::sleep(Duration::from_secs(2)).await;
        subject.tick(&remaining).await?;
        let observations = subject.observations(&remaining).await?;
        let leaver = subject.observations(&labels(&["david"])).await.ok();
        save(
            out,
            &format!("after-leave-round-{rounds:02}.json"),
            &json!({
                "seconds_since_leave": left_at.elapsed().as_secs(),
                "admitted_before_leave": admitted_before_leave,
                "admitted_after_leave": admitted_after_leave,
                "admitted_now": subject.relay_admitted_events().await,
                "survivors": observations,
                "leaver": leaver,
            }),
        )?;
        if observations
            .iter()
            .all(|o| o.protocol.member_count == remaining.len())
        {
            eprintln!(
                "survivors applied the leave after {}s",
                left_at.elapsed().as_secs()
            );
            break subject
                .await_observable_settlement(&remaining, SETTLEMENT)
                .await?;
        }
        rounds += 1;
        if tokio::time::Instant::now() >= deadline {
            return Err(format!(
                "survivors had not applied the leave {}s after it was published",
                left_at.elapsed().as_secs()
            )
            .into());
        }
    };
    save(out, "after-leave.json", &settled)?;
    let david_history = expected.remove("david").expect("david was a member");

    // Decryptable traffic in every direction is the real convergence check:
    // public epoch numbers can agree while devices sit on different branches.
    fresh_traffic_and_reopen(subject, "main", &mut expected, "bob", out, "main").await?;

    // The leaver's device keeps its pre-departure history and nothing it
    // attempts afterwards may reach the survivors. Whether its own runtime
    // refuses the send is recorded, not asserted: a voluntary leave is a
    // different terminal state from an administrative removal.
    let attempt = send(subject, "main", "david", "stale-from-david").await;
    subject.catch_up(&labels(&["david"])).await?;
    let david = subject.observations(&labels(&["david"])).await?.remove(0);
    save(
        out,
        "leaver.json",
        &json!({
            "send_refused": attempt.is_err(),
            "send_error": attempt.as_ref().err().map(ToString::to_string),
            "observation": david,
        }),
    )?;
    if multiset(&david.application.visible_plaintexts) != multiset(&david_history) {
        return Err("leaver's history changed after leaving".into());
    }
    expect_timeline(
        subject,
        "main",
        &expected,
        out,
        "survivors-after-stale-send.json",
    )
    .await?;
    Ok(())
}

/// Bob asks for a manual self-update, the same operation periodic maintenance
/// performs in production. The public epoch must advance for every member
/// without any message loss, and messaging must continue afterwards.
async fn manual_self_update(subject: &mut AppRuntimeHarness, out: &Path) -> TestResult {
    let clients = labels(&["alice", "bob"]);
    create_group(subject, "main", &labels(&["bob"]), &labels(&["alice"])).await?;
    let mut expected = clients
        .iter()
        .map(|client| (client.clone(), vec!["before".to_owned()]))
        .collect::<Timeline>();
    send(subject, "main", "alice", "before").await?;
    let before = expect_timeline(subject, "main", &expected, out, "before.json").await?;
    let epoch_before = before[0].protocol.epoch;

    subject
        .self_update(SubjectSelfUpdate {
            action_id: "bob-self-update",
            client: "bob",
            pending: "bob-self-update",
        })
        .await?;
    let deadline = tokio::time::Instant::now() + MAINTENANCE_PUBLICATION_BUDGET;
    let observations = loop {
        subject.run_due_maintenance(&labels(&["bob"])).await?;
        subject.catch_up(&clients).await?;
        let observations = subject.observations(&clients).await?;
        let advanced = observations.iter().all(|o| o.protocol.epoch > epoch_before);
        if advanced && complete(&observations, &expected, clients.len()) {
            break observations;
        }
        if tokio::time::Instant::now() >= deadline {
            save(out, "self-update-stalled.json", &observations)?;
            return Err(
                "manual self-update did not advance the shared public epoch in time".into(),
            );
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    };
    save(out, "after-self-update.json", &observations)?;
    fresh_traffic_and_reopen(subject, "main", &mut expected, "bob", out, "main").await
}

async fn check(journey: Journey) {
    let label = journey.label();
    let mut builder = tempfile::Builder::new();
    let prefix = format!("app-interaction-{label}-");
    builder.prefix(&prefix);
    let artifacts = if let Some(root) = std::env::var_os("MDK_APP_JOURNEY_ARTIFACTS") {
        fs_private::create_dir_all_private(Path::new(&root)).unwrap();
        builder.tempdir_in(root).unwrap()
    } else {
        builder.tempdir().unwrap()
    };
    fs_private::create_dir_all_private(artifacts.path()).unwrap();
    let clients = match journey {
        Journey::ConcurrentInviteAndRename { .. } | Journey::LeaveWithSeveralRemaining { .. } => {
            labels(&["alice", "bob", "carol", "david"])
        }
        Journey::ManualSelfUpdate => labels(&["alice", "bob"]),
        _ => labels(&["alice", "bob", "carol"]),
    };
    save(
        artifacts.path(),
        "input.json",
        &json!({
            "journey": label, "version": 1, "clients": clients,
            "adapter": "marmot_app_runtime", "storage": "sqlcipher_per_participant",
            "relay_order": "native local Nostr relay", "debug_assertions": cfg!(debug_assertions),
            "settlement_policy": "default production policy; no test override requested",
        }),
    )
    .unwrap();
    let mut subject = AppRuntimeHarness::new(&clients)
        .await
        .expect("public runtime setup");
    let exercise = async {
        match journey {
            Journey::TwoGroups => two_groups(&mut subject, artifacts.path()).await,
            Journey::ConcurrentProfileEdits { strict } => {
                concurrent_profile_edits(&mut subject, artifacts.path(), strict).await
            }
            Journey::ConcurrentInviteAndRename { strict } => {
                concurrent_invite_and_rename(&mut subject, artifacts.path(), strict).await
            }
            Journey::RemovedWhileOffline => {
                removed_while_offline(&mut subject, artifacts.path()).await
            }
            Journey::LeaveWithSeveralRemaining { strict } => {
                leave_with_several_remaining(&mut subject, artifacts.path(), strict).await
            }
            Journey::ManualSelfUpdate => manual_self_update(&mut subject, artifacts.path()).await,
        }
    };
    let result = match tokio::time::timeout(Duration::from_secs(600), exercise).await {
        Ok(result) => result,
        Err(_) => Err("public interaction journey exceeded its 600-second watchdog".into()),
    };
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

macro_rules! journey_test {
    ($name:ident, $journey:expr) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn $name() {
            check($journey).await;
        }
    };
}

journey_test!(public_app_07_two_groups_stay_isolated, Journey::TwoGroups);
journey_test!(
    public_app_08_concurrent_admin_profile_edits_converge,
    Journey::ConcurrentProfileEdits { strict: false }
);
journey_test!(
    public_app_09_concurrent_invite_and_rename_converge,
    Journey::ConcurrentInviteAndRename { strict: false }
);
journey_test!(
    public_app_10_member_removed_while_offline_learns_removal,
    Journey::RemovedWhileOffline
);
journey_test!(
    public_app_12_leave_with_several_remaining_members_converges,
    Journey::LeaveWithSeveralRemaining { strict: false }
);

// The strict forms additionally require that an edit the runtime reported as
// saved reaches the settled public state. Convergence currently parks the
// losing committer's intent without re-issuing it, so they document a known
// product gap rather than gating CI; see APP_PATH_COVERAGE.md.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "known gap: a losing admin edit is dropped after its caller was told it saved"]
async fn public_app_08_strict_concurrent_admin_profile_edits_are_never_lost() {
    check(Journey::ConcurrentProfileEdits { strict: true }).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "known gap: a losing invite or rename is dropped after its caller was told it saved"]
async fn public_app_09_strict_concurrent_invite_and_rename_are_never_lost() {
    check(Journey::ConcurrentInviteAndRename { strict: true }).await;
}

// The engine schedules a peer's SelfRemove auto-commit within 50 ms, but the
// app worker's convergence schedule has no arm for it, so survivors apply a
// leave only when some other commit or timer runs convergence for the group.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "known gap: survivors apply a voluntary leave only when another commit runs convergence"]
async fn public_app_12_strict_leave_is_applied_by_survivors_promptly() {
    check(Journey::LeaveWithSeveralRemaining { strict: true }).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "waits out the real-time maintenance quiet window and jitter; run explicitly"]
async fn public_app_11_manual_self_update_advances_every_member() {
    check(Journey::ManualSelfUpdate).await;
}
