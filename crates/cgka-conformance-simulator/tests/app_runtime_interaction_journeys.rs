//! Public-runtime interaction journeys: several groups, concurrent admins, a
//! member removed while offline, a voluntary leave with several remaining
//! auto-committers, and a manual self-update. Same production shape as
//! `app_runtime_journeys.rs`: real local Nostr relay, one SQLCipher database
//! per participant, public app commands and projections only.

use std::{collections::BTreeMap, error::Error, path::Path, time::Duration};

use cgka_conformance_simulator::{
    AppRuntimeHarness, AppRuntimeObservationV1, ConcurrentMutation, ConcurrentMutationReport,
    ConvergenceSubject, SubjectCreateGroup, SubjectError, SubjectFailureCategory,
    SubjectRemoveMembers, SubjectSelfUpdate, SubjectSendApplication,
};
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
const SETTLEMENT: Duration = Duration::from_secs(60);
/// A manual self-update publishes only after the protocol's quiet window and
/// sampled jitter (60 s plus up to 30 s on real clocks). This is the ceiling
/// for the production-timing run, which stays ignored in ordinary builds.
const MAINTENANCE_PUBLICATION_BUDGET: Duration = Duration::from_secs(150);
/// Built with `test-policy-overrides`, the journey's harness zeroes those
/// windows and the rotation lands within a few maintenance sweeps (about 15 s
/// locally, most of it public catch-up round trips). Production timing cannot
/// rotate before its 60 s quiet window has elapsed, so finishing inside this
/// budget is the proof that the override actually reached the runtime; a
/// build whose wiring silently fell back to production windows fails here.
const FAST_MAINTENANCE_PUBLICATION_BUDGET: Duration = Duration::from_secs(45);
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
    try_send(subject, group, sender, payload).await?;
    Ok(())
}

/// A send whose refusal the journey wants to classify rather than fail on.
async fn try_send(
    subject: &mut AppRuntimeHarness,
    group: &str,
    sender: &str,
    payload: &str,
) -> Result<(), SubjectError> {
    subject.select_scenario_group(group, false)?;
    subject
        .send_application(SubjectSendApplication {
            action_id: payload,
            sender,
            payload,
        })
        .await
}

/// The harness reports a group this device holds no projection of either as
/// an expected refusal from the public member read (`unknown_group` in the
/// classified message) or, when that read passes but the projection is
/// missing, as its own `unknown_group` code.
fn is_unknown_group(error: &SubjectError) -> bool {
    error.code == "unknown_group"
        || (error.category == SubjectFailureCategory::ExpectedRefusal
            && error.message.ends_with("unknown_group"))
}

/// An expected public refusal whose privacy-safe kind is `kind`.
fn refused_as(error: &SubjectError, kind: &str) -> bool {
    error.category == SubjectFailureCategory::ExpectedRefusal
        && error.message.ends_with(&format!(": {kind}"))
}

/// Tick a device that may legitimately hold no projection of the active group
/// yet: its Welcome is still in flight, or the invite never published one. The
/// harness reports that state through its public member read as
/// `unknown_group`, which is an expected outcome here, not a failure.
async fn tick_possible_non_member(subject: &mut AppRuntimeHarness, client: &str) -> TestResult {
    match subject.tick(&labels(&[client])).await {
        Ok(()) => Ok(()),
        Err(error) if is_unknown_group(&error) => Ok(()),
        Err(error) => Err(error.into()),
    }
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
        Err(error) if is_unknown_group(&error) => {}
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

/// Whether every settled observation carries the edit.
fn edit_applied(observations: &[AppRuntimeObservationV1], field: &str, value: &str) -> bool {
    !observations.is_empty()
        && observations.iter().all(|o| match field {
            "name" => o.protocol.group_name == value,
            _ => o.protocol.group_description == value,
        })
}

/// Which racing profile edits are present in the settled public state,
/// regardless of what the runtime told the caller.
fn settled_edits(
    observations: &[AppRuntimeObservationV1],
    edits: &[(&str, &str, &str)],
) -> Vec<String> {
    edits
        .iter()
        .filter(|(_, field, value)| edit_applied(observations, field, value))
        .map(|(client, field, _)| format!("{client}:{field}"))
        .collect()
}

/// Which racing profile edits the runtime reported as saved but the settled
/// public state does not contain. Convergence keeps one branch and parks the
/// other; the parked committer's intent is not re-issued today, so a losing
/// admin edit is dropped after its caller was told it succeeded (#1734). The
/// strict journeys fail on this; the default journeys record it as evidence.
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
        .filter(|(_, field, value)| !edit_applied(observations, field, value))
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
    let settled = settled_edits(&observations, &edits);
    let dropped = dropped_accepted_edits(&report, &observations, &edits);
    save(
        out,
        "after-race.json",
        &json!({
            "settled_edits": settled, "dropped_accepted_edits": dropped,
            "observations": observations,
        }),
    )?;
    // Presence is measured on the settled projection itself, so a command the
    // runtime rejected before publishing never counts as landed.
    if settled.is_empty() {
        return Err("neither concurrent profile edit reached the settled public state".into());
    }
    require_edits_retained(&dropped, strict)?;
    fresh_traffic_and_reopen(subject, "main", &mut expected, "carol", out, "main").await
}

/// One admin invites a fourth member while another admin renames the group at
/// the same instant. The founders must settle on one state with at least one
/// of the two edits present, and an invitee the founders admitted must send
/// and receive. When the founders exclude the invitee, the default form records
/// its device state (no projection, or a stranded parked-branch membership);
/// the strict form requires no projection and that an invite or rename
/// reported as saved is not lost (#1734, #1735).
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
    // Membership is decided by the founders' settled roster, not by the
    // inviter's success report. The invitee is progressed separately: until a
    // Welcome reaches it, or if the rejected invite never published one, its
    // device holds no group at all, which must not abort the journey.
    subject.tick(&founders).await?;
    tick_possible_non_member(subject, "david").await?;
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
        // The founders can commit the add before the Welcome lands on the
        // invitee's device; keep ticking it until it holds the group.
        let deadline = tokio::time::Instant::now() + SETTLEMENT;
        loop {
            tick_possible_non_member(subject, "david").await?;
            match subject.observations(&labels(&["david"])).await {
                Ok(_) => break,
                Err(error)
                    if is_unknown_group(&error) && tokio::time::Instant::now() < deadline =>
                {
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
                Err(error) => {
                    return Err(
                        format!("admitted invitee never received its Welcome: {error}").into(),
                    );
                }
            }
        }
    }
    let observations = subject
        .await_observable_settlement(&members, SETTLEMENT)
        .await?;
    let edits = [("bob", "name", "renamed during invite")];
    let mut settled = settled_edits(&observations, &edits);
    let mut dropped = dropped_accepted_edits(&report, &observations, &edits);
    if david_joined {
        settled.push("alice:invite".into());
    } else if invite_accepted {
        dropped.push("alice:invite".into());
    }
    // An invitee the founders exclude must hold no projection of the group. A
    // device that still reports membership joined a parked branch through a
    // stale Welcome: the stranded-invitee gap (#1735).
    let invitee_state = if david_joined {
        "member"
    } else {
        match subject.observations(&labels(&["david"])).await {
            Ok(view) => {
                save(out, "stranded-invitee.json", &view)?;
                "stranded"
            }
            Err(error) if is_unknown_group(&error) => "no_projection",
            Err(error) => {
                return Err(format!("unexpected invitee read failure: {error}").into());
            }
        }
    };
    save(
        out,
        "after-race.json",
        &json!({
            "settled_edits": settled, "dropped_accepted_edits": dropped,
            "invitee_state": invitee_state, "observations": observations,
        }),
    )?;
    if settled.is_empty() {
        return Err(
            "neither the concurrent invite nor the rename reached the settled state".into(),
        );
    }
    if strict && invitee_state == "stranded" {
        return Err(
            "invitee excluded by the founders still reports membership on a parked branch".into(),
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
    let refusal = try_send(subject, "main", "carol", "stale-from-carol").await;
    save(
        out,
        "carol-send-refusal.json",
        &json!({ "refused": refusal.is_err(), "error": refusal.as_ref().err().map(ToString::to_string) }),
    )?;
    match refusal {
        Ok(()) => return Err("removed member's send was accepted by its own runtime".into()),
        Err(error) if refused_as(&error, "group_removed") => {}
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
    let attempt = try_send(subject, "main", "david", "stale-from-david").await;
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
    // Each explicit sweep advances the obligation one phase (quiet, jitter,
    // publish) when the windows are zero, so poll quickly in that build and
    // slowly against production timing. The feature build's budget sits below
    // the production quiet window on purpose: it is what proves the zeroed
    // windows took effect rather than merely that a rotation eventually happened.
    let fast = AppRuntimeHarness::honors_maintenance_timing_override();
    let (sweep_interval, budget) = if fast {
        (
            Duration::from_millis(500),
            FAST_MAINTENANCE_PUBLICATION_BUDGET,
        )
    } else {
        (Duration::from_secs(2), MAINTENANCE_PUBLICATION_BUDGET)
    };
    let scheduled_at = tokio::time::Instant::now();
    let deadline = scheduled_at + budget;
    let mut sweeps = 0_u32;
    let observations = loop {
        subject.run_due_maintenance(&labels(&["bob"])).await?;
        sweeps += 1;
        subject.catch_up(&clients).await?;
        let observations = subject.observations(&clients).await?;
        let advanced = observations.iter().all(|o| o.protocol.epoch > epoch_before);
        if advanced && complete(&observations, &expected, clients.len()) {
            break observations;
        }
        if tokio::time::Instant::now() >= deadline {
            save(out, "self-update-stalled.json", &observations)?;
            return Err(if fast {
                format!(
                    "manual self-update did not rotate within {}s: the zeroed maintenance windows \
                     did not take effect, since production timing cannot rotate before its 60s quiet window",
                    budget.as_secs()
                )
                .into()
            } else {
                "manual self-update did not advance the shared public epoch in time".into()
            });
        }
        tokio::time::sleep(sweep_interval).await;
    };
    save(
        out,
        "after-self-update.json",
        &json!({
            "seconds_until_rotation": scheduled_at.elapsed().as_secs(),
            "maintenance_sweeps": sweeps,
            "immediate_maintenance_honored": AppRuntimeHarness::honors_maintenance_timing_override(),
            "observations": observations,
        }),
    )?;
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
            "settlement_policy": match journey {
                Journey::ManualSelfUpdate => "protocol-pinned 1000 ms settlement; maintenance windows zeroed when built with test-policy-overrides",
                _ => "protocol-pinned 1000 ms settlement; production maintenance windows",
            },
            "immediate_maintenance_honored": matches!(journey, Journey::ManualSelfUpdate)
                && AppRuntimeHarness::honors_maintenance_timing_override(),
        }),
    )
    .unwrap();
    let mut subject = match journey {
        // Production maintenance windows would hold this journey for 60 to 90
        // seconds; the harness zeroes them in test-policy builds only.
        Journey::ManualSelfUpdate => {
            AppRuntimeHarness::new_with_immediate_maintenance(&clients).await
        }
        // Workspace feature unification can enable marmot-app's instant
        // test settlement default through another crate. These journeys claim
        // production behavior, so pin that policy in every build.
        _ => AppRuntimeHarness::new_with_pinned_settlement(&clients).await,
    }
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
    // Same budget as the basic public journeys: the leave journey alone stacks
    // several sixty-second settlement deadlines around its three-minute wait.
    let result = match tokio::time::timeout(Duration::from_secs(900), exercise).await {
        Ok(result) => result,
        Err(_) => Err("public interaction journey exceeded its 900-second watchdog".into()),
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
// Strict since #1734: a losing profile edit is re-issued when the winning
// commit left its field untouched, so an edit the runtime reported as saved
// reaches the settled public state.
journey_test!(
    public_app_08_concurrent_admin_profile_edits_are_never_lost,
    Journey::ConcurrentProfileEdits { strict: true }
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

// The strict form additionally requires that an invite or rename the runtime
// reported as saved reaches the settled public state and that an excluded
// invitee holds no projection. A losing rename is re-issued since #1734; a
// losing invite still strands its invitee on a parked branch (#1735), so this
// documents a known product gap rather than gating CI; see
// APP_PATH_COVERAGE.md.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "known gap: a losing invite or rename is dropped after its caller was told it saved"]
async fn public_app_09_strict_concurrent_invite_and_rename_are_never_lost() {
    check(Journey::ConcurrentInviteAndRename { strict: true }).await;
}

// The worker now arms the engine's pending SelfRemove deadline, respecting
// collecting-pass and publication barriers. This ordinary 30-second regression
// requires survivors to apply a leave without an unrelated commit or timer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn public_app_12_strict_leave_is_applied_by_survivors_promptly() {
    check(Journey::LeaveWithSeveralRemaining { strict: true }).await;
}

// Built with `test-policy-overrides`, the harness zeroes the maintenance quiet
// window and jitter and this runs in seconds (`just simulator-fast-maintenance`).
// In an ordinary build it would wait out the real-time windows, so it stays
// ignored there and can still be run explicitly.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg_attr(
    not(feature = "test-policy-overrides"),
    ignore = "waits out the real-time maintenance quiet window and jitter; run explicitly or under test-policy-overrides"
)]
async fn public_app_11_manual_self_update_advances_every_member() {
    check(Journey::ManualSelfUpdate).await;
}
