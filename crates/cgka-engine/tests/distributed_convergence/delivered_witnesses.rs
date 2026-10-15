//! Delivered applications in a convergence pass (mdk#2330).
//!
//! Every candidate a pass materializes forks at the pass's replay start, and
//! an application witnesses a candidate only from an epoch strictly after
//! that fork. A delivered (`Processed`) application at or below it is probed
//! on the shared base state of every candidate, so it can neither weigh on
//! branch selection nor be withdrawn by it. These tests pin that a pass
//! leaves such applications out, and that it takes them back in when a later
//! rival lowers the replay start.

use super::*;
use cgka_traits::convergence_pass::ConvergencePassMemberRole;
use cgka_traits::storage::OpenMlsContentFilter;

async fn ingest_processed(
    engine: &mut Engine<SqliteAccountStorage>,
    storage: &SqliteAccountStorage,
    msg: TransportMessage,
) {
    let outcome = engine.ingest(msg.clone()).await.unwrap();
    assert!(
        matches!(outcome, IngestOutcome::Processed),
        "delivered application must apply directly, got {outcome:?}"
    );
    assert_message_state(storage, &msg, MessageState::Processed);
}

fn pass_member_ids(storage: &SqliteAccountStorage, group_id: &GroupId) -> Vec<MessageId> {
    storage
        .convergence_pass(group_id)
        .unwrap()
        .expect("a convergence pass is open")
        .members
        .into_iter()
        .map(|member| member.message_id)
        .collect()
}

#[tokio::test]
async fn a_pass_leaves_out_delivered_applications_that_cannot_witness_a_branch() {
    let (mut alice, alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "delivered-witnesses".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    bob.join_welcome(welcome_for(&welcomes, b"bob"))
        .await
        .unwrap();

    let mut delivered = Vec::new();
    for index in 0..4 {
        let app = send_app(&mut bob, &group_id, format!("history {index}").into_bytes()).await;
        ingest_processed(&mut alice, &alice_storage, app.clone()).await;
        delivered.push(app);
    }
    alice.drain_events();

    let (commit, bob_pending) = evolution(
        bob.send(SendIntent::SelfUpdate {
            group_id: group_id.clone(),
        })
        .await
        .unwrap(),
    );
    bob.confirm_published(bob_pending).await.unwrap();
    let target_epoch = bob.epoch(&group_id).unwrap();
    alice
        .buffer_openmls_convergence_message_at(&group_id, route(commit.clone(), &group_id), 1_000)
        .unwrap();

    let pass = alice_storage
        .convergence_pass(&group_id)
        .unwrap()
        .expect("the commit opens a pass");
    assert!(
        pass.members
            .iter()
            .all(|member| member.role != ConvergencePassMemberRole::AppWitnessCandidate),
        "applications delivered at the fork epoch cannot witness a branch: {:?}",
        pass.members
    );
    assert!(
        pass.members
            .iter()
            .any(|member| member.message_id == content_id(&commit)),
        "the commit that opened the pass is a member"
    );

    let result = alice
        .converge_stored_openmls_messages_at(&group_id, 1_000_000)
        .unwrap();
    assert_eq!(result.accepted_commits, vec![content_hex(&commit)]);
    assert!(result.invalidated_app_messages.is_empty());
    assert_eq!(alice.epoch(&group_id).unwrap(), target_epoch);
    for app in &delivered {
        assert_message_state(&alice_storage, app, MessageState::Processed);
    }
}

/// Carol adopts branch L and delivers two senders' applications on it. A
/// commit at her tip opens a pass that has no use for those applications;
/// the rival W from L's fork epoch arrives while the pass is still collecting.
/// W carries a child commit, so it is one commit deeper than L, and only the
/// two delivered applications (a witness quorum, worth one commit of depth)
/// keep L canonical. Leaving them out after W lowered the replay start would
/// reorganize Carol onto W.
#[tokio::test]
async fn a_lower_epoch_rival_admitted_mid_pass_takes_back_the_delivered_witnesses() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let (mut carol, carol_storage) = build_client(b"carol");
    let (mut frank, _frank_storage) = build_client(b"frank");

    let members = vec![
        bob.fresh_key_package().await.unwrap(),
        carol.fresh_key_package().await.unwrap(),
        frank.fresh_key_package().await.unwrap(),
    ];
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "delivered-witness-top-up".into(),
            description: "".into(),
            members,
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    for (engine, name) in [
        (&mut bob, b"bob".as_slice()),
        (&mut carol, b"carol".as_slice()),
        (&mut frank, b"frank".as_slice()),
    ] {
        engine
            .join_welcome(welcome_for(&welcomes, name))
            .await
            .unwrap();
    }
    let fork_epoch = carol.epoch(&group_id).unwrap();

    // L is the same-epoch commit that loses the committer tie-break, so with
    // no witnesses W would win even at equal depth.
    let alice_wins = commit_tiebreak_winner_index(&alice.self_id(), &bob.self_id()) == 0;
    let (losing, winning) = if alice_wins {
        (&mut bob, &mut alice)
    } else {
        (&mut alice, &mut bob)
    };
    let (l_commit, l_pending) = evolution(
        losing
            .send(SendIntent::SelfUpdate {
                group_id: group_id.clone(),
            })
            .await
            .unwrap(),
    );
    let (w_commit, w_pending) = evolution(
        winning
            .send(SendIntent::SelfUpdate {
                group_id: group_id.clone(),
            })
            .await
            .unwrap(),
    );
    losing.confirm_published(l_pending).await.unwrap();
    winning.confirm_published(w_pending).await.unwrap();
    let (w_child, w_child_pending) = evolution(
        winning
            .send(SendIntent::SelfUpdate {
                group_id: group_id.clone(),
            })
            .await
            .unwrap(),
    );
    winning.confirm_published(w_child_pending).await.unwrap();

    frank
        .buffer_openmls_convergence_message_at(&group_id, route(l_commit.clone(), &group_id), 1_000)
        .unwrap();
    frank
        .converge_stored_openmls_messages_at(&group_id, 1_000_000)
        .unwrap();
    assert_eq!(frank.epoch(&group_id).unwrap().0, fork_epoch.0 + 1);
    let witnesses = [
        send_app(losing, &group_id, b"witness from the committer".to_vec()).await,
        send_app(&mut frank, &group_id, b"witness from frank".to_vec()).await,
    ];

    // Carol adopts L and delivers both applications.
    carol
        .buffer_openmls_convergence_message_at(&group_id, route(l_commit.clone(), &group_id), 1_000)
        .unwrap();
    for witness in &witnesses {
        carol
            .buffer_openmls_convergence_message_at(&group_id, witness.clone(), 1_000)
            .unwrap();
    }
    let adopted = carol
        .converge_stored_openmls_messages_at(&group_id, 1_000_000)
        .unwrap();
    assert_eq!(adopted.accepted_commits, vec![content_hex(&l_commit)]);
    for witness in &witnesses {
        assert_message_state(&carol_storage, witness, MessageState::Processed);
    }
    carol.drain_events();

    // W's child forks from Carol's tip, so the pass it opens replays from the
    // tip and the applications delivered there cannot witness anything yet.
    carol
        .buffer_openmls_convergence_message_at(
            &group_id,
            route(w_child.clone(), &group_id),
            2_000_000,
        )
        .unwrap();
    let opened = pass_member_ids(&carol_storage, &group_id);
    for witness in &witnesses {
        assert!(
            !opened.contains(&content_id(witness)),
            "a pass replaying from the tip leaves out applications delivered at the tip"
        );
    }

    // W forks below the tip, so the replay start drops to the fork epoch and
    // the delivered applications become witnesses of L.
    carol
        .buffer_openmls_convergence_message_at(
            &group_id,
            route(w_commit.clone(), &group_id),
            2_000_100,
        )
        .unwrap();
    let topped_up = pass_member_ids(&carol_storage, &group_id);
    for witness in &witnesses {
        assert!(
            topped_up.contains(&content_id(witness)),
            "a rival below the tip takes the delivered witnesses back into the pass"
        );
    }

    let result = carol
        .converge_stored_openmls_messages_at(&group_id, u64::MAX)
        .unwrap();
    assert_eq!(
        result.accepted_commits,
        vec![content_hex(&l_commit)],
        "L stays canonical on the strength of its delivered witnesses"
    );
    for rival in [&w_commit, &w_child] {
        assert!(result.deferred_messages.iter().any(|deferred| {
            deferred.message_id == content_hex(rival)
                && deferred.reason == DeferredMessageReason::NonSelectedEligibleBranch
        }));
    }
    assert!(result.invalidated_app_messages.is_empty());
    assert_eq!(carol.epoch(&group_id).unwrap().0, fork_epoch.0 + 1);
    for witness in &witnesses {
        assert_message_state(&carol_storage, witness, MessageState::Processed);
    }
    assert_message_state(&carol_storage, &w_commit, MessageState::ConvergenceDeferred);
    assert_message_state(&carol_storage, &w_child, MessageState::ConvergenceDeferred);
}

/// What the engine itself keeps of a row under `filter`: the same decode and
/// projection pass seeding, the send gate and the commit fingerprint apply.
/// A row it cannot classify is kept for the engine to judge.
fn engine_keeps(record: &MessageRecord, filter: OpenMlsContentFilter) -> bool {
    let Ok(payload) = StoredMessagePayload::decode(&record.payload) else {
        return true;
    };
    let Some(message) = payload.as_openmls_wire() else {
        return false;
    };
    let Ok(projection) = project_mls_message(&message.payload) else {
        return true;
    };
    let Some(epoch) = projection.source_epoch else {
        return true;
    };
    let delivered_application = record.state == MessageState::Processed
        && projection.kind == cgka_engine::openmls_projection::OpenMlsContentKind::Application;
    match filter {
        OpenMlsContentFilter::Commits => {
            projection.kind == cgka_engine::openmls_projection::OpenMlsContentKind::Commit
        }
        OpenMlsContentFilter::WithoutProcessedApplicationsThrough(through) => {
            !(delivered_application && epoch <= through.0)
        }
        OpenMlsContentFilter::WithoutProcessedApplications => !delivered_application,
        OpenMlsContentFilter::ApplicationsAt(at) => {
            projection.kind == cgka_engine::openmls_projection::OpenMlsContentKind::Application
                && epoch == at.0
        }
    }
}

/// SQLite derives its content columns from the stored payload; whatever it
/// leaves out must be exactly what the engine's own projection of the same
/// real OpenMLS messages leaves out.
#[tokio::test]
async fn sqlite_content_listing_matches_the_engines_projection() {
    let (mut alice, alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "content-listing-parity".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    bob.join_welcome(welcome_for(&welcomes, b"bob"))
        .await
        .unwrap();

    for index in 0..2 {
        let app = send_app(&mut bob, &group_id, format!("before {index}").into_bytes()).await;
        ingest_processed(&mut alice, &alice_storage, app).await;
    }
    send_app(&mut alice, &group_id, b"own".to_vec()).await;
    let (commit, bob_pending) = evolution(
        bob.send(SendIntent::SelfUpdate {
            group_id: group_id.clone(),
        })
        .await
        .unwrap(),
    );
    bob.confirm_published(bob_pending).await.unwrap();
    alice
        .buffer_openmls_convergence_message_at(&group_id, route(commit, &group_id), 1_000)
        .unwrap();
    alice
        .converge_stored_openmls_messages_at(&group_id, 1_000_000)
        .unwrap();
    let app = send_app(&mut bob, &group_id, b"after".to_vec()).await;
    ingest_processed(&mut alice, &alice_storage, app).await;
    let leave = route(
        proposal(
            bob.send(SendIntent::Leave {
                group_id: group_id.clone(),
            })
            .await
            .unwrap(),
        ),
        &group_id,
    );
    alice.ingest(leave).await.unwrap();

    const STATES: [MessageState; 5] = [
        MessageState::Sent,
        MessageState::Created,
        MessageState::Retryable,
        MessageState::ConvergenceDeferred,
        MessageState::Processed,
    ];
    let all = alice_storage
        .list_messages_in_states(&group_id, &STATES, EpochId(0))
        .unwrap();
    let kinds: std::collections::BTreeSet<_> = all
        .iter()
        .filter_map(|record| {
            let payload = StoredMessagePayload::decode(&record.payload).ok()?;
            let Some(message) = payload.as_openmls_wire() else {
                return Some("no wire message".to_owned());
            };
            let projection = project_mls_message(&message.payload).ok()?;
            Some(format!("{:?} {:?}", record.state, projection.kind))
        })
        .collect();
    for expected in [
        "no wire message",
        "Processed Commit",
        "Created Proposal",
        "Processed Application",
    ] {
        assert!(
            kinds.contains(expected),
            "{expected} missing from {kinds:?}"
        );
    }
    let tip = alice.epoch(&group_id).unwrap();
    for filter in [
        OpenMlsContentFilter::Commits,
        OpenMlsContentFilter::WithoutProcessedApplications,
        OpenMlsContentFilter::WithoutProcessedApplicationsThrough(EpochId(tip.0 - 1)),
        OpenMlsContentFilter::WithoutProcessedApplicationsThrough(tip),
        OpenMlsContentFilter::ApplicationsAt(EpochId(tip.0 - 1)),
        OpenMlsContentFilter::ApplicationsAt(tip),
    ] {
        let expected: Vec<_> = all
            .iter()
            .filter(|record| engine_keeps(record, filter))
            .map(|record| record.id.clone())
            .collect();
        let listed: Vec<_> = alice_storage
            .list_openmls_messages_in_states(&group_id, &STATES, EpochId(0), filter)
            .unwrap()
            .into_iter()
            .map(|record| record.id)
            .collect();
        assert_eq!(listed, expected, "{filter:?}");
    }
}

#[derive(Clone, Copy, Debug)]
enum PendingArrival {
    BeforeThePassOpens,
    WhileThePassCollects,
}

/// Replay steps each sender's receive ratchet in the anchor state, and a
/// pending application can sit more than the forward-distance limit
/// (`DEFAULT_MAXIMUM_FORWARD_DISTANCE`, 1,000 generations) ahead of the
/// anchor. A delivered application from the same epoch replayed before it
/// steps the ratchet close enough, so a pass must keep it even though it can
/// never witness a branch.
#[tokio::test]
async fn a_pass_keeps_delivered_applications_a_pending_one_needs_to_decrypt() {
    for arrival in [
        PendingArrival::BeforeThePassOpens,
        PendingArrival::WhileThePassCollects,
    ] {
        check_ratchet_dependency(arrival).await;
    }
}

async fn check_ratchet_dependency(arrival: PendingArrival) {
    let (mut alice, alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let (mut carol, _carol_storage) = build_client(b"carol");
    let members = vec![
        bob.fresh_key_package().await.unwrap(),
        carol.fresh_key_package().await.unwrap(),
    ];
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "ratchet-dependency".into(),
            description: "".into(),
            members,
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    bob.join_welcome(welcome_for(&welcomes, b"bob"))
        .await
        .unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();
    let fork_epoch = alice.epoch(&group_id).unwrap();

    // Bob's generations 0..1,200 at the fork epoch, none of which Alice has.
    let mut bob_apps = Vec::new();
    for generation in 0..1_200 {
        bob_apps.push(
            send_app(
                &mut bob,
                &group_id,
                format!("gen {generation}").into_bytes(),
            )
            .await,
        );
    }
    // A delivered generation `d` and a pending generation `p` beyond the
    // forward limit from the anchor but within it from `d`, with `d` sorting
    // first among the epoch's applications the way replay orders them.
    let (delivered, pending) = (1_100..1_200)
        .flat_map(|p| (p - 900..1_000).map(move |d| (d, p)))
        .find(|(d, p)| content_hex(&bob_apps[*d]) < content_hex(&bob_apps[*p]))
        .map(|(d, p)| (bob_apps[d].clone(), bob_apps[p].clone()))
        .expect("some pair sorts delivered-first");

    // Alice leaves the fork epoch on Carol's commit, so the retained anchor
    // holds Bob's receive ratchet at generation 0.
    let (carol_commit, carol_pending) = evolution(
        carol
            .send(SendIntent::SelfUpdate {
                group_id: group_id.clone(),
            })
            .await
            .unwrap(),
    );
    carol.confirm_published(carol_pending).await.unwrap();
    alice
        .buffer_openmls_convergence_message_at(&group_id, route(carol_commit, &group_id), 1_000)
        .unwrap();
    alice
        .converge_stored_openmls_messages_at(&group_id, 1_000_000)
        .unwrap();
    assert_eq!(alice.epoch(&group_id).unwrap().0, fork_epoch.0 + 1);
    // The late delivery steps only the live past-epoch ratchet, not the anchor.
    ingest_processed(&mut alice, &alice_storage, delivered.clone()).await;
    alice.drain_events();

    let (rival, _rival_pending) = evolution(
        bob.send(SendIntent::SelfUpdate {
            group_id: group_id.clone(),
        })
        .await
        .unwrap(),
    );
    let rival = route(rival, &group_id);
    match arrival {
        PendingArrival::BeforeThePassOpens => {
            alice
                .buffer_openmls_convergence_message_at(&group_id, pending.clone(), 2_000_000)
                .unwrap();
            alice
                .buffer_openmls_convergence_message_at(&group_id, rival, 2_000_100)
                .unwrap();
        }
        PendingArrival::WhileThePassCollects => {
            alice
                .buffer_openmls_convergence_message_at(&group_id, rival, 2_000_000)
                .unwrap();
            alice
                .buffer_openmls_convergence_message_at(&group_id, pending.clone(), 2_000_100)
                .unwrap();
        }
    }
    let members = pass_member_ids(&alice_storage, &group_id);
    assert!(
        members.contains(&content_id(&delivered)),
        "{arrival:?}: the pass keeps the delivered application the pending one needs"
    );

    let result = alice
        .converge_stored_openmls_messages_at(&group_id, u64::MAX)
        .unwrap();
    assert!(
        result
            .accepted_app_messages
            .contains(&content_hex(&pending)),
        "{arrival:?}: the pending application decrypts after the delivered one: {result:?}"
    );
    assert_message_state(&alice_storage, &pending, MessageState::Processed);
}
