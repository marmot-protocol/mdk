//! An own-commit checkpoint must not attach to a sibling of the parent it was
//! built on (mdk#2657).
//!
//! X's own commit A loses to the rival's B and is parked. X then commits C on
//! top of B. Replaying the parked A restores A's checkpoint at C's source
//! epoch, so C's checkpoint used to restore after A as well: a phantom branch
//! `[A, C, ...]` that ties with the real `[B, C, ...]` on every selection rule
//! because both end in the same tip commit.

use super::*;

/// Selection breaks a full score tie toward the larger branch id. Mirror the
/// engine's content-derived id so the fixture can choose which branch wins.
fn branch_id(path: &[&TransportMessage]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"marmot-openmls-candidate-path/v1");
    for commit in path {
        hasher.update(project_mls_message(&commit.payload).unwrap().message_digest);
    }
    format!("path:{}", hex::encode(&hasher.finalize()[..16]))
}

/// One confirmed rival self-update whose bytes make `wins` hold.
async fn rival_update_where(
    rival: &mut Engine<SqliteAccountStorage>,
    group_id: &GroupId,
    wins: impl Fn(&TransportMessage) -> bool,
) -> TransportMessage {
    for _ in 0..64 {
        let (commit, pending) = evolution(
            rival
                .send(SendIntent::SelfUpdate {
                    group_id: group_id.clone(),
                })
                .await
                .unwrap(),
        );
        let commit = route(commit, group_id);
        if wins(&commit) {
            rival.confirm_published(pending).await.unwrap();
            return commit;
        }
        rival.publish_failed(pending).await.unwrap();
    }
    panic!("a branch-id order holds with probability 1/2 per commit");
}

async fn own_update(
    engine: &mut Engine<SqliteAccountStorage>,
    group_id: &GroupId,
) -> TransportMessage {
    let (commit, pending) = evolution(
        engine
            .send(SendIntent::SelfUpdate {
                group_id: group_id.clone(),
            })
            .await
            .unwrap(),
    );
    engine.confirm_published(pending).await.unwrap();
    route(commit, group_id)
}

async fn settle(engine: &mut Engine<SqliteAccountStorage>, group_id: &GroupId) {
    let result = engine
        .converge_stored_openmls_messages_at(group_id, u64::MAX)
        .unwrap();
    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
}

struct PhantomTie {
    x: Engine<SqliteAccountStorage>,
    x_storage: SqliteAccountStorage,
    rival: Engine<SqliteAccountStorage>,
    group_id: GroupId,
    a: TransportMessage,
    remote: [TransportMessage; 3],
}

/// X at epoch 5 holding the rival's G at 5, with the parked own A and the
/// chain B, C (own), D, F (own), G. The phantom `[A, C, D, F, G]` sorts after
/// the real `[B, C, D, F, G]`, so it wins the tie wherever both exist.
/// `passive_members` only widen the tree.
async fn phantom_tie(passive_members: usize) -> PhantomTie {
    // Equal-depth renames order by committer identity: the rival's must sort
    // first so its B displaces X's A.
    let (rival_name, x_name): (&[u8], &[u8]) = if committer_wins(
        &MemberId::new(pad32(b"phantom-1")),
        &MemberId::new(pad32(b"phantom-2")),
    ) {
        (b"phantom-1", b"phantom-2")
    } else {
        (b"phantom-2", b"phantom-1")
    };
    let (mut x, x_storage) = build_client(x_name);
    let (mut rival, _) = build_client(rival_name);
    let mut members = vec![rival.fresh_key_package().await.unwrap()];
    for index in 0..passive_members {
        let (mut passive, _) = build_client(format!("phantom-passive-{index}").as_bytes());
        members.push(passive.fresh_key_package().await.unwrap());
    }
    let (group_id, create) = x
        .create_group(CreateGroupRequest {
            name: "phantom own commit".into(),
            description: String::new(),
            members,
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![rival.self_id()],
        })
        .await
        .unwrap();
    let SendResult::GroupCreated { pending, welcomes } = create else {
        panic!("expected GroupCreated");
    };
    x.confirm_published(pending).await.unwrap();
    rival
        .join_welcome(welcome_for(&welcomes, rival_name))
        .await
        .unwrap();

    // A and B fork from epoch 1. B wins, and A is parked with its stamp.
    let a = alice_rename_commit(&mut x, &group_id, "a").await;
    let b = alice_rename_commit(&mut rival, &group_id, "b").await;
    x.ingest(b.clone()).await.unwrap();
    settle(&mut x, &group_id).await;
    assert_message_state(&x_storage, &b, MessageState::Processed);
    assert_eq!(
        x_storage.get_message(&a.id).unwrap().state,
        MessageState::ConvergenceDeferred
    );

    // X's own C is built on B; the rival follows with D. Before the fix, the
    // pass for D saw [A, C, D] beside [B, C, D]. Make the real branch win
    // that tie so A stays parked.
    let c = own_update(&mut x, &group_id).await;
    rival.ingest(c.clone()).await.unwrap();
    settle(&mut rival, &group_id).await;
    let d = rival_update_where(&mut rival, &group_id, |d| {
        branch_id(&[&b, &c, d]) > branch_id(&[&a, &c, d])
    })
    .await;
    x.ingest(d.clone()).await.unwrap();
    settle(&mut x, &group_id).await;
    assert_eq!(
        x_storage.get_message(&a.id).unwrap().state,
        MessageState::ConvergenceDeferred
    );

    // X's own F follows the remote D, and the rival's G follows F. Applying
    // the phantom must replay the own F after the remote D.
    let f = own_update(&mut x, &group_id).await;
    rival.ingest(f.clone()).await.unwrap();
    settle(&mut rival, &group_id).await;
    let g = rival_update_where(&mut rival, &group_id, |g| {
        branch_id(&[&a, &c, &d, &f, g]) > branch_id(&[&b, &c, &d, &f, g])
    })
    .await;
    x.ingest(g.clone()).await.unwrap();
    PhantomTie {
        x,
        x_storage,
        rival,
        group_id,
        a,
        remote: [b, d, g],
    }
}

#[tokio::test]
async fn own_checkpoint_rejects_parked_sibling_parent() {
    let PhantomTie {
        mut x,
        x_storage,
        rival,
        group_id,
        a,
        remote,
    } = phantom_tie(0).await;

    // Before the fix the phantom won, and its apply failed after the decision
    // on the own F: the pass stayed Resolving and every re-entry replayed the
    // same selection from scratch.
    let result = x
        .converge_stored_openmls_messages_at(&group_id, u64::MAX)
        .expect("the pass applies its decision");
    assert_eq!(result.selected_tip, Some(6));
    let tip_candidates = result
        .selection_trace
        .as_ref()
        .unwrap()
        .candidates
        .iter()
        .filter(|candidate| candidate.tip_digest == content_id(&remote[2]).as_slice())
        .count();
    assert_eq!(tip_candidates, 1, "one branch per tip commit");
    assert!(
        !result
            .accepted_commits
            .contains(&hex::encode(a.id.as_slice()))
    );
    assert_eq!(
        x_storage.get_message(&a.id).unwrap().state,
        MessageState::ConvergenceDeferred
    );
    for commit in &remote {
        assert_message_state(&x_storage, commit, MessageState::Processed);
    }
    assert_eq!(x.epoch(&group_id).unwrap(), EpochId(6));
    assert_eq!(
        x.members(&group_id).unwrap(),
        rival.members(&group_id).unwrap()
    );
    let exporter = |engine: &Engine<SqliteAccountStorage>| {
        engine
            .group_context(&group_id)
            .unwrap()
            .exporter_secret("marmot/group-event", 32)
            .unwrap()
    };
    assert_eq!(exporter(&x), exporter(&rival));

    // The pass completed, so the host has nothing to re-enter.
    assert!(!x.has_pending_convergence_inputs(&group_id).unwrap());
}

/// Host advances and wall time until X delivers the rival's first message at
/// the new tip. Run with `--ignored --nocapture`; it reports and asserts
/// nothing about timing. `PHANTOM_TIE_PASSIVE_MEMBERS` sets the group widths
/// (comma-separated, default `0,32`).
#[tokio::test]
#[ignore = "measurement; run explicitly with --ignored --nocapture"]
async fn phantom_tie_first_message_measurement() {
    const MAX_ADVANCES: usize = 8;
    let widths = std::env::var("PHANTOM_TIE_PASSIVE_MEMBERS").unwrap_or_else(|_| "0,32".into());
    for width in widths.split(',').map(|width| width.trim().parse().unwrap()) {
        let PhantomTie {
            mut x,
            mut rival,
            group_id,
            ..
        } = phantom_tie(width).await;
        let message = send_app(&mut rival, &group_id, b"after the tie".to_vec()).await;
        let _ = x.ingest(message).await;
        x.drain_events();
        let started = std::time::Instant::now();
        let mut failed = 0;
        let mut delivered_after = None;
        for advance in 1..=MAX_ADVANCES {
            if x.advance_convergence_inputs_until_settled(&group_id, u64::MAX)
                .await
                .is_err()
            {
                failed += 1;
            }
            if x.drain_events().iter().any(|event| {
                matches!(event, GroupEvent::MessageReceived { payload, .. }
                    if app_content(payload) == b"after the tie")
            }) {
                delivered_after = Some(advance);
                break;
            }
        }
        eprintln!(
            "phantom_tie members={} advances_to_first_message={} failed_advances={failed} \
             elapsed_ms={} epoch={}",
            width + 2,
            delivered_after.map_or_else(|| format!("none in {MAX_ADVANCES}"), |n| n.to_string()),
            started.elapsed().as_millis(),
            x.epoch(&group_id).unwrap().0,
        );
    }
}
