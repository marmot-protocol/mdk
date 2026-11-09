//! An admin's Leave owned by the engine (mdk#3014): `StepDownAndLeave`
//! records the leave request before anything is published, and the leave
//! re-drive stages the step-down and then the SelfRemove from that request.

use super::*;

/// alice creates the group with bob as a second admin.
async fn two_admins(
    alice_id: &[u8],
    bob_id: &[u8],
) -> (
    Engine<SqliteAccountStorage>,
    SqliteAccountStorage,
    Engine<SqliteAccountStorage>,
    GroupId,
) {
    let (mut alice, alice_storage) = build_with_storage(alice_id);
    let mut bob = build_client(bob_id);
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (gid, created) = alice
        .create_group(CreateGroupRequest {
            name: "admin leave".into(),
            description: String::new(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![bob.self_id()],
        })
        .await
        .unwrap();
    let SendResult::GroupCreated {
        pending,
        mut welcomes,
    } = created
    else {
        panic!("legacy create")
    };
    alice.confirm_published(pending).await.unwrap();
    bob.join_welcome(welcomes.remove(0)).await.unwrap();
    (alice, alice_storage, bob, gid)
}

fn is_admin(engine: &Engine<SqliteAccountStorage>, gid: &GroupId) -> bool {
    let own = engine.self_id();
    engine
        .admin_pubkeys(gid)
        .unwrap()
        .iter()
        .any(|admin| admin.as_slice() == own.as_slice())
}

async fn step_down_and_leave(
    engine: &mut Engine<SqliteAccountStorage>,
    gid: &GroupId,
) -> cgka_traits::storage::LeaveRequest {
    let SendResult::LeaveRequested { request } = engine
        .send(SendIntent::StepDownAndLeave {
            group_id: gid.clone(),
        })
        .await
        .unwrap()
    else {
        panic!("an admin's leave is a recorded request")
    };
    request
}

/// The call records the leave and publishes nothing; asking again returns
/// the same request. The next drain stages the step-down, and once that
/// Commit is applied the next one proposes the SelfRemove that bob, still an
/// admin, can commit.
#[tokio::test]
async fn an_admins_leave_is_recorded_before_anything_is_published() {
    let (mut alice, alice_storage, mut bob, gid) =
        two_admins(b"admin-leave-alice", b"admin-leave-bob").await;
    let epoch = alice.epoch(&gid).unwrap();

    let request = step_down_and_leave(&mut alice, &gid).await;
    assert_eq!(request.last_proposed_epoch, None);
    assert_eq!(
        alice_storage.leave_request(&gid).unwrap(),
        Some(request.clone()),
        "durable before anything is published"
    );
    assert!(alice.drain_auto_publish().is_empty());
    assert!(alice.drain_auto_proposals().is_empty());
    assert_eq!(alice.epoch(&gid).unwrap(), epoch);
    assert!(is_admin(&alice, &gid));
    assert!(alice.leave_in_progress(&gid).unwrap());
    assert!(
        alice.drain_pending_convergence_groups().contains(&gid),
        "the request wakes its group"
    );
    assert_eq!(step_down_and_leave(&mut alice, &gid).await, request);

    alice.advance_convergence(&gid).await.unwrap();
    let mut staged = alice.drain_auto_publish();
    assert_eq!(staged.len(), 1, "the step-down");
    assert!(alice.drain_auto_proposals().is_empty(), "no SelfRemove yet");
    let step_down = staged.remove(0);
    alice.confirm_published(step_down.pending).await.unwrap();
    assert!(!is_admin(&alice, &gid));

    alice.advance_convergence(&gid).await.unwrap();
    let proposals = alice.drain_auto_proposals();
    assert_eq!(proposals.len(), 1, "the SelfRemove");
    assert_eq!(
        alice_storage
            .leave_request(&gid)
            .unwrap()
            .and_then(|request| request.last_proposed_epoch),
        Some(alice.epoch(&gid).unwrap())
    );

    bob.ingest(step_down.msg).await.unwrap();
    converge_buffered_commit(&mut bob, &gid);
    assert_eq!(bob.epoch(&gid).unwrap(), alice.epoch(&gid).unwrap());
    let alice_id = alice.self_id();
    assert!(
        !bob.admin_pubkeys(&gid)
            .unwrap()
            .iter()
            .any(|admin| admin.as_slice() == alice_id.as_slice())
    );
    assert!(
        bob.ingest(proposals[0].clone()).await.is_ok(),
        "the SelfRemove is valid once the step-down is applied"
    );
}

/// A step-down whose publication is refused is rolled back, and the leave
/// request still owes it: the next drain stages it again rather than leaving
/// the account an admin with a leave nothing retries.
#[tokio::test]
async fn an_admins_refused_step_down_is_staged_again() {
    let (mut alice, alice_storage, _bob, gid) =
        two_admins(b"refused-step-down-alice", b"refused-step-down-bob").await;
    let request = step_down_and_leave(&mut alice, &gid).await;

    alice.advance_convergence(&gid).await.unwrap();
    let mut staged = alice.drain_auto_publish();
    assert_eq!(staged.len(), 1, "the step-down");
    alice
        .publish_failed(staged.remove(0).pending)
        .await
        .unwrap();
    assert!(is_admin(&alice, &gid));
    assert_eq!(alice_storage.leave_request(&gid).unwrap(), Some(request));
    assert!(alice.leave_redrive_owed(&gid).unwrap());

    alice.advance_convergence(&gid).await.unwrap();
    assert_eq!(alice.drain_auto_publish().len(), 1, "staged again");
}

/// The last active admin cannot step down, so its leave is refused before
/// anything is recorded. A member's call is an ordinary Leave.
#[tokio::test]
async fn step_down_and_leave_refuses_the_last_admin_and_is_a_leave_for_a_member() {
    let (mut alice, alice_storage) = build_with_storage(b"last-admin-leave-alice");
    let (mut bob, bob_storage) = build_with_storage(b"last-admin-leave-bob");
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (gid, created) = alice
        .create_group(CreateGroupRequest {
            name: "last admin".into(),
            description: String::new(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let SendResult::GroupCreated {
        pending,
        mut welcomes,
    } = created
    else {
        panic!("legacy create")
    };
    alice.confirm_published(pending).await.unwrap();
    bob.join_welcome(welcomes.remove(0)).await.unwrap();

    let refused = alice
        .send(SendIntent::StepDownAndLeave {
            group_id: gid.clone(),
        })
        .await;
    assert!(
        matches!(refused, Err(EngineError::AdminDepletion { .. })),
        "{refused:?}"
    );
    assert_eq!(alice_storage.leave_request(&gid).unwrap(), None);
    assert!(!alice.leave_in_progress(&gid).unwrap());
    assert!(alice.drain_auto_publish().is_empty());

    let epoch = bob.epoch(&gid).unwrap();
    let left = bob
        .send(SendIntent::StepDownAndLeave {
            group_id: gid.clone(),
        })
        .await
        .unwrap();
    assert!(matches!(left, SendResult::Proposal { .. }), "a SelfRemove");
    assert_eq!(
        bob_storage
            .leave_request(&gid)
            .unwrap()
            .and_then(|request| request.last_proposed_epoch),
        Some(epoch)
    );
}
