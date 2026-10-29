//! Turning account-devices on in an existing group (mdk#2628 item 2.4;
//! account-devices-v1.md, "Activation in an existing group").
//!
//! `SendIntent::EnableAccountDevices` is one admin Commit that requires 0x800d.
//! Every refusal comes before anything is staged, with a typed, aggregate
//! reason that `Engine::account_devices_activation_refusal` reports the same
//! way to a host deciding whether to offer the action. The race with a
//! concurrent Add of a device that lacks support is covered by the
//! `account-devices-activation-{wins-over,loses-to}-unsupported-invite`
//! simulator vectors; here a pending standalone Add stays out of the
//! activation Commit.

use super::*;
use cgka_traits::error::AccountDevicesActivationRefusal as Refusal;
use cgka_traits::storage::OutboundIntentStorage as _;

fn enable(gid: &GroupId) -> SendIntent {
    SendIntent::EnableAccountDevices {
        group_id: gid.clone(),
    }
}

fn refusal(device: &Device, gid: &GroupId) -> Option<Refusal> {
    device
        .engine
        .account_devices_activation_refusal(gid)
        .unwrap()
}

/// `device` refuses to activate for `reason` and stages nothing: the epoch
/// and the required list stay, and the next intent is not blocked.
#[track_caller]
fn assert_activation_refused(
    device: &Device,
    gid: &GroupId,
    result: Result<SendResult, EngineError>,
    reason: Refusal,
    epoch: u64,
) {
    match result {
        Err(EngineError::AccountDevicesActivationRefused { reason: got, .. }) => {
            assert_eq!(got, reason);
        }
        other => panic!("expected the {reason} refusal, got {other:?}"),
    }
    assert_eq!(refusal(device, gid), Some(reason));
    assert_eq!(device.engine.epoch(gid).unwrap().0, epoch);
    assert!(!requires_account_devices(&device.engine, gid) || reason == Refusal::AlreadyRequired);
}

/// Alice (admin) and Bob (not an admin) in a group that does not require
/// 0x800d; both advertise it unless `bob_advertises` is false.
async fn eligible_group(bob_advertises: bool) -> (Device, Device, GroupId) {
    let mut alice = device(b"alice", true);
    let mut bob = device(b"bob", bob_advertises);
    let bob_kp = bob.engine.fresh_key_package().await.unwrap();
    let gid = found_group(&mut alice, vec![bob_kp], false, &mut [&mut bob]).await;
    (alice, bob, gid)
}

#[tokio::test]
async fn an_admin_turns_account_devices_on_and_every_member_follows() {
    let (mut alice, mut bob, gid) = eligible_group(true).await;
    assert_eq!(refusal(&alice, &gid), None);

    let commit = send_commit(&mut alice, enable(&gid), &gid).await;
    assert_accepted(&mut bob, &commit, &gid).await;
    assert!(requires_account_devices(&alice.engine, &gid));
    assert!(requires_account_devices(&bob.engine, &gid));
    assert!(
        load_group(&alice, &gid)
            .extensions()
            .app_data_dictionary()
            .is_some_and(|ext| !ext.dictionary().contains(&ACCOUNT_DEVICES_COMPONENT_ID)),
        "activation installs no state"
    );

    // Requiring it is final, and a second activation is refused.
    let epoch = alice.engine.epoch(&gid).unwrap().0;
    let again = alice.engine.send(enable(&gid)).await;
    assert_activation_refused(&alice, &gid, again, Refusal::AlreadyRequired, epoch);
}

#[tokio::test]
async fn a_member_that_is_not_an_admin_cannot_turn_it_on() {
    let (alice, mut bob, gid) = eligible_group(true).await;
    // Bob's answer says nothing about the group's leaves, only that he
    // cannot decide.
    assert_eq!(refusal(&bob, &gid), Some(Refusal::NotAdmin));
    let epoch = bob.engine.epoch(&gid).unwrap().0;
    assert!(matches!(
        bob.engine.send(enable(&gid)).await,
        Err(EngineError::NotGroupAdmin { .. })
    ));
    assert_eq!(bob.engine.epoch(&gid).unwrap().0, epoch);
    assert!(!requires_account_devices(&alice.engine, &gid));
}

#[tokio::test]
async fn a_leaf_without_support_refuses_before_staging() {
    let (mut alice, bob, gid) = eligible_group(false).await;
    let epoch = alice.engine.epoch(&gid).unwrap().0;
    let result = alice.engine.send(enable(&gid)).await;
    assert_activation_refused(&alice, &gid, result, Refusal::UnsupportedLeaves, epoch);
    // Bob, not an admin, still learns only that he cannot decide.
    assert_eq!(refusal(&bob, &gid), Some(Refusal::NotAdmin));

    // Nothing was left staged: the admin's next Commit goes through.
    let remove = alice
        .engine
        .send(SendIntent::RemoveMembers {
            group_id: gid.clone(),
            members: vec![bob.engine.self_id()],
        })
        .await;
    assert!(matches!(remove, Ok(SendResult::GroupEvolution { .. })));
}

#[tokio::test]
async fn a_leaf_carrying_account_devices_data_refuses_before_staging() {
    let (mut alice, mut bob, gid) = eligible_group(true).await;
    // Before activation an entry under 0x800d is unknown data, so a device
    // whose leaf carries one can join.
    let mut carol = device(b"carol", true);
    let carol_kp = key_package_with_account_devices_data(&mut carol, true, false).await;
    let invite = send_commit(
        &mut alice,
        SendIntent::Invite {
            group_id: gid.clone(),
            key_packages: vec![carol_kp],
            initial_admins: vec![],
        },
        &gid,
    )
    .await;
    assert_accepted(&mut bob, &invite, &gid).await;

    let epoch = alice.engine.epoch(&gid).unwrap().0;
    let result = alice.engine.send(enable(&gid)).await;
    assert_activation_refused(&alice, &gid, result, Refusal::LeafCarriesData, epoch);
}

#[tokio::test]
async fn an_account_over_the_leaf_limit_refuses_before_staging() {
    let mut alice = device(b"alice", true);
    let mut carol = device(b"carol", true);
    let carol_kp = carol.engine.fresh_key_package().await.unwrap();
    let bob_kp = device(b"bob", true)
        .engine
        .fresh_key_package()
        .await
        .unwrap();
    let members = [carol_kp, bob_kp.clone()]
        .into_iter()
        .chain((0..MAX_LEAVES_PER_ACCOUNT).map(|_| sibling_key_package(&bob_kp, b"bob")))
        .collect();
    let gid = found_group(&mut alice, members, false, &mut [&mut carol]).await;

    let epoch = alice.engine.epoch(&gid).unwrap().0;
    let result = alice.engine.send(enable(&gid)).await;
    assert_activation_refused(&alice, &gid, result, Refusal::LeafLimitExceeded, epoch);
}

/// account-devices-v1.md, "Data": if the GroupContext carries an entry under
/// 0x800d, the activation Commit removes it.
#[tokio::test]
async fn activation_removes_a_group_context_entry_left_under_the_id() {
    let (mut alice, mut bob, gid) = eligible_group(true).await;
    let write = send_commit(
        &mut alice,
        SendIntent::UpdateAppComponents {
            group_id: gid.clone(),
            updates: vec![AppComponentData {
                component_id: ACCOUNT_DEVICES_COMPONENT_ID,
                data: vec![1],
            }],
        },
        &gid,
    )
    .await;
    assert_accepted(&mut bob, &write, &gid).await;
    assert_eq!(refusal(&alice, &gid), None);

    let commit = send_commit(&mut alice, enable(&gid), &gid).await;
    assert_accepted(&mut bob, &commit, &gid).await;
    for device in [&alice, &bob] {
        assert!(requires_account_devices(&device.engine, &gid));
        assert!(
            !load_group(device, &gid)
                .extensions()
                .app_data_dictionary()
                .unwrap()
                .dictionary()
                .contains(&ACCOUNT_DEVICES_COMPONENT_ID)
        );
    }
}

/// A standalone Add of a device without support, pending when the admin
/// activates, stays out of the activation Commit: the Commit references no
/// proposal, so its resulting state is the parent's leaves, all of which
/// advertise 0x800d. The proposal names the parent epoch and cannot be
/// committed on top of the activation.
#[tokio::test]
async fn a_pending_add_of_an_unsupported_device_stays_out_of_the_activation() {
    let mut alice = device(b"alice", true);
    let mut bob = device(b"bob", true);
    let bob_kp = bob.engine.fresh_key_package().await.unwrap();
    let gid = found_group_with_admins(
        &mut alice,
        vec![bob_kp],
        false,
        vec![bob.engine.self_id()],
        &mut [&mut bob],
    )
    .await;

    let dave_kp = device(b"dave", false)
        .engine
        .fresh_key_package()
        .await
        .unwrap();
    let crypto = RustCrypto::default();
    let provider =
        EngineOpenMlsProvider::<SqliteAccountStorage>::new(&crypto, bob.storage.mls_storage());
    let mut bob_group = load_group(&bob, &gid);
    let (proposal, _) = bob_group
        .propose_add_member(
            &provider,
            &device_signer(&bob),
            &parse_key_package(&dave_kp),
        )
        .expect("raw OpenMLS builds the proposal");
    let proposal = group_transport(proposal, &gid, "standalone-add");
    alice.engine.ingest(proposal).await.unwrap();

    assert_eq!(refusal(&alice, &gid), None);
    let members_before = alice.engine.group_record(&gid).unwrap().members.len();
    let commit = send_commit(&mut alice, enable(&gid), &gid).await;
    assert_accepted(&mut bob, &commit, &gid).await;
    for device in [&alice, &bob] {
        assert!(requires_account_devices(&device.engine, &gid));
        assert_eq!(
            device.engine.group_record(&gid).unwrap().members.len(),
            members_before
        );
    }
}

/// Bob's activation is buffered at Alice, unsettled, so the send waits for
/// convergence: `ingest` buffers it and the next send is queued behind it.
pub(super) async fn buffer_unsettled(receiver: &mut Device, commit: &TransportMessage) {
    assert!(matches!(
        receiver.engine.ingest(commit.clone()).await.unwrap(),
        IngestOutcome::Buffered { .. }
    ));
}

pub(super) fn queued_intents(device: &Device, gid: &GroupId) -> Vec<SendIntent> {
    device
        .storage
        .list_queued_outbound_intents(gid)
        .unwrap()
        .into_iter()
        .map(|record| record.intent)
        .collect()
}

/// A send that waits for convergence is checked before it is queued, so a
/// refusal the current state already shows is answered at once.
#[tokio::test]
async fn an_activation_the_current_state_refuses_is_not_queued() {
    let (mut alice, mut bob, gid) = eligible_group(false).await;
    let update = send_commit(
        &mut bob,
        SendIntent::SelfUpdate {
            group_id: gid.clone(),
        },
        &gid,
    )
    .await;
    buffer_unsettled(&mut alice, &update).await;

    let result = alice.engine.send(enable(&gid)).await;
    assert!(
        matches!(
            result,
            Err(EngineError::AccountDevicesActivationRefused {
                reason: Refusal::UnsupportedLeaves,
                ..
            })
        ),
        "{result:?}"
    );
    assert!(queued_intents(&alice, &gid).is_empty());
    // The group was waiting: another intent is queued, not sent.
    let other = alice
        .engine
        .send(SendIntent::SelfUpdate {
            group_id: gid.clone(),
        })
        .await;
    assert!(matches!(other, Ok(SendResult::Queued { .. })), "{other:?}");
}

/// An activation queued behind convergence is checked again on the settled
/// state. When that refuses it (here another admin's activation won), the
/// intent is retired: the drain succeeds, and the work queued after it still
/// goes out.
#[tokio::test]
async fn a_queued_activation_refused_on_the_settled_state_is_retired() {
    let mut alice = device(b"alice", true);
    let mut bob = device(b"bob", true);
    let bob_kp = bob.engine.fresh_key_package().await.unwrap();
    let gid = found_group_with_admins(
        &mut alice,
        vec![bob_kp],
        false,
        vec![bob.engine.self_id()],
        &mut [&mut bob],
    )
    .await;

    let bobs = send_commit(&mut bob, enable(&gid), &gid).await;
    buffer_unsettled(&mut alice, &bobs).await;
    let queued = alice.engine.send(enable(&gid)).await;
    assert!(
        matches!(queued, Ok(SendResult::Queued { .. })),
        "{queued:?}"
    );
    let queued = alice
        .engine
        .send(SendIntent::SelfUpdate {
            group_id: gid.clone(),
        })
        .await;
    assert!(
        matches!(queued, Ok(SendResult::Queued { .. })),
        "{queued:?}"
    );

    let mut drained = Vec::new();
    for _ in 0..3 {
        drained.extend(
            alice
                .engine
                .converge_and_drain_queued_outbound_intents(&gid, 1_000_000)
                .await
                .expect("a refused activation must not fail the drain"),
        );
    }
    assert!(requires_account_devices(&alice.engine, &gid));
    assert!(
        !queued_intents(&alice, &gid)
            .iter()
            .any(|intent| matches!(intent, SendIntent::EnableAccountDevices { .. })),
        "the refused activation is retired"
    );
    assert!(
        matches!(drained.as_slice(), [SendResult::GroupEvolution { .. }]),
        "the self-update queued after it still drains: {drained:?}"
    );
}
