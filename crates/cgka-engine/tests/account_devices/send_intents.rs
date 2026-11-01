//! The same-account send intents (mdk#2628 item 2.1e):
//! `SendIntent::AddOwnAccountDevices` and `SendIntent::RemoveOwnAccountDevices`.
//!
//! From the committer's side, each intent builds a Commit the classifier calls
//! same-account, stamps it `ordinary`, carries its proposals by value and
//! leaves the proposal store alone; every other request is refused before
//! anything is recorded or published. From the receivers' side, every member
//! and sibling accepts the Commit, an added device joins through its Welcome,
//! and a removed one sees its removal. Fair scheduling gives a queued
//! same-account intent the one preparation attempt an admin intent gets, and
//! never a self-update or a Leave.

use super::*;
use cgka_traits::convergence_pass::ConvergencePassPhase;
use cgka_traits::storage::{ConvergencePassStorage, OutboundIntentStorage, QueuedOutboundIntent};
use openmls::prelude::ProposalOrRefType;

pub(super) fn pending_proposals(device: &Device, gid: &GroupId) -> usize {
    load_group(device, gid).pending_proposals().count()
}

/// What a refused intent must leave as it was.
#[derive(Debug, PartialEq)]
struct Untouched {
    epoch: u64,
    stable: bool,
    staged: bool,
    record: cgka_traits::group::Group,
    pending_proposals: usize,
}

impl Untouched {
    fn of(device: &Device, gid: &GroupId) -> Self {
        Self {
            epoch: device.engine.epoch(gid).unwrap().0,
            stable: device
                .engine
                .epoch_state(gid)
                .is_some_and(|state| state.is_stable()),
            staged: load_group(device, gid).pending_commit().is_some(),
            record: device.engine.group_record(gid).unwrap(),
            pending_proposals: pending_proposals(device, gid),
        }
    }
}

/// `device`'s KeyPackage for a device of `account` that advertises nothing
/// beyond the defaults, so it misses account-devices.
async fn key_package_without_account_devices(account: &[u8]) -> KeyPackage {
    device(account, false)
        .engine
        .fresh_key_package()
        .await
        .unwrap()
}

/// Put an Add of `kp` in `device`'s OpenMLS proposal store, where a replayed
/// proposal waits for a Commit.
pub(super) fn store_pending_add(device: &Device, gid: &GroupId, kp: &KeyPackage) {
    let crypto = RustCrypto::default();
    let provider =
        EngineOpenMlsProvider::<SqliteAccountStorage>::new(&crypto, device.storage.mls_storage());
    load_group(device, gid)
        .propose_add_member(&provider, &device_signer(device), &parse_key_package(kp))
        .expect("raw OpenMLS stores the proposal");
}

/// bob's intents while an Add proposal is pending in his store. Each Commit
/// carries its own proposals by value and nothing else, and the pending
/// proposal stays where it was while the Commit is staged, after its publish
/// fails, and after a refused intent.
#[tokio::test]
async fn own_account_intents_leave_pending_proposals_alone() {
    let mut m = members(true).await;
    let gid = m.gid.clone();
    let dave_kp = device(b"dave", true)
        .engine
        .fresh_key_package()
        .await
        .unwrap();
    store_pending_add(&m.bob, &gid, &dave_kp);
    assert_eq!(pending_proposals(&m.bob, &gid), 1);

    let laptop_kp = new_sibling_key_package(&mut m.bob, b"bob").await;
    let sibling = signature_key(&m.bob_sibling, &gid);
    for (intent, adds, removes) in [
        (add_own_devices(&gid, vec![laptop_kp]), 1, 0),
        (remove_own_devices(&gid, vec![sibling]), 0, 1),
    ] {
        let SendResult::GroupEvolution { pending, .. } = m.bob.engine.send(intent).await.unwrap()
        else {
            panic!("expected GroupEvolution")
        };
        let group = load_group(&m.bob, &gid);
        let staged = group.pending_commit().expect("the Commit is staged");
        assert!(
            staged
                .queued_proposals()
                .all(|queued| queued.proposal_or_ref_type() == ProposalOrRefType::Proposal),
            "every proposal is carried by value"
        );
        assert_eq!(staged.add_proposals().count(), adds);
        assert_eq!(staged.remove_proposals().count(), removes);
        assert_eq!(staged.queued_proposals().count(), adds + removes);
        assert_eq!(pending_proposals(&m.bob, &gid), 1);

        m.bob.engine.publish_failed(pending).await.unwrap();
        assert!(load_group(&m.bob, &gid).pending_commit().is_none());
        assert_eq!(pending_proposals(&m.bob, &gid), 1);
    }

    assert_refused(
        m.bob
            .engine
            .send(add_own_devices(&gid, vec![dave_kp]))
            .await,
        "belongs to another account",
    );
    assert_eq!(pending_proposals(&m.bob, &gid), 1);
}

/// While each Commit's publish is pending, `members()` shows bob's devices as
/// the Commit leaves them, each added device included although it shares
/// bob's account. A failed publish puts them back.
#[tokio::test]
async fn members_show_a_pending_own_account_commit_until_its_publish_fails() {
    let mut m = members(true).await;
    let gid = m.gid.clone();
    let bob_id = m.bob.engine.self_id();
    let bob_devices = |device: &Device| {
        let mut keys: Vec<_> = device
            .engine
            .members(&gid)
            .unwrap()
            .into_iter()
            .filter(|member| member.id == bob_id)
            .map(|member| member.credential)
            .collect();
        keys.sort();
        keys
    };
    let before = bob_devices(&m.bob);
    assert_eq!(before.len(), 2);

    let laptop_kp = new_sibling_key_package(&mut m.bob, b"bob").await;
    let tablet_kp = new_sibling_key_package(&mut m.bob, b"bob").await;
    let mut with_added = before.clone();
    with_added.extend([&laptop_kp, &tablet_kp].map(|kp| {
        parse_key_package(kp)
            .leaf_node()
            .signature_key()
            .as_slice()
            .to_vec()
    }));
    with_added.sort();
    let sibling = signature_key(&m.bob_sibling, &gid);
    let without_sibling: Vec<_> = before
        .iter()
        .filter(|key| **key != sibling)
        .cloned()
        .collect();
    for (intent, pending_devices) in [
        (
            add_own_devices(&gid, vec![laptop_kp, tablet_kp]),
            with_added,
        ),
        (remove_own_devices(&gid, vec![sibling]), without_sibling),
    ] {
        let SendResult::GroupEvolution { pending, .. } = m.bob.engine.send(intent).await.unwrap()
        else {
            panic!("expected GroupEvolution")
        };
        assert_eq!(bob_devices(&m.bob), pending_devices);
        m.bob.engine.publish_failed(pending).await.unwrap();
        assert_eq!(bob_devices(&m.bob), before);
    }
}

/// bob adds a new device of his account, then removes his other device. Each
/// Commit is `ordinary` in bob's stamp and in every receiver's replay; the
/// other members and bob's siblings accept it, the new device joins through
/// its Welcome, and the removed device sees its removal.
#[tokio::test]
async fn own_account_intents_reach_every_member_and_sibling() {
    let mut m = members(true).await;
    let gid = m.gid.clone();
    let bob_id = m.bob.engine.self_id();
    let bob_leaves = |device: &Device| {
        device
            .engine
            .members(&gid)
            .unwrap()
            .iter()
            .filter(|member| member.id == bob_id)
            .count()
    };

    let mut laptop = device(b"bob", true);
    let laptop_kp = laptop.engine.fresh_key_package().await.unwrap();
    let SendResult::GroupEvolution {
        msg,
        welcomes,
        pending,
    } = m
        .bob
        .engine
        .send(add_own_devices(&gid, vec![laptop_kp]))
        .await
        .unwrap()
    else {
        panic!("expected GroupEvolution")
    };
    m.bob.engine.confirm_published(pending).await.unwrap();
    let add = route_to_group(&msg, &gid);
    assert_priorities(
        &m.bob,
        &add,
        &mut [&mut m.alice, &mut m.bob_sibling, &mut m.carol],
        &gid,
        CommitOrderingPriority::Ordinary,
    )
    .await;
    let [welcome] = &welcomes[..] else {
        panic!("one Welcome per added KeyPackage, got {}", welcomes.len())
    };
    assert_joins(&mut laptop, welcome, &gid, &m.bob).await;
    assert_eq!(bob_leaves(&m.alice), 3);

    let sibling = signature_key(&m.bob_sibling, &gid);
    let remove = send_commit(&mut m.bob, remove_own_devices(&gid, vec![sibling]), &gid).await;
    assert_priorities(
        &m.bob,
        &remove,
        &mut [&mut m.alice, &mut m.carol, &mut laptop],
        &gid,
        CommitOrderingPriority::Ordinary,
    )
    .await;
    assert_accepted(&mut m.bob_sibling, &remove, &gid).await;
    assert!(m.bob_sibling.engine.group_record(&gid).unwrap().removed);
    assert_eq!(bob_leaves(&m.alice), 2);
    assert_eq!(bob_leaves(&m.bob), 2);
}

/// An admin's own-device intent is same-account too, and `ordinary`.
#[tokio::test]
async fn an_admins_own_account_intent_is_ordinary() {
    let mut m = members(true).await;
    let gid = m.gid.clone();
    let kp = new_sibling_key_package(&mut m.alice, b"alice").await;
    let add = send_commit(&mut m.alice, add_own_devices(&gid, vec![kp]), &gid).await;
    assert_priorities(
        &m.alice,
        &add,
        &mut [&mut m.bob, &mut m.bob_sibling, &mut m.carol],
        &gid,
        CommitOrderingPriority::Ordinary,
    )
    .await;
}

/// Every request the classifier would not call same-account is refused
/// before anything is recorded or published, and leaves the committer's group
/// as it was. Afterwards a valid intent still goes through, so no refusal
/// left a staged Commit behind.
#[tokio::test]
async fn own_account_intents_refuse_what_is_not_same_account() {
    // Without the requirement, for a non-admin and an admin alike.
    let mut m = members(false).await;
    let gid = m.gid.clone();
    let before = Untouched::of(&m.bob, &gid);
    let bob_kp = new_sibling_key_package(&mut m.bob, b"bob").await;
    assert_not_required(m.bob.engine.send(add_own_devices(&gid, vec![bob_kp])).await);
    let sibling = signature_key(&m.bob_sibling, &gid);
    assert_not_required(
        m.bob
            .engine
            .send(remove_own_devices(&gid, vec![sibling]))
            .await,
    );
    assert_eq!(Untouched::of(&m.bob, &gid), before);
    let before = Untouched::of(&m.alice, &gid);
    let alice_kp = new_sibling_key_package(&mut m.alice, b"alice").await;
    assert_not_required(
        m.alice
            .engine
            .send(add_own_devices(&gid, vec![alice_kp]))
            .await,
    );
    assert_eq!(Untouched::of(&m.alice, &gid), before);

    // With it.
    let mut m = members(true).await;
    let gid = m.gid.clone();
    let before = Untouched::of(&m.bob, &gid);
    let dave_kp = device(b"dave", true)
        .engine
        .fresh_key_package()
        .await
        .unwrap();
    let template = m.bob.engine.fresh_key_package().await.unwrap();
    // bob has two leaves, so 19 more break the limit.
    let over_limit: Vec<_> = (0..MAX_LEAVES_PER_ACCOUNT - 1)
        .map(|_| sibling_key_package(&template, b"bob"))
        .collect();
    let limit_error = format!("an account holds more than {MAX_LEAVES_PER_ACCOUNT} leaves");
    let unknown_key = vec![0x5c; 32];
    for (intent, reason) in [
        (
            add_own_devices(&gid, vec![dave_kp.clone()]),
            "belongs to another account",
        ),
        (
            add_own_devices(
                &gid,
                vec![
                    new_sibling_key_package(&mut m.bob, b"bob").await,
                    dave_kp.clone(),
                ],
            ),
            "belongs to another account",
        ),
        (add_own_devices(&gid, over_limit), limit_error.as_str()),
        (
            remove_own_devices(&gid, vec![signature_key(&m.bob, &gid)]),
            "use SendIntent::Leave",
        ),
        (
            remove_own_devices(&gid, vec![signature_key(&m.carol, &gid)]),
            "belongs to another account",
        ),
        (
            remove_own_devices(&gid, vec![unknown_key]),
            "no current leaf",
        ),
    ] {
        assert_refused(m.bob.engine.send(intent).await, reason);
        assert_eq!(Untouched::of(&m.bob, &gid), before);
    }
    let missing = key_package_without_account_devices(b"bob").await;
    let refused = m
        .bob
        .engine
        .send(add_own_devices(&gid, vec![missing]))
        .await;
    assert!(
        matches!(
            refused,
            Err(EngineError::MissingRequiredCapabilities { .. })
        ),
        "{refused:?}"
    );
    assert_eq!(Untouched::of(&m.bob, &gid), before);

    let sibling = signature_key(&m.bob_sibling, &gid);
    let remove = send_commit(&mut m.bob, remove_own_devices(&gid, vec![sibling]), &gid).await;
    assert_accepted(&mut m.alice, &remove, &gid).await;
}

/// Restart keeps the publish lifecycle's rules: a staged same-account Add is
/// rolled back at open like an Invite, and a staged same-account Remove is
/// kept like any removal-bearing Commit.
#[tokio::test]
async fn restart_treats_own_account_intents_like_invites_and_removals() {
    let mut m = members(true).await;
    let gid = m.gid.clone();
    let epoch = m.bob.engine.epoch(&gid).unwrap();
    let kp = new_sibling_key_package(&mut m.bob, b"bob").await;
    let staged = m.bob.engine.send(add_own_devices(&gid, vec![kp])).await;
    assert!(matches!(staged, Ok(SendResult::GroupEvolution { .. })));
    assert_eq!(m.bob.engine.members(&gid).unwrap().len(), 5);
    let mut bob = restart(m.bob, b"bob");
    let events = bob.engine.drain_events();
    assert!(
        events.iter().any(|event| matches!(
            event,
            GroupEvent::PendingCommitRecovered { group_id, recovered_epoch }
                if group_id == &gid && *recovered_epoch == epoch
        )),
        "{events:?}"
    );
    assert!(load_group(&bob, &gid).pending_commit().is_none());
    assert_eq!(bob.engine.members(&gid).unwrap().len(), 4);

    let sibling = signature_key(&m.bob_sibling, &gid);
    let staged = bob
        .engine
        .send(remove_own_devices(&gid, vec![sibling]))
        .await;
    assert!(matches!(staged, Ok(SendResult::GroupEvolution { .. })));
    assert_eq!(bob.engine.members(&gid).unwrap().len(), 3);
    let bob = restart(bob, b"bob");
    assert!(load_group(&bob, &gid).pending_commit().is_some());
    assert_eq!(bob.engine.members(&gid).unwrap().len(), 3);
}

/// Drop `device`'s engine and open a new one on the same storage, hydrating
/// every stored group as a session open does.
fn restart(device: Device, account: &[u8]) -> Device {
    let Device { engine, storage } = device;
    drop(engine);
    let mut supported: Vec<_> = default_group_components().into_iter().collect();
    supported.push(ACCOUNT_DEVICES_COMPONENT_ID);
    let mut engine = EngineBuilder::new(storage.clone())
        .identity(pad32(account))
        .account_identity_proof_signer(proof_signer(account))
        .protocol_profile(ProtocolProfile::Current)
        .feature_registry(registry())
        .supported_app_components(supported)
        .peeler(Box::<MockPeeler>::default())
        .build()
        .unwrap();
    engine.hydrate_all_stored_groups().unwrap();
    Device { engine, storage }
}

// ── Fair scheduling (mdk#2628 D6) ───────────────────────────────────────────

fn queue(device: &Device, gid: &GroupId, id: &[u8], intent: SendIntent) {
    device
        .storage
        .put_queued_outbound_intent(&QueuedOutboundIntent {
            id: MessageId::new(id.to_vec()),
            group_id: gid.clone(),
            intent,
            created_at_ms: 1_000_001,
            reissue_attempts: 0,
        })
        .unwrap();
}

/// carol's self-update, which every other member receives as ordinary
/// inbound input.
async fn inbound_self_update(m: &mut Members) -> TransportMessage {
    let gid = m.gid.clone();
    send_commit(
        &mut m.carol,
        SendIntent::SelfUpdate {
            group_id: gid.clone(),
        },
        &gid,
    )
    .await
}

/// Settle one pass on `receiver` from `first`, queue `intents`, then buffer
/// `second`. Returns whether the completed pass still holds its fairness
/// slot, which keeps `second` out of a new pass until the slot's one
/// preparation attempt.
async fn holds_the_slot(
    receiver: &mut Device,
    gid: &GroupId,
    first: TransportMessage,
    second: TransportMessage,
    intents: Vec<SendIntent>,
) -> bool {
    receiver
        .engine
        .buffer_openmls_convergence_message_at(gid, first, 1_000)
        .unwrap();
    receiver
        .engine
        .converge_stored_openmls_messages_at(gid, 1_000_000)
        .unwrap();
    let completed = receiver.storage.convergence_pass(gid).unwrap().unwrap();
    assert_eq!(completed.phase, ConvergencePassPhase::Completed);
    assert!(completed.fairness_slot_available);
    for (index, intent) in intents.into_iter().enumerate() {
        queue(receiver, gid, format!("queued-{index}").as_bytes(), intent);
    }
    receiver
        .engine
        .buffer_openmls_convergence_message_at(gid, second, 1_000_100)
        .unwrap();
    let pass = receiver.storage.convergence_pass(gid).unwrap().unwrap();
    let held = pass.generation == completed.generation;
    assert_eq!(
        held,
        pass.phase == ConvergencePassPhase::Completed && pass.fairness_slot_available,
        "{pass:?}"
    );
    held
}

/// With inbound input waiting, a queued same-account intent gets the one
/// preparation attempt after a pass settles in `Stable`, as an admin intent
/// does, and inbound input proceeds after it.
#[tokio::test]
async fn a_queued_same_account_intent_gets_the_fairness_attempt() {
    for removes in [true, false] {
        let mut m = members(true).await;
        let gid = m.gid.clone();
        let first = inbound_self_update(&mut m).await;
        let second = inbound_self_update(&mut m).await;
        let intent = if removes {
            remove_own_devices(&gid, vec![signature_key(&m.bob_sibling, &gid)])
        } else {
            add_own_devices(
                &gid,
                vec![new_sibling_key_package(&mut m.bob, b"bob").await],
            )
        };
        assert!(holds_the_slot(&mut m.bob, &gid, first, second, vec![intent]).await);

        let drained = m
            .bob
            .engine
            .converge_and_drain_queued_outbound_intents(&gid, 1_000_200)
            .await
            .unwrap();
        let [SendResult::GroupEvolution { msg, pending, .. }] = &drained[..] else {
            panic!("expected the same-account attempt, got {drained:?}")
        };
        let consumed = m.bob.storage.convergence_pass(&gid).unwrap().unwrap();
        assert!(!consumed.fairness_slot_available);
        m.bob.engine.confirm_published(*pending).await.unwrap();
        assert_eq!(
            stamped_priority(&m.bob, &route_to_group(msg, &gid)),
            CommitOrderingPriority::Ordinary
        );
    }
}

/// A queued self-update or Leave never holds the slot, in a group that
/// requires account-devices or not.
#[tokio::test]
async fn self_updates_and_leaves_never_hold_the_fairness_slot() {
    for require in [true, false] {
        for leave in [false, true] {
            let mut m = members(require).await;
            let gid = m.gid.clone();
            let first = inbound_self_update(&mut m).await;
            let second = inbound_self_update(&mut m).await;
            let intent = if leave {
                SendIntent::Leave {
                    group_id: gid.clone(),
                }
            } else {
                SendIntent::SelfUpdate {
                    group_id: gid.clone(),
                }
            };
            assert!(!holds_the_slot(&mut m.bob, &gid, first, second, vec![intent]).await);
        }
    }
}

/// Without the requirement a queued same-account intent is not authorized,
/// so it takes no fairness attempt: alone it holds nothing, behind it an
/// admin intent gets the slot exactly as it would alone, and preparing it
/// later refuses it with the requirement's typed error and retires it
/// (mdk#2694).
#[tokio::test]
async fn without_account_devices_a_same_account_intent_takes_no_fairness_attempt() {
    let mut m = members(false).await;
    let gid = m.gid.clone();
    let first = inbound_self_update(&mut m).await;
    let second = inbound_self_update(&mut m).await;
    let own_device = new_sibling_key_package(&mut m.alice, b"alice").await;
    assert!(
        !holds_the_slot(
            &mut m.alice,
            &gid,
            first,
            second,
            vec![add_own_devices(&gid, vec![own_device])]
        )
        .await
    );
    m.alice
        .engine
        .converge_stored_openmls_messages_at(&gid, 2_000_000)
        .unwrap();
    m.alice.engine.drain_events();
    let prepared = m
        .alice
        .engine
        .converge_and_drain_queued_outbound_intents(&gid, 2_000_100)
        .await
        .unwrap();
    assert!(prepared.is_empty(), "{prepared:?}");
    let refusals = m
        .alice
        .engine
        .drain_events()
        .into_iter()
        .filter_map(|event| match event {
            GroupEvent::QueuedIntentRefused {
                intent_id,
                intent_kind,
                reason,
                ..
            } => Some((intent_id, intent_kind, reason)),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        refusals,
        vec![(
            MessageId::new(b"queued-0".to_vec()),
            "add_own_account_devices".to_string(),
            "invalid_transition".to_string()
        )]
    );
    assert!(
        m.alice
            .storage
            .list_queued_outbound_intents(&gid)
            .unwrap()
            .is_empty()
    );

    let mut m = members(false).await;
    let gid = m.gid.clone();
    let first = inbound_self_update(&mut m).await;
    let second = inbound_self_update(&mut m).await;
    let own_device = new_sibling_key_package(&mut m.alice, b"alice").await;
    let rename = SendIntent::UpdateGroupData {
        group_id: gid.clone(),
        name: Some("held for one attempt".into()),
        description: None,
    };
    assert!(
        holds_the_slot(
            &mut m.alice,
            &gid,
            first,
            second,
            vec![add_own_devices(&gid, vec![own_device]), rename]
        )
        .await
    );
    let drained = m
        .alice
        .engine
        .converge_and_drain_queued_outbound_intents(&gid, 1_000_200)
        .await
        .unwrap();
    let [SendResult::GroupEvolution { .. }] = &drained[..] else {
        panic!("expected the admin attempt, got {drained:?}")
    };
    let consumed = m.alice.storage.convergence_pass(&gid).unwrap().unwrap();
    assert!(!consumed.fairness_slot_available);
    assert_eq!(
        m.alice
            .storage
            .list_queued_outbound_intents(&gid)
            .unwrap()
            .len(),
        2,
        "the skipped same-account intent stays queued"
    );
}

/// A same-account Add of a device already in the group is refused by OpenMLS
/// (a repeated signature key), which surfaces as `Backend`. Queued, it is
/// retired and announced like any other refusal, and the self-update queued
/// behind it drains (mdk#2694).
#[tokio::test]
async fn a_queued_add_of_a_device_already_in_the_group_is_retired() {
    let mut m = members(true).await;
    let gid = m.gid.clone();
    let present = m.bob_sibling.engine.fresh_key_package().await.unwrap();
    queue(
        &m.bob,
        &gid,
        b"queued-0",
        add_own_devices(&gid, vec![present]),
    );
    let self_update = SendIntent::SelfUpdate {
        group_id: gid.clone(),
    };
    queue(&m.bob, &gid, b"queued-1", self_update.clone());
    m.bob.engine.drain_events();

    let mut drained = Vec::new();
    let mut refusals = Vec::new();
    for pass in 0..3 {
        drained.extend(
            m.bob
                .engine
                .converge_and_drain_queued_outbound_intents(&gid, 3_000_000 + pass)
                .await
                .expect("a refused queued intent must not fail the drain"),
        );
        refusals.extend(
            m.bob
                .engine
                .drain_events()
                .into_iter()
                .filter_map(|event| match event {
                    GroupEvent::QueuedIntentRefused {
                        intent_id,
                        intent_kind,
                        reason,
                        ..
                    } => Some((intent_id, intent_kind, reason)),
                    _ => None,
                }),
        );
    }
    assert_eq!(
        refusals,
        vec![(
            MessageId::new(b"queued-0".to_vec()),
            "add_own_account_devices".to_string(),
            "backend".to_string()
        )]
    );
    let [SendResult::GroupEvolution { .. }] = &drained[..] else {
        panic!("expected the self-update behind the refused Add, got {drained:?}")
    };
    let queued = m
        .bob
        .storage
        .list_queued_outbound_intents(&gid)
        .unwrap()
        .into_iter()
        .map(|record| record.intent)
        .collect::<Vec<_>>();
    assert_eq!(queued, vec![self_update], "only the in-flight self-update");
}
