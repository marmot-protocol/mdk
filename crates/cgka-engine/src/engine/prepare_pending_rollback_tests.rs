//! Fault-injection regression tests for `prepare_pending` rollback ordering (#3794).
//!
//! Each test drives a real `Engine<SqliteAccountStorage>` commit-staging path
//! with a one-shot failure injected into `EpochManager::prepare_pending`.
//! Because pending-state validation runs before committing durable SQLite rows
//! (`Sent` commits, content markers, staged Welcomes, `DisbandCandidate`,
//! `DisbandRequest`, `DurableGroupEvolution`, projected `group_record`), a
//! failing transition leaves no orphaned SQLite state and cleans up OpenMLS's
//! staged commit via `PendingCommitCleanupGuard` (or `NewGroupCleanupGuard`).

#![allow(clippy::disallowed_methods)]

use super::test_support::{
    PassthroughPeeler, SeedProofSigner, join_raw, seal_and_bind, signing_key,
};
use crate::convergence_clock::{ConvergenceClock, ManualConvergenceClock};
use crate::feature_registry::FeatureRegistry;
use crate::{Engine, EngineBuilder};
use cgka_traits::app_components::{
    ACCOUNT_DEVICES_COMPONENT_ID, AppComponentData, DEVICE_ROSTER_COMPONENT_ID, DeviceEntryV1,
    DeviceRosterOperationV1, DeviceRosterUpdateV1, DeviceRosterV1, NOSTR_ROUTING_COMPONENT_ID,
    default_group_components, encode_device_roster_update_v1, encode_device_roster_v1,
};
use cgka_traits::capabilities::{Capability, CapabilityRequirement, Feature, RequirementLevel};
use cgka_traits::engine::{CgkaEngine, CreateGroupRequest, KeyPackage, SendIntent, SendResult};
use cgka_traits::error::EngineError;
use cgka_traits::storage::{
    DisbandCandidateStorage, DisbandRequestStorage, GroupStorage, MessageStorage, StorageProvider,
};
use cgka_traits::transport::Timestamp;
use cgka_traits::types::{EpochId, GroupId};
use openmls::group::MlsGroup;
use rusqlite::{Connection, types::Value};
use std::sync::Arc;
use storage_sqlite::{
    SqlCipherHardening, SqlCipherKey, SqliteAccountStorage, open_hardened_sqlcipher,
};

const ACCOUNT_DEVICES_FEATURE: Feature = Feature("account-devices");

fn upgradeable_registry() -> FeatureRegistry {
    let mut r = FeatureRegistry::new();
    r.register(
        Feature("reactions"),
        CapabilityRequirement {
            requires: Capability::Proposal(0xF210),
            level: RequirementLevel::Optional,
            description: "custom upgradeable proposal",
        },
    );
    r
}

fn selfremove_registry() -> FeatureRegistry {
    let mut r = FeatureRegistry::new();
    r.register(
        Feature("self-remove"),
        CapabilityRequirement {
            requires: Capability::Proposal(10),
            level: RequirementLevel::Required,
            description: "MIP-03",
        },
    );
    r
}

fn account_devices_registry() -> FeatureRegistry {
    let mut r = FeatureRegistry::new();
    r.register(
        ACCOUNT_DEVICES_FEATURE,
        CapabilityRequirement {
            requires: Capability::AppComponent(ACCOUNT_DEVICES_COMPONENT_ID),
            level: RequirementLevel::Optional,
            description: "account-devices",
        },
    );
    r
}

fn build_client(
    seed: &[u8],
    storage: SqliteAccountStorage,
    clock: &ManualConvergenceClock,
    registry: FeatureRegistry,
) -> Engine<SqliteAccountStorage> {
    let key = signing_key(seed);
    let identity = key.verifying_key().to_bytes().to_vec();
    EngineBuilder::new(storage)
        .identity(identity)
        .account_identity_proof_signer(Arc::new(SeedProofSigner(key)))
        .feature_registry(registry)
        .peeler(Box::new(PassthroughPeeler))
        .convergence_clock(Arc::new(clock.clone()))
        .build()
        .expect("engine")
}

fn build_device_client(
    seed: &[u8],
    storage: SqliteAccountStorage,
    clock: &ManualConvergenceClock,
) -> Engine<SqliteAccountStorage> {
    let mut supported: Vec<_> = default_group_components().into_iter().collect();
    supported.extend([
        ACCOUNT_DEVICES_COMPONENT_ID,
        DEVICE_ROSTER_COMPONENT_ID,
        NOSTR_ROUTING_COMPONENT_ID,
    ]);
    let key = signing_key(seed);
    let identity = key.verifying_key().to_bytes().to_vec();
    EngineBuilder::new(storage)
        .identity(identity)
        .account_identity_proof_signer(Arc::new(SeedProofSigner(key)))
        .feature_registry(account_devices_registry())
        .supported_app_components(supported)
        .peeler(Box::new(PassthroughPeeler))
        .convergence_clock(Arc::new(clock.clone()))
        .build()
        .expect("device engine")
}

fn stored_mls_group(storage: &SqliteAccountStorage, group_id: &GroupId) -> MlsGroup {
    MlsGroup::load(
        storage.mls_storage(),
        &openmls::group::GroupId::from_slice(group_id.as_slice()),
    )
    .expect("load mls group")
    .expect("mls group exists")
}

fn assert_injected_prepare_pending_error<T: std::fmt::Debug>(result: &Result<T, EngineError>) {
    assert!(
        matches!(
            result,
            Err(EngineError::InvalidTransition(t))
                if t.from == "FaultInjected" && t.to == "PendingPublish"
        ),
        "expected injected prepare_pending failure, got {result:?}"
    );
}

fn key_package_ref_bytes(kp: &KeyPackage) -> Vec<u8> {
    hex::decode(
        crate::key_package::key_package_metadata(kp)
            .unwrap()
            .key_package_ref_hex,
    )
    .unwrap()
}

fn leaf_signature_key_bytes(kp: &KeyPackage) -> Vec<u8> {
    crate::key_package::key_package_metadata(kp)
        .unwrap()
        .leaf_signature_key
}

fn device_entry(label: &str) -> DeviceEntryV1 {
    DeviceEntryV1 {
        label: label.into(),
        client: "test-client".into(),
        ..DeviceEntryV1::default()
    }
}

async fn create_two_member_group(
    clock: &ManualConvergenceClock,
    registry_fn: fn() -> FeatureRegistry,
) -> (
    SqliteAccountStorage,
    Engine<SqliteAccountStorage>,
    Engine<SqliteAccountStorage>,
    GroupId,
) {
    let alice_storage = SqliteAccountStorage::in_memory_for_test().unwrap();
    let bob_storage = SqliteAccountStorage::in_memory_for_test().unwrap();
    let mut alice = build_client(
        b"rollback-alice",
        alice_storage.clone(),
        clock,
        registry_fn(),
    );
    let mut bob = build_client(b"rollback-bob", bob_storage, clock, registry_fn());
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (group_id, created) = alice
        .create_group(CreateGroupRequest {
            name: "initial name".into(),
            description: "initial desc".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let SendResult::FoundingGroupCreated { welcomes } = created else {
        panic!("expected FoundingGroupCreated");
    };
    let welcome = seal_and_bind(&mut alice, &welcomes).remove(0);
    join_raw(&mut bob, welcome).await;
    (alice_storage, alice, bob, group_id)
}

async fn create_solo_device_group(
    clock: &ManualConvergenceClock,
) -> (SqliteAccountStorage, Engine<SqliteAccountStorage>, GroupId) {
    let storage = SqliteAccountStorage::in_memory_for_test().unwrap();
    let mut phone = build_device_client(b"rollback-device-account", storage.clone(), clock);
    let mut roster = DeviceRosterV1 {
        leaf_tag_key: [0x33; 32].into(),
        ..DeviceRosterV1::default()
    };
    roster.devices.insert(
        [1; 32],
        DeviceEntryV1 {
            tag_signature_key: Some(phone.own_signature_key()),
            ..device_entry("Phone")
        },
    );
    let (group_id, created) = phone
        .create_group(CreateGroupRequest {
            name: String::new(),
            description: String::new(),
            members: vec![],
            required_features: vec![],
            app_components: vec![AppComponentData {
                component_id: DEVICE_ROSTER_COMPONENT_ID,
                data: encode_device_roster_v1(&roster).unwrap(),
            }],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    assert!(matches!(created, SendResult::FoundingGroupCreated { .. }));
    (storage, phone, group_id)
}

#[tokio::test]
async fn self_update_prepare_pending_failure_leaves_no_orphans_and_retries() {
    let clock = ManualConvergenceClock::new(1_000, 10_000);
    let (storage, mut alice, _bob, group_id) =
        create_two_member_group(&clock, FeatureRegistry::new).await;
    let before_messages = storage.list_messages(&group_id, EpochId(0)).unwrap();
    let before_group = storage.get_group(&group_id).unwrap();

    alice.epoch_manager.fail_next_prepare_pending_for_test();
    let result = alice
        .send(SendIntent::SelfUpdate {
            group_id: group_id.clone(),
        })
        .await;
    assert_injected_prepare_pending_error(&result);

    assert!(
        stored_mls_group(&storage, &group_id)
            .pending_commit()
            .is_none()
    );
    assert_eq!(
        storage.list_messages(&group_id, EpochId(0)).unwrap(),
        before_messages,
        "failed SelfUpdate prepare_pending must leave no orphaned Sent commit rows"
    );
    assert!(
        storage
            .maintenance_storage()
            .unwrap()
            .list_group_evolutions_for_group(&group_id)
            .unwrap()
            .is_empty(),
        "failed SelfUpdate prepare_pending must leave no Preparing/Prepared evolution row"
    );
    assert_eq!(storage.get_group(&group_id).unwrap(), before_group);
    assert!(alice.epoch_state(&group_id).unwrap().is_stable());

    let SendResult::GroupEvolution { pending, .. } = alice
        .send(SendIntent::SelfUpdate {
            group_id: group_id.clone(),
        })
        .await
        .expect("retry SelfUpdate succeeds")
    else {
        panic!("expected GroupEvolution");
    };
    alice.confirm_published(pending).await.unwrap();
    assert_eq!(
        alice.epoch(&group_id).unwrap(),
        EpochId(before_group.epoch.0 + 1)
    );
}

#[tokio::test]
async fn disband_prepare_pending_failure_leaves_no_orphans_and_retries() {
    let clock = ManualConvergenceClock::new(1_000, 10_000);
    let (storage, mut alice, _bob, group_id) =
        create_two_member_group(&clock, FeatureRegistry::new).await;

    assert!(matches!(
        alice
            .send(SendIntent::Disband {
                group_id: group_id.clone(),
            })
            .await
            .unwrap(),
        SendResult::DisbandRequested { .. }
    ));
    let before_messages = storage.list_messages(&group_id, EpochId(0)).unwrap();
    let before_request = storage.disband_request(&group_id).unwrap();
    assert_eq!(
        before_request.as_ref().and_then(|r| r.last_prepared_epoch),
        None
    );

    alice.epoch_manager.fail_next_prepare_pending_for_test();
    let result = alice.prepare_pending_disband(&group_id).await;
    assert_injected_prepare_pending_error(&result);

    assert!(
        stored_mls_group(&storage, &group_id)
            .pending_commit()
            .is_none()
    );
    assert_eq!(
        storage.list_messages(&group_id, EpochId(0)).unwrap(),
        before_messages,
        "failed disband prepare_pending must leave no orphaned Sent commit rows"
    );
    assert!(
        storage
            .list_disband_candidates(&group_id)
            .unwrap()
            .is_empty(),
        "failed disband prepare_pending must leave no orphaned DisbandCandidate rows"
    );
    assert_eq!(
        storage.disband_request(&group_id).unwrap(),
        before_request,
        "failed disband prepare_pending must not advance DisbandRequest.last_prepared_epoch"
    );
    assert!(alice.epoch_state(&group_id).unwrap().is_stable());

    let Some(SendResult::GroupEvolution { pending, .. }) = alice
        .prepare_pending_disband(&group_id)
        .await
        .expect("retry disband preparation succeeds")
    else {
        panic!("expected GroupEvolution");
    };
    alice.confirm_published(pending).await.unwrap();
}

#[tokio::test]
async fn invite_prepare_pending_failure_leaves_no_orphans_and_retries() {
    let clock = ManualConvergenceClock::new(1_000, 10_000);
    let (storage, mut alice, _bob, group_id) =
        create_two_member_group(&clock, FeatureRegistry::new).await;
    let mut carol = build_client(
        b"rollback-carol",
        SqliteAccountStorage::in_memory_for_test().unwrap(),
        &clock,
        FeatureRegistry::new(),
    );
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let before_messages = storage.list_messages(&group_id, EpochId(0)).unwrap();
    let before_group = storage.get_group(&group_id).unwrap();

    alice.epoch_manager.fail_next_prepare_pending_for_test();
    let result = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![carol_kp.clone()],
            initial_admins: vec![],
        })
        .await;
    assert_injected_prepare_pending_error(&result);

    assert!(
        stored_mls_group(&storage, &group_id)
            .pending_commit()
            .is_none()
    );
    assert_eq!(
        storage.list_messages(&group_id, EpochId(0)).unwrap(),
        before_messages,
        "failed Invite prepare_pending must leave no orphaned Sent commit or staged Welcome"
    );
    assert_eq!(
        storage.get_group(&group_id).unwrap(),
        before_group,
        "failed Invite prepare_pending must not commit projected members to group_record"
    );
    assert!(alice.epoch_state(&group_id).unwrap().is_stable());

    let SendResult::GroupEvolution {
        pending, welcomes, ..
    } = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![carol_kp],
            initial_admins: vec![],
        })
        .await
        .expect("retry Invite succeeds")
    else {
        panic!("expected GroupEvolution");
    };
    let welcome = seal_and_bind(&mut alice, &welcomes).remove(0);
    alice.confirm_published(pending).await.unwrap();
    join_raw(&mut carol, welcome).await;
    assert_eq!(alice.members(&group_id).unwrap().len(), 3);
}

#[tokio::test]
async fn remove_members_prepare_pending_failure_leaves_no_orphans_and_retries() {
    let clock = ManualConvergenceClock::new(1_000, 10_000);
    let (storage, mut alice, bob, group_id) =
        create_two_member_group(&clock, FeatureRegistry::new).await;
    let bob_id = bob.self_id();
    let before_messages = storage.list_messages(&group_id, EpochId(0)).unwrap();
    let before_group = storage.get_group(&group_id).unwrap();

    alice.epoch_manager.fail_next_prepare_pending_for_test();
    let result = alice
        .send(SendIntent::RemoveMembers {
            group_id: group_id.clone(),
            members: vec![bob_id.clone()],
        })
        .await;
    assert_injected_prepare_pending_error(&result);

    assert!(
        stored_mls_group(&storage, &group_id)
            .pending_commit()
            .is_none()
    );
    assert_eq!(
        storage.list_messages(&group_id, EpochId(0)).unwrap(),
        before_messages,
        "failed RemoveMembers prepare_pending must leave no orphaned Sent commit"
    );
    assert_eq!(
        storage.get_group(&group_id).unwrap(),
        before_group,
        "failed RemoveMembers prepare_pending must keep target member in group_record"
    );
    assert!(alice.epoch_state(&group_id).unwrap().is_stable());

    let SendResult::GroupEvolution { pending, .. } = alice
        .send(SendIntent::RemoveMembers {
            group_id: group_id.clone(),
            members: vec![bob_id],
        })
        .await
        .expect("retry RemoveMembers succeeds")
    else {
        panic!("expected GroupEvolution");
    };
    alice.confirm_published(pending).await.unwrap();
    assert_eq!(alice.members(&group_id).unwrap().len(), 1);
}

#[tokio::test]
async fn update_group_data_prepare_pending_failure_leaves_no_orphans_and_retries() {
    let clock = ManualConvergenceClock::new(1_000, 10_000);
    let (storage, mut alice, _bob, group_id) =
        create_two_member_group(&clock, FeatureRegistry::new).await;
    let before_messages = storage.list_messages(&group_id, EpochId(0)).unwrap();
    let before_group = storage.get_group(&group_id).unwrap();

    alice.epoch_manager.fail_next_prepare_pending_for_test();
    let result = alice
        .send(SendIntent::UpdateGroupData {
            group_id: group_id.clone(),
            name: Some("updated name".into()),
            description: Some("updated desc".into()),
        })
        .await;
    assert_injected_prepare_pending_error(&result);

    assert!(
        stored_mls_group(&storage, &group_id)
            .pending_commit()
            .is_none()
    );
    assert_eq!(
        storage.list_messages(&group_id, EpochId(0)).unwrap(),
        before_messages,
        "failed UpdateGroupData prepare_pending must leave no orphaned Sent commit"
    );
    assert_eq!(
        storage.get_group(&group_id).unwrap(),
        before_group,
        "failed UpdateGroupData prepare_pending must not mutate group_record name/description"
    );
    assert!(alice.epoch_state(&group_id).unwrap().is_stable());

    let SendResult::GroupEvolution { pending, .. } = alice
        .send(SendIntent::UpdateGroupData {
            group_id: group_id.clone(),
            name: Some("updated name".into()),
            description: Some("updated desc".into()),
        })
        .await
        .expect("retry UpdateGroupData succeeds")
    else {
        panic!("expected GroupEvolution");
    };
    alice.confirm_published(pending).await.unwrap();
    assert_eq!(storage.get_group(&group_id).unwrap().name, "updated name");
}

#[tokio::test]
async fn upgrade_prepare_pending_failure_leaves_no_orphans_and_retries() {
    let clock = ManualConvergenceClock::new(1_000, 10_000);
    let (storage, mut alice, _bob, group_id) =
        create_two_member_group(&clock, upgradeable_registry).await;
    let before_messages = storage.list_messages(&group_id, EpochId(0)).unwrap();
    let before_group = storage.get_group(&group_id).unwrap();

    alice.epoch_manager.fail_next_prepare_pending_for_test();
    let result = alice.upgrade_group_capabilities(&group_id).await;
    assert_injected_prepare_pending_error(&result);

    assert!(
        stored_mls_group(&storage, &group_id)
            .pending_commit()
            .is_none()
    );
    assert_eq!(
        storage.list_messages(&group_id, EpochId(0)).unwrap(),
        before_messages,
        "failed upgrade prepare_pending must leave no orphaned Sent commit"
    );
    assert_eq!(storage.get_group(&group_id).unwrap(), before_group);
    assert!(alice.epoch_state(&group_id).unwrap().is_stable());

    let SendResult::GroupEvolution { pending, .. } = alice
        .upgrade_group_capabilities(&group_id)
        .await
        .expect("retry upgrade succeeds")
    else {
        panic!("expected GroupEvolution");
    };
    alice.confirm_published(pending).await.unwrap();
}

#[tokio::test]
async fn auto_commit_prepare_pending_failure_leaves_no_orphans_or_stored_proposals() {
    let clock = ManualConvergenceClock::new(1_000, 10_000);
    let (storage, mut alice, mut bob, group_id) =
        create_two_member_group(&clock, selfremove_registry).await;

    let SendResult::Proposal {
        msg: leave_proposal,
    } = bob
        .send(SendIntent::Leave {
            group_id: group_id.clone(),
        })
        .await
        .unwrap()
    else {
        panic!("expected Leave Proposal");
    };
    let before_group = storage.get_group(&group_id).unwrap();

    // Ingest Bob's SelfRemove proposal, then advance the convergence clock past
    // the auto-commit delay and inject a prepare_pending failure during drain.
    alice.ingest(leave_proposal).await.unwrap();
    let before_messages = storage.list_messages(&group_id, EpochId(0)).unwrap();
    clock.advance_ms(60_000);

    alice.epoch_manager.fail_next_prepare_pending_for_test();
    let result = alice
        .converge_and_drain_queued_outbound_intents(&group_id, clock.now().monotonic_ms)
        .await;
    assert_injected_prepare_pending_error(&result);

    let mls_after_fault = stored_mls_group(&storage, &group_id);
    assert!(
        mls_after_fault.pending_commit().is_none(),
        "failed auto-commit prepare_pending must leave no stuck pending commit"
    );
    assert!(
        !mls_after_fault.has_pending_proposals(),
        "failed auto-commit prepare_pending must remove the stored proposal from OpenMLS"
    );
    assert_eq!(
        storage.list_messages(&group_id, EpochId(0)).unwrap(),
        before_messages,
        "failed auto-commit prepare_pending must leave no orphaned Sent commit"
    );
    assert_eq!(
        storage.get_group(&group_id).unwrap(),
        before_group,
        "failed auto-commit prepare_pending must not advance projected group_record"
    );
    assert!(alice.drain_auto_publish().is_empty());
    assert!(alice.epoch_state(&group_id).unwrap().is_stable());
}

#[tokio::test]
async fn link_and_unlink_device_prepare_pending_failure_leaves_no_orphans_and_retries() {
    let clock = ManualConvergenceClock::new(1_000, 10_000);
    let (storage, mut phone, group_id) = create_solo_device_group(&clock).await;
    let mut laptop = build_device_client(
        b"rollback-device-account",
        SqliteAccountStorage::in_memory_for_test().unwrap(),
        &clock,
    );
    let laptop_kp = laptop.fresh_key_package().await.unwrap();
    let link_roster_update = encode_device_roster_update_v1(
        &DeviceRosterUpdateV1::new(vec![DeviceRosterOperationV1::SetDevice(
            [2; 32],
            DeviceEntryV1 {
                linked_by: Some([1; 32]),
                announced_key_package: Some(key_package_ref_bytes(&laptop_kp)),
                tag_signature_key: Some(leaf_signature_key_bytes(&laptop_kp)),
                ..device_entry("Laptop")
            },
        )])
        .unwrap(),
    )
    .unwrap();

    let before_messages = storage.list_messages(&group_id, EpochId(0)).unwrap();
    let before_group = storage.get_group(&group_id).unwrap();

    phone.epoch_manager.fail_next_prepare_pending_for_test();
    let link_result = phone
        .send(SendIntent::LinkDevice {
            group_id: group_id.clone(),
            key_package: laptop_kp.clone(),
            roster_update: link_roster_update.clone(),
            deliver_until: Timestamp(u64::MAX),
        })
        .await;
    assert_injected_prepare_pending_error(&link_result);

    assert!(
        stored_mls_group(&storage, &group_id)
            .pending_commit()
            .is_none()
    );
    assert_eq!(
        storage.list_messages(&group_id, EpochId(0)).unwrap(),
        before_messages,
        "failed LinkDevice prepare_pending must leave no orphaned Sent commit or staged Welcome"
    );
    assert_eq!(
        storage.get_group(&group_id).unwrap(),
        before_group,
        "failed LinkDevice prepare_pending must not mutate group_record"
    );
    assert!(phone.epoch_state(&group_id).unwrap().is_stable());

    let SendResult::GroupEvolution { pending, .. } = phone
        .send(SendIntent::LinkDevice {
            group_id: group_id.clone(),
            key_package: laptop_kp.clone(),
            roster_update: link_roster_update,
            deliver_until: Timestamp(u64::MAX),
        })
        .await
        .expect("retry LinkDevice succeeds")
    else {
        panic!("expected GroupEvolution");
    };
    phone.confirm_published(pending).await.unwrap();
    assert_eq!(phone.members(&group_id).unwrap().len(), 2);

    // Now inject a failure on UnlinkDevice for the linked laptop leaf.
    let unlink_roster_update = encode_device_roster_update_v1(
        &DeviceRosterUpdateV1::new(vec![DeviceRosterOperationV1::RemoveDevice([2; 32])]).unwrap(),
    )
    .unwrap();
    let before_unlink_messages = storage.list_messages(&group_id, EpochId(0)).unwrap();
    let before_unlink_group = storage.get_group(&group_id).unwrap();

    phone.epoch_manager.fail_next_prepare_pending_for_test();
    let unlink_result = phone
        .send(SendIntent::UnlinkDevice {
            group_id: group_id.clone(),
            leaf_signature_key: leaf_signature_key_bytes(&laptop_kp),
            roster_update: unlink_roster_update.clone(),
        })
        .await;
    assert_injected_prepare_pending_error(&unlink_result);

    assert!(
        stored_mls_group(&storage, &group_id)
            .pending_commit()
            .is_none()
    );
    assert_eq!(
        storage.list_messages(&group_id, EpochId(0)).unwrap(),
        before_unlink_messages,
        "failed UnlinkDevice prepare_pending must leave no orphaned Sent commit"
    );
    assert_eq!(
        storage.get_group(&group_id).unwrap(),
        before_unlink_group,
        "failed UnlinkDevice prepare_pending must not drop laptop from group_record"
    );
    assert!(phone.epoch_state(&group_id).unwrap().is_stable());

    let SendResult::GroupEvolution { pending, .. } = phone
        .send(SendIntent::UnlinkDevice {
            group_id: group_id.clone(),
            leaf_signature_key: leaf_signature_key_bytes(&laptop_kp),
            roster_update: unlink_roster_update,
        })
        .await
        .expect("retry UnlinkDevice succeeds")
    else {
        panic!("expected GroupEvolution");
    };
    phone.confirm_published(pending).await.unwrap();
    assert_eq!(phone.members(&group_id).unwrap().len(), 1);
}

#[tokio::test]
async fn own_account_devices_prepare_pending_failure_leaves_no_orphans_and_retries() {
    let clock = ManualConvergenceClock::new(1_000, 10_000);
    let phone_storage = SqliteAccountStorage::in_memory_for_test().unwrap();
    let mut alice_phone = build_device_client(b"rollback-alice", phone_storage.clone(), &clock);
    let mut alice_laptop = build_device_client(
        b"rollback-alice",
        SqliteAccountStorage::in_memory_for_test().unwrap(),
        &clock,
    );
    let mut bob = build_device_client(
        b"rollback-bob",
        SqliteAccountStorage::in_memory_for_test().unwrap(),
        &clock,
    );
    let laptop_kp = alice_laptop.fresh_key_package().await.unwrap();
    let bob_kp = bob.fresh_key_package().await.unwrap();

    let (group_id, created) = alice_phone
        .create_group(CreateGroupRequest {
            name: "own-account chat".into(),
            description: String::new(),
            members: vec![laptop_kp.clone(), bob_kp],
            required_features: vec![ACCOUNT_DEVICES_FEATURE],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    assert!(matches!(created, SendResult::FoundingGroupCreated { .. }));
    let before_messages = phone_storage.list_messages(&group_id, EpochId(0)).unwrap();
    let before_group = phone_storage.get_group(&group_id).unwrap();

    alice_phone
        .epoch_manager
        .fail_next_prepare_pending_for_test();
    let result = alice_phone
        .send(SendIntent::RemoveOwnAccountDevices {
            group_id: group_id.clone(),
            leaf_signature_keys: vec![leaf_signature_key_bytes(&laptop_kp)],
        })
        .await;
    assert_injected_prepare_pending_error(&result);

    assert!(
        stored_mls_group(&phone_storage, &group_id)
            .pending_commit()
            .is_none()
    );
    assert_eq!(
        phone_storage.list_messages(&group_id, EpochId(0)).unwrap(),
        before_messages,
        "failed RemoveOwnAccountDevices prepare_pending must leave no orphaned Sent commit"
    );
    assert_eq!(
        phone_storage.get_group(&group_id).unwrap(),
        before_group,
        "failed RemoveOwnAccountDevices prepare_pending must not mutate group_record"
    );
    assert!(alice_phone.epoch_state(&group_id).unwrap().is_stable());

    let SendResult::GroupEvolution { pending, .. } = alice_phone
        .send(SendIntent::RemoveOwnAccountDevices {
            group_id: group_id.clone(),
            leaf_signature_keys: vec![leaf_signature_key_bytes(&laptop_kp)],
        })
        .await
        .expect("retry RemoveOwnAccountDevices succeeds")
    else {
        panic!("expected GroupEvolution");
    };
    alice_phone.confirm_published(pending).await.unwrap();
    assert_eq!(alice_phone.members(&group_id).unwrap().len(), 2);
}

#[tokio::test]
async fn legacy_create_group_prepare_pending_failure_leaves_no_orphans_and_retries() {
    let storage = SqliteAccountStorage::in_memory_for_test().unwrap();
    let key = signing_key(b"rollback-legacy-alice");
    let mut alice = EngineBuilder::new(storage.clone())
        .legacy_compatibility_profile()
        .identity(key.verifying_key().to_bytes().to_vec())
        .account_identity_proof_signer(Arc::new(SeedProofSigner(key)))
        .peeler(Box::new(PassthroughPeeler))
        .build()
        .unwrap();

    alice.epoch_manager.fail_next_prepare_pending_for_test();
    let result = alice
        .create_group(CreateGroupRequest {
            name: "legacy group".into(),
            description: String::new(),
            members: vec![],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![alice.self_id()],
        })
        .await;
    assert_injected_prepare_pending_error(&result);
    assert!(
        storage.list_groups().unwrap().is_empty(),
        "failed legacy create_group prepare_pending must leave no orphaned group row"
    );

    let (group_id, SendResult::GroupCreated { pending, .. }) = alice
        .create_group(CreateGroupRequest {
            name: "legacy group".into(),
            description: String::new(),
            members: vec![],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![alice.self_id()],
        })
        .await
        .expect("retry legacy create_group succeeds")
    else {
        panic!("expected legacy GroupCreated");
    };
    alice.confirm_published(pending).await.unwrap();
    assert_eq!(storage.get_group(&group_id).unwrap().name, "legacy group");
}

fn app_payload_for(engine: &impl CgkaEngine, body: &str) -> Vec<u8> {
    cgka_traits::app_event::MarmotAppEvent::new(
        hex::encode(engine.self_id().as_slice()),
        1_700_000_000,
        cgka_traits::app_event::MARMOT_APP_EVENT_KIND_CHAT,
        vec![],
        body.to_string(),
    )
    .encode()
    .expect("test app event encodes")
}

fn openmls_rows_for_label(conn: &Connection, label: &[u8]) -> Vec<Vec<Value>> {
    let mut stmt = conn
        .prepare(
            "SELECT storage_key, value FROM openmls_values WHERE label = ?1 ORDER BY storage_key",
        )
        .unwrap();
    stmt.query_map([label], |row| Ok(vec![row.get(0)?, row.get(1)?]))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

struct FailedSelfRemoveCleanupFixture {
    _dir: tempfile::TempDir,
    db_path: std::path::PathBuf,
    db_key: SqlCipherKey,
    storage: SqliteAccountStorage,
    observer: Connection,
    clock: ManualConvergenceClock,
    alice: Engine<SqliteAccountStorage>,
    group_id: GroupId,
    refs_after_fault: Vec<Vec<Value>>,
    queued_after_fault: Vec<Vec<Value>>,
}

/// Drive a real `SelfRemove` auto-commit staging attempt into a `prepare_pending`
/// failure while `PendingCommitCleanupGuard::drop`'s proposal delete is aborted
/// by a SQLite trigger on `QueuedProposal`, leaving both the staged commit and
/// stored proposal intact (no torn write) until recovery resumes.
async fn trigger_failed_self_remove_guard_cleanup() -> FailedSelfRemoveCleanupFixture {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("selfremove-guard-fault.sqlite");
    let db_key = SqlCipherKey::raw([0x5a; 32]);
    let storage = SqliteAccountStorage::open_encrypted(&db_path, &db_key).unwrap();
    let clock = ManualConvergenceClock::new(1_000, 10_000);
    let mut alice = build_client(
        b"rollback-alice",
        storage.clone(),
        &clock,
        selfremove_registry(),
    );
    let mut bob = build_client(
        b"rollback-bob",
        SqliteAccountStorage::in_memory_for_test().unwrap(),
        &clock,
        selfremove_registry(),
    );
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (group_id, created) = alice
        .create_group(CreateGroupRequest {
            name: "selfremove guard fault".into(),
            description: String::new(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let SendResult::FoundingGroupCreated { welcomes } = created else {
        panic!("expected FoundingGroupCreated");
    };
    let welcome = seal_and_bind(&mut alice, &welcomes).remove(0);
    join_raw(&mut bob, welcome).await;

    let SendResult::Proposal {
        msg: leave_proposal,
    } = bob
        .send(SendIntent::Leave {
            group_id: group_id.clone(),
        })
        .await
        .unwrap()
    else {
        panic!("expected Leave Proposal");
    };
    let before_group = storage.get_group(&group_id).unwrap();
    alice.ingest(leave_proposal).await.unwrap();
    clock.advance_ms(60_000);

    let observer = Connection::open(&db_path).unwrap();
    open_hardened_sqlcipher(&observer, &db_key, SqlCipherHardening::live_cache()).unwrap();
    observer
        .execute_batch(
            "CREATE TRIGGER fail_queued_proposal_delete \
             BEFORE DELETE ON openmls_values \
             WHEN OLD.label = CAST('QueuedProposal' AS BLOB) \
             BEGIN SELECT RAISE(ABORT, 'injected-proposal-delete-fault'); END;",
        )
        .unwrap();

    alice.epoch_manager.fail_next_prepare_pending_for_test();
    let result = alice
        .converge_and_drain_queued_outbound_intents(&group_id, clock.now().monotonic_ms)
        .await;
    assert_injected_prepare_pending_error(&result);

    // Guard drop failed under the trigger: ProposalQueueRefs and QueuedProposal
    // must remain consistent (no torn write), and clear_pending_commit rolled back.
    let refs_after_fault = openmls_rows_for_label(&observer, b"ProposalQueueRefs");
    let queued_after_fault = openmls_rows_for_label(&observer, b"QueuedProposal");
    assert!(!refs_after_fault.is_empty());
    assert!(!queued_after_fault.is_empty());
    let mls_after_fault = stored_mls_group(&storage, &group_id);
    assert!(mls_after_fault.pending_commit().is_some());
    assert!(mls_after_fault.has_pending_proposals());
    assert_eq!(storage.get_group(&group_id).unwrap(), before_group);
    assert!(alice.drain_auto_publish().is_empty());
    assert!(alice.epoch_state(&group_id).unwrap().is_stable());

    FailedSelfRemoveCleanupFixture {
        _dir: dir,
        db_path,
        db_key,
        storage,
        observer,
        clock,
        alice,
        group_id,
        refs_after_fault,
        queued_after_fault,
    }
}

#[tokio::test]
async fn auto_commit_guard_drop_fault_resumes_on_engine_retry_and_allows_send() {
    let mut fixture = trigger_failed_self_remove_guard_cleanup().await;

    // While the storage fault persists, a retry must fail cleanly without tearing
    // ProposalQueueRefs from QueuedProposal or dropping ownership of the cleanup.
    let still_failing = fixture
        .alice
        .converge_and_drain_queued_outbound_intents(
            &fixture.group_id,
            fixture.clock.now().monotonic_ms,
        )
        .await;
    assert!(still_failing.is_err());
    assert_eq!(
        openmls_rows_for_label(&fixture.observer, b"ProposalQueueRefs"),
        fixture.refs_after_fault
    );
    assert_eq!(
        openmls_rows_for_label(&fixture.observer, b"QueuedProposal"),
        fixture.queued_after_fault
    );

    // Once the storage fault clears, normal engine retry resumes unfinished
    // cleanup, stages the SelfRemove auto-commit, and outbound chat succeeds.
    fixture
        .observer
        .execute_batch("DROP TRIGGER fail_queued_proposal_delete")
        .unwrap();
    fixture
        .alice
        .converge_and_drain_queued_outbound_intents(
            &fixture.group_id,
            fixture.clock.now().monotonic_ms,
        )
        .await
        .expect("normal retry resumes unfinished cleanup and stages SelfRemove");
    let mut auto_publishes = fixture.alice.drain_auto_publish();
    assert_eq!(
        auto_publishes.len(),
        1,
        "retry must stage SelfRemove rather than deferring on leftover proposals"
    );
    fixture
        .alice
        .confirm_published(auto_publishes.remove(0).pending)
        .await
        .unwrap();
    let mls_after_confirm = stored_mls_group(&fixture.storage, &fixture.group_id);
    assert!(mls_after_confirm.pending_commit().is_none());
    assert!(!mls_after_confirm.has_pending_proposals());
    assert_eq!(fixture.alice.members(&fixture.group_id).unwrap().len(), 1);

    let sent = fixture
        .alice
        .send(SendIntent::AppMessage {
            group_id: fixture.group_id.clone(),
            payload: app_payload_for(&fixture.alice, "post-recovery chat"),
            expected_epoch: None,
            only_to_members: None,
        })
        .await
        .expect("outbound chat send succeeds after retry recovery");
    assert!(matches!(sent, SendResult::ApplicationMessage { .. }));
}

#[tokio::test]
async fn auto_commit_guard_drop_fault_resumes_before_direct_outbound_chat_send() {
    let mut fixture = trigger_failed_self_remove_guard_cleanup().await;

    fixture
        .observer
        .execute_batch("DROP TRIGGER fail_queued_proposal_delete")
        .unwrap();

    // Even without an explicit convergence retry first, an outbound chat send
    // must resume the unfinished cleanup rather than failing on OpenMLS's
    // leftover pending commit / proposal queue. Because Bob's SelfRemove
    // auto-commit is already due, `do_send` cleans up, stages the SelfRemove
    // auto-commit, and queues the chat behind the departure instead of failing
    // with `GroupStateError(PendingProposal)`.
    let sent = fixture
        .alice
        .send(SendIntent::AppMessage {
            group_id: fixture.group_id.clone(),
            payload: app_payload_for(&fixture.alice, "direct chat after fault clears"),
            expected_epoch: None,
            only_to_members: None,
        })
        .await
        .expect("direct outbound chat send resumes unfinished cleanup instead of failing");
    assert!(
        matches!(sent, SendResult::Queued { .. }),
        "due SelfRemove should stage ahead of chat, got {sent:?}"
    );
    let mut auto_publishes = fixture.alice.drain_auto_publish();
    assert_eq!(auto_publishes.len(), 1);
    fixture
        .alice
        .confirm_published(auto_publishes.remove(0).pending)
        .await
        .unwrap();
    assert_eq!(fixture.alice.members(&fixture.group_id).unwrap().len(), 1);

    let drained = fixture
        .alice
        .converge_and_drain_queued_outbound_intents(
            &fixture.group_id,
            fixture.clock.now().monotonic_ms,
        )
        .await
        .expect("queued chat drains after SelfRemove confirmation");
    assert!(
        matches!(drained.as_slice(), [SendResult::ApplicationMessage { .. }]),
        "queued outbound chat should drain as ApplicationMessage, got {drained:?}"
    );
    let mls_after_drain = stored_mls_group(&fixture.storage, &fixture.group_id);
    assert!(mls_after_drain.pending_commit().is_none());
    assert!(!mls_after_drain.has_pending_proposals());
}

#[tokio::test]
async fn auto_commit_guard_drop_fault_recovers_on_reopen_and_allows_send() {
    let fixture = trigger_failed_self_remove_guard_cleanup().await;
    let FailedSelfRemoveCleanupFixture {
        _dir,
        db_path,
        db_key,
        storage,
        observer,
        clock,
        alice,
        group_id,
        refs_after_fault,
        queued_after_fault,
    } = fixture;

    // Simulate process restart: drop the in-memory engine completely.
    drop(alice);
    drop(storage);

    // While the storage fault persists across reopen, hydration must keep
    // proposal writes atomic (rolling back cleanly) and quarantine the group.
    let reopened_storage = SqliteAccountStorage::open_encrypted(&db_path, &db_key).unwrap();
    let mut alice_reopened = build_client(
        b"rollback-alice",
        reopened_storage.clone(),
        &clock,
        selfremove_registry(),
    );
    alice_reopened.hydrate_all_stored_groups().unwrap();
    assert_eq!(
        alice_reopened.quarantined_reason(&group_id),
        Some(cgka_traits::engine::GroupHydrationQuarantineReason::PendingCommitRecoveryFailed)
    );
    assert_eq!(
        openmls_rows_for_label(&observer, b"ProposalQueueRefs"),
        refs_after_fault
    );
    assert_eq!(
        openmls_rows_for_label(&observer, b"QueuedProposal"),
        queued_after_fault
    );

    // Once the storage fault clears, retrying hydration recovers the unpublished
    // SelfRemove commit and stored proposal atomically so outbound chat and
    // auto-commit retry both succeed.
    observer
        .execute_batch("DROP TRIGGER fail_queued_proposal_delete")
        .unwrap();
    assert!(
        alice_reopened
            .retry_hydrate_quarantined_group(&group_id)
            .unwrap()
    );
    let mls_after_reopen = stored_mls_group(&reopened_storage, &group_id);
    assert!(mls_after_reopen.pending_commit().is_none());
    assert!(!mls_after_reopen.has_pending_proposals());

    let sent = alice_reopened
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: app_payload_for(&alice_reopened, "chat after reopen recovery"),
            expected_epoch: None,
            only_to_members: None,
        })
        .await
        .expect("outbound chat send succeeds after reopen recovery");
    assert!(matches!(sent, SendResult::ApplicationMessage { .. }));

    clock.advance_ms(60_000);
    alice_reopened
        .converge_and_drain_queued_outbound_intents(&group_id, clock.now().monotonic_ms)
        .await
        .unwrap();
    let mut auto_publishes = alice_reopened.drain_auto_publish();
    assert_eq!(auto_publishes.len(), 1);
    alice_reopened
        .confirm_published(auto_publishes.remove(0).pending)
        .await
        .unwrap();
    assert_eq!(alice_reopened.members(&group_id).unwrap().len(), 1);
}

#[tokio::test]
async fn leaver_reopen_preserves_own_pending_self_remove_proposal_for_commit_apply() {
    let dir = tempfile::tempdir().unwrap();
    let bob_path = dir.path().join("bob-leaver.sqlite");
    let bob_key = SqlCipherKey::raw([0x6b; 32]);
    let clock = ManualConvergenceClock::new(1_000, 10_000);

    let alice_storage = SqliteAccountStorage::in_memory_for_test().unwrap();
    let mut alice = build_client(
        b"leaver-reopen-alice",
        alice_storage,
        &clock,
        selfremove_registry(),
    );
    let bob_storage = SqliteAccountStorage::open_encrypted(&bob_path, &bob_key).unwrap();
    let mut bob = build_client(
        b"leaver-reopen-bob",
        bob_storage.clone(),
        &clock,
        selfremove_registry(),
    );
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (group_id, created) = alice
        .create_group(CreateGroupRequest {
            name: "leaver reopen".into(),
            description: String::new(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let SendResult::FoundingGroupCreated { welcomes } = created else {
        panic!("expected FoundingGroupCreated");
    };
    let welcome = seal_and_bind(&mut alice, &welcomes).remove(0);
    join_raw(&mut bob, welcome).await;

    // Bob sends Leave (SelfRemove proposal), then restarts before Alice's
    // SelfRemove commit arrives.
    let SendResult::Proposal {
        msg: leave_proposal,
    } = bob
        .send(SendIntent::Leave {
            group_id: group_id.clone(),
        })
        .await
        .unwrap()
    else {
        panic!("expected Leave Proposal");
    };
    let had_pending_proposals_before_restart =
        stored_mls_group(&bob_storage, &group_id).has_pending_proposals();
    drop(bob);
    drop(bob_storage);

    // Reopen Bob and hydrate: hydration must preserve any legitimate pending
    // SelfRemove proposal owned by the leaver (no pending_commit on Bob).
    let reopened_bob_storage = SqliteAccountStorage::open_encrypted(&bob_path, &bob_key).unwrap();
    let mut bob_reopened = build_client(
        b"leaver-reopen-bob",
        reopened_bob_storage.clone(),
        &clock,
        selfremove_registry(),
    );
    bob_reopened.hydrate_all_stored_groups().unwrap();
    assert_eq!(
        stored_mls_group(&reopened_bob_storage, &group_id).has_pending_proposals(),
        had_pending_proposals_before_restart,
        "hydration must not strip a leaving member's own stored SelfRemove proposal"
    );

    // Alice commits Bob's SelfRemove by reference; reopened Bob applies it cleanly.
    alice.ingest(leave_proposal).await.unwrap();
    clock.advance_ms(60_000);
    alice
        .converge_and_drain_queued_outbound_intents(&group_id, clock.now().monotonic_ms)
        .await
        .unwrap();
    let mut auto_publishes = alice.drain_auto_publish();
    assert_eq!(auto_publishes.len(), 1);
    let auto_publish = auto_publishes.remove(0);
    alice.confirm_published(auto_publish.pending).await.unwrap();

    let commit_msg = cgka_traits::transport::TransportMessage {
        envelope: cgka_traits::transport::TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..auto_publish.msg
    };
    bob_reopened.ingest(commit_msg).await.unwrap();
    clock.advance_ms(60_000);
    bob_reopened
        .converge_and_drain_queued_outbound_intents(&group_id, clock.now().monotonic_ms)
        .await
        .unwrap();
    assert!(
        reopened_bob_storage.get_group(&group_id).unwrap().removed,
        "reopened leaver must cleanly apply the SelfRemove commit referencing its proposal"
    );
}
