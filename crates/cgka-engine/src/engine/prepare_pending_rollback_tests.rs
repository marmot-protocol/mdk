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

use super::test_support::{PassthroughPeeler, SeedProofSigner, signing_key};
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
use std::sync::Arc;
use storage_sqlite::SqliteAccountStorage;

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
    let SendResult::FoundingGroupCreated { mut welcomes } = created else {
        panic!("expected FoundingGroupCreated");
    };
    bob.join_welcome(welcomes.remove(0)).await.unwrap();
    (alice_storage, alice, bob, group_id)
}

async fn create_solo_device_group(
    clock: &ManualConvergenceClock,
) -> (SqliteAccountStorage, Engine<SqliteAccountStorage>, GroupId) {
    let storage = SqliteAccountStorage::in_memory_for_test().unwrap();
    let mut phone = build_device_client(b"rollback-device-account", storage.clone(), clock);
    let mut roster = DeviceRosterV1 {
        leaf_tag_key: [0x33; 32],
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
        pending,
        mut welcomes,
        ..
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
    alice.confirm_published(pending).await.unwrap();
    carol.join_welcome(welcomes.remove(0)).await.unwrap();
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
