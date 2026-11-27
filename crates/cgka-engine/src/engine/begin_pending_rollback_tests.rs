//! Fault-injection regression tests for `begin_pending` rollback ordering (#3794).
//!
//! Each test drives a real `Engine<SqliteAccountStorage>` commit-staging path
//! with a one-shot failure injected into `EpochManager`'s pending-state
//! transition. Before the fix, durable SQLite writes (`Sent` commits, content
//! markers, staged Welcomes, `DisbandCandidate`, `DisbandRequest`,
//! `DurableGroupEvolution`, projected `group_record`) committed before
//! `begin_pending`, leaving orphaned SQLite state while
//! `PendingCommitCleanupGuard` cleared only OpenMLS's staged commit.

#![allow(clippy::disallowed_methods)]

use crate::account_identity_proof::{AccountIdentityProofRequest, AccountIdentityProofSigner};
use crate::convergence_clock::{ConvergenceClock, ManualConvergenceClock};
use crate::feature_registry::FeatureRegistry;
use crate::{Engine, EngineBuilder};
use async_trait::async_trait;
use cgka_traits::capabilities::{Capability, CapabilityRequirement, Feature, RequirementLevel};
use cgka_traits::engine::{CgkaEngine, CreateGroupRequest, SendIntent, SendResult};
use cgka_traits::error::{EngineError, PeelerError};
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{PeeledContent, PeeledMessage};
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::storage::{
    DisbandCandidateStorage, DisbandRequestStorage, GroupStorage, MessageStorage, StorageProvider,
};
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::types::{EpochId, GroupId, MemberId, MessageId};
use k256::schnorr::{SigningKey, signature::hazmat::PrehashSigner};
use openmls::group::MlsGroup;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use storage_sqlite::SqliteAccountStorage;

fn signing_key(seed: &[u8]) -> SigningKey {
    for counter in 0u64.. {
        let mut hasher = Sha256::new();
        hasher.update(b"cgka-engine-test-identity-v1");
        hasher.update(seed);
        hasher.update(counter.to_be_bytes());
        if let Ok(key) = SigningKey::from_slice(&hasher.finalize()) {
            return key;
        }
    }
    unreachable!("a signing key is found within u64 counters")
}

struct SeedProofSigner(SigningKey);

impl AccountIdentityProofSigner for SeedProofSigner {
    fn sign_account_identity_proof(
        &self,
        request: &AccountIdentityProofRequest,
    ) -> Result<[u8; 64], String> {
        Ok(self
            .0
            .sign_prehash(&request.proof_event_id()?)
            .map_err(|e| e.to_string())?
            .to_bytes())
    }
}

struct PassthroughPeeler;

fn carried(payload: &[u8], envelope: TransportEnvelope) -> TransportMessage {
    TransportMessage {
        id: MessageId::new(Sha256::digest(payload).to_vec()),
        payload: payload.to_vec(),
        timestamp: Timestamp(0),
        causal_deps: vec![],
        source: TransportSource("begin-pending-rollback-test".into()),
        envelope,
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl TransportPeeler for PassthroughPeeler {
    async fn wrap_group_recovery(
        &self,
        _message: &cgka_traits::GroupRecoveryMessage,
        _recipient: &MemberId,
    ) -> Result<TransportMessage, PeelerError> {
        Err(PeelerError::Malformed("no account channel".into()))
    }

    async fn peel_group_message(
        &self,
        msg: &cgka_traits::peeler::PreparedGroupMessage<'_>,
        _ctx: &GroupContextSnapshot,
    ) -> Result<PeeledMessage, PeelerError> {
        Ok(PeeledMessage {
            id: msg.message.id.clone(),
            group_id: None,
            sender: None,
            content: PeeledContent::MlsMessage {
                bytes: msg.message.payload.clone(),
            },
            origin: msg.message.clone(),
        })
    }

    async fn peel_welcome(&self, msg: &TransportMessage) -> Result<PeeledMessage, PeelerError> {
        Ok(PeeledMessage {
            id: msg.id.clone(),
            group_id: None,
            sender: None,
            content: PeeledContent::Welcome {
                created_at: None,
                bytes: msg.payload.clone(),
                key_package_event_id: None,
            },
            origin: msg.clone(),
        })
    }

    async fn wrap_group_message(
        &self,
        payload: &EncryptedPayload,
        _ctx: &GroupContextSnapshot,
    ) -> Result<TransportMessage, PeelerError> {
        Ok(carried(
            &payload.ciphertext,
            TransportEnvelope::GroupMessage {
                transport_group_id: Vec::new(),
            },
        ))
    }

    async fn wrap_welcome(
        &self,
        payload: &EncryptedPayload,
        recipient: &MemberId,
    ) -> Result<TransportMessage, PeelerError> {
        let mut addressed = payload.ciphertext.clone();
        addressed.extend_from_slice(recipient.as_slice());
        Ok(TransportMessage {
            id: MessageId::new(Sha256::digest(&addressed).to_vec()),
            payload: payload.ciphertext.clone(),
            timestamp: Timestamp(0),
            causal_deps: vec![],
            source: TransportSource("begin-pending-rollback-test".into()),
            envelope: TransportEnvelope::Welcome {
                recipient: recipient.clone(),
            },
        })
    }
}

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

fn stored_mls_group(storage: &SqliteAccountStorage, group_id: &GroupId) -> MlsGroup {
    MlsGroup::load(
        storage.mls_storage(),
        &openmls::group::GroupId::from_slice(group_id.as_slice()),
    )
    .expect("load mls group")
    .expect("mls group exists")
}

fn assert_injected_begin_pending_error<T: std::fmt::Debug>(result: &Result<T, EngineError>) {
    assert!(
        matches!(
            result,
            Err(EngineError::InvalidTransition(t))
                if t.from == "FaultInjected" && t.to == "PendingPublish"
        ),
        "expected injected begin_pending failure, got {result:?}"
    );
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

#[tokio::test]
async fn self_update_begin_pending_failure_leaves_no_orphans_and_retries() {
    let clock = ManualConvergenceClock::new(1_000, 10_000);
    let (storage, mut alice, _bob, group_id) =
        create_two_member_group(&clock, FeatureRegistry::new).await;
    let before_messages = storage.list_messages(&group_id, EpochId(0)).unwrap();
    let before_group = storage.get_group(&group_id).unwrap();

    alice.epoch_manager.fail_next_begin_pending_for_test();
    let result = alice
        .send(SendIntent::SelfUpdate {
            group_id: group_id.clone(),
        })
        .await;
    assert_injected_begin_pending_error(&result);

    assert!(
        stored_mls_group(&storage, &group_id)
            .pending_commit()
            .is_none()
    );
    assert_eq!(
        storage.list_messages(&group_id, EpochId(0)).unwrap(),
        before_messages,
        "failed SelfUpdate begin_pending must leave no orphaned Sent commit rows"
    );
    assert!(
        storage
            .maintenance_storage()
            .unwrap()
            .list_group_evolutions_for_group(&group_id)
            .unwrap()
            .is_empty(),
        "failed SelfUpdate begin_pending must leave no Preparing/Prepared evolution row"
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
async fn disband_begin_pending_failure_leaves_no_orphans_and_retries() {
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

    alice.epoch_manager.fail_next_begin_pending_for_test();
    let result = alice.prepare_pending_disband(&group_id).await;
    assert_injected_begin_pending_error(&result);

    assert!(
        stored_mls_group(&storage, &group_id)
            .pending_commit()
            .is_none()
    );
    assert_eq!(
        storage.list_messages(&group_id, EpochId(0)).unwrap(),
        before_messages,
        "failed disband begin_pending must leave no orphaned Sent commit rows"
    );
    assert!(
        storage
            .list_disband_candidates(&group_id)
            .unwrap()
            .is_empty(),
        "failed disband begin_pending must leave no orphaned DisbandCandidate rows"
    );
    assert_eq!(
        storage.disband_request(&group_id).unwrap(),
        before_request,
        "failed disband begin_pending must not advance DisbandRequest.last_prepared_epoch"
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
async fn invite_begin_pending_failure_leaves_no_orphans_and_retries() {
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

    alice.epoch_manager.fail_next_begin_pending_for_test();
    let result = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![carol_kp.clone()],
            initial_admins: vec![],
        })
        .await;
    assert_injected_begin_pending_error(&result);

    assert!(
        stored_mls_group(&storage, &group_id)
            .pending_commit()
            .is_none()
    );
    assert_eq!(
        storage.list_messages(&group_id, EpochId(0)).unwrap(),
        before_messages,
        "failed Invite begin_pending must leave no orphaned Sent commit or staged Welcome"
    );
    assert_eq!(
        storage.get_group(&group_id).unwrap(),
        before_group,
        "failed Invite begin_pending must not commit projected members to group_record"
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
async fn remove_members_begin_pending_failure_leaves_no_orphans_and_retries() {
    let clock = ManualConvergenceClock::new(1_000, 10_000);
    let (storage, mut alice, bob, group_id) =
        create_two_member_group(&clock, FeatureRegistry::new).await;
    let bob_id = bob.self_id();
    let before_messages = storage.list_messages(&group_id, EpochId(0)).unwrap();
    let before_group = storage.get_group(&group_id).unwrap();

    alice.epoch_manager.fail_next_begin_pending_for_test();
    let result = alice
        .send(SendIntent::RemoveMembers {
            group_id: group_id.clone(),
            members: vec![bob_id.clone()],
        })
        .await;
    assert_injected_begin_pending_error(&result);

    assert!(
        stored_mls_group(&storage, &group_id)
            .pending_commit()
            .is_none()
    );
    assert_eq!(
        storage.list_messages(&group_id, EpochId(0)).unwrap(),
        before_messages,
        "failed RemoveMembers begin_pending must leave no orphaned Sent commit"
    );
    assert_eq!(
        storage.get_group(&group_id).unwrap(),
        before_group,
        "failed RemoveMembers begin_pending must keep target member in group_record"
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
async fn update_group_data_begin_pending_failure_leaves_no_orphans_and_retries() {
    let clock = ManualConvergenceClock::new(1_000, 10_000);
    let (storage, mut alice, _bob, group_id) =
        create_two_member_group(&clock, FeatureRegistry::new).await;
    let before_messages = storage.list_messages(&group_id, EpochId(0)).unwrap();
    let before_group = storage.get_group(&group_id).unwrap();

    alice.epoch_manager.fail_next_begin_pending_for_test();
    let result = alice
        .send(SendIntent::UpdateGroupData {
            group_id: group_id.clone(),
            name: Some("updated name".into()),
            description: Some("updated desc".into()),
        })
        .await;
    assert_injected_begin_pending_error(&result);

    assert!(
        stored_mls_group(&storage, &group_id)
            .pending_commit()
            .is_none()
    );
    assert_eq!(
        storage.list_messages(&group_id, EpochId(0)).unwrap(),
        before_messages,
        "failed UpdateGroupData begin_pending must leave no orphaned Sent commit"
    );
    assert_eq!(
        storage.get_group(&group_id).unwrap(),
        before_group,
        "failed UpdateGroupData begin_pending must not mutate group_record name/description"
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
async fn upgrade_begin_pending_failure_leaves_no_orphans_and_retries() {
    let clock = ManualConvergenceClock::new(1_000, 10_000);
    let (storage, mut alice, _bob, group_id) =
        create_two_member_group(&clock, upgradeable_registry).await;
    let before_messages = storage.list_messages(&group_id, EpochId(0)).unwrap();
    let before_group = storage.get_group(&group_id).unwrap();

    alice.epoch_manager.fail_next_begin_pending_for_test();
    let result = alice.upgrade_group_capabilities(&group_id).await;
    assert_injected_begin_pending_error(&result);

    assert!(
        stored_mls_group(&storage, &group_id)
            .pending_commit()
            .is_none()
    );
    assert_eq!(
        storage.list_messages(&group_id, EpochId(0)).unwrap(),
        before_messages,
        "failed upgrade begin_pending must leave no orphaned Sent commit"
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
async fn auto_commit_begin_pending_failure_leaves_no_orphans_or_stored_proposals() {
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
    // the auto-commit delay and inject a begin_pending failure during drain.
    alice.ingest(leave_proposal).await.unwrap();
    let before_messages = storage.list_messages(&group_id, EpochId(0)).unwrap();
    clock.advance_ms(60_000);

    alice.epoch_manager.fail_next_begin_pending_for_test();
    let result = alice
        .converge_and_drain_queued_outbound_intents(&group_id, clock.now().monotonic_ms)
        .await;
    assert_injected_begin_pending_error(&result);

    let mls_after_fault = stored_mls_group(&storage, &group_id);
    assert!(
        mls_after_fault.pending_commit().is_none(),
        "failed auto-commit begin_pending must leave no stuck pending commit"
    );
    assert!(
        !mls_after_fault.has_pending_proposals(),
        "failed auto-commit begin_pending must remove the stored proposal from OpenMLS"
    );
    assert_eq!(
        storage.list_messages(&group_id, EpochId(0)).unwrap(),
        before_messages,
        "failed auto-commit begin_pending must leave no orphaned Sent commit"
    );
    assert_eq!(
        storage.get_group(&group_id).unwrap(),
        before_group,
        "failed auto-commit begin_pending must not advance projected group_record"
    );
    assert!(alice.drain_auto_publish().is_empty());
    assert!(alice.epoch_state(&group_id).unwrap().is_stable());
}
