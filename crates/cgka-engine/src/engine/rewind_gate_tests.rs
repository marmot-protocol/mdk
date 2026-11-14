//! The gates that refuse a group whose rewind restore failed (mdk#3272).
//!
//! `tests/hydration_quarantine/rewind_restore_fault.rs` drives the real fault
//! through every committing window. This test records the failure directly
//! and checks the handoff around it: every gate refuses the group before the
//! engine moves it into quarantine, the move announces it once and drops its
//! pending publication, and nothing this session clears it or commits on it.

use crate::account_identity_proof::{AccountIdentityProofRequest, AccountIdentityProofSigner};
use crate::canonicalization::CanonicalizationPolicy;
use crate::openmls_projection::OpenMlsProjectionError;
use crate::{Engine, EngineBuilder};
use async_trait::async_trait;
use cgka_traits::engine::{
    AutoPublish, CgkaEngine, CreateGroupRequest, GroupEvent, GroupHydrationQuarantineReason,
    SendIntent, SendResult,
};
use cgka_traits::error::{EngineError, PeelerError};
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{PeeledContent, PeeledMessage};
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::storage::{OutboundIntentStorage, StorageProvider};
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::types::{MemberId, MessageId};
use k256::schnorr::{SigningKey, signature::hazmat::PrehashSigner};
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

/// Carries every message verbatim.
struct PassthroughPeeler;

fn carried(payload: &[u8], envelope: TransportEnvelope) -> TransportMessage {
    TransportMessage {
        id: MessageId::new(Sha256::digest(payload).to_vec()),
        payload: payload.to_vec(),
        timestamp: Timestamp(0),
        causal_deps: vec![],
        source: TransportSource("rewind-gate-test".into()),
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
                transport_group_id: vec![],
            },
        ))
    }

    async fn wrap_welcome(
        &self,
        payload: &EncryptedPayload,
        recipient: &MemberId,
    ) -> Result<TransportMessage, PeelerError> {
        let mut message = carried(
            &payload.ciphertext,
            TransportEnvelope::Welcome {
                recipient: recipient.clone(),
            },
        );
        message.id = MessageId::new(
            Sha256::new()
                .chain_update(&payload.ciphertext)
                .chain_update(recipient.as_slice())
                .finalize()
                .to_vec(),
        );
        Ok(message)
    }
}

fn client(seed: &[u8]) -> (Engine<SqliteAccountStorage>, SqliteAccountStorage) {
    let storage = SqliteAccountStorage::in_memory_for_test().unwrap();
    let key = signing_key(seed);
    let engine = EngineBuilder::new(storage.clone())
        .legacy_compatibility_profile()
        .identity(key.verifying_key().to_bytes().to_vec())
        .account_identity_proof_signer(Arc::new(SeedProofSigner(key)))
        .peeler(Box::new(PassthroughPeeler))
        .build()
        .unwrap();
    (engine, storage)
}

#[tokio::test]
async fn unknown_routes_do_not_cache() {
    let (mut engine, _) = client(b"unknown-route-cache");
    for route in 0..32u8 {
        let message = carried(
            &[route],
            TransportEnvelope::GroupMessage {
                transport_group_id: vec![route; 32],
            },
        );
        assert!(matches!(
            engine.ingest(message).await.unwrap(),
            cgka_traits::IngestOutcome::Ignored {
                category: cgka_traits::InputRejectionCategory::UnknownGroup,
            }
        ));
        assert!(
            engine.deferred_peel.is_empty(),
            "unknown routing ids must not allocate per-group recovery state"
        );
    }
}

#[tokio::test]
async fn a_failed_rewind_restore_quarantines_its_group_for_the_session() {
    let (mut alice, storage) = client(b"alice-rewind-gate");
    let (mut bob, _) = client(b"bob-rewind-gate");
    let (mut carol, _) = client(b"carol-rewind-gate");
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (group, created) = alice
        .create_group(CreateGroupRequest {
            name: "rewind gates".into(),
            description: String::new(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![alice.self_id()],
        })
        .await
        .unwrap();
    let SendResult::GroupCreated { pending, .. } = created else {
        panic!("expected GroupCreated");
    };
    alice.confirm_published(pending).await.unwrap();
    // A staged invite: its commit is pending and its intent is recorded.
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let staged = alice
        .send(SendIntent::Invite {
            group_id: group.clone(),
            key_packages: vec![carol_kp],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let SendResult::GroupEvolution { pending, msg, .. } = staged else {
        panic!("expected a staged evolution, got {staged:?}");
    };
    alice.auto_publish_buf.push_back(AutoPublish {
        msg: msg.clone(),
        pending,
        welcomes: vec![],
    });
    let image = storage.group_replay_state_fingerprint(&group).unwrap();
    let intents = storage.list_own_commit_intents(Some(&group)).unwrap();
    assert!(!intents.is_empty(), "the staged invite records its intent");
    let _ = alice.drain_events();

    // A guard records the failure; every gate reads it before the engine
    // moves the group into quarantine.
    alice.rewinds.fail_for_test(&group);
    let unknown = |result: Result<(), EngineError>, gate: &str| {
        assert!(
            matches!(&result, Err(EngineError::UnknownGroup(id)) if *id == group),
            "{gate} must refuse the group, got {result:?}"
        );
    };
    let missing = |result: Result<(), OpenMlsProjectionError>, gate: &str| {
        assert!(
            matches!(result, Err(OpenMlsProjectionError::MissingGroup)),
            "{gate} must refuse the group, got {result:?}"
        );
    };
    let quarantined = vec![(
        group.clone(),
        GroupHydrationQuarantineReason::RewindRestoreFailed,
    )];
    unknown(alice.epoch(&group).map(drop), "epoch");
    assert!(!alice.live_group_ids().unwrap().contains(&group));
    assert_eq!(alice.quarantined_groups(), quarantined);

    // The host's next drain quarantines it, once, discarding its pending
    // publication and staged publish work.
    let events = alice.drain_events();
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(
                event,
                GroupEvent::GroupHydrationQuarantined { group_id, reason }
                    if *group_id == group
                        && *reason == GroupHydrationQuarantineReason::RewindRestoreFailed
            ))
            .count(),
        1,
        "{events:?}"
    );
    assert!(alice.drain_events().is_empty());
    assert_eq!(alice.quarantined_groups(), quarantined);
    assert!(alice.drain_auto_publish().is_empty());
    assert!(alice.auto_publish_buf.is_empty());
    assert!(matches!(
        alice.confirm_published(pending).await,
        Err(EngineError::UnknownPending)
    ));
    assert!(matches!(
        alice.publish_failed(pending).await,
        Err(EngineError::UnknownPending)
    ));

    // The side gates refuse it, and nothing clears it this session.
    for intent in &intents {
        unknown(
            alice
                .reissue_superseded_own_commit(&intent.commit_id)
                .map(drop),
            "reissue_superseded_own_commit",
        );
    }
    assert!(
        alice
            .reissue_superseded_own_commits_from_state()
            .unwrap()
            .is_empty()
    );
    missing(
        alice.set_group_convergence_policy(&group, CanonicalizationPolicy::default()),
        "set_group_convergence_policy",
    );
    missing(
        alice.buffer_openmls_convergence_message(&group, msg),
        "buffer_openmls_convergence_message",
    );
    // A host's scheduler gets an answer: nothing this device can resolve.
    assert!(!alice.has_pending_convergence_inputs(&group).unwrap());
    assert!(!alice.retry_hydrate_quarantined_group(&group).unwrap());
    assert!(!alice.leave_hydration_quarantine(&group));
    assert_eq!(alice.quarantined_groups(), quarantined);

    assert_eq!(
        storage.group_replay_state_fingerprint(&group).unwrap(),
        image
    );
    assert_eq!(
        storage.list_own_commit_intents(Some(&group)).unwrap(),
        intents
    );
}

// A failed restore leaves a retained anchor's OpenMLS state in the store until
// the next open, so no engine path may load it (mdk#3280). Every other
// quarantine keeps genuine local state, which its repair reads.
#[tokio::test]
async fn openmls_loads_refuse_only_a_failed_rewind_restore() {
    let (mut alice, _) = client(b"alice-mls-load-gate");
    let (group, created) = alice
        .create_group(CreateGroupRequest {
            name: "mls load gate".into(),
            description: String::new(),
            members: vec![],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![alice.self_id()],
        })
        .await
        .unwrap();
    let SendResult::GroupCreated { pending, .. } = created else {
        panic!("expected GroupCreated");
    };
    alice.confirm_published(pending).await.unwrap();
    // A read through the cache leaves the object cached; a fresh load skips it.
    let loads = |alice: &Engine<SqliteAccountStorage>| {
        (
            alice.with_mls_group(&group, |mls_group| Ok(mls_group.epoch().as_u64())),
            alice
                .load_mls_group(&group)
                .map(|mls_group| mls_group.epoch().as_u64()),
        )
    };
    let refused = |alice: &Engine<SqliteAccountStorage>, when: &str| {
        let (cached, fresh) = loads(alice);
        assert!(
            matches!(&cached, Err(EngineError::UnknownGroup(id)) if *id == group),
            "the cached read must refuse the group {when}, got {cached:?}"
        );
        assert!(
            matches!(&fresh, Err(EngineError::UnknownGroup(id)) if *id == group),
            "a fresh load must refuse the group {when}, got {fresh:?}"
        );
    };
    assert!(matches!(loads(&alice), (Ok(_), Ok(_))));

    // Another reason keeps loading: a hydration retry or a re-join reads it.
    alice.enter_hydration_quarantine(
        &group,
        GroupHydrationQuarantineReason::MemberValidationFailed,
    );
    assert!(matches!(loads(&alice), (Ok(_), Ok(_))));
    let cached_at = alice.storage.mls_write_generation();
    assert!(alice.leave_hydration_quarantine(&group));

    // A failed restore is refused from the moment the guard records it, and
    // after the engine moves it into quarantine. The object the last read
    // cached is still current here, so the cached read must refuse before
    // its lookup.
    alice.rewinds.fail_for_test(&group);
    assert_eq!(alice.storage.mls_write_generation(), cached_at);
    refused(&alice, "before the move");
    alice.quarantine_failed_rewinds();
    refused(&alice, "after the move");
}
