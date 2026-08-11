//! Engine behavior under **production transport visibility**.
//!
//! Every other Tier-2 file installs the pass-through `MockPeeler`, so each test
//! client can read every message regardless of which epoch state produced it.
//! Real transports do not work that way: a group message is sealed under the
//! sender's current-epoch exporter secret and carries no epoch hint, so a
//! device that never entered that epoch state sees opaque bytes.
//!
//! These tests install [`EpochSealedPeeler`] instead and assert the engine
//! behaviors that only this visibility model can exercise — starting with the
//! same-epoch fork, where post-fork traffic on a branch a device has not
//! adopted is unreadable until the convergence pass materializes that branch.

use cgka_engine::feature_registry::FeatureRegistry;
use cgka_engine::{Engine, EngineBuilder};
use cgka_traits::engine::{CgkaEngine, CreateGroupRequest, SendIntent, SendResult};
use cgka_traits::error::PeelerError;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::transport::{TransportEnvelope, TransportMessage};
use cgka_traits::types::{EpochId, GroupId, MemberId};
use std::collections::HashMap;
use storage_sqlite::SqliteAccountStorage;

mod support;
use support::epoch_sealed_peeler::{
    EpochSealedPeeler, GROUP_EVENT_EXPORTER_KEY, seal_group_payload, unseal_group_payload,
};
use support::proof_signer;

fn pad32(name: &[u8]) -> Vec<u8> {
    // Marmot credential identities MUST be a valid 32-byte x-only secp256k1
    // public key (spec/foundation/identity.md). Derive one deterministically
    // from the ergonomic label so member tracking stays stable across a run.
    use k256::schnorr::SigningKey;
    use sha2::{Digest, Sha256};
    let mut counter = 0u64;
    loop {
        let mut material = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(b"cgka-engine-test-identity-v1");
        hasher.update(name);
        hasher.update(counter.to_be_bytes());
        material.copy_from_slice(&hasher.finalize());
        if let Ok(sk) = SigningKey::from_bytes(&material) {
            return sk.verifying_key().to_bytes().to_vec();
        }
        counter += 1;
    }
}

fn build_client(id: &[u8]) -> Engine<SqliteAccountStorage> {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    EngineBuilder::new(storage)
        .legacy_compatibility_profile()
        .identity(pad32(id))
        .account_identity_proof_signer(proof_signer(id))
        .feature_registry(FeatureRegistry::new())
        .peeler(Box::new(EpochSealedPeeler))
        .build()
        .unwrap()
}

fn route(msg: TransportMessage, group_id: &GroupId) -> TransportMessage {
    TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..msg
    }
}

fn test_context(epoch: u64, secret: &[u8; 32]) -> GroupContextSnapshot {
    let mut secrets = HashMap::new();
    secrets.insert(GROUP_EVENT_EXPORTER_KEY.to_string(), secret.to_vec());
    GroupContextSnapshot::new(EpochId(epoch), secrets, Some(vec![7; 32]))
}

#[test]
fn sealed_payload_round_trips_under_the_sealing_context() {
    let ctx = test_context(4, &[0xAB; 32]);

    let sealed = seal_group_payload(b"inner mls bytes", &ctx).unwrap();

    assert_ne!(
        sealed, b"inner mls bytes",
        "a sealed payload must not carry the plaintext on the wire"
    );
    assert_eq!(
        unseal_group_payload(&sealed, &ctx).unwrap(),
        b"inner mls bytes"
    );
}

#[test]
fn sealed_payload_is_opaque_to_a_context_that_holds_a_different_epoch_secret() {
    let sender = test_context(4, &[0xAB; 32]);
    // Same epoch NUMBER, different epoch STATE: exactly the rival-branch shape.
    let rival_branch_at_same_epoch = test_context(4, &[0xCD; 32]);

    let sealed = seal_group_payload(b"inner mls bytes", &sender).unwrap();

    assert!(matches!(
        unseal_group_payload(&sealed, &rival_branch_at_same_epoch),
        Err(PeelerError::DecryptFailed)
    ));
}

#[tokio::test]
async fn ordinary_delivery_still_converges_when_the_transport_seals_per_epoch() {
    // The visibility model must not break the uncontested path: a member that
    // shares the sender's epoch state peels and applies exactly as before.
    let mut alice = build_client(b"sealed-alice");
    let mut bob = build_client(b"sealed-bob");
    let mut carol = build_client(b"sealed-carol");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "sealed".into(),
            description: String::new(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![bob.self_id()],
        })
        .await
        .unwrap();
    let welcome = match create {
        SendResult::GroupCreated {
            pending,
            mut welcomes,
        } => {
            alice.confirm_published(pending).await.unwrap();
            welcomes.remove(0)
        }
        other => panic!("unexpected create result: {other:?}"),
    };
    bob.join_welcome(welcome).await.unwrap();

    let carol_kp = carol.fresh_key_package().await.unwrap();
    let commit = match alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![carol_kp],
        })
        .await
        .unwrap()
    {
        SendResult::GroupEvolution { msg, pending, .. } => {
            alice.confirm_published(pending).await.unwrap();
            msg
        }
        other => panic!("unexpected invite result: {other:?}"),
    };

    bob.ingest(route(commit, &group_id)).await.unwrap();
    bob.converge_stored_openmls_messages_at(&group_id, u64::MAX)
        .expect("an uncontested sealed commit must settle");

    assert_eq!(bob.epoch(&group_id).unwrap().0, 2);
    assert!(
        bob.members(&group_id)
            .unwrap()
            .iter()
            .any(|member| member.id == MemberId::new(pad32(b"sealed-carol"))),
        "the invited member must be visible after an ordinary sealed delivery"
    );
}
