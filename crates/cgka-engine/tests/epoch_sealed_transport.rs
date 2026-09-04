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
use cgka_traits::ingest::IngestOutcome;
use cgka_traits::message::{MessageState, StoredMessagePayload};
use cgka_traits::storage::MessageStorage;
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
    build_client_with_storage(id).0
}

fn build_client_with_storage(id: &[u8]) -> (Engine<SqliteAccountStorage>, SqliteAccountStorage) {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let engine = EngineBuilder::new(storage.clone())
        .legacy_compatibility_profile()
        .identity(pad32(id))
        .account_identity_proof_signer(proof_signer(id))
        .feature_registry(FeatureRegistry::new())
        .peeler(Box::new(EpochSealedPeeler))
        .build()
        .unwrap();
    (engine, storage)
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
    let (mut bob, bob_storage) = build_client_with_storage(b"sealed-bob");
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
    assert!(
        bob_storage
            .list_group_snapshots(&group_id)
            .unwrap()
            .contains(&"openmls-retained-anchor-1".to_string()),
        "a Welcome join must atomically retain its joined epoch for later sibling-branch peeling"
    );

    let carol_kp = carol.fresh_key_package().await.unwrap();
    let commit = match alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![carol_kp],
            initial_admins: vec![],
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

#[tokio::test]
async fn incumbent_adopts_a_deeper_rival_branch_whose_traffic_only_it_can_read() {
    // The split-brain shape. Two members commit from the same epoch; the rival
    // then stacks a second commit, making its branch strictly deeper. Every
    // message after the fork is sealed under the SENDER's branch state, so the
    // incumbent — which adopted its own branch — cannot read the rival's
    // follow-on commit at all. Its epoch-1 retained anchor unseals the rival's
    // ROOT (both branches share that state), but nothing this device has
    // entered unseals anything further along the rival branch.
    //
    // Branch selection ranks on valid commit depth, and depth is counted over
    // commits the device has actually stored. If unreadable traffic never
    // becomes readable, each committer scores only its own branch's depth,
    // every device settles "stable" on its own lineage, and the group never
    // heals. Convergence must therefore be able to read a candidate branch's
    // traffic under THAT candidate's state, not only under the state this
    // device happens to have adopted.
    // Fix the equal-depth race up front: the incumbent must win on the ordering
    // key, so only the rival branch's greater DEPTH can move it. Same-epoch
    // privileged commits order by committer identity, lower identity first.
    let (incumbent_id, rival_id) = {
        let (a, b) = (b"split-one".as_slice(), b"split-two".as_slice());
        if pad32(a) < pad32(b) { (a, b) } else { (b, a) }
    };

    let (mut incumbent, incumbent_storage) = build_client_with_storage(incumbent_id);
    let mut rival = build_client(rival_id);
    let mut david = build_client(b"split-david");
    let mut eve = build_client(b"split-eve");
    let mut frank = build_client(b"split-frank");

    let rival_kp = rival.fresh_key_package().await.unwrap();
    let (group_id, create) = incumbent
        .create_group(CreateGroupRequest {
            name: "split".into(),
            description: String::new(),
            members: vec![rival_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![rival.self_id()],
        })
        .await
        .unwrap();
    let welcome = match create {
        SendResult::GroupCreated {
            pending,
            mut welcomes,
        } => {
            incumbent.confirm_published(pending).await.unwrap();
            welcomes.remove(0)
        }
        other => panic!("unexpected create result: {other:?}"),
    };
    rival.join_welcome(welcome).await.unwrap();
    assert_eq!(incumbent.epoch(&group_id).unwrap().0, 1);
    assert_eq!(rival.epoch(&group_id).unwrap().0, 1);

    // The fork: both admins commit from epoch 1, neither having seen the other.
    let david_kp = david.fresh_key_package().await.unwrap();
    let eve_kp = eve.fresh_key_package().await.unwrap();
    let incumbent_pending = match incumbent
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david_kp],
            initial_admins: vec![],
        })
        .await
        .unwrap()
    {
        SendResult::GroupEvolution { pending, .. } => pending,
        other => panic!("unexpected incumbent invite result: {other:?}"),
    };
    let rival_root = match rival
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![eve_kp],
            initial_admins: vec![],
        })
        .await
        .unwrap()
    {
        SendResult::GroupEvolution { msg, pending, .. } => {
            rival.confirm_published(pending).await.unwrap();
            msg
        }
        other => panic!("unexpected rival invite result: {other:?}"),
    };
    // Confirm the incumbent's own commit so it is on its own branch at epoch 2.
    incumbent
        .confirm_published(incumbent_pending)
        .await
        .unwrap();
    assert_eq!(incumbent.epoch(&group_id).unwrap().0, 2);

    // The rival branch grows deeper: a second commit from ITS epoch 2, sealed
    // under a state the incumbent has never entered.
    let frank_kp = frank.fresh_key_package().await.unwrap();
    let rival_follow_on = match rival
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![frank_kp],
            initial_admins: vec![],
        })
        .await
        .unwrap()
    {
        SendResult::GroupEvolution { msg, pending, .. } => {
            rival.confirm_published(pending).await.unwrap();
            msg
        }
        other => panic!("unexpected rival follow-on result: {other:?}"),
    };
    assert_eq!(rival.epoch(&group_id).unwrap().0, 3);

    // The rival's ROOT shares the incumbent's epoch-1 state, so the retained
    // anchor unseals it and it enters convergence as a same-epoch rival.
    let root_outcome = incumbent
        .ingest(route(rival_root, &group_id))
        .await
        .unwrap();
    assert!(
        matches!(root_outcome, IngestOutcome::Buffered { .. }),
        "the rival root must enter convergence, got {root_outcome:?}"
    );
    // The follow-on is sealed under a state this device has never entered, so
    // direct ingest cannot read it at all. This is the premise of the test, not
    // a defect: only a pass that materializes the rival branch can unseal it.
    let follow_on_outcome = incumbent
        .ingest(route(rival_follow_on, &group_id))
        .await
        .unwrap();
    assert!(
        matches!(follow_on_outcome, IngestOutcome::TransportDeferred { .. }),
        "the rival follow-on must be unreadable at direct ingest, got {follow_on_outcome:?}"
    );

    // Drive the production drain past its quiescence window. Each pass may
    // reveal one further commit along the rival branch, so the drain is what
    // walks the branch — not a single canonicalization pass.
    for _ in 0..4 {
        incumbent
            .converge_and_drain_queued_outbound_intents(&group_id, u64::MAX)
            .await
            .unwrap();
    }

    assert_eq!(
        incumbent.epoch(&group_id).unwrap().0,
        3,
        "the incumbent must adopt the deeper rival branch"
    );
    let mut incumbent_members = member_ids(&incumbent, &group_id);
    let mut rival_members = member_ids(&rival, &group_id);
    incumbent_members.sort();
    rival_members.sort();
    assert_eq!(
        incumbent_members, rival_members,
        "both devices must end on the identical canonical state"
    );
    assert!(
        !incumbent_members.contains(&pad32(b"split-david")),
        "the abandoned own branch's invitee must be gone"
    );

    // The displaced own commit must stay reconsiderable: a peer that applied it
    // and never saw the rival branch can still make it win a later pass.
    let commit_states = stored_commit_states(&incumbent_storage, &group_id);
    assert!(
        commit_states.contains(&MessageState::ConvergenceDeferred),
        "the displaced own commit must be parked reconsiderable, got {commit_states:?}"
    );
    assert!(
        !commit_states.contains(&MessageState::EpochInvalidated),
        "no commit may be terminally invalidated by this reorg, got {commit_states:?}"
    );
}

fn member_ids(engine: &Engine<SqliteAccountStorage>, group_id: &GroupId) -> Vec<Vec<u8>> {
    engine
        .members(group_id)
        .unwrap()
        .iter()
        .map(|member| member.id.as_slice().to_vec())
        .collect()
}

/// States of every stored MLS-wire commit row for the group.
fn stored_commit_states(storage: &SqliteAccountStorage, group_id: &GroupId) -> Vec<MessageState> {
    storage
        .list_messages(group_id, EpochId(0))
        .unwrap()
        .into_iter()
        .filter(|record| {
            StoredMessagePayload::decode(&record.payload)
                .ok()
                .and_then(|payload| payload.as_openmls_wire().cloned())
                .is_some_and(|message| is_commit(&message.payload))
        })
        .map(|record| record.state)
        .collect()
}

fn is_commit(mls_bytes: &[u8]) -> bool {
    use openmls::prelude::{MlsMessageIn, tls_codec::Deserialize as _};
    let Ok(message) = MlsMessageIn::tls_deserialize_exact(mls_bytes) else {
        return false;
    };
    match message.extract() {
        openmls::prelude::MlsMessageBodyIn::PrivateMessage(private) => {
            private.content_type() == openmls::prelude::ContentType::Commit
        }
        openmls::prelude::MlsMessageBodyIn::PublicMessage(public) => {
            public.content_type() == openmls::prelude::ContentType::Commit
        }
        _ => false,
    }
}
