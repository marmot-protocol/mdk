//! Ingest tests for stale classifications and application-message round trips.

use async_trait::async_trait;
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_engine::{Engine, EngineBuilder};
use cgka_traits::app_event::{MARMOT_APP_EVENT_KIND_CHAT, MarmotAppEvent};
use cgka_traits::capabilities::{Capability, CapabilityRequirement, Feature, RequirementLevel};
use cgka_traits::engine::{CgkaEngine, CreateGroupRequest, GroupEvent, SendIntent, SendResult};
use cgka_traits::error::PeelerError;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{IngestOutcome, PeeledContent, PeeledMessage, StaleReason};
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::types::{MemberId, MessageId};
use std::collections::HashSet;
use std::sync::Mutex;
use storage_memory::MemoryStorage;

mod support;
use support::proof_signer;

fn pad32(name: &[u8]) -> Vec<u8> {
    // Marmot credential identities MUST be a valid 32-byte x-only secp256k1
    // public key (spec/foundation/identity.md). Derive one deterministically
    // from the ergonomic label so admin/member tracking stays stable across a
    // run while the engine accepts the identity.
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

struct MockPeeler;
struct FailOncePeeler {
    failed: Mutex<HashSet<MessageId>>,
}

impl FailOncePeeler {
    fn new() -> Self {
        Self {
            failed: Mutex::new(HashSet::new()),
        }
    }
}

fn hash_id(bytes: &[u8]) -> MessageId {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    bytes.hash(&mut h);
    MessageId::new(h.finish().to_be_bytes().to_vec())
}

#[async_trait]
impl TransportPeeler for MockPeeler {
    async fn peel_group_message(
        &self,
        msg: &TransportMessage,
        _ctx: &GroupContextSnapshot,
    ) -> Result<PeeledMessage, PeelerError> {
        Ok(PeeledMessage {
            id: msg.id.clone(),
            group_id: None,
            sender: None,
            content: PeeledContent::MlsMessage {
                bytes: msg.payload.clone(),
            },
            origin: msg.clone(),
        })
    }

    async fn peel_welcome(&self, msg: &TransportMessage) -> Result<PeeledMessage, PeelerError> {
        Ok(PeeledMessage {
            id: msg.id.clone(),
            group_id: None,
            sender: None,
            content: PeeledContent::Welcome {
                bytes: msg.payload.clone(),
            },
            origin: msg.clone(),
        })
    }

    async fn wrap_group_message(
        &self,
        payload: &EncryptedPayload,
        _ctx: &GroupContextSnapshot,
    ) -> Result<TransportMessage, PeelerError> {
        Ok(TransportMessage {
            id: hash_id(&payload.ciphertext),
            payload: payload.ciphertext.clone(),
            timestamp: Timestamp(0),
            causal_deps: vec![],
            source: TransportSource("mock".into()),
            envelope: TransportEnvelope::GroupMessage {
                transport_group_id: vec![],
            },
        })
    }

    async fn wrap_welcome(
        &self,
        payload: &EncryptedPayload,
        recipient: &MemberId,
    ) -> Result<TransportMessage, PeelerError> {
        Ok(TransportMessage {
            id: hash_id(&payload.ciphertext),
            payload: payload.ciphertext.clone(),
            timestamp: Timestamp(0),
            causal_deps: vec![],
            source: TransportSource("mock".into()),
            envelope: TransportEnvelope::Welcome {
                recipient: recipient.clone(),
            },
        })
    }
}

#[async_trait]
impl TransportPeeler for FailOncePeeler {
    async fn peel_group_message(
        &self,
        msg: &TransportMessage,
        ctx: &GroupContextSnapshot,
    ) -> Result<PeeledMessage, PeelerError> {
        let should_fail = {
            let mut failed = self.failed.lock().unwrap();
            failed.insert(msg.id.clone())
        };
        if should_fail {
            return Err(PeelerError::DecryptFailed);
        }
        MockPeeler.peel_group_message(msg, ctx).await
    }

    async fn peel_welcome(&self, msg: &TransportMessage) -> Result<PeeledMessage, PeelerError> {
        MockPeeler.peel_welcome(msg).await
    }

    async fn wrap_group_message(
        &self,
        payload: &EncryptedPayload,
        ctx: &GroupContextSnapshot,
    ) -> Result<TransportMessage, PeelerError> {
        MockPeeler.wrap_group_message(payload, ctx).await
    }

    async fn wrap_welcome(
        &self,
        payload: &EncryptedPayload,
        recipient: &MemberId,
    ) -> Result<TransportMessage, PeelerError> {
        MockPeeler.wrap_welcome(payload, recipient).await
    }
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

fn build_client(id: &[u8]) -> Engine<MemoryStorage> {
    build_client_with_peeler(id, Box::new(MockPeeler))
}

fn build_client_with_peeler(id: &[u8], peeler: Box<dyn TransportPeeler>) -> Engine<MemoryStorage> {
    EngineBuilder::new(MemoryStorage::new())
        .identity(pad32(id))
        .account_identity_proof_signer(proof_signer(id))
        .feature_registry(selfremove_registry())
        .peeler(peeler)
        .build()
        .unwrap()
}

fn app_payload_for(engine: &Engine<MemoryStorage>, payload: impl AsRef<[u8]>) -> Vec<u8> {
    let content = String::from_utf8(payload.as_ref().to_vec()).expect("test app payload is utf8");
    MarmotAppEvent::new(
        hex::encode(engine.self_id().as_slice()),
        1_700_000_000,
        MARMOT_APP_EVENT_KIND_CHAT,
        vec![],
        content,
    )
    .encode()
    .expect("test app event encodes")
}

fn app_content(payload: &[u8]) -> Vec<u8> {
    MarmotAppEvent::decode(payload)
        .expect("test app event decodes")
        .content
        .into_bytes()
}

// ── Every StaleReason reachable ─────────────────────────────────────────────

#[tokio::test]
async fn ingest_unknown_group_message_returns_unknown_group() {
    let mut engine = build_client(b"a");
    let mut group_msg_transport_group_id = vec![0xAA; 32];
    // With envelope targeting a non-existent group.
    let msg = TransportMessage {
        id: MessageId::new(vec![1; 4]),
        payload: vec![1, 2, 3],
        timestamp: Timestamp(0),
        causal_deps: vec![],
        source: TransportSource("test".into()),
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: std::mem::take(&mut group_msg_transport_group_id),
        },
    };
    let outcome = engine.ingest(msg).await.unwrap();
    assert!(matches!(
        outcome,
        IngestOutcome::Stale {
            reason: StaleReason::UnknownGroup
        }
    ));
}

#[tokio::test]
async fn ingest_welcome_for_another_client_returns_not_for_this_client() {
    let mut engine = build_client(b"me");
    let msg = TransportMessage {
        id: MessageId::new(vec![2; 4]),
        payload: vec![],
        timestamp: Timestamp(0),
        causal_deps: vec![],
        source: TransportSource("test".into()),
        envelope: TransportEnvelope::Welcome {
            recipient: MemberId::new(b"someone-else".to_vec()),
        },
    };
    let outcome = engine.ingest(msg).await.unwrap();
    assert!(matches!(
        outcome,
        IngestOutcome::Stale {
            reason: StaleReason::NotForThisClient
        }
    ));
}

#[tokio::test]
async fn ingest_duplicate_message_id_returns_already_seen() {
    let mut engine = build_client(b"me");
    let msg = TransportMessage {
        id: MessageId::new(vec![3; 4]),
        payload: vec![],
        timestamp: Timestamp(0),
        causal_deps: vec![],
        source: TransportSource("test".into()),
        envelope: TransportEnvelope::Welcome {
            recipient: MemberId::new(b"nope".to_vec()),
        },
    };
    // First ingest classifies Stale{NotForThisClient} but still records the id.
    engine.ingest(msg.clone()).await.unwrap();
    let outcome = engine.ingest(msg).await.unwrap();
    assert!(matches!(
        outcome,
        IngestOutcome::Stale {
            reason: StaleReason::AlreadySeen
        }
    ));
}

#[tokio::test]
async fn peel_deferred_message_retries_instead_of_short_circuiting() {
    let mut alice = build_client(b"alice");
    let mut bob = build_client_with_peeler(b"bob", Box::new(FailOncePeeler::new()));
    let bob_kp = bob.fresh_key_package().await.unwrap();

    let (group_id, result) = alice
        .create_group(CreateGroupRequest {
            name: "".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (pending, bob_welcome) = match result {
        SendResult::GroupCreated {
            pending,
            mut welcomes,
        } => (pending, welcomes.remove(0)),
        _ => unreachable!(),
    };
    alice.confirm_published(pending).await.unwrap();
    bob.join_welcome(bob_welcome).await.unwrap();

    let msg = match alice
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: app_payload_for(&alice, b"retry after peel"),
        })
        .await
        .unwrap()
    {
        SendResult::ApplicationMessage { msg } => TransportMessage {
            envelope: TransportEnvelope::GroupMessage {
                transport_group_id: group_id.as_slice().to_vec(),
            },
            ..msg
        },
        _ => unreachable!(),
    };

    let first = bob.ingest(msg.clone()).await.unwrap();
    assert!(matches!(
        first,
        IngestOutcome::Stale {
            reason: StaleReason::PeelFailed
        }
    ));

    let second = bob.ingest(msg).await.unwrap();
    assert!(matches!(second, IngestOutcome::Processed));
    let events = bob.drain_events();
    assert!(
        events.iter().any(
            |event| matches!(event, GroupEvent::MessageReceived { payload, .. } if app_content(payload) == b"retry after peel")
        ),
        "expected retried message to emit after peel succeeds, got {events:?}"
    );
}

#[tokio::test]
async fn ingest_own_created_message_returns_own_echo() {
    // Alice sends an app message, then ingests her own outbound message
    // (which might be echoed by the transport). The engine should classify
    // this as OwnEcho via the sent_message_ids set.
    let mut alice = build_client(b"alice");
    let mut bob = build_client(b"bob");
    let bob_kp = bob.fresh_key_package().await.unwrap();

    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "x".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let pending = match &create {
        SendResult::GroupCreated { pending, .. } => *pending,
        _ => unreachable!(),
    };
    alice.confirm_published(pending).await.unwrap();

    let app_msg = match alice
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: app_payload_for(&alice, b"hi"),
        })
        .await
        .unwrap()
    {
        SendResult::ApplicationMessage { msg } => msg,
        _ => unreachable!(),
    };

    // Re-route so the envelope resolves to alice's group.
    let routed = TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..app_msg
    };
    let outcome = alice.ingest(routed).await.unwrap();
    assert!(matches!(
        outcome,
        IngestOutcome::Stale {
            reason: StaleReason::OwnEcho
        }
    ));
    let _ = (bob, create);
}

#[tokio::test]
async fn welcome_before_commit_yields_already_at_epoch() {
    // Post create_group-simplification (we no longer emit a commit for the
    // initial group, only welcomes — see group_lifecycle.rs), this scenario
    // plays out on INVITE commits instead: if a new member joins via
    // welcome at epoch N, and then ingests the invite commit that was for
    // epoch N-1 → N, MLS rejects WrongEpoch; we classify AlreadyAtEpoch.
    //
    // Reproduction:
    //   alice creates group with bob → bob joins welcome (epoch 1)
    //   alice invites carol → produces an invite commit (epoch 1→2)
    //   carol joins via welcome (epoch 2)
    //   carol ingests the invite commit → her MLS is at epoch 2, commit
    //   targets epoch 1 → WrongEpoch → AlreadyAtEpoch.
    let mut alice = build_client(b"alice");
    let mut bob = build_client(b"bob");
    let mut carol = build_client(b"carol");
    let bob_kp = bob.fresh_key_package().await.unwrap();

    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "x".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (create_pending, bob_welcome) = match create {
        SendResult::GroupCreated {
            pending,
            mut welcomes,
        } => (pending, welcomes.remove(0)),
        _ => unreachable!(),
    };
    alice.confirm_published(create_pending).await.unwrap();
    bob.join_welcome(bob_welcome).await.unwrap();

    let carol_kp = carol.fresh_key_package().await.unwrap();
    let invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![carol_kp],
        })
        .await
        .unwrap();
    let (invite_commit, carol_welcome, invite_pending) = match invite {
        SendResult::GroupEvolution {
            msg,
            mut welcomes,
            pending,
        } => (msg, welcomes.remove(0), pending),
        _ => unreachable!(),
    };
    alice.confirm_published(invite_pending).await.unwrap();

    // Carol joins via welcome (epoch 2).
    carol.join_welcome(carol_welcome).await.unwrap();

    // Carol ingests the invite commit (epoch 1 → 2) — her MLS is already
    // at epoch 2, so process_message returns WrongEpoch, which we classify
    // as AlreadyAtEpoch.
    let routed = TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..invite_commit
    };
    let outcome = carol.ingest(routed).await.unwrap();
    assert!(
        matches!(
            outcome,
            IngestOutcome::Stale {
                reason: StaleReason::AlreadyAtEpoch { .. }
            }
        ),
        "got: {outcome:?}"
    );
}

// ── Happy path: send+ingest AppMessage ──────────────────────────────────────

#[tokio::test]
async fn send_app_message_round_trips_to_another_client() {
    let mut alice = build_client(b"alice");
    let mut bob = build_client(b"bob");
    let bob_kp = bob.fresh_key_package().await.unwrap();

    let (group_id, result) = alice
        .create_group(CreateGroupRequest {
            name: "".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let pending = match &result {
        SendResult::GroupCreated { pending, .. } => *pending,
        _ => unreachable!(),
    };
    alice.confirm_published(pending).await.unwrap();

    let welcome = match result {
        SendResult::GroupCreated { mut welcomes, .. } => welcomes.remove(0),
        _ => unreachable!(),
    };
    bob.join_welcome(welcome).await.unwrap();
    bob.drain_events();

    // Alice sends an app message.
    let send_res = alice
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: app_payload_for(&alice, b"hello bob"),
        })
        .await
        .unwrap();

    let msg = match send_res {
        SendResult::ApplicationMessage { msg } => msg,
        _ => panic!("expected ApplicationMessage"),
    };

    // Re-route the transport_group_id so bob resolves it.
    let routed = TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..msg
    };

    let outcome = bob.ingest(routed).await.unwrap();
    assert!(matches!(outcome, IngestOutcome::Processed));

    let events = bob.drain_events();
    let got_it = events.iter().any(|e| {
        matches!(
            e,
            GroupEvent::MessageReceived { sender, payload, .. }
                if sender == &alice.self_id() && app_content(payload) == b"hello bob"
        )
    });
    assert!(got_it, "expected MessageReceived; got {events:?}");
}

#[tokio::test]
async fn inbound_group_message_during_pending_publish_replays_after_rollback() {
    let mut alice = build_client(b"alice");
    let mut bob = build_client(b"bob");
    let mut carol = build_client(b"carol");
    let bob_kp = bob.fresh_key_package().await.unwrap();

    let (group_id, result) = alice
        .create_group(CreateGroupRequest {
            name: "".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (create_pending, bob_welcome) = match result {
        SendResult::GroupCreated {
            pending,
            mut welcomes,
        } => (pending, welcomes.remove(0)),
        _ => unreachable!(),
    };
    alice.confirm_published(create_pending).await.unwrap();
    bob.join_welcome(bob_welcome).await.unwrap();
    alice.drain_events();
    bob.drain_events();

    let bob_msg = match bob
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: app_payload_for(&bob, b"arrived while alice was pending"),
        })
        .await
        .unwrap()
    {
        SendResult::ApplicationMessage { msg } => TransportMessage {
            envelope: TransportEnvelope::GroupMessage {
                transport_group_id: group_id.as_slice().to_vec(),
            },
            ..msg
        },
        _ => unreachable!(),
    };

    let carol_kp = carol.fresh_key_package().await.unwrap();
    let invite_pending = match alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![carol_kp],
        })
        .await
        .unwrap()
    {
        SendResult::GroupEvolution { pending, .. } => pending,
        _ => unreachable!(),
    };

    let outcome = alice.ingest(bob_msg).await.unwrap();
    assert!(
        matches!(outcome, IngestOutcome::Buffered { .. }),
        "expected buffering while PendingPublish, got {outcome:?}"
    );
    assert!(
        alice
            .drain_events()
            .into_iter()
            .all(|e| !matches!(e, GroupEvent::MessageReceived { .. })),
        "buffered message must not emit before rollback"
    );

    alice.publish_failed(invite_pending).await.unwrap();
    let events = alice.drain_events();
    let replayed = events.iter().any(
        |e| matches!(e, GroupEvent::MessageReceived { payload, .. } if app_content(payload) == b"arrived while alice was pending"),
    );
    assert!(
        replayed,
        "expected buffered message after rollback; got {events:?}"
    );
}
