//! Ingest tests for stale classifications and application-message round trips.

use async_trait::async_trait;
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_engine::{Engine, EngineBuilder};
use cgka_traits::app_components::{
    AppComponentData, GROUP_MESSAGE_RETENTION_COMPONENT_ID, default_group_components,
};
use cgka_traits::app_event::{MARMOT_APP_EVENT_KIND_CHAT, MarmotAppEvent};
use cgka_traits::capabilities::{Capability, CapabilityRequirement, Feature, RequirementLevel};
use cgka_traits::engine::{CgkaEngine, CreateGroupRequest, GroupEvent, SendIntent, SendResult};
use cgka_traits::error::PeelerError;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{IngestOutcome, PeeledContent, PeeledMessage, StaleReason};
use cgka_traits::message::MessageState;
use cgka_traits::peeler::{GroupMessageMetadata, TransportPeeler};
use cgka_traits::storage::{MessageStorage, StorageError};
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::types::{EpochId, MemberId, MessageId};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use storage_sqlite::{SqlCipherKey, SqliteAccountStorage};

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
struct RecordingPeeler {
    seen_metadata: Arc<Mutex<Vec<GroupMessageMetadata>>>,
}
struct FailOncePeeler {
    failed: Mutex<HashSet<MessageId>>,
}
/// Structural minimum mirroring the production Nostr peeler's content-length
/// gate: a payload too short to carry a nonce-prefixed ciphertext classifies
/// as `Malformed` before any decryption attempt.
const STRUCTURAL_MIN_PAYLOAD_LEN: usize = 28;
struct MalformedShortPayloadPeeler;

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

fn content_id(msg: &TransportMessage) -> MessageId {
    use sha2::{Digest, Sha256};

    MessageId::new(Sha256::digest(&msg.payload).to_vec())
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
impl TransportPeeler for RecordingPeeler {
    async fn peel_group_message(
        &self,
        msg: &TransportMessage,
        ctx: &GroupContextSnapshot,
    ) -> Result<PeeledMessage, PeelerError> {
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

    async fn wrap_group_message_with_metadata(
        &self,
        payload: &EncryptedPayload,
        ctx: &GroupContextSnapshot,
        metadata: &GroupMessageMetadata,
    ) -> Result<TransportMessage, PeelerError> {
        self.seen_metadata.lock().unwrap().push(*metadata);
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

#[async_trait]
impl TransportPeeler for MalformedShortPayloadPeeler {
    async fn peel_group_message(
        &self,
        msg: &TransportMessage,
        ctx: &GroupContextSnapshot,
    ) -> Result<PeeledMessage, PeelerError> {
        if msg.payload.len() < STRUCTURAL_MIN_PAYLOAD_LEN {
            return Err(PeelerError::Malformed(
                "content too short for nonce-prefixed ciphertext".into(),
            ));
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

/// Garbage payload whose malformed verdict is context-dependent: it peels
/// `DecryptFailed` against the live epoch (so ingest falls through to the
/// retained-snapshot fallback) but `Malformed` against any older snapshot
/// context. This simulates a trait-permitted non-Nostr peeler: the production
/// Nostr peeler can never reach the fallback with a `Malformed` verdict, since
/// its malformed detection is a pure function of the message bytes and is
/// always caught by the direct peel first. The public `TransportPeeler`
/// contract, however, allows `StaleEpoch`-hint peelers whose malformed
/// detection is context-dependent, so the fallback seam must still treat that
/// verdict as terminal (mdk#707).
const SNAPSHOT_FALLBACK_GARBAGE: &[u8] = b"snapshot-fallback-garbage-payload";

struct SnapshotFallbackMalformedPeeler {
    malformed_below_epoch: u64,
}

#[async_trait]
impl TransportPeeler for SnapshotFallbackMalformedPeeler {
    async fn peel_group_message(
        &self,
        msg: &TransportMessage,
        ctx: &GroupContextSnapshot,
    ) -> Result<PeeledMessage, PeelerError> {
        if msg.payload == SNAPSHOT_FALLBACK_GARBAGE {
            return if ctx.epoch().0 < self.malformed_below_epoch {
                Err(PeelerError::Malformed(
                    "malformed only against an older snapshot context".into(),
                ))
            } else {
                Err(PeelerError::DecryptFailed)
            };
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

/// Pass-through peeler (identical to [`MockPeeler`]) that counts how many times
/// `peel_group_message` is invoked, so a test can assert a retired raw row is
/// not wastefully re-peeled on later replay passes.
struct CountingPeeler {
    peels: Arc<Mutex<usize>>,
}

#[async_trait]
impl TransportPeeler for CountingPeeler {
    async fn peel_group_message(
        &self,
        msg: &TransportMessage,
        ctx: &GroupContextSnapshot,
    ) -> Result<PeeledMessage, PeelerError> {
        *self.peels.lock().unwrap() += 1;
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

fn build_client(id: &[u8]) -> Engine<SqliteAccountStorage> {
    build_client_with_storage_and_peeler(
        SqliteAccountStorage::in_memory().unwrap(),
        id,
        Box::new(MockPeeler),
    )
}

fn build_client_with_peeler(
    id: &[u8],
    peeler: Box<dyn TransportPeeler>,
) -> Engine<SqliteAccountStorage> {
    build_client_with_storage_and_peeler(SqliteAccountStorage::in_memory().unwrap(), id, peeler)
}

fn build_client_with_storage(
    storage: SqliteAccountStorage,
    id: &[u8],
) -> Engine<SqliteAccountStorage> {
    build_client_with_storage_and_peeler(storage, id, Box::new(MockPeeler))
}

fn build_client_with_storage_and_peeler(
    storage: SqliteAccountStorage,
    id: &[u8],
    peeler: Box<dyn TransportPeeler>,
) -> Engine<SqliteAccountStorage> {
    EngineBuilder::new(storage)
        .identity(pad32(id))
        .account_identity_proof_signer(proof_signer(id))
        .feature_registry(selfremove_registry())
        .peeler(peeler)
        .build()
        .unwrap()
}

fn app_payload_for(engine: &Engine<SqliteAccountStorage>, payload: impl AsRef<[u8]>) -> Vec<u8> {
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

#[tokio::test]
async fn send_app_message_passes_retention_metadata_to_peeler() {
    let seen_metadata = Arc::new(Mutex::new(Vec::new()));
    let mut supported = default_group_components();
    supported.insert(GROUP_MESSAGE_RETENTION_COMPONENT_ID);
    let mut alice = EngineBuilder::new(SqliteAccountStorage::in_memory().unwrap())
        .identity(pad32(b"alice"))
        .account_identity_proof_signer(proof_signer(b"alice"))
        .feature_registry(selfremove_registry())
        .supported_app_components(supported)
        .peeler(Box::new(RecordingPeeler {
            seen_metadata: seen_metadata.clone(),
        }))
        .build()
        .unwrap();

    let (group_id, created) = alice
        .create_group(CreateGroupRequest {
            name: "retention".into(),
            description: "metadata".into(),
            members: vec![],
            required_features: vec![],
            app_components: vec![AppComponentData {
                component_id: GROUP_MESSAGE_RETENTION_COMPONENT_ID,
                data: 60u64.to_be_bytes().to_vec(),
            }],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let pending = match created {
        SendResult::GroupCreated { pending, .. } => pending,
        other => panic!("unexpected create result: {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();

    let payload = app_payload_for(&alice, b"expiring hello");
    let sent = alice
        .send(SendIntent::AppMessage { group_id, payload })
        .await
        .unwrap();
    assert!(matches!(sent, SendResult::ApplicationMessage { .. }));

    let seen = seen_metadata.lock().unwrap();
    assert_eq!(
        seen.as_slice(),
        &[GroupMessageMetadata::application(1_700_000_000, Some(60))]
    );
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
async fn malformed_peeled_welcome_is_terminal_and_restart_deduplicated() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let mut engine = build_client_with_storage(storage.clone(), b"malformed-welcome");
    let message_id = MessageId::new(vec![0x67; 32]);
    let msg = TransportMessage {
        id: message_id.clone(),
        payload: b"not an MLS welcome".to_vec(),
        timestamp: Timestamp(0),
        causal_deps: vec![],
        source: TransportSource("test".into()),
        envelope: TransportEnvelope::Welcome {
            recipient: engine.self_id(),
        },
    };

    let outcome = engine
        .ingest(msg.clone())
        .await
        .expect("malformed welcome is a per-message stale outcome");
    assert!(matches!(
        outcome,
        IngestOutcome::Stale {
            reason: StaleReason::PeelFailed
        }
    ));
    assert!(storage.has_ingress_dedup_marker(&message_id).unwrap());
    drop(engine);

    let mut reopened = build_client_with_storage(storage, b"malformed-welcome");
    let replay = reopened
        .ingest(msg)
        .await
        .expect("poisoned welcome must not hard-error after restart");
    assert!(matches!(
        replay,
        IngestOutcome::Stale {
            reason: StaleReason::AlreadySeen
        }
    ));
}

#[tokio::test]
async fn rewrapped_identical_welcome_uses_content_dedup() {
    let mut alice = build_client(b"alice-welcome-content-dedup");
    let mut bob = build_client(b"bob-welcome-content-dedup");
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (_group_id, created) = alice
        .create_group(CreateGroupRequest {
            name: "content dedup".into(),
            description: String::new(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let welcome = match created {
        SendResult::GroupCreated {
            mut welcomes,
            pending,
        } => {
            alice.confirm_published(pending).await.unwrap();
            welcomes.remove(0)
        }
        other => panic!("expected group create, got {other:?}"),
    };

    assert!(matches!(
        bob.ingest(welcome.clone()).await.unwrap(),
        IngestOutcome::Processed
    ));
    bob.drain_events();

    let rewrapped = TransportMessage {
        id: MessageId::new(vec![0x68; 32]),
        ..welcome
    };
    let outcome = bob.ingest(rewrapped).await.unwrap();
    assert!(matches!(
        outcome,
        IngestOutcome::Stale {
            reason: StaleReason::AlreadySeen
        }
    ));
    assert!(
        bob.drain_events().is_empty(),
        "content-duplicate welcome must not emit a second join"
    );
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
async fn malformed_group_message_is_stale_and_does_not_wedge_ingest() {
    let mut alice = build_client(b"alice");
    let mut bob = build_client_with_peeler(b"bob", Box::new(MalformedShortPayloadPeeler));
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

    // Anyone can publish to a group's cleartext routing tag without being a
    // member, so structurally-invalid content is ordinary hostile input. It
    // must classify as stale — never abort ingest, or one garbage event
    // starves every message queued behind it in a transport drain.
    let garbage = TransportMessage {
        id: hash_id(b"malformed garbage"),
        payload: b"too short".to_vec(),
        timestamp: Timestamp(0),
        causal_deps: vec![],
        source: TransportSource("mock".into()),
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
    };
    let outcome = bob
        .ingest(garbage)
        .await
        .expect("malformed input must classify as stale, not abort ingest");
    assert!(
        matches!(
            outcome,
            IngestOutcome::Stale {
                reason: StaleReason::PeelFailed
            }
        ),
        "expected terminal PeelFailed for malformed content, got {outcome:?}"
    );

    let msg = match alice
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: app_payload_for(&alice, b"after the garbage"),
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
    let after = bob.ingest(msg).await.unwrap();
    assert!(matches!(after, IngestOutcome::Processed));
    let events = bob.drain_events();
    assert!(
        events.iter().any(
            |event| matches!(event, GroupEvent::MessageReceived { payload, .. } if app_content(payload) == b"after the garbage")
        ),
        "expected the message behind the garbage to still deliver, got {events:?}"
    );
}

#[tokio::test]
async fn post_peel_malformed_mls_message_is_terminal_and_does_not_wedge_ingest() {
    let mut alice = build_client(b"alice-post-peel");
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let mut bob = build_client_with_storage(storage.clone(), b"bob-post-peel");
    let bob_kp = bob.fresh_key_package().await.unwrap();

    let (group_id, result) = alice
        .create_group(CreateGroupRequest {
            name: String::new(),
            description: String::new(),
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
        other => panic!("expected group create, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    bob.join_welcome(bob_welcome).await.unwrap();

    // The pass-through test peeler represents a valid authenticated wrapper;
    // only the carried MLS bytes are malformed. This must be a per-message
    // terminal disposition, not an engine error that aborts the relay drain.
    let garbage = TransportMessage {
        id: hash_id(b"authenticated wrapper with malformed MLS bytes"),
        payload: b"not an MLS message".to_vec(),
        timestamp: Timestamp(0),
        causal_deps: vec![],
        source: TransportSource("mock".into()),
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
    };
    let garbage_content_id = content_id(&garbage);
    let outcome = bob
        .ingest(garbage)
        .await
        .expect("malformed post-peel MLS bytes must not abort ingest");
    assert!(matches!(
        outcome,
        IngestOutcome::Stale {
            reason: StaleReason::PeelFailed
        }
    ));
    assert_eq!(
        storage.get_message(&garbage_content_id).unwrap().state,
        MessageState::Failed,
        "the content-derived poison row must be durable and terminal"
    );

    let msg = match alice
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: app_payload_for(&alice, b"after post-peel garbage"),
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
        other => panic!("expected app message, got {other:?}"),
    };
    assert!(matches!(
        bob.ingest(msg).await.unwrap(),
        IngestOutcome::Processed
    ));
    assert!(bob.drain_events().iter().any(
        |event| matches!(event, GroupEvent::MessageReceived { payload, .. } if app_content(payload) == b"after post-peel garbage")
    ));
}

#[tokio::test]
async fn malformed_message_buffered_during_pending_publish_lands_terminal_after_rollback() {
    let mut alice =
        build_client_with_peeler(b"alice-pending", Box::new(MalformedShortPayloadPeeler));
    let mut bob = build_client(b"bob-pending");
    let bob_kp = bob.fresh_key_package().await.unwrap();

    let (group_id, result) = alice
        .create_group(CreateGroupRequest {
            name: "original".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let pending = match result {
        SendResult::GroupCreated { pending, .. } => pending,
        _ => unreachable!(),
    };
    alice.confirm_published(pending).await.unwrap();

    // Stage a commit so the group sits in PendingPublish — the window where
    // inbound input is persisted `Retryable` for replay BEFORE the peeler
    // ever classifies it.
    let staged = match alice
        .send(SendIntent::UpdateGroupData {
            group_id: group_id.clone(),
            name: Some("doomed".into()),
            description: None,
        })
        .await
        .unwrap()
    {
        SendResult::GroupEvolution { pending, .. } => pending,
        _ => unreachable!(),
    };

    let garbage = TransportMessage {
        id: hash_id(b"malformed garbage during pending publish"),
        payload: b"too short".to_vec(),
        timestamp: Timestamp(0),
        causal_deps: vec![],
        source: TransportSource("mock".into()),
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
    };
    let buffered = alice.ingest(garbage.clone()).await.unwrap();
    assert!(
        matches!(buffered, IngestOutcome::Buffered { .. }),
        "pre-peel buffering during PendingPublish is the tested entry \
         condition, got {buffered:?}"
    );

    // Rollback returns the group to Stable and replays the buffered backlog;
    // the garbage now peels `Malformed` for the first time. The terminal
    // contract: once classification has run, the attacker-keyed row must not
    // stay in a non-terminal state that re-enters replay forever.
    alice.publish_failed(staged).await.unwrap();
    let after_replay = alice.ingest(garbage).await.unwrap();
    assert!(
        matches!(after_replay, IngestOutcome::Stale { .. }),
        "a malformed message must land terminal once classified — a \
         `Buffered` here means the stored row is still non-terminal and \
         perpetually reported as pending, got {after_replay:?}"
    );
}

#[tokio::test]
async fn malformed_via_snapshot_fallback_is_stale_and_does_not_wedge_ingest() {
    // Simulates a trait-permitted non-Nostr peeler whose `Malformed` verdict is
    // context-dependent: the direct peel at the live epoch returns
    // `DecryptFailed`, driving ingest into the retained-snapshot fallback, where
    // the peel against the older snapshot context returns `Malformed`. The
    // production Nostr peeler cannot reach this branch (its malformed detection
    // is a pure function of the bytes, so the direct peel catches it first), but
    // the fallback seam must handle the verdict identically to the direct seam:
    // terminal stale, never an aborted drain (mdk#707).
    let mut alice = build_client(b"alice");
    // The group reaches epoch 2 below (create -> 1, invite -> 2), so the
    // retained epoch-1 anchor is the only past-peel snapshot older than live.
    let live_epoch = 2u64;
    let mut bob = build_client_with_peeler(
        b"bob",
        Box::new(SnapshotFallbackMalformedPeeler {
            malformed_below_epoch: live_epoch,
        }),
    );
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
    let (pending, bob_welcome) = match result {
        SendResult::GroupCreated {
            pending,
            mut welcomes,
        } => (pending, welcomes.remove(0)),
        _ => unreachable!(),
    };
    alice.confirm_published(pending).await.unwrap();
    bob.join_welcome(bob_welcome).await.unwrap();

    // Alice invites Carol so a commit advances the group and Bob retains an
    // anchor snapshot at the pre-commit epoch — the snapshot the fallback rolls
    // back to and peels against below.
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let invite = match alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![carol_kp],
        })
        .await
        .unwrap()
    {
        SendResult::GroupEvolution { msg, pending, .. } => {
            alice.confirm_published(pending).await.unwrap();
            TransportMessage {
                envelope: TransportEnvelope::GroupMessage {
                    transport_group_id: group_id.as_slice().to_vec(),
                },
                ..msg
            }
        }
        _ => unreachable!(),
    };
    // Convergence settles a peer commit only after its quiescence window has
    // elapsed, so buffer at one instant and converge at a later one (mirroring
    // the retained-anchor convergence tests) to apply the commit and retain the
    // pre-commit epoch anchor.
    bob.buffer_openmls_convergence_message(&group_id, invite, 1_000)
        .expect("invite commit buffered");
    bob.converge_stored_openmls_messages(&group_id, 1_000_000)
        .expect("invite commit applies and retains the pre-commit anchor");
    assert_eq!(
        bob.epoch(&group_id).unwrap(),
        EpochId(live_epoch),
        "Bob must advance to the live epoch so an older retained anchor exists"
    );

    // Garbage arrives: direct peel `DecryptFailed` -> snapshot fallback peels
    // `Malformed`. The terminal contract must hold on this seam too — classify
    // stale, do not abort the drain.
    let garbage = TransportMessage {
        id: hash_id(b"malformed via snapshot fallback"),
        payload: SNAPSHOT_FALLBACK_GARBAGE.to_vec(),
        timestamp: Timestamp(0),
        causal_deps: vec![],
        source: TransportSource("mock".into()),
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
    };
    let outcome = bob
        .ingest(garbage)
        .await
        .expect("malformed snapshot-fallback peel must classify stale, not abort ingest");
    assert!(
        matches!(
            outcome,
            IngestOutcome::Stale {
                reason: StaleReason::PeelFailed
            }
        ),
        "expected terminal PeelFailed for a malformed snapshot-fallback peel, got {outcome:?}"
    );

    // The drain is not wedged: a well-formed message queued behind the garbage
    // still processes.
    let msg = match alice
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: app_payload_for(&alice, b"after the snapshot garbage"),
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
    let after = bob.ingest(msg).await.unwrap();
    assert!(matches!(after, IngestOutcome::Processed));
    let events = bob.drain_events();
    assert!(
        events.iter().any(
            |event| matches!(event, GroupEvent::MessageReceived { payload, .. } if app_content(payload) == b"after the snapshot garbage")
        ),
        "expected the message behind the garbage to still deliver, got {events:?}"
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

/// A database created before durable sent-content markers existed can still
/// contain an outbound MLS message that OpenMLS itself recognizes as ours.
/// If that echo was buffered before peeling, the library-level `OwnPrivateMessage`
/// fallback must retire the raw retry row instead of leaving it replayable.
#[tokio::test]
async fn buffered_legacy_own_echo_retires_raw_retry_row() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let mut alice = build_client_with_storage(storage.clone(), b"alice-legacy-own-echo");
    let mut bob = build_client(b"bob-legacy-own-echo");
    let bob_kp = bob.fresh_key_package().await.unwrap();

    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "legacy own echo".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (pending, mut welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    bob.join_welcome(welcomes.remove(0)).await.unwrap();

    // Roll the local store back across the send to model a legacy database
    // that has the MLS group state but no durable sent-content marker.
    const SNAPSHOT: &str = "before-legacy-own-echo";
    storage.create_group_snapshot(&group_id, SNAPSHOT).unwrap();
    let own_message = match alice
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: app_payload_for(&alice, b"legacy own echo"),
        })
        .await
        .unwrap()
    {
        SendResult::ApplicationMessage { msg } => msg,
        other => panic!("expected ApplicationMessage, got {other:?}"),
    };
    let own_content_id = content_id(&own_message);
    assert_eq!(
        storage.get_message(&own_content_id).unwrap().state,
        MessageState::Sent,
        "the modern send path must first create the marker removed below"
    );
    storage
        .rollback_group_to_snapshot(&group_id, SNAPSHOT)
        .unwrap();
    storage.release_group_snapshot(&group_id, SNAPSHOT).unwrap();
    assert!(
        matches!(
            storage.get_message(&own_content_id),
            Err(StorageError::NotFound)
        ),
        "the simulated legacy store must not retain the sent-content marker"
    );

    // Rebuild to clear the hot-process sent-id cache as a real restart would.
    drop(alice);
    let mut alice = build_client_with_storage(storage.clone(), b"alice-legacy-own-echo");
    alice.hydrate_stable_groups_from_storage().unwrap();

    // Buffer the echo before peeling while a local commit awaits publication.
    let staged = match alice
        .send(SendIntent::UpdateGroupData {
            group_id: group_id.clone(),
            name: Some("pending".into()),
            description: None,
        })
        .await
        .unwrap()
    {
        SendResult::GroupEvolution { pending, .. } => pending,
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    let raw_id = MessageId::new(b"legacy-own-echo-wrapper".to_vec());
    let echoed = TransportMessage {
        id: raw_id.clone(),
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..own_message
    };
    assert!(
        matches!(
            alice.ingest(echoed).await.unwrap(),
            IngestOutcome::Buffered { .. }
        ),
        "the own echo must enter through the raw retry lifecycle"
    );
    assert_eq!(
        storage.get_message(&raw_id).unwrap().state,
        MessageState::Retryable
    );

    alice.publish_failed(staged).await.unwrap();

    assert_eq!(
        storage.get_message(&own_content_id).unwrap().state,
        MessageState::Processed,
        "OpenMLS must classify and terminalize the legacy own content"
    );
    assert_eq!(
        storage.get_message(&raw_id).unwrap().state,
        MessageState::Failed,
        "the raw retry row must be retired by the OwnEcho fallback"
    );
    assert!(
        alice
            .drain_events()
            .into_iter()
            .all(|event| !matches!(event, GroupEvent::MessageReceived { .. })),
        "an own echo must not surface as an inbound application message"
    );
}

#[tokio::test]
async fn rewrapped_own_openmls_message_after_restart_returns_own_echo() {
    // Alice's hot-process sent-message cache is gone after restart. A re-wrapped
    // echo with a fresh transport id must still hit a durable content-derived
    // Sent marker and classify as OwnEcho instead of being processed again.
    let dir = tempfile::tempdir().unwrap();
    let alice_path = dir.path().join("alice.sqlite");
    let key = SqlCipherKey::new("durable own echo content marker").unwrap();

    let group_id;
    let app_msg;
    {
        let alice_store = SqliteAccountStorage::open_encrypted(&alice_path, &key).unwrap();
        let mut alice = build_client_with_storage(alice_store, b"alice-own-restart");
        let mut bob = build_client(b"bob-own-restart");
        let bob_kp = bob.fresh_key_package().await.unwrap();

        let (gid, create) = alice
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
        group_id = gid.clone();
        let pending = match create {
            SendResult::GroupCreated { pending, .. } => pending,
            _ => unreachable!(),
        };
        alice.confirm_published(pending).await.unwrap();

        app_msg = match alice
            .send(SendIntent::AppMessage {
                group_id: group_id.clone(),
                payload: app_payload_for(&alice, b"durable own echo"),
            })
            .await
            .unwrap()
        {
            SendResult::ApplicationMessage { msg } => msg,
            _ => unreachable!(),
        };
    }

    let sent_content_id = content_id(&app_msg);
    let reopened_store = SqliteAccountStorage::open_encrypted(&alice_path, &key).unwrap();
    let marker = reopened_store
        .get_message(&sent_content_id)
        .expect("outbound OpenMLS send must persist a content-derived Sent marker");
    assert_eq!(marker.state, MessageState::Sent);

    let mut alice = build_client_with_storage(reopened_store, b"alice-own-restart");
    alice.hydrate_stable_groups_from_storage().unwrap();
    let rewrapped = TransportMessage {
        id: MessageId::new(b"fresh-own-echo-transport-id".to_vec()),
        timestamp: Timestamp(app_msg.timestamp.0 + 1),
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..app_msg
    };

    let outcome = alice.ingest(rewrapped).await.unwrap();
    assert!(
        matches!(
            outcome,
            IngestOutcome::Stale {
                reason: StaleReason::OwnEcho
            }
        ),
        "re-wrapped own OpenMLS echo after restart must be OwnEcho, got {outcome:?}"
    );
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

/// A peer message that arrives during our own `PendingPublish` window is
/// buffered `Retryable` (persisted before any peel). Once the publish cycle
/// resolves and replay applies it, the raw transport wrapper MUST reach a
/// terminal state: the content-derived row now carries the real verdict, so
/// leaving the raw row `Retryable` only makes replay re-peel it wastefully on
/// every subsequent publish cycle.
#[tokio::test]
async fn buffered_retryable_peer_message_is_retired_terminal_after_replay() {
    let peels = Arc::new(Mutex::new(0usize));
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let alice_storage = storage.clone();
    let mut alice = build_client_with_storage_and_peeler(
        storage,
        b"alice-buffered-retire",
        Box::new(CountingPeeler {
            peels: peels.clone(),
        }),
    );
    let mut bob = build_client(b"bob-buffered-retire");
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
    let raw_id = bob_msg.id.clone();

    // ── Cycle 1: buffer during PendingPublish, then replay on rollback. ──
    let staged = match alice
        .send(SendIntent::UpdateGroupData {
            group_id: group_id.clone(),
            name: Some("pending".into()),
            description: None,
        })
        .await
        .unwrap()
    {
        SendResult::GroupEvolution { pending, .. } => pending,
        _ => unreachable!(),
    };

    let buffered = alice.ingest(bob_msg).await.unwrap();
    assert!(
        matches!(buffered, IngestOutcome::Buffered { .. }),
        "peer message during PendingPublish must buffer, got {buffered:?}"
    );
    assert_eq!(
        *peels.lock().unwrap(),
        0,
        "buffering is pre-peel: the PendingPublish window must not peel the row"
    );
    assert_eq!(
        alice_storage.get_message(&raw_id).unwrap().state,
        MessageState::Retryable,
        "the buffered raw transport row is persisted Retryable pending replay"
    );

    alice.publish_failed(staged).await.unwrap();
    assert!(
        alice.drain_events().iter().any(
            |e| matches!(e, GroupEvent::MessageReceived { payload, .. } if app_content(payload) == b"arrived while alice was pending"),
        ),
        "the buffered message must be delivered once replay runs"
    );
    assert_eq!(
        *peels.lock().unwrap(),
        1,
        "replay peels the buffered row exactly once"
    );
    assert_eq!(
        alice_storage.get_message(&raw_id).unwrap().state,
        MessageState::Processed,
        "after replay applies it, the raw transport wrapper must be terminal \
         (Processed) — not left Retryable to be re-peeled forever"
    );

    // ── Cycle 2: a second publish cycle must not re-peel the retired row. ──
    let staged_again = match alice
        .send(SendIntent::UpdateGroupData {
            group_id: group_id.clone(),
            name: Some("pending-again".into()),
            description: None,
        })
        .await
        .unwrap()
    {
        SendResult::GroupEvolution { pending, .. } => pending,
        _ => unreachable!(),
    };
    alice.publish_failed(staged_again).await.unwrap();
    assert_eq!(
        *peels.lock().unwrap(),
        1,
        "a retired raw row is excluded from replay — no wasted re-peel on the \
         next publish cycle"
    );
    assert_eq!(
        alice_storage.get_message(&raw_id).unwrap().state,
        MessageState::Processed,
        "the retired raw row stays terminal across publish cycles"
    );
}

// ── Content-derived dedup id (#238) ──────────────────────────────────────────

/// Drive Alice + Bob into a shared group and return both engines plus the
/// group id, ready for app-message ingest assertions.
async fn alice_bob_in_group() -> (
    Engine<SqliteAccountStorage>,
    Engine<SqliteAccountStorage>,
    cgka_traits::types::GroupId,
) {
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
    let (pending, welcome) = match result {
        SendResult::GroupCreated {
            pending,
            mut welcomes,
        } => (pending, welcomes.remove(0)),
        _ => unreachable!(),
    };
    alice.confirm_published(pending).await.unwrap();
    bob.join_welcome(welcome).await.unwrap();
    bob.drain_events();
    (alice, bob, group_id)
}

/// The same MLS message re-wrapped in a fresh transport envelope (a different
/// transport id, which any group member can produce by re-sealing the same
/// bytes under a new ephemeral key + nonce) MUST collapse to a single applied
/// outcome: the canonical dedup id is derived from the recovered MLS bytes, not
/// the outer transport event id (foundation/wire-envelopes.md,
/// protocol-core/inbound-processing.md "Message identity").
#[tokio::test]
async fn rewrapped_mls_message_with_new_transport_id_is_a_duplicate() {
    let (mut alice, mut bob, group_id) = alice_bob_in_group().await;

    let msg = match alice
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: app_payload_for(&alice, b"only once"),
        })
        .await
        .unwrap()
    {
        SendResult::ApplicationMessage { msg } => msg,
        _ => unreachable!(),
    };

    // First delivery: re-route so bob resolves the group. Applied once.
    let first = TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..msg.clone()
    };
    assert!(matches!(
        bob.ingest(first).await.unwrap(),
        IngestOutcome::Processed
    ));
    let delivered = bob
        .drain_events()
        .iter()
        .filter(|e| {
            matches!(
                e,
                GroupEvent::MessageReceived { payload, .. } if app_content(payload) == b"only once"
            )
        })
        .count();
    assert_eq!(delivered, 1, "first delivery must be applied exactly once");

    // Second delivery: identical MLS payload, but a brand-new transport id and
    // a fresh nonce — exactly what a re-wrap into a new kind-445 envelope looks
    // like. The transport-id pre-filter cannot catch this; the content-derived
    // dedup id must.
    let rewrapped = TransportMessage {
        id: MessageId::new(b"a-completely-different-transport-event-id".to_vec()),
        timestamp: Timestamp(msg.timestamp.0 + 999),
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..msg
    };
    assert!(
        matches!(
            bob.ingest(rewrapped).await.unwrap(),
            IngestOutcome::Stale {
                reason: StaleReason::AlreadySeen
            }
        ),
        "re-wrapped duplicate MLS message must be classified AlreadySeen"
    );
    let after = bob.drain_events();
    assert!(
        after.iter().all(
            |e| !matches!(e, GroupEvent::MessageReceived { payload, .. } if app_content(payload) == b"only once")
        ),
        "re-wrapped duplicate must not be delivered a second time; got {after:?}"
    );
}

/// Two genuinely different MLS messages (different inner bytes) MUST NOT be
/// collapsed by content-derived dedup — only byte-identical re-wraps are
/// duplicates.
#[tokio::test]
async fn distinct_mls_messages_are_not_collapsed_by_content_dedup() {
    let (mut alice, mut bob, group_id) = alice_bob_in_group().await;

    for body in [b"first distinct".as_slice(), b"second distinct".as_slice()] {
        let msg = match alice
            .send(SendIntent::AppMessage {
                group_id: group_id.clone(),
                payload: app_payload_for(&alice, body),
            })
            .await
            .unwrap()
        {
            SendResult::ApplicationMessage { msg } => msg,
            _ => unreachable!(),
        };
        let routed = TransportMessage {
            envelope: TransportEnvelope::GroupMessage {
                transport_group_id: group_id.as_slice().to_vec(),
            },
            ..msg
        };
        assert!(
            matches!(bob.ingest(routed).await.unwrap(), IngestOutcome::Processed),
            "distinct message {body:?} must be applied, not deduped",
        );
    }

    let delivered: Vec<Vec<u8>> = bob
        .drain_events()
        .into_iter()
        .filter_map(|e| match e {
            GroupEvent::MessageReceived { payload, .. } => Some(app_content(&payload)),
            _ => None,
        })
        .collect();
    assert!(
        delivered.iter().any(|p| p == b"first distinct")
            && delivered.iter().any(|p| p == b"second distinct"),
        "both distinct messages must be delivered; got {delivered:?}"
    );
}
