use async_trait::async_trait;
use cgka_engine::account_identity_proof::{
    AccountIdentityProofRequest, AccountIdentityProofSigner,
};
use cgka_engine::canonicalization::CanonicalizationPolicy;
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_session::{AccountDeviceSession, PublishWork, SessionConfig};
use cgka_traits::app_event::{MARMOT_APP_EVENT_KIND_CHAT, MarmotAppEvent};
use cgka_traits::capabilities::{Capability, CapabilityRequirement, Feature, RequirementLevel};
use cgka_traits::engine::{CreateGroupRequest, GroupEvent, SendIntent};
use cgka_traits::error::{EngineError, PeelerError};
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{PeeledContent, PeeledMessage};
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::types::{EpochId, GroupId, MemberId, MessageId};
use std::sync::Arc;
use storage_sqlite::SqlCipherKey;

fn deterministic_nostr_keys(name: &[u8]) -> nostr::Keys {
    use sha2::{Digest, Sha256};
    let mut counter = 0u64;
    loop {
        let mut hasher = Sha256::new();
        hasher.update(b"cgka-session-test-identity-v1");
        hasher.update(name);
        hasher.update(counter.to_be_bytes());
        let secret = hasher.finalize();
        if let Ok(keys) = nostr::Keys::parse(&hex::encode(secret)) {
            return keys;
        }
        counter += 1;
    }
}

#[derive(Clone)]
struct NostrAccountIdentityProofSigner {
    keys: nostr::Keys,
}

impl AccountIdentityProofSigner for NostrAccountIdentityProofSigner {
    fn sign_account_identity_proof(
        &self,
        request: &AccountIdentityProofRequest,
    ) -> Result<[u8; 64], String> {
        if self.keys.public_key().to_bytes().as_slice() != request.account_identity.as_slice() {
            return Err("request account identity does not match session test key".into());
        }
        let message = nostr::secp256k1::Message::from_digest(request.signing_digest());
        Ok(self.keys.sign_schnorr(&message).serialize())
    }
}

fn hash_id(bytes: &[u8]) -> MessageId {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut h = DefaultHasher::new();
    bytes.hash(&mut h);
    MessageId::new(h.finish().to_be_bytes().to_vec())
}

struct MockPeeler;

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
            source: TransportSource("session-test".into()),
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
            source: TransportSource("session-test".into()),
            envelope: TransportEnvelope::Welcome {
                recipient: recipient.clone(),
            },
        })
    }
}

fn config(
    path: impl Into<std::path::PathBuf>,
    key: &SqlCipherKey,
    identity: &[u8],
) -> SessionConfig {
    let keys = deterministic_nostr_keys(identity);
    SessionConfig::new(
        path,
        SqlCipherKey::new(key.as_secret_str()).unwrap(),
        keys.public_key().to_bytes().to_vec(),
        Box::new(MockPeeler),
    )
    .account_identity_proof_signer(Arc::new(NostrAccountIdentityProofSigner { keys }))
    .feature_registry(FeatureRegistry::new())
}

fn selfremove_registry() -> FeatureRegistry {
    let mut registry = FeatureRegistry::new();
    registry.register(
        Feature("self-remove"),
        CapabilityRequirement {
            requires: Capability::Proposal(10),
            level: RequirementLevel::Required,
            description: "MIP-03",
        },
    );
    registry
}

fn route(msg: TransportMessage, group_id: &GroupId) -> TransportMessage {
    match msg.envelope {
        TransportEnvelope::Welcome { .. } => msg,
        TransportEnvelope::GroupMessage { .. } => TransportMessage {
            envelope: TransportEnvelope::GroupMessage {
                transport_group_id: group_id.as_slice().to_vec(),
            },
            ..msg
        },
    }
}

fn welcome_for(welcomes: &[TransportMessage], recipient: &MemberId) -> TransportMessage {
    welcomes
        .iter()
        .find(|msg| {
            matches!(
                &msg.envelope,
                TransportEnvelope::Welcome { recipient: r } if r == recipient
            )
        })
        .cloned()
        .expect("welcome for recipient")
}

fn app_payload_for(sender: &AccountDeviceSession, payload: impl AsRef<[u8]>) -> Vec<u8> {
    let content = String::from_utf8(payload.as_ref().to_vec()).expect("test app payload is utf8");
    MarmotAppEvent::new(
        hex::encode(sender.self_id().as_slice()),
        1_700_000_000,
        MARMOT_APP_EVENT_KIND_CHAT,
        vec![],
        content,
    )
    .encode()
    .expect("test app event encodes")
}

#[tokio::test]
async fn session_reopens_encrypted_sqlite_group_state() {
    let dir = tempfile::tempdir().unwrap();
    let alice_path = dir.path().join("alice.sqlite");
    let bob_path = dir.path().join("bob.sqlite");
    let key = SqlCipherKey::new("session lifecycle key").unwrap();

    let mut alice = AccountDeviceSession::open(config(&alice_path, &key, b"alice")).unwrap();
    let mut bob = AccountDeviceSession::open(config(&bob_path, &key, b"bob")).unwrap();

    let bob_key_package = bob.fresh_key_package().await.unwrap();
    let created = alice
        .create_group(CreateGroupRequest {
            name: "session-backed".into(),
            description: "account-device lifecycle".into(),
            members: vec![bob_key_package],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();

    let pending = match &created.effects.publish[0] {
        PublishWork::GroupCreated { pending, welcomes } => {
            assert_eq!(welcomes.len(), 1);
            *pending
        }
        other => panic!("expected GroupCreated publish work, got {other:?}"),
    };

    let confirmed = alice.confirm_published(pending).await.unwrap();
    assert_eq!(
        confirmed.events,
        vec![GroupEvent::GroupCreated {
            group_id: created.group_id.clone()
        }]
    );
    assert_eq!(alice.epoch(&created.group_id).unwrap(), EpochId(1));
    assert_eq!(alice.members(&created.group_id).unwrap().len(), 2);
    assert_eq!(alice.own_leaf_index(&created.group_id).unwrap(), 0);

    drop(alice);

    let reopened = AccountDeviceSession::open(config(&alice_path, &key, b"alice")).unwrap();
    assert_eq!(reopened.epoch(&created.group_id).unwrap(), EpochId(1));
    assert_eq!(reopened.members(&created.group_id).unwrap().len(), 2);
    assert_eq!(reopened.own_leaf_index(&created.group_id).unwrap(), 0);
}

#[tokio::test]
async fn session_ingest_surfaces_join_and_app_message_events() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("session app event key").unwrap();
    let mut alice =
        AccountDeviceSession::open(config(dir.path().join("alice.sqlite"), &key, b"alice"))
            .unwrap();
    let mut bob =
        AccountDeviceSession::open(config(dir.path().join("bob.sqlite"), &key, b"bob")).unwrap();

    let bob_key_package = bob.fresh_key_package().await.unwrap();
    let created = alice
        .create_group(CreateGroupRequest {
            name: "session-events".into(),
            description: "".into(),
            members: vec![bob_key_package],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (pending, welcome) = match &created.effects.publish[0] {
        PublishWork::GroupCreated { pending, welcomes } => (*pending, welcomes[0].clone()),
        other => panic!("expected GroupCreated publish work, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();

    let welcome_id = welcome.id.clone();
    let joined = bob.ingest(welcome).await.unwrap();
    assert_eq!(
        joined.effects.events,
        vec![GroupEvent::GroupJoined {
            group_id: created.group_id.clone(),
            via_welcome: welcome_id,
            welcomer: None,
        }]
    );

    let sent = alice
        .send(SendIntent::AppMessage {
            group_id: created.group_id.clone(),
            payload: app_payload_for(&alice, b"hello through session"),
        })
        .await
        .unwrap();
    let app_msg = match &sent.publish[0] {
        PublishWork::ApplicationMessage { msg } => route(msg.clone(), &created.group_id),
        other => panic!("expected application publish work, got {other:?}"),
    };

    let received = bob.ingest(app_msg).await.unwrap();
    assert_eq!(
        received.outcome,
        cgka_traits::ingest::IngestOutcome::Processed
    );
    assert_eq!(
        received.effects.events,
        vec![GroupEvent::MessageReceived {
            group_id: created.group_id,
            epoch: EpochId(1),
            sender: alice.self_id(),
            payload: app_payload_for(&alice, b"hello through session"),
        }]
    );
}

#[tokio::test]
async fn reopened_creator_can_send_valid_group_messages() {
    let dir = tempfile::tempdir().unwrap();
    let alice_path = dir.path().join("alice.sqlite");
    let bob_path = dir.path().join("bob.sqlite");
    let key = SqlCipherKey::new("session reopened signer key").unwrap();
    let mut alice = AccountDeviceSession::open(config(&alice_path, &key, b"alice")).unwrap();
    let mut bob = AccountDeviceSession::open(config(&bob_path, &key, b"bob")).unwrap();

    let bob_key_package = bob.fresh_key_package().await.unwrap();
    let created = alice
        .create_group(CreateGroupRequest {
            name: "session-reopened-signer".into(),
            description: "".into(),
            members: vec![bob_key_package],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (pending, welcome) = match &created.effects.publish[0] {
        PublishWork::GroupCreated { pending, welcomes } => (*pending, welcomes[0].clone()),
        other => panic!("expected GroupCreated publish work, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    bob.ingest(welcome).await.unwrap();

    drop(alice);
    let mut alice = AccountDeviceSession::open(config(&alice_path, &key, b"alice")).unwrap();

    let sent = alice
        .send(SendIntent::AppMessage {
            group_id: created.group_id.clone(),
            payload: app_payload_for(&alice, b"hello after restart"),
        })
        .await
        .unwrap();
    let app_msg = match &sent.publish[0] {
        PublishWork::ApplicationMessage { msg } => route(msg.clone(), &created.group_id),
        other => panic!("expected application publish work, got {other:?}"),
    };

    let received = bob.ingest(app_msg).await.unwrap();
    assert_eq!(
        received.outcome,
        cgka_traits::ingest::IngestOutcome::Processed
    );
    assert_eq!(
        received.effects.events,
        vec![GroupEvent::MessageReceived {
            group_id: created.group_id,
            epoch: EpochId(1),
            sender: alice.self_id(),
            payload: app_payload_for(&alice, b"hello after restart"),
        }]
    );
}

#[tokio::test]
async fn session_ingest_schedules_auto_publish_work() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("session auto publish key").unwrap();
    let mut alice = AccountDeviceSession::open(
        config(dir.path().join("alice.sqlite"), &key, b"alice")
            .feature_registry(selfremove_registry()),
    )
    .unwrap();
    let mut bob = AccountDeviceSession::open(
        config(dir.path().join("bob.sqlite"), &key, b"bob").feature_registry(selfremove_registry()),
    )
    .unwrap();

    let bob_key_package = bob.fresh_key_package().await.unwrap();
    let created = alice
        .create_group(CreateGroupRequest {
            name: "session-auto-publish".into(),
            description: "".into(),
            members: vec![bob_key_package],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (pending, welcome) = match &created.effects.publish[0] {
        PublishWork::GroupCreated { pending, welcomes } => (*pending, welcomes[0].clone()),
        other => panic!("expected GroupCreated publish work, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    bob.ingest(welcome).await.unwrap();

    let leave = bob
        .send(SendIntent::Leave {
            group_id: created.group_id.clone(),
        })
        .await
        .unwrap();
    let proposal = match &leave.publish[0] {
        PublishWork::Proposal { msg } => route(msg.clone(), &created.group_id),
        other => panic!("expected proposal publish work, got {other:?}"),
    };

    let ingested = alice.ingest(proposal).await.unwrap();
    assert_eq!(
        ingested.outcome,
        cgka_traits::ingest::IngestOutcome::Processed
    );
    assert_eq!(
        ingested.effects.pending_convergence,
        vec![created.group_id.clone()]
    );
    assert!(
        !ingested
            .effects
            .publish
            .iter()
            .any(|work| matches!(work, PublishWork::AutoPublish { .. })),
        "auto publish work should wait for the convergence timer, got {:?}",
        ingested.effects.publish
    );
    tokio::time::sleep(std::time::Duration::from_millis(75)).await;
    let advanced = alice.advance_convergence(&created.group_id).await.unwrap();
    assert!(
        advanced
            .publish
            .iter()
            .any(|work| matches!(work, PublishWork::AutoPublish { .. })),
        "expected delayed auto publish work, got {:?}",
        advanced.publish
    );
}

#[tokio::test]
async fn session_advance_convergence_surfaces_auto_selfremove_reproposal() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("session selfremove reproposal key").unwrap();
    let mut alice = AccountDeviceSession::open(
        config(dir.path().join("alice.sqlite"), &key, b"alice")
            .feature_registry(selfremove_registry()),
    )
    .unwrap();
    let mut bob = AccountDeviceSession::open(
        config(dir.path().join("bob.sqlite"), &key, b"bob").feature_registry(selfremove_registry()),
    )
    .unwrap();

    let bob_key_package = bob.fresh_key_package().await.unwrap();
    let created = alice
        .create_group(CreateGroupRequest {
            name: "session-selfremove-reproposal".into(),
            description: "".into(),
            members: vec![bob_key_package],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (pending, welcome) = match &created.effects.publish[0] {
        PublishWork::GroupCreated { pending, welcomes } => (*pending, welcomes[0].clone()),
        other => panic!("expected GroupCreated publish work, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    bob.ingest(welcome).await.unwrap();

    let leave = bob
        .send(SendIntent::Leave {
            group_id: created.group_id.clone(),
        })
        .await
        .unwrap();
    assert!(
        leave
            .publish
            .iter()
            .any(|work| matches!(work, PublishWork::Proposal { .. })),
        "initial leave should publish a SelfRemove proposal"
    );

    let rename = alice
        .send(SendIntent::UpdateGroupData {
            group_id: created.group_id.clone(),
            name: Some("still includes bob".into()),
            description: None,
        })
        .await
        .unwrap();
    let (commit, pending) = match &rename.publish[0] {
        PublishWork::GroupEvolution { msg, pending, .. } => (msg.clone(), *pending),
        other => panic!("expected GroupEvolution publish work, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();

    let buffered = bob.ingest(route(commit, &created.group_id)).await.unwrap();
    assert!(matches!(
        buffered.outcome,
        cgka_traits::ingest::IngestOutcome::Buffered { .. }
    ));

    bob.set_convergence_policy(CanonicalizationPolicy {
        settlement_quiescence_ms: 0,
        ..CanonicalizationPolicy::default()
    });
    let advanced = bob.advance_convergence(&created.group_id).await.unwrap();
    assert!(
        advanced
            .publish
            .iter()
            .any(|work| matches!(work, PublishWork::Proposal { .. })),
        "expected auto SelfRemove re-proposal publish work, got {:?}",
        advanced.publish
    );

    let blocked = bob
        .send(SendIntent::AppMessage {
            group_id: created.group_id.clone(),
            payload: app_payload_for(&bob, b"still leaving"),
        })
        .await;
    assert!(
        matches!(
            blocked,
            Err(cgka_session::SessionError::Engine(
                EngineError::InvalidTransition(_)
            ))
        ),
        "durable leave request should block app sends after re-proposal; got {blocked:?}"
    );
}

#[tokio::test]
async fn session_advance_convergence_releases_queued_outbound_work() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("session convergence key").unwrap();
    let mut alice =
        AccountDeviceSession::open(config(dir.path().join("alice.sqlite"), &key, b"alice"))
            .unwrap();
    let mut bob =
        AccountDeviceSession::open(config(dir.path().join("bob.sqlite"), &key, b"bob")).unwrap();
    let mut carol =
        AccountDeviceSession::open(config(dir.path().join("carol.sqlite"), &key, b"carol"))
            .unwrap();
    let mut david =
        AccountDeviceSession::open(config(dir.path().join("david.sqlite"), &key, b"david"))
            .unwrap();

    let bob_key_package = bob.fresh_key_package().await.unwrap();
    let carol_key_package = carol.fresh_key_package().await.unwrap();
    let created = alice
        .create_group(CreateGroupRequest {
            name: "session-convergence".into(),
            description: "".into(),
            members: vec![bob_key_package, carol_key_package],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match &created.effects.publish[0] {
        PublishWork::GroupCreated { pending, welcomes } => (*pending, welcomes.clone()),
        other => panic!("expected GroupCreated publish work, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    let carol_welcome = welcome_for(&welcomes, &carol.self_id());
    carol.ingest(carol_welcome).await.unwrap();

    let david_key_package = david.fresh_key_package().await.unwrap();
    let invite = alice
        .send(SendIntent::Invite {
            group_id: created.group_id.clone(),
            key_packages: vec![david_key_package],
        })
        .await
        .unwrap();
    let commit = match &invite.publish[0] {
        PublishWork::GroupEvolution { msg, .. } => route(msg.clone(), &created.group_id),
        other => panic!("expected group evolution publish work, got {other:?}"),
    };
    let buffered = carol.ingest(commit).await.unwrap();
    assert!(matches!(
        buffered.outcome,
        cgka_traits::ingest::IngestOutcome::Buffered { .. }
    ));

    // Pin a long settlement-quiescence window before the queued send. The
    // outbound intent is only queued while convergence reports `Syncing`,
    // which holds only while `now_ms - last_input_ms < settlement_quiescence_ms`.
    // With the default 1s window this test silently depended on under ~1s of
    // wall-clock elapsing between buffering the commit and sending; under a
    // loaded nextest shard that window blew past 1s, convergence settled
    // early, and the message published instead of queuing (issue #296).
    // A large explicit window makes the queue path deterministic regardless of
    // scheduling jitter; the reset to 0 below deterministically releases it.
    carol.set_convergence_policy(CanonicalizationPolicy {
        settlement_quiescence_ms: 3_600_000,
        ..CanonicalizationPolicy::default()
    });
    let queued = carol
        .send(SendIntent::AppMessage {
            group_id: created.group_id.clone(),
            payload: app_payload_for(&carol, b"queued by session"),
        })
        .await
        .unwrap();
    assert_eq!(queued.queued.len(), 1);
    assert!(queued.publish.is_empty());

    carol.set_convergence_policy(CanonicalizationPolicy {
        settlement_quiescence_ms: 0,
        ..CanonicalizationPolicy::default()
    });
    let advanced = carol.advance_convergence(&created.group_id).await.unwrap();

    assert_eq!(carol.epoch(&created.group_id).unwrap(), EpochId(2));
    assert!(
        advanced
            .publish
            .iter()
            .any(|work| matches!(work, PublishWork::ApplicationMessage { .. })),
        "expected queued application message to be regenerated, got {:?}",
        advanced.publish
    );
    assert!(advanced.queued.is_empty());
}
