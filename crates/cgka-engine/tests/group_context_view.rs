//! `GroupContextView` length-contract integration test.
//!
//! Verifies that `GroupContext::exporter_secret(label, length)` exposed via
//! `Engine::group_context()` returns `None` when the caller asks for more
//! bytes than the engine cached for that label, instead of silently
//! returning a too-short prefix.

use async_trait::async_trait;
use cgka_engine::EngineBuilder;
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_traits::engine::{CgkaEngine, CreateGroupRequest, SendResult};
use cgka_traits::error::PeelerError;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{PeeledContent, PeeledMessage};
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::types::{MemberId, MessageId};
use storage_memory::MemoryStorage;

const ENGINE_EXPORTER_LABEL: &str = "marmot/engine/v1";

fn pad32(name: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; 32];
    let n = name.len().min(32);
    out[..n].copy_from_slice(&name[..n]);
    out
}

struct MockPeeler;

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

fn build_client(identity: &[u8]) -> impl CgkaEngine {
    EngineBuilder::new(MemoryStorage::new())
        .identity(pad32(identity))
        .feature_registry(FeatureRegistry::new())
        .peeler(Box::new(MockPeeler))
        .build()
        .expect("build engine")
}

#[tokio::test]
async fn exporter_secret_returns_full_cached_secret_at_exact_length() {
    let mut alice = build_client(b"alice-context-view");
    let (group_id, send_result) = alice
        .create_group(CreateGroupRequest {
            name: "g".into(),
            description: "".into(),
            members: vec![],
            required_features: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();

    if let SendResult::GroupCreated { pending, .. } = send_result {
        alice.confirm_published(pending).await.unwrap();
    }

    let ctx = alice.group_context(&group_id).unwrap();
    let secret = ctx
        .exporter_secret(ENGINE_EXPORTER_LABEL, 32)
        .expect("32-byte cached exporter");
    assert_eq!(secret.len(), 32);
}

#[tokio::test]
async fn exporter_secret_returns_prefix_when_caller_asks_for_less() {
    let mut alice = build_client(b"alice-context-view");
    let (group_id, send_result) = alice
        .create_group(CreateGroupRequest {
            name: "g".into(),
            description: "".into(),
            members: vec![],
            required_features: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    if let SendResult::GroupCreated { pending, .. } = send_result {
        alice.confirm_published(pending).await.unwrap();
    }

    let ctx = alice.group_context(&group_id).unwrap();
    let prefix = ctx
        .exporter_secret(ENGINE_EXPORTER_LABEL, 16)
        .expect("prefix request within cached length is OK");
    assert_eq!(prefix.len(), 16);

    let full = ctx
        .exporter_secret(ENGINE_EXPORTER_LABEL, 32)
        .expect("full-length request is OK");
    assert_eq!(&full[..16], &prefix[..]);
}

#[tokio::test]
async fn exporter_secret_returns_none_when_caller_asks_for_more_than_cached() {
    let mut alice = build_client(b"alice-context-view");
    let (group_id, send_result) = alice
        .create_group(CreateGroupRequest {
            name: "g".into(),
            description: "".into(),
            members: vec![],
            required_features: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    if let SendResult::GroupCreated { pending, .. } = send_result {
        alice.confirm_published(pending).await.unwrap();
    }

    let ctx = alice.group_context(&group_id).unwrap();
    // Engine caches 32-byte secrets. Asking for 33 must NOT silently
    // return a 32-byte prefix.
    assert!(
        ctx.exporter_secret(ENGINE_EXPORTER_LABEL, 33).is_none(),
        "over-length request must be rejected, not silently truncated"
    );
}

#[tokio::test]
async fn exporter_secret_returns_none_for_unknown_label() {
    let mut alice = build_client(b"alice-context-view");
    let (group_id, send_result) = alice
        .create_group(CreateGroupRequest {
            name: "g".into(),
            description: "".into(),
            members: vec![],
            required_features: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    if let SendResult::GroupCreated { pending, .. } = send_result {
        alice.confirm_published(pending).await.unwrap();
    }

    let ctx = alice.group_context(&group_id).unwrap();
    assert!(ctx.exporter_secret("unknown-label", 32).is_none());
}
