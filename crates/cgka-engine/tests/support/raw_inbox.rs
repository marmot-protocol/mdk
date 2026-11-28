//! A pass-through account inbox for engine tests: what a session's sealer
//! does to Welcomes, without a signer. The engine never seals; these helpers
//! stand in for the session around it.

// Shared by every engine test binary; each uses only some of these.
#![allow(dead_code)]

use cgka_engine::Engine;
use cgka_traits::engine::{CgkaEngine, OutboundWelcome, SealedWelcome};
use cgka_traits::error::EngineError;
use cgka_traits::ingest::{IngestOutcome, PeeledContent, PeeledMessage};
use cgka_traits::storage::StorageProvider;
use cgka_traits::transport::{Timestamp, TransportEnvelope, TransportMessage, TransportSource};
use cgka_traits::types::{GroupId, MemberId, MessageId};
use sha2::{Digest, Sha256};

/// Seal `welcome` as a raw transport message: its payload is the Welcome
/// ciphertext, and its id is distinct per recipient and local id.
pub fn raw_seal(welcome: &OutboundWelcome) -> TransportMessage {
    let mut hasher = Sha256::new();
    hasher.update(welcome.local_id.as_slice());
    hasher.update(welcome.recipient.as_slice());
    hasher.update(&welcome.payload.ciphertext);
    raw_welcome_message(
        MessageId::new(hasher.finalize().to_vec()),
        welcome.payload.ciphertext.clone(),
        welcome.recipient.clone(),
    )
}

pub fn raw_welcome_message(
    id: MessageId,
    payload: Vec<u8>,
    recipient: MemberId,
) -> TransportMessage {
    TransportMessage {
        id,
        payload,
        timestamp: Timestamp(0),
        causal_deps: Vec::new(),
        source: TransportSource("raw-inbox".into()),
        envelope: TransportEnvelope::Welcome { recipient },
    }
}

/// Open a [`raw_seal`]ed Welcome. Its creation time is the envelope's
/// timestamp, or none for an unstamped one.
pub fn raw_unseal(msg: &TransportMessage) -> PeeledMessage {
    PeeledMessage {
        id: msg.id.clone(),
        group_id: None,
        sender: None,
        content: PeeledContent::Welcome {
            created_at: (msg.timestamp.0 != 0).then_some(msg.timestamp),
            bytes: msg.payload.clone(),
            key_package_event_id: None,
        },
        origin: msg.clone(),
    }
}

/// [`raw_seal`] each of `welcomes` and bind their rows, as a session does
/// before it publishes them.
pub fn seal_and_bind<S: StorageProvider + 'static>(
    engine: &mut Engine<S>,
    welcomes: &[OutboundWelcome],
) -> Vec<TransportMessage> {
    let sealed: Vec<SealedWelcome> = welcomes
        .iter()
        .map(|welcome| SealedWelcome {
            local_id: welcome.local_id.clone(),
            message: raw_seal(welcome),
        })
        .collect();
    engine
        .bind_sealed_welcomes(&sealed, None)
        .expect("bind sealed Welcomes");
    sealed.into_iter().map(|sealed| sealed.message).collect()
}

/// Ingest `msg`, unsealing a [`raw_seal`]ed inbox delivery as a session does.
pub async fn ingest_raw<S: StorageProvider + 'static>(
    engine: &mut Engine<S>,
    msg: TransportMessage,
) -> Result<IngestOutcome, EngineError> {
    match engine.ingest(msg.clone()).await? {
        IngestOutcome::InboxSealed => {
            let unsealed = raw_unseal(&msg);
            engine.ingest_unsealed(msg, Ok(unsealed)).await
        }
        outcome => Ok(outcome),
    }
}

/// Join a [`raw_seal`]ed Welcome.
pub async fn join_raw<S: StorageProvider + 'static>(
    engine: &mut Engine<S>,
    msg: TransportMessage,
) -> Result<GroupId, EngineError> {
    let unsealed = raw_unseal(&msg);
    engine.join_welcome(msg, unsealed).await
}
