//! Epoch-faithful transport peeler for Tier-2 engine tests.
//!
//! The pass-through `MockPeeler` most engine tests use hands every message to
//! every engine verbatim, which gives each test client perfect cross-branch
//! visibility — precisely what production lacks. Real transports seal a group
//! message under the **sender's current-epoch exporter secret** and carry no
//! epoch hint (see `crates/transport-nostr-peeler`: kind-445 content is
//! `base64(nonce || ciphertext)` under `ctx.exporter_secret(label)`, and an
//! undecryptable message is an opaque `DecryptFailed`). A device that has not
//! entered the sending epoch's state therefore cannot read the message at all.
//!
//! [`EpochSealedPeeler`] models exactly that: it seals on wrap and unseals on
//! peel with the group-event exporter secret of the supplied context, and
//! returns [`PeelerError::DecryptFailed`] when the receiving context is a
//! different epoch state. Welcomes never reach it: the account inbox is the
//! session's, and tests seal Welcomes with `support::raw_inbox`.
//!
//! Install it with `EngineBuilder::peeler(Box::new(EpochSealedPeeler))` to opt
//! a test into production epoch visibility. The engine already wraps every
//! outbound group message through the peeler with the pre-commit context, so
//! tests need no sealing step of their own: route the `TransportMessage` a
//! `SendResult` carries and the sealing is already faithful.

#![allow(dead_code)]

use cgka_traits::error::PeelerError;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{PeeledContent, PeeledMessage};
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::types::MessageId;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use sha2::{Digest, Sha256};

/// Snapshot key the engine caches the group-event exporter secret under
/// (`cgka_engine::group_lifecycle::EXPORTER_SNAPSHOT_KEY`).
pub const GROUP_EVENT_EXPORTER_KEY: &str = "marmot/group-event";

const NONCE_LEN: usize = 12;
/// The Nostr kind-445 wrap uses an empty AAD; keep the model identical.
const SEAL_AAD: &[u8] = b"";

/// Seals group messages under the sending context's exporter secret and only
/// unseals them for a context holding that same secret.
pub struct EpochSealedPeeler;

/// Deterministic nonce so a wrap is reproducible for a given plaintext, per the
/// `TransportPeeler` determinism note. Real transports use a random nonce; the
/// only property engine tests depend on is that the ciphertext is opaque
/// without the epoch key.
fn seal_nonce(plaintext: &[u8]) -> [u8; NONCE_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(b"cgka-engine-test-epoch-seal-nonce/v1");
    hasher.update(plaintext);
    let digest = hasher.finalize();
    let mut nonce = [0_u8; NONCE_LEN];
    nonce.copy_from_slice(&digest[..NONCE_LEN]);
    nonce
}

fn transport_id(sealed: &[u8]) -> MessageId {
    let mut hasher = Sha256::new();
    hasher.update(b"cgka-engine-test-epoch-seal-id/v1");
    hasher.update(sealed);
    MessageId::new(hasher.finalize()[..16].to_vec())
}

fn cipher(ctx: &GroupContextSnapshot) -> Result<ChaCha20Poly1305, PeelerError> {
    let key = ctx
        .exporter_secret(GROUP_EVENT_EXPORTER_KEY)
        .ok_or_else(|| PeelerError::MissingContext {
            label: GROUP_EVENT_EXPORTER_KEY.into(),
        })?;
    ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| PeelerError::WrapFailed(format!("group key: {e}")))
}

/// Seal `plaintext` under `ctx` into `nonce || ciphertext` wire bytes.
pub fn seal_group_payload(
    plaintext: &[u8],
    ctx: &GroupContextSnapshot,
) -> Result<Vec<u8>, PeelerError> {
    let nonce = seal_nonce(plaintext);
    let ciphertext = cipher(ctx)?
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: SEAL_AAD,
            },
        )
        .map_err(|_| PeelerError::WrapFailed("group encryption failed".into()))?;
    let mut sealed = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&ciphertext);
    Ok(sealed)
}

/// Unseal wire bytes produced by [`seal_group_payload`] under `ctx`.
///
/// Every failure — truncated frame, wrong epoch key, tampered ciphertext — is
/// the same opaque `DecryptFailed` the Nostr binding returns, because the wire
/// format carries no epoch hint that could justify a sharper verdict.
pub fn unseal_group_payload(
    sealed: &[u8],
    ctx: &GroupContextSnapshot,
) -> Result<Vec<u8>, PeelerError> {
    if sealed.len() <= NONCE_LEN {
        return Err(PeelerError::DecryptFailed);
    }
    let (nonce, ciphertext) = sealed.split_at(NONCE_LEN);
    cipher(ctx)?
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: SEAL_AAD,
            },
        )
        .map_err(|_| PeelerError::DecryptFailed)
}

impl TransportPeeler for EpochSealedPeeler {
    fn peel_group_message(
        &self,
        msg: &cgka_traits::peeler::PreparedGroupMessage<'_>,
        ctx: &GroupContextSnapshot,
    ) -> Result<PeeledMessage, PeelerError> {
        let bytes = unseal_group_payload(&msg.message.payload, ctx)?;
        Ok(PeeledMessage {
            id: msg.message.id.clone(),
            group_id: None,
            sender: None,
            content: PeeledContent::MlsMessage { bytes },
            origin: msg.message.clone(),
        })
    }

    fn wrap_group_message(
        &self,
        payload: &EncryptedPayload,
        ctx: &GroupContextSnapshot,
    ) -> Result<TransportMessage, PeelerError> {
        let sealed = seal_group_payload(&payload.ciphertext, ctx)?;
        Ok(TransportMessage {
            id: transport_id(&sealed),
            payload: sealed,
            timestamp: Timestamp(0),
            causal_deps: vec![],
            source: TransportSource("epoch-sealed".into()),
            envelope: TransportEnvelope::GroupMessage {
                transport_group_id: ctx.transport_group_id().unwrap_or_default().to_vec(),
            },
        })
    }
}
