//! Shared unit-test identity and pass-through transport fixtures for engine tests.

use crate::account_identity_proof::{AccountIdentityProofRequest, AccountIdentityProofSigner};
use cgka_traits::error::PeelerError;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{PeeledContent, PeeledMessage};
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::types::MessageId;
use k256::schnorr::{SigningKey, signature::hazmat::PrehashSigner};
use sha2::{Digest, Sha256};

pub(crate) fn signing_key(seed: &[u8]) -> SigningKey {
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

pub(crate) struct SeedProofSigner(pub(crate) SigningKey);

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

pub(crate) fn carried(
    source: &'static str,
    payload: &[u8],
    envelope: TransportEnvelope,
) -> TransportMessage {
    TransportMessage {
        id: MessageId::new(Sha256::digest(payload).to_vec()),
        payload: payload.to_vec(),
        timestamp: Timestamp(0),
        causal_deps: vec![],
        source: TransportSource(source.into()),
        envelope,
    }
}

/// Carries every message verbatim.
pub(crate) struct PassthroughPeeler;

impl TransportPeeler for PassthroughPeeler {
    fn peel_group_message(
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

    fn wrap_group_message(
        &self,
        payload: &EncryptedPayload,
        _ctx: &GroupContextSnapshot,
    ) -> Result<TransportMessage, PeelerError> {
        Ok(carried(
            "engine-unit-test",
            &payload.ciphertext,
            TransportEnvelope::GroupMessage {
                transport_group_id: vec![],
            },
        ))
    }
}
