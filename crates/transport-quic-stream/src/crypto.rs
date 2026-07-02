//! Per-stream AEAD: the `AgentTextStreamCrypto` key material, record
//! seal/open, and the HKDF key/nonce and AAD derivations vectors pin.

use cgka_traits::agent_text_stream::{
    AGENT_TEXT_STREAM_PROFILE_STREAM_ID_LEN, AGENT_TEXT_STREAM_RECORD_VERSION,
    AGENT_TEXT_STREAM_START_EVENT_ID_LEN, AgentTextStreamKeyContextV1, AgentTextStreamRecordV1,
};
use cgka_traits::app_components::encode_quic_varint;
use cgka_traits::{SecretBytes, agent_text_stream::AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

use crate::error::QuicTextStreamError;
use crate::protocol::{AEAD_TAG_LEN, AGENT_TEXT_STREAM_SECRET_LEN};

#[derive(Clone)]
pub struct AgentTextStreamCrypto {
    pub stream_secret: SecretBytes,
    pub context: AgentTextStreamKeyContextV1,
}

impl AgentTextStreamCrypto {
    pub fn new(stream_secret: SecretBytes, context: AgentTextStreamKeyContextV1) -> Self {
        Self {
            stream_secret,
            context,
        }
    }
}

impl std::fmt::Debug for AgentTextStreamCrypto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentTextStreamCrypto")
            .field("stream_secret", &"<redacted>")
            .field("context", &self.context)
            .finish()
    }
}

pub fn encrypt_record(
    crypto: &AgentTextStreamCrypto,
    record: &AgentTextStreamRecordV1,
) -> Result<AgentTextStreamRecordV1, QuicTextStreamError> {
    validate_crypto_record_context(crypto, record)?;
    // Plaintext within the app-profile cap (65519) keeps the ciphertext
    // (plaintext + 16-byte AEAD tag) within the record's
    // `ciphertext<0..2^16-1>` wire field bound.
    if record.plaintext_frame.len() > AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN as usize {
        return Err(QuicTextStreamError::EncryptedFrameTooLarge(
            record.plaintext_frame.len(),
        ));
    }
    let key = derive_record_key(crypto)?;
    let nonce = derive_record_nonce(crypto, record.seq)?;
    let aad = record_aad(crypto, record);
    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| QuicTextStreamError::Crypto("invalid record key".into()))?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &record.plaintext_frame,
                aad: &aad,
            },
        )
        .map_err(|_| QuicTextStreamError::Crypto("record encryption failed".into()))?;
    Ok(AgentTextStreamRecordV1 {
        plaintext_frame: ciphertext,
        ..record.clone()
    })
}

pub fn decrypt_record(
    crypto: &AgentTextStreamCrypto,
    record: &AgentTextStreamRecordV1,
) -> Result<AgentTextStreamRecordV1, QuicTextStreamError> {
    validate_crypto_record_context(crypto, record)?;
    if record.plaintext_frame.len() < AEAD_TAG_LEN {
        return Err(QuicTextStreamError::Crypto(
            "encrypted record frame is shorter than the AEAD tag".into(),
        ));
    }
    let key = derive_record_key(crypto)?;
    let nonce = derive_record_nonce(crypto, record.seq)?;
    let aad = record_aad(crypto, record);
    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| QuicTextStreamError::Crypto("invalid record key".into()))?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &record.plaintext_frame,
                aad: &aad,
            },
        )
        .map_err(|_| QuicTextStreamError::Crypto("record decryption failed".into()))?;
    Ok(AgentTextStreamRecordV1 {
        plaintext_frame: plaintext,
        ..record.clone()
    })
}

fn validate_crypto_record_context(
    crypto: &AgentTextStreamCrypto,
    record: &AgentTextStreamRecordV1,
) -> Result<(), QuicTextStreamError> {
    if crypto.stream_secret.as_slice().len() != AGENT_TEXT_STREAM_SECRET_LEN {
        return Err(QuicTextStreamError::Crypto(
            "agent text stream secret must be 32 bytes".into(),
        ));
    }
    if crypto.context.stream_id.len() != AGENT_TEXT_STREAM_PROFILE_STREAM_ID_LEN {
        return Err(QuicTextStreamError::Crypto(
            "agent text stream id must be 32 bytes".into(),
        ));
    }
    if crypto.context.start_event_id.as_slice().len() != AGENT_TEXT_STREAM_START_EVENT_ID_LEN {
        return Err(QuicTextStreamError::Crypto(
            "agent text stream start event id must be 32 bytes".into(),
        ));
    }
    if crypto.context.stream_id != record.stream_id {
        return Err(QuicTextStreamError::MixedStreamIds);
    }
    Ok(())
}

/// Derive the per-stream AEAD record key:
/// `HKDF-Expand(stream_secret, len("record key") || "record key" || key_context, 32)`.
///
/// Public so conformance vectors can pin the derivation bytes.
pub fn derive_record_key(crypto: &AgentTextStreamCrypto) -> Result<[u8; 32], QuicTextStreamError> {
    derive_bytes(crypto, b"record key")
}

/// Derive the per-record AEAD nonce: `nonce_base XOR uint96_be(seq)`, where
/// `nonce_base = HKDF-Expand(stream_secret, len("record nonce") || "record nonce" || key_context, 12)`.
/// Calling this with `seq = 0` yields `nonce_base` itself.
///
/// Public so conformance vectors can pin the derivation bytes.
pub fn derive_record_nonce(
    crypto: &AgentTextStreamCrypto,
    seq: u64,
) -> Result<[u8; 12], QuicTextStreamError> {
    let mut nonce = derive_bytes(crypto, b"record nonce")?;
    let seq = (seq as u128).to_be_bytes();
    for (byte, seq_byte) in nonce.iter_mut().zip(seq[4..].iter()) {
        *byte ^= *seq_byte;
    }
    Ok(nonce)
}

fn derive_bytes<const N: usize>(
    crypto: &AgentTextStreamCrypto,
    label: &[u8],
) -> Result<[u8; N], QuicTextStreamError> {
    let hkdf = Hkdf::<Sha256>::from_prk(crypto.stream_secret.as_slice())
        .map_err(|_| QuicTextStreamError::Crypto("invalid stream secret".into()))?;
    let key_context = crypto.context.encode();
    let mut info = Vec::with_capacity(label.len() + key_context.len() + 1);
    encode_quic_varint(label.len() as u64, &mut info);
    info.extend_from_slice(label);
    info.extend_from_slice(&key_context);
    let mut out = [0_u8; N];
    hkdf.expand(&info, &mut out)
        .map_err(|_| QuicTextStreamError::Crypto("agent text stream HKDF expand failed".into()))?;
    Ok(out)
}

/// Build the record AEAD AAD:
/// `version || SHA-256(group_id) || len(stream_id) || stream_id || mls_epoch ||
/// len(sender_id) || sender_id || seq || record_type || flags`, with every
/// `len(...)` a QUIC variable-length integer.
///
/// Public so conformance vectors can pin the AAD bytes.
pub fn record_aad(crypto: &AgentTextStreamCrypto, record: &AgentTextStreamRecordV1) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(AGENT_TEXT_STREAM_RECORD_VERSION);
    let group_hash = Sha256::digest(crypto.context.group_id.as_slice());
    out.extend_from_slice(&group_hash);
    encode_quic_varint(record.stream_id.len() as u64, &mut out);
    out.extend_from_slice(&record.stream_id);
    out.extend_from_slice(&crypto.context.mls_epoch.0.to_be_bytes());
    encode_quic_varint(crypto.context.sender_id.as_slice().len() as u64, &mut out);
    out.extend_from_slice(crypto.context.sender_id.as_slice());
    out.extend_from_slice(&record.seq.to_be_bytes());
    out.push(record.record_type);
    out.push(record.flags);
    out
}
