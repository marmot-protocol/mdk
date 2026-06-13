use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str;
use std::sync::Arc;
use std::time::Duration;

use cgka_traits::agent_text_stream::{
    AGENT_TEXT_STREAM_AEAD_TAG_LEN, AGENT_TEXT_STREAM_DEFAULT_MAX_PLAINTEXT_BYTES,
    AGENT_TEXT_STREAM_DEFAULT_MAX_RECORDS, AGENT_TEXT_STREAM_PROFILE_STREAM_ID_LEN,
    AGENT_TEXT_STREAM_RECORD_CHECKPOINT, AGENT_TEXT_STREAM_RECORD_PROGRESS_DELTA,
    AGENT_TEXT_STREAM_RECORD_STATUS, AGENT_TEXT_STREAM_RECORD_TEXT_DELTA,
    AGENT_TEXT_STREAM_RECORD_VERSION, AGENT_TEXT_STREAM_START_EVENT_ID_LEN,
    AgentTextStreamKeyContextV1, AgentTextStreamRecordError, AgentTextStreamRecordV1,
    AgentTextStreamTranscriptV1,
};
use cgka_traits::app_components::encode_quic_varint;
use cgka_traits::{
    MessageId, SecretBytes, agent_text_stream::AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN,
};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, Endpoint, ServerConfig};
use rand::{RngCore, rngs::OsRng};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls_platform_verifier::BuilderVerifierExt;
use sha2::{Digest, Sha256};
use tokio::time::{sleep, timeout};

const FRAME_LEN_BYTES: usize = 4;
const LOCAL_BIND: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

/// Direct-path QUIC ALPN, pinned by spec/transports/quic.md. Both peers MUST
/// negotiate exactly this protocol; it is the direct-path counterpart to the
/// broker path's `marmot.quic_broker.v1` and the direct path's versioning hook.
pub const QUIC_STREAM_PROTOCOL_V1: &str = "marmot.quic_stream.v1";
/// `QUIC_STREAM_PROTOCOL_V1` as ALPN bytes.
pub const QUIC_STREAM_ALPN_V1: &[u8] = QUIC_STREAM_PROTOCOL_V1.as_bytes();
/// Spec-pinned reader allowance on top of the plaintext frame policy cap: a
/// reader rejects a frame whose `frame_len` exceeds the group's
/// `max_plaintext_frame_len` policy value plus exactly 1024 bytes of header
/// and AEAD-tag allowance.
pub const AGENT_TEXT_STREAM_FRAME_ALLOWANCE: usize = 1024;
const MAX_FRAME_SIZE: usize =
    AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN as usize + AGENT_TEXT_STREAM_FRAME_ALLOWANCE;
const SEND_CLOSE_WAIT: Duration = Duration::from_secs(5);
const AEAD_TAG_LEN: usize = AGENT_TEXT_STREAM_AEAD_TAG_LEN;
const AGENT_TEXT_STREAM_SECRET_LEN: usize = 32;

/// Effective plaintext cap for a stream given an optional group policy value:
/// the policy bound when present, with the app-profile constant as the
/// ceiling and fallback.
pub fn effective_plaintext_cap(policy_max_plaintext_frame_len: Option<u32>) -> usize {
    policy_max_plaintext_frame_len
        .filter(|len| *len > 0)
        .map_or(AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN, |len| {
            len.min(AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN)
        }) as usize
}

/// Maximum accepted wire `frame_len` for a stream: the effective plaintext cap
/// plus the spec-pinned 1024-byte header/AEAD-tag allowance.
pub fn frame_len_cap(policy_max_plaintext_frame_len: Option<u32>) -> usize {
    effective_plaintext_cap(policy_max_plaintext_frame_len) + AGENT_TEXT_STREAM_FRAME_ALLOWANCE
}

pub struct QuicTextStreamReceiver {
    endpoint: Endpoint,
    server_cert_der: Vec<u8>,
}

impl QuicTextStreamReceiver {
    pub fn bind(bind_addr: SocketAddr) -> Result<Self, QuicTextStreamError> {
        let (server_config, server_cert_der) = configure_server()?;
        let endpoint = Endpoint::server(server_config, bind_addr)?;
        Ok(Self {
            endpoint,
            server_cert_der,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, QuicTextStreamError> {
        Ok(self.endpoint.local_addr()?)
    }

    pub fn server_cert_der(&self) -> &[u8] {
        &self.server_cert_der
    }

    pub async fn receive_once(
        self,
        start_event_id: MessageId,
        crypto: Option<AgentTextStreamCrypto>,
    ) -> Result<ReceivedTextStream, QuicTextStreamError> {
        self.receive_once_with_limits(
            start_event_id,
            crypto,
            AgentTextStreamReceiveLimits::default(),
        )
        .await
    }

    pub async fn receive_once_with_limits(
        self,
        start_event_id: MessageId,
        crypto: Option<AgentTextStreamCrypto>,
        limits: AgentTextStreamReceiveLimits,
    ) -> Result<ReceivedTextStream, QuicTextStreamError> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or(QuicTextStreamError::EndpointClosed)?;
        let connection = incoming.await?;
        let mut recv = connection.accept_uni().await?;
        let mut stream_id = None;
        // Last-accepted seq high-water mark per the QUIC transport binding:
        // records at or below it (duplicates, transport-level replay) are
        // discarded silently and are never stream-fatal; the next accepted
        // record is high_water + 1; a record further ahead is a gap.
        let mut high_water = 0_u64;
        let mut chunks = Vec::new();
        let mut text = String::new();
        let mut transcript = None;
        let mut limit_state = AgentTextStreamReceiveAccumulator::new(limits);
        let max_frame_len = frame_len_cap(Some(limits.max_plaintext_frame_len));

        while let Some(record) = read_record(&mut recv, max_frame_len).await? {
            if record.seq <= high_water {
                continue;
            }
            if record.seq != high_water + 1 {
                return Err(QuicTextStreamError::UnexpectedSequence {
                    expected: high_water + 1,
                    actual: record.seq,
                });
            }
            let record = if let Some(crypto) = &crypto {
                decrypt_record(crypto, &record)?
            } else {
                record
            };
            limit_state.observe(&record)?;
            high_water = record.seq;

            if let Some(existing) = &stream_id {
                if existing != &record.stream_id {
                    return Err(QuicTextStreamError::MixedStreamIds);
                }
            } else {
                transcript = Some(AgentTextStreamTranscriptV1::new(
                    record.stream_id.clone(),
                    start_event_id.clone(),
                ));
                stream_id = Some(record.stream_id.clone());
            }

            let frame_text = stream_record_text(&record)?;
            if record.record_type == AGENT_TEXT_STREAM_RECORD_TEXT_DELTA {
                text.push_str(&frame_text);
            }

            let transcript = transcript
                .as_mut()
                .expect("transcript is initialized with first record");
            transcript.append(record.seq, record.record_type, &record.plaintext_frame);
            chunks.push(ReceivedTextChunk {
                seq: record.seq,
                record_type: record.record_type,
                flags: record.flags,
                text: frame_text,
            });
        }

        connection.close(0_u32.into(), b"done");

        let Some(transcript) = transcript else {
            return Err(QuicTextStreamError::EmptyStream);
        };

        Ok(ReceivedTextStream {
            stream_id: stream_id.expect("stream id is initialized with first record"),
            chunks,
            text,
            transcript_hash: transcript.hash(),
            chunk_count: transcript.chunk_count(),
        })
    }
}

/// Decode the per-record text a consumer can surface for a single stream record.
///
/// `TextDelta`, `Status`, `ProgressDelta`, and `Checkpoint` carry UTF-8 the
/// consumer renders: deltas build the provisional preview, status/progress feed
/// non-chat agent chrome, and a `Checkpoint` is a full preview snapshot the
/// consumer swaps in for its live preview. `Abort` and `FinalNotice` are
/// advisory (the consumer acts on the record type, not its bytes), as is any
/// unknown future type, so they decode to an empty string. Note this only
/// decodes one record's frame; accumulation into the provisional answer text is
/// the caller's job and stays `TextDelta`-only.
fn stream_record_text(record: &AgentTextStreamRecordV1) -> Result<String, QuicTextStreamError> {
    match record.record_type {
        AGENT_TEXT_STREAM_RECORD_TEXT_DELTA
        | AGENT_TEXT_STREAM_RECORD_STATUS
        | AGENT_TEXT_STREAM_RECORD_PROGRESS_DELTA
        | AGENT_TEXT_STREAM_RECORD_CHECKPOINT => {
            Ok(str::from_utf8(&record.plaintext_frame)?.to_owned())
        }
        _ => Ok(String::new()),
    }
}

#[derive(Clone, Debug)]
pub struct SendTextStream {
    pub server_addr: SocketAddr,
    pub server_name: String,
    pub trust: ServerTrust,
    pub stream_id: Vec<u8>,
    pub start_event_id: MessageId,
    pub text: String,
    pub max_chunk_bytes: usize,
    pub chunk_delay: Duration,
    pub crypto: Option<AgentTextStreamCrypto>,
    /// Group policy `max_plaintext_frame_len` when the caller has the decoded
    /// `AgentTextStreamQuicPolicyV1` available. Chunk size is clamped to it;
    /// the app-profile constant is the ceiling and the fallback when `None`.
    pub max_plaintext_frame_len: Option<u32>,
}

#[derive(Clone, Debug)]
pub enum ServerTrust {
    Platform,
    CertificateDer(Vec<u8>),
    InsecureLocal,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceivedTextStream {
    pub stream_id: Vec<u8>,
    pub chunks: Vec<ReceivedTextChunk>,
    pub text: String,
    pub transcript_hash: [u8; 32],
    pub chunk_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SentTextStream {
    pub stream_id: Vec<u8>,
    pub transcript_hash: [u8; 32],
    pub chunk_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceivedTextChunk {
    pub seq: u64,
    pub record_type: u8,
    pub flags: u8,
    pub text: String,
}

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AgentTextStreamReceiveLimits {
    pub max_records: u64,
    pub max_plaintext_bytes: usize,
    /// Group policy `max_plaintext_frame_len` when available. Receive paths
    /// reject wire frames above this value plus the spec-pinned 1024-byte
    /// allowance; the app-profile constant is the ceiling and default.
    pub max_plaintext_frame_len: u32,
}

impl Default for AgentTextStreamReceiveLimits {
    fn default() -> Self {
        Self {
            max_records: AGENT_TEXT_STREAM_DEFAULT_MAX_RECORDS,
            max_plaintext_bytes: AGENT_TEXT_STREAM_DEFAULT_MAX_PLAINTEXT_BYTES,
            max_plaintext_frame_len: AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN,
        }
    }
}

#[derive(Clone, Debug)]
pub struct AgentTextStreamReceiveAccumulator {
    limits: AgentTextStreamReceiveLimits,
    records: u64,
    plaintext_bytes: usize,
}

impl AgentTextStreamReceiveAccumulator {
    pub fn new(limits: AgentTextStreamReceiveLimits) -> Self {
        Self {
            limits,
            records: 0,
            plaintext_bytes: 0,
        }
    }

    pub fn observe(
        &mut self,
        record: &AgentTextStreamRecordV1,
    ) -> Result<(), AgentTextStreamReceiveLimitError> {
        let records = self.records.checked_add(1).ok_or(
            AgentTextStreamReceiveLimitError::RecordLimitExceeded {
                attempted: u64::MAX,
                limit: self.limits.max_records,
            },
        )?;
        if records > self.limits.max_records {
            return Err(AgentTextStreamReceiveLimitError::RecordLimitExceeded {
                attempted: records,
                limit: self.limits.max_records,
            });
        }

        let plaintext_bytes = self
            .plaintext_bytes
            .checked_add(record.plaintext_frame.len())
            .ok_or(
                AgentTextStreamReceiveLimitError::PlaintextByteLimitExceeded {
                    attempted: usize::MAX,
                    limit: self.limits.max_plaintext_bytes,
                },
            )?;
        if plaintext_bytes > self.limits.max_plaintext_bytes {
            return Err(
                AgentTextStreamReceiveLimitError::PlaintextByteLimitExceeded {
                    attempted: plaintext_bytes,
                    limit: self.limits.max_plaintext_bytes,
                },
            );
        }

        self.records = records;
        self.plaintext_bytes = plaintext_bytes;
        Ok(())
    }

    pub fn records(&self) -> u64 {
        self.records
    }

    pub fn plaintext_bytes(&self) -> usize {
        self.plaintext_bytes
    }
}

impl Default for AgentTextStreamReceiveAccumulator {
    fn default() -> Self {
        Self::new(AgentTextStreamReceiveLimits::default())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AgentTextStreamReceiveLimitError {
    #[error("agent text stream record limit exceeded: {attempted} > {limit}")]
    RecordLimitExceeded { attempted: u64, limit: u64 },
    #[error("agent text stream plaintext byte limit exceeded: {attempted} > {limit}")]
    PlaintextByteLimitExceeded { attempted: usize, limit: usize },
}

pub async fn send_text_stream(
    config: SendTextStream,
) -> Result<SentTextStream, QuicTextStreamError> {
    if config.max_chunk_bytes == 0 {
        return Err(QuicTextStreamError::EmptyChunkSize);
    }
    if config.max_chunk_bytes > AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN as usize {
        return Err(QuicTextStreamError::ChunkSizeTooLarge(
            config.max_chunk_bytes,
        ));
    }
    // Clamp the chunk size to the group policy cap when the caller supplied
    // one. A plaintext within the cap always encrypts to a ciphertext within
    // the record's `ciphertext<0..2^16-1>` field bound (cap + 16 <= 65535).
    let max_chunk_bytes = config
        .max_chunk_bytes
        .min(effective_plaintext_cap(config.max_plaintext_frame_len));

    let endpoint = client_endpoint(config.trust, config.server_addr)?;
    let connection = endpoint
        .connect(config.server_addr, &config.server_name)?
        .await?;
    let mut send = connection.open_uni().await?;
    let mut transcript =
        AgentTextStreamTranscriptV1::new(config.stream_id.clone(), config.start_event_id);

    for (index, chunk) in split_text_deltas(&config.text, max_chunk_bytes)
        .into_iter()
        .enumerate()
    {
        let record =
            AgentTextStreamRecordV1::text_delta(config.stream_id.clone(), index as u64 + 1, chunk);
        let wire_record = if let Some(crypto) = &config.crypto {
            encrypt_record(crypto, &record)?
        } else {
            record.clone()
        };
        write_record(&mut send, &wire_record).await?;
        transcript.append(record.seq, record.record_type, &record.plaintext_frame);
        if !config.chunk_delay.is_zero() {
            sleep(config.chunk_delay).await;
        }
    }

    send.finish()?;
    if timeout(SEND_CLOSE_WAIT, connection.closed()).await.is_err() {
        connection.close(0_u32.into(), b"done");
    }
    endpoint.wait_idle().await;
    Ok(SentTextStream {
        stream_id: transcript.stream_id().to_vec(),
        transcript_hash: transcript.hash(),
        chunk_count: transcript.chunk_count(),
    })
}

pub fn random_stream_id() -> Vec<u8> {
    let mut stream_id = [0_u8; 32];
    OsRng.fill_bytes(&mut stream_id);
    stream_id.to_vec()
}

pub fn split_text_deltas(text: &str, max_chunk_bytes: usize) -> Vec<Vec<u8>> {
    if text.is_empty() {
        return Vec::new();
    }

    let mut chunks = Vec::new();
    let mut current = String::new();
    for ch in text.chars() {
        let ch_len = ch.len_utf8();
        if !current.is_empty() && current.len() + ch_len > max_chunk_bytes {
            chunks.push(std::mem::take(&mut current).into_bytes());
        }
        if current.is_empty() && ch_len > max_chunk_bytes {
            chunks.push(ch.to_string().into_bytes());
            continue;
        }
        current.push(ch);
    }
    if !current.is_empty() {
        chunks.push(current.into_bytes());
    }
    chunks
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

fn configure_server() -> Result<(ServerConfig, Vec<u8>), QuicTextStreamError> {
    let certified_key = rcgen::generate_simple_self_signed(vec!["localhost".into()])
        .map_err(|err| QuicTextStreamError::Certificate(err.to_string()))?;
    let cert_der = CertificateDer::from(certified_key.cert);
    let key_der = PrivatePkcs8KeyDer::from(certified_key.signing_key.serialize_der());
    // Build the rustls config directly (not via the quinn convenience
    // constructor) so the direct-path ALPN `marmot.quic_stream.v1` is negotiated
    // during the TLS handshake, per spec/transports/quic.md.
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut crypto = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|err| QuicTextStreamError::Certificate(err.to_string()))?
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der.into())
        .map_err(|err| QuicTextStreamError::Certificate(err.to_string()))?;
    crypto.alpn_protocols = vec![QUIC_STREAM_ALPN_V1.to_vec()];
    let server_config = ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(crypto)
            .map_err(|err| QuicTextStreamError::Certificate(err.to_string()))?,
    ));
    Ok((server_config, cert_der.as_ref().to_vec()))
}

fn client_endpoint(
    trust: ServerTrust,
    server_addr: SocketAddr,
) -> Result<Endpoint, QuicTextStreamError> {
    // Every direct-path client config negotiates the spec-mandated ALPN
    // `marmot.quic_stream.v1`, so the rustls config is built here rather than via
    // the quinn convenience constructors (which set no ALPN).
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|err| QuicTextStreamError::ClientConfig(err.to_string()))?;
    let mut crypto = match trust {
        ServerTrust::Platform => builder
            .with_platform_verifier()
            .map_err(|err| QuicTextStreamError::ClientConfig(err.to_string()))?
            .with_no_client_auth(),
        ServerTrust::CertificateDer(cert_der) => {
            let mut roots = rustls::RootCertStore::empty();
            roots.add(CertificateDer::from(cert_der))?;
            builder
                .with_root_certificates(Arc::new(roots))
                .with_no_client_auth()
        }
        ServerTrust::InsecureLocal => {
            if !server_addr.ip().is_loopback() {
                return Err(QuicTextStreamError::InsecureLocalRequiresLoopback(
                    server_addr,
                ));
            }
            builder
                .dangerous()
                .with_custom_certificate_verifier(SkipServerVerification::new(provider))
                .with_no_client_auth()
        }
    };
    crypto.alpn_protocols = vec![QUIC_STREAM_ALPN_V1.to_vec()];
    let client_config = ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(crypto)
            .map_err(|err| QuicTextStreamError::ClientConfig(err.to_string()))?,
    ));
    let mut endpoint = Endpoint::client(LOCAL_BIND)?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

async fn write_record(
    send: &mut quinn::SendStream,
    record: &AgentTextStreamRecordV1,
) -> Result<(), QuicTextStreamError> {
    let bytes = record.encode()?;
    let len =
        u32::try_from(bytes.len()).map_err(|_| QuicTextStreamError::FrameTooLarge(bytes.len()))?;
    send.write_all(&len.to_be_bytes()).await?;
    send.write_all(&bytes).await?;
    Ok(())
}

async fn read_record(
    recv: &mut quinn::RecvStream,
    max_frame_len: usize,
) -> Result<Option<AgentTextStreamRecordV1>, QuicTextStreamError> {
    let mut len_bytes = [0_u8; FRAME_LEN_BYTES];
    let mut read = 0;
    while read < FRAME_LEN_BYTES {
        match recv.read(&mut len_bytes[read..]).await? {
            Some(0) => return Err(QuicTextStreamError::TruncatedFrameLength),
            Some(n) => read += n,
            None if read == 0 => return Ok(None),
            None => return Err(QuicTextStreamError::TruncatedFrameLength),
        }
    }

    let len = u32::from_be_bytes(len_bytes) as usize;
    validate_frame_len(len, max_frame_len)?;
    let mut bytes = vec![0_u8; len];
    recv.read_exact(&mut bytes).await?;
    Ok(Some(AgentTextStreamRecordV1::decode(&bytes)?))
}

fn validate_frame_len(len: usize, max_frame_len: usize) -> Result<(), QuicTextStreamError> {
    if len == 0 {
        return Err(QuicTextStreamError::EmptyFrame);
    }
    if len > max_frame_len.min(MAX_FRAME_SIZE) {
        return Err(QuicTextStreamError::FrameTooLarge(len));
    }
    Ok(())
}

#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new(provider: Arc<rustls::crypto::CryptoProvider>) -> Arc<Self> {
        Arc::new(Self(provider))
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum QuicTextStreamError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Rustls(#[from] rustls::Error),
    #[error(transparent)]
    QuinnConfig(#[from] quinn::ConfigError),
    #[error(transparent)]
    Connect(#[from] quinn::ConnectError),
    #[error(transparent)]
    Connection(#[from] quinn::ConnectionError),
    #[error(transparent)]
    Write(#[from] quinn::WriteError),
    #[error(transparent)]
    Read(#[from] quinn::ReadError),
    #[error(transparent)]
    ReadExact(#[from] quinn::ReadExactError),
    #[error(transparent)]
    ClosedStream(#[from] quinn::ClosedStream),
    #[error(transparent)]
    Stopped(#[from] quinn::StoppedError),
    #[error(transparent)]
    Record(#[from] AgentTextStreamRecordError),
    #[error(transparent)]
    ReceiveLimit(#[from] AgentTextStreamReceiveLimitError),
    #[error(transparent)]
    Utf8(#[from] str::Utf8Error),
    #[error("certificate setup failed: {0}")]
    Certificate(String),
    #[error("QUIC client config failed: {0}")]
    ClientConfig(String),
    #[error("--insecure-local is only allowed for loopback QUIC endpoints, got {0}")]
    InsecureLocalRequiresLoopback(SocketAddr),
    #[error("QUIC endpoint closed before accepting a stream")]
    EndpointClosed,
    #[error("agent text stream did not contain any records")]
    EmptyStream,
    #[error("agent text stream frame length was truncated")]
    TruncatedFrameLength,
    #[error("agent text stream frame cannot be empty")]
    EmptyFrame,
    #[error("agent text stream frame is too large: {0}")]
    FrameTooLarge(usize),
    #[error("agent text stream chunk size cannot be zero")]
    EmptyChunkSize,
    #[error("agent text stream chunk size exceeds app profile max: {0}")]
    ChunkSizeTooLarge(usize),
    #[error("agent text stream encrypted frame would exceed app profile max: plaintext {0}")]
    EncryptedFrameTooLarge(usize),
    #[error("agent text stream mixed stream ids in one QUIC stream")]
    MixedStreamIds,
    /// A record arrived ahead of the high-water mark (`actual > expected`),
    /// signalling a gap the receiver cannot fill without a replay source.
    /// Records at or below the high-water mark are discarded silently and
    /// never raise this error.
    #[error("agent text stream sequence gap: expected {expected}, got {actual}")]
    UnexpectedSequence { expected: u64, actual: u64 },
    #[error("agent text stream crypto failed: {0}")]
    Crypto(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_path_alpn_is_the_pinned_wire_value() {
        // Wire-visible interop id; both peers must offer exactly this (quic.md).
        assert_eq!(QUIC_STREAM_PROTOCOL_V1, "marmot.quic_stream.v1");
        assert_eq!(QUIC_STREAM_ALPN_V1, b"marmot.quic_stream.v1");
    }

    #[test]
    fn text_delta_splitter_preserves_utf8_boundaries() {
        let chunks = split_text_deltas("héllo", 2);
        assert_eq!(
            chunks
                .iter()
                .map(|chunk| str::from_utf8(chunk).unwrap())
                .collect::<Vec<_>>(),
            vec!["h", "é", "ll", "o"]
        );
    }

    #[test]
    fn text_delta_splitter_keeps_oversized_multibyte_characters_whole() {
        let chunks = split_text_deltas("éa", 1);
        assert_eq!(
            chunks
                .iter()
                .map(|chunk| str::from_utf8(chunk).unwrap())
                .collect::<Vec<_>>(),
            vec!["é", "a"]
        );
    }

    #[test]
    fn oversized_frames_are_rejected_before_allocation() {
        assert!(matches!(
            validate_frame_len(MAX_FRAME_SIZE + 1, MAX_FRAME_SIZE),
            Err(QuicTextStreamError::FrameTooLarge(_))
        ));
    }

    #[test]
    fn policy_frame_cap_is_policy_plus_fixed_allowance_with_app_ceiling() {
        assert_eq!(AGENT_TEXT_STREAM_FRAME_ALLOWANCE, 1024);
        assert_eq!(frame_len_cap(None), MAX_FRAME_SIZE);
        assert_eq!(
            frame_len_cap(Some(4096)),
            4096 + AGENT_TEXT_STREAM_FRAME_ALLOWANCE
        );
        // A policy above the app-profile ceiling is clamped to the ceiling, and
        // a zero policy falls back to the ceiling.
        assert_eq!(frame_len_cap(Some(u32::MAX)), MAX_FRAME_SIZE);
        assert_eq!(frame_len_cap(Some(0)), MAX_FRAME_SIZE);
        assert!(matches!(
            validate_frame_len(
                4096 + AGENT_TEXT_STREAM_FRAME_ALLOWANCE + 1,
                frame_len_cap(Some(4096))
            ),
            Err(QuicTextStreamError::FrameTooLarge(_))
        ));
        assert!(
            validate_frame_len(
                4096 + AGENT_TEXT_STREAM_FRAME_ALLOWANCE,
                frame_len_cap(Some(4096))
            )
            .is_ok()
        );
    }

    #[test]
    fn stream_record_text_decodes_renderable_frames_and_leaves_advisory_records_empty() {
        use cgka_traits::agent_text_stream::{
            AGENT_TEXT_STREAM_RECORD_ABORT, AGENT_TEXT_STREAM_RECORD_FINAL_NOTICE,
        };

        let stream_id = vec![0x11; 32];
        let record = |record_type, plaintext: &str| {
            AgentTextStreamRecordV1::new(stream_id.clone(), 1, record_type, plaintext.as_bytes())
        };

        // Renderable frames decode to their UTF-8 plaintext. Checkpoint is a full
        // preview snapshot the consumer swaps in, so it must not stay blank.
        for (record_type, plaintext) in [
            (AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, "hello"),
            (AGENT_TEXT_STREAM_RECORD_STATUS, "thinking"),
            (AGENT_TEXT_STREAM_RECORD_PROGRESS_DELTA, "search: glp-1"),
            (AGENT_TEXT_STREAM_RECORD_CHECKPOINT, "hello world"),
        ] {
            assert_eq!(
                stream_record_text(&record(record_type, plaintext)).unwrap(),
                plaintext
            );
        }

        // Abort and FinalNotice are advisory: the consumer reacts to the record
        // type, so they decode to "" even when the sender attached bytes.
        for record_type in [
            AGENT_TEXT_STREAM_RECORD_ABORT,
            AGENT_TEXT_STREAM_RECORD_FINAL_NOTICE,
        ] {
            assert_eq!(
                stream_record_text(&record(record_type, "ignored")).unwrap(),
                ""
            );
        }
    }

    #[test]
    fn receive_limits_bound_record_count_and_plaintext_bytes() {
        let record = AgentTextStreamRecordV1::text_delta(vec![0x11; 32], 1, b"hello".to_vec());
        let mut record_limited =
            AgentTextStreamReceiveAccumulator::new(AgentTextStreamReceiveLimits {
                max_records: 1,
                max_plaintext_bytes: 1024,
                ..AgentTextStreamReceiveLimits::default()
            });
        record_limited.observe(&record).unwrap();
        assert!(matches!(
            record_limited.observe(&record),
            Err(AgentTextStreamReceiveLimitError::RecordLimitExceeded {
                attempted: 2,
                limit: 1
            })
        ));

        let mut byte_limited =
            AgentTextStreamReceiveAccumulator::new(AgentTextStreamReceiveLimits {
                max_records: 10,
                max_plaintext_bytes: 4,
                ..AgentTextStreamReceiveLimits::default()
            });
        assert!(matches!(
            byte_limited.observe(&record),
            Err(
                AgentTextStreamReceiveLimitError::PlaintextByteLimitExceeded {
                    attempted: 5,
                    limit: 4
                }
            )
        ));
    }

    #[test]
    fn crypto_seals_record_body_and_round_trips() {
        let stream_id = vec![0x42; 32];
        let crypto = AgentTextStreamCrypto::new(
            SecretBytes::new(vec![0x07; 32]),
            AgentTextStreamKeyContextV1::new(
                cgka_traits::GroupId::new(vec![0x01; 32]),
                stream_id.clone(),
                cgka_traits::EpochId(3),
                cgka_traits::MemberId::new(vec![0x02; 32]),
                MessageId::new(vec![0x24; 32]),
            ),
        );
        let record = AgentTextStreamRecordV1::text_delta(stream_id, 1, b"hello".to_vec());
        let sealed = encrypt_record(&crypto, &record).unwrap();
        assert_ne!(sealed.plaintext_frame, b"hello");
        assert!(
            !sealed
                .encode()
                .unwrap()
                .windows(b"hello".len())
                .any(|window| window == b"hello")
        );

        let opened = decrypt_record(&crypto, &sealed).unwrap();
        assert_eq!(opened, record);
    }

    #[test]
    fn crypto_debug_redacts_stream_secret() {
        let crypto = AgentTextStreamCrypto::new(
            SecretBytes::new(b"debug-visible stream secret!!!!!".to_vec()),
            AgentTextStreamKeyContextV1::new(
                cgka_traits::GroupId::new(vec![0x01; 32]),
                vec![0x42; 32],
                cgka_traits::EpochId(3),
                cgka_traits::MemberId::new(vec![0x02; 32]),
                MessageId::new(vec![0x24; 32]),
            ),
        );

        let rendered = format!("{crypto:?}");

        assert!(!rendered.contains("debug-visible"));
        assert!(rendered.contains("redacted"));
    }

    #[test]
    fn crypto_rejects_wrong_stream_secret_length() {
        let crypto = AgentTextStreamCrypto::new(
            SecretBytes::new(vec![0x07; 31]),
            AgentTextStreamKeyContextV1::new(
                cgka_traits::GroupId::new(vec![0x01; 32]),
                vec![0x42; 32],
                cgka_traits::EpochId(3),
                cgka_traits::MemberId::new(vec![0x02; 32]),
                MessageId::new(vec![0x24; 32]),
            ),
        );
        let record = AgentTextStreamRecordV1::text_delta(vec![0x42; 32], 1, b"hello".to_vec());

        assert!(matches!(
            encrypt_record(&crypto, &record),
            Err(QuicTextStreamError::Crypto(_))
        ));
    }

    #[tokio::test]
    async fn insecure_local_rejects_remote_server_addr() {
        let err = send_text_stream(SendTextStream {
            server_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 4450),
            server_name: "example.com".to_owned(),
            trust: ServerTrust::InsecureLocal,
            stream_id: vec![0x42; 32],
            start_event_id: MessageId::new(vec![0x24; 32]),
            text: "hello".to_owned(),
            max_chunk_bytes: 5,
            chunk_delay: Duration::ZERO,
            crypto: None,
            max_plaintext_frame_len: None,
        })
        .await
        .unwrap_err();

        assert!(matches!(
            err,
            QuicTextStreamError::InsecureLocalRequiresLoopback(_)
        ));
    }

    #[tokio::test]
    async fn quic_receiver_renders_text_deltas_in_order() {
        let receiver = QuicTextStreamReceiver::bind(LOCAL_BIND).unwrap();
        let server_addr = receiver.local_addr().unwrap();
        let server_cert = receiver.server_cert_der().to_vec();
        let stream_id = vec![0x42; 32];
        let start_event_id = MessageId::new(vec![0x24; 32]);
        let receive = tokio::spawn(receiver.receive_once(start_event_id.clone(), None));

        let sent = send_text_stream(SendTextStream {
            server_addr,
            server_name: "localhost".to_owned(),
            trust: ServerTrust::CertificateDer(server_cert),
            stream_id: stream_id.clone(),
            start_event_id,
            text: "hello over quic".to_owned(),
            max_chunk_bytes: 5,
            chunk_delay: Duration::ZERO,
            crypto: None,
            max_plaintext_frame_len: None,
        })
        .await
        .unwrap();

        let received = receive.await.unwrap().unwrap();
        assert_eq!(received.stream_id, stream_id);
        assert_eq!(received.text, "hello over quic");
        assert_eq!(
            received
                .chunks
                .iter()
                .map(|chunk| chunk.text.as_str())
                .collect::<Vec<_>>(),
            vec!["hello", " over", " quic"]
        );
        assert_eq!(received.chunk_count, 3);
        assert_eq!(sent.stream_id, stream_id);
        assert_eq!(sent.chunk_count, 3);
        assert_eq!(sent.transcript_hash, received.transcript_hash);
    }

    #[tokio::test]
    async fn send_clamps_chunk_size_to_group_policy_cap() {
        let receiver = QuicTextStreamReceiver::bind(LOCAL_BIND).unwrap();
        let server_addr = receiver.local_addr().unwrap();
        let server_cert = receiver.server_cert_der().to_vec();
        let stream_id = vec![0x42; 32];
        let start_event_id = MessageId::new(vec![0x24; 32]);
        let receive = tokio::spawn(receiver.receive_once(start_event_id.clone(), None));

        let sent = send_text_stream(SendTextStream {
            server_addr,
            server_name: "localhost".to_owned(),
            trust: ServerTrust::CertificateDer(server_cert),
            stream_id: stream_id.clone(),
            start_event_id,
            text: "hello over quic".to_owned(),
            max_chunk_bytes: 1024,
            chunk_delay: Duration::ZERO,
            crypto: None,
            max_plaintext_frame_len: Some(5),
        })
        .await
        .unwrap();

        let received = receive.await.unwrap().unwrap();
        assert_eq!(received.text, "hello over quic");
        assert_eq!(
            received
                .chunks
                .iter()
                .map(|chunk| chunk.text.as_str())
                .collect::<Vec<_>>(),
            vec!["hello", " over", " quic"]
        );
        assert_eq!(sent.chunk_count, 3);
    }

    async fn raw_record_sender(
        server_addr: SocketAddr,
        server_cert: Vec<u8>,
        records: Vec<AgentTextStreamRecordV1>,
    ) {
        let endpoint =
            client_endpoint(ServerTrust::CertificateDer(server_cert), server_addr).unwrap();
        let connection = endpoint
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        let mut send = connection.open_uni().await.unwrap();
        for record in &records {
            write_record(&mut send, record).await.unwrap();
        }
        send.finish().unwrap();
        if timeout(SEND_CLOSE_WAIT, connection.closed()).await.is_err() {
            connection.close(0_u32.into(), b"done");
        }
        endpoint.wait_idle().await;
    }

    #[tokio::test]
    async fn receiver_silently_discards_replayed_records_at_or_below_high_water() {
        let receiver = QuicTextStreamReceiver::bind(LOCAL_BIND).unwrap();
        let server_addr = receiver.local_addr().unwrap();
        let server_cert = receiver.server_cert_der().to_vec();
        let stream_id = vec![0x42; 32];
        let start_event_id = MessageId::new(vec![0x24; 32]);
        let receive = tokio::spawn(receiver.receive_once(start_event_id.clone(), None));

        let first = AgentTextStreamRecordV1::text_delta(stream_id.clone(), 1, b"hel".to_vec());
        let second = AgentTextStreamRecordV1::text_delta(stream_id.clone(), 2, b"lo".to_vec());
        let third = AgentTextStreamRecordV1::text_delta(stream_id.clone(), 3, b" world".to_vec());
        // A broker replaying its retained backlog re-sends records the receiver
        // already accepted; those must be discarded silently, never
        // stream-fatal, and the next accepted record is high-water + 1.
        raw_record_sender(
            server_addr,
            server_cert,
            vec![
                first.clone(),
                second.clone(),
                first.clone(),
                second.clone(),
                third.clone(),
            ],
        )
        .await;

        let received = receive.await.unwrap().unwrap();
        assert_eq!(received.text, "hello world");
        assert_eq!(received.chunk_count, 3);
        assert_eq!(
            received
                .chunks
                .iter()
                .map(|chunk| chunk.seq)
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );

        let mut transcript = AgentTextStreamTranscriptV1::new(stream_id, start_event_id);
        transcript.append(1, AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, b"hel");
        transcript.append(2, AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, b"lo");
        transcript.append(3, AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, b" world");
        assert_eq!(received.transcript_hash, transcript.hash());
    }

    #[tokio::test]
    async fn receiver_reports_gap_when_record_is_ahead_of_high_water() {
        let receiver = QuicTextStreamReceiver::bind(LOCAL_BIND).unwrap();
        let server_addr = receiver.local_addr().unwrap();
        let server_cert = receiver.server_cert_der().to_vec();
        let stream_id = vec![0x42; 32];
        let start_event_id = MessageId::new(vec![0x24; 32]);
        let receive = tokio::spawn(receiver.receive_once(start_event_id, None));

        raw_record_sender(
            server_addr,
            server_cert,
            vec![
                AgentTextStreamRecordV1::text_delta(stream_id.clone(), 1, b"hel".to_vec()),
                AgentTextStreamRecordV1::text_delta(stream_id, 3, b"lo".to_vec()),
            ],
        )
        .await;

        let err = receive.await.unwrap().unwrap_err();
        assert!(matches!(
            err,
            QuicTextStreamError::UnexpectedSequence {
                expected: 2,
                actual: 3
            }
        ));
    }
}
