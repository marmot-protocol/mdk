//! Shared agent text stream protocol values.
//!
//! This module intentionally stops below the QUIC transport binding. It gives
//! upper layers stable names for the Marmot component/capabilities and small
//! helpers for the component state, key context, and final transcript
//! hash.

pub use crate::app_components::{
    AGENT_TEXT_STREAM_QUIC_COMPONENT, AGENT_TEXT_STREAM_QUIC_COMPONENT_ID,
};
use crate::app_components::{AppComponentData, decode_quic_varint, encode_quic_varint};
use crate::capabilities::{Capability, Feature, GroupCapabilities};
use crate::types::{EpochId, GroupId, MemberId, MessageId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const AGENT_TEXT_STREAM_QUIC_RECEIVE_FEATURE: Feature =
    Feature("marmot.feature.agent_text_stream_quic.receive.v1");
pub const AGENT_TEXT_STREAM_QUIC_SEND_FEATURE: Feature =
    Feature("marmot.feature.agent_text_stream_quic.send.v1");
pub const AGENT_TEXT_STREAM_QUIC_FANOUT_FEATURE: Feature =
    Feature("marmot.feature.agent_text_stream_quic.fanout.v1");

/// MLS leaf-capability backing each agent-text-stream-QUIC role
/// (`agent-text-stream-quic-v1.md`). Each role capability advertised by a
/// KeyPackage is a distinct private-use MLS extension type, so a member can
/// advertise `receive` without advertising `send`/`fanout`. This is what makes
/// `required_member_roles` enforceable per role rather than only at
/// component-support granularity. The component id (`0x8006`) stays separate: it
/// gates "understands the component", these gate "supports the role".
pub const AGENT_TEXT_STREAM_QUIC_RECEIVE_CAPABILITY: Capability = Capability::Extension(0xF2D1);
pub const AGENT_TEXT_STREAM_QUIC_SEND_CAPABILITY: Capability = Capability::Extension(0xF2D2);
pub const AGENT_TEXT_STREAM_QUIC_FANOUT_CAPABILITY: Capability = Capability::Extension(0xF2D4);

/// Map a role to its `(bit, Feature, Capability)` triple. The single source of
/// truth for the role bit -> capability mapping in
/// `agent-text-stream-quic-v1.md`, shared by the engine enforcement and the app
/// feature registration so they cannot drift.
pub const AGENT_TEXT_STREAM_QUIC_ROLES: [(u8, Feature, Capability); 3] = [
    (
        AGENT_TEXT_STREAM_ROLE_RECEIVE,
        AGENT_TEXT_STREAM_QUIC_RECEIVE_FEATURE,
        AGENT_TEXT_STREAM_QUIC_RECEIVE_CAPABILITY,
    ),
    (
        AGENT_TEXT_STREAM_ROLE_SEND,
        AGENT_TEXT_STREAM_QUIC_SEND_FEATURE,
        AGENT_TEXT_STREAM_QUIC_SEND_CAPABILITY,
    ),
    (
        AGENT_TEXT_STREAM_ROLE_FANOUT,
        AGENT_TEXT_STREAM_QUIC_FANOUT_FEATURE,
        AGENT_TEXT_STREAM_QUIC_FANOUT_CAPABILITY,
    ),
];

/// Translate a `required_member_roles` mask into the set of role capabilities
/// every member MUST advertise. Empty when the mask requires no roles. Unknown
/// bits are ignored here; component validation rejects unknown bits separately.
pub fn required_role_capabilities(required_member_roles: u8) -> GroupCapabilities {
    let mut out = GroupCapabilities::default();
    for (bit, _feature, capability) in AGENT_TEXT_STREAM_QUIC_ROLES {
        if required_member_roles & bit != 0 {
            out.insert(capability);
        }
    }
    out
}

/// Lookup key for the agent-text-stream secret in the
/// [`crate::group_context::GroupContextSnapshot`] secrets map (used by
/// `GroupContextView::exporter_secret`). This is an internal cache key, NOT the
/// MLS exporter label/context: the secret is derived as
/// `MLS-Exporter("marmot", "agent-text-stream-quic", 32)` — label `"marmot"`,
/// context `"agent-text-stream-quic"` — per the Marmot spec.
pub const AGENT_TEXT_STREAM_EXPORTER_CACHE_KEY: &str = "marmot/agent-text-stream-quic";
pub const AGENT_TEXT_STREAM_KEY_CONTEXT_VERSION: &[u8] = b"v1";
pub const AGENT_TEXT_STREAM_TRANSCRIPT_HASH_CONTEXT: &[u8] =
    b"marmot agent text stream transcript v1";

pub const AGENT_TEXT_STREAM_ROLE_RECEIVE: u8 = 0x01;
pub const AGENT_TEXT_STREAM_ROLE_SEND: u8 = 0x02;
pub const AGENT_TEXT_STREAM_ROLE_FANOUT: u8 = 0x04;
pub const AGENT_TEXT_STREAM_ROLE_MASK: u8 =
    AGENT_TEXT_STREAM_ROLE_RECEIVE | AGENT_TEXT_STREAM_ROLE_SEND | AGENT_TEXT_STREAM_ROLE_FANOUT;

pub const AGENT_TEXT_STREAM_RECORD_TEXT_DELTA: u8 = 0x01;
pub const AGENT_TEXT_STREAM_RECORD_PROGRESS_DELTA: u8 = 0x02;
pub const AGENT_TEXT_STREAM_RECORD_STATUS: u8 = 0x03;
pub const AGENT_TEXT_STREAM_RECORD_CHECKPOINT: u8 = 0x04;
pub const AGENT_TEXT_STREAM_RECORD_ABORT: u8 = 0x05;
pub const AGENT_TEXT_STREAM_RECORD_FINAL_NOTICE: u8 = 0x06;
pub const AGENT_TEXT_STREAM_RECORD_VERSION: u8 = 0x01;
pub const AGENT_TEXT_STREAM_MAX_STREAM_ID_LEN: usize = 64;
pub const AGENT_TEXT_STREAM_PROFILE_STREAM_ID_LEN: usize = 32;
pub const AGENT_TEXT_STREAM_START_EVENT_ID_LEN: usize = 32;

/// App-profile cap on the plaintext bytes in one stream frame before record
/// encryption. 65519 keeps a maximum-length frame's ciphertext
/// (`plaintext_len + 16` AEAD tag bytes) within the record's
/// `ciphertext<0..2^16-1>` field bound.
pub const AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN: u32 = 65519;
/// Wire bound of the record's `ciphertext<0..2^16-1>` field. The
/// `AgentTextStreamRecordV1` frame field carries ciphertext on the wire, so
/// the struct-level validator enforces this bound; the plaintext policy cap is
/// [`AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN`].
pub const AGENT_TEXT_STREAM_MAX_RECORD_CIPHERTEXT_LEN: u32 = u16::MAX as u32;
/// AEAD tag bytes appended to every encrypted record frame
/// (ChaCha20-Poly1305).
pub const AGENT_TEXT_STREAM_AEAD_TAG_LEN: usize = 16;
pub const AGENT_TEXT_STREAM_DEFAULT_MAX_RECORDS: u64 = 4096;
pub const AGENT_TEXT_STREAM_DEFAULT_MAX_PLAINTEXT_BYTES: usize = 1024 * 1024;
pub const AGENT_TEXT_STREAM_MAX_REPLAY_TTL_SECS: u32 = 5 * 60;
pub const AGENT_TEXT_STREAM_MAX_PADDING_BUCKET_BYTES: u16 = 4096;

/// Encoded `0x8006` component state length in bytes: `required_member_roles`
/// (u8), `allowed_member_roles` (u8), `max_plaintext_frame_len` (u32),
/// `replay_ttl_secs` (u32), `padding_bucket_bytes` (u16).
pub const AGENT_TEXT_STREAM_COMPONENT_STATE_LEN: usize = 12;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentTextStreamQuicPolicyV1 {
    pub required_member_roles: u8,
    pub allowed_member_roles: u8,
    pub max_plaintext_frame_len: u32,
    pub replay_ttl_secs: u32,
    pub padding_bucket_bytes: u16,
}

impl AgentTextStreamQuicPolicyV1 {
    pub fn user_to_agent_default() -> Self {
        Self {
            required_member_roles: AGENT_TEXT_STREAM_ROLE_RECEIVE,
            allowed_member_roles: AGENT_TEXT_STREAM_ROLE_RECEIVE | AGENT_TEXT_STREAM_ROLE_SEND,
            max_plaintext_frame_len: 4096,
            replay_ttl_secs: 0,
            padding_bucket_bytes: 0,
        }
    }

    pub fn encode_component_state(&self) -> Result<Vec<u8>, AgentTextStreamPolicyError> {
        self.validate()?;
        let mut out = Vec::with_capacity(AGENT_TEXT_STREAM_COMPONENT_STATE_LEN);
        out.push(self.required_member_roles);
        out.push(self.allowed_member_roles);
        out.extend_from_slice(&self.max_plaintext_frame_len.to_be_bytes());
        out.extend_from_slice(&self.replay_ttl_secs.to_be_bytes());
        out.extend_from_slice(&self.padding_bucket_bytes.to_be_bytes());
        Ok(out)
    }

    pub fn decode_component_state(bytes: &[u8]) -> Result<Self, AgentTextStreamPolicyError> {
        if bytes.len() != AGENT_TEXT_STREAM_COMPONENT_STATE_LEN {
            return Err(AgentTextStreamPolicyError::InvalidComponentStateLength(
                bytes.len(),
            ));
        }
        let policy = Self {
            required_member_roles: bytes[0],
            allowed_member_roles: bytes[1],
            max_plaintext_frame_len: u32::from_be_bytes(
                bytes[2..6]
                    .try_into()
                    .expect("slice length checked by component state length"),
            ),
            replay_ttl_secs: u32::from_be_bytes(
                bytes[6..10]
                    .try_into()
                    .expect("slice length checked by component state length"),
            ),
            padding_bucket_bytes: u16::from_be_bytes(
                bytes[10..12]
                    .try_into()
                    .expect("slice length checked by component state length"),
            ),
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn to_app_component_data(&self) -> Result<AppComponentData, AgentTextStreamPolicyError> {
        Ok(AppComponentData {
            component_id: AGENT_TEXT_STREAM_QUIC_COMPONENT_ID,
            data: self.encode_component_state()?,
        })
    }

    pub fn validate(&self) -> Result<(), AgentTextStreamPolicyError> {
        if self.required_member_roles == 0 {
            return Err(AgentTextStreamPolicyError::EmptyRequiredRoles);
        }
        if self.required_member_roles & !AGENT_TEXT_STREAM_ROLE_MASK != 0 {
            return Err(AgentTextStreamPolicyError::UnknownRequiredRoleBits(
                self.required_member_roles,
            ));
        }
        if self.allowed_member_roles & !AGENT_TEXT_STREAM_ROLE_MASK != 0 {
            return Err(AgentTextStreamPolicyError::UnknownAllowedRoleBits(
                self.allowed_member_roles,
            ));
        }
        if self.required_member_roles & !self.allowed_member_roles != 0 {
            return Err(AgentTextStreamPolicyError::RequiredRolesNotAllowed);
        }
        if self.max_plaintext_frame_len == 0 {
            return Err(AgentTextStreamPolicyError::EmptyFrameLimit);
        }
        if self.max_plaintext_frame_len > AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN {
            return Err(AgentTextStreamPolicyError::FrameLimitTooLarge(
                self.max_plaintext_frame_len,
            ));
        }
        if self.replay_ttl_secs > AGENT_TEXT_STREAM_MAX_REPLAY_TTL_SECS {
            return Err(AgentTextStreamPolicyError::ReplayTtlTooLarge(
                self.replay_ttl_secs,
            ));
        }
        if self.padding_bucket_bytes > AGENT_TEXT_STREAM_MAX_PADDING_BUCKET_BYTES {
            return Err(AgentTextStreamPolicyError::PaddingBucketTooLarge(
                self.padding_bucket_bytes,
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AgentTextStreamPolicyError {
    #[error("required agent text stream roles cannot be empty")]
    EmptyRequiredRoles,
    #[error("required agent text stream role mask contains unknown bits: {0:#04x}")]
    UnknownRequiredRoleBits(u8),
    #[error("allowed agent text stream role mask contains unknown bits: {0:#04x}")]
    UnknownAllowedRoleBits(u8),
    #[error("required agent text stream roles must be a subset of allowed roles")]
    RequiredRolesNotAllowed,
    #[error("agent text stream plaintext frame limit cannot be zero")]
    EmptyFrameLimit,
    #[error("agent text stream component state must be 12 bytes, got {0}")]
    InvalidComponentStateLength(usize),
    #[error("agent text stream plaintext frame limit exceeds app profile max: {0}")]
    FrameLimitTooLarge(u32),
    #[error("agent text stream replay ttl exceeds app profile max: {0}")]
    ReplayTtlTooLarge(u32),
    #[error("agent text stream padding bucket exceeds app profile max: {0}")]
    PaddingBucketTooLarge(u16),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentTextStreamRecordV1 {
    pub stream_id: Vec<u8>,
    pub seq: u64,
    pub record_type: u8,
    pub flags: u8,
    pub plaintext_frame: Vec<u8>,
}

impl AgentTextStreamRecordV1 {
    pub fn new(
        stream_id: impl Into<Vec<u8>>,
        seq: u64,
        record_type: u8,
        plaintext_frame: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            stream_id: stream_id.into(),
            seq,
            record_type,
            flags: 0,
            plaintext_frame: plaintext_frame.into(),
        }
    }

    pub fn text_delta(
        stream_id: impl Into<Vec<u8>>,
        seq: u64,
        plaintext_frame: impl Into<Vec<u8>>,
    ) -> Self {
        Self::new(
            stream_id,
            seq,
            AGENT_TEXT_STREAM_RECORD_TEXT_DELTA,
            plaintext_frame,
        )
    }

    pub fn encode(&self) -> Result<Vec<u8>, AgentTextStreamRecordError> {
        self.validate()?;
        let mut out = Vec::new();
        out.push(AGENT_TEXT_STREAM_RECORD_VERSION);
        encode_quic_varint(self.stream_id.len() as u64, &mut out);
        out.extend_from_slice(&self.stream_id);
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.push(self.record_type);
        out.push(self.flags);
        encode_quic_varint(self.plaintext_frame.len() as u64, &mut out);
        out.extend_from_slice(&self.plaintext_frame);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, AgentTextStreamRecordError> {
        let (version, rest) = bytes
            .split_first()
            .ok_or(AgentTextStreamRecordError::Truncated("version"))?;
        if *version != AGENT_TEXT_STREAM_RECORD_VERSION {
            return Err(AgentTextStreamRecordError::UnsupportedVersion(*version));
        }

        let (stream_id, rest) = take_len_prefixed(rest, "stream_id")?;
        let (seq_bytes, rest) = take_exact(rest, 8, "seq")?;
        let seq = u64::from_be_bytes(
            seq_bytes
                .try_into()
                .expect("slice length checked by take_exact"),
        );
        let (record_type_bytes, rest) = take_exact(rest, 1, "record_type")?;
        let (flags_bytes, rest) = take_exact(rest, 1, "flags")?;
        let (plaintext_frame, rest) = take_len_prefixed(rest, "plaintext_frame")?;
        if !rest.is_empty() {
            return Err(AgentTextStreamRecordError::TrailingBytes(rest.len()));
        }

        let record = Self {
            stream_id: stream_id.to_vec(),
            seq,
            record_type: record_type_bytes[0],
            flags: flags_bytes[0],
            plaintext_frame: plaintext_frame.to_vec(),
        };
        record.validate()?;
        Ok(record)
    }

    pub fn validate(&self) -> Result<(), AgentTextStreamRecordError> {
        if self.stream_id.is_empty() {
            return Err(AgentTextStreamRecordError::EmptyStreamId);
        }
        if self.stream_id.len() > AGENT_TEXT_STREAM_MAX_STREAM_ID_LEN {
            return Err(AgentTextStreamRecordError::StreamIdTooLong(
                self.stream_id.len(),
            ));
        }
        if !is_known_record_type(self.record_type) {
            return Err(AgentTextStreamRecordError::UnknownRecordType(
                self.record_type,
            ));
        }
        // The frame field carries ciphertext on the wire, so the struct bound
        // is the `ciphertext<0..2^16-1>` field bound. The tighter plaintext
        // policy cap (`max_plaintext_frame_len`, app-profile max 65519) is
        // enforced on the send chunking and encrypt paths.
        if self.plaintext_frame.len() > AGENT_TEXT_STREAM_MAX_RECORD_CIPHERTEXT_LEN as usize {
            return Err(AgentTextStreamRecordError::PlaintextFrameTooLarge(
                self.plaintext_frame.len(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AgentTextStreamRecordError {
    #[error("agent text stream record is truncated while reading {0}")]
    Truncated(&'static str),
    #[error("unsupported agent text stream record version: {0}")]
    UnsupportedVersion(u8),
    #[error("agent text stream record contains trailing bytes: {0}")]
    TrailingBytes(usize),
    #[error("agent text stream record length decode failed for {field}: {reason}")]
    LengthDecode { field: &'static str, reason: String },
    #[error("agent text stream id cannot be empty")]
    EmptyStreamId,
    #[error("agent text stream id is too long: {0}")]
    StreamIdTooLong(usize),
    #[error("unknown agent text stream record type: {0:#04x}")]
    UnknownRecordType(u8),
    #[error("agent text stream plaintext frame is too large: {0}")]
    PlaintextFrameTooLarge(usize),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentTextStreamKeyContextV1 {
    pub group_id: GroupId,
    pub stream_id: Vec<u8>,
    pub mls_epoch: EpochId,
    pub sender_id: MemberId,
    pub start_event_id: MessageId,
}

impl AgentTextStreamKeyContextV1 {
    pub fn new(
        group_id: GroupId,
        stream_id: impl Into<Vec<u8>>,
        mls_epoch: EpochId,
        sender_id: MemberId,
        start_event_id: MessageId,
    ) -> Self {
        Self {
            group_id,
            stream_id: stream_id.into(),
            mls_epoch,
            sender_id,
            start_event_id,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_len_prefixed(&mut out, AGENT_TEXT_STREAM_KEY_CONTEXT_VERSION);
        push_len_prefixed(&mut out, self.group_id.as_slice());
        push_len_prefixed(&mut out, &self.stream_id);
        out.extend_from_slice(&self.mls_epoch.0.to_be_bytes());
        push_len_prefixed(&mut out, self.sender_id.as_slice());
        push_len_prefixed(&mut out, self.start_event_id.as_slice());
        out
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentTextStreamTranscriptV1 {
    stream_id: Vec<u8>,
    start_event_id: MessageId,
    hash: [u8; 32],
    chunk_count: u64,
}

impl AgentTextStreamTranscriptV1 {
    pub fn new(stream_id: impl Into<Vec<u8>>, start_event_id: MessageId) -> Self {
        let stream_id = stream_id.into();
        let mut hasher = Sha256::new();
        hasher.update(AGENT_TEXT_STREAM_TRANSCRIPT_HASH_CONTEXT);
        hash_len_prefixed(&mut hasher, &stream_id);
        hash_len_prefixed(&mut hasher, start_event_id.as_slice());
        Self {
            stream_id,
            start_event_id,
            hash: hasher.finalize().into(),
            chunk_count: 0,
        }
    }

    pub fn append(&mut self, seq: u64, record_type: u8, plaintext_frame: &[u8]) {
        let mut hasher = Sha256::new();
        hasher.update(self.hash);
        hasher.update(seq.to_be_bytes());
        hasher.update([record_type]);
        hasher.update(plaintext_frame);
        self.hash = hasher.finalize().into();
        self.chunk_count += 1;
    }

    pub fn stream_id(&self) -> &[u8] {
        &self.stream_id
    }

    pub fn start_event_id(&self) -> &MessageId {
        &self.start_event_id
    }

    pub fn hash(&self) -> [u8; 32] {
        self.hash
    }

    pub fn chunk_count(&self) -> u64 {
        self.chunk_count
    }
}

fn push_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    encode_quic_varint(bytes.len() as u64, out);
    out.extend_from_slice(bytes);
}

/// Hash `len(bytes) || bytes` where `len(...)` is the Marmot binary profile's
/// QUIC variable-length integer — the same length encoding the QUIC record and
/// key-context use, per the transcript-hash construction in the spec (a
/// 32-byte id's length prefix is the single byte `0x20`).
fn hash_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    let mut prefix = Vec::with_capacity(8);
    encode_quic_varint(bytes.len() as u64, &mut prefix);
    hasher.update(&prefix);
    hasher.update(bytes);
}

fn is_known_record_type(record_type: u8) -> bool {
    matches!(
        record_type,
        AGENT_TEXT_STREAM_RECORD_TEXT_DELTA
            | AGENT_TEXT_STREAM_RECORD_PROGRESS_DELTA
            | AGENT_TEXT_STREAM_RECORD_STATUS
            | AGENT_TEXT_STREAM_RECORD_CHECKPOINT
            | AGENT_TEXT_STREAM_RECORD_ABORT
            | AGENT_TEXT_STREAM_RECORD_FINAL_NOTICE
    )
}

fn take_exact<'a>(
    bytes: &'a [u8],
    len: usize,
    field: &'static str,
) -> Result<(&'a [u8], &'a [u8]), AgentTextStreamRecordError> {
    if bytes.len() < len {
        return Err(AgentTextStreamRecordError::Truncated(field));
    }
    Ok(bytes.split_at(len))
}

fn take_len_prefixed<'a>(
    bytes: &'a [u8],
    field: &'static str,
) -> Result<(&'a [u8], &'a [u8]), AgentTextStreamRecordError> {
    let (len, prefix_len) =
        decode_quic_varint(bytes).map_err(|source| AgentTextStreamRecordError::LengthDecode {
            field,
            reason: source,
        })?;
    let len = usize::try_from(len).map_err(|_| AgentTextStreamRecordError::LengthDecode {
        field,
        reason: "length does not fit usize".to_owned(),
    })?;
    let rest = bytes
        .get(prefix_len..)
        .ok_or(AgentTextStreamRecordError::Truncated(field))?;
    take_exact(rest, len, field)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_to_agent_policy_encodes_component_state() {
        let bytes = AgentTextStreamQuicPolicyV1::user_to_agent_default()
            .encode_component_state()
            .unwrap();
        assert_eq!(
            bytes,
            vec![
                AGENT_TEXT_STREAM_ROLE_RECEIVE,
                AGENT_TEXT_STREAM_ROLE_RECEIVE | AGENT_TEXT_STREAM_ROLE_SEND,
                0x00,
                0x00,
                0x10,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
            ]
        );
        assert_eq!(bytes.len(), AGENT_TEXT_STREAM_COMPONENT_STATE_LEN);
        assert_eq!(
            AgentTextStreamQuicPolicyV1::decode_component_state(&bytes).unwrap(),
            AgentTextStreamQuicPolicyV1::user_to_agent_default()
        );
    }

    #[test]
    fn policy_validation_enforces_app_profile_caps() {
        let too_large_frame = AgentTextStreamQuicPolicyV1 {
            max_plaintext_frame_len: AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN + 1,
            ..AgentTextStreamQuicPolicyV1::user_to_agent_default()
        };
        assert!(matches!(
            too_large_frame.validate(),
            Err(AgentTextStreamPolicyError::FrameLimitTooLarge(_))
        ));

        let too_large_replay = AgentTextStreamQuicPolicyV1 {
            replay_ttl_secs: AGENT_TEXT_STREAM_MAX_REPLAY_TTL_SECS + 1,
            ..AgentTextStreamQuicPolicyV1::user_to_agent_default()
        };
        assert!(matches!(
            too_large_replay.validate(),
            Err(AgentTextStreamPolicyError::ReplayTtlTooLarge(_))
        ));

        let too_large_padding = AgentTextStreamQuicPolicyV1 {
            padding_bucket_bytes: AGENT_TEXT_STREAM_MAX_PADDING_BUCKET_BYTES + 1,
            ..AgentTextStreamQuicPolicyV1::user_to_agent_default()
        };
        assert!(matches!(
            too_large_padding.validate(),
            Err(AgentTextStreamPolicyError::PaddingBucketTooLarge(_))
        ));

        let required_role_not_allowed = AgentTextStreamQuicPolicyV1 {
            required_member_roles: AGENT_TEXT_STREAM_ROLE_SEND,
            allowed_member_roles: AGENT_TEXT_STREAM_ROLE_RECEIVE,
            ..AgentTextStreamQuicPolicyV1::user_to_agent_default()
        };
        assert!(matches!(
            required_role_not_allowed.validate(),
            Err(AgentTextStreamPolicyError::RequiredRolesNotAllowed)
        ));
    }

    #[test]
    fn decode_rejects_wrong_length_component_state() {
        assert!(matches!(
            AgentTextStreamQuicPolicyV1::decode_component_state(&[0u8; 14]),
            Err(AgentTextStreamPolicyError::InvalidComponentStateLength(14))
        ));
        assert!(matches!(
            AgentTextStreamQuicPolicyV1::decode_component_state(&[0u8; 11]),
            Err(AgentTextStreamPolicyError::InvalidComponentStateLength(11))
        ));
    }

    #[test]
    fn key_context_is_versioned_and_length_delimited() {
        let context = AgentTextStreamKeyContextV1::new(
            GroupId::new(vec![0x01, 0x02]),
            vec![0x03; AGENT_TEXT_STREAM_PROFILE_STREAM_ID_LEN],
            EpochId(9),
            MemberId::new(vec![0x05]),
            MessageId::new(vec![0x06; AGENT_TEXT_STREAM_START_EVENT_ID_LEN]),
        )
        .encode();
        assert_eq!(&context[..3], &[2, b'v', b'1']);
        assert!(
            context
                .windows(8)
                .any(|window| window == 9_u64.to_be_bytes())
        );
    }

    #[test]
    fn plaintext_cap_keeps_max_ciphertext_within_wire_field_bound() {
        // Spec: max_plaintext_frame_len <= 65519 so a maximum-length frame's
        // ciphertext (plaintext + 16-byte AEAD tag) fits ciphertext<0..2^16-1>.
        assert_eq!(AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN, 65519);
        assert_eq!(
            AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN as usize + AGENT_TEXT_STREAM_AEAD_TAG_LEN,
            AGENT_TEXT_STREAM_MAX_RECORD_CIPHERTEXT_LEN as usize,
        );
        assert_eq!(
            AGENT_TEXT_STREAM_MAX_RECORD_CIPHERTEXT_LEN,
            u32::from(u16::MAX)
        );
    }

    #[test]
    fn record_frame_field_accepts_max_length_ciphertext() {
        // A 65519-byte plaintext encrypts to a 65535-byte ciphertext, which the
        // record struct must round-trip because the wire field bound is
        // ciphertext<0..2^16-1>, not the plaintext policy cap.
        let max_ciphertext = AgentTextStreamRecordV1::text_delta(
            vec![0x11; 32],
            1,
            vec![0x55; AGENT_TEXT_STREAM_MAX_RECORD_CIPHERTEXT_LEN as usize],
        );
        let decoded = AgentTextStreamRecordV1::decode(&max_ciphertext.encode().unwrap()).unwrap();
        assert_eq!(decoded, max_ciphertext);

        let oversized = AgentTextStreamRecordV1::text_delta(
            vec![0x11; 32],
            1,
            vec![0x55; AGENT_TEXT_STREAM_MAX_RECORD_CIPHERTEXT_LEN as usize + 1],
        );
        assert_eq!(
            oversized.encode(),
            Err(AgentTextStreamRecordError::PlaintextFrameTooLarge(
                AGENT_TEXT_STREAM_MAX_RECORD_CIPHERTEXT_LEN as usize + 1
            ))
        );
    }

    #[test]
    fn transcript_hash_uses_quic_varint_length_prefixes() {
        // Spec: every len(...) in the transcript construction is the QUIC
        // variable-length integer; a 32-byte id's prefix is the single byte
        // 0x20, never an 8-byte fixed-width length.
        let stream_id = vec![0x11; 32];
        let start = MessageId::new(vec![0x22; 32]);
        let transcript = AgentTextStreamTranscriptV1::new(stream_id.clone(), start.clone());

        let mut hasher = Sha256::new();
        hasher.update(AGENT_TEXT_STREAM_TRANSCRIPT_HASH_CONTEXT);
        hasher.update([0x20]);
        hasher.update(&stream_id);
        hasher.update([0x20]);
        hasher.update(start.as_slice());
        let expected: [u8; 32] = hasher.finalize().into();

        assert_eq!(transcript.hash(), expected);
    }

    #[test]
    fn transcript_hash_commits_to_order_and_type() {
        let start = MessageId::new(vec![0x22; 32]);
        let mut first = AgentTextStreamTranscriptV1::new(vec![0x11; 32], start.clone());
        first.append(1, AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, b"hel");
        first.append(2, AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, b"lo");

        let mut different_order = AgentTextStreamTranscriptV1::new(vec![0x11; 32], start.clone());
        different_order.append(2, AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, b"lo");
        different_order.append(1, AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, b"hel");

        let mut different_type = AgentTextStreamTranscriptV1::new(vec![0x11; 32], start);
        different_type.append(1, AGENT_TEXT_STREAM_RECORD_STATUS, b"hel");
        different_type.append(2, AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, b"lo");

        assert_eq!(first.chunk_count(), 2);
        assert_ne!(first.hash(), different_order.hash());
        assert_ne!(first.hash(), different_type.hash());
    }

    #[test]
    fn text_delta_record_round_trips_with_quic_lengths() {
        let record = AgentTextStreamRecordV1::text_delta(vec![0x11; 32], 7, "hello");

        let encoded = record.encode().unwrap();
        assert_eq!(encoded[0], AGENT_TEXT_STREAM_RECORD_VERSION);
        assert_eq!(encoded[1], 32);

        let decoded = AgentTextStreamRecordV1::decode(&encoded).unwrap();
        assert_eq!(decoded, record);
    }

    #[test]
    fn stream_record_decoder_rejects_malformed_records() {
        assert_eq!(
            AgentTextStreamRecordV1::decode(&[]),
            Err(AgentTextStreamRecordError::Truncated("version"))
        );

        let mut unsupported_version = AgentTextStreamRecordV1::text_delta(vec![0x11; 32], 1, "x")
            .encode()
            .unwrap();
        unsupported_version[0] = 2;
        assert_eq!(
            AgentTextStreamRecordV1::decode(&unsupported_version),
            Err(AgentTextStreamRecordError::UnsupportedVersion(2))
        );

        let unknown_type = AgentTextStreamRecordV1 {
            record_type: 0xff,
            ..AgentTextStreamRecordV1::text_delta(vec![0x11; 32], 1, "x")
        };
        assert_eq!(
            unknown_type.encode(),
            Err(AgentTextStreamRecordError::UnknownRecordType(0xff))
        );

        let empty_stream = AgentTextStreamRecordV1::text_delta(Vec::new(), 1, "x");
        assert_eq!(
            empty_stream.encode(),
            Err(AgentTextStreamRecordError::EmptyStreamId)
        );
    }
}
