//! Stored message records and their state machine.
//!
//! The state machine matches `cgka-engine-design.md:48-54`: messages live in
//! a typed state that the engine + coordinator walk through as processing
//! progresses. Kept here (and not inside the engine) so the storage backend
//! can query "what's retryable?" without cracking engine internals.

use crate::engine::CommitOrderingPriority;
use crate::transport::TransportMessage;
use crate::transport::{Timestamp, TransportEnvelope, TransportSource};
use crate::types::{EpochId, GroupId, MemberId, MessageId};
use serde::{Deserialize, Serialize};
use std::fmt;

const STORED_MESSAGE_PAYLOAD_MAGIC: &[u8; 5] = b"MDKMP";
const STORED_MESSAGE_PAYLOAD_VERSION: u16 = 2;
const MAX_STORED_MESSAGE_FIELD_LEN: usize = 1 << 30;
const MAX_STORED_MESSAGE_LIST_ITEMS: usize = 1 << 20;

/// Convergence-relevant ordering metadata for a commit this device published
/// and confirmed, captured at confirm time (while the staged commit is still
/// attached) and persisted alongside the stored wire bytes.
///
/// MLS cannot process a device's own commit through `process_message`, so
/// after an engine restart the stored wire record is the ONLY source from
/// which stored convergence can rebuild the own commit's branch-selection
/// ordering key (priority + authenticated committer; the digest is recomputed
/// from the stored bytes) and its consumed proposal references.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnCommitConvergenceStamp {
    /// This device's member identity — the authenticated committer of the
    /// stored commit.
    pub committer: MemberId,
    /// Authorization-aware ordering priority derived from the staged commit's
    /// shape at confirm time.
    pub priority: CommitOrderingPriority,
    /// Hex-encoded proposal references the commit consumed, in sorted order.
    pub consumed_proposal_refs: Vec<String>,
    /// Immutable canonical-state checkpoint produced by this commit.  The id
    /// is derived from the MLS wire commit digest rather than the epoch, so
    /// sibling branches can never replace one another's state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_id: Option<String>,
    /// Epoch authenticator of the checkpointed resulting state.  Restore
    /// verifies this value before the checkpoint can realize an own commit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resulting_epoch_authenticator: Option<String>,
}

/// Branch provenance for an application message authored by this device.
///
/// MLS sender ratchets are encryption-only, so a device cannot later decrypt
/// and authenticate its own private-message ciphertext during candidate
/// replay. The send path therefore captures the authenticated local source
/// state while it still owns it. Stored convergence may credit the message
/// only to candidate states whose epoch authenticator matches this stamp.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnApplicationConvergenceStamp {
    /// This device's authenticated Marmot member identity at send time.
    pub sender: MemberId,
    /// Hex-encoded MLS epoch authenticator of the state that encrypted the
    /// application message.
    pub source_epoch_authenticator: String,
}

/// Typed envelope for the opaque bytes stored in [`MessageRecord::payload`].
///
/// The database column remains a byte blob so backends do not need a schema
/// change every time the engine stores a new payload flavor. The bytes inside
/// the blob are this versioned JSON shape:
///
/// - `RawTransport`: original transport-wrapped message. Used when peeling is
///   deferred or the engine needs to retry with a different epoch context.
/// - `OutboundWelcome`: a locally produced Welcome retained until its
///   independent transport acknowledgement policy is satisfied. Keeping this
///   distinct from historical `RawTransport` `Sent` rows lets cold-restart
///   recovery find only delivery obligations created by versions that track
///   their completion.
/// - `StagedInviteWelcome`: a locally produced Welcome that is bound to one
///   exact, not-yet-confirmed invite commit. This representation is deliberately
///   not deliverable until that commit is confirmed.
/// - `OpenMlsWire`: transport metadata plus payload replaced with peeled MLS
///   wire bytes. This variant, `SignedOpenMlsWire`, and `OwnCommitWire` are
///   eligible for OpenMLS projection and convergence replay.
/// - `SignedOpenMlsWire`: the exact signed outer transport message alongside
///   the projection-friendly MLS wire message. This is the current outbound
///   representation and supports byte-identical retry after restart. Locally
///   authored applications also carry [`OwnApplicationConvergenceStamp`].
/// - `OwnCommitWire`: an `OpenMlsWire` commit this device published and
///   confirmed, enriched with its [`OwnCommitConvergenceStamp`] so stored
///   convergence can treat it as a pre-validated candidate branch after a
///   restart.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "message", rename_all = "snake_case")]
pub enum StoredMessagePayload {
    RawTransport(TransportMessage),
    OutboundWelcome(TransportMessage),
    StagedInviteWelcome {
        message: TransportMessage,
        origin_commit_id: MessageId,
    },
    OpenMlsWire(TransportMessage),
    SignedOpenMlsWire {
        exact_message: TransportMessage,
        openmls_message: TransportMessage,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        stamp: Option<OwnCommitConvergenceStamp>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        own_application_stamp: Option<Box<OwnApplicationConvergenceStamp>>,
    },
    OwnCommitWire {
        message: TransportMessage,
        stamp: OwnCommitConvergenceStamp,
    },
}

impl StoredMessagePayload {
    pub fn raw_transport(message: TransportMessage) -> Self {
        Self::RawTransport(message)
    }

    pub fn outbound_welcome(message: TransportMessage) -> Self {
        Self::OutboundWelcome(message)
    }

    pub fn staged_invite_welcome(message: TransportMessage, origin_commit_id: MessageId) -> Self {
        Self::StagedInviteWelcome {
            message,
            origin_commit_id,
        }
    }

    pub fn openmls_wire(message: TransportMessage) -> Self {
        Self::OpenMlsWire(message)
    }

    pub fn signed_openmls_wire(
        exact_message: TransportMessage,
        openmls_message: TransportMessage,
    ) -> Self {
        Self::SignedOpenMlsWire {
            exact_message,
            openmls_message,
            stamp: None,
            own_application_stamp: None,
        }
    }

    pub fn signed_openmls_application_wire(
        exact_message: TransportMessage,
        openmls_message: TransportMessage,
        own_application_stamp: OwnApplicationConvergenceStamp,
    ) -> Self {
        Self::SignedOpenMlsWire {
            exact_message,
            openmls_message,
            stamp: None,
            own_application_stamp: Some(Box::new(own_application_stamp)),
        }
    }

    pub fn own_commit_wire(message: TransportMessage, stamp: OwnCommitConvergenceStamp) -> Self {
        Self::OwnCommitWire { message, stamp }
    }

    /// Encode the MDK-local storage payload format.
    ///
    /// Version 2 deliberately follows Marmot's binary grammar (fixed-width
    /// network-order integers and canonical QUIC-varint length prefixes), but
    /// it is an implementation storage format rather than a Marmot wire type.
    pub fn encode(&self) -> Result<Vec<u8>, StoredMessagePayloadCodecError> {
        encode_stored_message_payload_v2(self)
    }

    /// Decode the current binary format, the previous tagged JSON envelope,
    /// or the oldest bare-`TransportMessage` JSON representation.
    pub fn decode(bytes: &[u8]) -> Result<Self, StoredMessagePayloadCodecError> {
        if bytes.starts_with(STORED_MESSAGE_PAYLOAD_MAGIC) {
            return decode_stored_message_payload_v2(bytes);
        }
        match serde_json::from_slice(bytes) {
            Ok(payload) => Ok(payload),
            Err(envelope_error) => match serde_json::from_slice(bytes) {
                Ok(legacy) => Ok(Self::OpenMlsWire(legacy)),
                Err(_) => Err(StoredMessagePayloadCodecError::LegacyJson(envelope_error)),
            },
        }
    }

    pub fn as_raw_transport(&self) -> Option<&TransportMessage> {
        match self {
            Self::RawTransport(message) => Some(message),
            Self::OutboundWelcome(_)
            | Self::StagedInviteWelcome { .. }
            | Self::OpenMlsWire(_)
            | Self::SignedOpenMlsWire { .. }
            | Self::OwnCommitWire { .. } => None,
        }
    }

    pub fn as_outbound_welcome(&self) -> Option<&TransportMessage> {
        match self {
            Self::OutboundWelcome(message) => Some(message),
            Self::RawTransport(_)
            | Self::StagedInviteWelcome { .. }
            | Self::OpenMlsWire(_)
            | Self::SignedOpenMlsWire { .. }
            | Self::OwnCommitWire { .. } => None,
        }
    }

    pub fn as_staged_invite_welcome(&self) -> Option<(&TransportMessage, &MessageId)> {
        match self {
            Self::StagedInviteWelcome {
                message,
                origin_commit_id,
            } => Some((message, origin_commit_id)),
            Self::RawTransport(_)
            | Self::OutboundWelcome(_)
            | Self::OpenMlsWire(_)
            | Self::SignedOpenMlsWire { .. }
            | Self::OwnCommitWire { .. } => None,
        }
    }

    pub fn as_openmls_wire(&self) -> Option<&TransportMessage> {
        match self {
            Self::RawTransport(_) | Self::OutboundWelcome(_) | Self::StagedInviteWelcome { .. } => {
                None
            }
            Self::OpenMlsWire(message) | Self::OwnCommitWire { message, .. } => Some(message),
            Self::SignedOpenMlsWire {
                openmls_message, ..
            } => Some(openmls_message),
        }
    }

    /// Exact signed outer event retained for restart-safe retransmission.
    pub fn as_exact_transport(&self) -> Option<&TransportMessage> {
        match self {
            Self::RawTransport(message) | Self::OutboundWelcome(message) => Some(message),
            Self::SignedOpenMlsWire { exact_message, .. } => Some(exact_message),
            Self::StagedInviteWelcome { .. }
            | Self::OpenMlsWire(_)
            | Self::OwnCommitWire { .. } => None,
        }
    }

    /// The confirm-time convergence stamp, when this payload is an own
    /// published-and-confirmed commit.
    pub fn own_commit_stamp(&self) -> Option<&OwnCommitConvergenceStamp> {
        match self {
            Self::RawTransport(_)
            | Self::OutboundWelcome(_)
            | Self::StagedInviteWelcome { .. }
            | Self::OpenMlsWire(_) => None,
            Self::SignedOpenMlsWire { stamp, .. } => stamp.as_ref(),
            Self::OwnCommitWire { stamp, .. } => Some(stamp),
        }
    }

    /// Send-time branch provenance for a locally authored application message.
    pub fn own_application_stamp(&self) -> Option<&OwnApplicationConvergenceStamp> {
        match self {
            Self::SignedOpenMlsWire {
                own_application_stamp,
                ..
            } => own_application_stamp.as_deref(),
            Self::RawTransport(_)
            | Self::OutboundWelcome(_)
            | Self::StagedInviteWelcome { .. }
            | Self::OpenMlsWire(_)
            | Self::OwnCommitWire { .. } => None,
        }
    }

    pub fn into_message(self) -> TransportMessage {
        match self {
            Self::RawTransport(message)
            | Self::OutboundWelcome(message)
            | Self::OpenMlsWire(message)
            | Self::OwnCommitWire { message, .. } => message,
            Self::StagedInviteWelcome { message, .. } => message,
            Self::SignedOpenMlsWire {
                openmls_message, ..
            } => openmls_message,
        }
    }
}

/// Failure to decode an MDK-local stored-message payload.
#[derive(Debug)]
pub enum StoredMessagePayloadCodecError {
    Invalid(String),
    LegacyJson(serde_json::Error),
}

impl fmt::Display for StoredMessagePayloadCodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => formatter.write_str(message),
            Self::LegacyJson(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for StoredMessagePayloadCodecError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Invalid(_) => None,
            Self::LegacyJson(error) => Some(error),
        }
    }
}

fn encode_stored_message_payload_v2(
    payload: &StoredMessagePayload,
) -> Result<Vec<u8>, StoredMessagePayloadCodecError> {
    let mut out = Vec::new();
    out.extend_from_slice(STORED_MESSAGE_PAYLOAD_MAGIC);
    out.extend_from_slice(&STORED_MESSAGE_PAYLOAD_VERSION.to_be_bytes());
    match payload {
        StoredMessagePayload::RawTransport(message) => {
            out.push(0);
            encode_transport_message(message, &mut out)?;
        }
        StoredMessagePayload::OutboundWelcome(message) => {
            out.push(1);
            encode_transport_message(message, &mut out)?;
        }
        StoredMessagePayload::StagedInviteWelcome {
            message,
            origin_commit_id,
        } => {
            out.push(5);
            encode_transport_message(message, &mut out)?;
            encode_var_bytes(
                origin_commit_id.as_slice(),
                &mut out,
                "staged Welcome origin commit id",
            )?;
        }
        StoredMessagePayload::OpenMlsWire(message) => {
            out.push(2);
            encode_transport_message(message, &mut out)?;
        }
        StoredMessagePayload::SignedOpenMlsWire {
            exact_message,
            openmls_message,
            stamp,
            own_application_stamp,
        } => {
            out.push(3);
            encode_transport_message(exact_message, &mut out)?;
            encode_transport_message(openmls_message, &mut out)?;
            encode_option(stamp.as_ref(), &mut out, encode_own_commit_stamp)?;
            encode_option(
                own_application_stamp.as_deref(),
                &mut out,
                encode_own_application_stamp,
            )?;
        }
        StoredMessagePayload::OwnCommitWire { message, stamp } => {
            out.push(4);
            encode_transport_message(message, &mut out)?;
            encode_own_commit_stamp(stamp, &mut out)?;
        }
    }
    Ok(out)
}

fn decode_stored_message_payload_v2(
    bytes: &[u8],
) -> Result<StoredMessagePayload, StoredMessagePayloadCodecError> {
    let mut decoder = Decoder::new(bytes);
    decoder.expect(STORED_MESSAGE_PAYLOAD_MAGIC, "stored-message payload magic")?;
    let version = decoder.u16("stored-message payload version")?;
    if version != STORED_MESSAGE_PAYLOAD_VERSION {
        return Err(invalid(format!(
            "unsupported stored-message payload version {version}"
        )));
    }
    let payload = match decoder.u8("stored-message payload variant")? {
        0 => StoredMessagePayload::RawTransport(decoder.transport_message()?),
        1 => StoredMessagePayload::OutboundWelcome(decoder.transport_message()?),
        2 => StoredMessagePayload::OpenMlsWire(decoder.transport_message()?),
        3 => StoredMessagePayload::SignedOpenMlsWire {
            exact_message: decoder.transport_message()?,
            openmls_message: decoder.transport_message()?,
            stamp: decoder.option(|decoder| decoder.own_commit_stamp())?,
            own_application_stamp: decoder
                .option(|decoder| decoder.own_application_stamp())?
                .map(Box::new),
        },
        4 => StoredMessagePayload::OwnCommitWire {
            message: decoder.transport_message()?,
            stamp: decoder.own_commit_stamp()?,
        },
        5 => StoredMessagePayload::StagedInviteWelcome {
            message: decoder.transport_message()?,
            origin_commit_id: MessageId::new(decoder.var_bytes("staged Welcome origin commit id")?),
        },
        variant => {
            return Err(invalid(format!(
                "unknown stored-message payload variant {variant}"
            )));
        }
    };
    decoder.finish("stored-message payload")?;
    Ok(payload)
}

fn encode_transport_message(
    message: &TransportMessage,
    out: &mut Vec<u8>,
) -> Result<(), StoredMessagePayloadCodecError> {
    encode_var_bytes(message.id.as_slice(), out, "message id")?;
    encode_var_bytes(&message.payload, out, "transport payload")?;
    out.extend_from_slice(&message.timestamp.0.to_be_bytes());
    encode_list(&message.causal_deps, out, |dependency, body| {
        encode_var_bytes(dependency.as_slice(), body, "causal dependency")
    })?;
    encode_var_bytes(message.source.0.as_bytes(), out, "transport source")?;
    match &message.envelope {
        TransportEnvelope::GroupMessage { transport_group_id } => {
            out.push(0);
            encode_var_bytes(transport_group_id, out, "transport group id")?;
        }
        TransportEnvelope::Welcome { recipient } => {
            out.push(1);
            encode_var_bytes(recipient.as_slice(), out, "welcome recipient")?;
        }
    }
    Ok(())
}

fn encode_own_commit_stamp(
    stamp: &OwnCommitConvergenceStamp,
    out: &mut Vec<u8>,
) -> Result<(), StoredMessagePayloadCodecError> {
    encode_var_bytes(stamp.committer.as_slice(), out, "commit stamp committer")?;
    out.push(match stamp.priority {
        CommitOrderingPriority::Privileged => 0,
        CommitOrderingPriority::Ordinary => 1,
    });
    encode_list(&stamp.consumed_proposal_refs, out, |proposal_ref, body| {
        encode_var_bytes(proposal_ref.as_bytes(), body, "consumed proposal reference")
    })?;
    encode_option(stamp.checkpoint_id.as_ref(), out, |value, body| {
        encode_var_bytes(value.as_bytes(), body, "checkpoint id")
    })?;
    encode_option(
        stamp.resulting_epoch_authenticator.as_ref(),
        out,
        |value, body| encode_var_bytes(value.as_bytes(), body, "epoch authenticator"),
    )
}

fn encode_own_application_stamp(
    stamp: &OwnApplicationConvergenceStamp,
    out: &mut Vec<u8>,
) -> Result<(), StoredMessagePayloadCodecError> {
    encode_var_bytes(stamp.sender.as_slice(), out, "application stamp sender")?;
    encode_var_bytes(
        stamp.source_epoch_authenticator.as_bytes(),
        out,
        "source epoch authenticator",
    )
}

fn encode_option<T>(
    value: Option<&T>,
    out: &mut Vec<u8>,
    encode: impl FnOnce(&T, &mut Vec<u8>) -> Result<(), StoredMessagePayloadCodecError>,
) -> Result<(), StoredMessagePayloadCodecError> {
    match value {
        None => out.push(0),
        Some(value) => {
            out.push(1);
            encode(value, out)?;
        }
    }
    Ok(())
}

fn encode_list<T>(
    values: &[T],
    out: &mut Vec<u8>,
    mut encode: impl FnMut(&T, &mut Vec<u8>) -> Result<(), StoredMessagePayloadCodecError>,
) -> Result<(), StoredMessagePayloadCodecError> {
    if values.len() > MAX_STORED_MESSAGE_LIST_ITEMS {
        return Err(invalid("stored-message list exceeds item limit"));
    }
    let mut body = Vec::new();
    for value in values {
        encode(value, &mut body)?;
    }
    encode_var_bytes(&body, out, "stored-message list")
}

fn encode_var_bytes(
    bytes: &[u8],
    out: &mut Vec<u8>,
    label: &str,
) -> Result<(), StoredMessagePayloadCodecError> {
    if bytes.len() > MAX_STORED_MESSAGE_FIELD_LEN {
        return Err(invalid(format!("{label} exceeds storage format limit")));
    }
    crate::app_components::encode_quic_varint(bytes.len() as u64, out);
    out.extend_from_slice(bytes);
    Ok(())
}

struct Decoder<'a> {
    remaining: &'a [u8],
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn expect(
        &mut self,
        expected: &[u8],
        label: &str,
    ) -> Result<(), StoredMessagePayloadCodecError> {
        if !self.remaining.starts_with(expected) {
            return Err(invalid(format!("invalid {label}")));
        }
        self.remaining = &self.remaining[expected.len()..];
        Ok(())
    }

    fn u8(&mut self, label: &str) -> Result<u8, StoredMessagePayloadCodecError> {
        let value = *self
            .remaining
            .first()
            .ok_or_else(|| invalid(format!("truncated {label}")))?;
        self.remaining = &self.remaining[1..];
        Ok(value)
    }

    fn u16(&mut self, label: &str) -> Result<u16, StoredMessagePayloadCodecError> {
        if self.remaining.len() < 2 {
            return Err(invalid(format!("truncated {label}")));
        }
        let value = u16::from_be_bytes([self.remaining[0], self.remaining[1]]);
        self.remaining = &self.remaining[2..];
        Ok(value)
    }

    fn u64(&mut self, label: &str) -> Result<u64, StoredMessagePayloadCodecError> {
        if self.remaining.len() < 8 {
            return Err(invalid(format!("truncated {label}")));
        }
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(&self.remaining[..8]);
        self.remaining = &self.remaining[8..];
        Ok(u64::from_be_bytes(bytes))
    }

    fn var_bytes(&mut self, label: &str) -> Result<Vec<u8>, StoredMessagePayloadCodecError> {
        let (len, prefix_len) = crate::app_components::decode_quic_varint(self.remaining)
            .map_err(|error| invalid(format!("{label} length: {error}")))?;
        let len = usize::try_from(len).map_err(|_| invalid(format!("{label} is too large")))?;
        if len > MAX_STORED_MESSAGE_FIELD_LEN {
            return Err(invalid(format!("{label} exceeds storage format limit")));
        }
        let end = prefix_len
            .checked_add(len)
            .ok_or_else(|| invalid(format!("{label} length overflow")))?;
        if self.remaining.len() < end {
            return Err(invalid(format!("truncated {label}")));
        }
        let value = self.remaining[prefix_len..end].to_vec();
        self.remaining = &self.remaining[end..];
        Ok(value)
    }

    fn string(&mut self, label: &str) -> Result<String, StoredMessagePayloadCodecError> {
        String::from_utf8(self.var_bytes(label)?)
            .map_err(|_| invalid(format!("{label} is not UTF-8")))
    }

    fn list<T>(
        &mut self,
        label: &str,
        mut decode: impl FnMut(&mut Decoder<'_>) -> Result<T, StoredMessagePayloadCodecError>,
    ) -> Result<Vec<T>, StoredMessagePayloadCodecError> {
        let body = self.var_bytes(label)?;
        let mut decoder = Decoder::new(&body);
        let mut values = Vec::new();
        while !decoder.remaining.is_empty() {
            if values.len() == MAX_STORED_MESSAGE_LIST_ITEMS {
                return Err(invalid(format!("{label} exceeds item limit")));
            }
            values.push(decode(&mut decoder)?);
        }
        Ok(values)
    }

    fn option<T>(
        &mut self,
        decode: impl FnOnce(&mut Decoder<'_>) -> Result<T, StoredMessagePayloadCodecError>,
    ) -> Result<Option<T>, StoredMessagePayloadCodecError> {
        match self.u8("option discriminant")? {
            0 => Ok(None),
            1 => decode(self).map(Some),
            value => Err(invalid(format!("invalid option discriminant {value}"))),
        }
    }

    fn transport_message(&mut self) -> Result<TransportMessage, StoredMessagePayloadCodecError> {
        let id = MessageId::new(self.var_bytes("message id")?);
        let payload = self.var_bytes("transport payload")?;
        let timestamp = Timestamp(self.u64("transport timestamp")?);
        let causal_deps = self.list("causal dependencies", |decoder| {
            decoder.var_bytes("causal dependency").map(MessageId::new)
        })?;
        let source = TransportSource(self.string("transport source")?);
        let envelope = match self.u8("transport envelope variant")? {
            0 => TransportEnvelope::GroupMessage {
                transport_group_id: self.var_bytes("transport group id")?,
            },
            1 => TransportEnvelope::Welcome {
                recipient: MemberId::new(self.var_bytes("welcome recipient")?),
            },
            value => {
                return Err(invalid(format!(
                    "unknown transport envelope variant {value}"
                )));
            }
        };
        Ok(TransportMessage {
            id,
            payload,
            timestamp,
            causal_deps,
            source,
            envelope,
        })
    }

    fn own_commit_stamp(
        &mut self,
    ) -> Result<OwnCommitConvergenceStamp, StoredMessagePayloadCodecError> {
        let committer = MemberId::new(self.var_bytes("commit stamp committer")?);
        let priority = match self.u8("commit ordering priority")? {
            0 => CommitOrderingPriority::Privileged,
            1 => CommitOrderingPriority::Ordinary,
            value => return Err(invalid(format!("unknown commit ordering priority {value}"))),
        };
        let consumed_proposal_refs = self.list("consumed proposal references", |decoder| {
            decoder.string("consumed proposal reference")
        })?;
        let checkpoint_id = self.option(|decoder| decoder.string("checkpoint id"))?;
        let resulting_epoch_authenticator =
            self.option(|decoder| decoder.string("epoch authenticator"))?;
        Ok(OwnCommitConvergenceStamp {
            committer,
            priority,
            consumed_proposal_refs,
            checkpoint_id,
            resulting_epoch_authenticator,
        })
    }

    fn own_application_stamp(
        &mut self,
    ) -> Result<OwnApplicationConvergenceStamp, StoredMessagePayloadCodecError> {
        Ok(OwnApplicationConvergenceStamp {
            sender: MemberId::new(self.var_bytes("application stamp sender")?),
            source_epoch_authenticator: self.string("source epoch authenticator")?,
        })
    }

    fn finish(self, label: &str) -> Result<(), StoredMessagePayloadCodecError> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(invalid(format!("{label} has trailing bytes")))
        }
    }
}

fn invalid(message: impl Into<String>) -> StoredMessagePayloadCodecError {
    StoredMessagePayloadCodecError::Invalid(message.into())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeferredPeelLifecycle {
    /// Wall-clock time when this account-device first retained the opaque
    /// transport object. This is local resource metadata, never wire data.
    pub first_observed_wall_ms: u64,
    /// Greatest wall-clock observation persisted for this row. A later
    /// backwards jump cannot erase already-observed residence.
    pub wall_high_water_ms: u64,
    /// Process-local convergence clock instance that owns
    /// `residence_deadline_monotonic_ms`.
    pub clock_instance_id: u64,
    /// Live-process deadline. It is rebased from the durable wall deadline
    /// after restart because monotonic clock values do not survive processes.
    pub residence_deadline_monotonic_ms: u64,
    /// Durable deadline used only to reconstruct the monotonic deadline after
    /// restart. Backwards wall movement must never make this deadline earlier.
    pub residence_deadline_wall_ms: u64,
    /// Number of distinct peel contexts actually consumed by this row.
    pub distinct_context_attempts: u32,
    /// Last `(epoch, retained snapshot set)` fingerprint attempted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_context_fingerprint: Option<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageRecord {
    pub id: MessageId,
    pub group_id: GroupId,
    pub epoch: EpochId,
    pub state: MessageState,
    pub payload: Vec<u8>,
    /// Durable local bookkeeping for raw transport objects in
    /// [`MessageState::PeelDeferred`]. Older rows deserialize without it and
    /// receive a fresh conservative residence window on first maintenance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deferred_peel: Option<DeferredPeelLifecycle>,
}

/// Per-message state.
///
/// Transitions:
///   `Sent` → `Sent` (outbound message recorded for durable own-echo checks)
///   `Sent` → `Processed` (a retained outbound Welcome met its delivery policy)
///   `Created` → `Processed` (happy path after successful ingest)
///   `Created` → `Failed` (terminal error — no retry)
///   `Created` → `Retryable` (transient error — can be re-tried later)
///   `Created` → `ConvergenceDeferred` (retained for a later convergence pass)
///   `Created` → `PeelDeferred` (transport bytes retained for later peel)
///   `Retryable` → `Processed` (retry succeeded)
///   `ConvergenceDeferred` → `Processed` (later evidence selects the input)
///   `PeelDeferred` → `Created` (peel succeeded and MLS bytes are buffered)
///   `PeelDeferred` → deleted (local retry budget exhausted; redelivery remains eligible)
///   any → `EpochInvalidated` (group forked past; message will never apply)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageState {
    /// Locally produced outbound message. If the transport echoes it back,
    /// the engine can classify it as `OwnEcho` even after restart.
    Sent,
    /// Stored but not yet processed.
    Created,
    /// Successfully applied to the group state, or a retained outbound
    /// Welcome whose independent delivery obligation completed.
    Processed,
    /// Terminal failure — do not retry.
    Failed,
    /// Transient failure — eligible for retry (e.g. awaiting out-of-order
    /// commit that hasn't arrived yet).
    Retryable,
    /// The convergence engine evaluated this input but cannot give it a
    /// terminal disposition in the completed pass. It remains graph input for
    /// a later pass, but does not by itself reopen convergence or gate sends.
    ConvergenceDeferred,
    /// Transport-wrapped bytes are stored, but no available epoch context has
    /// peeled them yet. The engine may retry when it learns or retains more
    /// group epoch state.
    PeelDeferred,
    /// The epoch this message targets has been superseded by a fork recovery
    /// transition; the message will never apply. Kept for audit.
    EpochInvalidated,
}

#[cfg(test)]
mod stored_payload_codec_tests {
    use super::*;

    fn transport(envelope: TransportEnvelope) -> TransportMessage {
        TransportMessage {
            id: MessageId::new([0xaa]),
            payload: vec![0xbb, 0xcc],
            timestamp: Timestamp(7),
            causal_deps: vec![MessageId::new([0x11]), MessageId::new([0x22, 0x23])],
            source: TransportSource("nostr".to_owned()),
            envelope,
        }
    }

    #[test]
    fn v2_round_trips_every_payload_variant() {
        let group_message = transport(TransportEnvelope::GroupMessage {
            transport_group_id: vec![0xdd; 32],
        });
        let welcome = transport(TransportEnvelope::Welcome {
            recipient: MemberId::new(vec![0xee; 32]),
        });
        let commit_stamp = OwnCommitConvergenceStamp {
            committer: MemberId::new(vec![0x33; 32]),
            priority: CommitOrderingPriority::Privileged,
            consumed_proposal_refs: vec!["01".to_owned(), "0203".to_owned()],
            checkpoint_id: Some("checkpoint".to_owned()),
            resulting_epoch_authenticator: Some("authenticator".to_owned()),
        };
        let app_stamp = OwnApplicationConvergenceStamp {
            sender: MemberId::new(vec![0x44; 32]),
            source_epoch_authenticator: "source-authenticator".to_owned(),
        };
        let values = [
            StoredMessagePayload::RawTransport(group_message.clone()),
            StoredMessagePayload::OutboundWelcome(welcome.clone()),
            StoredMessagePayload::StagedInviteWelcome {
                message: welcome,
                origin_commit_id: MessageId::new([0x55, 0x56]),
            },
            StoredMessagePayload::OpenMlsWire(group_message.clone()),
            StoredMessagePayload::SignedOpenMlsWire {
                exact_message: group_message.clone(),
                openmls_message: group_message.clone(),
                stamp: Some(commit_stamp.clone()),
                own_application_stamp: Some(Box::new(app_stamp)),
            },
            StoredMessagePayload::OwnCommitWire {
                message: group_message,
                stamp: commit_stamp,
            },
        ];

        for value in values {
            let encoded = value.encode().unwrap();
            assert!(encoded.starts_with(b"MDKMP\0\x02"));
            assert_eq!(StoredMessagePayload::decode(&encoded).unwrap(), value);
        }
    }

    #[test]
    fn v2_simple_payload_has_stable_golden_bytes() {
        let value = StoredMessagePayload::OpenMlsWire(TransportMessage {
            id: MessageId::new([0xaa]),
            payload: vec![0xbb, 0xcc],
            timestamp: Timestamp(7),
            causal_deps: Vec::new(),
            source: TransportSource("x".to_owned()),
            envelope: TransportEnvelope::GroupMessage {
                transport_group_id: vec![0xdd],
            },
        });
        assert_eq!(
            hex::encode(value.encode().unwrap()),
            "4d444b4d5000020201aa02bbcc00000000000000070001780001dd"
        );
    }

    #[test]
    fn decode_accepts_both_legacy_json_shapes() {
        let message = transport(TransportEnvelope::GroupMessage {
            transport_group_id: vec![0xdd; 32],
        });
        let envelope = StoredMessagePayload::RawTransport(message.clone());
        assert_eq!(
            StoredMessagePayload::decode(&serde_json::to_vec(&envelope).unwrap()).unwrap(),
            envelope
        );
        assert_eq!(
            StoredMessagePayload::decode(&serde_json::to_vec(&message).unwrap()).unwrap(),
            StoredMessagePayload::OpenMlsWire(message)
        );
    }

    #[test]
    fn v2_decode_rejects_trailing_and_noncanonical_bytes() {
        let value = StoredMessagePayload::OpenMlsWire(TransportMessage {
            id: MessageId::new([0xaa]),
            payload: Vec::new(),
            timestamp: Timestamp(0),
            causal_deps: Vec::new(),
            source: TransportSource(String::new()),
            envelope: TransportEnvelope::GroupMessage {
                transport_group_id: Vec::new(),
            },
        });
        let mut trailing = value.encode().unwrap();
        trailing.push(0);
        assert!(StoredMessagePayload::decode(&trailing).is_err());

        let mut noncanonical = value.encode().unwrap();
        noncanonical.splice(8..9, [0x40, 0x01]);
        assert!(StoredMessagePayload::decode(&noncanonical).is_err());
    }
}
