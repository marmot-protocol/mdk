//! Broker control envelope: the stream key, control-type tag, and the binary
//! publish/subscribe envelope exchanged on every broker stream.

use cgka_traits::MessageId;
use cgka_traits::agent_text_stream::AGENT_TEXT_STREAM_MAX_STREAM_ID_LEN;
use cgka_traits::app_components::{decode_quic_varint, encode_quic_varint};

use crate::error::QuicBrokerError;
use crate::protocol::{
    QUIC_BROKER_CONTROL_PUBLISH, QUIC_BROKER_CONTROL_SUBSCRIBE, QUIC_BROKER_PROTOCOL_V1,
};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BrokerStreamKey {
    pub stream_id: Vec<u8>,
    pub start_event_id: MessageId,
}

impl BrokerStreamKey {
    pub fn new(stream_id: impl Into<Vec<u8>>, start_event_id: MessageId) -> Self {
        Self {
            stream_id: stream_id.into(),
            start_event_id,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuicBrokerControlTypeV1 {
    Publish,
    Subscribe,
}

impl QuicBrokerControlTypeV1 {
    fn wire(self) -> u8 {
        match self {
            Self::Publish => QUIC_BROKER_CONTROL_PUBLISH,
            Self::Subscribe => QUIC_BROKER_CONTROL_SUBSCRIBE,
        }
    }

    fn from_wire(value: u8) -> Result<Self, QuicBrokerError> {
        match value {
            QUIC_BROKER_CONTROL_PUBLISH => Ok(Self::Publish),
            QUIC_BROKER_CONTROL_SUBSCRIBE => Ok(Self::Subscribe),
            other => Err(QuicBrokerError::UnknownControlType(other)),
        }
    }
}

/// Binary broker control envelope, Marmot binary profile:
///
/// ```text
/// struct {
///   opaque marmot_broker<1..255>;     // ASCII "marmot.quic_broker.v1"
///   BrokerControlType control_type;   // uint8: publish(1), subscribe(2)
///   opaque stream_id<1..64>;          // raw stream id bytes
///   opaque start_event_id<1..64>;     // raw event id bytes (32 bytes today)
/// } QuicBrokerControlEnvelopeV1;
/// ```
///
/// Each `opaque name<min..max>` field uses the QUIC variable-length length
/// prefix. On the wire the envelope is framed exactly like a record frame: a
/// 4-byte big-endian `frame_len` followed by that many envelope bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuicBrokerControlEnvelopeV1 {
    pub control_type: QuicBrokerControlTypeV1,
    pub stream_id: Vec<u8>,
    pub start_event_id: Vec<u8>,
}

impl QuicBrokerControlEnvelopeV1 {
    pub fn publish(stream_id: impl Into<Vec<u8>>, start_event_id: &MessageId) -> Self {
        Self {
            control_type: QuicBrokerControlTypeV1::Publish,
            stream_id: stream_id.into(),
            start_event_id: start_event_id.as_slice().to_vec(),
        }
    }

    pub fn subscribe(stream_id: impl Into<Vec<u8>>, start_event_id: &MessageId) -> Self {
        Self {
            control_type: QuicBrokerControlTypeV1::Subscribe,
            stream_id: stream_id.into(),
            start_event_id: start_event_id.as_slice().to_vec(),
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, QuicBrokerError> {
        self.validate_bounds()?;
        let mut out = Vec::new();
        encode_quic_varint(QUIC_BROKER_PROTOCOL_V1.len() as u64, &mut out);
        out.extend_from_slice(QUIC_BROKER_PROTOCOL_V1.as_bytes());
        out.push(self.control_type.wire());
        encode_quic_varint(self.stream_id.len() as u64, &mut out);
        out.extend_from_slice(&self.stream_id);
        encode_quic_varint(self.start_event_id.len() as u64, &mut out);
        out.extend_from_slice(&self.start_event_id);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, QuicBrokerError> {
        let (marmot_broker, rest) = take_control_len_prefixed(bytes, "marmot_broker")?;
        if marmot_broker.is_empty() || marmot_broker.len() > 255 {
            return Err(QuicBrokerError::WrongControlProtocol(
                String::from_utf8_lossy(marmot_broker).into_owned(),
            ));
        }
        if marmot_broker != QUIC_BROKER_PROTOCOL_V1.as_bytes() {
            return Err(QuicBrokerError::WrongControlProtocol(
                String::from_utf8_lossy(marmot_broker).into_owned(),
            ));
        }
        let (control_type, rest) = rest
            .split_first()
            .ok_or(QuicBrokerError::ControlTruncated("control_type"))?;
        let control_type = QuicBrokerControlTypeV1::from_wire(*control_type)?;
        let (stream_id, rest) = take_control_len_prefixed(rest, "stream_id")?;
        let (start_event_id, rest) = take_control_len_prefixed(rest, "start_event_id")?;
        if !rest.is_empty() {
            return Err(QuicBrokerError::ControlTrailingBytes(rest.len()));
        }
        let envelope = Self {
            control_type,
            stream_id: stream_id.to_vec(),
            start_event_id: start_event_id.to_vec(),
        };
        envelope.validate_bounds()?;
        Ok(envelope)
    }

    fn validate_bounds(&self) -> Result<(), QuicBrokerError> {
        if self.stream_id.is_empty() {
            return Err(QuicBrokerError::EmptyStreamId);
        }
        if self.stream_id.len() > AGENT_TEXT_STREAM_MAX_STREAM_ID_LEN {
            return Err(QuicBrokerError::StreamIdTooLong(self.stream_id.len()));
        }
        if self.start_event_id.is_empty() {
            return Err(QuicBrokerError::EmptyStartEventId);
        }
        if self.start_event_id.len() > AGENT_TEXT_STREAM_MAX_STREAM_ID_LEN {
            return Err(QuicBrokerError::StartEventIdTooLong(
                self.start_event_id.len(),
            ));
        }
        Ok(())
    }

    pub fn key(&self) -> BrokerStreamKey {
        BrokerStreamKey::new(
            self.stream_id.clone(),
            MessageId::new(self.start_event_id.clone()),
        )
    }
}

fn take_control_len_prefixed<'a>(
    bytes: &'a [u8],
    field: &'static str,
) -> Result<(&'a [u8], &'a [u8]), QuicBrokerError> {
    let (len, prefix_len) =
        decode_quic_varint(bytes).map_err(|_| QuicBrokerError::ControlTruncated(field))?;
    let len = usize::try_from(len).map_err(|_| QuicBrokerError::ControlTruncated(field))?;
    let rest = bytes
        .get(prefix_len..)
        .ok_or(QuicBrokerError::ControlTruncated(field))?;
    if rest.len() < len {
        return Err(QuicBrokerError::ControlTruncated(field));
    }
    Ok(rest.split_at(len))
}
