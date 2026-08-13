use super::rows::{
    GroupStateCheckpoint, MemberCapabilitiesSnapshot, OpenMlsValueSnapshot, OrderedMessage,
    OrderedQueuedOutbound, Snapshot,
};
use crate::codec::{SensitiveBytes, serialize_sensitive};
use crate::{deserialize, i64_to_u64, message_state_from_i64, message_state_to_i64, serialize};
use cgka_traits::message::MessageRecord;
use cgka_traits::storage::{StorageError, StorageResult};
use cgka_traits::types::{EpochId, GroupId, MemberId, MessageId};
use serde::de::DeserializeOwned;

const SNAPSHOT_MAGIC: &[u8; 4] = b"MDKS";
const SNAPSHOT_VERSION: u16 = 2;
const MAX_FIELD_LEN: usize = 1 << 30;
const MAX_LIST_ITEMS: usize = 1 << 20;

pub(super) fn encode(snapshot: &Snapshot) -> StorageResult<SensitiveBytes> {
    let prepared = PreparedSnapshot::new(snapshot)?;
    let encoded_len = snapshot_encoded_len(snapshot, &prepared)?;
    let mut encoder = Encoder::new(encoded_len);
    encoder.bytes(SNAPSHOT_MAGIC)?;
    encoder.u16(SNAPSHOT_VERSION)?;
    encoder.var(&prepared.group)?;
    encoder.option_list(snapshot.messages.as_deref(), |message, index, encoder| {
        encoder.u64(i64_to_u64(message.insert_order)?)?;
        encode_message(
            &message.record,
            prepared.message_deferred[index].as_deref(),
            encoder,
        )
    })?;
    encoder.option_list(
        snapshot.queued_outbound.as_deref(),
        |queued, index, encoder| {
            encoder.u64(i64_to_u64(queued.insert_order)?)?;
            encoder.var(prepared.queued[index].as_slice())
        },
    )?;
    encoder.list(&snapshot.member_caps, |caps, index, encoder| {
        encoder.var(caps.member_id.as_slice())?;
        encoder.var(&prepared.member_caps[index])
    })?;
    encoder.option_bytes(snapshot.convergence_policy.as_deref())?;
    encoder.option_bytes(snapshot.validated_tree_marker.as_deref())?;
    encoder.list(&snapshot.openmls_values, |value, _, encoder| {
        encoder.var(&value.label)?;
        encoder.var(&value.storage_key)?;
        encoder.var(&value.group_key)?;
        encoder.var(value.value.as_slice())
    })?;
    encoder.finish()
}

pub(super) fn decode(bytes: &[u8]) -> StorageResult<Snapshot> {
    if !bytes.starts_with(SNAPSHOT_MAGIC) {
        return deserialize(bytes);
    }
    let mut decoder = Decoder::new(bytes);
    decoder.expect(SNAPSHOT_MAGIC, "snapshot magic")?;
    let version = decoder.u16("snapshot version")?;
    if version != SNAPSHOT_VERSION {
        return Err(serialization(format!(
            "unsupported group snapshot version {version}"
        )));
    }
    let group = decoder.json("group")?;
    let messages = decoder.option_list("messages", |decoder| {
        let insert_order = decoder.i64_from_u64("message insert order")?;
        let id = MessageId::new(decoder.var("message id")?.to_vec());
        let group_id = GroupId::new(decoder.var("message group id")?.to_vec());
        let epoch = EpochId(decoder.u64("message epoch")?);
        let state = message_state_from_i64(i64::from(decoder.u8("message state")?))?;
        let payload = decoder.var("message payload")?.to_vec();
        let deferred_peel = decoder.option_json("deferred peel")?;
        Ok(OrderedMessage {
            insert_order,
            record: MessageRecord {
                id,
                group_id,
                epoch,
                state,
                payload,
                deferred_peel,
            },
        })
    })?;
    let queued_outbound = decoder.option_list("queued outbound", |decoder| {
        Ok(OrderedQueuedOutbound {
            insert_order: decoder.i64_from_u64("queued insert order")?,
            record: decoder.json("queued outbound record")?,
        })
    })?;
    let member_caps = decoder.list("member capabilities", |decoder| {
        Ok(MemberCapabilitiesSnapshot {
            member_id: MemberId::new(decoder.var("member id")?.to_vec()),
            capabilities: decoder.json("member capabilities")?,
        })
    })?;
    let convergence_policy = decoder.option_bytes("convergence policy")?;
    let validated_tree_marker = decoder.option_bytes("validated tree marker")?;
    let openmls_values = decoder.list("OpenMLS values", |decoder| {
        Ok(OpenMlsValueSnapshot {
            label: decoder.var("OpenMLS label")?.to_vec(),
            storage_key: decoder.var("OpenMLS storage key")?.to_vec(),
            group_key: decoder.var("OpenMLS group key")?.to_vec(),
            value: SensitiveBytes::new(decoder.var("OpenMLS value")?.to_vec()),
        })
    })?;
    decoder.finish("group snapshot")?;
    Ok(Snapshot {
        group,
        messages,
        queued_outbound,
        member_caps,
        convergence_policy,
        validated_tree_marker,
        openmls_values,
    })
}

pub(super) fn encode_checkpoint(
    checkpoint: &GroupStateCheckpoint,
) -> StorageResult<SensitiveBytes> {
    encode(&Snapshot {
        group: checkpoint.group.clone(),
        messages: None,
        queued_outbound: None,
        member_caps: checkpoint
            .member_caps
            .iter()
            .map(|caps| MemberCapabilitiesSnapshot {
                member_id: caps.member_id.clone(),
                capabilities: caps.capabilities.clone(),
            })
            .collect(),
        convergence_policy: None,
        validated_tree_marker: checkpoint.validated_tree_marker.clone(),
        openmls_values: checkpoint
            .openmls_values
            .iter()
            .map(|value| OpenMlsValueSnapshot {
                label: value.label.clone(),
                storage_key: value.storage_key.clone(),
                group_key: value.group_key.clone(),
                value: SensitiveBytes::new(value.value.as_slice().to_vec()),
            })
            .collect(),
    })
}

pub(super) fn decode_checkpoint(bytes: &[u8]) -> StorageResult<GroupStateCheckpoint> {
    if !bytes.starts_with(SNAPSHOT_MAGIC) {
        return deserialize(bytes);
    }
    let snapshot = decode(bytes)?;
    if snapshot.messages.is_some()
        || snapshot.queued_outbound.is_some()
        || snapshot.convergence_policy.is_some()
    {
        return Err(serialization(
            "group-state checkpoint contains rollback-only fields",
        ));
    }
    Ok(GroupStateCheckpoint {
        group: snapshot.group,
        member_caps: snapshot.member_caps,
        validated_tree_marker: snapshot.validated_tree_marker,
        openmls_values: snapshot.openmls_values,
    })
}

struct PreparedSnapshot {
    group: Vec<u8>,
    message_deferred: Vec<Option<Vec<u8>>>,
    queued: Vec<SensitiveBytes>,
    member_caps: Vec<Vec<u8>>,
}

impl PreparedSnapshot {
    fn new(snapshot: &Snapshot) -> StorageResult<Self> {
        Ok(Self {
            group: serialize(&snapshot.group)?,
            message_deferred: snapshot
                .messages
                .as_deref()
                .unwrap_or_default()
                .iter()
                .map(|message| {
                    message
                        .record
                        .deferred_peel
                        .as_ref()
                        .map(serialize)
                        .transpose()
                })
                .collect::<StorageResult<Vec<_>>>()?,
            queued: snapshot
                .queued_outbound
                .as_deref()
                .unwrap_or_default()
                .iter()
                .map(|queued| serialize_sensitive(&queued.record))
                .collect::<StorageResult<Vec<_>>>()?,
            member_caps: snapshot
                .member_caps
                .iter()
                .map(|caps| serialize(&caps.capabilities))
                .collect::<StorageResult<Vec<_>>>()?,
        })
    }
}

fn encode_message(
    message: &MessageRecord,
    deferred: Option<&[u8]>,
    encoder: &mut Encoder,
) -> StorageResult<()> {
    encoder.var(message.id.as_slice())?;
    encoder.var(message.group_id.as_slice())?;
    encoder.u64(message.epoch.0)?;
    encoder.u8(u8::try_from(message_state_to_i64(message.state))
        .map_err(|_| serialization("message state does not fit the snapshot encoding"))?)?;
    encoder.var(&message.payload)?;
    encoder.option_bytes(deferred)
}

// Compute the complete length without materializing secret-bearing output.
fn snapshot_encoded_len(snapshot: &Snapshot, prepared: &PreparedSnapshot) -> StorageResult<usize> {
    let mut len = SNAPSHOT_MAGIC.len() + 2 + var_len(prepared.group.len())?;
    len = checked_add(len, 1)?;
    if let Some(messages) = &snapshot.messages {
        let mut body = 0;
        for (index, message) in messages.iter().enumerate() {
            body = checked_add(body, 8)?;
            body = checked_add(
                body,
                message_encoded_len(&message.record, prepared.message_deferred[index].as_deref())?,
            )?;
        }
        len = checked_add(len, var_len(body)?)?;
    }
    len = checked_add(len, 1)?;
    if let Some(queued) = &snapshot.queued_outbound {
        let mut body = 0;
        for (index, _) in queued.iter().enumerate() {
            body = checked_add(body, 8)?;
            body = checked_add(body, var_len(prepared.queued[index].len())?)?;
        }
        len = checked_add(len, var_len(body)?)?;
    }
    let mut caps_body = 0;
    for (index, caps) in snapshot.member_caps.iter().enumerate() {
        caps_body = checked_add(caps_body, var_len(caps.member_id.as_slice().len())?)?;
        caps_body = checked_add(caps_body, var_len(prepared.member_caps[index].len())?)?;
    }
    len = checked_add(len, var_len(caps_body)?)?;
    len = checked_add(len, option_len(snapshot.convergence_policy.as_deref())?)?;
    len = checked_add(len, option_len(snapshot.validated_tree_marker.as_deref())?)?;
    let mut openmls_body = 0;
    for value in &snapshot.openmls_values {
        for field_len in [
            value.label.len(),
            value.storage_key.len(),
            value.group_key.len(),
            value.value.as_slice().len(),
        ] {
            openmls_body = checked_add(openmls_body, var_len(field_len)?)?;
        }
    }
    checked_add(len, var_len(openmls_body)?)
}

fn message_encoded_len(message: &MessageRecord, deferred: Option<&[u8]>) -> StorageResult<usize> {
    let mut len = var_len(message.id.as_slice().len())?;
    len = checked_add(len, var_len(message.group_id.as_slice().len())?)?;
    len = checked_add(len, 8 + 1)?;
    len = checked_add(len, var_len(message.payload.len())?)?;
    checked_add(len, option_len(deferred)?)
}

fn option_len(value: Option<&[u8]>) -> StorageResult<usize> {
    match value {
        None => Ok(1),
        Some(value) => checked_add(1, var_len(value.len())?),
    }
}

fn var_len(len: usize) -> StorageResult<usize> {
    if len > MAX_FIELD_LEN {
        return Err(serialization("snapshot field exceeds format limit"));
    }
    checked_add(quic_len(len)?, len)
}

fn quic_len(value: usize) -> StorageResult<usize> {
    match value {
        0..=63 => Ok(1),
        64..=16_383 => Ok(2),
        16_384..=1_073_741_823 => Ok(4),
        _ if value <= MAX_FIELD_LEN => Ok(8),
        _ => Err(serialization("snapshot length exceeds format limit")),
    }
}

fn checked_add(left: usize, right: usize) -> StorageResult<usize> {
    left.checked_add(right)
        .ok_or_else(|| serialization("snapshot encoded length overflow"))
}

struct Encoder {
    out: SensitiveBytes,
    expected_len: usize,
}

impl Encoder {
    fn new(expected_len: usize) -> Self {
        Self {
            out: SensitiveBytes::with_capacity(expected_len),
            expected_len,
        }
    }

    fn bytes(&mut self, bytes: &[u8]) -> StorageResult<()> {
        self.out.extend_exact(bytes)
    }

    fn u8(&mut self, value: u8) -> StorageResult<()> {
        self.bytes(&[value])
    }

    fn u16(&mut self, value: u16) -> StorageResult<()> {
        self.bytes(&value.to_be_bytes())
    }

    fn u64(&mut self, value: u64) -> StorageResult<()> {
        self.bytes(&value.to_be_bytes())
    }

    fn var(&mut self, bytes: &[u8]) -> StorageResult<()> {
        if bytes.len() > MAX_FIELD_LEN {
            return Err(serialization("snapshot field exceeds format limit"));
        }
        let mut prefix = Vec::with_capacity(8);
        cgka_traits::app_components::encode_quic_varint(bytes.len() as u64, &mut prefix);
        self.bytes(&prefix)?;
        self.bytes(bytes)
    }

    fn option_bytes(&mut self, bytes: Option<&[u8]>) -> StorageResult<()> {
        match bytes {
            None => self.u8(0),
            Some(bytes) => {
                self.u8(1)?;
                self.var(bytes)
            }
        }
    }

    fn list<T>(
        &mut self,
        values: &[T],
        mut encode: impl FnMut(&T, usize, &mut Encoder) -> StorageResult<()>,
    ) -> StorageResult<()> {
        if values.len() > MAX_LIST_ITEMS {
            return Err(serialization("snapshot list exceeds item limit"));
        }
        let start = self.out.len();
        // Reserve the prefix by first measuring the list body independently.
        let mut body = Encoder::new(self.expected_len.saturating_sub(start));
        for (index, value) in values.iter().enumerate() {
            encode(value, index, &mut body)?;
        }
        let body = body.finish_unchecked()?;
        self.var(body.as_slice())
    }

    fn option_list<T>(
        &mut self,
        values: Option<&[T]>,
        encode: impl FnMut(&T, usize, &mut Encoder) -> StorageResult<()>,
    ) -> StorageResult<()> {
        match values {
            None => self.u8(0),
            Some(values) => {
                self.u8(1)?;
                self.list(values, encode)
            }
        }
    }

    fn finish_unchecked(self) -> StorageResult<SensitiveBytes> {
        Ok(self.out)
    }

    fn finish(self) -> StorageResult<SensitiveBytes> {
        if self.out.len() != self.expected_len || self.out.capacity() != self.expected_len {
            return Err(serialization(format!(
                "snapshot length mismatch: expected {}, wrote {}",
                self.expected_len,
                self.out.len()
            )));
        }
        Ok(self.out)
    }
}

struct Decoder<'a> {
    remaining: &'a [u8],
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn expect(&mut self, expected: &[u8], label: &str) -> StorageResult<()> {
        if !self.remaining.starts_with(expected) {
            return Err(serialization(format!("invalid {label}")));
        }
        self.remaining = &self.remaining[expected.len()..];
        Ok(())
    }

    fn take(&mut self, len: usize, label: &str) -> StorageResult<&'a [u8]> {
        if self.remaining.len() < len {
            return Err(serialization(format!("truncated {label}")));
        }
        let value = &self.remaining[..len];
        self.remaining = &self.remaining[len..];
        Ok(value)
    }

    fn u8(&mut self, label: &str) -> StorageResult<u8> {
        Ok(self.take(1, label)?[0])
    }

    fn u16(&mut self, label: &str) -> StorageResult<u16> {
        let bytes = self.take(2, label)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u64(&mut self, label: &str) -> StorageResult<u64> {
        let bytes = self.take(8, label)?;
        let mut value = [0_u8; 8];
        value.copy_from_slice(bytes);
        Ok(u64::from_be_bytes(value))
    }

    fn i64_from_u64(&mut self, label: &str) -> StorageResult<i64> {
        i64::try_from(self.u64(label)?)
            .map_err(|_| serialization(format!("{label} exceeds SQLite integer range")))
    }

    fn var(&mut self, label: &str) -> StorageResult<&'a [u8]> {
        let (len, prefix_len) = cgka_traits::app_components::decode_quic_varint(self.remaining)
            .map_err(|error| serialization(format!("{label} length: {error}")))?;
        let len = usize::try_from(len).map_err(|_| serialization(format!("{label} too large")))?;
        if len > MAX_FIELD_LEN {
            return Err(serialization(format!("{label} exceeds format limit")));
        }
        self.take(prefix_len, label)?;
        self.take(len, label)
    }

    fn json<T: DeserializeOwned>(&mut self, label: &str) -> StorageResult<T> {
        deserialize(self.var(label)?)
    }

    fn option_bytes(&mut self, label: &str) -> StorageResult<Option<Vec<u8>>> {
        match self.u8("option discriminant")? {
            0 => Ok(None),
            1 => Ok(Some(self.var(label)?.to_vec())),
            value => Err(serialization(format!(
                "invalid option discriminant {value}"
            ))),
        }
    }

    fn option_json<T: DeserializeOwned>(&mut self, label: &str) -> StorageResult<Option<T>> {
        self.option_bytes(label)?
            .as_deref()
            .map(deserialize)
            .transpose()
    }

    fn list<T>(
        &mut self,
        label: &str,
        mut decode: impl FnMut(&mut Decoder<'_>) -> StorageResult<T>,
    ) -> StorageResult<Vec<T>> {
        let body = self.var(label)?;
        let mut decoder = Decoder::new(body);
        let mut values = Vec::new();
        while !decoder.remaining.is_empty() {
            if values.len() == MAX_LIST_ITEMS {
                return Err(serialization(format!("{label} exceeds item limit")));
            }
            values.push(decode(&mut decoder)?);
        }
        Ok(values)
    }

    fn option_list<T>(
        &mut self,
        label: &str,
        decode: impl FnMut(&mut Decoder<'_>) -> StorageResult<T>,
    ) -> StorageResult<Option<Vec<T>>> {
        match self.u8("option discriminant")? {
            0 => Ok(None),
            1 => self.list(label, decode).map(Some),
            value => Err(serialization(format!(
                "invalid option discriminant {value}"
            ))),
        }
    }

    fn finish(self, label: &str) -> StorageResult<()> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(serialization(format!("{label} has trailing bytes")))
        }
    }
}

fn serialization(message: impl Into<String>) -> StorageError {
    StorageError::Serialization(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::test_support::{gid, sample_group};

    #[test]
    fn state_scoped_v2_has_stable_golden_bytes() {
        let snapshot = Snapshot {
            group: sample_group(gid(1), 0, 0),
            messages: None,
            queued_outbound: None,
            member_caps: Vec::new(),
            convergence_policy: None,
            validated_tree_marker: None,
            openmls_values: Vec::new(),
        };
        let encoded = encode(&snapshot).unwrap();
        assert_eq!(
            hex::encode(encoded.as_slice()),
            "4d444b53000240f27b226964223a5b312c312c312c315d2c226e616d65223a2273616d706c65222c226465736372697074696f6e223a2264657363222c2265706f6368223a302c226d656d62657273223a5b5d2c2272657175697265645f6361706162696c6974696573223a7b2270726f706f73616c73223a5b5d2c22657874656e73696f6e73223a5b5d2c226170705f636f6d706f6e656e7473223a7b22696473223a5b5d7d7d2c2270726f746f636f6c5f70726f66696c65223a226c6567616379222c2272656d6f766564223a66616c73652c22756e7265636f76657261626c65223a66616c73652c226a6f696e5f65706f6368223a307d000000000000"
        );
    }
}
