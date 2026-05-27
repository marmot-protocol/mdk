use cgka_traits::message::{MessageRecord, MessageState, StoredMessagePayload};
use cgka_traits::storage::StorageProvider;
use cgka_traits::transport::TransportEnvelope;
use cgka_traits::types::GroupId;
use marmot_forensics::{
    ForensicsEngineGroupState, ForensicsExportOptions, ForensicsMessage, ForensicsOpenMlsMessage,
    ForensicsSnapshot, capture_payload,
};

use crate::engine::Engine;
use crate::openmls_projection::{OpenMlsContentKind, project_mls_message};

impl<S: StorageProvider> Engine<S> {
    pub fn group_forensics(
        &self,
        group_id: &GroupId,
        options: &ForensicsExportOptions,
    ) -> Result<ForensicsEngineGroupState, cgka_traits::error::EngineError> {
        let group = self.storage.get_group(group_id)?;
        let mut warnings = Vec::new();
        let mut messages = Vec::new();
        for record in self
            .storage
            .list_messages(group_id, cgka_traits::EpochId(0))?
        {
            match forensic_message_from_record(options, &record) {
                Ok(message) => messages.push(message),
                Err(warning) => warnings.push(warning),
            }
        }
        let snapshots = self
            .storage
            .list_group_snapshots(group_id)?
            .into_iter()
            .map(|name| ForensicsSnapshot {
                name: options.protect_text(&name),
            })
            .collect();
        Ok(ForensicsEngineGroupState {
            group_id: options.protect_hex(&hex::encode(group.id.as_slice())),
            epoch: group.epoch.0,
            member_count: group.members.len() as u32,
            required_app_components: group
                .required_capabilities
                .app_components
                .ids
                .iter()
                .copied()
                .collect(),
            messages,
            snapshots,
            warnings,
        })
    }
}

fn forensic_message_from_record(
    options: &ForensicsExportOptions,
    record: &MessageRecord,
) -> Result<ForensicsMessage, String> {
    let stored_payload = StoredMessagePayload::decode(&record.payload)
        .map_err(|err| format!("message payload decode failed: {err}"))?;
    let (payload_kind, message) = match stored_payload {
        StoredMessagePayload::RawTransport(message) => ("raw_transport", message),
        StoredMessagePayload::OpenMlsWire(message) => ("openmls_wire", message),
    };
    let (payload_len, payload_digest, payload_hex) = capture_payload(options, &message.payload);
    let openmls = (payload_kind == "openmls_wire")
        .then(|| openmls_forensics(options, &message.payload))
        .transpose()?;
    Ok(ForensicsMessage {
        message_id: options.protect_hex(&hex::encode(record.id.as_slice())),
        group_id: options.protect_hex(&hex::encode(record.group_id.as_slice())),
        epoch: record.epoch.0,
        state: message_state_name(record.state).to_owned(),
        payload_kind: payload_kind.to_owned(),
        envelope_kind: envelope_kind_name(&message.envelope).to_owned(),
        timestamp: message.timestamp.0,
        payload_len,
        payload_digest,
        payload_hex,
        openmls,
    })
}

fn openmls_forensics(
    options: &ForensicsExportOptions,
    payload: &[u8],
) -> Result<ForensicsOpenMlsMessage, String> {
    let projection =
        project_mls_message(payload).map_err(|err| format!("OpenMLS projection failed: {err}"))?;
    let message_digest = options.protect_digest_hex(&hex::encode(projection.message_digest));
    Ok(ForensicsOpenMlsMessage {
        content_kind: openmls_content_kind_name(projection.kind).to_owned(),
        source_epoch: projection.source_epoch,
        message_digest,
    })
}

fn message_state_name(state: MessageState) -> &'static str {
    match state {
        MessageState::Sent => "sent",
        MessageState::Created => "created",
        MessageState::Processed => "processed",
        MessageState::Failed => "failed",
        MessageState::Retryable => "retryable",
        MessageState::PeelDeferred => "peel_deferred",
        MessageState::EpochInvalidated => "epoch_invalidated",
    }
}

fn envelope_kind_name(envelope: &TransportEnvelope) -> &'static str {
    match envelope {
        TransportEnvelope::GroupMessage { .. } => "group_message",
        TransportEnvelope::Welcome { .. } => "welcome",
    }
}

fn openmls_content_kind_name(kind: OpenMlsContentKind) -> &'static str {
    match kind {
        OpenMlsContentKind::Application => "application",
        OpenMlsContentKind::Proposal => "proposal",
        OpenMlsContentKind::Commit => "commit",
        OpenMlsContentKind::Welcome => "welcome",
        OpenMlsContentKind::Other => "other",
    }
}
