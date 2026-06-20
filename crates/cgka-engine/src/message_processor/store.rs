//! Durable persistence, dedup classification, and stored-message state
//! transitions for the ingest/send paths of [`Engine`].

use super::content_dedup_id;
use crate::engine::Engine;
use cgka_traits::error::EngineError;
use cgka_traits::ingest::{IngestOutcome, StaleReason};
use cgka_traits::message::{MessageRecord, MessageState, StoredMessagePayload};
use cgka_traits::storage::{StorageError, StorageProvider};
use cgka_traits::transport::TransportMessage;
use cgka_traits::types::{EpochId, GroupId, MessageId};

impl<S: StorageProvider> Engine<S> {
    pub(crate) fn recorded_message_outcome(
        &self,
        id: &MessageId,
    ) -> Result<Option<IngestOutcome>, EngineError> {
        let record = match self.storage.get_message(id) {
            Ok(record) => record,
            Err(StorageError::NotFound) => return Ok(None),
            Err(e) => return Err(EngineError::Storage(e)),
        };

        let outcome = match record.state {
            MessageState::Sent => IngestOutcome::Stale {
                reason: StaleReason::OwnEcho,
            },
            MessageState::Created | MessageState::Retryable => IngestOutcome::Buffered {
                group_id: record.group_id,
                epoch: record.epoch,
            },
            MessageState::PeelDeferred => return Ok(None),
            MessageState::Processed | MessageState::Failed | MessageState::EpochInvalidated => {
                IngestOutcome::Stale {
                    reason: StaleReason::AlreadySeen,
                }
            }
        };
        Ok(Some(outcome))
    }

    pub(crate) fn should_remember_ingested_message(
        &self,
        id: &MessageId,
    ) -> Result<bool, EngineError> {
        let record = match self.storage.get_message(id) {
            Ok(record) => record,
            Err(StorageError::NotFound) => return Ok(true),
            Err(e) => return Err(EngineError::Storage(e)),
        };

        Ok(!matches!(
            record.state,
            MessageState::Created | MessageState::Retryable | MessageState::PeelDeferred
        ))
    }

    pub(crate) fn record_sent_message(
        &mut self,
        msg: &TransportMessage,
        group_id: &GroupId,
        epoch: EpochId,
    ) -> Result<(), EngineError> {
        self.sent_message_ids.insert(msg.id.clone());
        self.persist_transport_message(msg, group_id, epoch, MessageState::Sent)
    }

    pub(crate) fn record_sent_openmls_message(
        &mut self,
        msg: &TransportMessage,
        mls_bytes: &[u8],
        group_id: &GroupId,
        epoch: EpochId,
    ) -> Result<(), EngineError> {
        self.sent_message_ids.insert(msg.id.clone());
        // Also remember the content-derived id so our own commit / app message
        // echoed back inside a freshly re-wrapped transport envelope (different
        // transport id) is still classified `OwnEcho` by the post-peel content
        // check, not reprocessed.
        self.sent_message_ids.insert(content_dedup_id(mls_bytes));
        let openmls_msg = TransportMessage {
            payload: mls_bytes.to_vec(),
            ..msg.clone()
        };
        self.persist_openmls_wire_message(&openmls_msg, group_id, epoch, MessageState::Sent)
    }

    pub(crate) fn persist_transport_message(
        &self,
        msg: &TransportMessage,
        group_id: &GroupId,
        epoch: EpochId,
        state: MessageState,
    ) -> Result<(), EngineError> {
        self.persist_stored_message_payload(
            msg.id.clone(),
            group_id,
            epoch,
            state,
            StoredMessagePayload::raw_transport(msg.clone()),
        )
    }

    pub(crate) fn persist_transport_message_for_existing_group(
        &self,
        msg: &TransportMessage,
        group_id: &GroupId,
        epoch: EpochId,
        state: MessageState,
    ) -> Result<(), EngineError> {
        match self.storage.get_group(group_id) {
            Ok(_) => self.persist_transport_message(msg, group_id, epoch, state),
            Err(StorageError::NotFound) => Ok(()),
            Err(e) => Err(EngineError::Storage(e)),
        }
    }

    pub(crate) fn persist_openmls_wire_message(
        &self,
        msg: &TransportMessage,
        group_id: &GroupId,
        epoch: EpochId,
        state: MessageState,
    ) -> Result<(), EngineError> {
        self.persist_stored_message_payload(
            msg.id.clone(),
            group_id,
            epoch,
            state,
            StoredMessagePayload::openmls_wire(msg.clone()),
        )
    }

    fn persist_stored_message_payload(
        &self,
        id: MessageId,
        group_id: &GroupId,
        epoch: EpochId,
        state: MessageState,
        payload: StoredMessagePayload,
    ) -> Result<(), EngineError> {
        let id_hex = hex::encode(id.as_slice());
        let previous = match self.storage.get_message(&id) {
            Ok(record) => Some(record),
            Err(StorageError::NotFound) => None,
            Err(err) => return Err(EngineError::Storage(err)),
        };
        if previous.as_ref().is_some_and(|record| {
            record.group_id == *group_id && record.epoch == epoch && record.state == state
        }) {
            return Ok(());
        }
        let payload = payload
            .encode()
            .map_err(|e| EngineError::Serialize(format!("{e:?}")))?;
        self.storage.put_message(&MessageRecord {
            id,
            group_id: group_id.clone(),
            epoch,
            state,
            payload,
        })?;
        self.audit_group(
            group_id,
            crate::audit_helpers::message_state_transition_event(
                id_hex,
                previous.map(|record| record.state),
                state,
                Some(epoch),
                "persist",
            ),
        );
        Ok(())
    }

    pub(crate) fn update_stored_message_state(
        &self,
        id: &MessageId,
        state: MessageState,
    ) -> Result<(), EngineError> {
        let previous = self.storage.get_message(id).ok();
        self.storage.update_message_state(id, state)?;
        let event = crate::audit_helpers::message_state_transition_event(
            hex::encode(id.as_slice()),
            previous.as_ref().map(|record| record.state),
            state,
            previous.as_ref().map(|record| record.epoch),
            "state_update",
        );
        if let Some(record) = previous {
            self.audit_group(&record.group_id, event);
        } else {
            self.audit(event);
        }
        Ok(())
    }
}
