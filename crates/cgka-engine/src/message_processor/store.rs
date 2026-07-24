//! Durable persistence, dedup classification, and stored-message state
//! transitions for the ingest/send paths of [`Engine`].

use super::content_dedup_id;
use crate::engine::Engine;
use cgka_traits::error::EngineError;
use cgka_traits::ingest::{IngestOutcome, StaleReason};
use cgka_traits::message::{MessageRecord, MessageState, StoredMessagePayload};
use cgka_traits::storage::{LeaveRequest, StorageError, StorageProvider};
use cgka_traits::transport::TransportMessage;
use cgka_traits::types::{EpochId, GroupId, MessageId};

impl<S: StorageProvider> Engine<S> {
    pub(crate) fn recorded_message_outcome(
        &self,
        id: &MessageId,
    ) -> Result<Option<IngestOutcome>, EngineError> {
        if self.storage.has_ingress_dedup_marker(id)? {
            return Ok(Some(IngestOutcome::Stale {
                reason: StaleReason::AlreadySeen,
            }));
        }
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

    /// Whether the raw transport row `id` is STILL awaiting retry as of its
    /// *current* stored state — the same `Created | Retryable | PeelDeferred`
    /// set the replay / deferred-peel loops admit at entry.
    ///
    /// Retirement paths re-read through this rather than trusting a row state
    /// snapshotted before re-ingest: `ingest_group_message` can commit a
    /// terminal state to this same row during the call (e.g. the `SelfEvicted`
    /// path persists it `Failed`, `ingest.rs`), and that verdict is
    /// authoritative — overwriting it with `Processed` would relabel a row we
    /// were evicted on as a canonicalization input. A vanished row
    /// (`NotFound`) is not awaiting retry.
    pub(crate) fn raw_transport_row_awaiting_retry(
        &self,
        id: &MessageId,
    ) -> Result<bool, EngineError> {
        match self.storage.get_message(id) {
            Ok(record) => Ok(matches!(
                record.state,
                MessageState::Created | MessageState::Retryable | MessageState::PeelDeferred
            )),
            Err(StorageError::NotFound) => Ok(false),
            Err(e) => Err(EngineError::Storage(e)),
        }
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
        // Also remember and persist the content-derived id so our own commit /
        // app message echoed back inside a freshly re-wrapped transport envelope
        // (different transport id) is still classified `OwnEcho` by the
        // post-peel content check after the hot-process cache misses or the
        // engine restarts.
        let content_id = content_dedup_id(mls_bytes);
        let openmls_msg = TransportMessage {
            payload: mls_bytes.to_vec(),
            ..msg.clone()
        };
        self.storage.with_transaction(|_storage| {
            self.persist_openmls_wire_message(&openmls_msg, group_id, epoch, MessageState::Sent)?;
            self.persist_sent_openmls_content_marker(
                &openmls_msg,
                content_id.clone(),
                group_id,
                epoch,
            )
        })?;
        // Do not seed the hot-process cache until both durable rows commit.
        self.sent_message_ids.insert(msg.id.clone());
        self.sent_message_ids.insert(content_id);
        Ok(())
    }

    pub(crate) fn record_sent_openmls_message_with_leave_request(
        &mut self,
        msg: &TransportMessage,
        mls_bytes: &[u8],
        group_id: &GroupId,
        epoch: EpochId,
        request: &LeaveRequest,
    ) -> Result<(), EngineError> {
        let openmls_msg = TransportMessage {
            payload: mls_bytes.to_vec(),
            ..msg.clone()
        };
        let payload = StoredMessagePayload::openmls_wire(openmls_msg.clone())
            .encode()
            .map_err(|e| EngineError::Serialize(format!("{e:?}")))?;
        let record = MessageRecord {
            id: msg.id.clone(),
            group_id: group_id.clone(),
            epoch,
            state: MessageState::Sent,
            payload,
        };
        let previous = match self.storage.get_message(&record.id) {
            Ok(record) => Some(record),
            Err(StorageError::NotFound) => None,
            Err(err) => return Err(EngineError::Storage(err)),
        };
        self.storage.with_transaction(|storage| {
            storage.put_message(&record)?;
            storage.put_leave_request(request)?;
            Ok::<_, EngineError>(())
        })?;

        self.sent_message_ids.insert(msg.id.clone());
        let content_id = content_dedup_id(mls_bytes);
        self.sent_message_ids.insert(content_id.clone());
        self.persist_sent_openmls_content_marker(&openmls_msg, content_id, group_id, epoch)?;
        self.leaving_groups.insert(request.group_id.clone());
        self.leave_requests
            .insert(request.group_id.clone(), request.clone());
        self.audit_group(
            group_id,
            crate::audit_helpers::message_state_transition_event(
                hex::encode(msg.id.as_slice()),
                previous.map(|record| record.state),
                MessageState::Sent,
                Some(epoch),
                "persist",
            ),
        );
        Ok(())
    }

    fn persist_sent_openmls_content_marker(
        &self,
        openmls_msg: &TransportMessage,
        content_id: MessageId,
        group_id: &GroupId,
        epoch: EpochId,
    ) -> Result<(), EngineError> {
        if content_id == openmls_msg.id {
            return Ok(());
        }
        // Marker-only row: storage classifies the content id as Sent/OwnEcho,
        // but canonicalization ignores RawTransport Sent rows so the same MLS
        // bytes do not enter the OpenMLS candidate graph twice.
        let marker = TransportMessage {
            id: content_id,
            ..openmls_msg.clone()
        };
        self.persist_transport_message(&marker, group_id, epoch, MessageState::Sent)
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
            Ok(_) => {
                // An own transport echo must not erase the delivery-aware
                // payload flavor of a retained outbound Welcome. The row is
                // already durable when its id enters `sent_message_ids`.
                if self
                    .storage
                    .get_message(&msg.id)
                    .ok()
                    .and_then(|record| StoredMessagePayload::decode(&record.payload).ok())
                    .is_some_and(|payload| payload.as_outbound_welcome().is_some())
                {
                    return Ok(());
                }
                self.persist_transport_message(msg, group_id, epoch, state)
            }
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
        let payload = payload
            .encode()
            .map_err(|e| EngineError::Serialize(format!("{e:?}")))?;
        // Short-circuit only when the stored record is fully identical,
        // including the encoded payload bytes. A same (group, epoch, state)
        // row persisted under a different payload variant (e.g. RawTransport
        // then OpenMlsWire) must be overwritten, not silently kept — a reader
        // on the other processing path would otherwise skip the record (#369).
        if previous.as_ref().is_some_and(|record| {
            record.group_id == *group_id
                && record.epoch == epoch
                && record.state == state
                && record.payload == payload
        }) {
            return Ok(());
        }
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

    pub(crate) fn mark_raw_transport_message_failed_if_awaiting_retry(
        &mut self,
        raw_msg_id: &MessageId,
        reason: &str,
    ) -> Result<(), EngineError> {
        match self.storage.get_message(raw_msg_id) {
            Ok(record)
                if matches!(
                    record.state,
                    MessageState::PeelDeferred | MessageState::Retryable
                ) =>
            {
                self.storage
                    .update_message_state(raw_msg_id, MessageState::Failed)?;
                self.audit_group(
                    &record.group_id,
                    crate::audit_helpers::message_state_transition_event(
                        hex::encode(raw_msg_id.as_slice()),
                        Some(record.state),
                        MessageState::Failed,
                        Some(record.epoch),
                        reason,
                    ),
                );
                // Only a `PeelDeferred` row holds a flood-cap slot (mdk#339);
                // a `Retryable` row — input buffered pre-peel while the group
                // could not ingest — sits outside the cap.
                if record.state == MessageState::PeelDeferred {
                    self.note_peel_deferred_row_retired(&record.group_id, raw_msg_id);
                }
                Ok(())
            }
            Ok(_) | Err(StorageError::NotFound) => Ok(()),
            Err(err) => Err(EngineError::Storage(err)),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::account_identity_proof::{AccountIdentityProofRequest, AccountIdentityProofSigner};
    use crate::engine::EngineBuilder;
    use async_trait::async_trait;
    use cgka_traits::error::PeelerError;
    use cgka_traits::group_context::GroupContextSnapshot;
    use cgka_traits::ingest::PeeledMessage;
    use cgka_traits::message::{MessageState, StoredMessagePayload};
    use cgka_traits::peeler::TransportPeeler;
    use cgka_traits::storage::{GroupStorage, MessageStorage};
    use cgka_traits::transport::{
        EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
    };
    use cgka_traits::types::{EpochId, GroupId, MemberId, MessageId};
    use k256::schnorr::{SigningKey, signature::hazmat::PrehashSigner};
    use sha2::{Digest, Sha256};
    use std::sync::Arc;
    use storage_sqlite::SqliteAccountStorage;

    struct UnreachablePeeler;

    #[async_trait]
    impl TransportPeeler for UnreachablePeeler {
        async fn peel_group_message(
            &self,
            _msg: &TransportMessage,
            _ctx: &GroupContextSnapshot,
        ) -> Result<PeeledMessage, PeelerError> {
            Err(PeelerError::DecryptFailed)
        }

        async fn peel_welcome(
            &self,
            _msg: &TransportMessage,
        ) -> Result<PeeledMessage, PeelerError> {
            Err(PeelerError::DecryptFailed)
        }

        async fn wrap_group_message(
            &self,
            _payload: &EncryptedPayload,
            _ctx: &GroupContextSnapshot,
        ) -> Result<TransportMessage, PeelerError> {
            Err(PeelerError::DecryptFailed)
        }

        async fn wrap_welcome(
            &self,
            _payload: &EncryptedPayload,
            _recipient: &MemberId,
        ) -> Result<TransportMessage, PeelerError> {
            Err(PeelerError::DecryptFailed)
        }
    }

    struct TestProofSigner(SigningKey);

    impl AccountIdentityProofSigner for TestProofSigner {
        fn sign_account_identity_proof(
            &self,
            request: &AccountIdentityProofRequest,
        ) -> Result<[u8; 64], String> {
            let signature = self
                .0
                .sign_prehash(&request.proof_event_id()?)
                .map_err(|e| e.to_string())?;
            Ok(signature.to_bytes())
        }
    }

    fn test_signing_key() -> SigningKey {
        let mut counter = 0u64;
        loop {
            let mut material = [0u8; 32];
            let mut hasher = Sha256::new();
            hasher.update(b"cgka-engine-store-test-identity-v1");
            hasher.update(counter.to_be_bytes());
            material.copy_from_slice(&hasher.finalize());
            if let Ok(sk) = SigningKey::from_bytes(&material) {
                return sk;
            }
            counter += 1;
        }
    }

    fn transport_message(id: &[u8], payload: &[u8]) -> TransportMessage {
        TransportMessage {
            id: MessageId::new(id.to_vec()),
            payload: payload.to_vec(),
            timestamp: Timestamp(0),
            causal_deps: vec![],
            source: TransportSource("store-test".into()),
            envelope: TransportEnvelope::GroupMessage {
                transport_group_id: vec![],
            },
        }
    }

    /// Regression for mdk#369: the idempotency short-circuit must compare the
    /// encoded payload, not just (group, epoch, state) — a second persist of
    /// the same id under a different `StoredMessagePayload` variant must
    /// overwrite, or a reader on the other processing path silently loses the
    /// record.
    #[test]
    fn same_key_persist_with_different_payload_variant_overwrites() {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        let signing_key = test_signing_key();
        let identity = signing_key.verifying_key().to_bytes().to_vec();
        let engine = EngineBuilder::new(storage.clone())
            .legacy_compatibility_profile()
            .identity(identity)
            .account_identity_proof_signer(Arc::new(TestProofSigner(signing_key)))
            .peeler(Box::new(UnreachablePeeler))
            .build()
            .unwrap();

        let group_id = GroupId::new(vec![7u8; 16]);
        storage
            .put_group(&cgka_traits::group::Group {
                id: group_id.clone(),
                name: "store-test".into(),
                description: String::new(),
                epoch: EpochId(3),
                members: vec![],
                required_capabilities: Default::default(),
                protocol_profile: cgka_traits::group::ProtocolProfile::Legacy,
                removed: false,
                join_epoch: EpochId(0),
            })
            .unwrap();
        let msg = transport_message(b"colliding-id", b"wire-bytes");

        engine
            .persist_transport_message(&msg, &group_id, EpochId(3), MessageState::Failed)
            .unwrap();
        engine
            .persist_openmls_wire_message(&msg, &group_id, EpochId(3), MessageState::Failed)
            .unwrap();

        let record = storage.get_message(&msg.id).unwrap();
        let stored = StoredMessagePayload::decode(&record.payload).unwrap();
        assert!(
            stored.as_openmls_wire().is_some(),
            "second persist with a different payload variant must overwrite the record"
        );

        // Fully identical re-persist still short-circuits without error.
        engine
            .persist_openmls_wire_message(&msg, &group_id, EpochId(3), MessageState::Failed)
            .unwrap();
        let record = storage.get_message(&msg.id).unwrap();
        let stored = StoredMessagePayload::decode(&record.payload).unwrap();
        assert!(stored.as_openmls_wire().is_some());
    }
}
