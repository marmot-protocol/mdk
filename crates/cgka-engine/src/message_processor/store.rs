//! Durable persistence, dedup classification, and stored-message state
//! transitions for the ingest/send paths of [`Engine`].

use super::content_dedup_id;
use crate::engine::Engine;
use cgka_traits::engine::GroupEvent;
use cgka_traits::error::EngineError;
use cgka_traits::ingest::{InboundResourceLimit, IngestOutcome, InputRejectionCategory};
use cgka_traits::message::{
    DeferredPeelLifecycle, MessageRecord, MessageState, OwnApplicationConvergenceStamp,
    StoredMessagePayload,
};
use cgka_traits::storage::{LeaveRequest, StorageError, StorageProvider};
use cgka_traits::transport::{TransportEnvelope, TransportMessage};
use cgka_traits::types::{EpochId, GroupId, MessageId};

fn fresh_deferred_peel_lifecycle(
    now: crate::convergence_clock::ConvergenceTime,
    convergence_clock_instance_id: u64,
    deferred_peel_residence_ms: u64,
) -> DeferredPeelLifecycle {
    DeferredPeelLifecycle {
        first_observed_wall_ms: now.wall_ms,
        wall_high_water_ms: now.wall_ms,
        clock_instance_id: convergence_clock_instance_id,
        residence_deadline_monotonic_ms: now
            .monotonic_ms
            .saturating_add(deferred_peel_residence_ms),
        residence_deadline_wall_ms: now.wall_ms.saturating_add(deferred_peel_residence_ms),
        distinct_context_attempts: 0,
        last_context_fingerprint: None,
    }
}

/// Promote or retire the non-deliverable Welcome artifacts produced beside one
/// staged invite commit.
///
/// Normal publish resolution supplies the exact origin commit id, so another
/// staged or stale Welcome at the same group epoch cannot be promoted with the
/// current commit. Raw Welcome rows at this exact epoch came from a legacy
/// binary and cannot be coupled to the surviving commit; retire them rather
/// than risk delivering an orphan. Cold compatibility rollback may pass `None`
/// to retire every still-staged artifact at that source epoch.
pub(crate) fn transition_staged_invite_welcomes<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    source_epoch: EpochId,
    origin_commit_id: Option<&MessageId>,
    state: MessageState,
) -> Result<(), EngineError> {
    debug_assert!(matches!(state, MessageState::Sent | MessageState::Failed));
    for mut record in storage.list_messages(group_id, source_epoch)? {
        if record.epoch != source_epoch || record.state != MessageState::Sent {
            continue;
        }
        let payload = StoredMessagePayload::decode(&record.payload)
            .map_err(|error| EngineError::Serialize(format!("{error:?}")))?;
        if let Some(message) = payload.as_raw_transport()
            && matches!(message.envelope, TransportEnvelope::Welcome { .. })
        {
            record.state = MessageState::Failed;
            storage.put_message(&record)?;
            continue;
        }
        let Some((message, staged_origin_commit_id)) = payload.as_staged_invite_welcome() else {
            continue;
        };
        if !matches!(message.envelope, TransportEnvelope::Welcome { .. }) {
            continue;
        }
        if origin_commit_id.is_some_and(|expected| expected != staged_origin_commit_id) {
            record.state = MessageState::Failed;
            storage.put_message(&record)?;
            continue;
        }
        record.payload = StoredMessagePayload::outbound_welcome(message.clone())
            .encode()
            .map_err(|error| EngineError::Serialize(format!("{error:?}")))?;
        record.state = state;
        storage.put_message(&record)?;
    }
    Ok(())
}

/// Return the effective deferred-peel lifecycle for the current clock domain.
///
/// This is the single source of truth for legacy-row initialization and
/// restart rebasing. Runtime maintenance persists the returned value when
/// `changed` is true; conformance diagnostics use the same normalized copy
/// without mutating storage.
pub(crate) fn normalized_deferred_peel_lifecycle(
    lifecycle: Option<&DeferredPeelLifecycle>,
    now: crate::convergence_clock::ConvergenceTime,
    convergence_clock_instance_id: u64,
    deferred_peel_residence_ms: u64,
) -> (DeferredPeelLifecycle, bool) {
    let Some(lifecycle) = lifecycle else {
        return (
            fresh_deferred_peel_lifecycle(
                now,
                convergence_clock_instance_id,
                deferred_peel_residence_ms,
            ),
            true,
        );
    };

    let mut normalized = lifecycle.clone();
    if normalized.clock_instance_id == convergence_clock_instance_id {
        return (normalized, false);
    }

    // Monotonic values do not survive restart. Preserve elapsed wall
    // residence through a high-water mark. If wall time moved backwards,
    // using the prior high water prevents premature expiry.
    let observed_wall = normalized.wall_high_water_ms.max(now.wall_ms);
    let remaining = normalized
        .residence_deadline_wall_ms
        .saturating_sub(observed_wall);
    normalized.clock_instance_id = convergence_clock_instance_id;
    normalized.residence_deadline_monotonic_ms = now.monotonic_ms.saturating_add(remaining);
    normalized.wall_high_water_ms = observed_wall;
    (normalized, true)
}

impl<S: StorageProvider> Engine<S> {
    pub(crate) fn recorded_message_outcome(
        &self,
        id: &MessageId,
    ) -> Result<Option<IngestOutcome>, EngineError> {
        if self.storage.has_processed_transport_id(id)? {
            return Ok(Some(IngestOutcome::Ignored {
                category: InputRejectionCategory::Duplicate,
            }));
        }
        if self.storage.has_ingress_dedup_marker(id)? {
            return Ok(Some(IngestOutcome::Ignored {
                category: InputRejectionCategory::Duplicate,
            }));
        }
        let record = match self.storage.get_message(id) {
            Ok(record) => record,
            Err(StorageError::NotFound) => return Ok(None),
            Err(e) => return Err(EngineError::Storage(e)),
        };

        let outcome = match record.state {
            MessageState::Sent => IngestOutcome::Ignored {
                category: InputRejectionCategory::OwnEcho,
            },
            MessageState::Created | MessageState::Retryable
                if crate::openmls_projection::decode_openmls_wire_projection(&record.payload)
                    .is_some_and(|(_, projection)| {
                        projection.kind == crate::openmls_projection::OpenMlsContentKind::Proposal
                    }) =>
            {
                // Retained standalone proposals stay Created/Retryable until
                // convergence consumes or invalidates them, but byte-identical
                // transport repeats are still duplicates. Internal replay
                // bypasses this outer durable-dedup seam.
                IngestOutcome::Ignored {
                    category: InputRejectionCategory::Duplicate,
                }
            }
            MessageState::Created | MessageState::Retryable => IngestOutcome::Buffered {
                group_id: record.group_id,
                epoch: record.epoch,
            },
            MessageState::PeelDeferred => return Ok(None),
            MessageState::Processed
            | MessageState::Failed
            | MessageState::ConvergenceDeferred
            | MessageState::EpochInvalidated => IngestOutcome::Ignored {
                category: InputRejectionCategory::Duplicate,
            },
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

    pub(crate) fn record_staged_invite_welcome(
        &mut self,
        msg: &TransportMessage,
        origin_commit_id: &MessageId,
        group_id: &GroupId,
        epoch: EpochId,
    ) -> Result<(), EngineError> {
        self.sent_message_ids.insert(msg.id.clone());
        self.persist_stored_message_payload(
            msg.id.clone(),
            group_id,
            epoch,
            MessageState::Sent,
            StoredMessagePayload::staged_invite_welcome(msg.clone(), origin_commit_id.clone()),
            None,
        )
    }

    pub(crate) fn record_sent_openmls_message(
        &mut self,
        msg: &TransportMessage,
        mls_bytes: &[u8],
        group_id: &GroupId,
        epoch: EpochId,
    ) -> Result<(), EngineError> {
        self.record_sent_openmls_message_with_application_stamp(
            msg, mls_bytes, group_id, epoch, None,
        )
    }

    pub(crate) fn record_sent_openmls_application_message(
        &mut self,
        msg: &TransportMessage,
        mls_bytes: &[u8],
        group_id: &GroupId,
        epoch: EpochId,
        stamp: OwnApplicationConvergenceStamp,
    ) -> Result<(), EngineError> {
        self.record_sent_openmls_message_with_application_stamp(
            msg,
            mls_bytes,
            group_id,
            epoch,
            Some(stamp),
        )
    }

    fn record_sent_openmls_message_with_application_stamp(
        &mut self,
        msg: &TransportMessage,
        mls_bytes: &[u8],
        group_id: &GroupId,
        epoch: EpochId,
        application_stamp: Option<OwnApplicationConvergenceStamp>,
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
            let payload = match application_stamp {
                Some(stamp) => StoredMessagePayload::signed_openmls_application_wire(
                    msg.clone(),
                    openmls_msg.clone(),
                    stamp,
                ),
                None => StoredMessagePayload::signed_openmls_wire(msg.clone(), openmls_msg.clone()),
            };
            self.persist_stored_message_payload(
                msg.id.clone(),
                group_id,
                epoch,
                MessageState::Sent,
                payload,
                None,
            )?;
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
        let content_id = content_dedup_id(mls_bytes);
        let openmls_msg = TransportMessage {
            payload: mls_bytes.to_vec(),
            ..msg.clone()
        };
        let payload = StoredMessagePayload::signed_openmls_wire(msg.clone(), openmls_msg.clone())
            .encode()
            .map_err(|e| EngineError::Serialize(format!("{e:?}")))?;
        let record = MessageRecord {
            id: msg.id.clone(),
            group_id: group_id.clone(),
            epoch,
            state: MessageState::Sent,
            payload,
            deferred_peel: None,
        };
        let previous = match self.storage.get_message(&record.id) {
            Ok(record) => Some(record),
            Err(StorageError::NotFound) => None,
            Err(err) => return Err(EngineError::Storage(err)),
        };
        self.storage.with_transaction(|storage| {
            storage.put_message(&record)?;
            storage.put_leave_request(request)?;
            self.persist_sent_openmls_content_marker(
                &openmls_msg,
                content_id.clone(),
                group_id,
                epoch,
            )
        })?;

        // Do not seed any hot-process sent/leave state until all durable rows
        // commit together.
        self.sent_message_ids.insert(msg.id.clone());
        self.sent_message_ids.insert(content_id);
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
            None,
        )
    }

    pub(crate) fn persist_transport_message_for_existing_group(
        &self,
        msg: &TransportMessage,
        group_id: &GroupId,
        epoch: EpochId,
        state: MessageState,
    ) -> Result<(), EngineError> {
        if !self.should_persist_transport_message_for_existing_group(msg, group_id)? {
            return Ok(());
        }
        self.persist_transport_message(msg, group_id, epoch, state)
    }

    pub(crate) fn persist_encoded_transport_message_for_existing_group(
        &self,
        msg: &TransportMessage,
        group_id: &GroupId,
        epoch: EpochId,
        state: MessageState,
        encoded_payload: Vec<u8>,
    ) -> Result<(), EngineError> {
        if !self.should_persist_transport_message_for_existing_group(msg, group_id)? {
            return Ok(());
        }
        self.persist_encoded_stored_message_payload(
            msg.id.clone(),
            group_id,
            epoch,
            state,
            encoded_payload,
            None,
        )
    }

    fn should_persist_transport_message_for_existing_group(
        &self,
        msg: &TransportMessage,
        group_id: &GroupId,
    ) -> Result<bool, EngineError> {
        match self.storage.get_group(group_id) {
            Ok(_) => {
                // An own transport echo must not erase the lifecycle-aware
                // payload flavor of a retained or staged outbound Welcome. The
                // row is already durable when its id enters `sent_message_ids`.
                if self
                    .storage
                    .get_message(&msg.id)
                    .ok()
                    .and_then(|record| StoredMessagePayload::decode(&record.payload).ok())
                    .is_some_and(|payload| {
                        payload.as_outbound_welcome().is_some()
                            || payload.as_staged_invite_welcome().is_some()
                    })
                {
                    return Ok(false);
                }
                Ok(true)
            }
            Err(StorageError::NotFound) => Ok(false),
            Err(e) => Err(EngineError::Storage(e)),
        }
    }

    #[cfg(test)]
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
            None,
        )
    }

    /// Persist canonical peeled content and the exact transport wrapper that
    /// admitted it in one storage transaction. Once this succeeds, replay of
    /// the wrapper never needs the historical peel context again.
    pub(crate) fn persist_openmls_wire_message_with_processed_transport_id(
        &self,
        msg: &TransportMessage,
        group_id: &GroupId,
        epoch: EpochId,
        state: MessageState,
        transport_id: &MessageId,
    ) -> Result<(), EngineError> {
        self.persist_stored_message_payload(
            msg.id.clone(),
            group_id,
            epoch,
            state,
            StoredMessagePayload::openmls_wire(msg.clone()),
            Some(transport_id),
        )
    }

    fn persist_stored_message_payload(
        &self,
        id: MessageId,
        group_id: &GroupId,
        epoch: EpochId,
        state: MessageState,
        payload: StoredMessagePayload,
        processed_transport_id: Option<&MessageId>,
    ) -> Result<(), EngineError> {
        let payload = payload
            .encode()
            .map_err(|e| EngineError::Serialize(format!("{e:?}")))?;
        self.persist_encoded_stored_message_payload(
            id,
            group_id,
            epoch,
            state,
            payload,
            processed_transport_id,
        )
    }

    fn persist_encoded_stored_message_payload(
        &self,
        id: MessageId,
        group_id: &GroupId,
        epoch: EpochId,
        state: MessageState,
        payload: Vec<u8>,
        processed_transport_id: Option<&MessageId>,
    ) -> Result<(), EngineError> {
        let id_hex = hex::encode(id.as_slice());
        let previous = match self.storage.get_message(&id) {
            Ok(record) => Some(record),
            Err(StorageError::NotFound) => None,
            Err(err) => return Err(EngineError::Storage(err)),
        };
        let deferred_peel = if state == MessageState::PeelDeferred {
            previous
                .as_ref()
                .and_then(|record| record.deferred_peel.clone())
                .or_else(|| {
                    let now = self.convergence_now();
                    Some(fresh_deferred_peel_lifecycle(
                        now,
                        self.convergence_clock_instance_id,
                        self.deferred_peel_residence_ms,
                    ))
                })
        } else {
            None
        };
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
                && record.deferred_peel == deferred_peel
        }) {
            if let Some(transport_id) = processed_transport_id {
                self.storage
                    .put_processed_transport_id(group_id, transport_id)?;
            }
            return Ok(());
        }
        let record = MessageRecord {
            id,
            group_id: group_id.clone(),
            epoch,
            state,
            payload,
            deferred_peel,
        };
        if let Some(transport_id) = processed_transport_id {
            self.storage.with_transaction(|storage| {
                storage.put_message(&record)?;
                storage.put_processed_transport_id(group_id, transport_id)?;
                Ok::<(), EngineError>(())
            })?;
        } else {
            self.storage.put_message(&record)?;
        }
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

    /// Normalize legacy/restarted lifecycle rows and persist at most one
    /// sweep-sized slice. Returns whether additional normalized rows remain
    /// to be persisted by a later scheduler tick.
    pub(super) fn normalize_deferred_peel_lifecycles(
        &self,
        records: &mut [MessageRecord],
        now: crate::convergence_clock::ConvergenceTime,
        limit: usize,
    ) -> Result<bool, EngineError> {
        let mut persisted = 0usize;
        let mut normalization_pending = false;
        for record in records {
            let (lifecycle, changed) = normalized_deferred_peel_lifecycle(
                record.deferred_peel.as_ref(),
                now,
                self.convergence_clock_instance_id,
                self.deferred_peel_residence_ms,
            );
            record.deferred_peel = Some(lifecycle);
            if changed {
                if persisted < limit {
                    self.storage.put_message(record)?;
                    persisted += 1;
                } else {
                    normalization_pending = true;
                }
            }
        }
        Ok(normalization_pending)
    }

    pub(super) fn release_deferred_peel_row(
        &mut self,
        record: &MessageRecord,
        resource: InboundResourceLimit,
        disposition: crate::message_disposition::MessageDisposition,
    ) -> Result<(), EngineError> {
        let retry_count = record.deferred_peel.as_ref().map_or(0, |lifecycle| {
            u64::from(lifecycle.distinct_context_attempts)
        });
        let residence_ms = record.deferred_peel.as_ref().map_or(0, |lifecycle| {
            lifecycle
                .wall_high_water_ms
                .max(self.convergence_now().wall_ms)
                .saturating_sub(lifecycle.first_observed_wall_ms)
        });
        self.storage.delete_message(&record.id)?;
        self.audit_group(
            &record.group_id,
            crate::audit_helpers::deferred_peel_resource_refused_event(
                hex::encode(record.id.as_slice()),
                Some(record.epoch),
                disposition.tag(),
                retry_count,
                residence_ms,
            ),
        );
        self.events_buf
            .push_back(GroupEvent::TransportObjectResourceRefused {
                group_id: record.group_id.clone(),
                message_id: record.id.clone(),
                resource,
            });
        self.note_peel_deferred_row_retired(record);
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
                    self.note_peel_deferred_row_retired(&record);
                }
                Ok(())
            }
            Ok(_) | Err(StorageError::NotFound) => Ok(()),
            Err(err) => Err(EngineError::Storage(err)),
        }
    }

    /// Retire a raw transport wrapper whose content-derived row is now the
    /// durably buffered convergence witness. Mirrors
    /// [`Self::mark_raw_transport_message_failed_if_awaiting_retry`], but the
    /// verdict is `Processed`: the wrapper's job is done and it must leave
    /// the retry lifecycle instead of being re-peeled on every later
    /// publish-cycle replay. A no-op on the direct path where no separate
    /// raw row exists.
    pub(crate) fn mark_raw_transport_message_processed_if_awaiting_retry(
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
                    .update_message_state(raw_msg_id, MessageState::Processed)?;
                self.audit_group(
                    &record.group_id,
                    crate::audit_helpers::message_state_transition_event(
                        hex::encode(raw_msg_id.as_slice()),
                        Some(record.state),
                        MessageState::Processed,
                        Some(record.epoch),
                        reason,
                    ),
                );
                // Only a `PeelDeferred` row holds a flood-cap slot (mdk#339).
                if record.state == MessageState::PeelDeferred {
                    self.note_peel_deferred_row_retired(&record);
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

    #[cfg_attr(not(target_arch = "wasm32"), async_trait)]
    #[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
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

    fn engine_with_stored_group() -> (
        SqliteAccountStorage,
        crate::engine::Engine<SqliteAccountStorage>,
        GroupId,
    ) {
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
                unrecoverable: false,
                disbanded: None,
                join_epoch: EpochId(0),
            })
            .unwrap();
        (storage, engine, group_id)
    }

    /// Genuine OpenMLS commit wire bytes from a standalone one-member group.
    /// The projection only parses the wire format, so the group needs no
    /// relation to the engine under test.
    fn real_commit_wire_bytes() -> Vec<u8> {
        use openmls::group::{MlsGroupCreateConfig, PURE_PLAINTEXT_WIRE_FORMAT_POLICY};
        use openmls::prelude::{
            BasicCredential, Ciphersuite, CredentialWithKey, LeafNodeParameters,
        };
        use openmls_basic_credential::SignatureKeyPair;
        use tls_codec::Serialize as _;

        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        let provider = openmls_rust_crypto::OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
        let credential_with_key = CredentialWithKey {
            credential: BasicCredential::new(b"memo-test-member".to_vec()).into(),
            signature_key: signer.public().into(),
        };
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(ciphersuite)
            .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .build();
        let mut group =
            openmls::group::MlsGroup::new(&provider, &signer, &config, credential_with_key)
                .unwrap();
        let (commit_out, _welcome, _group_info) = group
            .self_update(&provider, &signer, LeafNodeParameters::default())
            .unwrap()
            .into_contents();
        commit_out.tls_serialize_detached().unwrap()
    }

    /// Regression for mdk#369: the idempotency short-circuit must compare the
    /// encoded payload, not just (group, epoch, state) — a second persist of
    /// the same id under a different `StoredMessagePayload` variant must
    /// overwrite, or a reader on the other processing path silently loses the
    /// record.
    #[test]
    fn same_key_persist_with_different_payload_variant_overwrites() {
        let (storage, engine, group_id) = engine_with_stored_group();
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

        // An own transport echo may re-enter through the raw ingest path while
        // an invite commit is still staged. It must not erase the
        // non-deliverable payload flavor and make the Welcome fetchable.
        let origin_commit_id = MessageId::new(b"origin-commit".to_vec());
        let mut staged_welcome = msg.clone();
        staged_welcome.envelope = TransportEnvelope::Welcome {
            recipient: cgka_traits::MemberId::new(vec![9; 32]),
        };
        engine
            .persist_stored_message_payload(
                staged_welcome.id.clone(),
                &group_id,
                EpochId(3),
                MessageState::Sent,
                StoredMessagePayload::staged_invite_welcome(
                    staged_welcome.clone(),
                    origin_commit_id.clone(),
                ),
                None,
            )
            .unwrap();
        engine
            .persist_transport_message_for_existing_group(
                &staged_welcome,
                &group_id,
                EpochId(3),
                MessageState::Sent,
            )
            .unwrap();
        let record = storage.get_message(&staged_welcome.id).unwrap();
        let stored = StoredMessagePayload::decode(&record.payload).unwrap();
        assert_eq!(
            stored.as_staged_invite_welcome().map(|(_, origin)| origin),
            Some(&origin_commit_id),
            "own echo must preserve staged Welcome ownership"
        );
    }

    #[test]
    fn canonical_content_and_processed_transport_id_admit_atomically() {
        let (storage, engine, first_group_id) = engine_with_stored_group();
        let mut second_group = storage.get_group(&first_group_id).unwrap();
        second_group.id = GroupId::new(vec![8u8; 16]);
        storage.put_group(&second_group).unwrap();
        let transport_id = MessageId::new(vec![0x91; 32]);
        storage
            .put_processed_transport_id(&first_group_id, &transport_id)
            .unwrap();
        let content = transport_message(b"new-canonical-content", b"wire-bytes");

        engine
            .persist_openmls_wire_message_with_processed_transport_id(
                &content,
                &second_group.id,
                EpochId(3),
                MessageState::Failed,
                &transport_id,
            )
            .expect_err("a transport id cannot be reassigned across groups");

        assert!(matches!(
            storage.get_message(&content.id),
            Err(cgka_traits::storage::StorageError::NotFound)
        ));
        assert!(storage.has_processed_transport_id(&transport_id).unwrap());
    }

    /// The commit-digest memo behind `deferred_peel_context_fingerprint`
    /// remembers a per-payload verdict keyed by `MessageId`. A same-id row
    /// overwritten under a different payload variant (RawTransport re-persisted
    /// as an OpenMLS-wire commit, the mdk#369 path above) must re-classify:
    /// a stale `None` verdict would hide the stored commit from the
    /// fingerprint and keep the deferred-peel gate armed.
    #[test]
    fn overwritten_payload_changes_peel_context_fingerprint() {
        let (_storage, mut engine, group_id) = engine_with_stored_group();
        let raw_row = transport_message(b"memo-overwritten-id", b"opaque-transport-bytes");
        engine
            .persist_transport_message(&raw_row, &group_id, EpochId(3), MessageState::Sent)
            .unwrap();

        let before = engine.deferred_peel_context_fingerprint(&group_id).unwrap();
        // Second call runs against the now-populated memo; it must agree.
        assert_eq!(
            before,
            engine.deferred_peel_context_fingerprint(&group_id).unwrap()
        );

        let commit_row = TransportMessage {
            payload: real_commit_wire_bytes(),
            ..raw_row
        };
        engine
            .persist_openmls_wire_message(&commit_row, &group_id, EpochId(3), MessageState::Sent)
            .unwrap();

        let after = engine.deferred_peel_context_fingerprint(&group_id).unwrap();
        assert_ne!(
            before, after,
            "a RawTransport row overwritten as an OpenMLS-wire commit must \
             re-classify instead of reusing the memoized non-commit verdict"
        );
    }
}
