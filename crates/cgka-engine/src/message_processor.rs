//! Inbound ingest and outbound send routing for [`Engine`].
//!
//! Inbound messages are peeled, classified, stored, and either applied or
//! buffered for convergence. Outbound intents are checked against local epoch
//! state and unresolved convergence inputs before any OpenMLS mutation.
//!
//! Classifiable stale ingest cases return
//! `Ok(IngestOutcome::Stale { .. })` with a typed `StaleReason`. `Err` is
//! reserved for storage, peeler, serialization, and OpenMLS failures.

use crate::engine::Engine;
use crate::fork_recovery::ForkResolution;
use crate::group_lifecycle::{self};
use crate::openmls_projection::{
    OpenMlsContentKind, project_mls_message, retained_anchor_epoch_from_snapshot_name,
};
use crate::provider::EngineOpenMlsProvider;
use cgka_traits::engine::{CommitOrderingKey, GroupEvent, SendIntent, SendResult};
use cgka_traits::engine_state::EpochState;
use cgka_traits::error::{EngineError, PeelerError};
use cgka_traits::ingest::{IngestOutcome, PeeledContent, StaleReason};
use cgka_traits::message::{MessageRecord, MessageState, StoredMessagePayload};
use cgka_traits::storage::{QueuedOutboundIntent, StorageError, StorageProvider};
use cgka_traits::transport::{EncryptedPayload, TransportEnvelope, TransportMessage};
use cgka_traits::types::{EpochId, GroupId, MemberId, MessageId};
use openmls::group::{MlsGroup, ProcessMessageError};
use openmls::prelude::{
    BasicCredential, ContentType, MlsMessageBodyIn, MlsMessageIn, MlsMessageOut,
    ProcessedMessageContent, Proposal, ProtocolMessage, Sender, ValidationError,
};
use sha2::{Digest, Sha256};
use tls_codec::{Deserialize as _, Serialize as _};

const MAX_CONVERGENCE_REPROCESSING_PASSES: usize = 16;

impl<S: StorageProvider> Engine<S> {
    /// Inbound pipeline. Never panics; every classifiable stale case returns
    /// a typed `StaleReason` inside `Ok(IngestOutcome::Stale { .. })`.
    pub(crate) async fn do_ingest(
        &mut self,
        msg: TransportMessage,
    ) -> Result<IngestOutcome, EngineError> {
        // Durable dedup / own-echo check. Storage is authoritative so a
        // restarted engine can classify replayed transport messages the same
        // way as a hot process.
        if let Some(outcome) = self.recorded_message_outcome(&msg.id)? {
            return Ok(outcome);
        }

        // In-memory fallback for messages produced before the durable record
        // is visible to this path.
        if self.seen_message_ids.contains(&msg.id) {
            return Ok(IngestOutcome::Stale {
                reason: StaleReason::AlreadySeen,
            });
        }
        if self.sent_message_ids.contains(&msg.id) {
            let group_id = record_group_id(&msg);
            self.persist_transport_message(&msg, &group_id, EpochId(0), MessageState::Sent)?;
            return Ok(IngestOutcome::Stale {
                reason: StaleReason::OwnEcho,
            });
        }

        let outcome = match &msg.envelope {
            TransportEnvelope::Welcome { recipient } => {
                self.ingest_welcome(&msg, recipient.clone()).await?
            }
            TransportEnvelope::GroupMessage { transport_group_id } => {
                self.ingest_group_message(&msg, transport_group_id.clone())
                    .await?
            }
        };

        if !matches!(outcome, IngestOutcome::Buffered { .. })
            && self.should_remember_ingested_message(&msg.id)?
        {
            self.seen_message_ids.insert(msg.id.clone());
        }
        Ok(outcome)
    }

    async fn ingest_welcome(
        &mut self,
        msg: &TransportMessage,
        recipient: MemberId,
    ) -> Result<IngestOutcome, EngineError> {
        // Welcome recipients are checked at the engine layer as well as the
        // transport layer. Test harnesses broadcast messages to all clients,
        // and multi-device or broadcast transports may break a one-pubkey-per-
        // member assumption. `NotForThisClient` also makes routing failures
        // easier to distinguish from decryption failures.
        if &recipient != self.identity.self_id() {
            self.persist_transport_message(
                msg,
                &GroupId::new(Vec::new()),
                EpochId(0),
                MessageState::Failed,
            )?;
            return Ok(IngestOutcome::Stale {
                reason: StaleReason::NotForThisClient,
            });
        }

        // Reuse the existing join_welcome machinery. Map its error shapes
        // to typed stale reasons where applicable.
        match self.do_join_welcome(msg.clone()).await {
            Ok(gid) => {
                self.persist_transport_message(msg, &gid, EpochId(0), MessageState::Processed)?;
                Ok(IngestOutcome::Processed)
            }
            Err(EngineError::Peeler(PeelerError::DecryptFailed)) => {
                self.persist_transport_message(
                    msg,
                    &GroupId::new(Vec::new()),
                    EpochId(0),
                    MessageState::Failed,
                )?;
                Ok(IngestOutcome::Stale {
                    reason: StaleReason::PeelFailed,
                })
            }
            Err(EngineError::Peeler(PeelerError::Malformed(_))) => {
                self.persist_transport_message(
                    msg,
                    &GroupId::new(Vec::new()),
                    EpochId(0),
                    MessageState::Failed,
                )?;
                Ok(IngestOutcome::Stale {
                    reason: StaleReason::PeelFailed,
                })
            }
            Err(other) => Err(other),
        }
    }

    async fn ingest_group_message(
        &mut self,
        msg: &TransportMessage,
        transport_group_id: Vec<u8>,
    ) -> Result<IngestOutcome, EngineError> {
        // Convention (0.1.0): transport_group_id bytes == MLS group_id bytes.
        // A real peeler/adapter may map via a local index; we'll carry that
        // indirection when the Nostr peeler lands.
        let group_id = GroupId::new(transport_group_id.clone());
        let mut pending_recovery: Option<(EpochId, CommitOrderingKey, CommitOrderingKey)> = None;

        loop {
            // Load MlsGroup from storage.
            let provider =
                EngineOpenMlsProvider::<S>::new(&self.crypto, self.storage.mls_storage());
            let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
            let mut mls_group = match MlsGroup::load(
                <EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::storage(
                    &provider,
                ),
                &mls_gid,
            ) {
                Ok(Some(g)) => g,
                Ok(None) => {
                    self.persist_transport_message(
                        msg,
                        &group_id,
                        EpochId(0),
                        MessageState::Retryable,
                    )?;
                    return Ok(IngestOutcome::Stale {
                        reason: StaleReason::UnknownGroup,
                    });
                }
                Err(e) => {
                    return Err(EngineError::Backend(format!("load: {e:?}")));
                }
            };

            // Must be ingestible in current EpochState. PendingPublish / Merging
            // store the transport message for deterministic replay once the
            // group returns to Stable.
            let current_epoch = EpochId(mls_group.epoch().as_u64());
            if !self.epoch_manager.can_ingest(&group_id) {
                self.persist_transport_message(
                    msg,
                    &group_id,
                    current_epoch,
                    MessageState::Retryable,
                )?;
                return Ok(IngestOutcome::Buffered {
                    group_id,
                    epoch: current_epoch,
                });
            }

            // Peel.
            let ctx = group_lifecycle::build_group_context_snapshot(&mls_group, &provider)?;
            let peeled = match self.peeler.peel_group_message(msg, &ctx).await {
                Ok(p) => p,
                Err(PeelerError::DecryptFailed) => {
                    if let Some(peeled) = self
                        .try_peel_group_message_from_available_snapshots(
                            msg,
                            &group_id,
                            current_epoch,
                        )
                        .await?
                    {
                        peeled
                    } else {
                        self.persist_transport_message(
                            msg,
                            &group_id,
                            current_epoch,
                            MessageState::PeelDeferred,
                        )?;
                        return Ok(IngestOutcome::Stale {
                            reason: StaleReason::PeelFailed,
                        });
                    }
                }
                Err(PeelerError::StaleEpoch { .. }) => {
                    if let Some(peeled) = self
                        .try_peel_group_message_from_available_snapshots(
                            msg,
                            &group_id,
                            current_epoch,
                        )
                        .await?
                    {
                        peeled
                    } else {
                        self.persist_transport_message(
                            msg,
                            &group_id,
                            current_epoch,
                            MessageState::Failed,
                        )?;
                        return Ok(IngestOutcome::Stale {
                            reason: StaleReason::PeelFailed,
                        });
                    }
                }
                Err(e) => return Err(EngineError::Peeler(e)),
            };
            let mls_bytes = match peeled.content {
                PeeledContent::MlsMessage { bytes } => bytes,
                PeeledContent::Welcome { .. } => {
                    self.persist_transport_message(
                        msg,
                        &group_id,
                        current_epoch,
                        MessageState::Failed,
                    )?;
                    self.update_stored_message_state(&msg.id, MessageState::Failed)?;
                    return Ok(IngestOutcome::Stale {
                        reason: StaleReason::PeelFailed,
                    });
                }
            };
            let openmls_msg = TransportMessage {
                payload: mls_bytes.clone(),
                ..msg.clone()
            };

            // Parse into ProtocolMessage. Grab its epoch before process_message
            // consumes it — we need it for the fork-detection branch below.
            let msg_in = MlsMessageIn::tls_deserialize_exact(mls_bytes.as_slice())
                .map_err(|e| EngineError::Serialize(format!("message deserialize: {e:?}")))?;
            let body = msg_in.extract();
            let proto: ProtocolMessage = match body {
                MlsMessageBodyIn::PrivateMessage(p) => p.into(),
                MlsMessageBodyIn::PublicMessage(p) => p.into(),
                _ => {
                    self.persist_transport_message(
                        &openmls_msg,
                        &group_id,
                        current_epoch,
                        MessageState::Failed,
                    )?;
                    return Ok(IngestOutcome::Stale {
                        reason: StaleReason::PeelFailed,
                    });
                }
            };

            let msg_epoch = EpochId(proto.epoch().as_u64());
            let msg_content_type = proto.content_type();
            if pending_recovery.is_none()
                && msg_content_type == ContentType::Commit
                && msg_epoch >= current_epoch
            {
                let now_ms = self.convergence_now_ms();
                self.buffer_openmls_convergence_message(&group_id, openmls_msg.clone(), now_ms)
                    .map_err(|e| EngineError::Backend(format!("buffer convergence: {e}")))?;
                let result = self
                    .converge_stored_openmls_messages(&group_id, now_ms)
                    .map_err(|e| EngineError::Backend(format!("converge: {e}")))?;
                return Ok(convergence_ingest_outcome(
                    &result,
                    msg,
                    group_id,
                    current_epoch,
                ));
            }
            if msg_content_type == ContentType::Application && msg_epoch > current_epoch {
                let now_ms = self.convergence_now_ms();
                self.buffer_openmls_convergence_message(&group_id, openmls_msg.clone(), now_ms)
                    .map_err(|e| EngineError::Backend(format!("buffer convergence: {e}")))?;
                let result = self
                    .converge_stored_openmls_messages(&group_id, now_ms)
                    .map_err(|e| EngineError::Backend(format!("converge: {e}")))?;
                return Ok(convergence_ingest_outcome(
                    &result,
                    msg,
                    group_id,
                    current_epoch,
                ));
            }

            self.persist_openmls_wire_message(
                &openmls_msg,
                &group_id,
                current_epoch,
                MessageState::Created,
            )?;

            // Process via MLS.
            let processed = match mls_group.process_message(&provider, proto) {
                Ok(p) => p,
                Err(ProcessMessageError::ValidationError(ValidationError::WrongEpoch)) => {
                    let current = EpochId(mls_group.epoch().as_u64());

                    // Same-epoch commit race. If our local history already
                    // advanced from the inbound commit's source epoch, ask
                    // ForkRecoveryManager whether the inbound branch wins
                    // and should be replayed from the pre-commit snapshot.
                    if msg_content_type == ContentType::Commit
                        && self.epoch_manager.we_committed_from(&group_id, msg_epoch)
                        && current > msg_epoch
                    {
                        match self.resolve_fork_candidate(
                            &group_id,
                            msg_epoch,
                            mls_bytes.as_slice(),
                        )? {
                            ForkResolution::CandidateWins {
                                winner,
                                invalidated,
                                invalidated_storage_id: _,
                            } => {
                                pending_recovery = Some((msg_epoch, winner, invalidated));
                                continue;
                            }
                            ForkResolution::IncumbentWins => {
                                self.update_stored_message_state(
                                    &msg.id,
                                    MessageState::EpochInvalidated,
                                )?;
                                return Ok(IngestOutcome::Stale {
                                    reason: StaleReason::AlreadyAtEpoch { current, msg_epoch },
                                });
                            }
                            ForkResolution::MissingSnapshot => {
                                self.epoch_manager.detect_fork(&group_id, vec![]);
                                self.update_stored_message_state(
                                    &msg.id,
                                    MessageState::EpochInvalidated,
                                )?;
                                return Err(EngineError::ForkedEpoch {
                                    group_id: group_id.clone(),
                                    last_stable: msg_epoch,
                                    conflicting_epoch: current,
                                });
                            }
                        }
                    }

                    self.update_stored_message_state(&msg.id, MessageState::Failed)?;
                    return Ok(IngestOutcome::Stale {
                        reason: StaleReason::AlreadyAtEpoch { current, msg_epoch },
                    });
                }
                Err(e) => {
                    self.update_stored_message_state(&msg.id, MessageState::Retryable)?;
                    return Err(EngineError::Backend(format!("process_message: {e:?}")));
                }
            };

            // Classify content.
            let sender_id = member_id_of_sender(processed.sender(), &mls_group);
            return match processed.into_content() {
                ProcessedMessageContent::ApplicationMessage(bytes) => {
                    self.events_buf.push_back(GroupEvent::MessageReceived {
                        group_id: group_id.clone(),
                        sender: sender_id.unwrap_or_else(|| MemberId::new(Vec::new())),
                        payload: bytes.into_bytes(),
                    });
                    self.update_stored_message_state(&msg.id, MessageState::Processed)?;
                    Ok(IngestOutcome::Processed)
                }
                ProcessedMessageContent::StagedCommitMessage(staged) => {
                    let before = EpochId(mls_group.epoch().as_u64());
                    let recovery_snapshot =
                        self.fork_recovery
                            .create_snapshot(&self.storage, &group_id, before)?;
                    let before_members = group_lifecycle::marmot_members(&mls_group);
                    let added: Vec<MemberId> = staged
                        .add_proposals()
                        .filter_map(|p| {
                            let leaf = p.add_proposal().key_package().leaf_node();
                            BasicCredential::try_from(leaf.credential().clone())
                                .ok()
                                .map(|bc| MemberId::new(bc.identity().to_vec()))
                        })
                        .collect();
                    self.retain_current_epoch_snapshot_for_group(&group_id)?;
                    // Extract capabilities from Add proposals before the
                    // staged commit is consumed by merge.
                    crate::capability_manager::cache_from_staged_commit(
                        &self.storage,
                        &group_id,
                        &staged,
                    )?;
                    mls_group
                        .merge_staged_commit(&provider, *staged)
                        .map_err(|e| EngineError::Backend(format!("merge_staged_commit: {e:?}")))?;
                    let after = EpochId(mls_group.epoch().as_u64());
                    let after_members = group_lifecycle::marmot_members(&mls_group);
                    let after_ids: std::collections::HashSet<MemberId> =
                        after_members.iter().map(|m| m.id.clone()).collect();
                    let removed: Vec<MemberId> = before_members
                        .into_iter()
                        .filter_map(|m| (!after_ids.contains(&m.id)).then_some(m.id))
                        .collect();

                    // Update our per-group state machine + storage mirror.
                    self.epoch_manager.set_stable(group_id.clone(), after);
                    self.record_applied_commit_for_recovery(
                        group_id.clone(),
                        before,
                        msg.id.clone(),
                        mls_bytes.as_slice(),
                        recovery_snapshot,
                    );
                    if let Ok(mut g) = self.storage.get_group(&group_id) {
                        g.epoch = after;
                        g.members = after_members;
                        self.storage.put_group(&g)?;
                    }
                    // Refresh self-cache since our own leaf may have been
                    // updated by the commit's path.
                    crate::capability_manager::cache_self_capabilities(
                        &self.storage,
                        &group_id,
                        &mls_group,
                        self.identity.self_id(),
                    )?;

                    if let Some((source_epoch, winner, invalidated)) = pending_recovery.take() {
                        self.events_buf.push_back(GroupEvent::ForkRecovered {
                            group_id: group_id.clone(),
                            source_epoch,
                            recovered_epoch: after,
                            winner,
                            invalidated,
                        });
                    }
                    self.events_buf.push_back(GroupEvent::EpochChanged {
                        group_id: group_id.clone(),
                        from: before,
                        to: after,
                    });
                    for m in added {
                        // Reconstruct a Member — credential bytes aren't needed
                        // for the event consumer since id is authoritative.
                        self.events_buf.push_back(GroupEvent::MemberAdded {
                            group_id: group_id.clone(),
                            member: cgka_traits::group::Member {
                                id: m,
                                credential: vec![],
                            },
                        });
                    }
                    for m in removed {
                        self.events_buf.push_back(GroupEvent::MemberRemoved {
                            group_id: group_id.clone(),
                            member: m,
                        });
                    }
                    self.update_stored_message_state(&msg.id, MessageState::Processed)?;
                    Ok(IngestOutcome::Processed)
                }
                ProcessedMessageContent::ProposalMessage(queued) => {
                    // Ask the auto-committer policy whether we should commit
                    // this proposal. OpenMLS does not auto-enqueue processed
                    // proposals, so store it before attempting to commit the
                    // pending proposal queue.
                    let decision = crate::auto_committer::decide(&mls_group, &queued);
                    let auto_removed = match queued.proposal() {
                        Proposal::Remove(r) => member_id_at_leaf(&mls_group, r.removed())
                            .into_iter()
                            .collect(),
                        Proposal::SelfRemove => member_id_of_sender(queued.sender(), &mls_group)
                            .into_iter()
                            .collect(),
                        _ => Vec::new(),
                    };
                    mls_group
                    .store_pending_proposal(
                        <EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::storage(
                            &provider,
                        ),
                        *queued,
                    )
                    .map_err(|e| EngineError::Backend(format!("store_pending: {e:?}")))?;
                    if matches!(decision, crate::auto_committer::AutoCommitDecision::Commit) {
                        // Fork-detection bookkeeping — we're committing FROM
                        // the current pre-commit epoch.
                        let pre_commit_epoch = EpochId(mls_group.epoch().as_u64());
                        let recovery_snapshot = self.fork_recovery.create_snapshot(
                            &self.storage,
                            &group_id,
                            pre_commit_epoch,
                        )?;
                        self.epoch_manager
                            .record_committed_from(&group_id, pre_commit_epoch);
                        let pre_commit_ctx =
                            group_lifecycle::build_group_context_snapshot(&mls_group, &provider)?;
                        let (commit_out, _welcome_opt, _gi) = mls_group
                            .commit_to_pending_proposals(&provider, &self.identity.signer)
                            .map_err(|e| EngineError::Backend(format!("auto_commit: {e:?}")))?;
                        let commit_bytes = commit_out
                            .tls_serialize_detached()
                            .map_err(|e| EngineError::Serialize(format!("{e:?}")))?;
                        let wrapped = self
                            .peeler
                            .wrap_group_message(
                                &EncryptedPayload {
                                    ciphertext: commit_bytes.clone(),
                                    aad: vec![],
                                },
                                &pre_commit_ctx,
                            )
                            .await
                            .map_err(EngineError::Peeler)?;
                        let wrapped = TransportMessage {
                            envelope: TransportEnvelope::GroupMessage {
                                transport_group_id: group_id.as_slice().to_vec(),
                            },
                            ..wrapped
                        };
                        self.retain_current_epoch_snapshot_for_group(&group_id)?;
                        mls_group
                            .merge_pending_commit(&provider)
                            .map_err(|e| EngineError::Backend(format!("merge_pending: {e:?}")))?;

                        let new_epoch = EpochId(mls_group.epoch().as_u64());
                        let prior = EpochId(new_epoch.0.saturating_sub(1));

                        self.record_sent_openmls_message(
                            &wrapped,
                            commit_bytes.as_slice(),
                            &group_id,
                            pre_commit_epoch,
                        )?;
                        self.record_applied_commit_for_recovery(
                            group_id.clone(),
                            pre_commit_epoch,
                            wrapped.id.clone(),
                            &commit_bytes,
                            recovery_snapshot,
                        );
                        self.auto_publish_buf.push_back(wrapped);

                        self.epoch_manager.set_stable(group_id.clone(), new_epoch);
                        if let Ok(mut g) = self.storage.get_group(&group_id) {
                            g.epoch = new_epoch;
                            g.members = group_lifecycle::marmot_members(&mls_group);
                            self.storage.put_group(&g)?;
                        }
                        crate::capability_manager::cache_self_capabilities(
                            &self.storage,
                            &group_id,
                            &mls_group,
                            self.identity.self_id(),
                        )?;

                        self.events_buf.push_back(GroupEvent::EpochChanged {
                            group_id: group_id.clone(),
                            from: prior,
                            to: new_epoch,
                        });
                        for member in auto_removed {
                            self.events_buf.push_back(GroupEvent::MemberRemoved {
                                group_id: group_id.clone(),
                                member,
                            });
                        }
                    }
                    Ok(IngestOutcome::Processed)
                }
                ProcessedMessageContent::ExternalJoinProposalMessage(_) => {
                    self.update_stored_message_state(&msg.id, MessageState::Processed)?;
                    Ok(IngestOutcome::Processed)
                }
            };
        }
    }

    pub(crate) async fn do_send(&mut self, intent: SendIntent) -> Result<SendResult, EngineError> {
        let group_id = send_intent_group_id(&intent).clone();
        self.retry_deferred_peels(&group_id).await?;
        if self.should_queue_outbound_intent(&group_id)? {
            return self.queue_outbound_intent(group_id, intent);
        }

        self.do_send_ready(intent).await
    }

    async fn do_send_ready(&mut self, intent: SendIntent) -> Result<SendResult, EngineError> {
        match intent {
            SendIntent::AppMessage { group_id, payload } => {
                self.do_send_app_message(group_id, payload).await
            }
            SendIntent::Invite {
                group_id,
                key_packages,
            } => self.do_send_invite(group_id, key_packages).await,
            SendIntent::Leave { group_id } => self.do_send_leave(group_id).await,
            SendIntent::UpdateGroupData {
                group_id,
                name,
                description,
            } => {
                self.do_send_update_group_data(group_id, name, description)
                    .await
            }
        }
    }

    pub async fn converge_and_drain_queued_outbound_intents(
        &mut self,
        group_id: &GroupId,
        now_ms: u64,
    ) -> Result<Vec<SendResult>, EngineError> {
        if let Some(state) = self.epoch_manager.state(group_id)
            && !matches!(state, EpochState::Stable { .. })
        {
            return Ok(Vec::new());
        }

        if !self
            .advance_convergence_inputs_until_stable(group_id, now_ms)
            .await?
        {
            return Ok(Vec::new());
        }

        let queued = self.storage.list_queued_outbound_intents(group_id)?;
        let mut drained = Vec::new();
        for record in queued {
            if !self
                .advance_convergence_inputs_until_stable(group_id, now_ms)
                .await?
            {
                break;
            }
            let result = self.do_send_ready(record.intent.clone()).await?;
            self.storage.delete_queued_outbound_intent(&record.id)?;
            let pauses_for_pending_publish = matches!(result, SendResult::GroupEvolution { .. });
            drained.push(result);
            if pauses_for_pending_publish {
                break;
            }
        }
        Ok(drained)
    }

    fn should_queue_outbound_intent(&mut self, group_id: &GroupId) -> Result<bool, EngineError> {
        if let Some(state) = self.epoch_manager.state(group_id)
            && !matches!(state, EpochState::Stable { .. })
        {
            return Ok(false);
        }

        if !self.has_unresolved_convergence_inputs(group_id)? {
            return Ok(false);
        }

        let now_ms = self.convergence_now_ms();
        let result = self
            .converge_stored_openmls_messages(group_id, now_ms)
            .map_err(|e| EngineError::Backend(format!("converge before send: {e}")))?;
        if result.sync_state != crate::canonicalization::SyncState::Stable {
            return Ok(true);
        }

        self.has_unresolved_convergence_inputs(group_id)
    }

    /// Drive stored OpenMLS inputs to stability, retrying raw transport
    /// records after each stable branch selection. This is the branch-aware
    /// path for future-epoch application messages and deeper branch commits:
    /// opaque transport bytes do not participate in canonicalization until a
    /// selected branch gives the peeler the epoch context needed to unwrap
    /// them.
    pub async fn advance_convergence_inputs_until_stable(
        &mut self,
        group_id: &GroupId,
        now_ms: u64,
    ) -> Result<bool, EngineError> {
        for _ in 0..MAX_CONVERGENCE_REPROCESSING_PASSES {
            if self.has_unresolved_convergence_inputs(group_id)? {
                let result = self
                    .converge_stored_openmls_messages(group_id, now_ms)
                    .map_err(|e| EngineError::Backend(format!("converge inputs: {e}")))?;
                if result.sync_state != crate::canonicalization::SyncState::Stable {
                    return Ok(false);
                }
                if self.has_unresolved_convergence_inputs(group_id)? {
                    return Ok(false);
                }
            }

            if self.retry_deferred_peels(group_id).await? == 0 {
                return Ok(!self.has_unresolved_convergence_inputs(group_id)?);
            }
        }

        Ok(false)
    }

    fn has_unresolved_convergence_inputs(&self, group_id: &GroupId) -> Result<bool, EngineError> {
        let anchor = match self.storage.get_group(group_id) {
            Ok(group) => {
                let policy = self
                    .convergence_policy_for_group(group_id)
                    .map_err(|e| EngineError::Backend(format!("load convergence policy: {e}")))?;
                group
                    .epoch
                    .0
                    .saturating_sub(policy.convergence.max_rewind_commits)
            }
            Err(StorageError::NotFound) => return Ok(false),
            Err(e) => return Err(EngineError::Storage(e)),
        };
        let records = self.storage.list_messages(group_id, EpochId(anchor))?;
        for record in records {
            if !matches!(
                record.state,
                MessageState::Created | MessageState::Retryable
            ) {
                continue;
            }
            let Ok(stored_payload) = StoredMessagePayload::decode(&record.payload) else {
                return Ok(true);
            };
            let Some(message) = stored_payload.as_openmls_wire() else {
                return Ok(true);
            };
            let Ok(projection) = project_mls_message(&message.payload) else {
                return Ok(true);
            };
            if matches!(
                projection.kind,
                OpenMlsContentKind::Commit
                    | OpenMlsContentKind::Proposal
                    | OpenMlsContentKind::Application
            ) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub async fn retry_deferred_peels(&mut self, group_id: &GroupId) -> Result<usize, EngineError> {
        if let Some(state) = self.epoch_manager.state(group_id)
            && !matches!(state, EpochState::Stable { .. })
        {
            return Ok(0);
        }

        let records = self.storage.list_messages(group_id, EpochId(0))?;
        let mut progressed = 0;
        for record in records {
            if record.state != MessageState::PeelDeferred {
                continue;
            }
            let stored_payload = StoredMessagePayload::decode(&record.payload)
                .map_err(|e| EngineError::Serialize(format!("{e:?}")))?;
            let Some(msg) = stored_payload.as_raw_transport().cloned() else {
                continue;
            };
            match self
                .ingest_group_message(&msg, group_id.as_slice().to_vec())
                .await
            {
                Ok(IngestOutcome::Stale {
                    reason: StaleReason::PeelFailed,
                }) => {}
                Ok(IngestOutcome::Buffered { .. } | IngestOutcome::Processed) => {
                    progressed += 1;
                }
                Ok(IngestOutcome::Stale { .. }) => {
                    progressed += 1;
                }
                Err(EngineError::ForkedEpoch {
                    group_id,
                    last_stable,
                    conflicting_epoch,
                }) => {
                    self.update_stored_message_state(&record.id, MessageState::EpochInvalidated)?;
                    return Err(EngineError::ForkedEpoch {
                        group_id,
                        last_stable,
                        conflicting_epoch,
                    });
                }
                Err(e) => {
                    self.update_stored_message_state(&record.id, MessageState::Retryable)?;
                    return Err(e);
                }
            }
        }
        Ok(progressed)
    }

    fn queue_outbound_intent(
        &mut self,
        group_id: GroupId,
        intent: SendIntent,
    ) -> Result<SendResult, EngineError> {
        let created_at_ms = self.convergence_now_ms();
        let existing_count = self.storage.list_queued_outbound_intents(&group_id)?.len() as u64;
        let intent_bytes =
            serde_json::to_vec(&intent).map_err(|e| EngineError::Serialize(format!("{e:?}")))?;
        let mut hasher = Sha256::new();
        hasher.update(b"marmot-queued-outbound-intent/v1");
        hasher.update(group_id.as_slice());
        hasher.update(self.identity.self_id().as_slice());
        hasher.update(created_at_ms.to_be_bytes());
        hasher.update(existing_count.to_be_bytes());
        hasher.update(&intent_bytes);
        let intent_id = MessageId::new(hasher.finalize().to_vec());
        self.storage
            .put_queued_outbound_intent(&QueuedOutboundIntent {
                id: intent_id.clone(),
                group_id: group_id.clone(),
                intent,
                created_at_ms,
            })?;
        Ok(SendResult::Queued {
            group_id,
            intent_id,
        })
    }

    async fn do_send_invite(
        &mut self,
        group_id: GroupId,
        key_packages: Vec<cgka_traits::engine::KeyPackage>,
    ) -> Result<SendResult, EngineError> {
        // Load group + require Stable.
        let provider = EngineOpenMlsProvider::<S>::new(&self.crypto, self.storage.mls_storage());
        let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
        let mut mls_group = MlsGroup::load(
            <EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::storage(&provider),
            &mls_gid,
        )
        .map_err(|e| EngineError::Backend(format!("load: {e:?}")))?
        .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;

        if let Some(state) = self.epoch_manager.state(&group_id)
            && !matches!(state, EpochState::Stable { .. })
        {
            return Err(EngineError::InvalidTransition(
                cgka_traits::engine_state::InvalidTransition {
                    from: state.name(),
                    to: "Invite",
                    reason: "invite requires Stable",
                },
            ));
        }

        // Validate capabilities (same rule as create_group — see Risk #1
        // capability doc).
        let existing = self.storage.get_group(&group_id)?;
        let required = existing.required_capabilities.clone();
        let mut parsed_kps = Vec::with_capacity(key_packages.len());
        for kp in &key_packages {
            let parsed = self.parse_key_package(kp)?;
            let had = crate::capabilities::capabilities_of_key_package(&parsed);
            let missing = required.missing_from(&had);
            if !missing.is_empty() {
                return Err(EngineError::MissingRequiredCapabilities { required, had });
            }
            parsed_kps.push(parsed);
        }

        // Record the pre-commit epoch so a later same-epoch commit can be
        // compared against this locally produced branch.
        let pre_commit_epoch = EpochId(mls_group.epoch().as_u64());
        let recovery_snapshot =
            self.fork_recovery
                .create_snapshot(&self.storage, &group_id, pre_commit_epoch)?;
        self.epoch_manager
            .record_committed_from(&group_id, pre_commit_epoch);
        let pre_commit_ctx =
            crate::group_lifecycle::build_group_context_snapshot(&mls_group, &provider)?;

        // Stage the add-members commit. Publish-before-apply keeps
        // `mls_group` at the pre-commit epoch with the staged commit attached.
        // Wrap reads exporter from the still-current (pre-stage) epoch,
        // which is the right key for receivers to derive when peeling
        // (they're at the same pre-commit epoch when they decrypt the
        // wrap; only after they apply the inner commit do they advance).
        let (commit_out, welcome_out, _gi) = mls_group
            .add_members(&provider, &self.identity.signer, &parsed_kps)
            .map_err(|e| EngineError::Backend(format!("add_members: {e:?}")))?;

        let commit_bytes = commit_out
            .tls_serialize_detached()
            .map_err(|e| EngineError::Serialize(format!("{e:?}")))?;
        let welcome_bytes = welcome_out
            .tls_serialize_detached()
            .map_err(|e| EngineError::Serialize(format!("{e:?}")))?;

        let commit_msg = self
            .peeler
            .wrap_group_message(
                &EncryptedPayload {
                    ciphertext: commit_bytes.clone(),
                    aad: vec![],
                },
                &pre_commit_ctx,
            )
            .await
            .map_err(EngineError::Peeler)?;
        let commit_msg = TransportMessage {
            envelope: TransportEnvelope::GroupMessage {
                transport_group_id: group_id.as_slice().to_vec(),
            },
            ..commit_msg
        };
        self.record_sent_openmls_message(
            &commit_msg,
            commit_bytes.as_slice(),
            &group_id,
            pre_commit_epoch,
        )?;

        let mut welcomes = Vec::with_capacity(parsed_kps.len());
        for kp in &parsed_kps {
            let recipient = {
                let bc = BasicCredential::try_from(kp.leaf_node().credential().clone())
                    .map_err(|e| EngineError::Backend(format!("credential: {e:?}")))?;
                MemberId::new(bc.identity().to_vec())
            };
            let wrapped = self
                .peeler
                .wrap_welcome(
                    &EncryptedPayload {
                        ciphertext: welcome_bytes.clone(),
                        aad: vec![],
                    },
                    &recipient,
                )
                .await
                .map_err(EngineError::Peeler)?;
            self.record_sent_message(&wrapped, &group_id, pre_commit_epoch)?;
            welcomes.push(wrapped);
        }

        // Cache invitees' capabilities NOW so `feature_status` reflects the
        // pending invite immediately. Update the Marmot record with the
        // projected post-merge member list — `members()` and
        // `feature_status` walk this list, and users expect the API to
        // reflect "what I just asked for" while the publish is pending.
        // Epoch stays at the pre-merge value; that updates on confirm.
        // On `publish_failed`, the engine re-derives from the (still-
        // unmerged) MLS state, which naturally drops the projection.
        crate::capability_manager::cache_from_key_packages(&self.storage, &group_id, &parsed_kps)?;
        let mut group_record = existing;
        group_record.members =
            crate::group_lifecycle::projected_members_with_pending(&mls_group, &parsed_kps)?;
        self.storage.put_group(&group_record)?;

        // State: begin pending at the projected new epoch via EpochManager.
        // The MLS group is still at the pre-commit epoch, so the projected
        // post-merge epoch is +1.
        let prior_epoch = EpochId(mls_group.epoch().as_u64());
        let new_epoch = EpochId(prior_epoch.0 + 1);
        let pending_ref = self.epoch_manager.next_pending_ref();
        let staged =
            cgka_traits::engine_state::StagedCommitHandle::from_bytes(group_id.as_slice().to_vec());
        self.epoch_manager.begin_pending(
            group_id.clone(),
            prior_epoch,
            new_epoch,
            staged,
            pending_ref,
            crate::epoch_manager::PendingKind::GroupEvolution,
        )?;
        self.track_pending_commit_for_recovery(
            pending_ref,
            group_id.clone(),
            prior_epoch,
            commit_msg.id.clone(),
            &commit_bytes,
            recovery_snapshot,
        );

        Ok(SendResult::GroupEvolution {
            msg: commit_msg,
            welcomes,
            pending: pending_ref,
        })
    }

    async fn do_send_leave(&mut self, group_id: GroupId) -> Result<SendResult, EngineError> {
        // MIP-03 SelfRemove only. The legacy Remove-self flow is not exposed
        // by this engine.
        let provider = EngineOpenMlsProvider::<S>::new(&self.crypto, self.storage.mls_storage());
        let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
        let mut mls_group = MlsGroup::load(
            <EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::storage(&provider),
            &mls_gid,
        )
        .map_err(|e| EngineError::Backend(format!("load: {e:?}")))?
        .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;

        // MIP-03 §149 admin-cannot-self-remove guard. If the leaver is an
        // admin AND they're the only admin, refuse with a typed error so
        // the caller can prompt for admin transfer.
        let self_pubkey = crate::group_data::admin_pubkey_from_member_id(self.identity.self_id())?;
        let admins = crate::group_data::admins_of_group(&mls_group)?;
        let i_am_admin = admins.iter().any(|k| k == &self_pubkey);
        let only_admin = i_am_admin && admins.len() == 1;
        if only_admin {
            return Err(EngineError::AdminCannotSelfRemove {
                group_id: group_id.clone(),
            });
        }

        let proposal = mls_group
            .leave_group_via_self_remove(&provider, &self.identity.signer)
            .map_err(|e| EngineError::Backend(format!("self_remove: {e:?}")))?;

        let bytes = proposal
            .tls_serialize_detached()
            .map_err(|e| EngineError::Serialize(format!("{e:?}")))?;

        let ctx = crate::group_lifecycle::build_group_context_snapshot(&mls_group, &provider)?;
        let wrapped = self
            .peeler
            .wrap_group_message(
                &EncryptedPayload {
                    ciphertext: bytes.clone(),
                    aad: vec![],
                },
                &ctx,
            )
            .await
            .map_err(EngineError::Peeler)?;
        let wrapped = TransportMessage {
            envelope: TransportEnvelope::GroupMessage {
                transport_group_id: group_id.as_slice().to_vec(),
            },
            ..wrapped
        };
        self.record_sent_openmls_message(
            &wrapped,
            bytes.as_slice(),
            &group_id,
            EpochId(mls_group.epoch().as_u64()),
        )?;

        // SelfRemove is a proposal — the leaver's epoch doesn't advance
        // until some other member (per MIP-03 §144, the lowest-index
        // remaining in our implementation) commits it. No state transition
        // on the leaver's side here.
        Ok(SendResult::Proposal { msg: wrapped })
    }

    async fn do_send_app_message(
        &mut self,
        group_id: GroupId,
        payload: Vec<u8>,
    ) -> Result<SendResult, EngineError> {
        let provider = EngineOpenMlsProvider::<S>::new(&self.crypto, self.storage.mls_storage());
        let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
        let mut mls_group = MlsGroup::load(
            <EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::storage(&provider),
            &mls_gid,
        )
        .map_err(|e| EngineError::Backend(format!("load: {e:?}")))?
        .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;

        // Direct sending still requires Stable after convergence gating.
        if let Some(state) = self.epoch_manager.state(&group_id)
            && !matches!(state, EpochState::Stable { .. })
        {
            return Err(EngineError::InvalidTransition(
                cgka_traits::engine_state::InvalidTransition {
                    from: state.name(),
                    to: "send",
                    reason: "send requires Stable",
                },
            ));
        }

        let out: MlsMessageOut = mls_group
            .create_message(&provider, &self.identity.signer, &payload)
            .map_err(|e| EngineError::Backend(format!("create_message: {e:?}")))?;
        let out_bytes = out
            .tls_serialize_detached()
            .map_err(|e| EngineError::Serialize(format!("{e:?}")))?;

        let ctx = group_lifecycle::build_group_context_snapshot(&mls_group, &provider)?;
        let wrapped = self
            .peeler
            .wrap_group_message(
                &EncryptedPayload {
                    ciphertext: out_bytes.clone(),
                    aad: vec![],
                },
                &ctx,
            )
            .await
            .map_err(EngineError::Peeler)?;

        let wrapped = TransportMessage {
            envelope: TransportEnvelope::GroupMessage {
                transport_group_id: group_id.as_slice().to_vec(),
            },
            ..wrapped
        };
        self.record_sent_openmls_message(
            &wrapped,
            out_bytes.as_slice(),
            &group_id,
            EpochId(mls_group.epoch().as_u64()),
        )?;

        Ok(SendResult::ApplicationMessage { msg: wrapped })
    }
}

fn member_id_of_sender(sender: &Sender, group: &MlsGroup) -> Option<MemberId> {
    match sender {
        Sender::Member(leaf_idx) => member_id_at_leaf(group, *leaf_idx),
        _ => None,
    }
}

fn member_id_at_leaf(
    group: &MlsGroup,
    leaf_idx: openmls::prelude::LeafNodeIndex,
) -> Option<MemberId> {
    let member = group.member_at(leaf_idx)?;
    let basic = BasicCredential::try_from(member.credential).ok()?;
    Some(MemberId::new(basic.identity().to_vec()))
}

fn record_group_id(msg: &TransportMessage) -> GroupId {
    match &msg.envelope {
        TransportEnvelope::GroupMessage { transport_group_id } => {
            GroupId::new(transport_group_id.clone())
        }
        TransportEnvelope::Welcome { .. } => GroupId::new(Vec::new()),
    }
}

fn send_intent_group_id(intent: &SendIntent) -> &GroupId {
    match intent {
        SendIntent::AppMessage { group_id, .. }
        | SendIntent::Invite { group_id, .. }
        | SendIntent::Leave { group_id }
        | SendIntent::UpdateGroupData { group_id, .. } => group_id,
    }
}

fn convergence_ingest_outcome(
    result: &crate::canonicalization::CanonicalizationResult,
    msg: &TransportMessage,
    group_id: GroupId,
    epoch: EpochId,
) -> IngestOutcome {
    let message_id = hex::encode(msg.id.as_slice());
    let accepted = result
        .accepted_commits
        .iter()
        .chain(&result.accepted_proposals)
        .chain(&result.accepted_app_messages)
        .any(|accepted| accepted == &message_id);

    if result.sync_state == crate::canonicalization::SyncState::Stable && accepted {
        IngestOutcome::Processed
    } else {
        IngestOutcome::Buffered { group_id, epoch }
    }
}

impl<S: StorageProvider> Engine<S> {
    fn recorded_message_outcome(
        &mut self,
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

    fn should_remember_ingested_message(&self, id: &MessageId) -> Result<bool, EngineError> {
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

    async fn try_peel_group_message_from_available_snapshots(
        &self,
        msg: &TransportMessage,
        group_id: &GroupId,
        current_epoch: EpochId,
    ) -> Result<Option<cgka_traits::ingest::PeeledMessage>, EngineError> {
        let snapshots = self.available_past_peel_snapshots(group_id)?;
        for (source_epoch, snapshot_name) in snapshots {
            if source_epoch >= current_epoch {
                continue;
            }
            let restore_snapshot = format!(
                "peel-restore-{}-{}-{}",
                hex::encode(group_id.as_slice()),
                current_epoch.0,
                hex::encode(msg.id.as_slice())
            );
            self.storage
                .create_group_snapshot(group_id, &restore_snapshot)?;
            let ctx = match self.context_from_group_snapshot(group_id, &snapshot_name) {
                Ok(ctx) => ctx,
                Err(err) => {
                    self.restore_after_snapshot_peel(group_id, &restore_snapshot)?;
                    return Err(err);
                }
            };
            let peeled = self.peeler.peel_group_message(msg, &ctx).await;
            self.restore_after_snapshot_peel(group_id, &restore_snapshot)?;
            match peeled {
                Ok(peeled) => return Ok(Some(peeled)),
                Err(PeelerError::DecryptFailed | PeelerError::StaleEpoch { .. }) => continue,
                Err(err) => return Err(EngineError::Peeler(err)),
            }
        }
        Ok(None)
    }

    fn available_past_peel_snapshots(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<(EpochId, String)>, EngineError> {
        let mut snapshots = self.retained_fork_snapshots(group_id);
        for snapshot_name in self.storage.list_group_snapshots(group_id)? {
            if let Some(epoch) = retained_anchor_epoch_from_snapshot_name(&snapshot_name) {
                snapshots.push((EpochId(epoch), snapshot_name));
            }
        }
        snapshots.sort_by(|(a_epoch, a_name), (b_epoch, b_name)| {
            b_epoch.cmp(a_epoch).then_with(|| a_name.cmp(b_name))
        });
        snapshots.dedup_by(|(a_epoch, a_name), (b_epoch, b_name)| {
            a_epoch == b_epoch && a_name == b_name
        });
        Ok(snapshots)
    }

    fn context_from_group_snapshot(
        &self,
        group_id: &GroupId,
        snapshot_name: &str,
    ) -> Result<cgka_traits::group_context::GroupContextSnapshot, EngineError> {
        self.storage
            .rollback_group_to_snapshot(group_id, snapshot_name)?;
        let provider = EngineOpenMlsProvider::<S>::new(&self.crypto, self.storage.mls_storage());
        let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
        let mls_group = MlsGroup::load(
            <EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::storage(&provider),
            &mls_gid,
        )
        .map_err(|e| EngineError::Backend(format!("load snapshot group: {e:?}")))?
        .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;
        group_lifecycle::build_group_context_snapshot(&mls_group, &provider)
    }

    fn restore_after_snapshot_peel(
        &self,
        group_id: &GroupId,
        restore_snapshot: &str,
    ) -> Result<(), EngineError> {
        self.storage
            .rollback_group_to_snapshot(group_id, restore_snapshot)?;
        match self
            .storage
            .release_group_snapshot(group_id, restore_snapshot)
        {
            Ok(()) | Err(StorageError::SnapshotMissing(_)) => Ok(()),
            Err(err) => Err(EngineError::Storage(err)),
        }
    }

    pub(crate) fn record_sent_openmls_message(
        &mut self,
        msg: &TransportMessage,
        mls_bytes: &[u8],
        group_id: &GroupId,
        epoch: EpochId,
    ) -> Result<(), EngineError> {
        self.sent_message_ids.insert(msg.id.clone());
        let openmls_msg = TransportMessage {
            payload: mls_bytes.to_vec(),
            ..msg.clone()
        };
        self.persist_openmls_wire_message(&openmls_msg, group_id, epoch, MessageState::Sent)
    }

    fn persist_transport_message(
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

    fn persist_openmls_wire_message(
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
        Ok(())
    }

    fn update_stored_message_state(
        &self,
        id: &MessageId,
        state: MessageState,
    ) -> Result<(), EngineError> {
        self.storage.update_message_state(id, state)?;
        Ok(())
    }

    pub(crate) async fn replay_buffered_messages(
        &mut self,
        group_id: &GroupId,
    ) -> Result<(), EngineError> {
        let records = self.storage.list_messages(group_id, EpochId(0))?;
        for record in records {
            if !matches!(
                record.state,
                MessageState::Created | MessageState::Retryable | MessageState::PeelDeferred
            ) {
                continue;
            }
            let stored_payload = StoredMessagePayload::decode(&record.payload)
                .map_err(|e| EngineError::Serialize(format!("{e:?}")))?;
            let Some(msg) = stored_payload.as_raw_transport().cloned() else {
                continue;
            };
            match self
                .ingest_group_message(&msg, group_id.as_slice().to_vec())
                .await
            {
                Ok(IngestOutcome::Buffered { .. }) => {
                    self.update_stored_message_state(&record.id, MessageState::Retryable)?;
                }
                Ok(_) => {}
                Err(EngineError::ForkedEpoch {
                    group_id,
                    last_stable,
                    conflicting_epoch,
                }) => {
                    self.update_stored_message_state(&record.id, MessageState::EpochInvalidated)?;
                    return Err(EngineError::ForkedEpoch {
                        group_id,
                        last_stable,
                        conflicting_epoch,
                    });
                }
                Err(e) => {
                    self.update_stored_message_state(&record.id, MessageState::Retryable)?;
                    return Err(e);
                }
            }
        }
        Ok(())
    }
}
