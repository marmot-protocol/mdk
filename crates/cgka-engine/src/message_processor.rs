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
use crate::snapshot_guard::SnapshotRollbackGuard;
use cgka_traits::app_components::AppComponentData;
use cgka_traits::engine::{
    AutoPublish, CommitOrderingKey, CommitOrderingPriority, GroupEvent, GroupStateChange,
    SendIntent, SendResult,
};
use cgka_traits::engine_state::EpochState;
use cgka_traits::error::{EngineError, PeelerError};
use cgka_traits::ingest::{IngestOutcome, PeeledContent, StaleReason};
use cgka_traits::message::{MessageRecord, MessageState, StoredMessagePayload};
use cgka_traits::storage::{QueuedOutboundIntent, StorageError, StorageProvider};
use cgka_traits::transport::{EncryptedPayload, TransportEnvelope, TransportMessage};
use cgka_traits::types::{EpochId, GroupId, MemberId, MessageId};
use openmls::component::ComponentData;
use openmls::group::{MlsGroup, MlsGroupStateError, ProcessMessageError};
use openmls::messages::proposals::{AppDataUpdateOperation, ProposalOrRef};
use openmls::prelude::{
    BasicCredential, ContentType, MlsMessageBodyIn, MlsMessageIn, MlsMessageOut, ProcessedMessage,
    ProcessedMessageContent, Proposal, ProtocolMessage, ProtocolVersion, Sender, ValidationError,
};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use tls_codec::{Deserialize as _, Serialize as _};

const MAX_CONVERGENCE_REPROCESSING_PASSES: usize = 16;

struct PastPeelRecovery {
    peeled: cgka_traits::ingest::PeeledMessage,
    source_epoch: EpochId,
    snapshot_name: String,
    attempt_count: u64,
}

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
            self.persist_transport_message_for_existing_group(
                &msg,
                &group_id,
                EpochId(0),
                MessageState::Sent,
            )?;
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
            Err(EngineError::Peeler(PeelerError::DecryptFailed)) => Ok(IngestOutcome::Stale {
                reason: StaleReason::PeelFailed,
            }),
            Err(EngineError::Peeler(PeelerError::Malformed(_))) => Ok(IngestOutcome::Stale {
                reason: StaleReason::PeelFailed,
            }),
            Err(other) => Err(other),
        }
    }

    async fn ingest_group_message(
        &mut self,
        msg: &TransportMessage,
        transport_group_id: Vec<u8>,
    ) -> Result<IngestOutcome, EngineError> {
        let group_id = self.group_id_for_transport_group_id(&transport_group_id)?;
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
                    self.persist_transport_message_for_existing_group(
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
            if !mls_group.is_active() {
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
            let msg_id_hex = hex::encode(msg.id.as_slice());
            let peel_result = self.peeler.peel_group_message(msg, &ctx).await;
            // Record the raw peeler verdict before any fallback attempt.
            let raw_outcome = match &peel_result {
                Ok(_) => marmot_forensics::PeelerOutcomeKind::Success,
                Err(PeelerError::DecryptFailed) => {
                    marmot_forensics::PeelerOutcomeKind::DecryptFailed
                }
                Err(PeelerError::StaleEpoch { .. }) => {
                    marmot_forensics::PeelerOutcomeKind::StaleEpoch
                }
                Err(PeelerError::Malformed(_)) => marmot_forensics::PeelerOutcomeKind::Malformed,
                Err(_) => marmot_forensics::PeelerOutcomeKind::Other,
            };
            self.audit_group(
                &group_id,
                marmot_forensics::AuditEventKind::PeelerOutcome {
                    msg_id: msg_id_hex.clone(),
                    outcome: raw_outcome,
                    fallback_snapshot_used: false,
                    fallback_snapshot_name: None,
                    fallback_snapshot_source_epoch: None,
                    fallback_attempt_count: None,
                    error_kind: match &peel_result {
                        Err(e) => Some(crate::audit_helpers::peeler_error_kind(e).to_string()),
                        Ok(_) => None,
                    },
                    detail: match &peel_result {
                        Err(e) => Some(format!("{e}")),
                        Ok(_) => None,
                    },
                },
            );
            let peeled = match peel_result {
                Ok(p) => p,
                Err(PeelerError::DecryptFailed) => {
                    if let Some(recovery) = self
                        .try_peel_group_message_from_available_snapshots(
                            msg,
                            &group_id,
                            current_epoch,
                        )
                        .await?
                    {
                        self.audit_group(
                            &group_id,
                            marmot_forensics::AuditEventKind::PeelerOutcome {
                                msg_id: msg_id_hex.clone(),
                                outcome: marmot_forensics::PeelerOutcomeKind::Success,
                                fallback_snapshot_used: true,
                                fallback_snapshot_name: Some(recovery.snapshot_name.clone()),
                                fallback_snapshot_source_epoch: Some(recovery.source_epoch.0),
                                fallback_attempt_count: Some(recovery.attempt_count),
                                error_kind: None,
                                detail: Some("recovered_after_decrypt_failed".to_string()),
                            },
                        );
                        recovery.peeled
                    } else {
                        self.persist_transport_message(
                            msg,
                            &group_id,
                            current_epoch,
                            MessageState::PeelDeferred,
                        )?;
                        self.audit_group(
                            &group_id,
                            crate::audit_helpers::message_state_changed_event(
                                msg_id_hex.clone(),
                                MessageState::PeelDeferred,
                                "peel_failed_no_snapshot",
                            ),
                        );
                        return Ok(IngestOutcome::Stale {
                            reason: StaleReason::PeelFailed,
                        });
                    }
                }
                Err(PeelerError::StaleEpoch { .. }) => {
                    if let Some(recovery) = self
                        .try_peel_group_message_from_available_snapshots(
                            msg,
                            &group_id,
                            current_epoch,
                        )
                        .await?
                    {
                        self.audit_group(
                            &group_id,
                            marmot_forensics::AuditEventKind::PeelerOutcome {
                                msg_id: msg_id_hex.clone(),
                                outcome: marmot_forensics::PeelerOutcomeKind::Success,
                                fallback_snapshot_used: true,
                                fallback_snapshot_name: Some(recovery.snapshot_name.clone()),
                                fallback_snapshot_source_epoch: Some(recovery.source_epoch.0),
                                fallback_attempt_count: Some(recovery.attempt_count),
                                error_kind: None,
                                detail: Some("recovered_after_stale_epoch".to_string()),
                            },
                        );
                        recovery.peeled
                    } else {
                        self.persist_transport_message(
                            msg,
                            &group_id,
                            current_epoch,
                            MessageState::Failed,
                        )?;
                        self.audit_group(
                            &group_id,
                            crate::audit_helpers::message_state_changed_event(
                                msg_id_hex.clone(),
                                MessageState::Failed,
                                "stale_epoch_no_snapshot",
                            ),
                        );
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

            // Process via MLS. Commits may contain AppDataUpdate proposals,
            // which require the application to compute the resulting
            // AppDataDictionary before OpenMLS stages the commit.
            let processed = match if msg_content_type == ContentType::Commit {
                process_commit_with_app_data_updates(&mut mls_group, &provider, proto)
            } else {
                mls_group.process_message(&provider, proto)
            } {
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
                        let Some(snapshot_name) =
                            self.recovery_snapshot_name_for_fork(&group_id, msg_epoch)
                        else {
                            match self.resolve_fork_candidate(
                                &group_id,
                                msg_epoch,
                                CommitOrderingPriority::Ordinary,
                                MemberId::new(Vec::new()),
                                mls_bytes.as_slice(),
                            )? {
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
                                ForkResolution::IncumbentWins
                                | ForkResolution::CandidateWins { .. } => {
                                    unreachable!("missing snapshot cannot resolve a fork candidate")
                                }
                            }
                        };
                        let (candidate_priority, candidate_committer) = self
                            .probe_commit_ordering_metadata_for_recovery(
                                &group_id,
                                msg_epoch,
                                &snapshot_name,
                                mls_bytes.as_slice(),
                            )?;
                        match self.resolve_fork_candidate(
                            &group_id,
                            msg_epoch,
                            candidate_priority,
                            candidate_committer,
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
                Err(ProcessMessageError::GroupStateError(MlsGroupStateError::UseAfterEviction)) => {
                    self.update_stored_message_state(&msg.id, MessageState::Failed)?;
                    return Ok(IngestOutcome::Stale {
                        reason: StaleReason::PeelFailed,
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
                    let Some(sender) = sender_id else {
                        // OpenMLS allows external senders for some
                        // ProcessedMessageContent variants but Marmot
                        // does not surface unattributable application
                        // messages to applications: a `MessageReceived`
                        // event without a real sender is silent
                        // attribution loss. Mark the message Failed and
                        // skip the event. (We deliberately avoid logging
                        // payload contents per observability.md.)
                        tracing::warn!(
                            target: "cgka_engine::message_processor",
                            method = "ingest_group_message",
                            "dropping application message with unattributable sender"
                        );
                        self.update_stored_message_state(&msg.id, MessageState::Failed)?;
                        return Ok(IngestOutcome::Stale {
                            reason: StaleReason::PeelFailed,
                        });
                    };
                    let payload = bytes.into_bytes();
                    if crate::app_payload::validate_app_payload_for_sender(&payload, &sender)
                        .is_err()
                    {
                        tracing::warn!(
                            target: "cgka_engine::message_processor",
                            method = "ingest_group_message",
                            "dropping application message with invalid Marmot app event",
                        );
                        self.update_stored_message_state(&msg.id, MessageState::Failed)?;
                        return Ok(IngestOutcome::Stale {
                            reason: StaleReason::PeelFailed,
                        });
                    }
                    self.events_buf.push_back(GroupEvent::MessageReceived {
                        group_id: group_id.clone(),
                        sender,
                        epoch: msg_epoch,
                        payload,
                    });
                    self.update_stored_message_state(&msg.id, MessageState::Processed)?;
                    Ok(IngestOutcome::Processed)
                }
                ProcessedMessageContent::StagedCommitMessage(staged) => {
                    let before = EpochId(mls_group.epoch().as_u64());
                    if let Err(err) = crate::app_components::require_admin_for_staged_commit(
                        &mls_group,
                        &group_id,
                        sender_id.as_ref(),
                        &staged,
                    ) {
                        self.update_stored_message_state(&msg.id, MessageState::Failed)?;
                        return Err(err);
                    }
                    let Some(commit_committer) = sender_id.clone() else {
                        self.update_stored_message_state(&msg.id, MessageState::Failed)?;
                        return Err(EngineError::Backend(
                            "commit has no authenticated member sender".into(),
                        ));
                    };
                    let commit_priority =
                        crate::app_components::commit_ordering_priority_for_staged(&staged);
                    // foundation/identity.md: reject an inbound commit that
                    // would add a member whose credential identity is not a
                    // valid x-only secp256k1 public key, before it mutates
                    // canonical state.
                    let mut added = Vec::new();
                    for add in staged.add_proposals() {
                        let leaf = add.add_proposal().key_package().leaf_node();
                        match crate::identity::validated_member_id_of_leaf(leaf).and_then(|id| {
                            crate::account_identity_proof::validate_leaf_account_identity_proof(
                                leaf,
                                self.ciphersuite,
                            )?;
                            Ok(id)
                        }) {
                            Ok(id) => added.push(id),
                            Err(err) => {
                                self.update_stored_message_state(&msg.id, MessageState::Failed)?;
                                return Err(err);
                            }
                        }
                    }
                    // Classify departures before the merge consumes the staged
                    // commit and the leaving leaves disappear: a SelfRemove is a
                    // member leaving (attributed to themselves); a Remove is an
                    // admin removing someone (attributed to the committer).
                    let mut self_removed: std::collections::HashSet<MemberId> =
                        std::collections::HashSet::new();
                    for queued in staged.queued_proposals() {
                        if matches!(queued.proposal(), Proposal::SelfRemove)
                            && let Some(id) = member_id_of_sender(queued.sender(), &mls_group)
                        {
                            self_removed.insert(id);
                        }
                    }
                    let recovery_snapshot =
                        self.fork_recovery
                            .create_snapshot(&self.storage, &group_id, before)?;
                    self.audit_snapshot_created(
                        &group_id,
                        &recovery_snapshot,
                        before,
                        "pre_inbound_commit_apply",
                    );
                    let before_members = group_lifecycle::marmot_members(&mls_group);
                    let before_admins =
                        crate::app_components::admins_of_group(&mls_group).unwrap_or_default();
                    let before_profile = crate::app_components::group_profile_of_group(&mls_group)
                        .ok()
                        .flatten();
                    let before_avatar = avatar_component_snapshot(&mls_group);
                    self.retain_current_epoch_snapshot_for_group(&group_id)?;
                    // Extract capabilities from Add proposals before the
                    // staged commit is consumed by merge.
                    crate::capability_manager::cache_from_staged_commit(
                        &self.storage,
                        &group_id,
                        &staged,
                        self.ciphersuite,
                    )?;
                    mls_group
                        .merge_staged_commit(&provider, *staged)
                        .map_err(|e| EngineError::Backend(format!("merge_staged_commit: {e:?}")))?;
                    let after = EpochId(mls_group.epoch().as_u64());
                    let after_members = group_lifecycle::marmot_members(&mls_group);
                    let after_admins =
                        crate::app_components::admins_of_group(&mls_group).unwrap_or_default();
                    let after_profile = crate::app_components::group_profile_of_group(&mls_group)
                        .ok()
                        .flatten();
                    let after_avatar = avatar_component_snapshot(&mls_group);
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
                        CommitOrderingKey::from_commit_bytes(
                            before,
                            commit_priority,
                            commit_committer,
                            mls_bytes.as_slice(),
                        ),
                        recovery_snapshot,
                    );
                    if let Ok(mut g) = self.storage.get_group(&group_id) {
                        g.epoch = after;
                        g.members = after_members;
                        g.required_capabilities =
                            crate::capability_manager::required_capabilities_from_group(&mls_group);
                        crate::group_lifecycle::mirror_app_components_into_record(
                            &mls_group, &mut g,
                        );
                        self.storage.put_group(&g)?;
                    }
                    // Refresh self-cache since our own leaf may have been
                    // updated by the commit's path.
                    crate::capability_manager::cache_self_capabilities(
                        &self.storage,
                        &group_id,
                        &mls_group,
                        self.identity.self_id(),
                        self.ciphersuite,
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
                    // Synthesize attributed state-change events, ordered:
                    // additions, departures, admin grants/revocations, then
                    // profile changes. The app turns each into a kind-1210 row.
                    for member in added {
                        self.push_group_state_change(
                            &group_id,
                            after,
                            sender_id.clone(),
                            GroupStateChange::MemberAdded { member },
                        );
                    }
                    for member in removed {
                        let (change, actor) = if self_removed.contains(&member) {
                            // A leave is attributed to the leaver, not the member
                            // that sequenced the auto-commit.
                            (
                                GroupStateChange::MemberLeft {
                                    member: member.clone(),
                                },
                                Some(member),
                            )
                        } else {
                            (
                                GroupStateChange::MemberRemoved { member },
                                sender_id.clone(),
                            )
                        };
                        self.push_group_state_change(&group_id, after, actor, change);
                    }
                    for change in
                        crate::group_state_changes::admin_changes(&before_admins, &after_admins)
                    {
                        self.push_group_state_change(&group_id, after, sender_id.clone(), change);
                    }
                    for change in crate::group_state_changes::profile_changes(
                        before_profile.as_ref().map(|(name, _)| name.as_str()),
                        after_profile.as_ref().map(|(name, _)| name.as_str()),
                        &before_avatar,
                        &after_avatar,
                    ) {
                        self.push_group_state_change(&group_id, after, sender_id.clone(), change);
                    }
                    self.update_stored_message_state(&msg.id, MessageState::Processed)?;
                    Ok(IngestOutcome::Processed)
                }
                ProcessedMessageContent::ProposalMessage(queued) => {
                    // Ask the auto-committer policy whether we should commit
                    // this proposal. OpenMLS does not auto-enqueue processed
                    // proposals, so store it before attempting to commit the
                    // pending proposal queue.
                    let decision_report =
                        crate::auto_committer::decide_with_reason(&mls_group, &queued);
                    let decision_str = match &decision_report.decision {
                        crate::auto_committer::AutoCommitDecision::Commit => "commit",
                        crate::auto_committer::AutoCommitDecision::Observe => "observe",
                    };
                    self.audit_group(
                        &group_id,
                        marmot_forensics::AuditEventKind::AutoCommitDecision {
                            proposal_kind: crate::audit_helpers::proposal_kind_str(
                                queued.proposal(),
                            )
                            .to_string(),
                            decision: decision_str.to_string(),
                            reason: Some(decision_report.reason.to_string()),
                        },
                    );
                    let auto_removed: Vec<MemberId> = match queued.proposal() {
                        Proposal::Remove(r) => member_id_at_leaf(&mls_group, r.removed())
                            .into_iter()
                            .collect(),
                        Proposal::SelfRemove => member_id_of_sender(queued.sender(), &mls_group)
                            .into_iter()
                            .collect(),
                        _ => Vec::new(),
                    };
                    // Capture attribution before `store_pending_proposal`
                    // consumes `queued`. A SelfRemove is a leave attributed to
                    // the leaver; a Remove is attributed to the proposer.
                    let auto_is_self_remove = matches!(queued.proposal(), Proposal::SelfRemove);
                    let auto_proposer = member_id_of_sender(queued.sender(), &mls_group);
                    mls_group
                    .store_pending_proposal(
                        <EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::storage(
                            &provider,
                        ),
                        *queued,
                    )
                    .map_err(|e| EngineError::Backend(format!("store_pending: {e:?}")))?;
                    if matches!(
                        decision_report.decision,
                        crate::auto_committer::AutoCommitDecision::Commit
                    ) {
                        // Fork-detection bookkeeping — we're committing FROM
                        // the current pre-commit epoch.
                        let pre_commit_epoch = EpochId(mls_group.epoch().as_u64());
                        let recovery_snapshot = self.fork_recovery.create_snapshot(
                            &self.storage,
                            &group_id,
                            pre_commit_epoch,
                        )?;
                        self.audit_snapshot_created(
                            &group_id,
                            &recovery_snapshot,
                            pre_commit_epoch,
                            "pre_auto_commit",
                        );
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
                        let wrapped = route_wrapped_group_message(wrapped, &pre_commit_ctx);
                        self.record_sent_openmls_message(
                            &wrapped,
                            commit_bytes.as_slice(),
                            &group_id,
                            pre_commit_epoch,
                        )?;

                        let new_epoch = EpochId(pre_commit_epoch.0.saturating_add(1));
                        let pending_ref = self.epoch_manager.next_pending_ref();
                        let staged = cgka_traits::engine_state::StagedCommitHandle::from_bytes(
                            group_id.as_slice().to_vec(),
                        );
                        self.epoch_manager.begin_pending(
                            group_id.clone(),
                            pre_commit_epoch,
                            new_epoch,
                            staged,
                            pending_ref,
                            crate::epoch_manager::PendingKind::GroupEvolution,
                            self.current_audit_context.clone(),
                        )?;
                        let commit_priority = mls_group
                            .pending_commit()
                            .map(crate::app_components::commit_ordering_priority_for_staged)
                            .ok_or_else(|| {
                                EngineError::Backend(
                                    "auto-commit produced no pending commit".into(),
                                )
                            })?;
                        self.track_pending_commit_for_recovery(
                            pending_ref,
                            group_id.clone(),
                            pre_commit_epoch,
                            wrapped.id.clone(),
                            CommitOrderingKey::from_commit_bytes(
                                pre_commit_epoch,
                                commit_priority,
                                self.identity.self_id().clone(),
                                &commit_bytes,
                            ),
                            recovery_snapshot,
                        );
                        let auto_changes = auto_removed
                            .iter()
                            .cloned()
                            .map(|member| {
                                let (change, actor) = if auto_is_self_remove {
                                    (
                                        GroupStateChange::MemberLeft {
                                            member: member.clone(),
                                        },
                                        Some(member),
                                    )
                                } else {
                                    (
                                        GroupStateChange::MemberRemoved { member },
                                        auto_proposer.clone(),
                                    )
                                };
                                crate::engine::PendingGroupStateChange { actor, change }
                            })
                            .collect();
                        self.pending_state_changes.insert(pending_ref, auto_changes);
                        self.auto_publish_buf.push_back(AutoPublish {
                            msg: wrapped,
                            pending: pending_ref,
                        });

                        // Match the explicit send paths' projected Marmot
                        // state: callers can see the pending member set, while
                        // the OpenMLS commit itself is not merged until
                        // confirm_published.
                        if let Ok(mut g) = self.storage.get_group(&group_id) {
                            g.epoch = new_epoch;
                            g.members
                                .retain(|member| !auto_removed.iter().any(|id| id == &member.id));
                            self.storage.put_group(&g)?;
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

    fn probe_commit_ordering_metadata_for_recovery(
        &self,
        group_id: &GroupId,
        source_epoch: EpochId,
        recovery_snapshot_name: &str,
        mls_bytes: &[u8],
    ) -> Result<(CommitOrderingPriority, MemberId), EngineError> {
        let mut hasher = Sha256::new();
        hasher.update(b"cgka-engine-fork-probe/v1");
        hasher.update(group_id.as_slice());
        hasher.update(source_epoch.0.to_be_bytes());
        hasher.update(mls_bytes);
        let digest = hasher.finalize();
        let probe_snapshot = format!(
            "fork-probe-{}-{}",
            source_epoch.0,
            hex::encode(&digest[..8])
        );
        let guard = SnapshotRollbackGuard::create(&self.storage, group_id.clone(), probe_snapshot)?;
        self.storage
            .rollback_group_to_snapshot(group_id, recovery_snapshot_name)?;

        let provider = EngineOpenMlsProvider::<S>::new(&self.crypto, self.storage.mls_storage());
        let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
        let mut probe_group = MlsGroup::load(
            <EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::storage(&provider),
            &mls_gid,
        )
        .map_err(|e| EngineError::Backend(format!("load fork probe: {e:?}")))?
        .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;

        let msg_in = MlsMessageIn::tls_deserialize_exact(mls_bytes)
            .map_err(|e| EngineError::Serialize(format!("fork probe deserialize: {e:?}")))?;
        let proto: ProtocolMessage = match msg_in.extract() {
            MlsMessageBodyIn::PrivateMessage(p) => p.into(),
            MlsMessageBodyIn::PublicMessage(p) => p.into(),
            _ => {
                return Err(EngineError::Serialize(
                    "fork probe expected MLS protocol message".into(),
                ));
            }
        };
        let processed = process_commit_with_app_data_updates(&mut probe_group, &provider, proto)
            .map_err(|e| EngineError::Backend(format!("fork probe process_message: {e:?}")))?;
        let sender = member_id_of_sender(processed.sender(), &probe_group).ok_or_else(|| {
            EngineError::Backend("fork candidate commit has no authenticated member sender".into())
        })?;
        let priority = match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                crate::app_components::require_admin_for_staged_commit(
                    &probe_group,
                    group_id,
                    Some(&sender),
                    staged.as_ref(),
                )?;
                crate::app_components::commit_ordering_priority_for_staged(staged.as_ref())
            }
            _ => {
                return Err(EngineError::Backend(
                    "fork probe expected staged commit".into(),
                ));
            }
        };
        guard.commit()?;
        Ok((priority, sender))
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
            SendIntent::RemoveMembers { group_id, members } => {
                self.do_send_remove_members(group_id, members).await
            }
            SendIntent::Leave { group_id } => self.do_send_leave(group_id).await,
            SendIntent::UpdateAppComponents { group_id, updates } => {
                self.do_send_update_app_components(group_id, updates).await
            }
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
            .advance_convergence_inputs_until_settled(group_id, now_ms)
            .await?
        {
            return Ok(Vec::new());
        }

        let queued = self.storage.list_queued_outbound_intents(group_id)?;
        let mut drained = Vec::new();
        for record in queued {
            if !self
                .advance_convergence_inputs_until_settled(group_id, now_ms)
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
        if result.convergence_status != crate::canonicalization::ConvergenceStatus::Settled {
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
    pub async fn advance_convergence_inputs_until_settled(
        &mut self,
        group_id: &GroupId,
        now_ms: u64,
    ) -> Result<bool, EngineError> {
        for _ in 0..MAX_CONVERGENCE_REPROCESSING_PASSES {
            if self.has_unresolved_convergence_inputs(group_id)? {
                let result = self
                    .converge_stored_openmls_messages(group_id, now_ms)
                    .map_err(|e| EngineError::Backend(format!("converge inputs: {e}")))?;
                if result.convergence_status != crate::canonicalization::ConvergenceStatus::Settled
                {
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

    /// Queue a `GroupStateChanged` event for the application to synthesize into
    /// a durable kind-1210 group system row.
    pub(crate) fn push_group_state_change(
        &mut self,
        group_id: &GroupId,
        epoch: EpochId,
        actor: Option<MemberId>,
        change: GroupStateChange,
    ) {
        self.events_buf.push_back(GroupEvent::GroupStateChanged {
            group_id: group_id.clone(),
            epoch,
            actor,
            change,
        });
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
        crate::app_components::require_admin(&mls_group, &group_id, self.identity.self_id())?;

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
                return Err(EngineError::MissingRequiredCapabilities {
                    required: Box::new(required),
                    had: Box::new(had),
                });
            }
            parsed_kps.push(parsed);
        }

        // Record the pre-commit epoch so a later same-epoch commit can be
        // compared against this locally produced branch.
        let pre_commit_epoch = EpochId(mls_group.epoch().as_u64());
        let recovery_snapshot =
            self.fork_recovery
                .create_snapshot(&self.storage, &group_id, pre_commit_epoch)?;
        self.audit_snapshot_created(
            &group_id,
            &recovery_snapshot,
            pre_commit_epoch,
            "pre_invite_commit",
        );
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
        let commit_msg = route_wrapped_group_message(commit_msg, &pre_commit_ctx);
        self.record_sent_openmls_message(
            &commit_msg,
            commit_bytes.as_slice(),
            &group_id,
            pre_commit_epoch,
        )?;

        let mut welcomes = Vec::with_capacity(parsed_kps.len());
        let welcome_relays = crate::group_lifecycle::welcome_relays_for_group(&mls_group)?;
        for (source_kp, parsed_kp) in key_packages.iter().zip(parsed_kps.iter()) {
            let recipient = {
                let bc = BasicCredential::try_from(parsed_kp.leaf_node().credential().clone())
                    .map_err(|e| EngineError::Backend(format!("credential: {e:?}")))?;
                MemberId::new(bc.identity().to_vec())
            };
            let payload = EncryptedPayload {
                ciphertext: welcome_bytes.clone(),
                aad: vec![],
            };
            let wrapped = if let Some(metadata) =
                crate::group_lifecycle::welcome_metadata_for_key_package(
                    source_kp,
                    welcome_relays.as_deref(),
                )? {
                self.peeler
                    .wrap_welcome_with_metadata(&payload, &recipient, &metadata)
                    .await
            } else {
                self.peeler.wrap_welcome(&payload, &recipient).await
            }
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
        crate::capability_manager::cache_from_key_packages(
            &self.storage,
            &group_id,
            &parsed_kps,
            self.ciphersuite,
        )?;
        let mut group_record = existing;
        group_record.members =
            crate::group_lifecycle::projected_members_with_pending(&mls_group, &parsed_kps)?;
        self.storage.put_group(&group_record)?;

        // State: begin pending at the projected new epoch via EpochManager.
        // The MLS group is still at the pre-commit epoch, so the projected
        // post-merge epoch is +1.
        let prior_epoch = EpochId(mls_group.epoch().as_u64());
        let new_epoch = EpochId(prior_epoch.0.saturating_add(1));
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
            self.current_audit_context.clone(),
        )?;
        let commit_priority = mls_group
            .pending_commit()
            .map(crate::app_components::commit_ordering_priority_for_staged)
            .ok_or_else(|| EngineError::Backend("invite produced no pending commit".into()))?;
        self.track_pending_commit_for_recovery(
            pending_ref,
            group_id.clone(),
            prior_epoch,
            commit_msg.id.clone(),
            CommitOrderingKey::from_commit_bytes(
                prior_epoch,
                commit_priority,
                self.identity.self_id().clone(),
                &commit_bytes,
            ),
            recovery_snapshot,
        );
        // Buffer the additions so confirm_published emits an attributed
        // GroupStateChanged (and the app a kind-1210 row) once the commit merges.
        let added_changes = parsed_kps
            .iter()
            .filter_map(|kp| crate::identity::validated_member_id_of_leaf(kp.leaf_node()).ok())
            .map(|member| crate::engine::PendingGroupStateChange {
                actor: Some(self.identity.self_id().clone()),
                change: GroupStateChange::MemberAdded { member },
            })
            .collect();
        self.pending_state_changes
            .insert(pending_ref, added_changes);

        Ok(SendResult::GroupEvolution {
            msg: commit_msg,
            welcomes,
            pending: pending_ref,
        })
    }

    async fn do_send_remove_members(
        &mut self,
        group_id: GroupId,
        members: Vec<MemberId>,
    ) -> Result<SendResult, EngineError> {
        let mut target_set = HashSet::new();
        let mut unique_targets = Vec::new();
        for member in members {
            if target_set.insert(member.clone()) {
                unique_targets.push(member);
            }
        }
        if unique_targets.is_empty() {
            return Err(EngineError::Other(
                "remove requires at least one member".into(),
            ));
        }
        if unique_targets
            .iter()
            .any(|member| member == self.identity.self_id())
        {
            return Err(EngineError::Other(
                "use SendIntent::Leave to remove the local member".into(),
            ));
        }

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
                    to: "RemoveMembers",
                    reason: "remove members requires Stable",
                },
            ));
        }

        let existing = self.storage.get_group(&group_id)?;
        crate::app_components::require_admin(&mls_group, &group_id, self.identity.self_id())?;
        let admins = crate::app_components::admins_of_group(&mls_group)?;

        let mut leaf_indices = Vec::with_capacity(unique_targets.len());
        let mut found = HashSet::new();
        for member in mls_group.members() {
            let basic = BasicCredential::try_from(member.credential)
                .map_err(|e| EngineError::Backend(format!("credential: {e:?}")))?;
            let member_id = MemberId::new(basic.identity().to_vec());
            if target_set.contains(&member_id) {
                leaf_indices.push(member.index);
                found.insert(member_id);
            }
        }
        for member in &unique_targets {
            if !found.contains(member) {
                return Err(EngineError::UnknownMember {
                    group_id: group_id.clone(),
                    member: member.clone(),
                });
            }
        }

        let target_admins = unique_targets
            .iter()
            .map(crate::app_components::admin_pubkey_from_member_id)
            .collect::<Result<Vec<_>, _>>()?;
        if admins
            .iter()
            .all(|admin| target_admins.iter().any(|target| target == admin))
        {
            return Err(EngineError::AdminDepletion {
                group_id: group_id.clone(),
            });
        }

        let pre_commit_epoch = EpochId(mls_group.epoch().as_u64());
        let recovery_snapshot =
            self.fork_recovery
                .create_snapshot(&self.storage, &group_id, pre_commit_epoch)?;
        self.audit_snapshot_created(
            &group_id,
            &recovery_snapshot,
            pre_commit_epoch,
            "pre_remove_members_commit",
        );
        self.epoch_manager
            .record_committed_from(&group_id, pre_commit_epoch);
        let pre_commit_ctx =
            crate::group_lifecycle::build_group_context_snapshot(&mls_group, &provider)?;

        let (commit_out, _welcome_opt, _gi) = mls_group
            .remove_members(&provider, &self.identity.signer, &leaf_indices)
            .map_err(|e| EngineError::Backend(format!("remove_members: {e:?}")))?;

        let commit_bytes = commit_out
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
        let commit_msg = route_wrapped_group_message(commit_msg, &pre_commit_ctx);
        self.record_sent_openmls_message(
            &commit_msg,
            commit_bytes.as_slice(),
            &group_id,
            pre_commit_epoch,
        )?;

        let mut group_record = existing;
        group_record
            .members
            .retain(|member| !target_set.contains(&member.id));
        self.storage.put_group(&group_record)?;

        let prior_epoch = EpochId(mls_group.epoch().as_u64());
        let new_epoch = EpochId(prior_epoch.0.saturating_add(1));
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
            self.current_audit_context.clone(),
        )?;
        let commit_priority = mls_group
            .pending_commit()
            .map(crate::app_components::commit_ordering_priority_for_staged)
            .ok_or_else(|| EngineError::Backend("remove produced no pending commit".into()))?;
        self.track_pending_commit_for_recovery(
            pending_ref,
            group_id.clone(),
            prior_epoch,
            commit_msg.id.clone(),
            CommitOrderingKey::from_commit_bytes(
                prior_epoch,
                commit_priority,
                self.identity.self_id().clone(),
                &commit_bytes,
            ),
            recovery_snapshot,
        );
        let removed_changes = unique_targets
            .iter()
            .cloned()
            .map(|member| crate::engine::PendingGroupStateChange {
                actor: Some(self.identity.self_id().clone()),
                change: GroupStateChange::MemberRemoved { member },
            })
            .collect();
        self.pending_state_changes
            .insert(pending_ref, removed_changes);

        Ok(SendResult::GroupEvolution {
            msg: commit_msg,
            welcomes: vec![],
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

        if let Some(state) = self.epoch_manager.state(&group_id)
            && !matches!(state, EpochState::Stable { .. })
        {
            return Err(EngineError::InvalidTransition(
                cgka_traits::engine_state::InvalidTransition {
                    from: state.name(),
                    to: "Leave",
                    reason: "leave requires Stable",
                },
            ));
        }

        // member-departure.md:23-26 — an admin must leave the admin set before
        // using SelfRemove. This is stricter than merely preserving a non-empty
        // admin set: it prevents an admin identity from departing while still
        // present in the prior epoch's admin policy.
        let self_pubkey =
            crate::app_components::admin_pubkey_from_member_id(self.identity.self_id())?;
        let admins = crate::app_components::admins_of_group(&mls_group)?;
        let i_am_admin = admins.iter().any(|k| k == &self_pubkey);
        if i_am_admin {
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
        let wrapped = route_wrapped_group_message(wrapped, &ctx);
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

        crate::app_payload::validate_app_payload_for_sender(&payload, self.identity.self_id())?;

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

        let wrapped = route_wrapped_group_message(wrapped, &ctx);
        self.record_sent_openmls_message(
            &wrapped,
            out_bytes.as_slice(),
            &group_id,
            EpochId(mls_group.epoch().as_u64()),
        )?;

        Ok(SendResult::ApplicationMessage { msg: wrapped })
    }
}

fn process_commit_with_app_data_updates<S: StorageProvider>(
    mls_group: &mut MlsGroup,
    provider: &EngineOpenMlsProvider<'_, S>,
    proto: ProtocolMessage,
) -> Result<
    ProcessedMessage,
    ProcessMessageError<
        <<S as StorageProvider>::Mls as openmls_traits::storage::StorageProvider<
            { openmls_traits::storage::CURRENT_VERSION },
        >>::Error,
    >,
> {
    let unverified = mls_group.unprotect_message(provider, proto)?;
    let mut updater = mls_group.app_data_dictionary_updater();
    if let Some(committed_proposals) = unverified.committed_proposals() {
        for proposal_or_ref in committed_proposals {
            let validated = proposal_or_ref.clone().validate(
                <EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::crypto(provider),
                mls_group.ciphersuite(),
                ProtocolVersion::Mls10,
            )?;
            let proposal = match validated {
                ProposalOrRef::Proposal(proposal) => proposal,
                ProposalOrRef::Reference(reference) => mls_group
                    .proposal_store()
                    .proposals()
                    .find(|p| p.proposal_reference_ref() == &*reference)
                    .map(|p| Box::new(p.proposal().clone()))
                    .ok_or(ProcessMessageError::FoundAppDataUpdateProposal)?,
            };
            if let Proposal::AppDataUpdate(update) = proposal.as_ref() {
                match update.operation() {
                    AppDataUpdateOperation::Update(data) => {
                        crate::app_components::validate_app_component_update(&AppComponentData {
                            component_id: update.component_id(),
                            data: data.as_slice().to_vec(),
                        })
                        .map_err(|_| {
                            ProcessMessageError::ValidationError(ValidationError::WrongWireFormat)
                        })?;
                        updater.set(ComponentData::from_parts(
                            update.component_id(),
                            data.clone(),
                        ));
                    }
                    AppDataUpdateOperation::Remove => {
                        crate::app_components::validate_app_component_remove(
                            mls_group,
                            update.component_id(),
                        )
                        .map_err(|_| {
                            ProcessMessageError::ValidationError(ValidationError::WrongWireFormat)
                        })?;
                        updater.remove(&update.component_id());
                    }
                }
            }
        }
    }
    mls_group.process_unverified_message_with_app_data_updates(
        provider,
        unverified,
        updater.changes(),
    )
}

/// Snapshot the two avatar-bearing component byte blobs (avatar-url and
/// blossom-image) so a before/after comparison can detect an avatar change.
///
/// Presence is normalized: an absent component (`None`) and the canonical
/// "absent" encoding both collapse to `None`, so this inbound diff matches the
/// own-commit diff in `update_group_data` and a "clear an already-absent
/// avatar" commit converges to no row on every client.
fn avatar_component_snapshot(mls_group: &MlsGroup) -> [Option<Vec<u8>>; 2] {
    let snapshot = |component_id| {
        crate::app_components::app_component_data_of_group(mls_group, component_id)
            .filter(|bytes| crate::app_components::avatar_component_present(component_id, bytes))
    };
    [
        snapshot(cgka_traits::app_components::GROUP_AVATAR_URL_COMPONENT_ID),
        snapshot(cgka_traits::app_components::GROUP_BLOSSOM_IMAGE_COMPONENT_ID),
    ]
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

fn route_wrapped_group_message(
    msg: TransportMessage,
    ctx: &cgka_traits::group_context::GroupContextSnapshot,
) -> TransportMessage {
    let Some(transport_group_id) = ctx.transport_group_id().map(ToOwned::to_owned) else {
        return msg;
    };
    TransportMessage {
        envelope: TransportEnvelope::GroupMessage { transport_group_id },
        ..msg
    }
}

fn send_intent_group_id(intent: &SendIntent) -> &GroupId {
    match intent {
        SendIntent::AppMessage { group_id, .. }
        | SendIntent::Invite { group_id, .. }
        | SendIntent::RemoveMembers { group_id, .. }
        | SendIntent::Leave { group_id }
        | SendIntent::UpdateAppComponents { group_id, .. }
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

    // Was this exact message classified by the canonicalize pass? Map
    // the disposition to a typed outcome so callers can log by category
    // instead of treating every non-accepted result as "Buffered, retry
    // later" — a message that was dropped (BeyondAnchor) or invalidated
    // (LosingBranch) is terminal.
    let accepted = result
        .accepted_commits
        .iter()
        .chain(&result.accepted_proposals)
        .chain(&result.accepted_app_messages)
        .any(|accepted| accepted == &message_id);
    if accepted && result.convergence_status == crate::canonicalization::ConvergenceStatus::Settled
    {
        return IngestOutcome::Processed;
    }

    if result
        .already_seen
        .iter()
        .any(|seen| seen.message_id == message_id)
    {
        return IngestOutcome::Stale {
            reason: StaleReason::AlreadySeen,
        };
    }

    // `dropped_messages` and most `invalidated_app_messages` reasons
    // are terminal — the engine can never accept them, so reporting
    // Buffered would mislead callers into expecting a later retry.
    //
    // The one retryable invalidation reason is
    // `UndecryptableInCanonicalState`: the message arrived for a
    // future epoch the local context can't yet peel. A subsequent
    // canonicalize pass that advances the MLS context will re-evaluate
    // it. Keep that case as Buffered.
    if result
        .dropped_messages
        .iter()
        .any(|dropped| dropped.message_id == message_id)
    {
        return IngestOutcome::Stale {
            reason: StaleReason::PeelFailed,
        };
    }
    if let Some(inv) = result
        .invalidated_app_messages
        .iter()
        .find(|inv| inv.message_id == message_id)
    {
        use crate::canonicalization::InvalidatedAppMessageReason;
        match inv.reason {
            InvalidatedAppMessageReason::UndecryptableInCanonicalState => {
                // Possibly retryable on a later pass; fall through to
                // Buffered so the application keeps the message and
                // waits for branch selection to advance.
            }
            InvalidatedAppMessageReason::LosingBranch
            | InvalidatedAppMessageReason::BeyondAnchor
            | InvalidatedAppMessageReason::BeyondAppRetention => {
                return IngestOutcome::Stale {
                    reason: StaleReason::PeelFailed,
                };
            }
        }
    }

    IngestOutcome::Buffered { group_id, epoch }
}

impl<S: StorageProvider> Engine<S> {
    fn group_id_for_transport_group_id(
        &self,
        transport_group_id: &[u8],
    ) -> Result<GroupId, EngineError> {
        let direct = GroupId::new(transport_group_id.to_vec());
        match self.storage.get_group(&direct) {
            Ok(group) => return Ok(group.id),
            Err(StorageError::NotFound) => {}
            Err(err) => return Err(EngineError::Storage(err)),
        }

        let provider = EngineOpenMlsProvider::<S>::new(&self.crypto, self.storage.mls_storage());
        for group_id in self.storage.list_groups()? {
            if group_id.as_slice() == transport_group_id {
                return Ok(group_id);
            }
            let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
            let Some(mls_group) = MlsGroup::load(
                <EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::storage(
                    &provider,
                ),
                &mls_gid,
            )
            .map_err(|e| EngineError::Backend(format!("load route candidate: {e:?}")))?
            else {
                continue;
            };
            if crate::app_components::transport_group_id_of_group(&mls_group)? == transport_group_id
            {
                return Ok(group_id);
            }
        }

        Ok(direct)
    }

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
    ) -> Result<Option<PastPeelRecovery>, EngineError> {
        use crate::snapshot_guard::SnapshotRollbackGuard;
        let snapshots = self.available_past_peel_snapshots(group_id)?;
        let mut attempt_count = 0_u64;
        for (source_epoch, snapshot_name) in snapshots {
            if source_epoch >= current_epoch {
                continue;
            }
            attempt_count = attempt_count.saturating_add(1);
            // Privacy: do not embed `group_id` or `msg.id` as hex in the
            // snapshot name. Storage error messages and any future
            // tracing on snapshot names would otherwise leak routing /
            // dedup-key material that observability.md explicitly
            // forbids.
            let mut hasher = Sha256::new();
            hasher.update(b"cgka-engine-peel-restore/v1");
            hasher.update(group_id.as_slice());
            hasher.update(current_epoch.0.to_be_bytes());
            hasher.update(msg.id.as_slice());
            let snapshot_digest = hasher.finalize();
            let restore_snapshot = format!(
                "peel-restore-{}-{}",
                current_epoch.0,
                hex::encode(&snapshot_digest[..8])
            );
            // RAII guard: rollback + release on any unwind path
            // (panic, early error, async cancel) so the live group
            // state never leaks past this scope as the past-snapshot
            // state.
            let guard =
                SnapshotRollbackGuard::create(&self.storage, group_id.clone(), restore_snapshot)?;
            let ctx = match self.context_from_group_snapshot(group_id, &snapshot_name) {
                Ok(ctx) => ctx,
                Err(err) => {
                    // Drop on `guard` rolls back to live + releases.
                    guard.commit()?;
                    return Err(err);
                }
            };
            let peeled = self.peeler.peel_group_message(msg, &ctx).await;
            guard.commit()?;
            match peeled {
                Ok(peeled) => {
                    return Ok(Some(PastPeelRecovery {
                        peeled,
                        source_epoch,
                        snapshot_name,
                        attempt_count,
                    }));
                }
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

    fn persist_transport_message_for_existing_group(
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
        let id_hex = hex::encode(id.as_slice());
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
                None,
                state,
                Some(epoch),
                "persist",
            ),
        );
        Ok(())
    }

    fn update_stored_message_state(
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
