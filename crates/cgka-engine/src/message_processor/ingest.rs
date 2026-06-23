//! Inbound ingest path for [`Engine`]: peel, classify, apply or buffer.
//!
//! Inbound messages are peeled, classified, stored, and either applied or
//! buffered for convergence. Classifiable stale ingest cases return
//! `Ok(IngestOutcome::Stale { .. })` with a typed `StaleReason`. `Err` is
//! reserved for storage, peeler, serialization, and OpenMLS failures.

use super::{content_dedup_id, route_wrapped_group_message};
use crate::engine::{Engine, ScheduledSelfRemoveAutoCommit};
use crate::fork_recovery::ForkResolution;
use crate::group_lifecycle::{self};
use crate::identity::{member_id_at_leaf, member_id_of_sender};
use crate::openmls_projection::{
    OpenMlsContentKind, process_commit_with_app_data_updates, project_mls_message,
    retained_anchor_epoch_from_snapshot_name,
};
use crate::pending_commit_guard::PendingCommitCleanupGuard;
use crate::provider::EngineOpenMlsProvider;
use crate::snapshot_guard::SnapshotRollbackGuard;
use cgka_traits::engine::{
    AutoPublish, CommitOrderingKey, CommitOrderingPriority, GroupEvent, GroupStateChange,
};
use cgka_traits::error::{EngineError, PeelerError};
use cgka_traits::ingest::{IngestOutcome, PeeledContent, StaleReason};
use cgka_traits::message::{MessageState, StoredMessagePayload};
use cgka_traits::storage::{StorageError, StorageProvider};
use cgka_traits::transport::{EncryptedPayload, TransportMessage};
use cgka_traits::types::{EpochId, GroupId, MemberId, MessageId};
use openmls::framing::errors::{MessageDecryptionError, SecretTreeError};
use openmls::group::{MlsGroup, MlsGroupStateError, ProcessMessageError};
use openmls::prelude::{
    ContentType, MlsMessageBodyIn, MlsMessageIn, ProcessedMessageContent, Proposal,
    ProtocolMessage, QueuedProposal, ValidationError,
};
use sha2::{Digest, Sha256};
use tls_codec::{Deserialize as _, Serialize as _};

struct PastPeelRecovery {
    peeled: cgka_traits::ingest::PeeledMessage,
    source_epoch: EpochId,
    snapshot_name: String,
    attempt_count: u64,
}

enum ScheduledAutoCommitReplay {
    Staged,
    NotApplicable,
}

impl<S: StorageProvider> Engine<S> {
    pub(crate) async fn ingest_welcome(
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

    pub(crate) async fn ingest_group_message(
        &mut self,
        msg: &TransportMessage,
        transport_group_id: Vec<u8>,
    ) -> Result<IngestOutcome, EngineError> {
        let group_id = self.group_id_for_transport_group_id(&transport_group_id)?;
        let mut pending_recovery: Option<(
            EpochId,
            CommitOrderingKey,
            CommitOrderingKey,
            MessageId,
        )> = None;

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
            let raw_msg_id = msg.id.clone();
            let msg_id_hex = hex::encode(raw_msg_id.as_slice());
            let peel_result = self.peeler.peel_group_message(msg, &ctx).await;
            // Plain decrypt misses are expected for future epochs, pre-join
            // messages, and retained-snapshot fallback. The terminal state
            // transition below is the useful audit breadcrumb for no-snapshot
            // deferrals; logging every raw miss here swamps Goggles with
            // routine retry noise.
            if !matches!(&peel_result, Err(PeelerError::DecryptFailed)) {
                let raw_outcome = match &peel_result {
                    Ok(_) => marmot_forensics::PeelerOutcomeKind::Success,
                    Err(PeelerError::StaleEpoch { .. }) => {
                        marmot_forensics::PeelerOutcomeKind::StaleEpoch
                    }
                    Err(PeelerError::Malformed(_)) => {
                        marmot_forensics::PeelerOutcomeKind::Malformed
                    }
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
            }
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

            // foundation/wire-envelopes.md + protocol-core/inbound-processing.md:
            // the canonical dedup/replay id MUST be stable for the carried
            // protocol bytes and MUST NOT depend on the transport event id. The
            // transport id only acts as the cheap pre-filter at the top of
            // `do_ingest`; the same MLS message re-wrapped in a fresh kind-445
            // envelope (new ephemeral key + nonce -> new transport id, which any
            // member can produce) MUST collapse to a single duplicate outcome.
            // Rebind every downstream storage / convergence / fork-recovery row
            // and the in-memory dedup sets to this content-derived id.
            let content_id = content_dedup_id(&mls_bytes);
            if let Some(outcome) = self.recorded_message_outcome(&content_id)? {
                return Ok(outcome);
            }
            if self.seen_message_ids.contains(&content_id) {
                return Ok(IngestOutcome::Stale {
                    reason: StaleReason::AlreadySeen,
                });
            }
            if self.sent_message_ids.contains(&content_id) {
                return Ok(IngestOutcome::Stale {
                    reason: StaleReason::OwnEcho,
                });
            }
            let content_msg = TransportMessage {
                id: content_id,
                ..msg.clone()
            };
            // Shadow `msg` for the remainder of the loop body so every
            // `persist_*`, `update_stored_message_state`, convergence buffer,
            // and fork-recovery storage id keys on the content-derived id. The
            // original transport `msg` is only read above the peel, before this
            // shadow, so a fork-recovery `continue` still re-peels the real
            // transport bytes.
            let msg = &content_msg;
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
            let commit_should_enter_convergence = if msg_content_type == ContentType::Commit {
                if msg_epoch >= current_epoch {
                    true
                } else {
                    let policy = self.convergence_policy_for_group(&group_id).map_err(|e| {
                        EngineError::Backend(format!("load convergence policy: {e}"))
                    })?;
                    let within_rewind_horizon = current_epoch.0.saturating_sub(msg_epoch.0)
                        <= policy.convergence.max_rewind_commits;
                    within_rewind_horizon
                        && !self.epoch_manager.we_committed_from(&group_id, msg_epoch)
                        && self.has_retained_anchor_snapshot(&group_id, msg_epoch)?
                }
            } else {
                false
            };
            if pending_recovery.is_none() && commit_should_enter_convergence {
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
                Err(e) if process_message_error_is_too_distant_in_the_past(&e) => {
                    self.update_stored_message_state(&msg.id, MessageState::Failed)?;
                    self.mark_raw_transport_message_failed_if_deferred(
                        &raw_msg_id,
                        "too_distant_in_the_past",
                    )?;
                    return Ok(IngestOutcome::Stale {
                        reason: StaleReason::PeelFailed,
                    });
                }
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
                                invalidated_storage_id,
                            } => {
                                pending_recovery =
                                    Some((msg_epoch, winner, invalidated, invalidated_storage_id));
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
                    // In-memory fast path mirrors the durable record, keyed on
                    // the content-derived id so a re-wrapped duplicate is caught
                    // before the durable lookup.
                    self.seen_message_ids.insert(msg.id.clone());
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
                    // Reject (pre-merge) a commit whose resulting epoch would list an
                    // admin key with no member leaf — e.g. removing an account's last
                    // leaf without dropping it from `admins`. admin-policy-v1.md.
                    if let Err(err) =
                        crate::app_components::validate_admin_leaf_coupling_for_staged_commit(
                            &mls_group, &group_id, &staged,
                        )
                    {
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
                    // foundation/identity.md: reject inbound commits that
                    // introduce or mutate a member LeafNode whose credential
                    // identity is invalid, lacks a valid account proof, or no
                    // longer matches the member identity being updated.
                    let added = match crate::account_identity_proof::validate_staged_commit_account_identity_proofs(
                        &staged,
                        &mls_group,
                        &commit_committer,
                        self.ciphersuite,
                    ) {
                        Ok(added) => added,
                        Err(err) => {
                            self.update_stored_message_state(&msg.id, MessageState::Failed)?;
                            return Err(err);
                        }
                    };
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
                    let before_message_retention =
                        crate::app_components::message_retention_seconds_of_group(&mls_group)?;
                    self.retain_current_epoch_snapshot_for_group(&group_id)?;
                    // Extract capabilities from Add proposals before the
                    // staged commit is consumed by merge.
                    crate::capability_manager::cache_from_staged_commit(
                        &self.storage,
                        &group_id,
                        &staged,
                        self.ciphersuite,
                    )?;
                    self.storage.with_transaction(|storage| {
                        let tx_provider =
                            EngineOpenMlsProvider::<S>::new(&self.crypto, storage.mls_storage());
                        mls_group
                            .merge_staged_commit(&tx_provider, *staged)
                            .map_err(|e| {
                                EngineError::Backend(format!("merge_staged_commit: {e:?}"))
                            })
                    })?;
                    let after = EpochId(mls_group.epoch().as_u64());
                    let after_members = group_lifecycle::marmot_members(&mls_group);
                    let after_admins =
                        crate::app_components::admins_of_group(&mls_group).unwrap_or_default();
                    let after_profile = crate::app_components::group_profile_of_group(&mls_group)
                        .ok()
                        .flatten();
                    let after_avatar = avatar_component_snapshot(&mls_group);
                    let after_message_retention =
                        crate::app_components::message_retention_seconds_of_group(&mls_group)?;
                    let after_ids: std::collections::HashSet<MemberId> =
                        after_members.iter().map(|m| m.id.clone()).collect();
                    let removed: Vec<MemberId> = before_members
                        .into_iter()
                        .filter_map(|m| (!after_ids.contains(&m.id)).then_some(m.id))
                        .collect();

                    // Update our per-group state machine + storage mirror.
                    self.epoch_manager.set_stable(group_id.clone(), after);
                    self.drop_self_remove_auto_commit_schedules_for_group(&group_id);
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
                    self.prune_fork_recovery_for_group(&group_id)?;

                    if let Some((source_epoch, winner, invalidated, invalidated_commit_id)) =
                        pending_recovery.take()
                    {
                        self.events_buf.push_back(GroupEvent::ForkRecovered {
                            group_id: group_id.clone(),
                            source_epoch,
                            recovered_epoch: after,
                            winner,
                            invalidated,
                            invalidated_commit_id,
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
                    // All rows from this commit carry its transport id so they
                    // can be invalidated together if the commit later loses a
                    // fork and is rolled back.
                    let origin_commit_id = Some(msg.id.clone());
                    for member in added {
                        self.push_group_state_change(
                            &group_id,
                            after,
                            sender_id.clone(),
                            GroupStateChange::MemberAdded { member },
                            origin_commit_id.clone(),
                        );
                    }
                    if removed
                        .iter()
                        .any(|member| member == self.identity.self_id())
                    {
                        self.clear_leave_request_state(&group_id)?;
                    } else if after_ids.contains(self.identity.self_id()) {
                        if self.load_leave_request_state(&group_id)?.is_some() {
                            // A SelfRemove proposal is valid only in its
                            // source epoch, but the local leave request is not.
                            // Keep the send gate and publish a fresh proposal
                            // for the accepted epoch.
                            self.leaving_groups.insert(group_id.clone());
                            self.try_auto_repropose_leave_request(&group_id).await;
                        } else if self.leaving_groups.contains(&group_id) {
                            // Compatibility cleanup for a pre-durable in-memory
                            // gate that survived until an unrelated accepted
                            // commit kept us in the group.
                            self.leaving_groups.remove(&group_id);
                        }
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
                        self.push_group_state_change(
                            &group_id,
                            after,
                            actor,
                            change,
                            origin_commit_id.clone(),
                        );
                    }
                    for change in
                        crate::group_state_changes::admin_changes(&before_admins, &after_admins)
                    {
                        self.push_group_state_change(
                            &group_id,
                            after,
                            sender_id.clone(),
                            change,
                            origin_commit_id.clone(),
                        );
                    }
                    for change in crate::group_state_changes::profile_changes(
                        before_profile.as_ref().map(|(name, _)| name.as_str()),
                        after_profile.as_ref().map(|(name, _)| name.as_str()),
                        &before_avatar,
                        &after_avatar,
                    ) {
                        self.push_group_state_change(
                            &group_id,
                            after,
                            sender_id.clone(),
                            change,
                            origin_commit_id.clone(),
                        );
                    }
                    for change in crate::group_state_changes::message_retention_changes(
                        before_message_retention,
                        after_message_retention,
                    ) {
                        self.push_group_state_change(
                            &group_id,
                            after,
                            sender_id.clone(),
                            change,
                            origin_commit_id.clone(),
                        );
                    }
                    self.update_stored_message_state(&msg.id, MessageState::Processed)?;
                    // In-memory fast path mirrors the durable record, keyed on
                    // the content-derived id so a re-wrapped duplicate commit is
                    // caught before the durable lookup.
                    self.seen_message_ids.insert(msg.id.clone());
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
                    if matches!(
                        decision_report.decision,
                        crate::auto_committer::AutoCommitDecision::Commit
                    ) {
                        self.schedule_self_remove_auto_commit(
                            &group_id,
                            &msg.id,
                            msg_epoch,
                            self.convergence_now_ms(),
                        )?;
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

    pub(crate) async fn stage_due_self_remove_auto_commit(
        &mut self,
        group_id: &GroupId,
        now_ms: u64,
    ) -> Result<bool, EngineError> {
        if self.load_leave_request_state(group_id)?.is_some() {
            self.drop_self_remove_auto_commit_schedules_for_group(group_id);
            return Ok(false);
        }
        if let Some(state) = self.epoch_manager.state(group_id)
            && !state.is_stable()
        {
            if self
                .scheduled_self_remove_auto_commits
                .values()
                .any(|scheduled| &scheduled.group_id == group_id)
            {
                self.schedule_pending_convergence_group(group_id);
            }
            return Ok(false);
        }

        loop {
            let Some(schedule) = self
                .scheduled_self_remove_auto_commits
                .values()
                .filter(|scheduled| &scheduled.group_id == group_id)
                .min_by_key(|scheduled| scheduled.due_at_ms)
                .cloned()
            else {
                return Ok(false);
            };
            if schedule.due_at_ms > now_ms {
                self.schedule_pending_convergence_group(group_id);
                return Ok(false);
            }

            self.scheduled_self_remove_auto_commits
                .remove(&schedule.proposal_id);
            match self
                .replay_scheduled_self_remove_auto_commit(schedule)
                .await?
            {
                ScheduledAutoCommitReplay::Staged => {
                    self.drop_self_remove_auto_commit_schedules_for_group(group_id);
                    return Ok(true);
                }
                ScheduledAutoCommitReplay::NotApplicable => continue,
            }
        }
    }

    async fn replay_scheduled_self_remove_auto_commit(
        &mut self,
        schedule: ScheduledSelfRemoveAutoCommit,
    ) -> Result<ScheduledAutoCommitReplay, EngineError> {
        let group = match self.storage.get_group(&schedule.group_id) {
            Ok(group) => group,
            Err(StorageError::NotFound) => return Ok(ScheduledAutoCommitReplay::NotApplicable),
            Err(err) => return Err(EngineError::Storage(err)),
        };
        if group.epoch != schedule.source_epoch {
            return Ok(ScheduledAutoCommitReplay::NotApplicable);
        }

        let record = match self.storage.get_message(&schedule.proposal_id) {
            Ok(record) => record,
            Err(StorageError::NotFound) => return Ok(ScheduledAutoCommitReplay::NotApplicable),
            Err(err) => return Err(EngineError::Storage(err)),
        };
        if !matches!(
            record.state,
            MessageState::Created | MessageState::Retryable
        ) {
            return Ok(ScheduledAutoCommitReplay::NotApplicable);
        }

        let Ok(stored_payload) = StoredMessagePayload::decode(&record.payload) else {
            return Ok(ScheduledAutoCommitReplay::NotApplicable);
        };
        let Some(message) = stored_payload.as_openmls_wire() else {
            return Ok(ScheduledAutoCommitReplay::NotApplicable);
        };
        let Ok(projection) = project_mls_message(&message.payload) else {
            return Ok(ScheduledAutoCommitReplay::NotApplicable);
        };
        if projection.kind != OpenMlsContentKind::Proposal
            || projection.source_epoch != Some(schedule.source_epoch.0)
        {
            return Ok(ScheduledAutoCommitReplay::NotApplicable);
        }

        let msg_in = MlsMessageIn::tls_deserialize_exact(message.payload.as_slice())
            .map_err(|e| EngineError::Serialize(format!("message deserialize: {e:?}")))?;
        let proto: ProtocolMessage = match msg_in.extract() {
            MlsMessageBodyIn::PrivateMessage(p) => p.into(),
            MlsMessageBodyIn::PublicMessage(p) => p.into(),
            _ => return Ok(ScheduledAutoCommitReplay::NotApplicable),
        };

        let (mut mls_group, queued) = {
            let provider =
                EngineOpenMlsProvider::<S>::new(&self.crypto, self.storage.mls_storage());
            let mls_gid = openmls::group::GroupId::from_slice(schedule.group_id.as_slice());
            let mut mls_group = MlsGroup::load(
                <EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::storage(
                    &provider,
                ),
                &mls_gid,
            )
            .map_err(|e| EngineError::Backend(format!("load auto-commit replay: {e:?}")))?
            .ok_or_else(|| EngineError::UnknownGroup(schedule.group_id.clone()))?;
            if EpochId(mls_group.epoch().as_u64()) != schedule.source_epoch {
                return Ok(ScheduledAutoCommitReplay::NotApplicable);
            }

            let processed = match mls_group.process_message(&provider, proto) {
                Ok(processed) => processed,
                Err(_) => return Ok(ScheduledAutoCommitReplay::NotApplicable),
            };
            let queued = match processed.into_content() {
                ProcessedMessageContent::ProposalMessage(queued)
                    if matches!(queued.proposal(), Proposal::SelfRemove) =>
                {
                    queued
                }
                _ => return Ok(ScheduledAutoCommitReplay::NotApplicable),
            };
            (mls_group, queued)
        };

        if self
            .stage_auto_commit_for_queued_proposal(&schedule.group_id, &mut mls_group, queued)
            .await?
        {
            Ok(ScheduledAutoCommitReplay::Staged)
        } else {
            Ok(ScheduledAutoCommitReplay::NotApplicable)
        }
    }

    async fn stage_auto_commit_for_queued_proposal(
        &mut self,
        group_id: &GroupId,
        mls_group: &mut MlsGroup,
        queued: Box<QueuedProposal>,
    ) -> Result<bool, EngineError> {
        let decision_report = crate::auto_committer::decide_with_reason(mls_group, &queued);
        let decision_str = match &decision_report.decision {
            crate::auto_committer::AutoCommitDecision::Commit => "commit",
            crate::auto_committer::AutoCommitDecision::Observe => "observe",
        };
        self.audit_group(
            group_id,
            marmot_forensics::AuditEventKind::AutoCommitDecision {
                proposal_kind: crate::audit_helpers::proposal_kind_str(queued.proposal())
                    .to_string(),
                decision: decision_str.to_string(),
                reason: Some(decision_report.reason.to_string()),
            },
        );
        if !matches!(
            decision_report.decision,
            crate::auto_committer::AutoCommitDecision::Commit
        ) {
            return Ok(false);
        }

        let auto_removed: Vec<MemberId> = match queued.proposal() {
            Proposal::Remove(r) => member_id_at_leaf(mls_group, r.removed())
                .into_iter()
                .collect(),
            Proposal::SelfRemove => member_id_of_sender(queued.sender(), mls_group)
                .into_iter()
                .collect(),
            _ => Vec::new(),
        };
        let auto_is_self_remove = matches!(queued.proposal(), Proposal::SelfRemove);
        let auto_proposer = member_id_of_sender(queued.sender(), mls_group);
        let auto_proposal_kind =
            crate::audit_helpers::proposal_kind_str(queued.proposal()).to_string();

        let is_stable = self
            .epoch_manager
            .state(group_id)
            .is_none_or(|s| s.is_stable());
        if !is_stable {
            self.audit_group(
                group_id,
                marmot_forensics::AuditEventKind::AutoCommitDecision {
                    proposal_kind: auto_proposal_kind,
                    decision: "observe".to_string(),
                    reason: Some("group_not_stable".to_string()),
                },
            );
            self.schedule_pending_convergence_group(group_id);
            return Ok(false);
        }

        let provider = EngineOpenMlsProvider::<S>::new(&self.crypto, self.storage.mls_storage());
        mls_group
            .store_pending_proposal(
                <EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::storage(
                    &provider,
                ),
                *queued,
            )
            .map_err(|e| EngineError::Backend(format!("store_pending: {e:?}")))?;

        let pre_commit_epoch = EpochId(mls_group.epoch().as_u64());
        let mut pending_commit_guard =
            PendingCommitCleanupGuard::arm(&self.storage, &provider, group_id.clone());
        let recovery_snapshot =
            self.fork_recovery
                .create_snapshot(&self.storage, group_id, pre_commit_epoch)?;
        pending_commit_guard.set_snapshot(recovery_snapshot.clone());
        self.audit_snapshot_created(
            group_id,
            &recovery_snapshot,
            pre_commit_epoch,
            "pre_auto_commit",
        );
        let pre_commit_ctx = group_lifecycle::build_group_context_snapshot(mls_group, &provider)?;
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
            group_id,
            pre_commit_epoch,
        )?;

        let new_epoch = EpochId(pre_commit_epoch.0.saturating_add(1));
        if let Ok(mut g) = self.storage.get_group(group_id) {
            g.epoch = new_epoch;
            g.members
                .retain(|member| !auto_removed.iter().any(|id| id == &member.id));
            self.storage.put_group(&g)?;
        }

        let commit_priority = mls_group
            .pending_commit()
            .map(crate::app_components::commit_ordering_priority_for_staged)
            .ok_or_else(|| EngineError::Backend("auto-commit produced no pending commit".into()))?;
        let pending_ref = self.epoch_manager.next_pending_ref();
        let staged =
            cgka_traits::engine_state::StagedCommitHandle::from_bytes(group_id.as_slice().to_vec());
        self.epoch_manager.begin_pending(
            group_id.clone(),
            pre_commit_epoch,
            new_epoch,
            staged,
            pending_ref,
            crate::epoch_manager::PendingKind::GroupEvolution,
            self.current_audit_context.clone(),
        )?;
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
        pending_commit_guard.disarm();
        Ok(true)
    }

    fn mark_raw_transport_message_failed_if_deferred(
        &self,
        raw_msg_id: &MessageId,
        reason: &str,
    ) -> Result<(), EngineError> {
        match self.storage.get_message(raw_msg_id) {
            Ok(record) if record.state == MessageState::PeelDeferred => {
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
                Ok(())
            }
            Ok(_) | Err(StorageError::NotFound) => Ok(()),
            Err(err) => Err(EngineError::Storage(err)),
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

    fn has_retained_anchor_snapshot(
        &self,
        group_id: &GroupId,
        epoch: EpochId,
    ) -> Result<bool, EngineError> {
        for snapshot_name in self.storage.list_group_snapshots(group_id)? {
            if retained_anchor_epoch_from_snapshot_name(&snapshot_name) == Some(epoch.0) {
                return Ok(true);
            }
        }
        Ok(false)
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
}

fn process_message_error_is_too_distant_in_the_past<E>(err: &ProcessMessageError<E>) -> bool {
    matches!(
        err,
        ProcessMessageError::ValidationError(ValidationError::NoPastEpochData)
            | ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(
                MessageDecryptionError::SecretTreeError(SecretTreeError::TooDistantInThePast),
            ))
    )
}

/// Snapshot the two avatar-bearing component byte blobs (avatar-url and
/// blossom-image) so a before/after comparison can detect an avatar change.
///
/// Presence is normalized: an absent component (`None`) and the canonical
/// "absent" encoding both collapse to `None`, so this inbound diff matches the
/// own-commit diff in `update_group_data` and a "clear an already-absent
/// avatar" commit converges to no row on every client.
pub(crate) fn avatar_component_snapshot(mls_group: &MlsGroup) -> [Option<Vec<u8>>; 2] {
    let snapshot = |component_id| {
        crate::app_components::app_component_data_of_group(mls_group, component_id)
            .filter(|bytes| crate::app_components::avatar_component_present(component_id, bytes))
    };
    [
        snapshot(cgka_traits::app_components::GROUP_AVATAR_URL_COMPONENT_ID),
        snapshot(cgka_traits::app_components::GROUP_BLOSSOM_IMAGE_COMPONENT_ID),
    ]
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
