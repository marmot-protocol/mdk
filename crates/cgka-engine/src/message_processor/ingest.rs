//! Inbound ingest path for [`Engine`]: peel, classify, apply or buffer.
//!
//! Inbound messages are peeled, classified, stored, and either applied or
//! buffered for convergence. Routing/dedup exclusions, local canonical state,
//! stale convergence input, and authenticated proposal rejection are distinct
//! typed outcomes. `Err` is reserved for storage, peeler, serialization, and
//! unclassified OpenMLS failures.

use super::{content_dedup_id, route_wrapped_group_message};
use crate::engine::{Engine, ScheduledSelfRemoveAutoCommit};
use crate::group_lifecycle::{self};
use crate::identity::member_id_of_sender;
use crate::openmls_projection::{
    OpenMlsContentKind, process_commit_with_app_data_updates, project_mls_message,
    retained_anchor_epoch_from_snapshot_name,
};
use crate::pending_commit_guard::PendingCommitCleanupGuard;
use crate::provider::EngineOpenMlsProvider;
use crate::snapshot_guard::SnapshotRollbackGuard;
use cgka_traits::app_event::AppMessageRetentionDecision;
use cgka_traits::engine::{AutoPublish, GroupEvent, GroupStateChange};
use cgka_traits::error::{EngineError, PeelerError};
use cgka_traits::ingest::{
    InboundResourceLimit, IngestOutcome, InputRejectionCategory, LocalIngestState, PeeledContent,
    ProposalRejectionCategory, StaleReason,
};
use cgka_traits::message::{MessageState, StoredMessagePayload};
use cgka_traits::storage::{StorageError, StorageProvider};
use cgka_traits::transport::{EncryptedPayload, TransportMessage};
use cgka_traits::types::{EpochId, GroupId, MemberId, MessageId};
use openmls::framing::errors::{MessageDecryptionError, SecretTreeError};
use openmls::group::{MlsGroup, MlsGroupStateError, ProcessMessageError};
use openmls::prelude::{
    ContentType, MlsMessageBodyIn, MlsMessageIn, ProcessedMessageContent, Proposal,
    ProtocolMessage, QueuedProposal, Sender, ValidationError,
};
use sha2::{Digest, Sha256};
use tls_codec::{Deserialize as _, Serialize as _};

struct PastPeelRecovery {
    peeled: cgka_traits::ingest::PeeledMessage,
    source_epoch: EpochId,
    message_retention_seconds: Option<u64>,
    snapshot_name: String,
    attempt_count: u64,
}

struct RetainedSelfRemoveProposal {
    leaf: openmls::prelude::LeafNodeIndex,
    digest: [u8; 32],
    queued: QueuedProposal,
}

/// What an applied inbound commit changed, derived from the merged group state.
///
/// Produced inside the apply transaction because the durable record mirror is
/// written from the same values the post-apply events are synthesized from.
struct AppliedCommitProjection {
    epoch: EpochId,
    remaining_member_ids: std::collections::HashSet<MemberId>,
    removed_member_ids: Vec<MemberId>,
    message_retention_seconds: Option<u64>,
}

enum ScheduledAutoCommitReplay {
    Staged,
    NotApplicable,
}

impl<S: StorageProvider> Engine<S> {
    fn terminalize_rejected_proposal(
        &mut self,
        group_id: &GroupId,
        msg_id: &MessageId,
        raw_msg_id: Option<&MessageId>,
        category: ProposalRejectionCategory,
    ) -> Result<IngestOutcome, EngineError> {
        let reason = crate::app_components::proposal_rejection_category_tag(category);
        self.update_stored_message_state(msg_id, MessageState::Failed)?;
        if let Some(raw_msg_id) = raw_msg_id {
            self.mark_raw_transport_message_failed_if_awaiting_retry(raw_msg_id, reason)?;
        }
        self.audit_group(
            group_id,
            marmot_forensics::AuditEventKind::Rejection {
                msg_id: hex::encode(msg_id.as_slice()),
                reason: reason.to_string(),
            },
        );
        Ok(IngestOutcome::Rejected { category })
    }

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
            return Ok(IngestOutcome::Ignored {
                category: InputRejectionCategory::WrongRecipient,
            });
        }

        // Reuse the existing join_welcome machinery. Any classifiable failure
        // for this individual welcome is terminal input, not a failure of the
        // transport drain: persist an account-scoped marker even when no group
        // id could be recovered, then return a typed stale outcome. Storage and
        // truly internal transition failures still propagate.
        match self.do_join_welcome(msg.clone()).await {
            Ok(gid) => {
                self.persist_transport_message(msg, &gid, EpochId(0), MessageState::Processed)?;
                Ok(IngestOutcome::Processed)
            }
            Err(EngineError::WelcomeAlreadyProcessed) => {
                self.storage.put_ingress_dedup_marker(&msg.id)?;
                Ok(IngestOutcome::Ignored {
                    category: InputRejectionCategory::Duplicate,
                })
            }
            Err(EngineError::Peeler(PeelerError::WrongRecipient)) => {
                self.storage.put_ingress_dedup_marker(&msg.id)?;
                Ok(IngestOutcome::Ignored {
                    category: InputRejectionCategory::WrongRecipient,
                })
            }
            Err(error) if group_lifecycle::terminal_welcome_error(&error) => {
                self.storage.put_ingress_dedup_marker(&msg.id)?;
                let category = match error {
                    EngineError::Peeler(PeelerError::InvalidSignature)
                    | EngineError::InvalidCredentialIdentity(_)
                    | EngineError::InvalidAccountIdentityProof(_) => {
                        InputRejectionCategory::InvalidSignature
                    }
                    EngineError::MissingRequiredCapabilities { .. } => {
                        InputRejectionCategory::UnsupportedRequiredFeature
                    }
                    EngineError::NotGroupAdmin { .. } => {
                        InputRejectionCategory::AuthorizationFailed
                    }
                    _ => InputRejectionCategory::InvalidEncoding,
                };
                Ok(IngestOutcome::Ignored { category })
            }
            Err(other) => Err(other),
        }
    }

    pub(crate) async fn ingest_group_message(
        &mut self,
        msg: &TransportMessage,
        transport_group_id: Vec<u8>,
    ) -> Result<IngestOutcome, EngineError> {
        let group_id = self.resolve_or_backfill_group_id_for_transport(&transport_group_id)?;

        // Authenticated terminal evidence is permanent. Drop late traffic
        // before the missing-OpenMLS fallback can retain it as retryable
        // unknown-group input.
        if self.storage.disband_tombstone(&group_id)?.is_some() {
            self.storage.put_ingress_dedup_marker(&msg.id)?;
            return Ok(IngestOutcome::Ignored {
                category: InputRejectionCategory::UnknownGroup,
            });
        }

        // mdk#1161: an inbound message for a seeded-but-unhydrated group runs
        // that group's full hydration first, so the peel below sees validated
        // live state. A hydration failure quarantines the group and the
        // quarantine gate below retains this input for post-repair replay.
        let _ = self.ensure_hydrated(&group_id);

        // Quarantine gate (mdk#364): a group frozen by hydration
        // quarantine must not process any input — its OpenMLS state may load
        // fine (e.g. MemberValidationFailed) and a merged commit would call
        // set_stable, silently re-activating a group validation rejected.
        // Retain the raw transport durably instead: PeelDeferred rows are
        // excluded from settlement math and replay through
        // retry_deferred_peels once repair clears the quarantine.
        if self.quarantined_reason(&group_id).is_some() {
            let already_retained = matches!(
                self.storage.get_message(&msg.id),
                Ok(record) if record.state == MessageState::PeelDeferred
            );
            if already_retained || self.has_peel_deferred_capacity(&group_id)? {
                self.persist_transport_message_for_existing_group(
                    msg,
                    &group_id,
                    EpochId(0),
                    MessageState::PeelDeferred,
                )?;
                if !already_retained {
                    self.note_peel_deferred_row_persisted(&group_id);
                }
                self.audit_group(
                    &group_id,
                    crate::audit_helpers::message_state_changed_event(
                        hex::encode(msg.id.as_slice()),
                        MessageState::PeelDeferred,
                        crate::message_disposition::MessageDisposition::Quarantined.tag(),
                    ),
                );
            } else {
                self.retryable_unpersisted_ingest_id = Some(msg.id.clone());
                if self.should_audit_peel_deferred_cap_rejection(&group_id) {
                    // Same flood cap as the deferral seam (mdk#339): a
                    // quarantined group's replay buffer must not grow
                    // unboundedly either. Audited once per cap-full episode so
                    // a flood does not emit one write per rejected message.
                    self.audit_group(
                        &group_id,
                        marmot_forensics::AuditEventKind::Rejection {
                            msg_id: hex::encode(msg.id.as_slice()),
                            reason: crate::message_disposition::MessageDisposition::DeferredCapacityRefused
                                .tag()
                                .to_string(),
                        },
                    );
                }
                return Ok(IngestOutcome::ResourceRefused {
                    group_id,
                    resource: InboundResourceLimit::TransportDeferredCapacity,
                });
            }
            return Ok(IngestOutcome::LocalState {
                state: LocalIngestState::Quarantined,
            });
        }

        // mdk#971: sync a durable Unrecoverable halt into memory before the
        // can_ingest gate so a restart cannot accept group-state changes on an
        // unrepaired base. Runs before the OpenMLS provider borrow below.
        let _ = self.sync_unrecoverable_halt_from_storage(&group_id)?;

        // Load MlsGroup from storage.
        let provider = EngineOpenMlsProvider::<S>::new(&self.crypto, self.storage.mls_storage());
        let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
        let mut mls_group = match MlsGroup::load(
            <EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::storage(&provider),
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
                // Unknown-group traffic is deliberately not retained when
                // no group row exists (#740: unknown-route floods must
                // not consume storage), so this ignore is not terminal
                // evidence either. Keep the id out of the in-memory seen
                // cache: if this client later joins the group (a Welcome
                // that raced behind its commits), relay redelivery of the
                // same event must process instead of classifying as a
                // duplicate of a message that left no durable record.
                self.retryable_unpersisted_ingest_id = Some(msg.id.clone());
                return Ok(IngestOutcome::Ignored {
                    category: InputRejectionCategory::UnknownGroup,
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
            // The persisted OpenMLS group state is `Inactive`: retained
            // canonical state records our own removal. This is
            // authenticated evidence (a merged commit removed our leaf),
            // not a decrypt failure, so later input for this group is
            // `SelfEvicted` and must perform "realizing removal" when not
            // already done (member-departure.md), instead of classifying
            // as ordinary stale traffic while the group still presents as
            // active.
            self.persist_transport_message(msg, &group_id, current_epoch, MessageState::Failed)?;
            self.realize_self_eviction(&group_id, current_epoch)?;
            return Ok(IngestOutcome::LocalState {
                state: LocalIngestState::Removed,
            });
        }
        if !self.epoch_manager.can_ingest(&group_id) {
            self.persist_transport_message(msg, &group_id, current_epoch, MessageState::Retryable)?;
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
                Err(PeelerError::Malformed(_)) => marmot_forensics::PeelerOutcomeKind::Malformed,
                Err(PeelerError::InvalidSignature) => {
                    marmot_forensics::PeelerOutcomeKind::InvalidSignature
                }
                Err(PeelerError::WrongRecipient) => {
                    marmot_forensics::PeelerOutcomeKind::WrongRecipient
                }
                Err(_) => marmot_forensics::PeelerOutcomeKind::Other,
            };
            self.audit_group(
                &group_id,
                marmot_forensics::AuditEventKind::PeelerOutcome {
                    msg_id: msg_id_hex.clone(),
                    // Artifact kind is unknown until after the peel succeeds.
                    artifact_kind: None,
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
        let mut recovered_source_retention = None;
        let peeled = match peel_result {
            Ok(p) => p,
            Err(PeelerError::DecryptFailed) => {
                let recovered = match self
                    .try_peel_group_message_from_available_snapshots(msg, &group_id, current_epoch)
                    .await
                {
                    Ok(recovered) => recovered,
                    // Defense-in-depth for the public TransportPeeler
                    // contract: a malformed or invalid-signature verdict
                    // raised only by the snapshot fallback is terminal on
                    // this seam too — never an aborted drain (mdk#707). Not
                    // reachable via the production Nostr peeler (both
                    // checks are deterministic in the message bytes, so
                    // the direct peel catches them first); MissingContext /
                    // storage errors keep propagating as genuine engine
                    // faults.
                    Err(EngineError::Peeler(
                        rejection @ (PeelerError::Malformed(_) | PeelerError::InvalidSignature),
                    )) => {
                        let category = if matches!(rejection, PeelerError::InvalidSignature) {
                            InputRejectionCategory::InvalidSignature
                        } else {
                            InputRejectionCategory::InvalidEncoding
                        };
                        return self.terminal_peel_rejection_ignored(
                            &raw_msg_id,
                            &msg.id,
                            "malformed_payload_snapshot_fallback",
                            category,
                        );
                    }
                    Err(EngineError::Peeler(PeelerError::WrongRecipient)) => {
                        return self.terminal_peel_rejection_ignored(
                            &raw_msg_id,
                            &msg.id,
                            "wrong_recipient_snapshot_fallback",
                            InputRejectionCategory::WrongRecipient,
                        );
                    }
                    Err(e) => return Err(e),
                };
                if let Some(recovery) = recovered {
                    recovered_source_retention =
                        Some((recovery.source_epoch, recovery.message_retention_seconds));
                    self.audit_group(
                        &group_id,
                        marmot_forensics::AuditEventKind::PeelerOutcome {
                            msg_id: msg_id_hex.clone(),
                            artifact_kind: None,
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
                    // Flood cap (mdk#339): raw transport ids are
                    // attacker-controllable, so retained rows are capped
                    // per group; at the cap, new undecryptable input is
                    // dropped unpersisted and transport redelivery is the
                    // recovery path once the backlog drains.
                    let already_retained = matches!(
                        self.storage.get_message(&msg.id),
                        Ok(record) if record.state == MessageState::PeelDeferred
                    );
                    if !already_retained && !self.has_peel_deferred_capacity(&group_id)? {
                        self.retryable_unpersisted_ingest_id = Some(msg.id.clone());
                        if self.should_audit_peel_deferred_cap_rejection(&group_id) {
                            self.audit_group(
                                &group_id,
                                marmot_forensics::AuditEventKind::Rejection {
                                    msg_id: msg_id_hex.clone(),
                                    reason: crate::message_disposition::MessageDisposition::DeferredCapacityRefused
                                        .tag()
                                        .to_string(),
                                },
                            );
                        }
                        tracing::debug!(
                            target: "cgka_engine::message_processor",
                            method = "ingest_group_message",
                            "peel-deferred row cap reached; dropping undecryptable input unpersisted"
                        );
                        return Ok(IngestOutcome::ResourceRefused {
                            group_id,
                            resource: InboundResourceLimit::TransportDeferredCapacity,
                        });
                    }
                    self.persist_transport_message(
                        msg,
                        &group_id,
                        current_epoch,
                        MessageState::PeelDeferred,
                    )?;
                    if !already_retained {
                        self.note_peel_deferred_row_persisted(&group_id);
                    }
                    // A stable peel context may never change again. Keep
                    // the group scheduled so the durable residence
                    // deadline can retire this row without unrelated
                    // traffic.
                    self.schedule_pending_convergence_group(&group_id);
                    self.audit_group(
                        &group_id,
                        crate::audit_helpers::message_state_changed_event(
                            msg_id_hex.clone(),
                            MessageState::PeelDeferred,
                            crate::message_disposition::MessageDisposition::RetryPending.tag(),
                        ),
                    );
                    return Ok(IngestOutcome::TransportDeferred { group_id });
                }
            }
            Err(PeelerError::StaleEpoch {
                message_epoch,
                context_epoch,
            }) => {
                let recovered = match self
                    .try_peel_group_message_from_available_snapshots(msg, &group_id, current_epoch)
                    .await
                {
                    Ok(recovered) => recovered,
                    // Defense-in-depth for the public TransportPeeler
                    // contract: a malformed or invalid-signature verdict
                    // raised only by the snapshot fallback is terminal on
                    // this seam too — never an aborted drain (mdk#707). Not
                    // reachable via the production Nostr peeler (both
                    // checks are deterministic in the message bytes, so
                    // the direct peel catches them first); MissingContext /
                    // storage errors keep propagating as genuine engine
                    // faults.
                    Err(EngineError::Peeler(
                        rejection @ (PeelerError::Malformed(_) | PeelerError::InvalidSignature),
                    )) => {
                        let category = if matches!(rejection, PeelerError::InvalidSignature) {
                            InputRejectionCategory::InvalidSignature
                        } else {
                            InputRejectionCategory::InvalidEncoding
                        };
                        return self.terminal_peel_rejection_ignored(
                            &raw_msg_id,
                            &msg.id,
                            "malformed_payload_snapshot_fallback",
                            category,
                        );
                    }
                    Err(EngineError::Peeler(PeelerError::WrongRecipient)) => {
                        return self.terminal_peel_rejection_ignored(
                            &raw_msg_id,
                            &msg.id,
                            "wrong_recipient_snapshot_fallback",
                            InputRejectionCategory::WrongRecipient,
                        );
                    }
                    Err(e) => return Err(e),
                };
                if let Some(recovery) = recovered {
                    recovered_source_retention =
                        Some((recovery.source_epoch, recovery.message_retention_seconds));
                    self.audit_group(
                        &group_id,
                        marmot_forensics::AuditEventKind::PeelerOutcome {
                            msg_id: msg_id_hex.clone(),
                            artifact_kind: None,
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
                    // Terminal peel failure. Retire the raw deferred row
                    // (if this came via the retry lifecycle) so it stops
                    // holding a per-group cap slot (mdk#339); a no-op on
                    // the direct path where no deferred row exists.
                    self.mark_raw_transport_message_failed_if_awaiting_retry(
                        &raw_msg_id,
                        "stale_epoch_no_snapshot",
                    )?;
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
                        reason: StaleReason::AlreadyAtEpoch {
                            current: context_epoch,
                            msg_epoch: message_epoch,
                        },
                    });
                }
            }
            Err(rejection @ (PeelerError::Malformed(_) | PeelerError::InvalidSignature)) => {
                // Structurally-invalid or unauthenticated content is
                // ordinary hostile input: anyone can publish to the
                // cleartext routing tag without group membership, and no
                // epoch context can ever make it valid. Terminal —
                // propagating an error here would abort the caller's whole
                // transport drain on one garbage event, starving every
                // message queued behind it. Dropped unpersisted for the
                // same reason as the mdk#339 flood cap: transport ids are
                // attacker-controllable, so durable rows keyed by them
                // would grow without bound. Retire the raw deferred row if
                // this arrived via the retry lifecycle; a no-op on the
                // direct path.
                let reason = if matches!(rejection, PeelerError::InvalidSignature) {
                    "invalid_signature"
                } else {
                    "malformed_payload"
                };
                let category = if matches!(rejection, PeelerError::InvalidSignature) {
                    InputRejectionCategory::InvalidSignature
                } else {
                    InputRejectionCategory::InvalidEncoding
                };
                return self.terminal_peel_rejection_ignored(
                    &raw_msg_id,
                    &msg.id,
                    reason,
                    category,
                );
            }
            Err(PeelerError::WrongRecipient) => {
                return self.terminal_peel_rejection_ignored(
                    &raw_msg_id,
                    &msg.id,
                    "wrong_recipient",
                    InputRejectionCategory::WrongRecipient,
                );
            }
            Err(e) => return Err(EngineError::Peeler(e)),
        };
        let mls_bytes = match peeled.content {
            PeeledContent::MlsMessage { bytes } => bytes,
            PeeledContent::Welcome { .. } => {
                // A group-message envelope that peels to a Welcome is
                // malformed: terminal. Retire the raw deferred row first
                // so its cap slot is released (mdk#339).
                self.mark_raw_transport_message_failed_if_awaiting_retry(
                    &raw_msg_id,
                    "peeled_welcome_in_group_message",
                )?;
                self.persist_transport_message(
                    msg,
                    &group_id,
                    current_epoch,
                    MessageState::Failed,
                )?;
                return Ok(IngestOutcome::Ignored {
                    category: InputRejectionCategory::InvalidEncoding,
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
            return Ok(IngestOutcome::Ignored {
                category: InputRejectionCategory::Duplicate,
            });
        }
        if self.sent_message_ids.contains(&content_id) {
            return Ok(IngestOutcome::Ignored {
                category: InputRejectionCategory::OwnEcho,
            });
        }
        let content_msg = TransportMessage {
            id: content_id,
            ..msg.clone()
        };
        // Shadow `msg` for the remainder of this function so every
        // `persist_*`, `update_stored_message_state`, and convergence-buffer
        // storage id keys on the content-derived id. The original transport
        // `msg` is only read above the peel, before this shadow.
        let msg = &content_msg;
        let openmls_msg = TransportMessage {
            payload: mls_bytes.clone(),
            ..msg.clone()
        };

        // Parse into ProtocolMessage. Grab its epoch before process_message
        // consumes it — we need it for the fork-detection branch below.
        let msg_in = match MlsMessageIn::tls_deserialize_exact(mls_bytes.as_slice()) {
            Ok(msg_in) => msg_in,
            Err(_) => {
                // The transport envelope authenticated successfully, but
                // a member is still free to wrap arbitrary bytes. Treat a
                // structurally invalid MLS message as terminal hostile
                // input: returning `Err` here aborts the transport drain
                // and lets the same poison event redeliver forever.
                self.persist_openmls_wire_message(
                    &openmls_msg,
                    &group_id,
                    current_epoch,
                    MessageState::Failed,
                )?;
                self.mark_raw_transport_message_failed_if_awaiting_retry(
                    &raw_msg_id,
                    "malformed_mls_message",
                )?;
                return Ok(IngestOutcome::Ignored {
                    category: InputRejectionCategory::InvalidEncoding,
                });
            }
        };
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
                // Peeled successfully but the MLS body is neither a
                // public nor private message: terminal. Retire the raw
                // deferred row so it leaves the retry lifecycle (mdk#339).
                self.mark_raw_transport_message_failed_if_awaiting_retry(
                    &raw_msg_id,
                    "non_mls_message_body",
                )?;
                return Ok(IngestOutcome::Ignored {
                    category: InputRejectionCategory::InvalidEncoding,
                });
            }
        };

        let msg_epoch = EpochId(proto.epoch().as_u64());
        let msg_content_type = proto.content_type();

        // Pre-membership classification (mdk#339): an application
        // message whose MLS epoch precedes this device's join epoch can
        // never be decrypted here by design — OpenMLS holds no secrets
        // for epochs before the welcome. Classify it terminal before any
        // OpenMLS processing instead of feeding it the retry lifecycle.
        if msg_content_type == ContentType::Application
            && msg_epoch < current_epoch
            && self.msg_is_pre_membership(&group_id, msg_epoch)
        {
            let tag = crate::message_disposition::MessageDisposition::PreMembershipEvent.tag();
            self.persist_openmls_wire_message(
                &openmls_msg,
                &group_id,
                current_epoch,
                MessageState::Failed,
            )?;
            self.audit_group(
                &group_id,
                crate::audit_helpers::message_state_changed_event(
                    hex::encode(msg.id.as_slice()),
                    MessageState::Failed,
                    tag,
                ),
            );
            self.mark_raw_transport_message_failed_if_awaiting_retry(&raw_msg_id, tag)?;
            return Ok(IngestOutcome::Stale {
                reason: StaleReason::PreMembership,
            });
        }

        // Set when convergence admission is refused ONLY because the
        // fork-source anchor snapshot is gone. Within the rewind horizon
        // that absence is abnormal by construction — every canonical
        // advance retains a source-epoch anchor and pruning runs only
        // beyond the horizon — so the WrongEpoch arm below must fail
        // closed loudly instead of silently classifying the rival stale.
        // Commits forking from before this device's join epoch are the
        // one legitimate in-horizon absence and keep the stale fallback.
        //
        // One rule for every member: an in-horizon rival commit enters
        // distributed convergence whether or not this device is itself
        // the committer that advanced past the rival's source epoch. Own
        // commits materialize inside the pass from their commit-addressed
        // checkpoints, so a committer adjudicates its rival exactly like
        // an observer does.
        let mut convergence_refused_for_missing_anchor = false;
        let commit_should_enter_convergence = if msg_content_type == ContentType::Commit {
            if msg_epoch >= current_epoch {
                true
            } else {
                let policy = self
                    .convergence_policy_for_group(&group_id)
                    .map_err(|e| EngineError::Backend(format!("load convergence policy: {e}")))?;
                let within_rewind_horizon = current_epoch.0.saturating_sub(msg_epoch.0)
                    <= policy.convergence.max_rewind_commits;
                let active_pass = self
                    .storage
                    .convergence_pass(&group_id)?
                    .is_some_and(|pass| pass.is_active());
                let has_source_anchor = self.has_retained_anchor_snapshot(&group_id, msg_epoch)?;
                convergence_refused_for_missing_anchor = within_rewind_horizon
                    && !active_pass
                    && !has_source_anchor
                    && !self.msg_is_pre_membership(&group_id, msg_epoch);
                within_rewind_horizon && (active_pass || has_source_anchor)
            }
        } else {
            false
        };
        if commit_should_enter_convergence {
            let now = self.convergence_now();
            self.buffer_openmls_convergence_message_with_time(&group_id, openmls_msg.clone(), now)
                .map_err(|e| EngineError::Backend(format!("buffer convergence: {e}")))?;
            // The content-derived row is now the durable convergence witness;
            // a raw wrapper that arrived through the retry lifecycle has done
            // its job and must leave it instead of being re-peeled on every
            // later publish-cycle replay (mdk#339). No-op on the direct path.
            if raw_msg_id != msg.id {
                self.mark_raw_transport_message_processed_if_awaiting_retry(
                    &raw_msg_id,
                    "buffered_into_convergence",
                )?;
            }
            let result = self
                .converge_stored_openmls_messages_with_time(&group_id, now)
                .map_err(|e| EngineError::Backend(format!("converge: {e}")))?;
            return Ok(convergence_ingest_outcome(
                &result,
                msg,
                group_id,
                current_epoch,
            ));
        }
        if msg_content_type == ContentType::Application && msg_epoch > current_epoch {
            let now = self.convergence_now();
            self.buffer_openmls_convergence_message_with_time(&group_id, openmls_msg.clone(), now)
                .map_err(|e| EngineError::Backend(format!("buffer convergence: {e}")))?;
            // Same wrapper retirement as the commit branch above.
            if raw_msg_id != msg.id {
                self.mark_raw_transport_message_processed_if_awaiting_retry(
                    &raw_msg_id,
                    "buffered_into_convergence",
                )?;
            }
            let result = self
                .converge_stored_openmls_messages_with_time(&group_id, now)
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
                // Refine the historical classification (mdk#339):
                // before the join epoch the message was never decryptable
                // here by design; at or after it, this device was a
                // member but the past-epoch secrets are gone.
                let pre_membership = self.msg_is_pre_membership(&group_id, msg_epoch);
                let tag = if pre_membership {
                    crate::message_disposition::MessageDisposition::PreMembershipEvent.tag()
                } else {
                    crate::message_disposition::MessageDisposition::AppPayloadRetentionExpired.tag()
                };
                self.update_stored_message_state(&msg.id, MessageState::Failed)?;
                self.mark_raw_transport_message_failed_if_awaiting_retry(&raw_msg_id, tag)?;
                return Ok(IngestOutcome::Stale {
                    reason: if pre_membership {
                        StaleReason::PreMembership
                    } else {
                        StaleReason::BeyondAppRetention
                    },
                });
            }
            Err(ProcessMessageError::ValidationError(ValidationError::WrongEpoch)) => {
                let current = EpochId(mls_group.epoch().as_u64());

                // An in-horizon rival commit refused convergence admission
                // only because its fork-source anchor is gone SHOULD have
                // been adjudicated by distributed convergence. Falling
                // through to the stale fallback would retire the retained
                // row and leave our own (possibly losing) branch with
                // nothing recorded. Keep it loud and retained instead —
                // but derive no durable terminal state from it, because
                // `msg_epoch` is unauthenticated here by construction.
                if convergence_refused_for_missing_anchor {
                    // The retained content row is now the durable convergence
                    // witness for this rival and the group is scheduled for a
                    // pass; a raw wrapper that arrived through the retry
                    // lifecycle has done its job and leaves it the same way
                    // the convergence-buffer path retires it.
                    if raw_msg_id != msg.id {
                        self.mark_raw_transport_message_processed_if_awaiting_retry(
                            &raw_msg_id,
                            "fork_rival_missing_retained_anchor",
                        )?;
                    }
                    return self
                        .unadjudicable_fork_rival_without_anchor(group_id, &msg.id, current);
                }

                self.update_stored_message_state(&msg.id, MessageState::Failed)?;
                return Ok(IngestOutcome::Stale {
                    reason: StaleReason::AlreadyAtEpoch { current, msg_epoch },
                });
            }
            Err(ProcessMessageError::GroupStateError(MlsGroupStateError::UseAfterEviction)) => {
                // OpenMLS states authoritatively that our own leaf was
                // removed (the group state records eviction). Surface the
                // removal instead of silently dropping the message: this
                // is the `SelfEvicted` outcome, and processing it must
                // perform "realizing removal" when not already done
                // (member-departure.md). Normally the `is_active` gate
                // above classifies this first; this arm keeps the
                // realization obligation attached to the authenticated
                // OpenMLS signal itself.
                self.update_stored_message_state(&msg.id, MessageState::Failed)?;
                self.realize_self_eviction(&group_id, current_epoch)?;
                return Ok(IngestOutcome::LocalState {
                    state: LocalIngestState::Removed,
                });
            }
            Err(e) => {
                if crate::app_components::is_parent_dependent_process_message_error(
                    &e,
                    msg_content_type,
                ) {
                    // Sender and membership-tag authentication can depend
                    // on a retained same-epoch parent. Try every retained
                    // branch before classifying the proposal as terminal.
                    let result = self
                        .converge_stored_openmls_messages(&group_id)
                        .map_err(|error| EngineError::Backend(format!("converge: {error}")))?;
                    return Ok(convergence_ingest_outcome(
                        &result,
                        msg,
                        group_id,
                        current_epoch,
                    ));
                }
                if let Some(category) =
                    crate::app_components::classify_process_message_rejection(&e, msg_content_type)
                {
                    return self.terminalize_rejected_proposal(
                        &group_id,
                        &msg.id,
                        Some(&raw_msg_id),
                        category,
                    );
                }
                self.update_stored_message_state(&msg.id, MessageState::Retryable)?;
                return Err(EngineError::Backend(format!("process_message: {e:?}")));
            }
        };

        // Classify content.
        let sender_leaf_index = match processed.sender() {
            Sender::Member(index) => Some(*index),
            _ => None,
        };
        let sender_id = member_id_of_sender(processed.sender(), &mls_group);
        match processed.into_content() {
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
                    // Peeled successfully but terminally rejected: retire
                    // the raw deferred row so it leaves the retry
                    // lifecycle instead of holding a cap slot (mdk#339).
                    self.mark_raw_transport_message_failed_if_awaiting_retry(
                        &raw_msg_id,
                        "unattributable_sender",
                    )?;
                    return Ok(IngestOutcome::Ignored {
                        category: InputRejectionCategory::InvalidSignature,
                    });
                };
                let payload = bytes.into_bytes();
                let app_event =
                    match crate::app_payload::validate_app_payload_for_sender(&payload, &sender) {
                        Ok(event) => event,
                        Err(_) => {
                            tracing::warn!(
                                target: "cgka_engine::message_processor",
                                method = "ingest_group_message",
                                "dropping application message with invalid Marmot app event",
                            );
                            self.update_stored_message_state(&msg.id, MessageState::Failed)?;
                            // Peeled successfully but terminally rejected: retire
                            // the raw deferred row (mdk#339).
                            self.mark_raw_transport_message_failed_if_awaiting_retry(
                                &raw_msg_id,
                                "invalid_app_payload",
                            )?;
                            return Ok(IngestOutcome::Ignored {
                                category: InputRejectionCategory::InvalidEncoding,
                            });
                        }
                    };
                let retention_seconds = if msg_epoch == current_epoch {
                    Some(
                        crate::app_components::message_retention_seconds_of_group(&mls_group)?
                            .unwrap_or(0),
                    )
                } else {
                    let recovered =
                        recovered_source_retention.and_then(|(snapshot_epoch, seconds)| {
                            (snapshot_epoch == msg_epoch).then_some(seconds.unwrap_or(0))
                        });
                    match recovered {
                        Some(seconds) => Some(seconds),
                        None => self
                            .message_retention_seconds_for_retained_source_epoch(
                                &group_id,
                                msg_epoch,
                                current_epoch,
                            )?
                            .map(|seconds| seconds.unwrap_or(0)),
                    }
                };
                // Full-data forensic mode: surface the decrypted app content
                // and authenticated author. Strictly gated — obfuscated mode
                // never decodes or logs plaintext/author identities.
                if self.recorder.data_mode() == marmot_forensics::AuditDataMode::FullData
                    && let Some(decoded) = crate::audit_helpers::message_content_decoded_event(
                        hex::encode(msg.id.as_slice()),
                        &sender,
                        &payload,
                    )
                {
                    self.audit_group(&group_id, decoded);
                }
                let event = GroupEvent::MessageReceived {
                    group_id: group_id.clone(),
                    message_id: msg.id.clone(),
                    sender,
                    epoch: msg_epoch,
                    payload,
                    retention: retention_seconds.map(|seconds| {
                        AppMessageRetentionDecision::new(app_event.created_at, seconds)
                    }),
                };
                let previous = self.storage.get_message(&msg.id).ok();
                self.storage.with_transaction(|storage| {
                    storage.update_message_state(&msg.id, MessageState::Processed)?;
                    storage.put_pending_application_event(&event)?;
                    Ok::<_, EngineError>(())
                })?;
                let transition = crate::audit_helpers::message_state_transition_event(
                    hex::encode(msg.id.as_slice()),
                    previous.as_ref().map(|record| record.state),
                    MessageState::Processed,
                    previous.as_ref().map(|record| record.epoch),
                    "state_update",
                );
                self.audit_group(&group_id, transition);
                self.events_buf.push_back(event);
                // In-memory fast path mirrors the durable record, keyed on
                // the content-derived id so a re-wrapped duplicate is caught
                // before the durable lookup.
                self.seen_message_ids.insert(msg.id.clone());
                Ok(IngestOutcome::Processed)
            }
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                let before = EpochId(mls_group.epoch().as_u64());
                if let Err(error) = self.strict_cutover_rejects_legacy_group_addition(
                    &group_id,
                    staged.add_proposals().next().is_some(),
                ) {
                    return match error {
                        EngineError::InvalidTransition(_) => self.terminalize_rejected_proposal(
                            &group_id,
                            &msg.id,
                            Some(&raw_msg_id),
                            ProposalRejectionCategory::UnsupportedProposal,
                        ),
                        error => Err(error),
                    };
                }
                if let Err(rejection) =
                    crate::app_components::authorize_staged_commit_proposals(&mls_group, &staged)
                {
                    return self.terminalize_rejected_proposal(
                        &group_id,
                        &msg.id,
                        Some(&raw_msg_id),
                        rejection.category,
                    );
                }
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
                // Reject (pre-merge) a commit whose resulting GroupContext
                // strips or rewrites app-component state outside the
                // validated AppDataUpdate channel — e.g. a
                // GroupContextExtensions-only commit that replaces the
                // extensions without the dictionary, or with tampered
                // component bytes.
                if let Err(err) =
                    crate::app_components::validate_app_component_integrity_for_staged_commit(
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
                let Some(committer_index) = sender_leaf_index else {
                    self.update_stored_message_state(&msg.id, MessageState::Failed)?;
                    return Err(EngineError::Backend(
                        "commit has no authenticated member leaf".into(),
                    ));
                };
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
                if let Err(err) =
                    crate::app_components::validate_current_profile_invariants_for_staged_commit(
                        &mls_group,
                        &staged,
                        committer_index,
                    )
                {
                    self.update_stored_message_state(&msg.id, MessageState::Failed)?;
                    return Err(err);
                }
                // A valid terminal Commit never takes the direct merge
                // shortcut. Persist its authenticated evidence and force
                // the same bounded convergence pass used for competing
                // branches; terminal cleanup happens only after selection.
                if crate::app_components::staged_commit_disbands(&mls_group, &staged)? {
                    self.record_inbound_disband_candidate(
                        &group_id,
                        before,
                        msg.id.clone(),
                        mls_bytes.as_slice(),
                        commit_committer,
                        committer_index == mls_group.own_leaf_index(),
                    )?;
                    let result = self
                        .converge_stored_openmls_messages(&group_id)
                        .map_err(|error| EngineError::Backend(format!("converge: {error}")))?;
                    return Ok(convergence_ingest_outcome(
                        &result,
                        msg,
                        group_id,
                        current_epoch,
                    ));
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
                // Merge and mirror the Marmot record in one durable unit, the
                // same rule `do_confirm_published` applies to its own merge.
                // Session open seeds the epoch state machine FROM that
                // record, so a failed mirror must undo the merge instead of
                // leaving the two stores at different epochs. Nothing between
                // this transaction and `set_stable` below is fallible, so the
                // in-memory epoch authority can only advance over a committed
                // mirror.
                let AppliedCommitProjection {
                    epoch: after,
                    remaining_member_ids: after_ids,
                    removed_member_ids: removed,
                    message_retention_seconds: after_message_retention,
                } = match self.storage.with_transaction(
                    |storage| -> Result<AppliedCommitProjection, EngineError> {
                        // The staged commit is the only public source for
                        // newly added members' KeyPackage capabilities.
                        // Cache them on the same transaction rail as the
                        // merge and every other durable projection.
                        crate::capability_manager::cache_from_staged_commit(
                            storage, &group_id, &staged,
                        )?;
                        let tx_provider =
                            EngineOpenMlsProvider::<S>::new(&self.crypto, storage.mls_storage());
                        mls_group
                            .merge_staged_commit(&tx_provider, *staged)
                            .map_err(|e| {
                                EngineError::Backend(format!("merge_staged_commit: {e:?}"))
                            })?;
                        crate::app_components::validate_current_profile_group_invariants(
                            &mls_group,
                        )?;
                        let after = EpochId(mls_group.epoch().as_u64());
                        let after_members = group_lifecycle::marmot_members(&mls_group);
                        let after_ids: std::collections::HashSet<MemberId> =
                            after_members.iter().map(|m| m.id.clone()).collect();
                        let removed: Vec<MemberId> = before_members
                            .into_iter()
                            .filter_map(|m| (!after_ids.contains(&m.id)).then_some(m.id))
                            .collect();
                        let mut g = storage.get_group(&group_id)?;
                        g.epoch = after;
                        g.members = after_members;
                        g.required_capabilities =
                            crate::capability_manager::required_capabilities_from_group(&mls_group);
                        crate::group_lifecycle::mirror_app_components_into_record(
                            &mls_group, &mut g,
                        );
                        // This commit removed our own leaf: mark the local
                        // copy removed (member-departure.md, "Realizing
                        // removal") in the same record write. The departure
                        // notification for self is emitted with the roster
                        // diff below, so the marker and the notification stay
                        // coupled and later `SelfEvicted` input does not
                        // re-emit it.
                        if removed
                            .iter()
                            .any(|member| member == self.identity.self_id())
                        {
                            g.removed = true;
                        }
                        storage.put_group(&g)?;
                        // A commit path update may change our own leaf.
                        // Feature-status correctness requires this cache to
                        // advance atomically with MLS and the group record.
                        crate::capability_manager::cache_self_capabilities(
                            storage,
                            &group_id,
                            &mls_group,
                            self.identity.self_id(),
                            self.ciphersuite,
                        )?;
                        Ok(AppliedCommitProjection {
                            epoch: after,
                            remaining_member_ids: after_ids,
                            removed_member_ids: removed,
                            message_retention_seconds:
                                crate::app_components::message_retention_seconds_of_group(
                                    &mls_group,
                                )?,
                        })
                    },
                ) {
                    Ok(projection) => projection,
                    Err(error) => {
                        // The commit is durably retained as a `Created` wire
                        // row, so hand the group back to stored convergence —
                        // that pass is the repair path, and without the
                        // schedule nothing would ever apply it.
                        self.schedule_pending_convergence_group(&group_id);
                        return Err(error);
                    }
                };
                let after_admins =
                    crate::app_components::admins_of_group(&mls_group).unwrap_or_default();
                let after_profile = crate::app_components::group_profile_of_group(&mls_group)
                    .ok()
                    .flatten();
                let after_avatar = avatar_component_snapshot(&mls_group);

                // Update our per-group state machine.
                self.epoch_manager.set_stable(group_id.clone(), after);
                self.drop_self_remove_auto_commit_schedules_for_group(&group_id);
                // Proposal-arrival schedule signals are source-epoch
                // scoped. An accepted commit advances the group, so every
                // such signal from the prior epoch is obsolete.
                self.valid_proposal_groups.remove(&group_id);
                // #740 rotation: a peer's applied commit may have changed the
                // Nostr routing component; additively refresh the transport-id
                // index so the new nostr_group_id resolves (prior id retained
                // for the overlap window). No-op when routing was unchanged.
                self.reindex_transport_group_id(&group_id);

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
                    // The copy just became removed: purge queued outbound
                    // intents so later drains do not re-fail them forever
                    // against the removed-copy send gate.
                    self.discard_queued_outbound_intents_for_removed_group(&group_id)?;
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
                if let Err(error) = self.strict_cutover_rejects_legacy_group_addition(
                    &group_id,
                    matches!(queued.proposal(), Proposal::Add(_)),
                ) {
                    return match error {
                        EngineError::InvalidTransition(_) => self.terminalize_rejected_proposal(
                            &group_id,
                            &msg.id,
                            Some(&raw_msg_id),
                            ProposalRejectionCategory::UnsupportedProposal,
                        ),
                        error => Err(error),
                    };
                }
                if let Err(rejection) =
                    crate::app_components::authorize_standalone_proposal(&mls_group, &queued)
                {
                    return self.terminalize_rejected_proposal(
                        &group_id,
                        &msg.id,
                        Some(&raw_msg_id),
                        rejection.category,
                    );
                }
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
                        proposal_kind: crate::audit_helpers::proposal_kind_str(queued.proposal())
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
                self.valid_proposal_groups.insert(group_id);
                Ok(IngestOutcome::Processed)
            }
            ProcessedMessageContent::ExternalJoinProposalMessage(_) => self
                .terminalize_rejected_proposal(
                    &group_id,
                    &msg.id,
                    Some(&raw_msg_id),
                    ProposalRejectionCategory::UnsupportedProposal,
                ),
            ProcessedMessageContent::OwnPendingCommit
            | ProcessedMessageContent::OwnPrivateMessage => {
                // This normally returns through the durable sent-content
                // marker before OpenMLS processing. Keep the library-level
                // classification as a safe fallback, but do not merge the
                // pending commit: MDK applies local commits only through
                // its explicit publish-before-apply confirmation path.
                self.update_stored_message_state(&msg.id, MessageState::Processed)?;
                self.mark_raw_transport_message_failed_if_awaiting_retry(&raw_msg_id, "own_echo")?;
                self.seen_message_ids.insert(msg.id.clone());
                Ok(IngestOutcome::Ignored {
                    category: InputRejectionCategory::OwnEcho,
                })
            }
            ProcessedMessageContent::UnresolvedAppDataCommit(_) => {
                // `process_commit_with_app_data_updates` must resolve this
                // before returning. Retain the message for diagnosis and
                // retry rather than accepting a partially processed commit.
                self.update_stored_message_state(&msg.id, MessageState::Retryable)?;
                Err(EngineError::Backend(
                    "commit retained unresolved app-data updates".into(),
                ))
            }
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
                .min_by(|left, right| {
                    left.due_at_ms.cmp(&right.due_at_ms).then_with(|| {
                        left.proposal_id
                            .as_slice()
                            .cmp(right.proposal_id.as_slice())
                    })
                })
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

        let mut mls_group = {
            let provider =
                EngineOpenMlsProvider::<S>::new(&self.crypto, self.storage.mls_storage());
            let mls_gid = openmls::group::GroupId::from_slice(schedule.group_id.as_slice());
            let mls_group = MlsGroup::load(
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
            mls_group
        };

        let selected = self.retained_self_remove_proposals_for_local_commit(
            &schedule.group_id,
            schedule.source_epoch,
            &mut mls_group,
        )?;
        if selected.is_empty() {
            return Ok(ScheduledAutoCommitReplay::NotApplicable);
        }

        if self
            .stage_auto_commit_for_queued_proposals(&schedule.group_id, &mut mls_group, selected)
            .await?
        {
            Ok(ScheduledAutoCommitReplay::Staged)
        } else {
            self.schedule_self_remove_auto_commit(
                &schedule.group_id,
                &schedule.proposal_id,
                schedule.source_epoch,
                self.convergence_now_ms(),
            )?;
            Ok(ScheduledAutoCommitReplay::NotApplicable)
        }
    }

    fn retained_self_remove_proposals_for_local_commit(
        &self,
        group_id: &GroupId,
        source_epoch: EpochId,
        mls_group: &mut MlsGroup,
    ) -> Result<Vec<QueuedProposal>, EngineError> {
        let provider = EngineOpenMlsProvider::<S>::new(&self.crypto, self.storage.mls_storage());
        let mut candidates = Vec::new();
        for record in self.storage.list_messages(group_id, source_epoch)? {
            if record.epoch != source_epoch
                || !matches!(
                    record.state,
                    MessageState::Created
                        | MessageState::Retryable
                        | MessageState::ConvergenceDeferred
                        | MessageState::Processed
                )
            {
                continue;
            }
            let Ok(stored_payload) = StoredMessagePayload::decode(&record.payload) else {
                continue;
            };
            let Some(message) = stored_payload.as_openmls_wire() else {
                continue;
            };
            let Ok(projection) = project_mls_message(&message.payload) else {
                continue;
            };
            if projection.kind != OpenMlsContentKind::Proposal
                || projection.source_epoch != Some(source_epoch.0)
            {
                continue;
            }
            let Ok(msg_in) = MlsMessageIn::tls_deserialize_exact(message.payload.as_slice()) else {
                continue;
            };
            let proto: ProtocolMessage = match msg_in.extract() {
                MlsMessageBodyIn::PrivateMessage(private) => private.into(),
                MlsMessageBodyIn::PublicMessage(public) => public.into(),
                _ => continue,
            };
            let Ok(processed) = mls_group.process_message(&provider, proto) else {
                continue;
            };
            let ProcessedMessageContent::ProposalMessage(queued) = processed.into_content() else {
                continue;
            };
            if !matches!(queued.proposal(), Proposal::SelfRemove)
                || crate::app_components::authorize_standalone_proposal(mls_group, &queued).is_err()
                || !matches!(
                    crate::auto_committer::decide_with_reason(mls_group, &queued).decision,
                    crate::auto_committer::AutoCommitDecision::Commit
                )
            {
                continue;
            }
            let Sender::Member(leaf) = queued.sender() else {
                continue;
            };
            let mut digest = [0u8; 32];
            digest.copy_from_slice(&Sha256::digest(message.payload.as_slice()));
            candidates.push(RetainedSelfRemoveProposal {
                leaf: *leaf,
                digest,
                queued: *queued,
            });
        }

        let selection_inputs: Vec<_> = candidates
            .iter()
            .map(|candidate| (candidate.leaf, candidate.digest))
            .collect();
        let selected = crate::auto_committer::select_lowest_digest_per_leaf(&selection_inputs);
        Ok(selected
            .into_iter()
            .map(|index| candidates[index].queued.clone())
            .collect())
    }

    async fn stage_auto_commit_for_queued_proposals(
        &mut self,
        group_id: &GroupId,
        mls_group: &mut MlsGroup,
        queued_proposals: Vec<QueuedProposal>,
    ) -> Result<bool, EngineError> {
        if queued_proposals.is_empty() {
            return Ok(false);
        }
        for queued in &queued_proposals {
            let decision_report = crate::auto_committer::decide_with_reason(mls_group, queued);
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
            ) || crate::app_components::authorize_standalone_proposal(mls_group, queued).is_err()
            {
                return Ok(false);
            }
        }

        let auto_removed: Vec<MemberId> = queued_proposals
            .iter()
            .filter_map(|queued| member_id_of_sender(queued.sender(), mls_group))
            .collect();
        let auto_proposal_kind = "self_remove".to_string();

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
        // This path must never consume unrelated pending proposals. In normal
        // engine operation retained inbound proposals live in MessageStorage,
        // not OpenMLS's proposal store; a non-empty store therefore means some
        // other operation owns it and SelfRemove preparation waits.
        if mls_group.has_pending_proposals() {
            self.schedule_pending_convergence_group(group_id);
            return Ok(false);
        }

        let pre_commit_epoch = EpochId(mls_group.epoch().as_u64());
        let mut pending_commit_guard =
            PendingCommitCleanupGuard::arm(&self.storage, &provider, group_id.clone());
        for queued in queued_proposals {
            let stored_proposal_ref = queued.proposal_reference_ref().clone();
            mls_group
                .store_pending_proposal(
                    <EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::storage(
                        &provider,
                    ),
                    queued,
                )
                .map_err(|e| EngineError::Backend(format!("store_pending: {e:?}")))?;
            pending_commit_guard.set_stored_proposal_ref(stored_proposal_ref);
        }
        let pre_commit_ctx = group_lifecycle::build_group_context_snapshot(mls_group, &provider)?;
        let (commit_out, _welcome_opt, _gi) = mls_group
            .commit_to_pending_proposals(&provider, &self.identity.signer)
            .map_err(|e| EngineError::Backend(format!("auto_commit: {e:?}")))?;
        let staged_commit = mls_group
            .pending_commit()
            .ok_or_else(|| EngineError::Backend("auto-commit produced no pending commit".into()))?;
        crate::app_components::validate_current_profile_invariants_for_staged_commit(
            mls_group,
            staged_commit,
            mls_group.own_leaf_index(),
        )?;
        crate::account_identity_proof::validate_staged_commit_account_identity_proofs(
            staged_commit,
            mls_group,
            self.identity.self_id(),
            self.ciphersuite,
        )?;
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

        // Project the post-merge record only after every other fallible
        // staging step has succeeded: a torn record (epoch N+1 with members
        // dropped while MLS and the state machine stay at N) permanently
        // strands auto-commit replay, which bails on any epoch mismatch
        // (mdk#333).
        // Read-then-project as one fallible unit: a failed read is no more
        // recoverable than a failed write here (both leave the state machine
        // pending at N+1 with no matching durable record), so both funnel
        // through the same compensation.
        let projection = self.storage.get_group(group_id).and_then(|mut g| {
            g.epoch = new_epoch;
            g.members
                .retain(|member| !auto_removed.iter().any(|id| id == &member.id));
            self.storage.put_group(&g)
        });
        if let Err(err) = projection {
            // The pending slot was never handed off to a caller, so
            // `publish_failed` can never reach it — rewind the state
            // machine here (in-memory, so the storage pressure that
            // failed the read/write cannot also defeat the compensation);
            // the still-armed guard clears the staged OpenMLS commit on the
            // early return.
            if self.epoch_manager.rollback_publish(pending_ref).is_err() {
                tracing::warn!(
                    target: "cgka_engine::message_processor",
                    method = "stage_auto_commit_for_queued_proposals",
                    "state-machine rollback failed after group record projection failure"
                );
            }
            self.audit_group(
                group_id,
                crate::audit_helpers::epoch_state_changed_event(
                    Some("pending_publish"),
                    "stable",
                    pre_commit_epoch,
                    "auto_commit_stage_failed",
                    Some(pending_ref),
                    Some("group_evolution"),
                ),
            );
            return Err(err.into());
        }
        self.track_pending_origin_commit(pending_ref, wrapped.id.clone());
        let auto_changes = auto_removed
            .iter()
            .cloned()
            .map(|member| {
                let change = GroupStateChange::MemberLeft {
                    member: member.clone(),
                };
                let actor = Some(member);
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

    /// Realize our own removal from `group_id` (member-departure.md,
    /// "Realizing removal"): emit the self-removed state notification and mark
    /// the local group copy removed. State-derived and idempotent — when the
    /// copy is already marked removed the notification was already surfaced,
    /// so this is a no-op. The record and its history are retained (the copy
    /// is kept inactive, never deleted). Callers must only invoke this on
    /// authenticated evidence of eviction (the local MLS group state records
    /// our removal), never on a bare decrypt failure.
    ///
    /// Ordering: the notification is enqueued BEFORE the durable marker write,
    /// so a crash between the two re-runs realization on the next
    /// `SelfEvicted` input (at worst a duplicate notification, absorbed by the
    /// app's canonical-row-id upsert) instead of leaving a durable marker that
    /// suppresses a notification nobody observed. A window this ordering
    /// cannot close remains: `events_buf` is in-memory, so a process death
    /// after the marker write but before the caller drains and persists the
    /// event still loses it. That at-most-once property is shared by every
    /// `GroupStateChanged` emission in the engine today (the commit-apply seam
    /// has the same shape for all roster/admin/profile rows); making the event
    /// channel durable — or reconciling on session open from `Group::removed`
    /// at the app layer — is a systemic follow-up, not realization-specific.
    pub(crate) fn realize_self_eviction(
        &mut self,
        group_id: &GroupId,
        epoch: EpochId,
    ) -> Result<(), EngineError> {
        let mut group = match self.storage.get_group(group_id) {
            Ok(group) => group,
            Err(StorageError::NotFound) => return Ok(()),
            Err(err) => return Err(EngineError::Storage(err)),
        };
        if group.removed {
            return Ok(());
        }
        // OpenMLS's `Inactive` state does not record WHY our leaf left the
        // tree. The durable leave request is local, authenticated intent to
        // leave, so when one is pending the departure being realized is our
        // own leave: attribute it as `MemberLeft` (actor = self), matching the
        // direct seam's SelfRemove classification. Without one the removal is
        // attributed as involuntary with an unknown actor — the accepted
        // degradation when the removing commit itself was never applied.
        let had_leave_request = self.load_leave_request_state(group_id)?.is_some();
        // Privacy-safe breadcrumb: aggregate signal only, no group/member ids
        // (observability.md).
        tracing::info!(
            target: "cgka_engine::message_processor",
            method = "realize_self_eviction",
            "realized own removal for a group whose canonical state records eviction"
        );
        let member = self.identity.self_id().clone();
        let (actor, change) = if had_leave_request {
            (
                Some(member.clone()),
                GroupStateChange::MemberLeft { member },
            )
        } else {
            (None, GroupStateChange::MemberRemoved { member })
        };
        self.push_group_state_change(group_id, epoch, actor, change, None);
        // Marker + roster reconciliation in one durable write: a removed copy
        // must not keep presenting self as a member, so roster-gated callers
        // (`members()`, hydrate restore checks, backfill) cannot disagree with
        // the terminal marker. The seam and convergence paths already write
        // the post-removal roster; this reconciles the pathological copy whose
        // roster was never mirrored.
        group.removed = true;
        let self_id = self.identity.self_id().clone();
        group.members.retain(|member| member.id != self_id);
        self.storage.put_group(&group)?;
        // A removed copy must never publish: drop any outbound intents that
        // were durably queued before the removal was realized, instead of
        // leaving them to re-fail through the removed-copy send gate on every
        // later drain.
        self.discard_queued_outbound_intents_for_removed_group(group_id)?;
        // Deliberately LAST, after the marker write — not before it like the
        // convergence path (which has no attribution read). The notification
        // is already enqueued above, so a failure here cannot lose it; it only
        // leaves a stale leave-request row, which the removed-copy send gate
        // supersedes and re-join cleans up. Clearing BEFORE the marker write
        // would be worse: a failed marker write would then retry against
        // already-cleared leave state and emit a differently-attributed
        // duplicate (`MemberRemoved` after an original `MemberLeft`), i.e. a
        // second visible row. With this order any retry duplicate is
        // byte-identical and collapses in the app's canonical-row-id upsert.
        self.clear_leave_request_state(group_id)?;
        Ok(())
    }

    fn terminal_peel_rejection_ignored(
        &mut self,
        raw_msg_id: &MessageId,
        msg_id: &MessageId,
        reason: &'static str,
        category: InputRejectionCategory,
    ) -> Result<IngestOutcome, EngineError> {
        self.mark_raw_transport_message_failed_if_awaiting_retry(raw_msg_id, reason)?;
        self.seen_message_ids.insert(msg_id.clone());
        Ok(IngestOutcome::Ignored { category })
    }

    /// Whether `msg_epoch` predates this device's membership in `group_id`
    /// (mdk#339): such a message was never decryptable here by design —
    /// OpenMLS holds no secrets for epochs before the welcome — so it is
    /// terminal, never retried. Best-effort: a `join_epoch` of `EpochId(0)`
    /// (legacy records or a missing record) is "unknown", which applies no
    /// bound and returns `false`.
    fn msg_is_pre_membership(&self, group_id: &GroupId, msg_epoch: EpochId) -> bool {
        let join_epoch = self
            .storage
            .get_group(group_id)
            .map(|group| group.join_epoch)
            .unwrap_or_default();
        join_epoch.0 > 0 && msg_epoch < join_epoch
    }

    /// Loud, non-terminal handling for an in-horizon rival commit whose
    /// fork-source anchor snapshot is gone (pre-mechanism database, storage
    /// loss). The rival SHOULD have been adjudicated by distributed
    /// convergence; without the anchor the rival cannot even be admitted to a
    /// pass here, and silently dropping it would leave the device on its own —
    /// possibly losing — branch with nothing recorded anywhere. So: keep the
    /// retained content row, record the refusal in the audit log, and schedule
    /// the group so convergence gives the rival a verdict from canonical state.
    /// Canonical state is left untouched here.
    ///
    /// # This seam derives NO durable terminal state, deliberately
    ///
    /// It used to. Reaching here means OpenMLS rejected the message with
    /// `WrongEpoch`, and `validate_framing` — which raises that error — is the
    /// FIRST statement of `decrypt_message`, strictly upstream of membership-tag
    /// and signature verification. Nothing cryptographic has run, and nothing
    /// could: the membership MAC needs the claimed epoch's membership key and
    /// the signature covers that epoch's serialized group context, and both live
    /// in the very anchor snapshot that is missing by precondition. `msg_epoch`
    /// is therefore raw attacker input that no check downstream can ever
    /// corroborate.
    ///
    /// A durable `unrecoverable` marker derived from it handed any group member
    /// — or a removed member whose epoch snapshot is still retained, via the
    /// snapshot-fallback peel — a fire-and-forget freeze: one parseable datagram
    /// naming any in-horizon epoch for which the victim holds no anchor, and the
    /// group is permanently un-ingestable, across restarts, exitable only by a
    /// replacement Welcome or disband. Nothing about the victim's storage had to
    /// be known; a device with a legitimate gap (`join_epoch == 0` legacy
    /// records defeat the pre-membership carve-out) is exactly the target.
    ///
    /// Parking the rival `ConvergenceDeferred` keyed by `msg_epoch` was the same
    /// defect one level down. That key is the row's `source_epoch`, and
    /// `openmls_projection::historical_replay_start_epoch` takes the `min` over
    /// unresolved rows to pick where a pass rewinds to — so the claimed epoch
    /// would steer the convergence coordinator into its own
    /// `MissingRetainedAnchor` halt on every later pass. The row this seam
    /// leaves alone is the one ingest already persisted `Created` at
    /// `current_epoch`: still retained, still pass-opening, but never a
    /// historical rewind target chosen by an unauthenticated claim.
    ///
    /// # Retiring that row is the repair path's job, not this seam's
    ///
    /// Leaving it pass-opening is what keeps the coordinator's verdict
    /// reachable, and the pass seeder re-derives each retained commit's source
    /// epoch from its own wire bytes regardless of the column this seam wrote —
    /// so for a genuine anchor gap the row keeps re-deriving the halt until
    /// something evicts it. That eviction belongs to a seam holding
    /// authenticated material: `group_lifecycle::do_join_welcome` retires
    /// unresolved commits below the replacement Welcome's own `MlsGroup::epoch()`
    /// (`openmls_projection::retire_commits_superseded_by_replacement_welcome`),
    /// in the same transaction that discards this device's superseded MLS copy.
    /// Without it a verified repair does not stick: the group exits the halt and
    /// the next convergence drain walks it straight back in.
    ///
    /// # The local half is not lost
    ///
    /// "Our anchor set has a gap inside the rewind horizon" is a LOCAL fact with
    /// zero attacker input, and it is the only half that could justify a hard
    /// stop. Evaluating it belongs on a seam that reads no inbound bytes —
    /// session open, i.e. the per-group full hydration behind
    /// `Engine::ensure_hydrated`, alongside `sync_unrecoverable_halt_from_storage`.
    /// Whether a gap there SHOULD hard-stop a group is a product decision and is
    /// deliberately not made here.
    fn unadjudicable_fork_rival_without_anchor(
        &mut self,
        group_id: GroupId,
        msg_id: &MessageId,
        current: EpochId,
    ) -> Result<IngestOutcome, EngineError> {
        // `Buffered` promises a later replay of the retained row, and
        // applications open passes off `drain_pending_convergence_groups`, so
        // the seam owes the group a schedule. The insert is idempotent and
        // in-memory.
        self.schedule_pending_convergence_group(&group_id);
        self.audit_group(
            &group_id,
            marmot_forensics::AuditEventKind::Rejection {
                msg_id: hex::encode(msg_id.as_slice()),
                reason: "fork_rival_missing_retained_anchor".to_string(),
            },
        );
        Ok(IngestOutcome::Buffered {
            group_id,
            epoch: current,
        })
    }

    fn group_id_for_transport_group_id(
        &self,
        transport_group_id: &[u8],
    ) -> Result<GroupId, EngineError> {
        let direct = GroupId::new(transport_group_id.to_vec());
        match self.storage.get_group(&direct) {
            Ok(group) => {
                if self.storage.disband_tombstone(&group.id)?.is_none() {
                    return Ok(group.id);
                }
            }
            Err(StorageError::NotFound) => {}
            Err(err) => return Err(EngineError::Storage(err)),
        }

        // #740: for Nostr-routed groups the `transport_group_id` (nostr_group_id)
        // differs from the MLS group id, so the direct lookup above misses on the
        // normal production path. Resolve via the authoritative in-memory index
        // (built at hydration and group establishment; see
        // `Engine::transport_group_id_index`) instead of the former O(groups)
        // scan that deserialized every joined `MlsGroup`. That scan ran BEFORE
        // payload authentication, so a peer flooding kind-445 events with unknown
        // `transport_group_id`s forced attacker-paced CPU + storage I/O. A miss
        // now costs one hash probe: the id is not one of our groups, so fall
        // through to the direct id and let the unknown-group / NotForThisClient
        // handling drop it without any per-event scan.
        if let Some(group_id) = self.transport_group_id_index.get(transport_group_id) {
            return Ok(group_id.clone());
        }

        Ok(direct)
    }

    /// Maximum backfill-pending groups probed (MLS-loaded) per unknown
    /// inbound route. Small so one attacker-supplied route id never turns
    /// into account-wide work; the background pipeline drains the rest.
    const ROUTE_BACKFILL_PROBES_PER_MISS: usize = 4;

    /// [`Self::group_id_for_transport_group_id`] plus the route backfill for
    /// groups whose durable route set is missing or stale (mdk#1161): while
    /// any such group remains, an index miss cannot be trusted, so this loads
    /// pending groups' MLS state to persist + index their current route and
    /// retries the match.
    ///
    /// Bounded per event: one unknown inbound route probes at most
    /// [`ROUTE_BACKFILL_PROBES_PER_MISS`] pending groups — never the whole
    /// account — so an attacker-supplied route id cannot force O(groups) MLS
    /// loads in a single request (the amplification mdk#408 closed). The
    /// remainder stays queued for later misses and for the app-layer
    /// background hydration pipeline, which drains backfill-pending groups
    /// first. A pending id leaves the set only on a successful route index or
    /// the explicit terminal "group has no routing component" disposition; an
    /// MLS load failure keeps the id pending because full hydration owns that
    /// failure — every backfill-pending group is also in `unhydrated_groups`,
    /// so `ensure_hydrated` will either index its route or quarantine it.
    fn resolve_or_backfill_group_id_for_transport(
        &mut self,
        transport_group_id: &[u8],
    ) -> Result<GroupId, EngineError> {
        let resolved = self.group_id_for_transport_group_id(transport_group_id)?;
        if self.route_backfill_pending.is_empty()
            || self
                .transport_group_id_index
                .contains_key(transport_group_id)
            || self.storage.get_group(&resolved).is_ok()
        {
            return Ok(resolved);
        }
        let probes: Vec<GroupId> = self
            .route_backfill_pending
            .iter()
            .take(Self::ROUTE_BACKFILL_PROBES_PER_MISS)
            .cloned()
            .collect();
        let mut matched = None;
        for group_id in probes {
            let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
            let mls_group = {
                let provider = crate::provider::EngineOpenMlsProvider::<S>::new(
                    &self.crypto,
                    self.storage.mls_storage(),
                );
                match openmls::group::MlsGroup::load(
                    <crate::provider::EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::storage(
                        &provider,
                    ),
                    &mls_gid,
                ) {
                    Ok(Some(group)) => group,
                    // Unreadable MLS state: keep the id pending — full
                    // hydration owns the failure and will quarantine or
                    // repair it; the per-miss budget bounds re-probes.
                    _ => continue,
                }
            };
            match crate::app_components::transport_group_id_of_group(&mls_group) {
                Ok(route) => {
                    let is_match = route == transport_group_id;
                    let current_epoch = cgka_traits::types::EpochId(mls_group.epoch().as_u64());
                    self.route_backfill_pending.remove(&group_id);
                    self.index_transport_group_route(route, &group_id, current_epoch);
                    if is_match && matched.is_none() {
                        matched = Some(group_id);
                    }
                }
                Err(_) => {
                    // Terminal for routing: the group carries no routing
                    // component, so there is no route to backfill.
                    self.route_backfill_pending.remove(&group_id);
                }
            }
        }
        Ok(matched.unwrap_or(resolved))
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
            let (ctx, message_retention_seconds) =
                match self.context_from_group_snapshot(group_id, &snapshot_name) {
                    Ok(Some(context)) => context,
                    Ok(None) => {
                        // Evicted-era snapshot: no exporter secret exists for
                        // it. Restore live state and try the next snapshot.
                        guard.commit()?;
                        continue;
                    }
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
                        message_retention_seconds,
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

    /// Resolve retention from the exact retained MLS state for a delayed
    /// application message. The outer `Option` distinguishes a recovered
    /// source decision from an unavailable historical policy; the inner
    /// `Option` is the component's disabled/absent state.
    fn message_retention_seconds_for_retained_source_epoch(
        &self,
        group_id: &GroupId,
        source_epoch: EpochId,
        current_epoch: EpochId,
    ) -> Result<Option<Option<u64>>, EngineError> {
        let snapshot_name = self
            .storage
            .list_group_snapshots(group_id)?
            .into_iter()
            .find(|name| {
                retained_anchor_epoch_from_snapshot_name(name.as_str()) == Some(source_epoch.0)
            });
        let Some(snapshot_name) = snapshot_name else {
            return Ok(None);
        };

        let mut hasher = Sha256::new();
        hasher.update(b"cgka-engine-retention-restore/v1");
        hasher.update(group_id.as_slice());
        hasher.update(source_epoch.0.to_be_bytes());
        hasher.update(current_epoch.0.to_be_bytes());
        let restore_name = format!(
            "retention-restore-{}-{}",
            current_epoch.0,
            hex::encode(&hasher.finalize()[..8])
        );
        let guard = SnapshotRollbackGuard::create(&self.storage, group_id.clone(), restore_name)?;
        let resolved = match self
            .storage
            .rollback_group_to_snapshot(group_id, &snapshot_name)
        {
            Ok(()) => {
                let provider =
                    EngineOpenMlsProvider::<S>::new(&self.crypto, self.storage.mls_storage());
                let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
                let historical_group = MlsGroup::load(
                    <EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::storage(
                        &provider,
                    ),
                    &mls_gid,
                )
                .map_err(|error| {
                    EngineError::Backend(format!("load retention source snapshot: {error:?}"))
                })?
                .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;
                if historical_group.epoch().as_u64() != source_epoch.0 {
                    None
                } else {
                    Some(crate::app_components::message_retention_seconds_of_group(
                        &historical_group,
                    )?)
                }
            }
            Err(StorageError::SnapshotMissing(_)) => None,
            Err(error) => return Err(error.into()),
        };
        guard.commit()?;
        Ok(resolved)
    }

    pub(crate) fn available_past_peel_snapshots(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<(EpochId, String)>, EngineError> {
        let mut snapshots = Vec::new();
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

    /// `Ok(None)` means the retained snapshot cannot serve as a peel source:
    /// its own leaf is evicted, so OpenMLS refuses every exporter derivation
    /// (`UseAfterEviction`). A re-added member keeps such snapshots from its
    /// pre-removal era; they must be skipped like an undecryptable snapshot,
    /// not surfaced as an ingest failure.
    fn context_from_group_snapshot(
        &self,
        group_id: &GroupId,
        snapshot_name: &str,
    ) -> Result<
        Option<(
            cgka_traits::group_context::GroupContextSnapshot,
            Option<u64>,
        )>,
        EngineError,
    > {
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
        if !mls_group.is_active() {
            return Ok(None);
        }
        let message_retention_seconds =
            crate::app_components::message_retention_seconds_of_group(&mls_group)?;
        Ok(Some((
            group_lifecycle::build_group_context_snapshot(&mls_group, &provider)?,
            message_retention_seconds,
        )))
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
    let content_message_id = hex::encode(content_dedup_id(&msg.payload).as_slice());

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
        .any(|accepted| accepted == &message_id || accepted == &content_message_id);
    if accepted && result.convergence_status == crate::canonicalization::ConvergenceStatus::Settled
    {
        return IngestOutcome::Processed;
    }

    if result
        .already_seen
        .iter()
        .any(|seen| seen.message_id == message_id || seen.message_id == content_message_id)
    {
        return IngestOutcome::Ignored {
            category: InputRejectionCategory::Duplicate,
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
    if let Some(dropped) = result.dropped_messages.iter().find(|dropped| {
        dropped.message_id == message_id || dropped.message_id == content_message_id
    }) {
        if let Some(category) = dropped.rejection_category {
            return IngestOutcome::Rejected { category };
        }
        use crate::canonicalization::DroppedMessageReason;
        return match dropped.reason {
            DroppedMessageReason::BeyondRollbackHorizon => IngestOutcome::Stale {
                reason: StaleReason::BeyondRollbackHorizon,
            },
            DroppedMessageReason::BeyondAnchor => IngestOutcome::Stale {
                reason: StaleReason::BeyondAnchor,
            },
            DroppedMessageReason::BeyondAppRetention => IngestOutcome::Stale {
                reason: StaleReason::BeyondAppRetention,
            },
            DroppedMessageReason::InvalidAgainstCandidateState => IngestOutcome::Stale {
                reason: StaleReason::InvalidAgainstCanonicalState,
            },
            DroppedMessageReason::UnsupportedPolicy => IngestOutcome::Ignored {
                category: InputRejectionCategory::UnsupportedRequiredFeature,
            },
            DroppedMessageReason::Malformed => IngestOutcome::Ignored {
                category: InputRejectionCategory::InvalidEncoding,
            },
        };
    }
    if let Some(inv) = result
        .invalidated_app_messages
        .iter()
        .find(|inv| inv.message_id == message_id || inv.message_id == content_message_id)
    {
        use crate::canonicalization::InvalidatedAppMessageReason;
        match inv.reason {
            InvalidatedAppMessageReason::UndecryptableInCanonicalState => {
                // Possibly retryable on a later pass; fall through to
                // Buffered so the application keeps the message and
                // waits for branch selection to advance.
            }
            InvalidatedAppMessageReason::LosingBranch => {
                return IngestOutcome::Stale {
                    reason: StaleReason::LosingBranch,
                };
            }
            InvalidatedAppMessageReason::BeyondAnchor => {
                return IngestOutcome::Stale {
                    reason: StaleReason::BeyondAnchor,
                };
            }
            InvalidatedAppMessageReason::BeyondAppRetention => {
                return IngestOutcome::Stale {
                    reason: StaleReason::BeyondAppRetention,
                };
            }
        }
    }

    IngestOutcome::Buffered { group_id, epoch }
}
