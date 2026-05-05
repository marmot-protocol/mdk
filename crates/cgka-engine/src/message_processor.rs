//! MessageProcessor — inbound `ingest` pipeline + outbound `send` routing.
//!
//! Inbound:  peel → classify by envelope → route to welcome / group-message
//!           path → produce `IngestOutcome` + emit events
//! Outbound: classify `SendIntent` → MLS create_message / add / self_remove →
//!           wrap via peeler → `SendResult`
//!
//! Per spike-findings §1.5, every "we can't apply this" case returns
//! `Ok(IngestOutcome::Stale { .. })` with a typed `StaleReason`, never
//! `Err`. The wiring layer logs `Stale` at debug, real errors at warn.

use crate::engine::Engine;
use crate::fork_recovery::ForkResolution;
use crate::group_lifecycle::{self};
use crate::provider::EngineOpenMlsProvider;
use cgka_traits::engine::{CommitOrderingKey, GroupEvent, SendIntent, SendResult};
use cgka_traits::engine_state::EpochState;
use cgka_traits::error::{EngineError, PeelerError};
use cgka_traits::ingest::{IngestOutcome, PeeledContent, StaleReason};
use cgka_traits::message::{MessageRecord, MessageState};
use cgka_traits::storage::{StorageError, StorageProvider};
use cgka_traits::transport::{EncryptedPayload, TransportEnvelope, TransportMessage};
use cgka_traits::types::{EpochId, GroupId, MemberId, MessageId};
use openmls::group::{MlsGroup, ProcessMessageError};
use openmls::prelude::{
    BasicCredential, ContentType, MlsMessageBodyIn, MlsMessageIn, MlsMessageOut,
    ProcessedMessageContent, Proposal, ProtocolMessage, Sender, ValidationError,
};
use tls_codec::{Deserialize as _, Serialize as _};

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

        if !matches!(outcome, IngestOutcome::Buffered { .. }) {
            self.seen_message_ids.insert(msg.id.clone());
        }
        Ok(outcome)
    }

    async fn ingest_welcome(
        &mut self,
        msg: &TransportMessage,
        recipient: MemberId,
    ) -> Result<IngestOutcome, EngineError> {
        // Two-layer addressing. Transport layer filters by endpoint
        // (e.g. Nostr NIP-44 decryption only succeeds for the intended
        // pubkey) — in a well-behaved 1:1 pubkey-to-identity deployment,
        // this engine-layer check would be dead code. It ISN'T dead code
        // because:
        //   - the in-memory test harness broadcasts every message to every
        //     client (Phase 6), so recipient filtering MUST happen here
        //   - future multi-device (MIP-06) and broadcast transports (FIPS
        //     mesh) break the 1:1 assumption at the transport layer
        //   - typed `NotForThisClient` is diagnostically richer than
        //     `PeelFailed` — routing issue vs. crypto issue at the log site
        // Do not remove this check under "unreachable in production" logic.
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

            self.persist_transport_message(msg, &group_id, current_epoch, MessageState::Created)?;

            // Peel.
            let ctx = group_lifecycle::build_group_context_snapshot(&mls_group, &provider)?;
            let peeled = match self.peeler.peel_group_message(msg, &ctx).await {
                Ok(p) => p,
                Err(PeelerError::DecryptFailed) => {
                    self.update_stored_message_state(&msg.id, MessageState::Failed)?;
                    return Ok(IngestOutcome::Stale {
                        reason: StaleReason::PeelFailed,
                    });
                }
                Err(e) => return Err(EngineError::Peeler(e)),
            };
            let mls_bytes = match peeled.content {
                PeeledContent::MlsMessage { bytes } => bytes,
                PeeledContent::Welcome { .. } => {
                    self.update_stored_message_state(&msg.id, MessageState::Failed)?;
                    return Ok(IngestOutcome::Stale {
                        reason: StaleReason::PeelFailed,
                    });
                }
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
                    return Ok(IngestOutcome::Stale {
                        reason: StaleReason::PeelFailed,
                    });
                }
            };

            let msg_epoch = EpochId(proto.epoch().as_u64());
            let msg_content_type = proto.content_type();

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
                        match self.resolve_fork_candidate(&group_id, msg_epoch, msg)? {
                            ForkResolution::CandidateWins {
                                winner,
                                invalidated,
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
                    // Task 4.7: extract capabilities from the commit's Add
                    // proposals before we consume the staged commit.
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
                        after,
                        msg,
                        recovery_snapshot,
                    );
                    if let Ok(mut g) = self.storage.get_group(&group_id) {
                        g.epoch = after;
                        g.members = after_members;
                        self.storage.put_group(&g)?;
                    }
                    // Task 4.7: refresh self-cache since our own leaf may have
                    // been updated by the commit's path (force_self_update).
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
                    // Task 4.11 — ask the auto-committer policy whether we
                    // should commit this proposal. Currently fires only on
                    // SelfRemove. OpenMLS does NOT auto-enqueue processed
                    // proposals — we must explicitly `store_pending_proposal`
                    // first so `commit_to_pending_proposals` can find it.
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
                        let (commit_out, _welcome_opt, _gi) = mls_group
                            .commit_to_pending_proposals(&provider, &self.identity.signer)
                            .map_err(|e| EngineError::Backend(format!("auto_commit: {e:?}")))?;
                        let commit_bytes = commit_out
                            .tls_serialize_detached()
                            .map_err(|e| EngineError::Serialize(format!("{e:?}")))?;
                        mls_group
                            .merge_pending_commit(&provider)
                            .map_err(|e| EngineError::Backend(format!("merge_pending: {e:?}")))?;

                        let new_epoch = EpochId(mls_group.epoch().as_u64());
                        let prior = EpochId(new_epoch.0.saturating_sub(1));

                        let ctx =
                            group_lifecycle::build_group_context_snapshot(&mls_group, &provider)?;
                        let wrapped = self
                            .peeler
                            .wrap_group_message(
                                &EncryptedPayload {
                                    ciphertext: commit_bytes,
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
                        self.record_sent_message(&wrapped, &group_id, new_epoch)?;
                        self.record_applied_commit_for_recovery(
                            group_id.clone(),
                            pre_commit_epoch,
                            new_epoch,
                            &wrapped,
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
                    self.update_stored_message_state(&msg.id, MessageState::Processed)?;
                    Ok(IngestOutcome::Processed)
                }
                ProcessedMessageContent::ExternalJoinProposalMessage(_) => {
                    self.update_stored_message_state(&msg.id, MessageState::Processed)?;
                    Ok(IngestOutcome::Processed)
                }
            };
        }
    }

    /// Outbound: `SendIntent::AppMessage` only for this iteration. Invite +
    /// Leave + UpdateGroupData land in subsequent Phase 4 slices.
    pub(crate) async fn do_send(&mut self, intent: SendIntent) -> Result<SendResult, EngineError> {
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

        // Fork-detection bookkeeping (Task 4.5) lives on EpochManager —
        // record that we're about to commit FROM the current epoch.
        let pre_commit_epoch = EpochId(mls_group.epoch().as_u64());
        let recovery_snapshot =
            self.fork_recovery
                .create_snapshot(&self.storage, &group_id, pre_commit_epoch)?;
        self.epoch_manager
            .record_committed_from(&group_id, pre_commit_epoch);

        // Stage the add-members commit. Under publish-before-apply (Task
        // 4.13) we do NOT call `merge_pending_commit` here — `mls_group`
        // stays at the pre-commit epoch with the staged commit attached.
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

        let ctx = crate::group_lifecycle::build_group_context_snapshot(&mls_group, &provider)?;
        let commit_msg = self
            .peeler
            .wrap_group_message(
                &EncryptedPayload {
                    ciphertext: commit_bytes,
                    aad: vec![],
                },
                &ctx,
            )
            .await
            .map_err(EngineError::Peeler)?;
        let commit_msg = TransportMessage {
            envelope: TransportEnvelope::GroupMessage {
                transport_group_id: group_id.as_slice().to_vec(),
            },
            ..commit_msg
        };
        self.record_sent_message(&commit_msg, &group_id, pre_commit_epoch)?;

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
            new_epoch,
            &commit_msg,
            recovery_snapshot,
        );

        Ok(SendResult::GroupEvolution {
            msg: commit_msg,
            welcomes,
            pending: pending_ref,
        })
    }

    async fn do_send_leave(&mut self, group_id: GroupId) -> Result<SendResult, EngineError> {
        // Opinionated default — MIP-03 SelfRemove only. `leave_group()` (the
        // legacy pre-SelfRemove Remove-self proposal) is deliberately NOT
        // an option anywhere in this engine. See spike-findings §2.2 and
        // `docs/learnings.md:115-116`.
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
                    ciphertext: bytes,
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
        self.record_sent_message(&wrapped, &group_id, EpochId(mls_group.epoch().as_u64()))?;

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

        // Must be Stable to send (buffering of sends lives in Task 4.13).
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
                    ciphertext: out_bytes,
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
        self.record_sent_message(&wrapped, &group_id, EpochId(mls_group.epoch().as_u64()))?;

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
            MessageState::Processed | MessageState::Failed | MessageState::EpochInvalidated => {
                IngestOutcome::Stale {
                    reason: StaleReason::AlreadySeen,
                }
            }
        };
        Ok(Some(outcome))
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

    fn persist_transport_message(
        &self,
        msg: &TransportMessage,
        group_id: &GroupId,
        epoch: EpochId,
        state: MessageState,
    ) -> Result<(), EngineError> {
        let payload =
            serde_json::to_vec(msg).map_err(|e| EngineError::Serialize(format!("{e:?}")))?;
        self.storage.put_message(&MessageRecord {
            id: msg.id.clone(),
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
                MessageState::Created | MessageState::Retryable
            ) {
                continue;
            }
            let msg: TransportMessage = serde_json::from_slice(&record.payload)
                .map_err(|e| EngineError::Serialize(format!("{e:?}")))?;
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
