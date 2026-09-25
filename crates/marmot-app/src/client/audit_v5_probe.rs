//! Bounded Welcome observations from the normal app operation path. When a v5
//! recorder is enabled, the same events are written by its source/session;
//! tests can inspect a private in-memory probe without changing product flow.
//!
//! A received envelope, its actual transport peel, and a committed app
//! checkpoint are distinct evidence boundaries. A sender founding preparation
//! also records the returned retained artifact and recipient engine join.
//! Publication receipts are captured at the account owner boundary.
use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use cgka_session::{PublishWork, SessionEffects};
use cgka_traits::engine::WelcomeMetadata;
use cgka_traits::error::PeelerError;
use cgka_traits::group::{Group, ProtocolProfile};
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::PeeledMessage;
use cgka_traits::peeler::{GroupMessageMetadata, TransportPeeler};
use cgka_traits::transport::EncryptedPayload;
use cgka_traits::types::MemberId;
use cgka_traits::{GroupEvent, GroupId, MessageId, TransportMessage};
use marmot_forensics::v5::*;
use transport_nostr_peeler::{NostrMlsPeeler, NostrTransportEvent, WelcomePeelProvenance};

use crate::AppGroupRecord;

const MAX_ROWS: usize = 128;
const MAX_BYTES: usize = 256 * 1024;
const MAX_PENDING: usize = 64;

/// Public selection captured from the already validated KeyPackage metadata
/// on the real app create path. No KeyPackage bytes or secrets enter the probe.
pub(crate) struct FoundingSelection {
    pub recipient_hex: String,
    pub key_package_event_id: Option<MessageId>,
}

pub(crate) struct PendingFounding {
    selected: BTreeMap<Vec<u8>, (LocalId, [u8; 32])>,
}

/// One selected AppClient delivery episode. The app arms it before engine
/// ingress and drains it immediately after. No source/session lives here.
#[derive(Default)]
pub(crate) struct PeelSlot {
    armed: Option<(Vec<u8>, LocalId, NostrEventRef)>,
    completed: Option<PeelCompletion>,
}

pub(crate) struct PeelCompletion {
    pub receive_id: LocalId,
    pub outer: NostrEventRef,
    pub result: UnwrapResult,
    pub reason: Option<UnwrapReason>,
    pub provenance: Option<WelcomePeelProvenance>,
    pub elapsed_us: u64,
}

impl PeelSlot {
    pub(crate) fn arm(&mut self, message: &TransportMessage, receive: (LocalId, NostrEventRef)) {
        self.armed = Some((message.id.as_slice().to_vec(), receive.0, receive.1));
        self.completed = None;
    }

    pub(crate) fn take(&mut self) -> Option<PeelCompletion> {
        self.armed = None;
        self.completed.take()
    }
}

/// The only selected test peeler. It delegates product behavior, and observes
/// the same concrete Welcome peel the engine uses without a second decode.
pub(crate) struct ProbePeeler {
    pub inner: NostrMlsPeeler,
    pub slot: Arc<Mutex<PeelSlot>>,
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl TransportPeeler for ProbePeeler {
    async fn peel_group_message(
        &self,
        msg: &TransportMessage,
        ctx: &GroupContextSnapshot,
    ) -> Result<PeeledMessage, PeelerError> {
        self.inner.peel_group_message(msg, ctx).await
    }

    async fn peel_welcome(&self, msg: &TransportMessage) -> Result<PeeledMessage, PeelerError> {
        let started = Instant::now();
        let result = self.inner.peel_welcome_with_provenance(msg).await;
        let elapsed_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
        let mut slot = self.slot.lock().unwrap();
        if let Some((id, receive_id, outer)) = slot.armed.take()
            && id == msg.id.as_slice()
        {
            let (outcome, reason, provenance) = match &result {
                Ok((_, provenance)) => (UnwrapResult::Validated, None, Some(provenance.clone())),
                Err(error) => {
                    let (outcome, reason) = match error {
                        PeelerError::WrongRecipient => {
                            (UnwrapResult::Rejected, UnwrapReason::WrongRecipient)
                        }
                        PeelerError::InvalidSignature => {
                            (UnwrapResult::Rejected, UnwrapReason::InvalidSignature)
                        }
                        PeelerError::Malformed(_) => {
                            (UnwrapResult::Rejected, UnwrapReason::InvalidEncoding)
                        }
                        PeelerError::DecryptFailed => {
                            (UnwrapResult::Failed, UnwrapReason::UnwrapFailed)
                        }
                        PeelerError::MissingContext { .. } | PeelerError::Backend(_) => {
                            (UnwrapResult::Failed, UnwrapReason::InternalFailed)
                        }
                        PeelerError::StaleEpoch { .. } | PeelerError::WrapFailed(_) => {
                            (UnwrapResult::Failed, UnwrapReason::Unclassified)
                        }
                    };
                    (outcome, Some(reason), None)
                }
            };
            slot.completed = Some(PeelCompletion {
                receive_id,
                outer,
                result: outcome,
                reason,
                provenance,
                elapsed_us,
            });
        }
        result.map(|(peeled, _)| peeled)
    }

    async fn wrap_group_message(
        &self,
        payload: &EncryptedPayload,
        ctx: &GroupContextSnapshot,
    ) -> Result<TransportMessage, PeelerError> {
        self.inner.wrap_group_message(payload, ctx).await
    }

    async fn wrap_group_message_with_metadata(
        &self,
        payload: &EncryptedPayload,
        ctx: &GroupContextSnapshot,
        metadata: &GroupMessageMetadata,
    ) -> Result<TransportMessage, PeelerError> {
        self.inner
            .wrap_group_message_with_metadata(payload, ctx, metadata)
            .await
    }

    async fn wrap_welcome(
        &self,
        payload: &EncryptedPayload,
        recipient: &MemberId,
    ) -> Result<TransportMessage, PeelerError> {
        self.inner.wrap_welcome(payload, recipient).await
    }

    async fn wrap_welcome_with_metadata(
        &self,
        payload: &EncryptedPayload,
        recipient: &MemberId,
        metadata: &WelcomeMetadata,
    ) -> Result<TransportMessage, PeelerError> {
        self.inner
            .wrap_welcome_with_metadata(payload, recipient, metadata)
            .await
    }
}

pub(crate) struct WelcomeProbe {
    source: SourceRef,
    session: SessionId,
    producer: Producer,
    started: Instant,
    seq: u64,
    next_id: u64,
    bytes: usize,
    pub(super) rows: Vec<Record>,
    live: bool,
    pending_live: Vec<(Option<GroupRef>, Event)>,
    validated_refs: Vec<(String, NostrEventRef, LocalId, GroupRef)>,
    // Only origins observed at an actual projection path are eligible. Absence
    // of a receive row never implies local replay or successful computation.
    projections: BTreeMap<String, UpdateCause>,
    pub(super) dropped: usize,
    pub(super) invalid: usize,
    #[cfg(test)]
    pub(super) reject_checkpoints: bool,
}

pub(super) struct PendingUpdate {
    group: GroupRef,
    outer: NostrEventRef,
    cause: UpdateCause,
    invite: InviteState,
    projection_key: Option<String>,
}

impl PendingUpdate {
    fn for_group(group: &AppGroupRecord, cause: UpdateCause) -> Option<Self> {
        // This is persisted engine-derived Welcome provenance, never a group
        // routing id or a caller-supplied substitute for the outer event id.
        let welcome_id = hex::decode(group.via_welcome_message_id_hex.as_ref()?).ok()?;
        let id: [u8; 32] = welcome_id.try_into().ok()?;
        Some(Self {
            group: GroupRef::from_group_id(&hex::decode(&group.group_id_hex).ok()?).ok()?,
            outer: NostrEventRef::from_validated_event_id(&id),
            cause,
            invite: if group.pending_confirmation {
                InviteState::PendingConfirmation
            } else {
                InviteState::Accepted
            },
            projection_key: None,
        })
    }
}

impl WelcomeProbe {
    pub(super) fn new(source: SourceRef, session: SessionId, producer: Producer) -> Self {
        Self {
            source,
            session,
            producer,
            started: Instant::now(),
            seq: 0,
            next_id: 0,
            bytes: 0,
            rows: Vec::new(),
            live: false,
            pending_live: Vec::new(),
            validated_refs: Vec::new(),
            projections: BTreeMap::new(),
            dropped: 0,
            invalid: 0,
            #[cfg(test)]
            reject_checkpoints: false,
        }
    }

    pub(crate) fn live() -> Self {
        let mut probe = Self::new(
            "00".repeat(16).try_into().expect("valid placeholder"),
            "00".repeat(16).try_into().expect("valid placeholder"),
            Producer {
                mdk_revision: None,
                build_profile: BuildProfile::Debug,
                platform: Platform::Other,
                host_build: None,
            },
        );
        probe.live = true;
        probe
    }

    pub(super) fn take_live_events(&mut self) -> Vec<(Option<GroupRef>, Event)> {
        std::mem::take(&mut self.pending_live)
    }

    pub(super) fn take_validated_refs(
        &mut self,
    ) -> Vec<(String, NostrEventRef, LocalId, GroupRef)> {
        std::mem::take(&mut self.validated_refs)
    }

    fn local_id(&mut self) -> LocalId {
        self.next_id += 1;
        format!("{:032x}", self.next_id).try_into().unwrap()
    }

    fn record(&mut self, group_ref: Option<GroupRef>, event: Event) {
        if self.live {
            if self.pending_live.len() < MAX_ROWS {
                self.pending_live.push((group_ref, event));
            } else {
                self.dropped += 1;
            }
            return;
        }
        self.seq += 1;
        let row = Record::new(RecordFields {
            schema_version: SchemaVersion::V5,
            source_ref: self.source.clone(),
            session_id: self.session.clone(),
            seq: self.seq.into(),
            wall_time_ms: i64::try_from(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis(),
            )
            .unwrap()
            .into(),
            mono_us: u64::try_from(self.started.elapsed().as_micros())
                .unwrap()
                .into(),
            producer: self.producer.clone(),
            group_ref,
            event,
        });
        let Ok(row) = row else {
            self.invalid += 1;
            return;
        };
        let size = row.to_json().unwrap().len();
        if self.rows.len() == MAX_ROWS || self.bytes + size > MAX_BYTES {
            self.dropped += 1;
            return;
        }
        self.bytes += size;
        self.rows.push(row);
    }

    /// Allocate operation IDs before the authoritative preparation call. A
    /// failed call drops this bounded token and emits no fictitious terminal.
    pub(crate) fn begin_founding(
        &mut self,
        selections: Vec<FoundingSelection>,
    ) -> Option<PendingFounding> {
        if selections.len() > MAX_PENDING {
            self.dropped += selections.len();
            return None;
        }
        let mut selected = BTreeMap::new();
        for selection in selections {
            let Ok(recipient) = hex::decode(selection.recipient_hex) else {
                self.invalid += 1;
                return None;
            };
            if recipient.len() != 32 {
                self.invalid += 1;
                return None;
            }
            let Some(event_id) = selection.key_package_event_id else {
                self.invalid += 1;
                return None;
            };
            let Ok(event_id) = <[u8; 32]>::try_from(event_id.as_slice()) else {
                self.invalid += 1;
                return None;
            };
            let op_id = self.local_id();
            if selected.insert(recipient, (op_id, event_id)).is_some() {
                self.invalid += 1;
                return None;
            }
        }
        Some(PendingFounding { selected })
    }

    /// The returned FoundingGroupCreated artifact comes after the engine's
    /// canonical transaction retained these exact Welcome messages as Sent.
    /// Match by validated recipient identity, never by incidental vec order.
    pub(crate) fn founding_prepared(
        &mut self,
        mut pending: PendingFounding,
        group_id: &GroupId,
        effects: &SessionEffects,
    ) {
        let Ok(group_ref) = GroupRef::from_group_id(group_id.as_slice()) else {
            self.invalid += 1;
            return;
        };
        let mut rows = Vec::new();
        let mut found_work = false;
        for work in &effects.publish {
            let PublishWork::FoundingGroupCreated { welcomes } = work else {
                continue;
            };
            if found_work {
                self.invalid += 1;
                return;
            }
            found_work = true;
            for welcome in welcomes {
                let cgka_traits::transport::TransportEnvelope::Welcome { recipient } =
                    &welcome.envelope
                else {
                    self.invalid += 1;
                    return;
                };
                let Some((op_id, key_package_event_id)) =
                    pending.selected.remove(recipient.as_slice())
                else {
                    self.invalid += 1;
                    return;
                };
                let Ok(outer) = NostrTransportEvent::from_transport_message(welcome)
                    .and_then(|event| event.to_transport_message())
                else {
                    self.invalid += 1;
                    return;
                };
                if outer.id != welcome.id || outer.envelope != welcome.envelope {
                    self.invalid += 1;
                    return;
                }
                let Ok(outer_event_id) = <[u8; 32]>::try_from(outer.id.as_slice()) else {
                    self.invalid += 1;
                    return;
                };
                let Ok(recipient_ref) = MemberRef::from_member_identity(recipient.as_slice())
                else {
                    self.invalid += 1;
                    return;
                };
                rows.push((op_id, recipient_ref, key_package_event_id, outer_event_id));
            }
        }
        if !found_work || !pending.selected.is_empty() {
            self.invalid += 1;
            return;
        }
        for (op_id, recipient_ref, key_package_event_id, outer_event_id) in rows {
            self.validated_refs.push((
                hex::encode(outer_event_id),
                NostrEventRef::from_validated_event_id(&outer_event_id),
                op_id.clone(),
                group_ref.clone(),
            ));
            self.record(
                Some(group_ref.clone()),
                Event::WelcomePrepared(WelcomePrepared {
                    op_id,
                    recipient_ref,
                    mode: Mode::Founding,
                    basis: Basis::Founding {},
                    key_package_event_ref: Some(NostrEventRef::from_validated_event_id(
                        &key_package_event_id,
                    )),
                    outer_event_ref: Some(NostrEventRef::from_validated_event_id(&outer_event_id)),
                    construction: Construction::Constructed,
                    retention: Retention::Committed,
                    failure_stage: None,
                    reason: None,
                    // A batch duration would misstate per-recipient construction.
                    elapsed_us: None,
                }),
            );
        }
    }

    pub(super) fn observe(
        &mut self,
        message: &TransportMessage,
    ) -> Option<(LocalId, NostrEventRef)> {
        // Validate the NIP-01 hash and envelope before deriving a Nostr reference.
        // This is not signature/decryption evidence. The normal peeler still
        // owns those decisions, and probe failure never changes admission.
        let validated = NostrTransportEvent::from_transport_message(message)
            .and_then(|event| event.to_transport_message());
        let Ok(validated) = validated else {
            self.invalid += 1;
            return None;
        };
        if validated.id != message.id {
            self.invalid += 1;
            return None;
        }
        let Ok(id) = <[u8; 32]>::try_from(validated.id.as_slice()) else {
            self.invalid += 1;
            return None;
        };
        let receive_id = self.local_id();
        let outer = NostrEventRef::from_validated_event_id(&id);
        let before = if self.live {
            self.pending_live.len()
        } else {
            self.rows.len()
        };
        self.record(
            None,
            Event::WelcomeObserved(WelcomeObserved {
                receive_id: receive_id.clone(),
                outer_event_ref: outer.clone(),
                // The app drain does not expose a reliable live/history distinction.
                acquisition: Acquisition::Unknown,
                endpoint_ref: None,
                fetch_id: None,
            }),
        );
        let after = if self.live {
            self.pending_live.len()
        } else {
            self.rows.len()
        };
        (after > before).then_some((receive_id, outer))
    }

    pub(super) fn unwrapped(&mut self, completion: PeelCompletion) {
        self.record(
            None,
            Event::WelcomeUnwrapped(WelcomeUnwrapped {
                receive_id: completion.receive_id,
                outer_event_ref: completion.outer,
                result: completion.result,
                rumor_event_ref: completion
                    .provenance
                    .as_ref()
                    .map(|p| NostrEventRef::from_validated_event_id(&p.rumor_event_id)),
                key_package_event_ref: completion
                    .provenance
                    .as_ref()
                    .map(|p| NostrEventRef::from_validated_event_id(&p.key_package_event_id)),
                reason: completion.reason,
                elapsed_us: Some(completion.elapsed_us.into()),
            }),
        );
    }

    /// The matching GroupJoined was durably journaled in the engine's join
    /// transaction. The copy-install epoch is written there too; a buffered
    /// group message can advance `group.epoch` before this call returns.
    pub(super) fn joined(&mut self, receive: (LocalId, NostrEventRef), group: &Group) -> bool {
        // A replacement Welcome resets join_epoch to zero. Zero is also the
        // stored unknown-bound sentinel; only equal, known first-join and
        // copy-install epochs establish this subset's initial-join scope.
        if group.protocol_profile != ProtocolProfile::Current
            || group.is_terminal()
            || group.join_epoch.0 == 0
            || group.join_epoch != group.local_copy_install_epoch
        {
            return false;
        }
        let Ok(group_ref) = GroupRef::from_group_id(group.id.as_slice()) else {
            self.invalid += 1;
            return false;
        };
        self.record(
            Some(group_ref),
            Event::WelcomeJoinFinished(WelcomeJoinFinished {
                receive_id: receive.0,
                outer_event_ref: receive.1,
                result: JoinResult::Joined,
                reason: None,
                epoch: Some(group.local_copy_install_epoch.0.into()),
                engine_commit: EngineCommit::Committed,
                elapsed_us: None,
            }),
        );
        true
    }

    /// Snapshot the authoritative stored roster once at a canonical create or
    /// join boundary. Admin policy read failure is explicit partial coverage.
    pub(super) fn baseline(
        &mut self,
        group: &Group,
        admins: Option<&[[u8; 32]]>,
        reason: BaselineReason,
        cause_outer_event_ref: Option<NostrEventRef>,
    ) {
        if group.protocol_profile != ProtocolProfile::Current || group.is_terminal() {
            return;
        }
        let Ok(group_ref) = GroupRef::from_group_id(group.id.as_slice()) else {
            return;
        };
        let mut members = group
            .members
            .iter()
            .filter_map(|member| {
                let member_ref = MemberRef::from_member_identity(member.id.as_slice()).ok()?;
                let admin = admins.and_then(|admins| {
                    let id: [u8; 32] = member.id.as_slice().try_into().ok()?;
                    Some(admins.contains(&id))
                });
                Some(BaselineMember { member_ref, admin })
            })
            .collect::<Vec<_>>();
        members.sort_by(|a, b| a.member_ref.cmp(&b.member_ref));
        members.dedup_by(|a, b| a.member_ref == b.member_ref);
        let member_count = u32::try_from(group.members.len()).ok();
        let mut limitations = Vec::new();
        if members.len() > MAX_MEMBERS {
            members.truncate(MAX_MEMBERS);
            limitations.push(Limitation::MemberLimit);
        }
        if admins.is_none() || members.iter().any(|member| member.admin.is_none()) {
            limitations.push(Limitation::AdminPolicyUnavailable);
        }
        let members_complete = member_count == Some(members.len() as u32);
        self.record(
            Some(group_ref),
            Event::GroupBaseline(GroupBaseline {
                reason,
                cause_outer_event_ref,
                epoch: Some(group.epoch.0.into()),
                basis: if reason == BaselineReason::Created {
                    Basis::Founding {}
                } else {
                    Basis::Unavailable {}
                },
                members,
                member_count,
                members_complete,
                limitations: limitations.clone(),
                capture: if limitations.is_empty() && members_complete {
                    Capture::Complete
                } else {
                    Capture::Partial
                },
            }),
        );
    }

    pub(super) fn projected(&mut self, event: &GroupEvent, cause: UpdateCause) {
        if let GroupEvent::GroupJoined { via_welcome, .. } = event {
            let key = hex::encode(via_welcome.as_slice());
            if self.projections.len() < MAX_PENDING || self.projections.contains_key(&key) {
                self.projections.insert(key, cause);
            } else {
                self.dropped += 1;
            }
        }
    }

    // Attribute acceptance at the same checkpoint as Welcome projection work.
    // If the operation rolls its candidate back, restore the prior origin too.
    pub(super) fn begin_confirmation(
        &mut self,
        group: &AppGroupRecord,
    ) -> Option<(String, Option<UpdateCause>)> {
        let key = group.via_welcome_message_id_hex.clone()?;
        if self.projections.len() == MAX_PENDING && !self.projections.contains_key(&key) {
            self.dropped += 1;
            return None;
        }
        let previous = self
            .projections
            .insert(key.clone(), UpdateCause::InviteConfirmation);
        Some((key, previous))
    }

    pub(super) fn rollback_confirmation(&mut self, origin: (String, Option<UpdateCause>)) {
        let (key, previous) = origin;
        if let Some(cause) = previous {
            self.projections.insert(key, cause);
        } else {
            self.projections.remove(&key);
        }
    }

    pub(super) fn pending_updates(
        &self,
        groups: &[AppGroupRecord],
        dirty: &HashSet<String>,
    ) -> Vec<PendingUpdate> {
        groups
            .iter()
            .filter_map(|group| {
                if !dirty.contains(&group.group_id_hex) {
                    return None;
                }
                let key = group.via_welcome_message_id_hex.as_ref()?;
                let cause = *self.projections.get(key)?;
                let mut update = PendingUpdate::for_group(group, cause)?;
                update.projection_key = Some(key.clone());
                Some(update)
            })
            .collect()
    }

    pub(super) fn finish_checkpoint(
        &mut self,
        updates: Vec<PendingUpdate>,
        success: bool,
        known_before_commit: bool,
    ) {
        for update in updates {
            let update_id = self.local_id();
            self.record(
                Some(update.group),
                Event::AppGroupUpdateFinished(AppGroupUpdateFinished {
                    update_id,
                    outer_event_ref: update.outer,
                    cause: update.cause,
                    compute: Compute::Completed,
                    checkpoint: if success {
                        Checkpoint::Committed
                    } else if known_before_commit {
                        Checkpoint::FailedBeforeCommit
                    } else {
                        Checkpoint::Unknown
                    },
                    invite_state: if success {
                        update.invite
                    } else {
                        InviteState::Unknown
                    },
                    reason: (!success).then_some(UpdateReason::Unclassified),
                    // No misleading ingest-to-checkpoint timing: this slice has not
                    // instrumented the complete computation/checkpoint interval.
                    elapsed_us: None,
                }),
            );
            if success && let Some(key) = update.projection_key {
                self.projections.remove(&key);
            }
        }
    }
}

#[cfg(test)]
mod tests;
