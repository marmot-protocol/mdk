//! Unit-test-only observations of the real recipient app path. Not a v5 recorder
//! option, upload source, or native API. Production does not compile this module.
//!
//! These two event families deliberately say nothing about successful unwrap,
//! engine commit, baseline capture, relay ACKs, or sender construction. A received
//! envelope and a committed app checkpoint are distinct evidence boundaries.
use std::collections::{BTreeMap, HashSet};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use cgka_traits::{GroupEvent, TransportMessage};
use marmot_forensics::v5::*;
use transport_nostr_peeler::NostrTransportEvent;

use crate::AppGroupRecord;

const MAX_ROWS: usize = 128;
const MAX_BYTES: usize = 256 * 1024;
const MAX_PENDING: usize = 64;

pub(crate) struct WelcomeProbe {
    source: SourceRef,
    session: SessionId,
    producer: Producer,
    started: Instant,
    seq: u64,
    next_id: u64,
    bytes: usize,
    pub(super) rows: Vec<Record>,
    // Only origins observed at an actual projection path are eligible. Absence
    // of a receive row never implies local replay or successful computation.
    projections: BTreeMap<String, UpdateCause>,
    pub(super) dropped: usize,
    pub(super) invalid: usize,
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
            projections: BTreeMap::new(),
            dropped: 0,
            invalid: 0,
            reject_checkpoints: false,
        }
    }

    fn local_id(&mut self) -> LocalId {
        self.next_id += 1;
        format!("{:032x}", self.next_id).try_into().unwrap()
    }

    fn record(&mut self, group_ref: Option<GroupRef>, event: Event) {
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

    pub(super) fn observe(&mut self, message: &TransportMessage) {
        // Validate the NIP-01 hash and envelope before deriving a Nostr reference.
        // This is not signature/decryption evidence. The normal peeler still
        // owns those decisions, and probe failure never changes admission.
        let validated = NostrTransportEvent::from_transport_message(message)
            .and_then(|event| event.to_transport_message());
        let Ok(validated) = validated else {
            self.invalid += 1;
            return;
        };
        if validated.id != message.id {
            self.invalid += 1;
            return;
        }
        let Ok(id) = <[u8; 32]>::try_from(validated.id.as_slice()) else {
            self.invalid += 1;
            return;
        };
        let receive_id = self.local_id();
        self.record(
            None,
            Event::WelcomeObserved(WelcomeObserved {
                receive_id,
                outer_event_ref: NostrEventRef::from_validated_event_id(&id),
                // The app drain does not expose a reliable live/history distinction.
                acquisition: Acquisition::Unknown,
                endpoint_ref: None,
                fetch_id: None,
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
