//! Top-level event firehose FFI conversion.

use cgka_traits::GroupId;
use cgka_traits::engine::{AppMessageInvalidationReason, GroupEvent, GroupStateChange};
use marmot_app::{AppGroupHydrationQuarantineReason, MarmotAppEvent};

use super::group::AppGroupHydrationQuarantineReasonFfi;
use super::message::RuntimeMessageReceivedFfi;
use super::timeline::RuntimeProjectionUpdateFfi;

/// The group id every [`GroupEvent`] variant carries. Centralised so the FFI
/// firehose can surface it without re-listing all variants at the call site.
fn group_id_from_event(event: &GroupEvent) -> &GroupId {
    match event {
        GroupEvent::GroupCreated { group_id }
        | GroupEvent::GroupJoined { group_id, .. }
        | GroupEvent::MessageReceived { group_id, .. }
        | GroupEvent::AppMessageInvalidated { group_id, .. }
        | GroupEvent::GroupStateChanged { group_id, .. }
        | GroupEvent::EpochChanged { group_id, .. }
        | GroupEvent::ForkRecovered { group_id, .. }
        | GroupEvent::CommitRolledBack { group_id, .. }
        | GroupEvent::GroupUnrecoverable { group_id, .. }
        | GroupEvent::PendingCommitRecovered { group_id, .. }
        | GroupEvent::GroupHydrationQuarantined { group_id, .. }
        | GroupEvent::GroupHydrationRecovered { group_id, .. } => group_id,
    }
}

/// Top-level event firehose, FFI-shaped. Agent streams collapse to a single
/// "agent stream activity" variant — host apps do not differentiate them at
/// the surface level for v1.
// FFI enum: see `TimelineSubscriptionUpdateFfi` — UniFFI lowers each variant
// by value, so boxing wouldn't change the wire size.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, uniffi::Enum)]
pub enum MarmotEventFfi {
    GroupJoined {
        account_id_hex: String,
        account_label: String,
        group_id_hex: String,
    },
    GroupStateUpdated {
        account_id_hex: String,
        account_label: String,
        group_id_hex: String,
    },
    MessageReceived {
        received: RuntimeMessageReceivedFfi,
    },
    ProjectionUpdated {
        update: RuntimeProjectionUpdateFfi,
    },
    GroupEvent {
        account_id_hex: String,
        account_label: String,
        group_id_hex: String,
        event: GroupEventKindFfi,
    },
    AccountError {
        account_id_hex: String,
        account_label: String,
        message: String,
    },
    AgentStreamActivity {
        account_id_hex: String,
        account_label: String,
    },
}

/// FFI projection of [`cgka_traits::engine::GroupEvent`]. The previous FFI
/// firehose collapsed every group event to bare `account_id_hex` /
/// `account_label`, discarding the group id, event kind, and the typed
/// recovery details (quarantine reason, recovered epoch) — so native clients
/// could not react to the typed events the recovery feature surfaces
/// (darkmatter#441 finding 1). This enum mirrors each `GroupEvent` variant and
/// carries its privacy-safe scalar fields: ids are hex-encoded, epochs are
/// `u64`, and the two deeply-nested inner enums (`GroupStateChange`,
/// `AppMessageInvalidationReason`) are surfaced as stable low-cardinality tag
/// strings rather than re-modeled in full. No payloads, ciphertext, plaintext,
/// or key material cross the boundary.
#[derive(Clone, Debug, uniffi::Enum)]
pub enum GroupEventKindFfi {
    GroupCreated,
    GroupJoined {
        via_welcome_hex: String,
        welcomer_id_hex: Option<String>,
    },
    MessageReceived {
        sender_id_hex: String,
        epoch: u64,
    },
    AppMessageInvalidated {
        message_id_hex: String,
        epoch: u64,
        reason: String,
        decrypted_payload_ref: Option<String>,
    },
    GroupStateChanged {
        epoch: u64,
        actor_id_hex: Option<String>,
        change: String,
        origin_commit_id_hex: Option<String>,
    },
    GroupHydrationQuarantined {
        reason: AppGroupHydrationQuarantineReasonFfi,
    },
    EpochChanged {
        from: u64,
        to: u64,
    },
    ForkRecovered {
        source_epoch: u64,
        recovered_epoch: u64,
        invalidated_commit_id_hex: String,
    },
    CommitRolledBack {
        invalidated_commit_id_hex: String,
    },
    GroupUnrecoverable,
    PendingCommitRecovered {
        recovered_epoch: u64,
    },
    GroupHydrationRecovered {
        recovered_epoch: u64,
    },
}

/// Stable, low-cardinality tag for a [`GroupStateChange`] — surfaced to FFI in
/// place of re-modeling the member-id-bearing variants. The subject/actor ids
/// are intentionally not duplicated here; clients that need them should consume
/// the projection/timeline surfaces.
fn group_state_change_tag(change: &GroupStateChange) -> &'static str {
    match change {
        GroupStateChange::MemberAdded { .. } => "member_added",
        GroupStateChange::MemberRemoved { .. } => "member_removed",
        GroupStateChange::MemberLeft { .. } => "member_left",
        GroupStateChange::AdminAdded { .. } => "admin_added",
        GroupStateChange::AdminRemoved { .. } => "admin_removed",
        GroupStateChange::GroupRenamed { .. } => "group_renamed",
        GroupStateChange::GroupAvatarChanged => "group_avatar_changed",
        GroupStateChange::MessageRetentionChanged { .. } => "disappearing_timer_changed",
    }
}

/// Stable, low-cardinality tag for an [`AppMessageInvalidationReason`].
fn app_message_invalidation_reason_tag(reason: &AppMessageInvalidationReason) -> &'static str {
    match reason {
        AppMessageInvalidationReason::LosingBranch => "losing_branch",
        AppMessageInvalidationReason::BeyondAnchor => "beyond_anchor",
        AppMessageInvalidationReason::BeyondAppRetention => "beyond_app_retention",
        AppMessageInvalidationReason::UndecryptableInCanonicalState => {
            "undecryptable_in_canonical_state"
        }
    }
}

impl From<GroupEvent> for GroupEventKindFfi {
    fn from(event: GroupEvent) -> Self {
        match event {
            GroupEvent::GroupCreated { .. } => Self::GroupCreated,
            GroupEvent::GroupJoined {
                via_welcome,
                welcomer,
                ..
            } => Self::GroupJoined {
                via_welcome_hex: hex::encode(via_welcome.as_slice()),
                welcomer_id_hex: welcomer.map(|m| hex::encode(m.as_slice())),
            },
            GroupEvent::MessageReceived { sender, epoch, .. } => Self::MessageReceived {
                sender_id_hex: hex::encode(sender.as_slice()),
                epoch: epoch.0,
            },
            GroupEvent::AppMessageInvalidated {
                message_id,
                epoch,
                reason,
                decrypted_payload_ref,
                ..
            } => Self::AppMessageInvalidated {
                message_id_hex: hex::encode(message_id.as_slice()),
                epoch: epoch.0,
                reason: app_message_invalidation_reason_tag(&reason).to_string(),
                decrypted_payload_ref,
            },
            GroupEvent::GroupStateChanged {
                epoch,
                actor,
                change,
                origin_commit_id,
                ..
            } => Self::GroupStateChanged {
                epoch: epoch.0,
                actor_id_hex: actor.map(|m| hex::encode(m.as_slice())),
                change: group_state_change_tag(&change).to_string(),
                origin_commit_id_hex: origin_commit_id.map(|m| hex::encode(m.as_slice())),
            },
            GroupEvent::GroupHydrationQuarantined { reason, .. } => {
                Self::GroupHydrationQuarantined {
                    reason: AppGroupHydrationQuarantineReason::from(reason).into(),
                }
            }
            GroupEvent::EpochChanged { from, to, .. } => Self::EpochChanged {
                from: from.0,
                to: to.0,
            },
            GroupEvent::ForkRecovered {
                source_epoch,
                recovered_epoch,
                invalidated_commit_id,
                ..
            } => Self::ForkRecovered {
                source_epoch: source_epoch.0,
                recovered_epoch: recovered_epoch.0,
                invalidated_commit_id_hex: hex::encode(invalidated_commit_id.as_slice()),
            },
            GroupEvent::CommitRolledBack {
                invalidated_commit_id,
                ..
            } => Self::CommitRolledBack {
                invalidated_commit_id_hex: hex::encode(invalidated_commit_id.as_slice()),
            },
            GroupEvent::GroupUnrecoverable { .. } => Self::GroupUnrecoverable,
            GroupEvent::PendingCommitRecovered {
                recovered_epoch, ..
            } => Self::PendingCommitRecovered {
                recovered_epoch: recovered_epoch.0,
            },
            GroupEvent::GroupHydrationRecovered {
                recovered_epoch, ..
            } => Self::GroupHydrationRecovered {
                recovered_epoch: recovered_epoch.0,
            },
        }
    }
}

impl From<MarmotAppEvent> for MarmotEventFfi {
    fn from(value: MarmotAppEvent) -> Self {
        match value {
            MarmotAppEvent::GroupJoined {
                account_id_hex,
                account_label,
                group_id,
            } => Self::GroupJoined {
                account_id_hex,
                account_label,
                group_id_hex: hex::encode(group_id.as_slice()),
            },
            MarmotAppEvent::GroupStateUpdated {
                account_id_hex,
                account_label,
                group_id,
            } => Self::GroupStateUpdated {
                account_id_hex,
                account_label,
                group_id_hex: hex::encode(group_id.as_slice()),
            },
            MarmotAppEvent::MessageReceived(m) => Self::MessageReceived { received: m.into() },
            MarmotAppEvent::ProjectionUpdated(update) => Self::ProjectionUpdated {
                update: update.into(),
            },
            MarmotAppEvent::GroupEvent(e) => {
                let group_id_hex = hex::encode(group_id_from_event(&e.event).as_slice());
                Self::GroupEvent {
                    account_id_hex: e.account_id_hex,
                    account_label: e.account_label,
                    group_id_hex,
                    event: e.event.into(),
                }
            }
            MarmotAppEvent::AccountError(e) => Self::AccountError {
                account_id_hex: e.account_id_hex,
                account_label: e.account_label,
                message: e.message,
            },
            MarmotAppEvent::AgentStreamStarted(m) => Self::AgentStreamActivity {
                account_id_hex: m.account_id_hex,
                account_label: m.account_label,
            },
        }
    }
}
