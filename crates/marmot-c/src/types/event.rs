//! C mirrors of the top-level runtime event firehose.

use std::ffi::c_char;

use marmot_uniffi::conversions::{GroupEventKindFfi, MarmotEventFfi};

use super::group::MarmotAppGroupHydrationQuarantineReason;
use super::message::MarmotRuntimeMessageReceived;
use super::timeline::MarmotRuntimeProjectionUpdate;
use crate::memory::{CFree, free_c_string, owned_c_string, owned_opt_c_string};

/// One per-group lifecycle event.
#[repr(C)]
pub enum MarmotGroupEventKind {
    GroupCreated,
    GroupJoined {
        via_welcome_hex: *mut c_char,
        /// Nullable.
        welcomer_id_hex: *mut c_char,
    },
    /// A transport object was released because a local resource budget
    /// was exhausted. Exact-id redelivery remains eligible.
    TransportObjectResourceRefused {
        message_id_hex: *mut c_char,
        resource: *mut c_char,
    },
    MessageReceived {
        sender_id_hex: *mut c_char,
        epoch: u64,
    },
    AppMessageInvalidated {
        message_id_hex: *mut c_char,
        epoch: u64,
        reason: *mut c_char,
        /// Nullable.
        decrypted_payload_ref: *mut c_char,
    },
    GroupStateChanged {
        epoch: u64,
        /// Nullable.
        actor_id_hex: *mut c_char,
        change: *mut c_char,
        /// Nullable.
        origin_commit_id_hex: *mut c_char,
    },
    GroupHydrationQuarantined {
        reason: MarmotAppGroupHydrationQuarantineReason,
    },
    EpochChanged {
        from: u64,
        to: u64,
    },
    CommitRolledBack {
        invalidated_commit_id_hex: *mut c_char,
    },
    /// Withdraws every `GroupStateChanged` whose `origin_commit_id_hex`
    /// matches: branch selection superseded that commit.
    GroupStateInvalidated {
        epoch: u64,
        invalidated_commit_id_hex: *mut c_char,
        reason: *mut c_char,
    },
    /// Takes a `GroupStateInvalidated` withdrawal back: a later convergence
    /// pass re-adopted the commit, so every notification it produced describes
    /// canonical history again.
    GroupStateRevalidated {
        epoch: u64,
        revalidated_commit_id_hex: *mut c_char,
    },
    GroupUnrecoverable,
    PendingCommitRecovered {
        recovered_epoch: u64,
    },
    GroupHydrationRecovered {
        recovered_epoch: u64,
    },
}

impl From<GroupEventKindFfi> for MarmotGroupEventKind {
    fn from(value: GroupEventKindFfi) -> Self {
        use GroupEventKindFfi as F;
        match value {
            F::GroupCreated => Self::GroupCreated,
            F::GroupJoined {
                via_welcome_hex,
                welcomer_id_hex,
            } => Self::GroupJoined {
                via_welcome_hex: owned_c_string(via_welcome_hex),
                welcomer_id_hex: owned_opt_c_string(welcomer_id_hex),
            },
            F::TransportObjectResourceRefused {
                message_id_hex,
                resource,
            } => Self::TransportObjectResourceRefused {
                message_id_hex: owned_c_string(message_id_hex),
                resource: owned_c_string(resource),
            },
            F::MessageReceived {
                sender_id_hex,
                epoch,
            } => Self::MessageReceived {
                sender_id_hex: owned_c_string(sender_id_hex),
                epoch,
            },
            F::AppMessageInvalidated {
                message_id_hex,
                epoch,
                reason,
                decrypted_payload_ref,
            } => Self::AppMessageInvalidated {
                message_id_hex: owned_c_string(message_id_hex),
                epoch,
                reason: owned_c_string(reason),
                decrypted_payload_ref: owned_opt_c_string(decrypted_payload_ref),
            },
            F::GroupStateChanged {
                epoch,
                actor_id_hex,
                change,
                origin_commit_id_hex,
            } => Self::GroupStateChanged {
                epoch,
                actor_id_hex: owned_opt_c_string(actor_id_hex),
                change: owned_c_string(change),
                origin_commit_id_hex: owned_opt_c_string(origin_commit_id_hex),
            },
            F::GroupHydrationQuarantined { reason } => Self::GroupHydrationQuarantined {
                reason: reason.into(),
            },
            F::EpochChanged { from, to } => Self::EpochChanged { from, to },
            F::CommitRolledBack {
                invalidated_commit_id_hex,
            } => Self::CommitRolledBack {
                invalidated_commit_id_hex: owned_c_string(invalidated_commit_id_hex),
            },
            F::GroupStateInvalidated {
                epoch,
                invalidated_commit_id_hex,
                reason,
            } => Self::GroupStateInvalidated {
                epoch,
                invalidated_commit_id_hex: owned_c_string(invalidated_commit_id_hex),
                reason: owned_c_string(reason),
            },
            F::GroupStateRevalidated {
                epoch,
                revalidated_commit_id_hex,
            } => Self::GroupStateRevalidated {
                epoch,
                revalidated_commit_id_hex: owned_c_string(revalidated_commit_id_hex),
            },
            F::GroupUnrecoverable => Self::GroupUnrecoverable,
            F::PendingCommitRecovered { recovered_epoch } => {
                Self::PendingCommitRecovered { recovered_epoch }
            }
            F::GroupHydrationRecovered { recovered_epoch } => {
                Self::GroupHydrationRecovered { recovered_epoch }
            }
        }
    }
}

impl CFree for MarmotGroupEventKind {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            match self {
                Self::GroupCreated
                | Self::GroupHydrationQuarantined { .. }
                | Self::EpochChanged { .. }
                | Self::GroupUnrecoverable
                | Self::PendingCommitRecovered { .. }
                | Self::GroupHydrationRecovered { .. } => {}
                Self::GroupJoined {
                    via_welcome_hex,
                    welcomer_id_hex,
                } => {
                    free_c_string(*via_welcome_hex);
                    free_c_string(*welcomer_id_hex);
                }
                Self::TransportObjectResourceRefused {
                    message_id_hex,
                    resource,
                } => {
                    free_c_string(*message_id_hex);
                    free_c_string(*resource);
                }
                Self::MessageReceived { sender_id_hex, .. } => free_c_string(*sender_id_hex),
                Self::AppMessageInvalidated {
                    message_id_hex,
                    reason,
                    decrypted_payload_ref,
                    ..
                } => {
                    free_c_string(*message_id_hex);
                    free_c_string(*reason);
                    free_c_string(*decrypted_payload_ref);
                }
                Self::GroupStateChanged {
                    actor_id_hex,
                    change,
                    origin_commit_id_hex,
                    ..
                } => {
                    free_c_string(*actor_id_hex);
                    free_c_string(*change);
                    free_c_string(*origin_commit_id_hex);
                }
                Self::CommitRolledBack {
                    invalidated_commit_id_hex,
                } => free_c_string(*invalidated_commit_id_hex),
                Self::GroupStateInvalidated {
                    invalidated_commit_id_hex,
                    reason,
                    ..
                } => {
                    free_c_string(*invalidated_commit_id_hex);
                    free_c_string(*reason);
                }
                Self::GroupStateRevalidated {
                    revalidated_commit_id_hex,
                    ..
                } => free_c_string(*revalidated_commit_id_hex),
            }
        }
    }
}

/// One top-level runtime event.
#[repr(C)]
pub enum MarmotEvent {
    GroupJoined {
        account_id_hex: *mut c_char,
        account_label: *mut c_char,
        group_id_hex: *mut c_char,
    },
    GroupStateUpdated {
        account_id_hex: *mut c_char,
        account_label: *mut c_char,
        group_id_hex: *mut c_char,
    },
    MessageReceived {
        received: MarmotRuntimeMessageReceived,
    },
    ProjectionUpdated {
        update: MarmotRuntimeProjectionUpdate,
    },
    GroupEvent {
        account_id_hex: *mut c_char,
        account_label: *mut c_char,
        group_id_hex: *mut c_char,
        event: MarmotGroupEventKind,
    },
    AccountError {
        account_id_hex: *mut c_char,
        account_label: *mut c_char,
        message: *mut c_char,
    },
    AgentStreamActivity {
        account_id_hex: *mut c_char,
        account_label: *mut c_char,
    },
    /// A confirmed create/invite could not deliver a welcome to
    /// `recipient_hex`; that member is unjoinable until the welcome is
    /// re-delivered.
    WelcomeDeliveryPending {
        account_id_hex: *mut c_char,
        account_label: *mut c_char,
        group_id_hex: *mut c_char,
        message_id_hex: *mut c_char,
        recipient_hex: *mut c_char,
    },
    /// This device armed `arms` epoch-gap backfills with no catch-up in
    /// between: the group cannot catch up; re-syncing is recommended.
    EpochStallEscalated {
        account_id_hex: *mut c_char,
        account_label: *mut c_char,
        group_id_hex: *mut c_char,
        stalled_epoch: u64,
        arms: u32,
    },
}

impl From<MarmotEventFfi> for MarmotEvent {
    fn from(value: MarmotEventFfi) -> Self {
        use MarmotEventFfi as F;
        match value {
            F::GroupJoined {
                account_id_hex,
                account_label,
                group_id_hex,
            } => Self::GroupJoined {
                account_id_hex: owned_c_string(account_id_hex),
                account_label: owned_c_string(account_label),
                group_id_hex: owned_c_string(group_id_hex),
            },
            F::GroupStateUpdated {
                account_id_hex,
                account_label,
                group_id_hex,
            } => Self::GroupStateUpdated {
                account_id_hex: owned_c_string(account_id_hex),
                account_label: owned_c_string(account_label),
                group_id_hex: owned_c_string(group_id_hex),
            },
            F::MessageReceived { received } => Self::MessageReceived {
                received: received.into(),
            },
            F::ProjectionUpdated { update } => Self::ProjectionUpdated {
                update: update.into(),
            },
            F::GroupEvent {
                account_id_hex,
                account_label,
                group_id_hex,
                event,
            } => Self::GroupEvent {
                account_id_hex: owned_c_string(account_id_hex),
                account_label: owned_c_string(account_label),
                group_id_hex: owned_c_string(group_id_hex),
                event: event.into(),
            },
            F::AccountError {
                account_id_hex,
                account_label,
                message,
            } => Self::AccountError {
                account_id_hex: owned_c_string(account_id_hex),
                account_label: owned_c_string(account_label),
                message: owned_c_string(message),
            },
            F::AgentStreamActivity {
                account_id_hex,
                account_label,
            } => Self::AgentStreamActivity {
                account_id_hex: owned_c_string(account_id_hex),
                account_label: owned_c_string(account_label),
            },
            F::WelcomeDeliveryPending {
                account_id_hex,
                account_label,
                group_id_hex,
                message_id_hex,
                recipient_hex,
            } => Self::WelcomeDeliveryPending {
                account_id_hex: owned_c_string(account_id_hex),
                account_label: owned_c_string(account_label),
                group_id_hex: owned_c_string(group_id_hex),
                message_id_hex: owned_c_string(message_id_hex),
                recipient_hex: owned_c_string(recipient_hex),
            },
            F::EpochStallEscalated {
                account_id_hex,
                account_label,
                group_id_hex,
                stalled_epoch,
                arms,
            } => Self::EpochStallEscalated {
                account_id_hex: owned_c_string(account_id_hex),
                account_label: owned_c_string(account_label),
                group_id_hex: owned_c_string(group_id_hex),
                stalled_epoch,
                arms,
            },
        }
    }
}

impl CFree for MarmotEvent {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            match self {
                Self::GroupJoined {
                    account_id_hex,
                    account_label,
                    group_id_hex,
                }
                | Self::GroupStateUpdated {
                    account_id_hex,
                    account_label,
                    group_id_hex,
                } => {
                    free_c_string(*account_id_hex);
                    free_c_string(*account_label);
                    free_c_string(*group_id_hex);
                }
                Self::MessageReceived { received } => received.free_in_place(),
                Self::ProjectionUpdated { update } => update.free_in_place(),
                Self::GroupEvent {
                    account_id_hex,
                    account_label,
                    group_id_hex,
                    event,
                } => {
                    free_c_string(*account_id_hex);
                    free_c_string(*account_label);
                    free_c_string(*group_id_hex);
                    event.free_in_place();
                }
                Self::AccountError {
                    account_id_hex,
                    account_label,
                    message,
                } => {
                    free_c_string(*account_id_hex);
                    free_c_string(*account_label);
                    free_c_string(*message);
                }
                Self::AgentStreamActivity {
                    account_id_hex,
                    account_label,
                } => {
                    free_c_string(*account_id_hex);
                    free_c_string(*account_label);
                }
                Self::WelcomeDeliveryPending {
                    account_id_hex,
                    account_label,
                    group_id_hex,
                    message_id_hex,
                    recipient_hex,
                } => {
                    free_c_string(*account_id_hex);
                    free_c_string(*account_label);
                    free_c_string(*group_id_hex);
                    free_c_string(*message_id_hex);
                    free_c_string(*recipient_hex);
                }
                Self::EpochStallEscalated {
                    account_id_hex,
                    account_label,
                    group_id_hex,
                    ..
                } => {
                    free_c_string(*account_id_hex);
                    free_c_string(*account_label);
                    free_c_string(*group_id_hex);
                }
            }
        }
    }
}

// The callback pump moves mirror values across threads before handing C a
// borrowed pointer; mirrors own every pointer they carry exclusively.
unsafe impl Send for MarmotEvent {}

/// Free an event returned by this library. NULL is a no-op.
///
/// # Safety
/// `event` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_event_free(event: *mut MarmotEvent) {
    crate::memory::free_guard(|| unsafe { crate::memory::free_boxed(event) });
}
