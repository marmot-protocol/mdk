//! C mirrors of the top-level event firehose conversions
//! (`marmot-uniffi/src/conversions/event.rs`).

use std::ffi::c_char;

use marmot_uniffi::conversions::{GroupEventKindFfi, MarmotEventFfi};

use crate::memory::{CFree, free_boxed, free_c_string, owned_c_string, owned_opt_c_string};
use crate::types::group::MarmotAppGroupHydrationQuarantineReason;
use crate::types::message::MarmotRuntimeMessageReceived;
use crate::types::timeline::MarmotRuntimeProjectionUpdate;

/// Per-group event kind delivered inside [`MarmotEvent::GroupEvent`]. Mirrors
/// the engine's typed group events with privacy-safe scalar fields only: ids
/// are hex-encoded, epochs are `u64`, and the deeply-nested inner enums
/// (group-state change, app-message invalidation reason) are surfaced as
/// stable low-cardinality tag strings rather than re-modeled in full. No
/// payloads, ciphertext, plaintext, or key material cross the boundary.
#[repr(C)]
pub enum MarmotGroupEventKind {
    GroupCreated,
    GroupJoined {
        via_welcome_hex: *mut c_char,
        /// Member id of the welcomer, when known. Nullable.
        welcomer_id_hex: *mut c_char,
    },
    MessageReceived {
        sender_id_hex: *mut c_char,
        epoch: u64,
    },
    AppMessageInvalidated {
        message_id_hex: *mut c_char,
        epoch: u64,
        /// Stable low-cardinality tag (e.g. `losing_branch`, `beyond_anchor`).
        reason: *mut c_char,
        /// Reference to the previously-decrypted payload, when one exists.
        /// Nullable.
        decrypted_payload_ref: *mut c_char,
    },
    GroupStateChanged {
        epoch: u64,
        /// Member id of the actor, when known. Nullable.
        actor_id_hex: *mut c_char,
        /// Stable low-cardinality tag (e.g. `member_added`, `group_renamed`).
        change: *mut c_char,
        /// Commit id this change originated from, when known. Nullable.
        origin_commit_id_hex: *mut c_char,
    },
    GroupHydrationQuarantined {
        reason: MarmotAppGroupHydrationQuarantineReason,
    },
    EpochChanged {
        from: u64,
        to: u64,
    },
    ForkRecovered {
        source_epoch: u64,
        recovered_epoch: u64,
        invalidated_commit_id_hex: *mut c_char,
    },
    CommitRolledBack {
        invalidated_commit_id_hex: *mut c_char,
    },
    /// Explicit withdrawal of every `GroupStateChanged` notification whose
    /// `origin_commit_id_hex` matches `invalidated_commit_id_hex`: branch
    /// selection superseded that commit, so the changes it announced never
    /// canonically happened. `reason` is a stable low-cardinality tag
    /// (`superseded_by_branch_selection`).
    GroupStateInvalidated {
        epoch: u64,
        invalidated_commit_id_hex: *mut c_char,
        reason: *mut c_char,
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
        match value {
            GroupEventKindFfi::GroupCreated => Self::GroupCreated,
            GroupEventKindFfi::GroupJoined {
                via_welcome_hex,
                welcomer_id_hex,
            } => Self::GroupJoined {
                via_welcome_hex: owned_c_string(via_welcome_hex),
                welcomer_id_hex: owned_opt_c_string(welcomer_id_hex),
            },
            GroupEventKindFfi::MessageReceived {
                sender_id_hex,
                epoch,
            } => Self::MessageReceived {
                sender_id_hex: owned_c_string(sender_id_hex),
                epoch,
            },
            GroupEventKindFfi::AppMessageInvalidated {
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
            GroupEventKindFfi::GroupStateChanged {
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
            GroupEventKindFfi::GroupHydrationQuarantined { reason } => {
                Self::GroupHydrationQuarantined {
                    reason: reason.into(),
                }
            }
            GroupEventKindFfi::EpochChanged { from, to } => Self::EpochChanged { from, to },
            GroupEventKindFfi::ForkRecovered {
                source_epoch,
                recovered_epoch,
                invalidated_commit_id_hex,
            } => Self::ForkRecovered {
                source_epoch,
                recovered_epoch,
                invalidated_commit_id_hex: owned_c_string(invalidated_commit_id_hex),
            },
            GroupEventKindFfi::CommitRolledBack {
                invalidated_commit_id_hex,
            } => Self::CommitRolledBack {
                invalidated_commit_id_hex: owned_c_string(invalidated_commit_id_hex),
            },
            GroupEventKindFfi::GroupStateInvalidated {
                epoch,
                invalidated_commit_id_hex,
                reason,
            } => Self::GroupStateInvalidated {
                epoch,
                invalidated_commit_id_hex: owned_c_string(invalidated_commit_id_hex),
                reason: owned_c_string(reason),
            },
            GroupEventKindFfi::GroupUnrecoverable => Self::GroupUnrecoverable,
            GroupEventKindFfi::PendingCommitRecovered { recovered_epoch } => {
                Self::PendingCommitRecovered { recovered_epoch }
            }
            GroupEventKindFfi::GroupHydrationRecovered { recovered_epoch } => {
                Self::GroupHydrationRecovered { recovered_epoch }
            }
        }
    }
}

impl CFree for MarmotGroupEventKind {
    unsafe fn free_in_place(&mut self) {
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
            } => unsafe {
                free_c_string(*via_welcome_hex);
                free_c_string(*welcomer_id_hex);
            },
            Self::MessageReceived { sender_id_hex, .. } => unsafe {
                free_c_string(*sender_id_hex);
            },
            Self::AppMessageInvalidated {
                message_id_hex,
                reason,
                decrypted_payload_ref,
                ..
            } => unsafe {
                free_c_string(*message_id_hex);
                free_c_string(*reason);
                free_c_string(*decrypted_payload_ref);
            },
            Self::GroupStateChanged {
                actor_id_hex,
                change,
                origin_commit_id_hex,
                ..
            } => unsafe {
                free_c_string(*actor_id_hex);
                free_c_string(*change);
                free_c_string(*origin_commit_id_hex);
            },
            Self::ForkRecovered {
                invalidated_commit_id_hex,
                ..
            }
            | Self::CommitRolledBack {
                invalidated_commit_id_hex,
            } => unsafe {
                free_c_string(*invalidated_commit_id_hex);
            },
            Self::GroupStateInvalidated {
                invalidated_commit_id_hex,
                reason,
                ..
            } => unsafe {
                free_c_string(*invalidated_commit_id_hex);
                free_c_string(*reason);
            },
        }
    }
}

/// Top-level event firehose item delivered by the events subscription's
/// `next`. Agent streams collapse to a single "agent stream activity"
/// variant — host apps do not differentiate them at the surface level for v1.
/// Rich payloads are carried by value so hosts read them without extra
/// dereferences.
// Variants intentionally differ widely in size; the firehose delivers one
// heap root per event, so boxing the large payloads would only add derefs.
#[repr(C)]
#[allow(clippy::large_enum_variant)]
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
    /// `recipient_hex`; that member is in the group but unjoinable until the
    /// welcome is re-delivered via `redeliver_welcome(message_id_hex)`.
    WelcomeDeliveryPending {
        account_id_hex: *mut c_char,
        account_label: *mut c_char,
        group_id_hex: *mut c_char,
        message_id_hex: *mut c_char,
        recipient_hex: *mut c_char,
    },
}

impl From<MarmotEventFfi> for MarmotEvent {
    fn from(value: MarmotEventFfi) -> Self {
        match value {
            MarmotEventFfi::GroupJoined {
                account_id_hex,
                account_label,
                group_id_hex,
            } => Self::GroupJoined {
                account_id_hex: owned_c_string(account_id_hex),
                account_label: owned_c_string(account_label),
                group_id_hex: owned_c_string(group_id_hex),
            },
            MarmotEventFfi::GroupStateUpdated {
                account_id_hex,
                account_label,
                group_id_hex,
            } => Self::GroupStateUpdated {
                account_id_hex: owned_c_string(account_id_hex),
                account_label: owned_c_string(account_label),
                group_id_hex: owned_c_string(group_id_hex),
            },
            MarmotEventFfi::MessageReceived { received } => Self::MessageReceived {
                received: received.into(),
            },
            MarmotEventFfi::ProjectionUpdated { update } => Self::ProjectionUpdated {
                update: update.into(),
            },
            MarmotEventFfi::GroupEvent {
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
            MarmotEventFfi::AccountError {
                account_id_hex,
                account_label,
                message,
            } => Self::AccountError {
                account_id_hex: owned_c_string(account_id_hex),
                account_label: owned_c_string(account_label),
                message: owned_c_string(message),
            },
            MarmotEventFfi::AgentStreamActivity {
                account_id_hex,
                account_label,
            } => Self::AgentStreamActivity {
                account_id_hex: owned_c_string(account_id_hex),
                account_label: owned_c_string(account_label),
            },
            MarmotEventFfi::WelcomeDeliveryPending {
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
        }
    }
}

impl CFree for MarmotEvent {
    unsafe fn free_in_place(&mut self) {
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
            } => unsafe {
                free_c_string(*account_id_hex);
                free_c_string(*account_label);
                free_c_string(*group_id_hex);
            },
            Self::MessageReceived { received } => unsafe {
                received.free_in_place();
            },
            Self::ProjectionUpdated { update } => unsafe {
                update.free_in_place();
            },
            Self::GroupEvent {
                account_id_hex,
                account_label,
                group_id_hex,
                event,
            } => unsafe {
                free_c_string(*account_id_hex);
                free_c_string(*account_label);
                free_c_string(*group_id_hex);
                event.free_in_place();
            },
            Self::AccountError {
                account_id_hex,
                account_label,
                message,
            } => unsafe {
                free_c_string(*account_id_hex);
                free_c_string(*account_label);
                free_c_string(*message);
            },
            Self::AgentStreamActivity {
                account_id_hex,
                account_label,
            } => unsafe {
                free_c_string(*account_id_hex);
                free_c_string(*account_label);
            },
            Self::WelcomeDeliveryPending {
                account_id_hex,
                account_label,
                group_id_hex,
                message_id_hex,
                recipient_hex,
            } => unsafe {
                free_c_string(*account_id_hex);
                free_c_string(*account_label);
                free_c_string(*group_id_hex);
                free_c_string(*message_id_hex);
                free_c_string(*recipient_hex);
            },
        }
    }
}

// SAFETY: every pointer reachable from a `MarmotEvent` is exclusively owned
// by the value (allocated by this crate's conversion code and released
// exactly once by its deep-free), so moving the value to the callback-pump
// task on another thread is safe.
unsafe impl Send for MarmotEvent {}

/// Free an event root returned by the events subscription. NULL is a no-op.
///
/// # Safety
/// `event` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_event_free(event: *mut MarmotEvent) {
    crate::memory::free_guard(|| unsafe { free_boxed(event) });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::boxed;
    use marmot_uniffi::conversions::{
        AppGroupHydrationQuarantineReasonFfi, ChatListUpdateTriggerFfi, MessageTagFfi,
        ReceivedMessageFfi, RuntimeMessageReceivedFfi, RuntimeProjectionUpdateFfi,
        TimelineProjectionUpdateFfi,
    };
    use marmot_uniffi::{MarkdownBlockFfi, MarkdownDocumentFfi, MarkdownInlineFfi};

    fn c_str_eq(ptr: *mut c_char, expected: &str) -> bool {
        assert!(!ptr.is_null());
        unsafe { std::ffi::CStr::from_ptr(ptr) }
            .to_str()
            .expect("valid UTF-8")
            == expected
    }

    fn sample_runtime_received() -> RuntimeMessageReceivedFfi {
        RuntimeMessageReceivedFfi {
            account_id_hex: "eeff".to_string(),
            account_label: "primary".to_string(),
            message: ReceivedMessageFfi {
                message_id_hex: "msg-1".to_string(),
                group_id_hex: "aabb".to_string(),
                sender: "bob".to_string(),
                sender_display_name: Some("Bob".to_string()),
                plaintext: "fresh dirt".to_string(),
                content_tokens: MarkdownDocumentFfi {
                    blocks: vec![MarkdownBlockFfi::Paragraph {
                        inlines: vec![MarkdownInlineFfi::Text {
                            content: "fresh dirt".to_string(),
                        }],
                    }],
                    truncated: false,
                },
                kind: 9,
                tags: vec![MessageTagFfi {
                    values: vec!["e".to_string(), "abcd".to_string()],
                }],
                recorded_at: 1_700_000_010,
            },
        }
    }

    fn sample_runtime_projection_update() -> RuntimeProjectionUpdateFfi {
        RuntimeProjectionUpdateFfi {
            account_id_hex: "eeff".to_string(),
            account_label: "primary".to_string(),
            update: TimelineProjectionUpdateFfi {
                group_id_hex: "aabb".to_string(),
                messages: Vec::new(),
                changes: Vec::new(),
                chat_list_row: None,
                chat_list_trigger: ChatListUpdateTriggerFfi::UnreadChanged,
            },
        }
    }

    // Each caller already holds the global audit lock (via the per-test
    // guard), so this helper must NOT re-lock the non-reentrant mutex.
    fn roundtrip(event: MarmotEventFfi, assert_mirror: impl FnOnce(&MarmotEvent)) {
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let mirror: MarmotEvent = event.into();
        assert_mirror(&mirror);
        let root = boxed(mirror);
        unsafe { marmot_event_free(root) };

        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn group_joined_event_roundtrip() {
        let _guard = crate::memory::audit::test_lock();
        roundtrip(
            MarmotEventFfi::GroupJoined {
                account_id_hex: "eeff".to_string(),
                account_label: "primary".to_string(),
                group_id_hex: "aabb".to_string(),
            },
            |mirror| match mirror {
                MarmotEvent::GroupJoined {
                    account_id_hex,
                    account_label,
                    group_id_hex,
                } => {
                    assert!(c_str_eq(*account_id_hex, "eeff"));
                    assert!(c_str_eq(*account_label, "primary"));
                    assert!(c_str_eq(*group_id_hex, "aabb"));
                }
                _ => panic!("expected GroupJoined"),
            },
        );
    }

    #[test]
    fn group_state_updated_event_roundtrip() {
        let _guard = crate::memory::audit::test_lock();
        roundtrip(
            MarmotEventFfi::GroupStateUpdated {
                account_id_hex: "eeff".to_string(),
                account_label: "primary".to_string(),
                group_id_hex: "aabb".to_string(),
            },
            |mirror| match mirror {
                MarmotEvent::GroupStateUpdated { group_id_hex, .. } => {
                    assert!(c_str_eq(*group_id_hex, "aabb"));
                }
                _ => panic!("expected GroupStateUpdated"),
            },
        );
    }

    #[test]
    fn message_received_event_roundtrip() {
        let _guard = crate::memory::audit::test_lock();
        roundtrip(
            MarmotEventFfi::MessageReceived {
                received: sample_runtime_received(),
            },
            |mirror| match mirror {
                MarmotEvent::MessageReceived { received } => {
                    assert!(c_str_eq(received.account_id_hex, "eeff"));
                    assert!(c_str_eq(received.message.message_id_hex, "msg-1"));
                    assert!(c_str_eq(received.message.plaintext, "fresh dirt"));
                    assert!(!received.message.sender_display_name.is_null());
                    assert_eq!(received.message.tags_len, 1);
                }
                _ => panic!("expected MessageReceived"),
            },
        );
    }

    #[test]
    fn projection_updated_event_roundtrip() {
        let _guard = crate::memory::audit::test_lock();
        roundtrip(
            MarmotEventFfi::ProjectionUpdated {
                update: sample_runtime_projection_update(),
            },
            |mirror| match mirror {
                MarmotEvent::ProjectionUpdated { update } => {
                    assert!(c_str_eq(update.account_id_hex, "eeff"));
                    assert!(c_str_eq(update.update.group_id_hex, "aabb"));
                    // Empty nested vectors and None row become NULL.
                    assert!(update.update.messages.is_null());
                    assert_eq!(update.update.messages_len, 0);
                    assert!(update.update.chat_list_row.is_null());
                }
                _ => panic!("expected ProjectionUpdated"),
            },
        );
    }

    #[test]
    fn group_event_group_joined_kind_roundtrip() {
        let _guard = crate::memory::audit::test_lock();
        roundtrip(
            MarmotEventFfi::GroupEvent {
                account_id_hex: "eeff".to_string(),
                account_label: "primary".to_string(),
                group_id_hex: "aabb".to_string(),
                event: GroupEventKindFfi::GroupJoined {
                    via_welcome_hex: "11ff".to_string(),
                    welcomer_id_hex: Some("22cc".to_string()),
                },
            },
            |mirror| match mirror {
                MarmotEvent::GroupEvent {
                    group_id_hex,
                    event,
                    ..
                } => {
                    assert!(c_str_eq(*group_id_hex, "aabb"));
                    match event {
                        MarmotGroupEventKind::GroupJoined {
                            via_welcome_hex,
                            welcomer_id_hex,
                        } => {
                            assert!(c_str_eq(*via_welcome_hex, "11ff"));
                            assert!(c_str_eq(*welcomer_id_hex, "22cc"));
                        }
                        _ => panic!("expected GroupJoined kind"),
                    }
                }
                _ => panic!("expected GroupEvent"),
            },
        );
    }

    #[test]
    fn group_event_app_message_invalidated_kind_roundtrip() {
        let _guard = crate::memory::audit::test_lock();
        roundtrip(
            MarmotEventFfi::GroupEvent {
                account_id_hex: "eeff".to_string(),
                account_label: "primary".to_string(),
                group_id_hex: "aabb".to_string(),
                event: GroupEventKindFfi::AppMessageInvalidated {
                    message_id_hex: "msg-9".to_string(),
                    epoch: 7,
                    reason: "losing_branch".to_string(),
                    decrypted_payload_ref: Some("ref-1".to_string()),
                },
            },
            |mirror| match mirror {
                MarmotEvent::GroupEvent { event, .. } => match event {
                    MarmotGroupEventKind::AppMessageInvalidated {
                        message_id_hex,
                        epoch,
                        reason,
                        decrypted_payload_ref,
                    } => {
                        assert!(c_str_eq(*message_id_hex, "msg-9"));
                        assert_eq!(*epoch, 7);
                        assert!(c_str_eq(*reason, "losing_branch"));
                        assert!(c_str_eq(*decrypted_payload_ref, "ref-1"));
                    }
                    _ => panic!("expected AppMessageInvalidated kind"),
                },
                _ => panic!("expected GroupEvent"),
            },
        );
    }

    #[test]
    fn group_event_hydration_quarantined_kind_roundtrip() {
        let _guard = crate::memory::audit::test_lock();
        roundtrip(
            MarmotEventFfi::GroupEvent {
                account_id_hex: "eeff".to_string(),
                account_label: "primary".to_string(),
                group_id_hex: "aabb".to_string(),
                event: GroupEventKindFfi::GroupHydrationQuarantined {
                    reason: AppGroupHydrationQuarantineReasonFfi::OpenMlsLoadFailed,
                },
            },
            |mirror| match mirror {
                MarmotEvent::GroupEvent { event, .. } => match event {
                    MarmotGroupEventKind::GroupHydrationQuarantined { reason } => {
                        assert_eq!(
                            *reason,
                            MarmotAppGroupHydrationQuarantineReason::OpenMlsLoadFailed
                        );
                    }
                    _ => panic!("expected GroupHydrationQuarantined kind"),
                },
                _ => panic!("expected GroupEvent"),
            },
        );
    }

    #[test]
    fn account_error_event_roundtrip() {
        let _guard = crate::memory::audit::test_lock();
        roundtrip(
            MarmotEventFfi::AccountError {
                account_id_hex: "eeff".to_string(),
                account_label: "primary".to_string(),
                message: "relay unreachable".to_string(),
            },
            |mirror| match mirror {
                MarmotEvent::AccountError { message, .. } => {
                    assert!(c_str_eq(*message, "relay unreachable"));
                }
                _ => panic!("expected AccountError"),
            },
        );
    }

    #[test]
    fn agent_stream_activity_event_roundtrip() {
        let _guard = crate::memory::audit::test_lock();
        roundtrip(
            MarmotEventFfi::AgentStreamActivity {
                account_id_hex: "eeff".to_string(),
                account_label: "primary".to_string(),
            },
            |mirror| match mirror {
                MarmotEvent::AgentStreamActivity {
                    account_id_hex,
                    account_label,
                } => {
                    assert!(c_str_eq(*account_id_hex, "eeff"));
                    assert!(c_str_eq(*account_label, "primary"));
                }
                _ => panic!("expected AgentStreamActivity"),
            },
        );
    }

    #[test]
    fn welcome_delivery_pending_event_roundtrip() {
        let _guard = crate::memory::audit::test_lock();
        roundtrip(
            MarmotEventFfi::WelcomeDeliveryPending {
                account_id_hex: "eeff".to_string(),
                account_label: "primary".to_string(),
                group_id_hex: "aabb".to_string(),
                message_id_hex: "msg-3".to_string(),
                recipient_hex: "44dd".to_string(),
            },
            |mirror| match mirror {
                MarmotEvent::WelcomeDeliveryPending {
                    message_id_hex,
                    recipient_hex,
                    ..
                } => {
                    assert!(c_str_eq(*message_id_hex, "msg-3"));
                    assert!(c_str_eq(*recipient_hex, "44dd"));
                }
                _ => panic!("expected WelcomeDeliveryPending"),
            },
        );
    }

    #[test]
    fn none_optionals_convert_to_null() {
        let _guard = crate::memory::audit::test_lock();
        roundtrip(
            MarmotEventFfi::GroupEvent {
                account_id_hex: "eeff".to_string(),
                account_label: "primary".to_string(),
                group_id_hex: "aabb".to_string(),
                event: GroupEventKindFfi::GroupStateChanged {
                    epoch: 3,
                    actor_id_hex: None,
                    change: "member_added".to_string(),
                    origin_commit_id_hex: None,
                },
            },
            |mirror| match mirror {
                MarmotEvent::GroupEvent { event, .. } => match event {
                    MarmotGroupEventKind::GroupStateChanged {
                        epoch,
                        actor_id_hex,
                        change,
                        origin_commit_id_hex,
                    } => {
                        assert_eq!(*epoch, 3);
                        assert!(actor_id_hex.is_null());
                        assert!(c_str_eq(*change, "member_added"));
                        assert!(origin_commit_id_hex.is_null());
                    }
                    _ => panic!("expected GroupStateChanged kind"),
                },
                _ => panic!("expected GroupEvent"),
            },
        );
    }
}
