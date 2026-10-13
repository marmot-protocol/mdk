//! C mirrors of the raw message conversions.

use marmot_uniffi::conversions::{
    AppMessageRecordFfi, MessageUpdateFfi, ReceivedMessageFfi, RetentionSweepGroupOutcomeFfi,
    RetentionSweepReportFfi, RetentionSweepStatusFfi, RuntimeMessageReceivedFfi,
    SecureDeleteExpiredResultFfi,
};

use super::common::MarmotMessageTag;
use super::markdown::MarmotMarkdownDocument;
use crate::macros::{c_enum, c_mirror};
use crate::memory::CFree;

/// Authenticated source-epoch device evidence, owned by the containing message.
#[repr(C)]
pub enum MarmotSenderDevice {
    Exact {
        device_id: *mut std::ffi::c_char,
        leaf_index: u32,
        client_label: *mut std::ffi::c_char,
        is_this_installation: bool,
    },
    OneOf {
        device_count: u32,
    },
    Unknown,
}

impl From<marmot_uniffi::conversions::SenderDevice> for MarmotSenderDevice {
    fn from(value: marmot_uniffi::conversions::SenderDevice) -> Self {
        use marmot_uniffi::conversions::SenderDevice;
        match value {
            SenderDevice::Exact {
                device_id,
                leaf_index,
                client_label,
                is_this_installation,
            } => Self::Exact {
                device_id: crate::memory::owned_c_string(device_id),
                leaf_index,
                client_label: client_label
                    .map(crate::memory::owned_c_string)
                    .unwrap_or(std::ptr::null_mut()),
                is_this_installation,
            },
            SenderDevice::OneOf { device_count } => Self::OneOf { device_count },
            SenderDevice::Unknown => Self::Unknown,
        }
    }
}

impl CFree for MarmotSenderDevice {
    unsafe fn free_in_place(&mut self) {
        if let Self::Exact {
            device_id,
            client_label,
            ..
        } = self
        {
            unsafe {
                crate::memory::free_c_string(*device_id);
                crate::memory::free_c_string(*client_label);
            }
        }
    }
}

c_mirror! {
    /// One stored raw app message.
    MarmotAppMessageRecord from AppMessageRecordFfi,
    free marmot_app_message_record_free,
    list(MarmotAppMessageRecordList, marmot_app_message_record_list_free) {
        str message_id_hex,
        str direction,
        str group_id_hex,
        str sender,
        rec sender_device: MarmotSenderDevice,
        str plaintext,
        rec content_tokens: MarmotMarkdownDocument,
        /// Nostr `kind` of the inner Marmot app event (9 chat, 7
        /// reaction, …).
        copy kind: u64,
        vec tags/tags_len: MarmotMessageTag,
        opt_copy has_source_epoch/source_epoch: u64,
        /// Unset means no recoverable source-epoch decision (legacy/safe
        /// retain); `0` means retention explicitly disabled.
        opt_copy has_retention_seconds/retention_seconds: u64,
        opt_copy has_retention_expires_at/retention_expires_at: u64,
        /// Sender-authenticated inner app-event timestamp.
        copy recorded_at: u64,
        /// Local wall-clock time when this device observed the delivery.
        copy received_at: u64,
    }
}

c_mirror! {
    /// Result of the per-group secure-delete sweep.
    MarmotSecureDeleteExpiredResult from SecureDeleteExpiredResultFfi,
    free marmot_secure_delete_expired_result_free {
        copy pruned_messages: u64,
        copy secrets_deleted: u64,
        str_vec media_ciphertext_sha256/media_ciphertext_sha256_len,
        copy erasure_pending: bool,
    }
}

c_mirror! {
    /// One live-received message.
    MarmotReceivedMessage from ReceivedMessageFfi {
        str message_id_hex,
        str group_id_hex,
        str sender,
        rec sender_device: MarmotSenderDevice,
        opt_str sender_display_name,
        str plaintext,
        rec content_tokens: MarmotMarkdownDocument,
        /// Nostr `kind` of the inner Marmot app event.
        copy kind: u64,
        vec tags/tags_len: MarmotMessageTag,
        copy source_epoch: u64,
        /// Unset means the engine could not recover the historical source
        /// policy.
        opt_copy has_retention_seconds/retention_seconds: u64,
        opt_copy has_retention_expires_at/retention_expires_at: u64,
        /// Sender-authenticated inner app-event timestamp (seconds).
        copy recorded_at: u64,
        /// Local wall-clock time when this device observed the delivery.
        copy received_at: u64,
    }
}

c_mirror! {
    /// A received message plus the account it arrived on.
    MarmotRuntimeMessageReceived from RuntimeMessageReceivedFfi,
    free marmot_runtime_message_received_free {
        str account_id_hex,
        str account_label,
        rec message: MarmotReceivedMessage,
    }
}

/// One message-subscription update.
#[repr(C)]
pub enum MarmotMessageUpdate {
    /// A raw message update: chat, reply, media, reaction, delete, or the
    /// kind-9 stream-final.
    Message {
        received: MarmotRuntimeMessageReceived,
    },
    /// A kind-1200 agent text stream start — the signal to open the QUIC
    /// preview. Its stream id, route, and brokers live on `message.tags`.
    AgentStreamStarted {
        received: MarmotRuntimeMessageReceived,
    },
}

impl From<MessageUpdateFfi> for MarmotMessageUpdate {
    fn from(value: MessageUpdateFfi) -> Self {
        match value {
            MessageUpdateFfi::Message { received } => Self::Message {
                received: received.into(),
            },
            MessageUpdateFfi::AgentStreamStarted { received } => Self::AgentStreamStarted {
                received: received.into(),
            },
        }
    }
}

impl CFree for MarmotMessageUpdate {
    unsafe fn free_in_place(&mut self) {
        match self {
            Self::Message { received } | Self::AgentStreamStarted { received } => unsafe {
                received.free_in_place()
            },
        }
    }
}

/// Free a message update returned by this library. NULL is a no-op.
///
/// # Safety
/// `update` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_message_update_free(update: *mut MarmotMessageUpdate) {
    crate::memory::free_guard(|| unsafe { crate::memory::free_boxed(update) });
}

c_enum! {
    /// What a retention sweep did to one group.
    MarmotRetentionSweepStatus from RetentionSweepStatusFfi {
        NoExpiredMessages,
        Pruned,
        /// Host clock moved backwards; pruning waits rather than risk
        /// deleting unexpired messages.
        DeferredClockSkew,
        /// Expired messages are still unread; pruning waits.
        DeferredUnread,
        DeferredScanExhausted,
        Failed,
    }
}

c_mirror! {
    /// One group's retention-sweep outcome.
    MarmotRetentionSweepGroupOutcome from RetentionSweepGroupOutcomeFfi {
        str group_id_hex,
        copy status: MarmotRetentionSweepStatus,
        copy pruned_messages: u64,
        copy secrets_deleted: u64,
        /// Ciphertext hashes whose blobs the caller may now delete.
        str_vec media_ciphertext_sha256/media_ciphertext_sha256_len,
        opt_str failure_kind,
    }
}

c_mirror! {
    /// What one retention sweep did across the account. Free with
    /// `marmot_retention_sweep_report_free`.
    MarmotRetentionSweepReport from RetentionSweepReportFfi,
    free marmot_retention_sweep_report_free {
        vec groups/groups_len: MarmotRetentionSweepGroupOutcome,
    }
}

#[cfg(test)]
mod sender_device_tests {
    use super::*;
    use marmot_uniffi::conversions::SenderDevice;
    #[test]
    fn sender_device_raw_and_timeline_c_records_preserve_and_free_evidence() {
        use marmot_uniffi::conversions::{
            DeletionSourceFfi, TimelineMessageRecordFfi, TimelineReactionSummaryFfi,
        };
        let _lock = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let baseline = crate::memory::audit::live_allocations();
        let device = SenderDevice::Exact {
            device_id: "42".repeat(32),
            leaf_index: 7,
            client_label: Some("Test Client".into()),
            is_this_installation: true,
        };
        let mut raw: MarmotAppMessageRecord = AppMessageRecordFfi {
            message_id_hex: "message".into(),
            direction: "sent".into(),
            group_id_hex: "group".into(),
            sender: "account".into(),
            sender_device: device.clone(),
            plaintext: "hello".into(),
            content_tokens: Default::default(),
            kind: 9,
            tags: vec![],
            source_epoch: Some(1),
            retention_seconds: None,
            retention_expires_at: None,
            recorded_at: 1,
            received_at: 2,
        }
        .into();
        let mut timeline: super::super::timeline::MarmotTimelineMessageRecord =
            TimelineMessageRecordFfi {
                client_token: None,
                has_reports: false,
                poll: None,
                message_id_hex: "message".into(),
                source_message_id_hex: None,
                source_epoch: Some(1),
                retention_seconds: None,
                retention_expires_at: None,
                direction: "sent".into(),
                group_id_hex: "group".into(),
                sender: "account".into(),
                sender_device: device,
                plaintext: "hello".into(),
                content_tokens: Default::default(),
                kind: 9,
                tags: vec![],
                timeline_at: 1,
                received_at: 2,
                reply_to_message_id_hex: None,
                reply_preview: None,
                media_json: None,
                media: vec![],
                agent_text_stream_json: None,
                group_system: None,
                reactions: TimelineReactionSummaryFfi {
                    by_emoji: vec![],
                    user_reactions: vec![],
                },
                edit: None,
                deleted: false,
                deletion_source: DeletionSourceFfi::Unknown,
                deleted_by_message_id_hex: None,
                invalidation_status: None,
            }
            .into();
        for device in [&raw.sender_device, &timeline.sender_device] {
            assert!(matches!(
                device,
                MarmotSenderDevice::Exact {
                    leaf_index: 7,
                    is_this_installation: true,
                    ..
                }
            ));
            if let MarmotSenderDevice::Exact {
                device_id,
                client_label,
                ..
            } = device
            {
                assert_eq!(
                    unsafe { std::ffi::CStr::from_ptr(*device_id) }
                        .to_str()
                        .unwrap(),
                    "42".repeat(32)
                );
                assert_eq!(
                    unsafe { std::ffi::CStr::from_ptr(*client_label) }
                        .to_str()
                        .unwrap(),
                    "Test Client"
                );
            }
        }
        unsafe {
            raw.free_in_place();
            timeline.free_in_place();
        }
        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), baseline);
    }
    #[test]
    fn sender_device_c_conversion_and_deep_free() {
        let _lock = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let baseline = crate::memory::audit::live_allocations();
        for label in [None, Some("Test Client".to_owned())] {
            let mut device: MarmotSenderDevice = SenderDevice::Exact {
                device_id: "42".repeat(32),
                leaf_index: 5,
                client_label: label.clone(),
                is_this_installation: true,
            }
            .into();
            match &device {
                MarmotSenderDevice::Exact {
                    device_id,
                    leaf_index,
                    client_label,
                    is_this_installation,
                } => {
                    assert_eq!(
                        unsafe { std::ffi::CStr::from_ptr(*device_id) }
                            .to_str()
                            .unwrap(),
                        "42".repeat(32)
                    );
                    assert_eq!(*leaf_index, 5);
                    assert!(*is_this_installation);
                    assert_eq!(client_label.is_null(), label.is_none());
                    if let Some(label) = label {
                        assert_eq!(
                            unsafe { std::ffi::CStr::from_ptr(*client_label) }
                                .to_str()
                                .unwrap(),
                            label
                        );
                    }
                }
                _ => panic!("expected exact device"),
            }
            unsafe {
                device.free_in_place();
            }
        }
        assert!(matches!(
            MarmotSenderDevice::from(SenderDevice::Unknown),
            MarmotSenderDevice::Unknown
        ));
        assert!(matches!(
            MarmotSenderDevice::from(SenderDevice::OneOf { device_count: 2 }),
            MarmotSenderDevice::OneOf { device_count: 2 }
        ));
        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), baseline);
    }
}
