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

c_mirror! {
    /// One stored raw app message.
    MarmotAppMessageRecord from AppMessageRecordFfi,
    free marmot_app_message_record_free,
    list(MarmotAppMessageRecordList, marmot_app_message_record_list_free) {
        str message_id_hex,
        str direction,
        str group_id_hex,
        str sender,
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
