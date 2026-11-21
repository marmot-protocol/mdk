//! C mirrors of the per-conversation message-draft conversions.

use marmot_uniffi::conversions::{
    MessageDraftAttachmentFfi, MessageDraftAttachmentFileRequestFfi,
    MessageDraftAttachmentInputFfi, MessageDraftAttachmentSummaryFfi, MessageDraftFfi,
    MessageDraftSummaryFfi,
};

use crate::MarmotStatus;
use crate::macros::c_mirror;
use crate::memory::{optional_str, required_str};
use crate::status::set_last_error;

c_mirror! {
    /// One attachment staged in a draft, with its plaintext bytes.
    MarmotMessageDraftAttachment from MessageDraftAttachmentFfi {
        str id,
        str file_name,
        str media_type,
        bytes plaintext/plaintext_len,
        opt_str dim,
        opt_str thumbhash,
        opt_copy has_duration_seconds/duration_seconds: f64,
        prim_vec waveform_samples/waveform_samples_len: f64,
    }
}

c_mirror! {
    /// A conversation's stored draft. Free with
    /// `marmot_message_draft_free`.
    MarmotMessageDraft from MessageDraftFfi,
    free marmot_message_draft_free {
        str group_id_hex,
        str content,
        opt_str reply_to_message_id_hex,
        vec media_attachments/media_attachments_len: MarmotMessageDraftAttachment,
        copy created_at_ms: i64,
        copy updated_at_ms: i64,
    }
}

c_mirror! {
    /// Attachment metadata without the plaintext bytes.
    MarmotMessageDraftAttachmentSummary from MessageDraftAttachmentSummaryFfi {
        str id,
        str file_name,
        str media_type,
        copy plaintext_size: u64,
    }
}

c_mirror! {
    /// One draft as listed across the account: attachment metadata only,
    /// so listing every draft does not materialize their bytes.
    MarmotMessageDraftSummary from MessageDraftSummaryFfi,
    free marmot_message_draft_summary_free,
    list(MarmotMessageDraftSummaryList, marmot_message_draft_summary_list_free) {
        str group_id_hex,
        str content,
        opt_str reply_to_message_id_hex,
        vec media_attachments/media_attachments_len: MarmotMessageDraftAttachmentSummary,
        copy created_at_ms: i64,
        copy updated_at_ms: i64,
    }
}

/// One attachment to stage in a draft. Borrowed input only: the
/// plaintext bytes are copied, never retained or freed.
#[repr(C)]
pub struct MarmotMessageDraftAttachmentInput {
    pub id: *const ::std::ffi::c_char,
    pub file_name: *const ::std::ffi::c_char,
    pub media_type: *const ::std::ffi::c_char,
    pub plaintext: *const u8,
    pub plaintext_len: usize,
    /// Nullable.
    pub dim: *const ::std::ffi::c_char,
    /// Nullable.
    pub thumbhash: *const ::std::ffi::c_char,
    /// Playback length for audio/video; set `has_duration_seconds`
    /// (`uint8_t` boolean: nonzero is true).
    pub has_duration_seconds: u8,
    pub duration_seconds: f64,
    /// Waveform preview samples; NULL with length 0 for none.
    pub waveform_samples: *const f64,
    pub waveform_samples_len: usize,
}

impl MarmotMessageDraftAttachmentInput {
    /// # Safety
    /// Strings must be valid; `plaintext` must point to `plaintext_len`
    /// bytes and `waveform_samples` to `waveform_samples_len` values (or
    /// each be NULL with length 0).
    pub(crate) unsafe fn to_ffi(&self) -> Result<MessageDraftAttachmentFfi, MarmotStatus> {
        if self.plaintext.is_null() && self.plaintext_len != 0 {
            set_last_error("plaintext was NULL with nonzero length");
            return Err(MarmotStatus::NullPointer);
        }
        let plaintext = if self.plaintext.is_null() {
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(self.plaintext, self.plaintext_len) }.to_vec()
        };
        let waveform_samples = unsafe {
            crate::memory::opt_num_array(self.waveform_samples, self.waveform_samples_len)
        }?
        .unwrap_or_default();

        Ok(MessageDraftAttachmentFfi {
            id: unsafe { required_str(self.id) }?,
            file_name: unsafe { required_str(self.file_name) }?,
            media_type: unsafe { required_str(self.media_type) }?,
            plaintext,
            dim: unsafe { optional_str(self.dim) }?,
            thumbhash: unsafe { optional_str(self.thumbhash) }?,
            duration_seconds: crate::memory::c_bool(self.has_duration_seconds)
                .then_some(self.duration_seconds),
            waveform_samples,
        })
    }
}

/// One attachment of `marmot_save_message_draft_inputs_if_revision`.
/// Borrowed input only. A non-NULL `retained_id` keeps the draft's own
/// attachment with that id, body untouched; a non-NULL `removed_id` removes
/// the draft's attachment with that id (and its file). Either way
/// `attachment` is ignored. With both NULL, `attachment` is saved as a new
/// inline body; both non-NULL is MARMOT_STATUS_INVALID_ARGUMENT. An
/// attachment the save does not name stays in the draft.
#[repr(C)]
pub struct MarmotMessageDraftAttachmentSaveInput {
    /// Nullable.
    pub retained_id: *const ::std::ffi::c_char,
    pub attachment: MarmotMessageDraftAttachmentInput,
    /// Nullable.
    pub removed_id: *const ::std::ffi::c_char,
}

impl MarmotMessageDraftAttachmentSaveInput {
    /// # Safety
    /// `retained_id` and `removed_id` must each be NULL or valid; with both
    /// NULL, `attachment` must meet
    /// [`MarmotMessageDraftAttachmentInput::to_ffi`]'s contract.
    pub(crate) unsafe fn to_ffi(&self) -> Result<MessageDraftAttachmentInputFfi, MarmotStatus> {
        let retained = unsafe { optional_str(self.retained_id) }?;
        let removed = unsafe { optional_str(self.removed_id) }?;
        Ok(match (retained, removed) {
            (Some(_), Some(_)) => return Err(MarmotStatus::InvalidArgument),
            (Some(id), None) => MessageDraftAttachmentInputFfi::Retained { id },
            (None, Some(id)) => MessageDraftAttachmentInputFfi::Removed { id },
            (None, None) => MessageDraftAttachmentInputFfi::Inline {
                attachment: unsafe { self.attachment.to_ffi() }?,
            },
        })
    }
}

/// A host file to copy into a draft as attachment `id`. Borrowed input
/// only; the path is local and never published. `source_path` names a
/// regular file (not a symlink); a nonzero `has_expected_size` requires it
/// to hold exactly `expected_size` bytes.
#[repr(C)]
pub struct MarmotMessageDraftAttachmentFileRequest {
    pub id: *const ::std::ffi::c_char,
    pub source_path: *const ::std::ffi::c_char,
    pub has_expected_size: u8,
    pub expected_size: u64,
    pub file_name: *const ::std::ffi::c_char,
    pub media_type: *const ::std::ffi::c_char,
    /// Nullable.
    pub dim: *const ::std::ffi::c_char,
    /// Nullable.
    pub thumbhash: *const ::std::ffi::c_char,
    /// Playback length for audio/video; set `has_duration_seconds`.
    pub has_duration_seconds: u8,
    pub duration_seconds: f64,
    /// Waveform preview samples; NULL with length 0 for none.
    pub waveform_samples: *const f64,
    pub waveform_samples_len: usize,
}

impl MarmotMessageDraftAttachmentFileRequest {
    /// # Safety
    /// Strings must be valid; `waveform_samples` must point to
    /// `waveform_samples_len` values, or be NULL with length 0.
    pub(crate) unsafe fn to_ffi(
        &self,
    ) -> Result<MessageDraftAttachmentFileRequestFfi, MarmotStatus> {
        Ok(MessageDraftAttachmentFileRequestFfi {
            id: unsafe { required_str(self.id) }?,
            source_path: unsafe { required_str(self.source_path) }?,
            expected_size: crate::memory::c_bool(self.has_expected_size)
                .then_some(self.expected_size),
            file_name: unsafe { required_str(self.file_name) }?,
            media_type: unsafe { required_str(self.media_type) }?,
            dim: unsafe { optional_str(self.dim) }?,
            thumbhash: unsafe { optional_str(self.thumbhash) }?,
            duration_seconds: crate::memory::c_bool(self.has_duration_seconds)
                .then_some(self.duration_seconds),
            waveform_samples: unsafe {
                crate::memory::opt_num_array(self.waveform_samples, self.waveform_samples_len)
            }?
            .unwrap_or_default(),
        })
    }
}
