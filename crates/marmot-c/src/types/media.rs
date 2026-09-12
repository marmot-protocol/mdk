//! C mirrors of the encrypted-media conversions.

use marmot_uniffi::conversions::{
    MediaAttachmentProjectionFfi, MediaAttachmentReferenceFfi, MediaAttachmentResultFfi,
    MediaDiagnosticFfi, MediaDownloadResultFfi, MediaErrorCodeFfi, MediaErrorFieldFfi,
    MediaErrorStageFfi, MediaLocatorFfi, MediaRecordFfi, MediaUploadAttachmentRequestFfi,
    MediaUploadAttachmentResultFfi, MediaUploadRequestFfi, MediaUploadResultFfi,
};

use super::account::MarmotSendSummary;
use super::group::MarmotEncryptedMediaVersion;
use crate::MarmotStatus;
use crate::macros::{c_enum, c_mirror};
use crate::memory::{CFree, c_bool, optional_str, required_str};
use crate::status::set_last_error;

c_mirror! {
    /// One storage locator for an encrypted attachment.
    MarmotMediaLocator from MediaLocatorFfi {
        str kind,
        str value,
    }
}

impl MarmotMediaLocator {
    /// # Safety
    /// Both fields must be valid NUL-terminated strings.
    pub(crate) unsafe fn to_ffi(&self) -> Result<MediaLocatorFfi, MarmotStatus> {
        Ok(MediaLocatorFfi {
            kind: unsafe { required_str(self.kind) }?,
            value: unsafe { required_str(self.value) }?,
        })
    }
}

c_mirror! {
    /// Fully-resolved encrypted attachment reference. Also a borrowed
    /// input to `marmot_send_media_reference` /
    /// `marmot_send_media_attachments` / `marmot_download_media`, and the
    /// success result of `marmot_parse_media_imeta_tag`.
    MarmotMediaAttachmentReference from MediaAttachmentReferenceFfi,
    free marmot_media_attachment_reference_free {
        vec locators/locators_len: MarmotMediaLocator,
        str ciphertext_sha256,
        str plaintext_sha256,
        str nonce_hex,
        str file_name,
        str media_type,
        /// `MarmotEncryptedMediaVersion` discriminant.
        enum_val version: MarmotEncryptedMediaVersion,
        copy source_epoch: u64,
        opt_str dim,
        opt_str thumbhash,
    }
}

impl MarmotMediaAttachmentReference {
    /// # Safety
    /// Strings must be valid; `locators` must point to `locators_len`
    /// valid structs (or be NULL with len 0).
    pub(crate) unsafe fn to_ffi(&self) -> Result<MediaAttachmentReferenceFfi, MarmotStatus> {
        if self.locators.is_null() && self.locators_len != 0 {
            set_last_error("locators was NULL with nonzero length");
            return Err(MarmotStatus::NullPointer);
        }
        let mut locators = Vec::with_capacity(self.locators_len);
        for i in 0..self.locators_len {
            locators.push(unsafe { (*self.locators.add(i)).to_ffi() }?);
        }
        Ok(MediaAttachmentReferenceFfi {
            locators,
            ciphertext_sha256: unsafe { required_str(self.ciphertext_sha256) }?,
            plaintext_sha256: unsafe { required_str(self.plaintext_sha256) }?,
            nonce_hex: unsafe { required_str(self.nonce_hex) }?,
            file_name: unsafe { required_str(self.file_name) }?,
            media_type: unsafe { required_str(self.media_type) }?,
            version: match MarmotEncryptedMediaVersion::from_c(self.version)? {
                MarmotEncryptedMediaVersion::V1 => {
                    marmot_uniffi::conversions::EncryptedMediaVersionFfi::V1
                }
                MarmotEncryptedMediaVersion::V2 => {
                    marmot_uniffi::conversions::EncryptedMediaVersionFfi::V2
                }
            },
            source_epoch: self.source_epoch,
            dim: unsafe { optional_str(self.dim) }?,
            thumbhash: unsafe { optional_str(self.thumbhash) }?,
        })
    }
}

/// One attachment to encrypt and upload. Borrowed input only: the
/// plaintext bytes are copied, never retained or freed.
#[repr(C)]
pub struct MarmotMediaUploadAttachmentRequest {
    pub file_name: *const ::std::ffi::c_char,
    pub media_type: *const ::std::ffi::c_char,
    pub plaintext: *const u8,
    pub plaintext_len: usize,
    /// Nullable.
    pub dim: *const ::std::ffi::c_char,
    /// Nullable.
    pub thumbhash: *const ::std::ffi::c_char,
}

impl MarmotMediaUploadAttachmentRequest {
    /// # Safety
    /// Strings must be valid; `plaintext` must point to `plaintext_len`
    /// bytes (or be NULL with len 0).
    pub(crate) unsafe fn to_ffi(&self) -> Result<MediaUploadAttachmentRequestFfi, MarmotStatus> {
        if self.plaintext.is_null() && self.plaintext_len != 0 {
            set_last_error("plaintext was NULL with nonzero length");
            return Err(MarmotStatus::NullPointer);
        }
        let plaintext = if self.plaintext.is_null() {
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(self.plaintext, self.plaintext_len) }.to_vec()
        };
        Ok(MediaUploadAttachmentRequestFfi {
            file_name: unsafe { required_str(self.file_name) }?,
            media_type: unsafe { required_str(self.media_type) }?,
            plaintext,
            dim: unsafe { optional_str(self.dim) }?,
            thumbhash: unsafe { optional_str(self.thumbhash) }?,
        })
    }
}

/// A full upload request. Borrowed input only.
#[repr(C)]
pub struct MarmotMediaUploadRequest {
    pub attachments: *const MarmotMediaUploadAttachmentRequest,
    pub attachments_len: usize,
    /// Nullable.
    pub caption: *const ::std::ffi::c_char,
    /// Whether to also send the message after uploading (`uint8_t`
    /// boolean: nonzero is true).
    pub send: u8,
    /// Override Blossom server URL. Nullable.
    pub blossom_server: *const ::std::ffi::c_char,
}

impl MarmotMediaUploadRequest {
    /// # Safety
    /// `attachments` must point to `attachments_len` valid structs (or be
    /// NULL with len 0); strings must be valid.
    pub(crate) unsafe fn to_ffi(&self) -> Result<MediaUploadRequestFfi, MarmotStatus> {
        if self.attachments.is_null() && self.attachments_len != 0 {
            set_last_error("attachments was NULL with nonzero length");
            return Err(MarmotStatus::NullPointer);
        }
        let mut attachments = Vec::with_capacity(self.attachments_len);
        for i in 0..self.attachments_len {
            attachments.push(unsafe { (*self.attachments.add(i)).to_ffi() }?);
        }
        Ok(MediaUploadRequestFfi {
            attachments,
            caption: unsafe { optional_str(self.caption) }?,
            send: c_bool(self.send),
            blossom_server: unsafe { optional_str(self.blossom_server) }?,
        })
    }
}

c_mirror! {
    /// One uploaded attachment plus its encrypted size.
    MarmotMediaUploadAttachmentResult from MediaUploadAttachmentResultFfi {
        rec reference: MarmotMediaAttachmentReference,
        copy encrypted_size_bytes: u64,
    }
}

c_mirror! {
    /// Result of `marmot_upload_media`.
    MarmotMediaUploadResult from MediaUploadResultFfi,
    free marmot_media_upload_result_free {
        vec attachments/attachments_len: MarmotMediaUploadAttachmentResult,
        opt_rec sent: MarmotSendSummary,
    }
}

c_mirror! {
    /// Result of `marmot_download_media`: decrypted plaintext plus its
    /// metadata.
    MarmotMediaDownloadResult from MediaDownloadResultFfi,
    free marmot_media_download_result_free {
        bytes plaintext/plaintext_len,
        str file_name,
        str media_type,
        copy size_bytes: u64,
    }
}

c_enum! {
    /// Attachment pipeline stage.
    MarmotMediaErrorStage from MediaErrorStageFfi {
        Metadata,
        Outbound,
        Fetch,
        Decrypt,
    }
}

c_enum! {
    /// Closed attachment failure reason.
    MarmotMediaErrorCode from MediaErrorCodeFfi {
        InvalidStructure,
        MissingField,
        DuplicateField,
        MalformedField,
        UnsupportedVersion,
        UnsupportedFormat,
        ProfileMismatch,
        DestinationPolicy,
        NoSupportedLocator,
        DownloadFailed,
        DecryptionFailed,
        IntegrityMismatch,
    }
}

c_enum! {
    /// Closed attachment field vocabulary.
    MarmotMediaErrorField from MediaErrorFieldFfi {
        Version,
        Locator,
        CiphertextSha256,
        PlaintextSha256,
        Nonce,
        MediaType,
        FileName,
        Dimensions,
        Thumbhash,
    }
}

// Derived Default would need a #[default] variant attr the c_enum! spec
// grammar doesn't carry; manual impl is equivalent.
#[allow(clippy::derivable_impls)]
impl Default for MarmotMediaErrorField {
    fn default() -> Self {
        Self::Version
    }
}

c_mirror! {
    /// Privacy-safe attachment diagnostic. Also a root returned by
    /// `marmot_last_media_error`.
    MarmotMediaDiagnostic from MediaDiagnosticFfi,
    free marmot_media_diagnostic_free {
        copy stage: MarmotMediaErrorStage,
        copy code: MarmotMediaErrorCode,
        opt_copy has_field/field: MarmotMediaErrorField,
        str message,
    }
}

/// Parsed or rejected attachment outcome.
#[repr(C)]
pub enum MarmotMediaAttachmentResult {
    Parsed {
        reference: MarmotMediaAttachmentReference,
    },
    Rejected {
        diagnostic: MarmotMediaDiagnostic,
    },
}

impl From<MediaAttachmentResultFfi> for MarmotMediaAttachmentResult {
    fn from(value: MediaAttachmentResultFfi) -> Self {
        match value {
            MediaAttachmentResultFfi::Parsed { reference } => Self::Parsed {
                reference: reference.into(),
            },
            MediaAttachmentResultFfi::Rejected { diagnostic } => Self::Rejected {
                diagnostic: diagnostic.into(),
            },
        }
    }
}

impl CFree for MarmotMediaAttachmentResult {
    unsafe fn free_in_place(&mut self) {
        match self {
            Self::Parsed { reference } => unsafe { reference.free_in_place() },
            Self::Rejected { diagnostic } => unsafe { diagnostic.free_in_place() },
        }
    }
}

c_mirror! {
    /// One ordered attachment outcome.
    MarmotMediaAttachmentProjection from MediaAttachmentProjectionFfi {
        opt_copy has_attachment_index/attachment_index: u32,
        rec result: MarmotMediaAttachmentResult,
    }
}

/// Legacy success-only stored media record. Rejected attachments are
/// omitted by `marmot_list_media`.
#[repr(C)]
pub struct MarmotMediaRecord {
    pub message_id_hex: *mut ::std::ffi::c_char,
    pub attachment_index: u32,
    pub direction: *mut ::std::ffi::c_char,
    pub group_id_hex: *mut ::std::ffi::c_char,
    pub sender: *mut ::std::ffi::c_char,
    pub reference: MarmotMediaAttachmentReference,
    pub caption: *mut ::std::ffi::c_char,
    pub recorded_at: u64,
    pub received_at: u64,
}

impl MarmotMediaRecord {
    fn from_parsed(value: MediaRecordFfi, reference: MediaAttachmentReferenceFfi) -> Self {
        Self {
            message_id_hex: crate::memory::owned_c_string(value.message_id_hex),
            attachment_index: value.attachment_index,
            direction: crate::memory::owned_c_string(value.direction),
            group_id_hex: crate::memory::owned_c_string(value.group_id_hex),
            sender: crate::memory::owned_c_string(value.sender),
            reference: reference.into(),
            caption: crate::memory::owned_opt_c_string(value.caption),
            recorded_at: value.recorded_at,
            received_at: value.received_at,
        }
    }
}

impl CFree for MarmotMediaRecord {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            crate::memory::free_c_string(self.message_id_hex);
            crate::memory::free_c_string(self.direction);
            crate::memory::free_c_string(self.group_id_hex);
            crate::memory::free_c_string(self.sender);
            self.reference.free_in_place();
            crate::memory::free_c_string(self.caption);
        }
    }
}

/// Owned list of legacy success-only media records.
#[repr(C)]
pub struct MarmotMediaRecordList {
    pub items: *mut MarmotMediaRecord,
    pub len: usize,
}

impl From<Vec<MediaRecordFfi>> for MarmotMediaRecordList {
    fn from(value: Vec<MediaRecordFfi>) -> Self {
        let items = value
            .into_iter()
            .filter_map(|record| {
                let reference = match &record.attachment {
                    MediaAttachmentResultFfi::Parsed { reference } => reference.clone(),
                    MediaAttachmentResultFfi::Rejected { .. } => return None,
                };
                Some(MarmotMediaRecord::from_parsed(record, reference))
            })
            .collect();
        let (items, len) = crate::memory::owned_vec(items);
        Self { items, len }
    }
}

impl CFree for MarmotMediaRecordList {
    unsafe fn free_in_place(&mut self) {
        unsafe { crate::memory::free_vec(self.items, self.len) };
    }
}

/// Free a list returned by this library. NULL is a no-op.
///
/// # Safety
/// `list` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_media_record_list_free(list: *mut MarmotMediaRecordList) {
    crate::memory::free_guard(|| unsafe { crate::memory::free_boxed(list) });
}

c_mirror! {
    /// Rich stored media record that retains rejected attachments.
    MarmotMediaRecordV2 from MediaRecordFfi,
    free marmot_media_record_v2_free,
    list(MarmotMediaRecordV2List, marmot_media_record_v2_list_free) {
        str message_id_hex,
        copy attachment_index: u32,
        str direction,
        str group_id_hex,
        str sender,
        rec attachment: MarmotMediaAttachmentResult,
        opt_str caption,
        copy recorded_at: u64,
        copy received_at: u64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use marmot_uniffi::MarmotKitError;
    use marmot_uniffi::conversions::{
        EncryptedMediaVersionFfi, MediaAttachmentResultFfi, MediaDiagnosticFfi, MediaErrorCodeFfi,
        MediaErrorFieldFfi, MediaErrorStageFfi, MediaLocatorFfi, MediaRecordFfi,
    };

    fn sample_reference() -> MediaAttachmentReferenceFfi {
        MediaAttachmentReferenceFfi {
            locators: vec![MediaLocatorFfi {
                kind: "blossom-v1".into(),
                value: "https://media.example/aa.bin".into(),
            }],
            ciphertext_sha256: "11".repeat(32),
            plaintext_sha256: "22".repeat(32),
            nonce_hex: "33".repeat(12),
            file_name: "diagram.png".into(),
            media_type: "image/png".into(),
            version: EncryptedMediaVersionFfi::V1,
            source_epoch: 7,
            dim: None,
            thumbhash: None,
        }
    }

    fn rejected_record() -> MediaRecordFfi {
        MediaRecordFfi {
            message_id_hex: "aa".repeat(32),
            attachment_index: 0,
            direction: "incoming".into(),
            group_id_hex: "bb".repeat(32),
            sender: "alice".into(),
            attachment: MediaAttachmentResultFfi::Rejected {
                diagnostic: MediaDiagnosticFfi {
                    stage: MediaErrorStageFfi::Metadata,
                    code: MediaErrorCodeFfi::MissingField,
                    field: Some(MediaErrorFieldFfi::Nonce),
                    message: "media attachment is missing nonce".into(),
                },
            },
            caption: Some("keep me".into()),
            recorded_at: 1,
            received_at: 2,
        }
    }

    fn parsed_record() -> MediaRecordFfi {
        MediaRecordFfi {
            message_id_hex: "cc".repeat(32),
            attachment_index: 1,
            direction: "incoming".into(),
            group_id_hex: "bb".repeat(32),
            sender: "bob".into(),
            attachment: MediaAttachmentResultFfi::Parsed {
                reference: sample_reference(),
            },
            caption: None,
            recorded_at: 3,
            received_at: 4,
        }
    }

    #[test]
    fn legacy_list_media_omits_rejected_records() {
        let _guard = crate::memory::audit::test_lock();
        let list = MarmotMediaRecordList::from(vec![rejected_record(), parsed_record()]);
        assert_eq!(list.len, 1);
        unsafe {
            assert_eq!((*list.items).attachment_index, 1);
            marmot_media_record_list_free(crate::memory::boxed(list));
        }
    }

    #[test]
    fn v2_list_media_keeps_rejected_records() {
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();
        let list = MarmotMediaRecordV2List::from(vec![rejected_record(), parsed_record()]);
        assert_eq!(list.len, 2);
        unsafe {
            match &(*list.items).attachment {
                MarmotMediaAttachmentResult::Rejected { diagnostic } => {
                    assert_eq!(diagnostic.code, MarmotMediaErrorCode::MissingField);
                }
                MarmotMediaAttachmentResult::Parsed { .. } => {
                    panic!("first row should be rejected")
                }
            }
            marmot_media_record_v2_list_free(crate::memory::boxed(list));
        }
        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn last_media_error_is_taken_and_cleared_by_non_media_failures() {
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();
        let err = MarmotKitError::MediaAttachment {
            diagnostic: MediaDiagnosticFfi {
                stage: MediaErrorStageFfi::Fetch,
                code: MediaErrorCodeFfi::DownloadFailed,
                field: Some(MediaErrorFieldFfi::Locator),
                message: "media download failed".into(),
            },
        };
        assert_eq!(
            crate::status::status_from_error(&err),
            crate::MarmotStatus::MediaAttachment
        );
        let first = crate::marmot_last_media_error();
        assert!(!first.is_null());
        unsafe { marmot_media_diagnostic_free(first) };
        assert!(crate::marmot_last_media_error().is_null());

        let _ = crate::status::status_from_error(&err);
        let _ = crate::status::status_from_error(&MarmotKitError::Runtime {
            details: "unrelated".into(),
        });
        assert!(crate::marmot_last_media_error().is_null());
        let detail = crate::marmot_last_error_message();
        unsafe { crate::marmot_string_free(detail) };
        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn parse_media_imeta_tag_null_out_is_preflighted() {
        let status = unsafe {
            crate::commands::marmot_parse_media_imeta_tag(std::ptr::null(), 1, std::ptr::null_mut())
        };
        assert_eq!(status, crate::MarmotStatus::NullPointer);
        assert!(crate::marmot_last_media_error().is_null());
    }

    #[test]
    fn media_record_array_strides_are_stable_within_each_layout() {
        assert!(std::mem::size_of::<MarmotMediaRecord>() > 0);
        assert_ne!(
            std::mem::size_of::<MarmotMediaRecord>(),
            std::mem::size_of::<MarmotMediaRecordV2>()
        );
        assert_eq!(
            std::mem::size_of::<[MarmotMediaRecord; 2]>(),
            std::mem::size_of::<MarmotMediaRecord>() * 2
        );
        assert_eq!(
            std::mem::size_of::<[MarmotMediaRecordV2; 2]>(),
            std::mem::size_of::<MarmotMediaRecordV2>() * 2
        );
    }
}
