//! C mirrors of the encrypted-media conversions.

use marmot_uniffi::conversions::{
    MediaAttachmentOutcomeFfi, MediaAttachmentReferenceFfi, MediaAttachmentRejectionFfi,
    MediaAttachmentRejectionKindFfi, MediaDownloadResultFfi, MediaLocatorFfi, MediaRecordFfi,
    MediaUploadAttachmentRequestFfi, MediaUploadAttachmentResultFfi, MediaUploadRequestFfi,
    MediaUploadResultFfi,
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
    /// `marmot_send_media_attachments` / `marmot_download_media`.
    MarmotMediaAttachmentReference from MediaAttachmentReferenceFfi {
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

c_enum! {
    /// Stable category of a rejected encrypted-media attachment (mdk#1787).
    /// Branch on this rather than on `detail`; the set only grows.
    MarmotMediaAttachmentRejectionKind from MediaAttachmentRejectionKindFfi {
        /// Not a decodable encrypted-media `imeta` tag.
        InvalidStructure,
        /// The `v` field is absent or names a format this build does not
        /// implement (legacy MIP-era and future shapes).
        UnsupportedFormat,
        /// A required field is absent or empty.
        MissingField,
        /// A single-occurrence field appears more than once.
        DuplicateField,
        /// A present field has an invalid value.
        MalformedField,
    }
}

c_mirror! {
    /// Why one attachment was rejected. `detail` is privacy-safe
    /// presentation text from the shared parser; it never echoes tag
    /// content.
    MarmotMediaAttachmentRejection from MediaAttachmentRejectionFfi {
        copy kind: MarmotMediaAttachmentRejectionKind,
        str detail,
    }
}

/// One `imeta` attachment of a message, in tag order. `attachment_index`
/// is the position among the message's `imeta` tags, rejected siblings
/// included, so a host can render media and placeholders in order and
/// correlate a timeline row with `MarmotMediaRecord` entries for the same
/// message. Pass an `Accepted` reference to `marmot_download_media`;
/// render `Rejected` as an unsupported/invalid attachment placeholder
/// using `rejection.kind`.
#[repr(C)]
pub enum MarmotMediaAttachmentOutcome {
    Accepted {
        attachment_index: u32,
        reference: MarmotMediaAttachmentReference,
    },
    Rejected {
        attachment_index: u32,
        rejection: MarmotMediaAttachmentRejection,
    },
}

impl From<MediaAttachmentOutcomeFfi> for MarmotMediaAttachmentOutcome {
    fn from(value: MediaAttachmentOutcomeFfi) -> Self {
        match value {
            MediaAttachmentOutcomeFfi::Accepted {
                attachment_index,
                reference,
            } => Self::Accepted {
                attachment_index,
                reference: reference.into(),
            },
            MediaAttachmentOutcomeFfi::Rejected {
                attachment_index,
                rejection,
            } => Self::Rejected {
                attachment_index,
                rejection: rejection.into(),
            },
        }
    }
}

impl CFree for MarmotMediaAttachmentOutcome {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            match self {
                Self::Accepted { reference, .. } => reference.free_in_place(),
                Self::Rejected { rejection, .. } => rejection.free_in_place(),
            }
        }
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

c_mirror! {
    /// One stored media record.
    MarmotMediaRecord from MediaRecordFfi,
    list(MarmotMediaRecordList, marmot_media_record_list_free) {
        str message_id_hex,
        /// Position among the source message's `imeta` tags, rejected
        /// siblings included, matching the timeline row's outcome index.
        copy attachment_index: u32,
        str direction,
        str group_id_hex,
        str sender,
        rec reference: MarmotMediaAttachmentReference,
        opt_str caption,
        copy recorded_at: u64,
        copy received_at: u64,
    }
}
