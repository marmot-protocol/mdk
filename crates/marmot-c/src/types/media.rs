//! C mirrors of the media conversions (`marmot-uniffi/src/conversions/media.rs`).

use std::ffi::c_char;

use marmot_uniffi::conversions::{
    MediaAttachmentReferenceFfi, MediaDownloadResultFfi, MediaLocatorFfi, MediaRecordFfi,
    MediaUploadAttachmentRequestFfi, MediaUploadAttachmentResultFfi, MediaUploadRequestFfi,
    MediaUploadResultFfi,
};

use super::account::MarmotSendSummary;
use crate::MarmotStatus;
use crate::memory::{
    CFree, boxed_opt, free_boxed, free_c_string, free_vec, optional_str, owned_c_string,
    owned_opt_c_string, owned_vec, required_str,
};

/// One place an encrypted media blob can be fetched from (e.g. a
/// `blossom-v1` URL). Used both inside owned attachment references returned
/// by this library and inside caller-owned input references (this library
/// never frees input structs).
#[repr(C)]
pub struct MarmotMediaLocator {
    /// Locator scheme, e.g. `blossom-v1`.
    pub kind: *mut c_char,
    /// Scheme-specific location value, e.g. the blob URL.
    pub value: *mut c_char,
}

impl From<MediaLocatorFfi> for MarmotMediaLocator {
    fn from(value: MediaLocatorFfi) -> Self {
        Self {
            kind: owned_c_string(value.kind),
            value: owned_c_string(value.value),
        }
    }
}

impl MarmotMediaLocator {
    /// Read a caller-owned locator into the Ffi record without taking
    /// ownership of any caller memory.
    ///
    /// # Safety
    /// `kind` and `value` must be valid NUL-terminated strings.
    pub(crate) unsafe fn to_ffi(&self) -> Result<MediaLocatorFfi, MarmotStatus> {
        Ok(MediaLocatorFfi {
            kind: unsafe { required_str(self.kind.cast_const()) }?,
            value: unsafe { required_str(self.value.cast_const()) }?,
        })
    }
}

impl CFree for MarmotMediaLocator {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_c_string(self.kind);
            free_c_string(self.value);
        }
    }
}

/// Fully-downloadable reference to one encrypted media attachment. Used
/// both as a return value (owned, freed via its parent root) and as a
/// borrowed input to send/download commands (caller-owned; this library
/// never frees input structs).
#[repr(C)]
pub struct MarmotMediaAttachmentReference {
    pub locators: *mut MarmotMediaLocator,
    pub locators_len: usize,
    /// SHA-256 of the uploaded ciphertext blob, hex-encoded.
    pub ciphertext_sha256: *mut c_char,
    /// SHA-256 of the original plaintext, hex-encoded.
    pub plaintext_sha256: *mut c_char,
    /// AEAD nonce, hex-encoded.
    pub nonce_hex: *mut c_char,
    pub file_name: *mut c_char,
    /// MIME type of the plaintext, e.g. `image/png`.
    pub media_type: *mut c_char,
    /// Encrypted-media format version, e.g. `encrypted-media-v1`.
    pub version: *mut c_char,
    /// Group epoch whose media secret encrypted this attachment.
    pub source_epoch: u64,
    /// Pixel dimensions as `WxH`, when known. Nullable.
    pub dim: *mut c_char,
    /// Thumbhash preview string, when known. Nullable.
    pub thumbhash: *mut c_char,
}

impl From<MediaAttachmentReferenceFfi> for MarmotMediaAttachmentReference {
    fn from(value: MediaAttachmentReferenceFfi) -> Self {
        let (locators, locators_len) =
            owned_vec(value.locators.into_iter().map(Into::into).collect());
        Self {
            locators,
            locators_len,
            ciphertext_sha256: owned_c_string(value.ciphertext_sha256),
            plaintext_sha256: owned_c_string(value.plaintext_sha256),
            nonce_hex: owned_c_string(value.nonce_hex),
            file_name: owned_c_string(value.file_name),
            media_type: owned_c_string(value.media_type),
            version: owned_c_string(value.version),
            source_epoch: value.source_epoch,
            dim: owned_opt_c_string(value.dim),
            thumbhash: owned_opt_c_string(value.thumbhash),
        }
    }
}

impl MarmotMediaAttachmentReference {
    /// Read a caller-owned attachment reference into the Ffi record without
    /// taking ownership of any caller memory.
    ///
    /// # Safety
    /// Every non-NULL string field must be a valid NUL-terminated string,
    /// and when `locators` is non-NULL it must point to `locators_len`
    /// valid locator structs.
    pub(crate) unsafe fn to_ffi(&self) -> Result<MediaAttachmentReferenceFfi, MarmotStatus> {
        let locators = if self.locators.is_null() {
            if self.locators_len != 0 {
                crate::status::set_last_error("media locator array was NULL with nonzero length");
                return Err(MarmotStatus::NullPointer);
            }
            Vec::new()
        } else {
            let borrowed = unsafe {
                std::slice::from_raw_parts(self.locators.cast_const(), self.locators_len)
            };
            let mut locators = Vec::with_capacity(self.locators_len);
            for locator in borrowed {
                locators.push(unsafe { locator.to_ffi() }?);
            }
            locators
        };
        Ok(MediaAttachmentReferenceFfi {
            locators,
            ciphertext_sha256: unsafe { required_str(self.ciphertext_sha256.cast_const()) }?,
            plaintext_sha256: unsafe { required_str(self.plaintext_sha256.cast_const()) }?,
            nonce_hex: unsafe { required_str(self.nonce_hex.cast_const()) }?,
            file_name: unsafe { required_str(self.file_name.cast_const()) }?,
            media_type: unsafe { required_str(self.media_type.cast_const()) }?,
            version: unsafe { required_str(self.version.cast_const()) }?,
            source_epoch: self.source_epoch,
            dim: unsafe { optional_str(self.dim.cast_const()) }?,
            thumbhash: unsafe { optional_str(self.thumbhash.cast_const()) }?,
        })
    }
}

impl CFree for MarmotMediaAttachmentReference {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_vec(self.locators, self.locators_len);
            free_c_string(self.ciphertext_sha256);
            free_c_string(self.plaintext_sha256);
            free_c_string(self.nonce_hex);
            free_c_string(self.file_name);
            free_c_string(self.media_type);
            free_c_string(self.version);
            free_c_string(self.dim);
            free_c_string(self.thumbhash);
        }
    }
}

/// One plaintext attachment to encrypt and upload. Caller-owned input to
/// `marmot_upload_media`; this library never frees input structs.
#[repr(C)]
pub struct MarmotMediaUploadAttachmentRequest {
    pub file_name: *mut c_char,
    /// MIME type of the plaintext, e.g. `image/png`.
    pub media_type: *mut c_char,
    /// Plaintext bytes to encrypt and upload. NULL with `plaintext_len == 0`
    /// is an empty payload.
    pub plaintext: *mut u8,
    pub plaintext_len: usize,
    /// Pixel dimensions as `WxH`, when known. Nullable.
    pub dim: *mut c_char,
    /// Thumbhash preview string, when known. Nullable.
    pub thumbhash: *mut c_char,
}

impl From<MediaUploadAttachmentRequestFfi> for MarmotMediaUploadAttachmentRequest {
    fn from(value: MediaUploadAttachmentRequestFfi) -> Self {
        let (plaintext, plaintext_len) = owned_vec(value.plaintext);
        Self {
            file_name: owned_c_string(value.file_name),
            media_type: owned_c_string(value.media_type),
            plaintext,
            plaintext_len,
            dim: owned_opt_c_string(value.dim),
            thumbhash: owned_opt_c_string(value.thumbhash),
        }
    }
}

impl MarmotMediaUploadAttachmentRequest {
    /// Read a caller-owned upload attachment into the Ffi record without
    /// taking ownership of any caller memory.
    ///
    /// # Safety
    /// Every non-NULL string field must be a valid NUL-terminated string,
    /// and when `plaintext` is non-NULL it must point to `plaintext_len`
    /// readable bytes.
    pub(crate) unsafe fn to_ffi(&self) -> Result<MediaUploadAttachmentRequestFfi, MarmotStatus> {
        let plaintext = if self.plaintext.is_null() {
            if self.plaintext_len != 0 {
                crate::status::set_last_error("plaintext buffer was NULL with nonzero length");
                return Err(MarmotStatus::NullPointer);
            }
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(self.plaintext.cast_const(), self.plaintext_len) }
                .to_vec()
        };
        Ok(MediaUploadAttachmentRequestFfi {
            file_name: unsafe { required_str(self.file_name.cast_const()) }?,
            media_type: unsafe { required_str(self.media_type.cast_const()) }?,
            plaintext,
            dim: unsafe { optional_str(self.dim.cast_const()) }?,
            thumbhash: unsafe { optional_str(self.thumbhash.cast_const()) }?,
        })
    }
}

impl CFree for MarmotMediaUploadAttachmentRequest {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_c_string(self.file_name);
            free_c_string(self.media_type);
            free_vec(self.plaintext, self.plaintext_len);
            free_c_string(self.dim);
            free_c_string(self.thumbhash);
        }
    }
}

/// Batch upload request: encrypt plaintext attachments, upload the
/// ciphertext blobs, and optionally send the resulting references into the
/// group. Caller-owned input to `marmot_upload_media`; this library never
/// frees input structs.
#[repr(C)]
pub struct MarmotMediaUploadRequest {
    pub attachments: *mut MarmotMediaUploadAttachmentRequest,
    pub attachments_len: usize,
    /// Optional chat caption to send alongside the attachments. Nullable.
    pub caption: *mut c_char,
    /// Whether to send the uploaded references into the group immediately.
    pub send: bool,
    /// Blossom server override. Nullable for the account default.
    pub blossom_server: *mut c_char,
}

impl From<MediaUploadRequestFfi> for MarmotMediaUploadRequest {
    fn from(value: MediaUploadRequestFfi) -> Self {
        let (attachments, attachments_len) =
            owned_vec(value.attachments.into_iter().map(Into::into).collect());
        Self {
            attachments,
            attachments_len,
            caption: owned_opt_c_string(value.caption),
            send: value.send,
            blossom_server: owned_opt_c_string(value.blossom_server),
        }
    }
}

impl MarmotMediaUploadRequest {
    /// Read a caller-owned upload request into the Ffi record without
    /// taking ownership of any caller memory.
    ///
    /// # Safety
    /// Every non-NULL string field must be a valid NUL-terminated string,
    /// and when `attachments` is non-NULL it must point to
    /// `attachments_len` valid attachment request structs.
    pub(crate) unsafe fn to_ffi(&self) -> Result<MediaUploadRequestFfi, MarmotStatus> {
        let attachments = if self.attachments.is_null() {
            if self.attachments_len != 0 {
                crate::status::set_last_error(
                    "media upload attachment array was NULL with nonzero length",
                );
                return Err(MarmotStatus::NullPointer);
            }
            Vec::new()
        } else {
            let borrowed = unsafe {
                std::slice::from_raw_parts(self.attachments.cast_const(), self.attachments_len)
            };
            let mut attachments = Vec::with_capacity(self.attachments_len);
            for attachment in borrowed {
                attachments.push(unsafe { attachment.to_ffi() }?);
            }
            attachments
        };
        Ok(MediaUploadRequestFfi {
            attachments,
            caption: unsafe { optional_str(self.caption.cast_const()) }?,
            send: self.send,
            blossom_server: unsafe { optional_str(self.blossom_server.cast_const()) }?,
        })
    }
}

impl CFree for MarmotMediaUploadRequest {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_vec(self.attachments, self.attachments_len);
            free_c_string(self.caption);
            free_c_string(self.blossom_server);
        }
    }
}

/// One uploaded attachment inside an upload result: the sendable reference
/// plus the encrypted blob size.
#[repr(C)]
pub struct MarmotMediaUploadAttachmentResult {
    pub reference: MarmotMediaAttachmentReference,
    pub encrypted_size_bytes: u64,
}

impl From<MediaUploadAttachmentResultFfi> for MarmotMediaUploadAttachmentResult {
    fn from(value: MediaUploadAttachmentResultFfi) -> Self {
        Self {
            reference: value.reference.into(),
            encrypted_size_bytes: value.encrypted_size_bytes,
        }
    }
}

impl CFree for MarmotMediaUploadAttachmentResult {
    unsafe fn free_in_place(&mut self) {
        unsafe { self.reference.free_in_place() };
    }
}

/// Result of `marmot_upload_media`: one entry per uploaded attachment, plus
/// the publish summary when the request asked to send.
#[repr(C)]
pub struct MarmotMediaUploadResult {
    pub attachments: *mut MarmotMediaUploadAttachmentResult,
    pub attachments_len: usize,
    /// Publish summary when the request asked to send. Nullable.
    pub sent: *mut MarmotSendSummary,
}

impl From<MediaUploadResultFfi> for MarmotMediaUploadResult {
    fn from(value: MediaUploadResultFfi) -> Self {
        let (attachments, attachments_len) =
            owned_vec(value.attachments.into_iter().map(Into::into).collect());
        Self {
            attachments,
            attachments_len,
            sent: boxed_opt(value.sent.map(Into::into)),
        }
    }
}

impl CFree for MarmotMediaUploadResult {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_vec(self.attachments, self.attachments_len);
            free_boxed(self.sent);
        }
    }
}

/// Free an upload result root returned by `marmot_upload_media`. NULL is a
/// no-op.
///
/// # Safety
/// `result` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_media_upload_result_free(result: *mut MarmotMediaUploadResult) {
    crate::memory::free_guard(|| unsafe { free_boxed(result) });
}

/// Result of `marmot_download_media`: the decrypted plaintext plus its
/// original metadata.
#[repr(C)]
pub struct MarmotMediaDownloadResult {
    /// Decrypted plaintext bytes. NULL with `plaintext_len == 0` when empty.
    pub plaintext: *mut u8,
    pub plaintext_len: usize,
    pub file_name: *mut c_char,
    /// MIME type of the plaintext, e.g. `image/png`.
    pub media_type: *mut c_char,
    /// Plaintext size in bytes.
    pub size_bytes: u64,
}

impl From<MediaDownloadResultFfi> for MarmotMediaDownloadResult {
    fn from(value: MediaDownloadResultFfi) -> Self {
        let (plaintext, plaintext_len) = owned_vec(value.plaintext);
        Self {
            plaintext,
            plaintext_len,
            file_name: owned_c_string(value.file_name),
            media_type: owned_c_string(value.media_type),
            size_bytes: value.size_bytes,
        }
    }
}

impl CFree for MarmotMediaDownloadResult {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_vec(self.plaintext, self.plaintext_len);
            free_c_string(self.file_name);
            free_c_string(self.media_type);
        }
    }
}

/// Free a download result root returned by `marmot_download_media`. NULL is
/// a no-op.
///
/// # Safety
/// `result` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_media_download_result_free(result: *mut MarmotMediaDownloadResult) {
    crate::memory::free_guard(|| unsafe { free_boxed(result) });
}

/// One media attachment projected from group message history. The embedded
/// `reference` can be passed back to `marmot_download_media`.
#[repr(C)]
pub struct MarmotMediaRecord {
    pub message_id_hex: *mut c_char,
    /// Zero-based position of this attachment within its carrying message.
    pub attachment_index: u32,
    /// Message direction, e.g. `incoming` or `outgoing`.
    pub direction: *mut c_char,
    pub group_id_hex: *mut c_char,
    pub sender: *mut c_char,
    pub reference: MarmotMediaAttachmentReference,
    /// Chat caption carried alongside the attachment, when any. Nullable.
    pub caption: *mut c_char,
    pub recorded_at: u64,
    pub received_at: u64,
}

impl From<MediaRecordFfi> for MarmotMediaRecord {
    fn from(value: MediaRecordFfi) -> Self {
        Self {
            message_id_hex: owned_c_string(value.message_id_hex),
            attachment_index: value.attachment_index,
            direction: owned_c_string(value.direction),
            group_id_hex: owned_c_string(value.group_id_hex),
            sender: owned_c_string(value.sender),
            reference: value.reference.into(),
            caption: owned_opt_c_string(value.caption),
            recorded_at: value.recorded_at,
            received_at: value.received_at,
        }
    }
}

impl CFree for MarmotMediaRecord {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_c_string(self.message_id_hex);
            free_c_string(self.direction);
            free_c_string(self.group_id_hex);
            free_c_string(self.sender);
            self.reference.free_in_place();
            free_c_string(self.caption);
        }
    }
}

/// Owned list of media records (`marmot_list_media`).
#[repr(C)]
pub struct MarmotMediaRecordList {
    pub items: *mut MarmotMediaRecord,
    pub len: usize,
}

impl From<Vec<MediaRecordFfi>> for MarmotMediaRecordList {
    fn from(value: Vec<MediaRecordFfi>) -> Self {
        let (items, len) = owned_vec(value.into_iter().map(Into::into).collect());
        Self { items, len }
    }
}

impl CFree for MarmotMediaRecordList {
    unsafe fn free_in_place(&mut self) {
        unsafe { free_vec(self.items, self.len) };
    }
}

/// Free a list returned by `marmot_list_media`. NULL is a no-op.
///
/// # Safety
/// `list` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_media_record_list_free(list: *mut MarmotMediaRecordList) {
    crate::memory::free_guard(|| unsafe { free_boxed(list) });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::boxed;
    use marmot_uniffi::conversions::SendSummaryFfi;

    fn sample_reference(byte: u8, file_name: &str) -> MediaAttachmentReferenceFfi {
        MediaAttachmentReferenceFfi {
            locators: vec![MediaLocatorFfi {
                kind: "blossom-v1".into(),
                value: format!("https://media.example/{byte:02x}.bin"),
            }],
            ciphertext_sha256: format!("{byte:02x}").repeat(32),
            plaintext_sha256: format!("{:02x}", byte.wrapping_add(1)).repeat(32),
            nonce_hex: format!("{byte:02x}").repeat(12),
            file_name: file_name.into(),
            media_type: "image/png".into(),
            version: "encrypted-media-v1".into(),
            source_epoch: 7,
            dim: Some("800x600".into()),
            thumbhash: Some("1QcSHQRnh493V4dIh4eXh1h4kJUI".into()),
        }
    }

    #[test]
    fn media_upload_result_deep_roundtrip() {
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let mirror: MarmotMediaUploadResult = MediaUploadResultFfi {
            attachments: vec![
                MediaUploadAttachmentResultFfi {
                    reference: sample_reference(0x11, "diagram.png"),
                    encrypted_size_bytes: 2048,
                },
                MediaUploadAttachmentResultFfi {
                    reference: sample_reference(0x22, "clip.mp4"),
                    encrypted_size_bytes: 4096,
                },
            ],
            sent: Some(SendSummaryFfi {
                published: 1,
                message_ids: vec!["ee".repeat(32)],
            }),
        }
        .into();
        assert_eq!(mirror.attachments_len, 2);
        let first = unsafe { &*mirror.attachments };
        assert_eq!(first.encrypted_size_bytes, 2048);
        assert_eq!(first.reference.locators_len, 1);
        assert_eq!(first.reference.source_epoch, 7);
        assert!(!first.reference.dim.is_null());
        assert!(!mirror.sent.is_null());
        assert_eq!(unsafe { (*mirror.sent).published }, 1);
        let root = boxed(mirror);
        unsafe { marmot_media_upload_result_free(root) };

        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn media_download_result_deep_roundtrip() {
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let mirror: MarmotMediaDownloadResult = MediaDownloadResultFfi {
            plaintext: vec![1, 2, 3, 4],
            file_name: "diagram.png".into(),
            media_type: "image/png".into(),
            size_bytes: 4,
        }
        .into();
        assert_eq!(mirror.plaintext_len, 4);
        let bytes = unsafe { std::slice::from_raw_parts(mirror.plaintext, mirror.plaintext_len) };
        assert_eq!(bytes, &[1, 2, 3, 4]);
        assert_eq!(mirror.size_bytes, 4);
        let root = boxed(mirror);
        unsafe { marmot_media_download_result_free(root) };

        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn media_record_list_deep_roundtrip() {
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let list: MarmotMediaRecordList = vec![MediaRecordFfi {
            message_id_hex: "aa".repeat(32),
            attachment_index: 0,
            direction: "incoming".into(),
            group_id_hex: "bb".repeat(32),
            sender: "alice".into(),
            reference: sample_reference(0x33, "voice.ogg"),
            caption: Some("album caption".into()),
            recorded_at: 10,
            received_at: 11,
        }]
        .into();
        assert_eq!(list.len, 1);
        let record = unsafe { &*list.items };
        assert_eq!(record.attachment_index, 0);
        assert!(!record.caption.is_null());
        assert_eq!(record.reference.locators_len, 1);
        assert_eq!(record.recorded_at, 10);
        let root = boxed(list);
        unsafe { marmot_media_record_list_free(root) };

        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn attachment_reference_input_roundtrips_borrowed_fields() {
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let mut owned: MarmotMediaAttachmentReference = sample_reference(0x44, "brief.pdf").into();
        let ffi = unsafe { owned.to_ffi() }.expect("valid borrowed reference");
        assert_eq!(ffi.locators.len(), 1);
        assert_eq!(ffi.locators[0].kind, "blossom-v1");
        assert_eq!(ffi.file_name, "brief.pdf");
        assert_eq!(ffi.source_epoch, 7);
        assert_eq!(ffi.dim.as_deref(), Some("800x600"));
        assert_eq!(
            ffi.thumbhash.as_deref(),
            Some("1QcSHQRnh493V4dIh4eXh1h4kJUI")
        );
        unsafe { owned.free_in_place() };

        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn upload_request_input_roundtrips_borrowed_fields() {
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let mut owned: MarmotMediaUploadRequest = MediaUploadRequestFfi {
            attachments: vec![
                MediaUploadAttachmentRequestFfi {
                    file_name: "diagram.png".into(),
                    media_type: "image/png".into(),
                    plaintext: vec![9, 8, 7],
                    dim: Some("800x600".into()),
                    thumbhash: Some("abc".into()),
                },
                MediaUploadAttachmentRequestFfi {
                    file_name: "clip.mp4".into(),
                    media_type: "video/mp4".into(),
                    plaintext: vec![1],
                    dim: None,
                    thumbhash: None,
                },
            ],
            caption: Some("two files".into()),
            send: true,
            blossom_server: Some("https://blossom.example".into()),
        }
        .into();
        let ffi = unsafe { owned.to_ffi() }.expect("valid borrowed request");
        assert_eq!(ffi.attachments.len(), 2);
        assert_eq!(ffi.attachments[0].plaintext, vec![9, 8, 7]);
        assert_eq!(ffi.attachments[0].dim.as_deref(), Some("800x600"));
        assert_eq!(ffi.attachments[1].file_name, "clip.mp4");
        assert_eq!(ffi.attachments[1].dim, None);
        assert_eq!(ffi.caption.as_deref(), Some("two files"));
        assert!(ffi.send);
        assert_eq!(
            ffi.blossom_server.as_deref(),
            Some("https://blossom.example")
        );
        unsafe { owned.free_in_place() };

        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn empty_vecs_and_none_convert_to_null() {
        let _guard = crate::memory::audit::test_lock();

        let mirror: MarmotMediaUploadResult = MediaUploadResultFfi {
            attachments: Vec::new(),
            sent: None,
        }
        .into();
        assert!(mirror.attachments.is_null());
        assert_eq!(mirror.attachments_len, 0);
        assert!(mirror.sent.is_null());
        let root = boxed(mirror);
        unsafe { marmot_media_upload_result_free(root) };

        let mut request: MarmotMediaUploadRequest = MediaUploadRequestFfi {
            attachments: Vec::new(),
            caption: None,
            send: false,
            blossom_server: None,
        }
        .into();
        assert!(request.attachments.is_null());
        assert!(request.caption.is_null());
        assert!(request.blossom_server.is_null());
        let ffi = unsafe { request.to_ffi() }.expect("empty request reads back");
        assert!(ffi.attachments.is_empty());
        assert_eq!(ffi.caption, None);
        assert_eq!(ffi.blossom_server, None);
        unsafe { request.free_in_place() };

        let list: MarmotMediaRecordList = Vec::<MediaRecordFfi>::new().into();
        assert!(list.items.is_null());
        assert_eq!(list.len, 0);
        let root = boxed(list);
        unsafe { marmot_media_record_list_free(root) };
    }
}
