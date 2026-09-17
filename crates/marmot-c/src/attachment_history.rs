//! Local attachment discovery and opaque process-local cursor/version ownership.
use crate::commands::{deliver, try_arg};
use crate::macros::{c_enum, c_mirror};
use crate::memory::{
    CFree, boxed, boxed_opt, free_boxed, free_guard, free_vec, owned_vec, required_str,
};
use crate::types::media::MarmotMediaAttachmentOutcome;
use crate::{MarmotClient, MarmotStatus, check_out, client_ref, ffi_guard, preflight_out_ptr};
use marmot_uniffi::conversions::*;
use std::{ffi::c_char, sync::Arc};

pub struct MarmotAttachmentHistoryCursor {
    inner: Arc<AttachmentHistoryCursor>,
}
pub struct MarmotAttachmentHistoryVersion {
    inner: Arc<AttachmentHistoryVersion>,
}
impl From<Arc<AttachmentHistoryCursor>> for MarmotAttachmentHistoryCursor {
    fn from(inner: Arc<AttachmentHistoryCursor>) -> Self {
        Self { inner }
    }
}
impl From<Arc<AttachmentHistoryVersion>> for MarmotAttachmentHistoryVersion {
    fn from(inner: Arc<AttachmentHistoryVersion>) -> Self {
        Self { inner }
    }
}
impl CFree for MarmotAttachmentHistoryCursor {
    unsafe fn free_in_place(&mut self) {}
}
impl CFree for MarmotAttachmentHistoryVersion {
    unsafe fn free_in_place(&mut self) {}
}
c_enum! { MarmotAttachmentCategory from AttachmentCategoryFfi { Image, Video, Audio, File, Rejected, } }
c_enum! { MarmotAttachmentHistoryChange from AttachmentHistoryChangeFfi { Unchanged, Additions, RestartRequired, } }
c_mirror! { MarmotAttachmentEntry from AttachmentEntryFfi {
    str message_id_hex,
    str source_message_id_hex,
    str sender,
    copy timeline_at: u64,
    copy received_at: u64,
    opt_copy has_source_epoch/source_epoch: u64,
    copy category: MarmotAttachmentCategory,
    rec attachment: MarmotMediaAttachmentOutcome,
} }
/// All fields, including opaque handles, are owned by this page's result.
/// Keep that result live while borrowing its cursor/version; do not free fields separately.
#[repr(C)]
pub struct MarmotAttachmentPage {
    pub entries: *mut MarmotAttachmentEntry,
    pub entries_len: usize,
    pub version: *mut MarmotAttachmentHistoryVersion,
    pub next_cursor: *mut MarmotAttachmentHistoryCursor,
    pub has_more: bool,
}
impl From<AttachmentPageFfi> for MarmotAttachmentPage {
    fn from(value: AttachmentPageFfi) -> Self {
        let (entries, entries_len) = owned_vec(value.entries.into_iter().map(Into::into).collect());
        Self {
            entries,
            entries_len,
            version: boxed(value.version.into()),
            next_cursor: boxed_opt(value.next_cursor.map(Into::into)),
            has_more: value.has_more,
        }
    }
}
impl CFree for MarmotAttachmentPage {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_vec(self.entries, self.entries_len);
            free_boxed(self.version);
            free_boxed(self.next_cursor);
        }
    }
}
#[repr(C)]
pub enum MarmotAttachmentPageRead {
    Page { page: MarmotAttachmentPage },
    RestartRequired,
    CursorMismatch,
    InvalidLimit,
}
impl From<AttachmentPageReadFfi> for MarmotAttachmentPageRead {
    fn from(value: AttachmentPageReadFfi) -> Self {
        match value {
            AttachmentPageReadFfi::Page { page } => Self::Page { page: page.into() },
            AttachmentPageReadFfi::RestartRequired => Self::RestartRequired,
            AttachmentPageReadFfi::CursorMismatch => Self::CursorMismatch,
            AttachmentPageReadFfi::InvalidLimit => Self::InvalidLimit,
        }
    }
}
impl CFree for MarmotAttachmentPageRead {
    unsafe fn free_in_place(&mut self) {
        if let Self::Page { page } = self {
            unsafe { page.free_in_place() };
        }
    }
}
/// Deep-free a page result and its cursor/version. NULL is a no-op.
/// # Safety
/// Value must be NULL or an owned result, not freed or borrowed by an active call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_attachment_page_read_free(value: *mut MarmotAttachmentPageRead) {
    free_guard(|| unsafe { free_boxed(value) });
}
/// Free a standalone version returned by a version read or clone, not a page field.
/// # Safety
/// Value must be NULL or a standalone owned version, with no active borrows.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_attachment_history_version_free(
    value: *mut MarmotAttachmentHistoryVersion,
) {
    free_guard(|| unsafe { free_boxed(value) });
}
/// Retain a standalone baseline version without retaining its owning page.
/// Free the result with marmot_attachment_history_version_free.
/// # Safety
/// Value must be a live standalone version or borrowed page field; out must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_attachment_history_version_clone(
    value: *const MarmotAttachmentHistoryVersion,
    out: *mut *mut MarmotAttachmentHistoryVersion,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let Some(value) = (unsafe { value.as_ref() }) else {
            return MarmotStatus::NullPointer;
        };
        unsafe { *out = boxed(value.inner.clone().into()) };
        MarmotStatus::Ok
    })
}
/// Blocking local read. Call off the UI thread; limit is 1..=100 slots.
/// NULL cursor starts at the head. Cursor is borrowed for this call; no network work starts.
/// # Safety
/// Client and strings must be live; cursor must be NULL or live; out must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_attachment_history_page(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    limit: u32,
    cursor: *const MarmotAttachmentHistoryCursor,
    out: *mut *mut MarmotAttachmentPageRead,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let client = try_arg!(unsafe { client_ref(client) });
        let account = try_arg!(unsafe { required_str(account_ref) });
        let group = try_arg!(unsafe { required_str(group_id_hex) });
        let cursor = unsafe { cursor.as_ref() }.map(|c| c.inner.clone());
        unsafe {
            deliver(
                client.block_on(
                    client
                        .marmot
                        .attachment_history_page(account, group, limit, cursor),
                ),
                out,
            )
        }
    })
}
/// Blocking local revision read, including after exhaustion. Free the standalone result.
/// # Safety
/// Client/strings must be live and out writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_attachment_history_version(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    out: *mut *mut MarmotAttachmentHistoryVersion,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let client = try_arg!(unsafe { client_ref(client) });
        let account = try_arg!(unsafe { required_str(account_ref) });
        let group = try_arg!(unsafe { required_str(group_id_hex) });
        unsafe {
            deliver(
                client.block_on(client.marmot.attachment_history_version(account, group)),
                out,
            )
        }
    })
}
/// Compare a current version with the retained baseline. Output is a MarmotAttachmentHistoryChange discriminant.
/// # Safety
/// Both versions must be live (standalone or borrowed page fields); out must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_attachment_history_version_change_since(
    current: *const MarmotAttachmentHistoryVersion,
    previous: *const MarmotAttachmentHistoryVersion,
    out: *mut u32,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { check_out(out) });
        let Some(current) = (unsafe { current.as_ref() }) else {
            return MarmotStatus::NullPointer;
        };
        let Some(previous) = (unsafe { previous.as_ref() }) else {
            return MarmotStatus::NullPointer;
        };
        let value: MarmotAttachmentHistoryChange =
            current.inner.change_since(previous.inner.clone()).into();
        unsafe {
            *out = value as u32;
        }
        MarmotStatus::Ok
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use marmot_uniffi::{Marmot, MarmotKitError, SecretStore};
    use std::{collections::HashMap, ffi::CString, ptr, sync::Mutex};
    #[derive(Default)]
    struct Store(Mutex<HashMap<String, String>>);
    impl SecretStore for Store {
        fn has_secret_for_label(&self, label: String) -> Result<bool, MarmotKitError> {
            Ok(self.0.lock().unwrap().contains_key(&label))
        }
        fn has_secret_for_account_id(&self, _: String) -> Result<bool, MarmotKitError> {
            Ok(false)
        }
        fn write_secret(
            &self,
            label: String,
            _: String,
            key: String,
        ) -> Result<(), MarmotKitError> {
            self.0.lock().unwrap().insert(label, key);
            Ok(())
        }
        fn load_secret(&self, label: String, _: String) -> Result<String, MarmotKitError> {
            self.0
                .lock()
                .unwrap()
                .get(&label)
                .cloned()
                .ok_or(MarmotKitError::SecretNotFound {
                    details: "test".into(),
                })
        }
        fn remove_secret(&self, label: String, _: String) -> Result<(), MarmotKitError> {
            self.0.lock().unwrap().remove(&label);
            Ok(())
        }
    }
    #[test]
    fn attachment_c_handles_preflight_borrowing_and_deep_free() {
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let before = crate::memory::audit::live_allocations();
        let dir = tempfile::tempdir().unwrap();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let relay = rt.block_on(nostr_relay_builder::MockRelay::run()).unwrap();
        let url = rt.block_on(relay.url()).to_string();
        let kit = Marmot::new_with_options(
            dir.path().to_str().unwrap().into(),
            vec![url.clone()],
            marmot_uniffi::RelayPolicyFfi::AllowLoopback,
            Some(Arc::new(Store::default())),
        )
        .unwrap();
        let client = MarmotClient {
            runtime: rt,
            marmot: kit,
        };
        let account = client
            .block_on(client.marmot.create_identity(vec![url.clone()], vec![url]))
            .unwrap()
            .account_id_hex;
        let group = client
            .block_on(client.marmot.create_group(
                account.clone(),
                "C attachments".into(),
                vec![],
                None,
            ))
            .unwrap();
        let reference = MediaAttachmentReferenceFfi {
            locators: vec![MediaLocatorFfi {
                kind: "blossom-v1".into(),
                value: format!("https://media.example/{}.bin", "11".repeat(32)),
            }],
            ciphertext_sha256: "11".repeat(32),
            plaintext_sha256: "22".repeat(32),
            nonce_hex: "33".repeat(12),
            file_name: "image.png".into(),
            media_type: "image/png".into(),
            version: EncryptedMediaVersionFfi::V2,
            source_epoch: 0,
            dim: None,
            thumbhash: None,
        };
        client
            .block_on(client.marmot.send_media_attachments(
                account.clone(),
                group.clone(),
                vec![reference.clone(), reference],
                None,
            ))
            .unwrap();
        let account = CString::new(account).unwrap();
        let group = CString::new(group).unwrap();
        unsafe {
            assert_eq!(
                marmot_attachment_history_page(
                    &client,
                    account.as_ptr(),
                    group.as_ptr(),
                    1,
                    ptr::null(),
                    ptr::null_mut()
                ),
                MarmotStatus::NullPointer
            );
            let mut first = ptr::null_mut();
            assert_eq!(
                marmot_attachment_history_page(
                    &client,
                    account.as_ptr(),
                    group.as_ptr(),
                    1,
                    ptr::null(),
                    &mut first
                ),
                MarmotStatus::Ok
            );
            let MarmotAttachmentPageRead::Page { page } = &*first else {
                panic!("page")
            };
            assert_eq!(page.entries_len, 1);
            assert!(page.has_more);
            assert!(!page.next_cursor.is_null());
            let mut second = ptr::null_mut();
            assert_eq!(
                marmot_attachment_history_page(
                    &client,
                    account.as_ptr(),
                    group.as_ptr(),
                    1,
                    page.next_cursor,
                    &mut second
                ),
                MarmotStatus::Ok
            );
            let mut version = ptr::null_mut();
            assert_eq!(
                marmot_attachment_history_version(
                    &client,
                    account.as_ptr(),
                    group.as_ptr(),
                    &mut version
                ),
                MarmotStatus::Ok
            );
            let mut change = u32::MAX;
            assert_eq!(
                marmot_attachment_history_version_change_since(version, page.version, &mut change),
                MarmotStatus::Ok
            );
            assert_eq!(change, MarmotAttachmentHistoryChange::Unchanged as u32);
            // Failure must not synthesize Unchanged (zero) into an enum output.
            for (current, previous) in [
                (ptr::null(), page.version.cast_const()),
                (version.cast_const(), ptr::null()),
            ] {
                change = u32::MAX;
                assert_eq!(
                    marmot_attachment_history_version_change_since(current, previous, &mut change),
                    MarmotStatus::NullPointer
                );
                assert_eq!(change, u32::MAX);
            }
            assert_eq!(
                marmot_attachment_history_version_change_since(
                    version,
                    page.version,
                    ptr::null_mut()
                ),
                MarmotStatus::NullPointer
            );
            let mut baseline = ptr::null_mut();
            assert_eq!(
                marmot_attachment_history_version_clone(page.version, &mut baseline),
                MarmotStatus::Ok
            );
            assert_eq!(
                marmot_attachment_history_version_clone(page.version, ptr::null_mut()),
                MarmotStatus::NullPointer
            );
            let mut invalid = baseline;
            assert_eq!(
                marmot_attachment_history_version_clone(ptr::null(), &mut invalid),
                MarmotStatus::NullPointer
            );
            assert!(invalid.is_null());
            marmot_attachment_history_version_free(version);
            // Child cursor/version are released with the page; the next result is independent.
            marmot_attachment_page_read_free(first);
            let MarmotAttachmentPageRead::Page { page } = &*second else {
                panic!("page")
            };
            assert_eq!(
                marmot_attachment_history_version_change_since(page.version, baseline, &mut change),
                MarmotStatus::Ok
            );
            assert_eq!(change, MarmotAttachmentHistoryChange::Unchanged as u32);
            marmot_attachment_history_version_free(baseline);
            assert!(!page.has_more);
            assert!(page.next_cursor.is_null());
            marmot_attachment_page_read_free(second);
            for result in [
                AttachmentPageReadFfi::RestartRequired,
                AttachmentPageReadFfi::CursorMismatch,
                AttachmentPageReadFfi::InvalidLimit,
            ] {
                marmot_attachment_page_read_free(boxed(MarmotAttachmentPageRead::from(result)));
            }
            let rejected = MarmotAttachmentEntry::from(AttachmentEntryFfi {
                message_id_hex: "m".into(),
                source_message_id_hex: "s".into(),
                sender: "author".into(),
                timeline_at: 1,
                received_at: 2,
                source_epoch: None,
                category: AttachmentCategoryFfi::Rejected,
                attachment: MediaAttachmentOutcomeFfi::Rejected {
                    attachment_index: 3,
                    rejection: MediaAttachmentRejectionFfi {
                        kind: MediaAttachmentRejectionKindFfi::UnsupportedFormat,
                        detail: "unsupported".into(),
                    },
                },
            });
            free_boxed(boxed(rejected));
        }
        client.block_on(client.marmot.shutdown_and_close()).unwrap();
        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), before);
    }
}
