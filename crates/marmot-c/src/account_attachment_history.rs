//! Bounded account-local attachment pages and borrowed opaque cursor ownership.
use crate::attachment_history::MarmotAttachmentEntry;
use crate::commands::{deliver, try_arg};
use crate::macros::c_mirror;
use crate::memory::{
    CFree, boxed, boxed_opt, free_boxed, free_guard, free_vec, owned_vec, required_str, str_array,
};
use crate::{MarmotClient, MarmotStatus, check_out, client_ref, ffi_guard, preflight_out_ptr};
use marmot_uniffi::conversions::*;
use std::{ffi::c_char, sync::Arc};
pub struct MarmotAccountAttachmentCursor {
    inner: Arc<AccountAttachmentCursor>,
}
pub struct MarmotAccountAttachmentVersion {
    inner: Arc<AccountAttachmentVersion>,
}
impl From<Arc<AccountAttachmentCursor>> for MarmotAccountAttachmentCursor {
    fn from(inner: Arc<AccountAttachmentCursor>) -> Self {
        Self { inner }
    }
}
impl From<Arc<AccountAttachmentVersion>> for MarmotAccountAttachmentVersion {
    fn from(inner: Arc<AccountAttachmentVersion>) -> Self {
        Self { inner }
    }
}
impl CFree for MarmotAccountAttachmentCursor {
    unsafe fn free_in_place(&mut self) {}
}
impl CFree for MarmotAccountAttachmentVersion {
    unsafe fn free_in_place(&mut self) {}
}
/// Borrowed arrays, at most100 entries each. Empty means all; has_after/has_before are uint8_t flags.
#[repr(C)]
pub struct MarmotAccountAttachmentQuery {
    pub groups: *const *const c_char,
    pub groups_len: usize,
    pub senders: *const *const c_char,
    pub senders_len: usize,
    pub has_after: u8,
    pub after: u64,
    pub has_before: u8,
    pub before: u64,
}
impl MarmotAccountAttachmentQuery {
    unsafe fn to_ffi(&self) -> Result<AccountAttachmentQueryFfi, MarmotStatus> {
        if self.groups_len > 100 || self.senders_len > 100 {
            return Err(MarmotStatus::InvalidArgument);
        }
        Ok(AccountAttachmentQueryFfi {
            groups: unsafe { str_array(self.groups, self.groups_len) }?,
            senders: unsafe { str_array(self.senders, self.senders_len) }?,
            after: (self.has_after != 0).then_some(self.after),
            before: (self.has_before != 0).then_some(self.before),
        })
    }
}
c_mirror! {MarmotAccountAttachmentEntry from AccountAttachmentEntryFfi {copy metadata_limited:bool,str group_id_hex,rec entry:MarmotAttachmentEntry,}}
/// Owned result fields; borrow handles only while the result is live, or clone the version baseline.
#[repr(C)]
pub struct MarmotAccountAttachmentPage {
    pub entries: *mut MarmotAccountAttachmentEntry,
    pub entries_len: usize,
    pub version: *mut MarmotAccountAttachmentVersion,
    pub next_cursor: *mut MarmotAccountAttachmentCursor,
    pub has_more: bool,
    pub has_next_expiry: bool,
    pub next_expiry: u64,
}
impl From<AccountAttachmentPageFfi> for MarmotAccountAttachmentPage {
    fn from(v: AccountAttachmentPageFfi) -> Self {
        let (entries, entries_len) = owned_vec(v.entries.into_iter().map(Into::into).collect());
        Self {
            entries,
            entries_len,
            version: boxed(v.version.into()),
            next_cursor: boxed_opt(v.next_cursor.map(Into::into)),
            has_more: v.has_more,
            has_next_expiry: v.next_expiry.is_some(),
            next_expiry: v.next_expiry.unwrap_or(0),
        }
    }
}
impl CFree for MarmotAccountAttachmentPage {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_vec(self.entries, self.entries_len);
            free_boxed(self.version);
            free_boxed(self.next_cursor);
        }
    }
}
#[repr(C)]
pub enum MarmotAccountAttachmentPageRead {
    Page { page: MarmotAccountAttachmentPage },
    RestartRequired,
    CursorMismatch,
    InvalidQuery,
    InvalidLimit,
    ResponseTooLarge,
}
impl From<AccountAttachmentPageReadFfi> for MarmotAccountAttachmentPageRead {
    fn from(v: AccountAttachmentPageReadFfi) -> Self {
        match v {
            AccountAttachmentPageReadFfi::Page { page } => Self::Page { page: page.into() },
            AccountAttachmentPageReadFfi::RestartRequired => Self::RestartRequired,
            AccountAttachmentPageReadFfi::CursorMismatch => Self::CursorMismatch,
            AccountAttachmentPageReadFfi::InvalidQuery => Self::InvalidQuery,
            AccountAttachmentPageReadFfi::InvalidLimit => Self::InvalidLimit,
            AccountAttachmentPageReadFfi::ResponseTooLarge => Self::ResponseTooLarge,
        }
    }
}
impl CFree for MarmotAccountAttachmentPageRead {
    unsafe fn free_in_place(&mut self) {
        if let Self::Page { page } = self {
            unsafe { page.free_in_place() };
        }
    }
}
/// Deep-free the page result, including its borrowed cursor/version fields. NULL is a no-op.
/// # Safety
/// Value must be NULL or an owned, unfreed result with no outstanding borrows.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_account_attachment_page_read_free(
    value: *mut MarmotAccountAttachmentPageRead,
) {
    free_guard(|| unsafe { free_boxed(value) });
}
/// Free a standalone version, never a field of a page result. NULL is a no-op.
/// # Safety
/// Value must be NULL or an owned standalone version with no outstanding borrows.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_account_attachment_version_free(
    value: *mut MarmotAccountAttachmentVersion,
) {
    free_guard(|| unsafe { free_boxed(value) });
}
/// Clone a borrowed version into an independently owned baseline.
/// # Safety
/// Value must be live and out writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_account_attachment_version_clone(
    value: *const MarmotAccountAttachmentVersion,
    out: *mut *mut MarmotAccountAttachmentVersion,
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
/// Blocking local read; call off the UI thread. Limit is1..=100 candidates, not a filtered row target.
/// # Safety
/// Client, strings and query arrays must be valid, cursor NULL or live, and out writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_account_attachment_history_page(
    client: *const MarmotClient,
    account_ref: *const c_char,
    query: *const MarmotAccountAttachmentQuery,
    limit: u32,
    cursor: *const MarmotAccountAttachmentCursor,
    out: *mut *mut MarmotAccountAttachmentPageRead,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let client = try_arg!(unsafe { client_ref(client) });
        let account = try_arg!(unsafe { required_str(account_ref) });
        let Some(query) = (unsafe { query.as_ref() }) else {
            return MarmotStatus::NullPointer;
        };
        let query = try_arg!(unsafe { query.to_ffi() });
        let cursor = unsafe { cursor.as_ref() }.map(|v| v.inner.clone());
        unsafe {
            deliver(
                client.block_on(
                    client
                        .marmot
                        .account_attachment_history_page(account, query, limit, cursor),
                ),
                out,
            )
        }
    })
}
/// Read a constant-work account change token, owned independently from any page.
/// # Safety
/// Client and string must be live and out writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_account_attachment_history_version(
    client: *const MarmotClient,
    account_ref: *const c_char,
    out: *mut *mut MarmotAccountAttachmentVersion,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let client = try_arg!(unsafe { client_ref(client) });
        let account = try_arg!(unsafe { required_str(account_ref) });
        unsafe {
            deliver(
                client.block_on(client.marmot.account_attachment_history_version(account)),
                out,
            )
        }
    })
}
/// Compare against the retained baseline; outputs a MarmotAttachmentHistoryChange discriminant, not a count.
/// # Safety
/// Both versions must be live and out writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_account_attachment_version_change_since(
    current: *const MarmotAccountAttachmentVersion,
    previous: *const MarmotAccountAttachmentVersion,
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
        unsafe {
            *out = crate::attachment_history::MarmotAttachmentHistoryChange::from(
                current.inner.change_since(previous.inner.clone()),
            ) as u32
        };
        MarmotStatus::Ok
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_null_output_before_touching_inputs_and_bounds_borrowed_arrays() {
        assert_eq!(
            unsafe {
                marmot_account_attachment_history_page(
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null(),
                    50,
                    std::ptr::null(),
                    std::ptr::null_mut(),
                )
            },
            MarmotStatus::NullPointer
        );
        let input = MarmotAccountAttachmentQuery {
            groups: std::ptr::null(),
            groups_len: 101,
            senders: std::ptr::null(),
            senders_len: 0,
            has_after: 0,
            after: 0,
            has_before: 0,
            before: 0,
        };
        assert!(matches!(
            unsafe { input.to_ffi() },
            Err(MarmotStatus::InvalidArgument)
        ));
    }
}
