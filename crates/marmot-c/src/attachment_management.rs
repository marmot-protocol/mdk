//! Global/chat download management. Inputs borrowed, returned roots owned and deep-freed.
use crate::attachment_controls::MarmotAttachmentTransferStatus;
use crate::attachment_history::MarmotAttachmentEntry;
use crate::commands::{deliver, try_arg};
use crate::macros::{c_enum, c_mirror};
use crate::memory::{
    CFree, boxed, boxed_opt, free_boxed, free_c_string, free_guard, free_vec, optional_str,
    owned_c_string, owned_vec, required_str,
};
use crate::types::history_notice::MarmotHistoryNotice;
use crate::{MarmotClient, MarmotStatus, client_ref, ffi_guard, preflight_out, preflight_out_ptr};
use marmot_uniffi::conversions::*;
use std::{ffi::c_char, sync::Arc};
c_enum! {MarmotAttachmentJobView from AttachmentJobViewFfi {All,Active,NeedsAttention,Ready,}}
c_enum! {MarmotAttachmentJobOrigin from AttachmentJobOriginFfi {Any,Automatic,Explicit,}}
c_enum! {MarmotAttachmentFailureCategory from AttachmentFailureCategoryFfi {None,UnclassifiedFailure,RetryExhausted,RetainedBytesUnavailable,CompletedWithoutRetention,PolicyBlocked,}}
/// Nullable group selects account scope; enums are checked integer discriminants.
#[repr(C)]
pub struct MarmotAttachmentJobQuery {
    pub group_id_hex: *const c_char,
    pub view: u32,
    pub origin: u32,
}
impl MarmotAttachmentJobQuery {
    pub(crate) unsafe fn to_ffi(&self) -> Result<AttachmentJobQueryFfi, MarmotStatus> {
        Ok(AttachmentJobQueryFfi {
            group_id_hex: unsafe { optional_str(self.group_id_hex) }?,
            view: MarmotAttachmentJobView::from_c(self.view)?.into(),
            origin: MarmotAttachmentJobOrigin::from_c(self.origin)?.into(),
        })
    }
}
pub struct MarmotAttachmentJobCursor {
    inner: Arc<AttachmentJobCursor>,
}
pub struct MarmotAttachmentJobActionToken {
    inner: Arc<AttachmentJobActionToken>,
}
pub struct MarmotAttachmentCancellationCursor {
    inner: Arc<AttachmentCancellationCursor>,
}
pub struct MarmotAttachmentManagementVersion {
    inner: Arc<AttachmentManagementVersion>,
}
macro_rules! handle {
    ($name:ident,$ffi:ty) => {
        impl From<Arc<$ffi>> for $name {
            fn from(inner: Arc<$ffi>) -> Self {
                Self { inner }
            }
        }
        impl CFree for $name {
            unsafe fn free_in_place(&mut self) {}
        }
    };
}
handle!(MarmotAttachmentJobCursor, AttachmentJobCursor);
handle!(MarmotAttachmentJobActionToken, AttachmentJobActionToken);
handle!(
    MarmotAttachmentCancellationCursor,
    AttachmentCancellationCursor
);
handle!(
    MarmotAttachmentManagementVersion,
    AttachmentManagementVersion
);
c_mirror! {MarmotAttachmentJobCounts from AttachmentJobCountsFfi {copy active:u32,copy needs_attention:u32,copy ready:u32,copy paused:u32,copy cancelled:u32,copy policy_blocked:u32,copy other:u32,copy complete:bool,}}
#[repr(C)]
pub struct MarmotManagedAttachmentEntry {
    pub group_id_hex: *mut c_char,
    pub entry: MarmotAttachmentEntry,
    pub explicit: bool,
    pub status: MarmotAttachmentTransferStatus,
    pub failure: MarmotAttachmentFailureCategory,
    pub action: *mut MarmotAttachmentJobActionToken,
}
impl From<ManagedAttachmentEntryFfi> for MarmotManagedAttachmentEntry {
    fn from(e: ManagedAttachmentEntryFfi) -> Self {
        Self {
            group_id_hex: owned_c_string(e.group_id_hex),
            entry: e.entry.into(),
            explicit: e.explicit,
            status: e.status.into(),
            failure: e.failure.into(),
            action: boxed(e.action.into()),
        }
    }
}
impl CFree for MarmotManagedAttachmentEntry {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_c_string(self.group_id_hex);
            self.entry.free_in_place();
            self.status.free_in_place();
            free_boxed(self.action);
        }
    }
}
#[repr(C)]
pub struct MarmotManagedAttachmentPage {
    pub entries: *mut MarmotManagedAttachmentEntry,
    pub entries_len: usize,
    pub next_cursor: *mut MarmotAttachmentJobCursor,
    pub has_next_expiry: bool,
    pub next_expiry: u64,
    pub observed_at: u64,
}
impl From<ManagedAttachmentPageFfi> for MarmotManagedAttachmentPage {
    fn from(p: ManagedAttachmentPageFfi) -> Self {
        let (entries, entries_len) = owned_vec(p.entries.into_iter().map(Into::into).collect());
        Self {
            entries,
            entries_len,
            next_cursor: boxed_opt(p.next_cursor.map(Into::into)),
            has_next_expiry: p.next_expiry.is_some(),
            next_expiry: p.next_expiry.unwrap_or(0),
            observed_at: p.observed_at,
        }
    }
}
impl CFree for MarmotManagedAttachmentPage {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_vec(self.entries, self.entries_len);
            free_boxed(self.next_cursor);
        }
    }
}
#[repr(C)]
pub struct MarmotAttachmentManagementSnapshot {
    pub available: bool,
    pub has_automatic_recovery_failed: bool,
    pub automatic_recovery_failed: bool,
    pub notices: *mut MarmotHistoryNotice,
    pub notices_len: usize,
    pub notices_complete: bool,
    pub counts: MarmotAttachmentJobCounts,
    pub page: MarmotManagedAttachmentPage,
    pub version: *mut MarmotAttachmentManagementVersion,
    pub redacted_diagnostics: *mut c_char,
}
impl From<AttachmentManagementSnapshotFfi> for MarmotAttachmentManagementSnapshot {
    fn from(s: AttachmentManagementSnapshotFfi) -> Self {
        let (notices, notices_len) = owned_vec(s.notices.into_iter().map(Into::into).collect());
        Self {
            available: s.available,
            has_automatic_recovery_failed: s.automatic_recovery_failed.is_some(),
            automatic_recovery_failed: s.automatic_recovery_failed.unwrap_or(false),
            notices,
            notices_len,
            notices_complete: s.notices_complete,
            counts: s.counts.into(),
            page: s.page.into(),
            version: boxed(s.version.into()),
            redacted_diagnostics: owned_c_string(s.redacted_diagnostics),
        }
    }
}
impl CFree for MarmotAttachmentManagementSnapshot {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_vec(self.notices, self.notices_len);
            self.page.free_in_place();
            free_boxed(self.version);
            free_c_string(self.redacted_diagnostics);
        }
    }
}
#[repr(C)]
pub struct MarmotAttachmentCancellationBatch {
    pub visited: u32,
    pub requested: u32,
    pub preserved: u32,
    pub next_cursor: *mut MarmotAttachmentCancellationCursor,
}
impl From<AttachmentCancellationBatchFfi> for MarmotAttachmentCancellationBatch {
    fn from(b: AttachmentCancellationBatchFfi) -> Self {
        Self {
            visited: b.visited,
            requested: b.requested,
            preserved: b.preserved,
            next_cursor: boxed_opt(b.next_cursor.map(Into::into)),
        }
    }
}
impl CFree for MarmotAttachmentCancellationBatch {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_boxed(self.next_cursor);
        }
    }
}
/// One local candidate page,1..50; an empty filtered page can continue. Blocking: call off UI thread.
/// # Safety
/// Inputs must be live; query borrowed; cursor NULL or live; out writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_managed_attachment_page(
    client: *const MarmotClient,
    account_ref: *const c_char,
    query: *const MarmotAttachmentJobQuery,
    limit: u32,
    cursor: *const MarmotAttachmentJobCursor,
    out: *mut *mut MarmotManagedAttachmentPage,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let client = try_arg!(unsafe { client_ref(client) });
        let account = try_arg!(unsafe { required_str(account_ref) });
        let Some(q) = (unsafe { query.as_ref() }) else {
            return MarmotStatus::NullPointer;
        };
        let q = try_arg!(unsafe { q.to_ffi() });
        let cursor = unsafe { cursor.as_ref() }.map(|v| v.inner.clone());
        unsafe {
            deliver(
                client.block_on(
                    client
                        .marmot
                        .managed_attachment_page(account, q, limit, cursor),
                ),
                out,
            )
        }
    })
}
/// One local head and independently observed health. Incomplete counts are lower bounds.
/// # Safety
/// Inputs live, query borrowed and out writable; result independently owned.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_attachment_management_snapshot(
    client: *const MarmotClient,
    account_ref: *const c_char,
    query: *const MarmotAttachmentJobQuery,
    out: *mut *mut MarmotAttachmentManagementSnapshot,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let client = try_arg!(unsafe { client_ref(client) });
        let account = try_arg!(unsafe { required_str(account_ref) });
        let Some(q) = (unsafe { query.as_ref() }) else {
            return MarmotStatus::NullPointer;
        };
        let q = try_arg!(unsafe { q.to_ffi() });
        unsafe {
            deliver(
                client.block_on(client.marmot.attachment_management_snapshot(account, q)),
                out,
            )
        }
    })
}
/// Capture old account/chat intent without changing it. Nonzero automatic_only excludes explicit requests.
/// # Safety
/// Client/account live; group NULL or live; out writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_begin_attachment_cancellation(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    automatic_only: u8,
    out: *mut *mut MarmotAttachmentCancellationCursor,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let client = try_arg!(unsafe { client_ref(client) });
        let account = try_arg!(unsafe { required_str(account_ref) });
        let group = try_arg!(unsafe { optional_str(group_id_hex) });
        unsafe {
            deliver(
                client.block_on(client.marmot.begin_attachment_cancellation(
                    account,
                    group,
                    automatic_only != 0,
                )),
                out,
            )
        }
    })
}
/// Request at most64 old cancellations. Preserves ready files and newer intent; does not confirm network stopped.
/// # Safety
/// Inputs live, cursor borrowed and out writable before any mutation.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_cancel_attachment_batch(
    client: *const MarmotClient,
    account_ref: *const c_char,
    cursor: *const MarmotAttachmentCancellationCursor,
    out: *mut *mut MarmotAttachmentCancellationBatch,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let client = try_arg!(unsafe { client_ref(client) });
        let account = try_arg!(unsafe { required_str(account_ref) });
        let Some(cursor) = (unsafe { cursor.as_ref() }) else {
            return MarmotStatus::NullPointer;
        };
        unsafe {
            deliver(
                client.block_on(
                    client
                        .marmot
                        .cancel_attachment_batch(account, cursor.inner.clone()),
                ),
                out,
            )
        }
    })
}
/// Cancel or retry an observed intent generation; nonzero retry selects retry. False means stale/unavailable.
/// # Safety
/// Inputs/action live and out writable; action borrowed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_control_managed_attachment(
    client: *const MarmotClient,
    account_ref: *const c_char,
    action: *const MarmotAttachmentJobActionToken,
    retry: u8,
    out: *mut bool,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out(out) });
        let client = try_arg!(unsafe { client_ref(client) });
        let account = try_arg!(unsafe { required_str(account_ref) });
        let Some(action) = (unsafe { action.as_ref() }) else {
            return MarmotStatus::NullPointer;
        };
        match client.block_on(client.marmot.control_managed_attachment(
            account,
            action.inner.clone(),
            retry != 0,
        )) {
            Ok(v) => {
                unsafe { *out = v };
                MarmotStatus::Ok
            }
            Err(e) => crate::status_from_error(&e),
        }
    })
}
/// Compare replacement generations. False means replace the snapshot, not a diagnosis.
/// # Safety
/// Both borrowed handles live; out writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_attachment_management_version_same_as(
    value: *const MarmotAttachmentManagementVersion,
    previous: *const MarmotAttachmentManagementVersion,
    out: *mut bool,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out(out) });
        let (Some(value), Some(previous)) =
            (unsafe { value.as_ref() }, unsafe { previous.as_ref() })
        else {
            return MarmotStatus::NullPointer;
        };
        unsafe { *out = value.inner.same_as(previous.inner.clone()) };
        MarmotStatus::Ok
    })
}

/// Clone a live borrowed handle into independent ownership.
/// # Safety
/// Value live and out writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_attachment_job_cursor_clone(
    value: *const MarmotAttachmentJobCursor,
    out: *mut *mut MarmotAttachmentJobCursor,
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

/// Clone a live borrowed handle into independent ownership.
/// # Safety
/// Value live and out writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_attachment_job_action_token_clone(
    value: *const MarmotAttachmentJobActionToken,
    out: *mut *mut MarmotAttachmentJobActionToken,
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

/// Clone a live borrowed handle into independent ownership.
/// # Safety
/// Value live and out writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_attachment_cancellation_cursor_clone(
    value: *const MarmotAttachmentCancellationCursor,
    out: *mut *mut MarmotAttachmentCancellationCursor,
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

/// Clone a live borrowed handle into independent ownership.
/// # Safety
/// Value live and out writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_attachment_management_version_clone(
    value: *const MarmotAttachmentManagementVersion,
    out: *mut *mut MarmotAttachmentManagementVersion,
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

/// Deep-free an independently owned root or clone. NULL is a no-op; embedded handles are borrowed.
/// # Safety
/// Value NULL or library-owned, unfreed and with no outstanding borrows.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_attachment_job_cursor_free(value: *mut MarmotAttachmentJobCursor) {
    free_guard(|| unsafe { free_boxed(value) })
}

/// Deep-free an independently owned root or clone. NULL is a no-op; embedded handles are borrowed.
/// # Safety
/// Value NULL or library-owned, unfreed and with no outstanding borrows.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_attachment_job_action_token_free(
    value: *mut MarmotAttachmentJobActionToken,
) {
    free_guard(|| unsafe { free_boxed(value) })
}

/// Deep-free an independently owned root or clone. NULL is a no-op; embedded handles are borrowed.
/// # Safety
/// Value NULL or library-owned, unfreed and with no outstanding borrows.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_attachment_cancellation_cursor_free(
    value: *mut MarmotAttachmentCancellationCursor,
) {
    free_guard(|| unsafe { free_boxed(value) })
}

/// Deep-free an independently owned root or clone. NULL is a no-op; embedded handles are borrowed.
/// # Safety
/// Value NULL or library-owned, unfreed and with no outstanding borrows.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_attachment_management_version_free(
    value: *mut MarmotAttachmentManagementVersion,
) {
    free_guard(|| unsafe { free_boxed(value) })
}

/// Deep-free an independently owned root or clone. NULL is a no-op; embedded handles are borrowed.
/// # Safety
/// Value NULL or library-owned, unfreed and with no outstanding borrows.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_managed_attachment_page_free(
    value: *mut MarmotManagedAttachmentPage,
) {
    free_guard(|| unsafe { free_boxed(value) })
}

/// Deep-free an independently owned root or clone. NULL is a no-op; embedded handles are borrowed.
/// # Safety
/// Value NULL or library-owned, unfreed and with no outstanding borrows.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_attachment_management_snapshot_free(
    value: *mut MarmotAttachmentManagementSnapshot,
) {
    free_guard(|| unsafe { free_boxed(value) })
}

/// Deep-free an independently owned root or clone. NULL is a no-op; embedded handles are borrowed.
/// # Safety
/// Value NULL or library-owned, unfreed and with no outstanding borrows.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_attachment_cancellation_batch_free(
    value: *mut MarmotAttachmentCancellationBatch,
) {
    free_guard(|| unsafe { free_boxed(value) })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn management_mutations_preflight_outputs_and_reject_invalid_discriminants() {
        let query = MarmotAttachmentJobQuery {
            group_id_hex: std::ptr::null(),
            view: u32::MAX,
            origin: 0,
        };
        assert!(matches!(
            unsafe { query.to_ffi() },
            Err(MarmotStatus::InvalidArgument)
        ));
        assert_eq!(
            unsafe {
                marmot_cancel_attachment_batch(
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null_mut(),
                )
            },
            MarmotStatus::NullPointer
        );
        assert_eq!(
            unsafe {
                marmot_control_managed_attachment(
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null(),
                    255,
                    std::ptr::null_mut(),
                )
            },
            MarmotStatus::NullPointer
        );
        assert_eq!(
            unsafe {
                marmot_begin_attachment_cancellation(
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null(),
                    255,
                    std::ptr::null_mut(),
                )
            },
            MarmotStatus::NullPointer
        );
        unsafe {
            marmot_managed_attachment_page_free(std::ptr::null_mut());
            marmot_attachment_management_snapshot_free(std::ptr::null_mut());
            marmot_attachment_cancellation_batch_free(std::ptr::null_mut());
        }
    }
}
