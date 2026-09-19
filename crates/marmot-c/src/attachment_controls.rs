//! Attachment controls and source-bound transfer snapshots. Calls block: use off the UI thread.
use crate::attachment_access::MarmotAttachmentLocalTarget;
use crate::commands::{deliver, deliver_opt_string, deliver_scalar, deliver_unit, try_arg};
use crate::macros::{c_enum, c_mirror};
use crate::memory::required_str;
use crate::{MarmotClient, MarmotStatus, client_ref, ffi_guard, preflight_out, preflight_out_ptr};
use marmot_uniffi::conversions::*;
use std::ffi::c_char;
c_enum! {MarmotAttachmentControl from AttachmentControlFfi {Cancel,Retry,Remove,}}
c_enum! {MarmotAttachmentTransferState from AttachmentTransferStateFfi {Unavailable,NotRequested,Queued,Downloading,VerifyingCiphertext,Decrypting,VerifyingPlaintext,Ready,RetryScheduled,Failed,Cancelled,Paused,Removed,PolicyBlocked,}}
c_mirror! {MarmotAttachmentDownloadPolicy from AttachmentDownloadPolicyFfi, free marmot_attachment_download_policy_free {
 copy automatic: bool, copy retained_bytes: u64, copy disk_reserve: u64, copy transfer_limit: u64,
}}
/// Borrowed policy input. Nonzero automatic enables acquisition.
#[repr(C)]
pub struct MarmotAttachmentDownloadPolicyInput {
    pub automatic: u8,
    pub retained_bytes: u64,
    pub disk_reserve: u64,
    pub transfer_limit: u64,
}
c_mirror! {MarmotAttachmentTransferStatus from AttachmentTransferStatusFfi {
 opt_str reference,copy state: MarmotAttachmentTransferState,copy attempt: u64,copy received: u64,
 opt_copy has_total/total: u64,opt_copy has_retry_at/retry_at: u64,
}}
c_mirror! {MarmotAttachmentTransferSnapshot from AttachmentTransferSnapshotFfi, free marmot_attachment_transfer_snapshot_free {
 vec items/items_len: MarmotAttachmentTransferStatus,
}}
pub(crate) unsafe fn read_targets(
    targets: *const MarmotAttachmentLocalTarget,
    len: usize,
) -> Result<Vec<AttachmentLocalTargetFfi>, MarmotStatus> {
    if len > marmot_uniffi::MAX_ATTACHMENT_ASSET_LOOKUPS {
        crate::status::set_last_error("too many attachment targets");
        return Err(MarmotStatus::InvalidArgument);
    }
    let slice = if len == 0 {
        &[]
    } else {
        if targets.is_null() {
            return Err(MarmotStatus::NullPointer);
        }
        unsafe { std::slice::from_raw_parts(targets, len) }
    };
    slice
        .iter()
        .map(|t| {
            Ok(AttachmentLocalTargetFfi {
                message_id_hex: unsafe { required_str(t.message_id_hex) }?,
                source_message_id_hex: unsafe { required_str(t.source_message_id_hex) }?,
                attachment_index: t.attachment_index,
            })
        })
        .collect()
}
/// Read the effective durable policy.
/// # Safety
/// Client and strings must be live, out writable. Free the returned record.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_attachment_download_policy(
    client: *const MarmotClient,
    account_ref: *const c_char,
    out: *mut *mut MarmotAttachmentDownloadPolicy,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let client = try_arg!(unsafe { client_ref(client) });
        let account = try_arg!(unsafe { required_str(account_ref) });
        unsafe {
            deliver(
                client.block_on(client.marmot.attachment_download_policy(account)),
                out,
            )
        }
    })
}
/// Persist policy. Disable pauses automatic work but preserves explicit transfers and cached bytes.
/// # Safety
/// Client, strings and policy must be live throughout this call. Inputs are borrowed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_set_attachment_download_policy(
    client: *const MarmotClient,
    account_ref: *const c_char,
    policy: *const MarmotAttachmentDownloadPolicyInput,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account = try_arg!(unsafe { required_str(account_ref) });
        let Some(p) = (unsafe { policy.as_ref() }) else {
            return MarmotStatus::NullPointer;
        };
        deliver_unit(
            client.block_on(client.marmot.set_attachment_download_policy(
                account,
                AttachmentDownloadPolicyFfi {
                    automatic: p.automatic != 0,
                    retained_bytes: p.retained_bytes,
                    disk_reserve: p.disk_reserve,
                    transfer_limit: p.transfer_limit,
                },
            )),
        )
    })
}
/// Apply a MarmotAttachmentControl discriminant to an opaque reference.
/// # Safety
/// Client/strings must be live and out writable. No inputs are retained.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_control_attachment(
    client: *const MarmotClient,
    account_ref: *const c_char,
    reference: *const c_char,
    control: u32,
    out: *mut bool,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out(out) });
        let control = try_arg!(MarmotAttachmentControl::from_c(control));
        let client = try_arg!(unsafe { client_ref(client) });
        let account = try_arg!(unsafe { required_str(account_ref) });
        let reference = try_arg!(unsafe { required_str(reference) });
        unsafe {
            deliver_scalar(
                client.block_on(client.marmot.control_attachment(
                    account,
                    reference,
                    match control {
                        MarmotAttachmentControl::Cancel => AttachmentControlFfi::Cancel,
                        MarmotAttachmentControl::Retry => AttachmentControlFfi::Retry,
                        MarmotAttachmentControl::Remove => AttachmentControlFfi::Remove,
                    },
                )),
                out,
            )
        }
    })
}
/// Explicitly request the current slot, including after cancellation/removal. NULL result is unavailable.
/// # Safety
/// Client, strings and target must be live; out writable. Free returned string with marmot_string_free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_download_attachment_again(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    target: *const MarmotAttachmentLocalTarget,
    out: *mut *mut c_char,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let target = try_arg!(unsafe { read_targets(target, 1) }).remove(0);
        let client = try_arg!(unsafe { client_ref(client) });
        let account = try_arg!(unsafe { required_str(account_ref) });
        let group = try_arg!(unsafe { required_str(group_id_hex) });
        unsafe {
            deliver_opt_string(
                client.block_on(
                    client
                        .marmot
                        .download_attachment_again(account, group, target),
                ),
                out,
            )
        }
    })
}
/// Read up to 64 progress entries in input order. No network demand is created.
/// # Safety
/// Inputs must be live; targets may be NULL only for zero length; out writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_attachment_transfer_snapshot(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    targets: *const MarmotAttachmentLocalTarget,
    targets_len: usize,
    out: *mut *mut MarmotAttachmentTransferSnapshot,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let targets = try_arg!(unsafe { read_targets(targets, targets_len) });
        let client = try_arg!(unsafe { client_ref(client) });
        let account = try_arg!(unsafe { required_str(account_ref) });
        let group = try_arg!(unsafe { required_str(group_id_hex) });
        unsafe {
            deliver(
                client.block_on(
                    client
                        .marmot
                        .attachment_transfer_snapshot(account, group, targets),
                ),
                out,
            )
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::{audit, boxed};
    #[test]
    fn attachment_controls_c_preflight_enums_bounds_and_owned_snapshot() {
        let _guard = audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let before = audit::live_allocations();
        unsafe {
            let mut changed = true;
            assert_eq!(
                marmot_control_attachment(
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null(),
                    99,
                    &raw mut changed
                ),
                MarmotStatus::InvalidArgument
            );
            assert!(!changed);
            let mut out = std::ptr::dangling_mut();
            assert_eq!(
                marmot_attachment_transfer_snapshot(
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null(),
                    65,
                    &raw mut out
                ),
                MarmotStatus::InvalidArgument
            );
            assert!(out.is_null());
            let snapshot = MarmotAttachmentTransferSnapshot::from(AttachmentTransferSnapshotFfi {
                items: vec![AttachmentTransferStatusFfi {
                    reference: Some("opaque".into()),
                    state: AttachmentTransferStateFfi::Downloading,
                    attempt: 2,
                    received: 9,
                    total: Some(10),
                    retry_at: None,
                }],
            });
            let item = &*snapshot.items;
            assert_eq!(item.received, 9);
            assert!(item.has_total);
            assert!(!item.has_retry_at);
            marmot_attachment_transfer_snapshot_free(boxed(snapshot));
            marmot_attachment_transfer_snapshot_free(std::ptr::null_mut());
        }
        #[cfg(feature = "alloc-audit")]
        assert_eq!(before, audit::live_allocations());
    }
}
