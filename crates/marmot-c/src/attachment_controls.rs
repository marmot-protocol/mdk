//! Attachment controls and source-bound transfer snapshots. Calls block: use off the UI thread.
use crate::attachment_access::MarmotAttachmentLocalTarget;
use crate::commands::{
    deliver, deliver_opt_string, deliver_scalar, deliver_string, deliver_unit, try_arg,
};
use crate::macros::{c_enum, c_mirror};
use crate::memory::required_str;
use crate::{MarmotClient, MarmotStatus, client_ref, ffi_guard, preflight_out, preflight_out_ptr};
use marmot_uniffi::conversions::*;
use std::ffi::c_char;
c_enum! {MarmotAttachmentAcquisitionMode from AttachmentAcquisitionModeFfi {NativeAutomatic,HostManaged,}}
impl From<MarmotAttachmentAcquisitionMode> for AttachmentAcquisitionModeFfi {
    fn from(mode: MarmotAttachmentAcquisitionMode) -> Self {
        match mode {
            MarmotAttachmentAcquisitionMode::NativeAutomatic => Self::NativeAutomatic,
            MarmotAttachmentAcquisitionMode::HostManaged => Self::HostManaged,
        }
    }
}
c_enum! {MarmotAttachmentControl from AttachmentControlFfi {Cancel,Retry,Remove,}}
c_enum! {MarmotAttachmentTransferState from AttachmentTransferStateFfi {Unavailable,NotRequested,Queued,Downloading,VerifyingCiphertext,Decrypting,VerifyingPlaintext,Ready,RetryScheduled,Failed,Cancelled,Paused,Removed,PolicyBlocked,PreviouslyAcquiredUnavailable,CompletedUnretained,RetryExhausted,}}
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
    #[test]
    fn automatic_attachment_c_preflights_outputs_and_deep_frees_status() {
        let _guard = audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let before = audit::live_allocations();
        unsafe {
            assert_eq!(
                marmot_request_automatic_attachment(
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null_mut()
                ),
                MarmotStatus::NullPointer
            );
            let mut applied = true;
            assert_eq!(
                marmot_set_attachment_automatic_permission(
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null(),
                    &mut applied
                ),
                MarmotStatus::NullPointer
            );
            assert!(!applied);
            let result = MarmotAutomaticAttachmentRequest::from(AutomaticAttachmentRequestFfi {
                newly_queued: false,
                status: AttachmentTransferStatusFfi {
                    reference: Some("opaque reference".to_owned()),
                    state: AttachmentTransferStateFfi::PreviouslyAcquiredUnavailable,
                    attempt: 1,
                    received: 0,
                    total: None,
                    retry_at: None,
                },
            });
            assert_eq!(
                result.status.state as u32,
                MarmotAttachmentTransferState::PreviouslyAcquiredUnavailable as u32
            );
            marmot_automatic_attachment_request_free(boxed(result));
            marmot_automatic_attachment_request_free(std::ptr::null_mut());
        }
        #[cfg(feature = "alloc-audit")]
        assert_eq!(audit::live_allocations(), before);
    }
}

c_mirror! {MarmotAutomaticAttachmentRequest from AutomaticAttachmentRequestFfi, free marmot_automatic_attachment_request_free {
 rec status: MarmotAttachmentTransferStatus,
 copy newly_queued: bool,
}}
/// Borrowed runtime permission. All fields are boolean integers (nonzero = true).
#[repr(C)]
pub struct MarmotAttachmentAutomaticPermissionInput {
    pub images: u8,
    pub videos: u8,
    pub audio: u8,
    pub files: u8,
}
/// Revoke automatic permission and return a single-use generation.
/// # Safety
/// Client and account must be live, out writable. Free with marmot_string_free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_begin_attachment_permission_update(
    client: *const MarmotClient,
    account_ref: *const c_char,
    out: *mut *mut c_char,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let client = try_arg!(unsafe { client_ref(client) });
        let account = try_arg!(unsafe { required_str(account_ref) });
        unsafe {
            deliver_string(
                client.block_on(client.marmot.begin_attachment_permission_update(account)),
                out,
            )
        }
    })
}
/// Apply permission only for the current unused generation.
/// # Safety
/// Inputs must be live and permission nonnull, out writable. Inputs are borrowed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_set_attachment_automatic_permission(
    client: *const MarmotClient,
    account_ref: *const c_char,
    generation: *const c_char,
    permission: *const MarmotAttachmentAutomaticPermissionInput,
    out: *mut bool,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out(out) });
        let client = try_arg!(unsafe { client_ref(client) });
        let account = try_arg!(unsafe { required_str(account_ref) });
        let generation = try_arg!(unsafe { required_str(generation) });
        let Some(p) = (unsafe { permission.as_ref() }) else {
            return MarmotStatus::NullPointer;
        };
        let permission = AttachmentAutomaticPermissionFfi {
            images: p.images != 0,
            videos: p.videos != 0,
            audio: p.audio != 0,
            files: p.files != 0,
        };
        unsafe {
            deliver_scalar(
                client.block_on(
                    client
                        .marmot
                        .set_attachment_automatic_permission(account, generation, permission),
                ),
                out,
            )
        }
    })
}
/// Idempotent automatic demand, preserving suppression, history and retry budget.
/// # Safety
/// Inputs must be live, target nonnull, out writable. Free the returned record.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_request_automatic_attachment(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    target: *const MarmotAttachmentLocalTarget,
    out: *mut *mut MarmotAutomaticAttachmentRequest,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let target = try_arg!(unsafe { read_targets(target, 1) }).remove(0);
        let client = try_arg!(unsafe { client_ref(client) });
        let account = try_arg!(unsafe { required_str(account_ref) });
        let group = try_arg!(unsafe { required_str(group_id_hex) });
        unsafe {
            deliver(
                client.block_on(
                    client
                        .marmot
                        .request_automatic_attachment(account, group, target),
                ),
                out,
            )
        }
    })
}
