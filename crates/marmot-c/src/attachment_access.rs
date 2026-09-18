//! Local verified attachment access. Blocking calls must run off the host UI thread.
use crate::commands::{deliver, try_arg};
use crate::macros::c_mirror;
use crate::memory::required_str;
use crate::{MarmotClient, MarmotStatus, client_ref, ffi_guard, preflight_out_ptr};
use marmot_uniffi::conversions::*;
use std::ffi::c_char;

/// Borrowed original source slot from a timeline/history entry. Strings must be
/// NUL-terminated; caller retains ownership throughout the call.
#[repr(C)]
pub struct MarmotAttachmentLocalTarget {
    pub message_id_hex: *const c_char,
    pub source_message_id_hex: *const c_char,
    pub attachment_index: u32,
}
c_mirror! {
    /// NULL reference means unavailable, with byte_count zero. A non-NULL reference
    /// with byte_count zero is a verified empty file. References are opaque.
    MarmotAttachmentLocalAsset from AttachmentLocalAssetFfi,
    list(MarmotAttachmentLocalAssetList, marmot_attachment_local_asset_list_free) {
        opt_str reference,
        copy byte_count: u64,
    }
}
c_mirror! {
    /// available=false means discard any assembled host result. Available with
    /// zero bytes is EOF. Hosts own decoding and plaintext buffer lifetime.
    MarmotAttachmentLocalBytes from AttachmentLocalBytesFfi,
    free marmot_attachment_local_bytes_free {
        copy available: bool,
        bytes bytes/bytes_len,
    }
}
/// Look up up to 64 original slots in one group, preserving input order/duplicates.
/// Does not load bytes, enqueue demand, start a worker or perform network work.
/// # Safety
/// Client/strings and targets[0..targets_len] must be live. Targets may be NULL only
/// with zero length. Out must be writable. Inputs are borrowed, outputs owned.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_attachment_local_assets(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    targets: *const MarmotAttachmentLocalTarget,
    targets_len: usize,
    out: *mut *mut MarmotAttachmentLocalAssetList,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        if targets_len > 64 {
            return MarmotStatus::InvalidArgument;
        }
        let targets = if targets_len == 0 {
            &[]
        } else {
            if targets.is_null() {
                return MarmotStatus::NullPointer;
            }
            unsafe { std::slice::from_raw_parts(targets, targets_len) }
        };
        let client = try_arg!(unsafe { client_ref(client) });
        let account = try_arg!(unsafe { required_str(account_ref) });
        let group = try_arg!(unsafe { required_str(group_id_hex) });
        let mut input = Vec::with_capacity(targets_len);
        for target in targets {
            input.push(AttachmentLocalTargetFfi {
                message_id_hex: try_arg!(unsafe { required_str(target.message_id_hex) }),
                source_message_id_hex: try_arg!(unsafe {
                    required_str(target.source_message_id_hex)
                }),
                attachment_index: target.attachment_index,
            });
        }
        unsafe {
            deliver(
                client.block_on(client.marmot.attachment_local_assets(account, group, input)),
                out,
            )
        }
    })
}
/// Read a bounded range (1..=1048576 bytes) from a local reference. No network fallback.
/// Rechecks source visibility/expiry on every call. Offset at/beyond EOF returns
/// available=true and empty bytes. An obsolete or wrong-account reference is unavailable.
/// # Safety
/// Client and NUL-terminated strings must be live; out must be writable. Borrowed inputs.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_read_attachment_asset(
    client: *const MarmotClient,
    account_ref: *const c_char,
    reference: *const c_char,
    offset: u64,
    limit: u32,
    out: *mut *mut MarmotAttachmentLocalBytes,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let client = try_arg!(unsafe { client_ref(client) });
        let account = try_arg!(unsafe { required_str(account_ref) });
        let reference = try_arg!(unsafe { required_str(reference) });
        unsafe {
            deliver(
                client.block_on(
                    client
                        .marmot
                        .read_attachment_asset(account, reference, offset, limit),
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
    use std::ptr;
    #[test]
    fn attachment_local_c_preflight_bounds_and_deep_free() {
        let _guard = audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let before = audit::live_allocations();
        unsafe {
            let mut out = ptr::dangling_mut();
            assert_eq!(
                marmot_attachment_local_assets(
                    ptr::null(),
                    ptr::null(),
                    ptr::null(),
                    ptr::null(),
                    65,
                    &mut out
                ),
                MarmotStatus::InvalidArgument
            );
            assert!(out.is_null());
            assert_eq!(
                marmot_attachment_local_assets(
                    ptr::null(),
                    ptr::null(),
                    ptr::null(),
                    ptr::null(),
                    1,
                    &mut out
                ),
                MarmotStatus::NullPointer
            );
            assert!(out.is_null());
            assert_eq!(
                marmot_read_attachment_asset(
                    ptr::null(),
                    ptr::null(),
                    ptr::null(),
                    0,
                    1,
                    ptr::null_mut()
                ),
                MarmotStatus::NullPointer
            );
            let mut bytes_out = ptr::dangling_mut();
            assert_eq!(
                marmot_read_attachment_asset(
                    ptr::null(),
                    ptr::null(),
                    ptr::null(),
                    0,
                    1,
                    &mut bytes_out
                ),
                MarmotStatus::NullPointer
            );
            assert!(bytes_out.is_null());
            let list: MarmotAttachmentLocalAssetList = vec![
                AttachmentLocalAssetFfi {
                    reference: Some("opaque".into()),
                    byte_count: 0,
                },
                AttachmentLocalAssetFfi {
                    reference: None,
                    byte_count: 0,
                },
            ]
            .into();
            assert!(!(*list.items).reference.is_null());
            assert!((*list.items.add(1)).reference.is_null());
            marmot_attachment_local_asset_list_free(boxed(list));
            let bytes: MarmotAttachmentLocalBytes = AttachmentLocalBytesFfi {
                available: true,
                bytes: vec![0, 255, 0, 42],
            }
            .into();
            assert!(bytes.available);
            assert_eq!(
                std::slice::from_raw_parts(bytes.bytes, bytes.bytes_len),
                &[0, 255, 0, 42]
            );
            marmot_attachment_local_bytes_free(boxed(bytes));
            marmot_attachment_local_asset_list_free(ptr::null_mut());
            marmot_attachment_local_bytes_free(ptr::null_mut());
        }
        #[cfg(feature = "alloc-audit")]
        assert_eq!(before, audit::live_allocations());
    }
}
