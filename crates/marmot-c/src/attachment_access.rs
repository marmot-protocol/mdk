//! Local verified attachment access. Blocking calls must run off the host UI thread.
use crate::commands::{deliver, deliver_opt, deliver_unit, try_arg};
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
c_mirror! {
    /// A plaintext copy of a retained attachment lent to the host. Pass path
    /// to the OS surface that needs a file, then release lease when it is done.
    MarmotAttachmentHandoff from AttachmentHandoffFfi,
    free marmot_attachment_handoff_free {
        str lease,
        str path,
        copy byte_count: u64,
        str media_type,
        str file_name,
    }
}
/// Write a plaintext copy of one retained attachment for an OS surface that
/// needs a real file, lent under a lease. Writes NULL with MARMOT_STATUS_OK when
/// the attachment is not held locally. MARMOT_STATUS_STORAGE_FULL when the disk
/// cannot hold the copy beyond the reserve. The control reports copied bytes and
/// cancels. Free the record with marmot_attachment_handoff_free; that does not
/// release the lease. Blocking for the whole copy: call off the UI thread.
/// Cancel the copy with marmot_media_file_transfer_control_cancel from
/// another thread; a cancelled copy leaves no file and no lease.
/// # Safety
/// Client, control and strings must be live; target must point to a valid
/// target whose strings stay valid until return; out must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_open_attachment_handoff(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    target: *const MarmotAttachmentLocalTarget,
    control: *const crate::file_media::MarmotMediaFileTransferControl,
    out: *mut *mut MarmotAttachmentHandoff,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let client = try_arg!(unsafe { client_ref(client) });
        let account = try_arg!(unsafe { required_str(account_ref) });
        let group = try_arg!(unsafe { required_str(group_id_hex) });
        let Some(target) = (unsafe { target.as_ref() }) else {
            crate::status::set_last_error("attachment target was NULL");
            return MarmotStatus::NullPointer;
        };
        let target = AttachmentLocalTargetFfi {
            message_id_hex: try_arg!(unsafe { required_str(target.message_id_hex) }),
            source_message_id_hex: try_arg!(unsafe { required_str(target.source_message_id_hex) }),
            attachment_index: target.attachment_index,
        };
        let Some(control) = (unsafe { control.as_ref() }) else {
            crate::status::set_last_error("transfer control was NULL");
            return MarmotStatus::NullPointer;
        };
        unsafe {
            deliver_opt(
                client.block_on(client.marmot.open_attachment_handoff(
                    account,
                    group,
                    target,
                    control.inner.clone(),
                )),
                out,
            )
        }
    })
}
/// Delete a handoff copy once the OS surface is done with it. An unknown or
/// already released lease returns MARMOT_STATUS_OK; a malformed lease returns
/// MARMOT_STATUS_INVALID_MEDIA_REFERENCE. A copy that cannot be deleted
/// returns MARMOT_STATUS_IO and stays leased, so the call can be retried.
/// Blocking: call off the UI thread.
/// # Safety
/// Client and lease must be live NUL-terminated inputs.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_release_attachment_handoff(
    client: *const MarmotClient,
    lease: *const c_char,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let lease = try_arg!(unsafe { required_str(lease) });
        deliver_unit(client.block_on(client.marmot.release_attachment_handoff(lease)))
    })
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
        if targets_len > marmot_uniffi::MAX_ATTACHMENT_ASSET_LOOKUPS {
            crate::status::set_last_error("too many attachment asset lookups");
            return MarmotStatus::InvalidArgument;
        }
        let targets = if targets_len == 0 {
            &[]
        } else {
            if targets.is_null() {
                crate::status::set_last_error("attachment targets were NULL with nonzero length");
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
#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::marmot_read_attachment_asset;
    use crate::memory::{audit, boxed};
    use marmot_uniffi::MarmotKitError;
    use std::ptr;
    /// With a real client: NULL inputs are refused before any work, an
    /// unknown account is an error rather than a lease, and release is
    /// idempotent for unknown leases but rejects malformed ones.
    #[test]
    fn attachment_handoff_c_forwards_and_validates_with_a_client() {
        let _guard = audit::test_lock();
        // No platform keystore on CI runners.
        keyring_core::set_default_store(keyring_core::mock::Store::new().unwrap());
        let home = tempfile::tempdir().unwrap();
        let root = std::ffi::CString::new(home.path().to_str().unwrap()).unwrap();
        let relay = c"wss://relay.example";
        let relays = [relay.as_ptr()];
        unsafe {
            let mut client = ptr::null_mut();
            assert_eq!(
                crate::marmot_client_new(root.as_ptr(), relays.as_ptr(), 1, &mut client),
                MarmotStatus::Ok
            );
            let message = std::ffi::CString::new("aa".repeat(32)).unwrap();
            let source = std::ffi::CString::new("bb".repeat(32)).unwrap();
            let group = std::ffi::CString::new("ab".repeat(16)).unwrap();
            let target = MarmotAttachmentLocalTarget {
                message_id_hex: message.as_ptr(),
                source_message_id_hex: source.as_ptr(),
                attachment_index: 0,
            };
            let mut control = ptr::null_mut();
            assert_eq!(
                crate::file_media::marmot_media_file_transfer_control_new(&mut control),
                MarmotStatus::Ok
            );
            let mut out = ptr::dangling_mut();
            assert_eq!(
                marmot_open_attachment_handoff(
                    client,
                    c"alice".as_ptr(),
                    group.as_ptr(),
                    ptr::null(),
                    control,
                    &mut out
                ),
                MarmotStatus::NullPointer
            );
            assert!(out.is_null());
            assert_eq!(
                marmot_open_attachment_handoff(
                    client,
                    c"alice".as_ptr(),
                    group.as_ptr(),
                    &target,
                    ptr::null(),
                    &mut out
                ),
                MarmotStatus::NullPointer
            );
            assert_eq!(
                marmot_open_attachment_handoff(
                    client,
                    c"alice".as_ptr(),
                    group.as_ptr(),
                    &target,
                    control,
                    ptr::null_mut()
                ),
                MarmotStatus::NullPointer
            );
            let status = marmot_open_attachment_handoff(
                client,
                c"absent-account".as_ptr(),
                group.as_ptr(),
                &target,
                control,
                &mut out,
            );
            assert_ne!(status, MarmotStatus::Ok, "no account, no lease");
            assert!(out.is_null());
            let unknown = std::ffi::CString::new("cd".repeat(16)).unwrap();
            assert_eq!(
                marmot_release_attachment_handoff(client, unknown.as_ptr()),
                MarmotStatus::Ok
            );
            assert_eq!(
                marmot_release_attachment_handoff(client, unknown.as_ptr()),
                MarmotStatus::Ok,
                "release is idempotent"
            );
            assert_eq!(
                marmot_release_attachment_handoff(client, c"not-a-lease".as_ptr()),
                MarmotStatus::InvalidMediaReference
            );
            crate::file_media::marmot_media_file_transfer_control_free(control);
            assert_eq!(crate::marmot_client_shutdown(client), MarmotStatus::Ok);
            crate::marmot_client_free(client);
        }
    }

    /// The two failures a handoff can report besides bad input reach C as
    /// distinct statuses: a full disk (retry once space frees) and a failed
    /// deletion (retry the release), never the malformed-lease status.
    #[test]
    fn handoff_failures_map_to_distinct_c_statuses() {
        // The runtime reports a full disk as StorageFull and a failed
        // deletion as Io (marmot-uniffi tests the AppError mapping).
        let status = |error: MarmotKitError| crate::status::status_from_error(&error);
        assert_eq!(
            status(MarmotKitError::StorageFull {
                details: "d".into()
            }),
            MarmotStatus::StorageFull
        );
        assert_eq!(
            status(MarmotKitError::Io {
                details: "d".into()
            }),
            MarmotStatus::Io
        );
        assert_eq!(
            status(MarmotKitError::InvalidMediaReference {
                details: "d".into()
            }),
            MarmotStatus::InvalidMediaReference
        );
    }

    #[test]
    fn attachment_local_c_preflight_bounds_and_deep_free() {
        let _guard = audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let before = audit::live_allocations();
        unsafe {
            crate::status::set_last_error("earlier unrelated failure");
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
                crate::status::take_last_error().as_deref(),
                Some("too many attachment asset lookups")
            );
            crate::status::set_last_error("earlier unrelated failure");
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
                crate::status::take_last_error().as_deref(),
                Some("attachment targets were NULL with nonzero length")
            );
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
            let mut handoff_out = ptr::dangling_mut();
            assert_eq!(
                marmot_open_attachment_handoff(
                    ptr::null(),
                    ptr::null(),
                    ptr::null(),
                    ptr::null(),
                    ptr::null(),
                    &mut handoff_out
                ),
                MarmotStatus::NullPointer
            );
            assert!(handoff_out.is_null());
            assert_eq!(
                marmot_release_attachment_handoff(ptr::null(), ptr::null()),
                MarmotStatus::NullPointer
            );
            let handoff: MarmotAttachmentHandoff = AttachmentHandoffFfi {
                lease: "ab".repeat(16),
                path: "/private/handoff/file.apk".into(),
                byte_count: 9,
                media_type: "application/vnd.android.package-archive".into(),
                file_name: "file.apk".into(),
            }
            .into();
            assert_eq!(handoff.byte_count, 9);
            assert!(!handoff.path.is_null());
            marmot_attachment_handoff_free(boxed(handoff));
            marmot_attachment_handoff_free(ptr::null_mut());
        }
        #[cfg(feature = "alloc-audit")]
        assert_eq!(before, audit::live_allocations());
    }
}
