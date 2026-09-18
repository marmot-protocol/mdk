use super::*;
use crate::attachment_access::MarmotAttachmentLocalTarget;
use crate::attachment_controls::{MarmotAttachmentTransferSnapshot, read_targets};
/// Close/free before freeing its client. Never free during an active call.
pub struct MarmotAttachmentTransferSubscription {
    core: SubscriptionCore,
    inner: Arc<marmot_uniffi::AttachmentTransferSubscription>,
}
/// Open a bounded progress stream. First next returns the initial snapshot.
/// # Safety
/// Inputs must be live, targets NULL only with zero length, out writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_subscribe_attachment_transfers(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    targets: *const MarmotAttachmentLocalTarget,
    targets_len: usize,
    out: *mut *mut MarmotAttachmentTransferSubscription,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let targets = try_arg!(unsafe { read_targets(targets, targets_len) });
        let client = try_arg!(unsafe { client_ref(client) });
        let account = try_arg!(unsafe { required_str(account_ref) });
        let group = try_arg!(unsafe { required_str(group_id_hex) });
        match client.block_on(
            client
                .marmot
                .subscribe_attachment_transfers(account, group, targets),
        ) {
            Ok(inner) => unsafe {
                write_handle(
                    MarmotAttachmentTransferSubscription {
                        core: SubscriptionCore::new(client.runtime.handle().clone()),
                        inner,
                    },
                    out,
                )
            },
            Err(e) => status_from_error(&e),
        }
    })
}
/// Initial snapshot then replacements, at most four per second. Zero timeout waits indefinitely.
/// Timeout does not consume updates. Free results with marmot_attachment_transfer_snapshot_free.
/// # Safety
/// Sub must be live and out writable. Use one receiver per handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_attachment_transfer_subscription_next(
    sub: *const MarmotAttachmentTransferSubscription,
    timeout_ms: u32,
    out: *mut *mut MarmotAttachmentTransferSnapshot,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let sub = try_arg!(unsafe { sub_ref(sub) });
        let result = match sub
            .core
            .block_next(timeout_ms, async { Some(sub.inner.next().await) })
        {
            Ok(Some(Ok(item))) => Ok(item),
            Ok(Some(Err(e))) => Err(status_from_error(&e)),
            Ok(None) => Ok(None),
            Err(s) => Err(s),
        };
        unsafe { deliver_next(result, out) }
    })
}
/// Close observation and wake receivers. Does not cancel downloads.
/// # Safety
/// Sub must remain live throughout the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_attachment_transfer_subscription_cancel(
    sub: *const MarmotAttachmentTransferSubscription,
) -> MarmotStatus {
    ffi_guard(|| {
        let sub = try_arg!(unsafe { sub_ref(sub) });
        sub.inner.cancel();
        MarmotStatus::Ok
    })
}
/// NULL-safe free. Already returned snapshots remain separately owned.
/// # Safety
/// Sub must be NULL or library-owned with no active calls.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_attachment_transfer_subscription_free(
    sub: *mut MarmotAttachmentTransferSubscription,
) {
    crate::memory::free_guard(|| unsafe { free_plain(sub) });
}
