use super::*;
use crate::attachment_management::{MarmotAttachmentJobQuery, MarmotAttachmentManagementSnapshot};
/// Close/free before freeing its client. Never free during an active call.
pub struct MarmotAttachmentManagementSubscription {
    core: SubscriptionCore,
    inner: Arc<marmot_uniffi::AttachmentManagementSubscription>,
}
/// Open a bounded progress stream. First next returns the initial snapshot.
/// # Safety
/// Inputs must be live, query live and borrowed, out writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_subscribe_attachment_management(
    client: *const MarmotClient,
    account_ref: *const c_char,
    query: *const MarmotAttachmentJobQuery,
    out: *mut *mut MarmotAttachmentManagementSubscription,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let Some(query) = (unsafe { query.as_ref() }) else {
            return MarmotStatus::NullPointer;
        };
        let query = try_arg!(unsafe { query.to_ffi() });
        let client = try_arg!(unsafe { client_ref(client) });
        let account = try_arg!(unsafe { required_str(account_ref) });
        match client.block_on(
            client
                .marmot
                .subscribe_attachment_management(account, query),
        ) {
            Ok(inner) => unsafe {
                write_handle(
                    MarmotAttachmentManagementSubscription {
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
/// Timeout does not consume updates. Free results with marmot_attachment_management_snapshot_free.
/// # Safety
/// Sub must be live and out writable. Use one receiver per handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_attachment_management_subscription_next(
    sub: *const MarmotAttachmentManagementSubscription,
    timeout_ms: u32,
    out: *mut *mut MarmotAttachmentManagementSnapshot,
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
pub unsafe extern "C" fn marmot_attachment_management_subscription_cancel(
    sub: *const MarmotAttachmentManagementSubscription,
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
pub unsafe extern "C" fn marmot_attachment_management_subscription_free(
    sub: *mut MarmotAttachmentManagementSubscription,
) {
    crate::memory::free_guard(|| unsafe {
        if let Some(s) = sub.as_ref() {
            s.inner.cancel();
        }
        free_plain(sub)
    });
}
