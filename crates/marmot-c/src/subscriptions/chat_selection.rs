//! Blocking C commands over the existing complete-selection owner.
use super::*;
use crate::commands::{deliver_opt, deliver_scalar};
use crate::memory::str_array;
use crate::preflight_out;
use crate::types::account::MarmotSendSummary;
use crate::types::chat_selection::*;
use crate::types::group::MarmotGroupMutationResult;

/// One selection owner. Free before its client, with no calls in progress.
/// The client runtime and the selected account store must remain live.
pub struct MarmotChatSelection {
    runtime: Handle,
    inner: Arc<marmot_uniffi::ChatSelection>,
}

/// Open a complete selection. A successful unresolved status is not an empty set.
/// # Safety
/// All input pointers must be readable; out must be writable. Inputs are borrowed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_open_chat_selection(
    client: *const MarmotClient,
    account_ref: *const c_char,
    open: *const MarmotChatSelectionOpenInput,
    out: *mut *mut MarmotChatSelection,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        let open = try_arg!(unsafe { sub_ref(open) });
        let open = try_arg!(unsafe { open.to_ffi() });
        match client.block_on(client.marmot.open_chat_selection(account_ref, open)) {
            Ok(inner) => {
                unsafe {
                    out.write(boxed(MarmotChatSelection {
                        runtime: client.runtime.handle().clone(),
                        inner,
                    }))
                };
                MarmotStatus::Ok
            }
            Err(error) => status_from_error(&error),
        }
    })
}

unsafe fn visible_ids(ids: *const *const c_char, len: usize) -> Result<Vec<String>, MarmotStatus> {
    if len > 200 {
        set_last_error("chat selection visible-ID input exceeds 200");
        return Err(MarmotStatus::ChatSelectionInvalidSlots);
    }
    unsafe { str_array(ids, len) }
}

/// Return count/hints as optional values, never treating unresolved as zero or false.
/// # Safety
/// selection must remain live; borrowed inputs readable and out writable throughout the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_chat_selection_status(
    selection: *const MarmotChatSelection,
    out: *mut *mut MarmotChatSelectionStatus,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let selection = try_arg!(unsafe { sub_ref(selection) });
        let result = block_on_handle(&selection.runtime, selection.inner.status());
        unsafe { deliver(result, out) }
    })
}

/// Read or update the same selection owner; revision and uncertainty gates remain native.
/// # Safety
/// selection must remain live; borrowed inputs readable and out writable throughout the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_chat_selection_count(
    selection: *const MarmotChatSelection,
    out: *mut *mut MarmotChatSelectionSummary,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let selection = try_arg!(unsafe { sub_ref(selection) });
        let result = block_on_handle(&selection.runtime, selection.inner.count());
        unsafe { deliver(result, out) }
    })
}

/// Display-only page; this is not mutation or folder-assignment authority.
/// # Safety
/// selection must remain live; borrowed inputs readable and out writable throughout the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_chat_selection_page(
    selection: *const MarmotChatSelection,
    revision: u64,
    offset: u64,
    limit: u32,
    out: *mut *mut MarmotChatSelectionPage,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let selection = try_arg!(unsafe { sub_ref(selection) });
        let result = block_on_handle(
            &selection.runtime,
            selection.inner.page(revision, offset, limit),
        );
        unsafe { deliver(result, out) }
    })
}

/// Fresh folder handoff. Discard prior pages when the returned revision changes; use done, not empty-page termination.
/// # Safety
/// selection must remain live; borrowed inputs readable and out writable throughout the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_chat_selection_folder_assignment_page(
    selection: *const MarmotChatSelection,
    revision: u64,
    context: *const MarmotChatSelectionContextInput,
    after: *const c_char,
    limit: u32,
    out: *mut *mut MarmotChatSelectionFolderPage,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let selection = try_arg!(unsafe { sub_ref(selection) });
        let context = try_arg!(unsafe { sub_ref(context) });
        let context = try_arg!(unsafe { context.to_ffi() });
        let after = try_arg!(unsafe { optional_str(after) });
        let result = block_on_handle(
            &selection.runtime,
            selection
                .inner
                .folder_assignment_page(revision, context, after, limit),
        );
        unsafe { deliver(result, out) }
    })
}

/// Read or update the same selection owner; revision and uncertainty gates remain native.
/// # Safety
/// selection must remain live; borrowed inputs readable and out writable throughout the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_chat_selection_membership(
    selection: *const MarmotChatSelection,
    revision: u64,
    group_ids: *const *const c_char,
    group_ids_len: usize,
    out: *mut *mut MarmotChatSelectionMembership,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let selection = try_arg!(unsafe { sub_ref(selection) });
        let group_ids = try_arg!(unsafe { visible_ids(group_ids, group_ids_len) });
        let result = block_on_handle(
            &selection.runtime,
            selection.inner.membership(revision, group_ids),
        );
        unsafe { deliver(result, out) }
    })
}

/// Read or update the same selection owner; revision and uncertainty gates remain native.
/// # Safety
/// selection must remain live; borrowed inputs readable and out writable throughout the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_chat_selection_exclude(
    selection: *const MarmotChatSelection,
    revision: u64,
    group_ids: *const *const c_char,
    group_ids_len: usize,
    out: *mut *mut MarmotChatSelectionStatus,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let selection = try_arg!(unsafe { sub_ref(selection) });
        let group_ids = try_arg!(unsafe { visible_ids(group_ids, group_ids_len) });
        let result = block_on_handle(
            &selection.runtime,
            selection.inner.exclude(revision, group_ids),
        );
        unsafe { deliver(result, out) }
    })
}

/// Restore only explicitly unchecked original IDs before any operation has begun; never reopen a scope to retick.
/// # Safety
/// selection must remain live; borrowed inputs readable and out writable throughout the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_chat_selection_reselect(
    selection: *const MarmotChatSelection,
    revision: u64,
    context: *const MarmotChatSelectionContextInput,
    group_ids: *const *const c_char,
    group_ids_len: usize,
    out: *mut *mut MarmotChatSelectionStatus,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let selection = try_arg!(unsafe { sub_ref(selection) });
        let context = try_arg!(unsafe { sub_ref(context) });
        let context = try_arg!(unsafe { context.to_ffi() });
        let group_ids = try_arg!(unsafe { visible_ids(group_ids, group_ids_len) });
        let result = block_on_handle(
            &selection.runtime,
            selection.inner.reselect(revision, context, group_ids),
        );
        unsafe { deliver(result, out) }
    })
}

/// Read or update the same selection owner; revision and uncertainty gates remain native.
/// # Safety
/// selection must remain live; borrowed inputs readable and out writable throughout the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_chat_selection_presentation_page(
    selection: *const MarmotChatSelection,
    revision: u64,
    offset: u64,
    limit: u32,
    out: *mut *mut MarmotChatSelectionOperandList,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let selection = try_arg!(unsafe { sub_ref(selection) });
        let result = block_on_handle(
            &selection.runtime,
            selection.inner.presentation_page(revision, offset, limit),
        );
        unsafe { deliver(result, out) }
    })
}

/// Read or update the same selection owner; revision and uncertainty gates remain native.
/// # Safety
/// selection must remain live; borrowed inputs readable and out writable throughout the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_chat_selection_submit_presentation(
    selection: *const MarmotChatSelection,
    revision: u64,
    host: *const MarmotChatSelectionHostContextInput,
    answers: *const MarmotChatSelectionAnswerInput,
    answers_len: usize,
    out: *mut *mut MarmotChatSelectionStatus,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let selection = try_arg!(unsafe { sub_ref(selection) });
        let host = try_arg!(unsafe { sub_ref(host) });
        let host = try_arg!(unsafe { host.to_ffi() });
        let answers = try_arg!(unsafe { read_answers(answers, answers_len) });
        let result = block_on_handle(
            &selection.runtime,
            selection.inner.submit_presentation(revision, host, answers),
        );
        unsafe { deliver(result, out) }
    })
}

/// Read or update the same selection owner; revision and uncertainty gates remain native.
/// # Safety
/// selection must remain live; borrowed inputs readable and out writable throughout the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_chat_selection_resolve_presentation(
    selection: *const MarmotChatSelection,
    revision: u64,
    out: *mut *mut MarmotChatSelectionSummary,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let selection = try_arg!(unsafe { sub_ref(selection) });
        let result = block_on_handle(
            &selection.runtime,
            selection.inner.resolve_presentation(revision),
        );
        unsafe { deliver(result, out) }
    })
}

/// Read or update the same selection owner; revision and uncertainty gates remain native.
/// # Safety
/// selection must remain live; borrowed inputs readable and out writable throughout the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_chat_selection_prepare_action_hints(
    selection: *const MarmotChatSelection,
    revision: u64,
    context: *const MarmotChatSelectionContextInput,
    out: *mut *mut MarmotChatSelectionStatus,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let selection = try_arg!(unsafe { sub_ref(selection) });
        let context = try_arg!(unsafe { sub_ref(context) });
        let context = try_arg!(unsafe { context.to_ffi() });
        let result = block_on_handle(
            &selection.runtime,
            selection.inner.prepare_action_hints(revision, context),
        );
        unsafe { deliver(result, out) }
    })
}

/// Read or update the same selection owner; revision and uncertainty gates remain native.
/// # Safety
/// selection must remain live; borrowed inputs readable and out writable throughout the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_chat_selection_refresh_scope(
    selection: *const MarmotChatSelection,
    revision: u64,
    context: *const MarmotChatSelectionContextInput,
    out: *mut *mut MarmotChatSelectionStatus,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let selection = try_arg!(unsafe { sub_ref(selection) });
        let context = try_arg!(unsafe { sub_ref(context) });
        let context = try_arg!(unsafe { context.to_ffi() });
        let result = block_on_handle(
            &selection.runtime,
            selection.inner.refresh_scope(revision, context),
        );
        unsafe { deliver(result, out) }
    })
}

/// Apply archive/local-delete with retained operation/attempt readback. Unknown effects must not be retried as a fresh operation.
/// # Safety
/// selection must remain live; borrowed inputs readable and out writable throughout the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_chat_selection_apply(
    selection: *const MarmotChatSelection,
    operation_id: u64,
    attempt_id: u64,
    revision: u64,
    context: *const MarmotChatSelectionContextInput,
    mutation: *const MarmotChatSelectionMutationInput,
    out: *mut *mut MarmotChatSelectionMutationReport,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let selection = try_arg!(unsafe { sub_ref(selection) });
        let context = try_arg!(unsafe { sub_ref(context) });
        let context = try_arg!(unsafe { context.to_ffi() });
        let mutation = try_arg!(unsafe { sub_ref(mutation) });
        let mutation = try_arg!(unsafe { mutation.to_ffi() });
        let result = block_on_handle(
            &selection.runtime,
            selection
                .inner
                .apply(operation_id, attempt_id, revision, context, mutation),
        );
        unsafe { deliver(result, out) }
    })
}

/// Read retained mutation result; OK with NULL means no result, not failure.
/// # Safety
/// selection must remain live; borrowed inputs readable and out writable throughout the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_chat_selection_last_mutation(
    selection: *const MarmotChatSelection,
    out: *mut *mut MarmotChatSelectionMutationReport,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let selection = try_arg!(unsafe { sub_ref(selection) });
        let result = block_on_handle(&selection.runtime, selection.inner.last_mutation());
        unsafe { deliver_opt(result, out) }
    })
}

/// Read retained per-target departure result; OK with NULL means no result.
/// # Safety
/// selection must remain live; borrowed inputs readable and out writable throughout the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_chat_selection_last_departure(
    selection: *const MarmotChatSelection,
    out: *mut *mut MarmotChatSelectionDepartureReport,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let selection = try_arg!(unsafe { sub_ref(selection) });
        let result = block_on_handle(&selection.runtime, selection.inner.last_departure());
        unsafe { deliver_opt(result, out) }
    })
}

unsafe fn read_answers(
    answers: *const MarmotChatSelectionAnswerInput,
    len: usize,
) -> Result<Vec<marmot_uniffi::conversions::ChatSelectionAnswerFfi>, MarmotStatus> {
    if answers.is_null() && len != 0 {
        set_last_error("answer array was NULL with nonzero length");
        return Err(MarmotStatus::NullPointer);
    }
    if len > isize::MAX as usize / std::mem::size_of::<MarmotChatSelectionAnswerInput>() {
        set_last_error("answer array length exceeds addressable memory");
        return Err(MarmotStatus::InvalidArgument);
    }
    let mut result = Vec::new();
    result
        .try_reserve_exact(len)
        .map_err(|_| MarmotStatus::ChatSelectionResourceExhausted)?;
    for index in 0..len {
        result.push(unsafe { (&*answers.add(index)).to_ffi() }?);
    }
    Ok(result)
}

/// Retire this selection owner without freeing the handle. Idempotent.
/// # Safety
/// selection must remain live for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_chat_selection_close(
    selection: *const MarmotChatSelection,
) -> MarmotStatus {
    ffi_guard(|| {
        let selection = try_arg!(unsafe { sub_ref(selection) });
        selection.inner.close_selection();
        MarmotStatus::Ok
    })
}

/// Retire this selection owner without freeing the handle. Idempotent.
/// # Safety
/// selection must remain live for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_chat_selection_cancel(
    selection: *const MarmotChatSelection,
) -> MarmotStatus {
    ffi_guard(|| {
        let selection = try_arg!(unsafe { sub_ref(selection) });
        selection.inner.cancel();
        MarmotStatus::Ok
    })
}

/// Retire and free one selection. NULL is a no-op; returned records remain caller-owned.
/// # Safety
/// selection must be NULL or a library-owned handle with no active calls.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_chat_selection_free(selection: *mut MarmotChatSelection) {
    crate::memory::free_guard(|| {
        if let Some(selection) = unsafe { selection.as_ref() } {
            selection.inner.close_selection();
        }
        unsafe { free_plain(selection) };
    });
}

/// Run the existing guarded per-target departure step on this same selection owner.
/// Retain operation/attempt identity and read back unresolved effects; do not replay them.
/// # Safety
/// client and selection must remain live; input records/strings readable, out writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_selection_promote_admin_detailed(
    client: *const MarmotClient,
    selection: *const MarmotChatSelection,
    account_ref: *const c_char,
    action: *const MarmotChatSelectionActionInput,
    member_ref: *const c_char,
    out: *mut *mut MarmotGroupMutationResult,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let client = try_arg!(unsafe { client_ref(client) });
        let selection = try_arg!(unsafe { sub_ref(selection) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        let action = try_arg!(unsafe { sub_ref(action) });
        let action = try_arg!(unsafe { action.to_ffi() });
        let member_ref = try_arg!(unsafe { required_str(member_ref) });
        let result = client.block_on(client.marmot.selection_promote_admin_detailed(
            Arc::clone(&selection.inner),
            account_ref,
            action,
            member_ref,
        ));
        unsafe { deliver(result, out) }
    })
}

/// Run the existing guarded per-target departure step on this same selection owner.
/// Retain operation/attempt identity and read back unresolved effects; do not replay them.
/// # Safety
/// client and selection must remain live; input records/strings readable, out writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_selection_self_demote_admin_detailed(
    client: *const MarmotClient,
    selection: *const MarmotChatSelection,
    account_ref: *const c_char,
    action: *const MarmotChatSelectionActionInput,
    out: *mut *mut MarmotGroupMutationResult,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let client = try_arg!(unsafe { client_ref(client) });
        let selection = try_arg!(unsafe { sub_ref(selection) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        let action = try_arg!(unsafe { sub_ref(action) });
        let action = try_arg!(unsafe { action.to_ffi() });
        let result = client.block_on(client.marmot.selection_self_demote_admin_detailed(
            Arc::clone(&selection.inner),
            account_ref,
            action,
        ));
        unsafe { deliver(result, out) }
    })
}

/// Run the existing guarded per-target departure step on this same selection owner.
/// Retain operation/attempt identity and read back unresolved effects; do not replay them.
/// # Safety
/// client and selection must remain live; input records/strings readable, out writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_selection_leave_group(
    client: *const MarmotClient,
    selection: *const MarmotChatSelection,
    account_ref: *const c_char,
    action: *const MarmotChatSelectionActionInput,
    out: *mut *mut MarmotSendSummary,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let client = try_arg!(unsafe { client_ref(client) });
        let selection = try_arg!(unsafe { sub_ref(selection) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        let action = try_arg!(unsafe { sub_ref(action) });
        let action = try_arg!(unsafe { action.to_ffi() });
        let result = client.block_on(client.marmot.selection_leave_group(
            Arc::clone(&selection.inner),
            account_ref,
            action,
        ));
        unsafe { deliver(result, out) }
    })
}

/// Run the existing guarded per-target departure step on this same selection owner.
/// Retain operation/attempt identity and read back unresolved effects; do not replay them.
/// # Safety
/// client and selection must remain live; input records/strings readable, out writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_selection_forget_group_local(
    client: *const MarmotClient,
    selection: *const MarmotChatSelection,
    account_ref: *const c_char,
    action: *const MarmotChatSelectionActionInput,
    out: *mut bool,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out(out) });
        let client = try_arg!(unsafe { client_ref(client) });
        let selection = try_arg!(unsafe { sub_ref(selection) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        let action = try_arg!(unsafe { sub_ref(action) });
        let action = try_arg!(unsafe { action.to_ffi() });
        let result = client.block_on(client.marmot.selection_forget_group_local(
            Arc::clone(&selection.inner),
            account_ref,
            action,
        ));
        unsafe { deliver_scalar(result, out) }
    })
}

/// Run the existing guarded per-target departure step on this same selection owner.
/// Retain operation/attempt identity and read back unresolved effects; do not replay them.
/// # Safety
/// client and selection must remain live; input records/strings readable, out writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_selection_delete_group_local(
    client: *const MarmotClient,
    selection: *const MarmotChatSelection,
    account_ref: *const c_char,
    action: *const MarmotChatSelectionActionInput,
    out: *mut bool,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out(out) });
        let client = try_arg!(unsafe { client_ref(client) });
        let selection = try_arg!(unsafe { sub_ref(selection) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        let action = try_arg!(unsafe { sub_ref(action) });
        let action = try_arg!(unsafe { action.to_ffi() });
        let result = client.block_on(client.marmot.selection_delete_group_local(
            Arc::clone(&selection.inner),
            account_ref,
            action,
        ));
        unsafe { deliver_scalar(result, out) }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::{
        marmot_catch_up_accounts, marmot_create_group, marmot_create_identity,
        marmot_presented_chat_list,
    };
    use crate::types::account::marmot_account_summary_free;
    use crate::types::presentation::marmot_presented_chat_list_snapshot_free;
    use crate::{
        MarmotRelayPolicy, marmot_client_free, marmot_client_new_with_options,
        marmot_client_shutdown, marmot_client_start, marmot_string_free,
    };
    use std::ffi::{CStr, CString};
    use std::ptr;

    #[test]
    fn selection_required_output_precedes_invalid_input_and_never_retains_sentinel() {
        unsafe {
            assert_eq!(
                marmot_open_chat_selection(ptr::null(), ptr::null(), ptr::null(), ptr::null_mut()),
                MarmotStatus::NullPointer
            );
            assert_eq!(
                marmot_chat_selection_apply(
                    ptr::null(),
                    1,
                    1,
                    1,
                    ptr::null(),
                    ptr::null(),
                    ptr::null_mut()
                ),
                MarmotStatus::NullPointer
            );
            assert_eq!(
                marmot_selection_leave_group(
                    ptr::null(),
                    ptr::null(),
                    ptr::null(),
                    ptr::null(),
                    ptr::null_mut()
                ),
                MarmotStatus::NullPointer
            );
            assert_eq!(
                marmot_selection_delete_group_local(
                    ptr::null(),
                    ptr::null(),
                    ptr::null(),
                    ptr::null(),
                    ptr::null_mut()
                ),
                MarmotStatus::NullPointer
            );
            let mut out = ptr::dangling_mut();
            assert_eq!(
                marmot_chat_selection_status(ptr::null(), &raw mut out),
                MarmotStatus::NullPointer
            );
            assert!(out.is_null());
            marmot_chat_selection_free(ptr::null_mut());
        }
    }

    #[test]
    fn selection_same_c_owner_excludes_restores_and_preflights_real_archive() {
        let _audit_lock = crate::memory::audit::test_lock();
        keyring_core::set_default_store(keyring_core::mock::Store::new().unwrap());
        let relay_runtime = tokio::runtime::Runtime::new().unwrap();
        let relay = relay_runtime
            .block_on(nostr_relay_builder::MockRelay::run())
            .unwrap();
        let relay_url = CString::new(relay_runtime.block_on(relay.url()).to_string()).unwrap();
        let relays = [relay_url.as_ptr()];
        let home = tempfile::tempdir().unwrap();
        let home_c = CString::new(home.path().to_str().unwrap()).unwrap();
        unsafe {
            let mut client = ptr::null_mut();
            assert_eq!(
                marmot_client_new_with_options(
                    home_c.as_ptr(),
                    relays.as_ptr(),
                    1,
                    MarmotRelayPolicy::AllowLoopback as u32,
                    ptr::null(),
                    crate::deployment::OwnedDeployment::white_noise().as_ptr(),
                    &raw mut client
                ),
                MarmotStatus::Ok
            );
            assert_eq!(marmot_client_start(client), MarmotStatus::Ok);
            let mut account = ptr::null_mut();
            assert_eq!(
                marmot_create_identity(
                    client,
                    relays.as_ptr(),
                    1,
                    relays.as_ptr(),
                    1,
                    ptr::null(),
                    0,
                    &raw mut account
                ),
                MarmotStatus::Ok
            );
            let mut group = ptr::null_mut();
            assert_eq!(
                marmot_create_group(
                    client,
                    (*account).account_id_hex,
                    c"Selection C fixture".as_ptr(),
                    ptr::null(),
                    0,
                    ptr::null(),
                    &raw mut group
                ),
                MarmotStatus::Ok
            );
            assert_eq!(marmot_catch_up_accounts(client), MarmotStatus::Ok);
            // Existing public preparation supplies the same source-owned row contract as the list.
            let mut presented = ptr::null_mut();
            assert_eq!(
                marmot_presented_chat_list(
                    client,
                    (*account).account_id_hex,
                    1,
                    &raw mut presented
                ),
                MarmotStatus::Ok
            );
            marmot_presented_chat_list_snapshot_free(presented);
            assert_eq!(marmot_catch_up_accounts(client), MarmotStatus::Ok);
            // All input records contain only fixed-width integers and raw pointers; zero is a valid inactive field.
            let mut open: MarmotChatSelectionOpenInput = std::mem::zeroed();
            open.base.tag = 1;
            open.scope.direct = 1;
            open.scope.groups = 1;
            open.context.host.account_id_hex = (*account).account_id_hex;
            open.context.host.runtime_generation = 1;
            open.context.host.selection_generation = 1;
            open.context.host.presentation_context_id = 1;
            let mut selection = ptr::dangling_mut();
            open.base.tag = u32::MAX;
            assert_eq!(
                marmot_open_chat_selection(
                    client,
                    (*account).account_id_hex,
                    &raw const open,
                    &raw mut selection
                ),
                MarmotStatus::InvalidArgument
            );
            assert!(selection.is_null());
            open.base.tag = 1;
            assert_eq!(
                marmot_open_chat_selection(
                    client,
                    (*account).account_id_hex,
                    &raw const open,
                    &raw mut selection
                ),
                MarmotStatus::Ok
            );
            let mut status = ptr::null_mut();
            assert_eq!(
                marmot_chat_selection_status(selection, &raw mut status),
                MarmotStatus::Ok
            );
            assert!((*status).has_count);
            assert_eq!((*status).count, 1);
            let mut revision = (*status).revision;
            marmot_chat_selection_status_free(status);
            let mutation = MarmotChatSelectionMutationInput {
                tag: 0,
                archived: 255,
            };
            assert_eq!(
                marmot_chat_selection_apply(
                    selection,
                    13,
                    1,
                    revision,
                    &raw const open.context,
                    &raw const mutation,
                    ptr::null_mut()
                ),
                MarmotStatus::NullPointer
            );
            let mut retained = ptr::dangling_mut();
            assert_eq!(
                marmot_chat_selection_last_mutation(selection, &raw mut retained),
                MarmotStatus::Ok
            );
            assert!(
                retained.is_null(),
                "NULL output never admitted an archive attempt"
            );
            let ids = [group.cast_const()];
            assert_eq!(
                marmot_chat_selection_exclude(
                    selection,
                    revision,
                    ids.as_ptr(),
                    1,
                    ptr::null_mut()
                ),
                MarmotStatus::NullPointer
            );
            let mut membership = ptr::null_mut();
            assert_eq!(
                marmot_chat_selection_membership(
                    selection,
                    revision,
                    ids.as_ptr(),
                    1,
                    &raw mut membership
                ),
                MarmotStatus::Ok
            );
            assert_eq!((*membership).matches_len, 1);
            assert!(*(*membership).matches);
            marmot_chat_selection_membership_free(membership);
            assert_eq!(
                marmot_chat_selection_exclude(
                    selection,
                    revision,
                    ids.as_ptr(),
                    1,
                    &raw mut status
                ),
                MarmotStatus::Ok
            );
            assert_eq!((*status).count, 0);
            revision = (*status).revision;
            marmot_chat_selection_status_free(status);
            assert_eq!(
                marmot_chat_selection_reselect(
                    selection,
                    revision,
                    &raw const open.context,
                    ids.as_ptr(),
                    1,
                    &raw mut status
                ),
                MarmotStatus::Ok
            );
            assert!((*status).has_count);
            assert_eq!((*status).count, 1);
            revision = (*status).revision;
            marmot_chat_selection_status_free(status);
            let mut page = ptr::null_mut();
            assert_eq!(
                marmot_chat_selection_page(selection, revision, 0, 1, &raw mut page),
                MarmotStatus::Ok
            );
            assert_eq!((*page).group_ids_len, 1);
            assert_eq!(CStr::from_ptr(*(*page).group_ids), CStr::from_ptr(group));
            marmot_chat_selection_page_free(page);
            let mut report = ptr::null_mut();
            assert_eq!(
                marmot_chat_selection_apply(
                    selection,
                    13,
                    1,
                    revision,
                    &raw const open.context,
                    &raw const mutation,
                    &raw mut report
                ),
                MarmotStatus::Ok
            );
            assert_eq!((*report).operation_id, 13);
            assert_eq!((*report).attempt_id, 1);
            assert_eq!((*report).applied_group_ids_len, 1);
            assert!(!(*report).uncertain);
            marmot_chat_selection_mutation_report_free(report);
            assert_eq!(
                marmot_chat_selection_last_mutation(selection, &raw mut retained),
                MarmotStatus::Ok
            );
            assert!(!retained.is_null());
            assert_eq!((*retained).operation_id, 13);
            assert_eq!((*retained).attempt_id, 1);
            marmot_chat_selection_mutation_report_free(retained);
            assert_eq!(marmot_chat_selection_close(selection), MarmotStatus::Ok);
            assert_eq!(marmot_chat_selection_cancel(selection), MarmotStatus::Ok);
            marmot_chat_selection_free(selection);
            marmot_string_free(group);
            marmot_account_summary_free(account);
            assert_eq!(marmot_client_shutdown(client), MarmotStatus::Ok);
            marmot_client_free(client);
        }
    }
}
