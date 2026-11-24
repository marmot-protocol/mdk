//! Async exports a cancelled Swift task still awaits to completion.
//!
//! Each is `#[marmot_uniffi_macros::survives_cancellation]`: its work starts on
//! the future's first poll, which a pre-cancelled Swift call would skip, and
//! hosts rely on it having finished (storage closed before suspension, an
//! account wiped). `src/bin/uniffi-bindgen.rs` leaves these Swift calls
//! uncancellable; `tokio_runtime` tests keep the list equal to the marked
//! exports.

pub(crate) const SWIFT_AWAITS_COMPLETION: &[&str] = &[
    "uniffi_marmot_uniffi_fn_method_marmot_login",
    "uniffi_marmot_uniffi_fn_method_marmot_login_external_signer",
    "uniffi_marmot_uniffi_fn_method_marmot_login_recovering_incomplete_setup",
    "uniffi_marmot_uniffi_fn_method_marmot_release_attachment_handoff",
    "uniffi_marmot_uniffi_fn_method_marmot_remove_account",
    "uniffi_marmot_uniffi_fn_method_marmot_set_audit_log_settings",
    "uniffi_marmot_uniffi_fn_method_marmot_shutdown_and_close",
    "uniffi_marmot_uniffi_fn_method_marmot_sign_out",
    "uniffi_marmot_uniffi_fn_method_marmot_sign_out_and_wipe",
    "uniffi_marmot_uniffi_fn_method_marmot_start_direct_conversation",
    "uniffi_marmot_uniffi_fn_method_marmot_start_direct_conversation_with_options",
    "uniffi_marmot_uniffi_fn_method_nip46sessionffi_approve_permissions",
    "uniffi_marmot_uniffi_fn_method_nip46sessionffi_logout",
];
