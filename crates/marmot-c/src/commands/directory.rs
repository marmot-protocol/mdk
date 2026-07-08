//! Directory, identity-resolution, profile, and Markdown-preview commands.

use std::ffi::c_char;

use crate::memory::{free_c_string, owned_opt_c_string, required_str, str_array};
use crate::status::MarmotStatus;
use crate::types::account::MarmotUserProfileMetadata;
use crate::types::markdown::MarmotMarkdownDocument;
use crate::{MarmotClient, client_ref, ffi_guard, write_out};

use super::account::try_arg;
use super::{deliver, deliver_opt, deliver_unit};

/// Write an infallible `Option<String>` through the out-pointer: `Some`
/// becomes an owned C string, `None` writes NULL. Either way the status
/// is `MARMOT_STATUS_OK` once the arguments checked out.
unsafe fn deliver_opt_string(value: Option<String>, out: *mut *mut c_char) -> MarmotStatus {
    let ptr = owned_opt_c_string(value);
    match unsafe { write_out(out, ptr) } {
        Ok(()) => MarmotStatus::Ok,
        Err(status) => {
            unsafe { free_c_string(ptr) };
            status
        }
    }
}

/// Best-effort cached display name for an account id. Returns the Nostr
/// kind:0 display_name/name when the runtime has projected one, or the
/// local account label if the id refers to one of our own accounts.
/// Writes NULL (with `MARMOT_STATUS_OK`) when nothing is known yet —
/// call `marmot_refresh_directory` to fetch.
///
/// # Safety
/// `client` must be a live handle; `account_id_hex` a valid string;
/// `out_name` a valid pointer. Free a non-NULL result with
/// `marmot_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_display_name(
    client: *const MarmotClient,
    account_id_hex: *const c_char,
    out_name: *mut *mut c_char,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_id_hex = try_arg!(unsafe { required_str(account_id_hex) });
        unsafe { deliver_opt_string(client.marmot.display_name(account_id_hex), out_name) }
    })
}

/// Convert a hex account id (Nostr public key) into its `npub…` bech32
/// form for display. Writes NULL (with `MARMOT_STATUS_OK`) if the hex
/// isn't a valid public key.
///
/// # Safety
/// `client` must be a live handle; `account_id_hex` a valid string;
/// `out_npub` a valid pointer. Free a non-NULL result with
/// `marmot_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_npub(
    client: *const MarmotClient,
    account_id_hex: *const c_char,
    out_npub: *mut *mut c_char,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_id_hex = try_arg!(unsafe { required_str(account_id_hex) });
        unsafe { deliver_opt_string(client.marmot.npub(account_id_hex), out_npub) }
    })
}

/// Normalize a public-key reference (npub or hex) to canonical hex.
/// Writes NULL (with `MARMOT_STATUS_OK`) if it isn't a valid public key.
/// Used to resolve a scanned or deep-linked npub back to the account id
/// the rest of the API expects.
///
/// # Safety
/// `client` must be a live handle; `reference` a valid string;
/// `out_hex` a valid pointer. Free a non-NULL result with
/// `marmot_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_account_id_hex(
    client: *const MarmotClient,
    reference: *const c_char,
    out_hex: *mut *mut c_char,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let reference = try_arg!(unsafe { required_str(reference) });
        unsafe { deliver_opt_string(client.marmot.account_id_hex(reference), out_hex) }
    })
}

/// Parse plaintext message content into the same Markdown AST returned on
/// message and timeline records. Useful for draft previews and host-side
/// fallback rendering.
///
/// # Safety
/// `client` must be a live handle; `text` a valid string;
/// `out_document` a valid pointer. Free the result with
/// `marmot_markdown_document_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_parse_markdown(
    client: *const MarmotClient,
    text: *const c_char,
    out_document: *mut *mut MarmotMarkdownDocument,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let text = try_arg!(unsafe { required_str(text) });
        unsafe { deliver(Ok(client.marmot.parse_markdown(text)), out_document) }
    })
}

/// Full cached Nostr kind:0 profile for an account id (name, display
/// name, about, picture, nip05, lud16), if the runtime has one
/// projected. The local account's own profile is cached immediately
/// after `marmot_publish_user_profile`; other accounts' profiles
/// populate via `marmot_refresh_directory`. Writes NULL (with
/// `MARMOT_STATUS_OK`) when nothing is cached yet.
///
/// # Safety
/// `client` must be a live handle; `account_id_hex` a valid string;
/// `out_profile` a valid pointer. Free a non-NULL result with
/// `marmot_user_profile_metadata_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_user_profile(
    client: *const MarmotClient,
    account_id_hex: *const c_char,
    out_profile: *mut *mut MarmotUserProfileMetadata,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_id_hex = try_arg!(unsafe { required_str(account_id_hex) });
        unsafe { deliver_opt(client.marmot.user_profile(account_id_hex), out_profile) }
    })
}

/// Fetch and cache an account's own Nostr kind:0 profile from `relays`.
/// After this resolves, `marmot_user_profile` / `marmot_display_name`
/// return the freshly-fetched metadata (name, picture, etc.) for that
/// account.
///
/// # Safety
/// `client` must be a live handle; `account_id_hex` a valid string; the
/// relay array must hold `relays_len` valid strings (or be NULL with
/// len 0).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_refresh_profile(
    client: *const MarmotClient,
    account_id_hex: *const c_char,
    relays: *const *const c_char,
    relays_len: usize,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_id_hex = try_arg!(unsafe { required_str(account_id_hex) });
        let relays = try_arg!(unsafe { str_array(relays, relays_len) });
        deliver_unit(client.block_on(client.marmot.refresh_profile(account_id_hex, relays)))
    })
}
