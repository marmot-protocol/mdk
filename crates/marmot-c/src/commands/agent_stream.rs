//! Live agent text stream anchor command.
//!
//! Only the start/anchor command lives here; the watch side
//! (`marmot_watch_agent_text_stream` and its subscription handle) lives in
//! the subscriptions layer (`crate::subscriptions`) with the other
//! long-lived stream handles.

use std::ffi::c_char;

use crate::memory::{optional_str, required_str, str_array};
use crate::status::MarmotStatus;
use crate::types::agent_stream::MarmotAgentStreamStart;
use crate::{MarmotClient, client_ref, ffi_guard};

use super::account::try_arg;
use super::deliver;

/// Anchor a live agent text stream start in the encrypted group history.
/// `quic_candidates` (`quic_candidates_len` entries) are the broker
/// candidate URLs the host will publish to, such as
/// `quic://quic-broker.ipf.dev:4450`; pass `stream_id_hex = NULL` to let
/// the library generate a 32-byte stream id (the one actually used is in
/// the result).
///
/// # Safety
/// `client` must be a live handle; `account_ref` and `group_id_hex` valid
/// strings; `stream_id_hex` NULL or a valid string; `quic_candidates`
/// must hold `quic_candidates_len` valid strings (or be NULL with len 0);
/// `out_start` must be a valid pointer. Free the result with
/// `marmot_agent_stream_start_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_start_agent_text_stream(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    stream_id_hex: *const c_char,
    quic_candidates: *const *const c_char,
    quic_candidates_len: usize,
    out_start: *mut *mut MarmotAgentStreamStart,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        let group_id_hex = try_arg!(unsafe { required_str(group_id_hex) });
        let stream_id_hex = try_arg!(unsafe { optional_str(stream_id_hex) });
        let quic_candidates = try_arg!(unsafe { str_array(quic_candidates, quic_candidates_len) });
        unsafe {
            deliver(
                client.block_on(client.marmot.start_agent_text_stream(
                    account_ref,
                    group_id_hex,
                    stream_id_hex,
                    quic_candidates,
                )),
                out_start,
            )
        }
    })
}
