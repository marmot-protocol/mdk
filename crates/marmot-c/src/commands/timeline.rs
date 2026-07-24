//! Materialized timeline read command.
//!
//! `subscribe_timeline_messages` is a subscription-returning method and is
//! owned by the subscriptions layer (`src/subscriptions.rs`), not wrapped
//! here.

use std::ffi::c_char;

use crate::memory::required_str;
use crate::status::MarmotStatus;
use crate::types::timeline::{MarmotTimelineMessageQuery, MarmotTimelinePage};
use crate::{MarmotClient, client_ref, ffi_guard};

use super::account::try_arg;
use super::deliver;

/// Materialized conversation timeline for a group or account-wide tail.
///
/// This is the app-facing aggregated view: kind-9 chat/reply/media rows,
/// kind-1200 stream-start rows, stream-final metadata pointing back to the
/// start, reaction summaries, delete tombstones, and pagination flags. Raw
/// kind-7/kind-5 events remain available through `marmot_messages` for
/// diagnostics.
///
/// This call is **synchronous** and runs the store read on the calling
/// thread; clients should not use it for scroll-back. Prefer the timeline
/// subscription (`marmot_subscribe_timeline_messages`) plus its
/// `paginate_backwards` / `paginate_forwards`, which own a bounded window
/// and run off the caller thread. Retained for one-shot
/// diagnostics/tooling only.
///
/// # Safety
/// `client` must be a live handle; `account_ref` a valid string; `query` a
/// valid borrowed struct (never freed by the library) whose non-NULL string
/// fields are valid NUL-terminated strings; `out_page` a valid pointer.
/// Free the result with `marmot_timeline_page_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_timeline_messages(
    client: *const MarmotClient,
    account_ref: *const c_char,
    query: *const MarmotTimelineMessageQuery,
    out_page: *mut *mut MarmotTimelinePage,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        if query.is_null() {
            crate::status::set_last_error("query argument was NULL");
            return MarmotStatus::NullPointer;
        }
        let query = try_arg!(unsafe { (*query).to_ffi() });
        unsafe {
            deliver(
                client.marmot.timeline_messages(account_ref, query),
                out_page,
            )
        }
    })
}
