//! Opaque publisher handles. Inputs are borrowed; results have deep frees.

use std::ffi::c_char;
use std::sync::Arc;

use marmot_uniffi::{
    AgentTextPublisher, PublisherAckFfi, PublisherInfoFfi, PublisherOptionsFfi, PublisherRecordFfi,
    PublisherTrustFfi,
};
use tokio::runtime::Handle;

use crate::commands::{deliver, try_arg};
use crate::macros::c_mirror;
use crate::memory::{CFree, boxed, free_boxed, required_str};
use crate::status::{set_last_error, status_from_error};
use crate::types::account::MarmotSendSummary;
use crate::{
    MarmotClient, MarmotStatus, block_on_handle, client_ref, ffi_guard, preflight_out_ptr,
};

/// Single live stream. Free before its creating `MarmotClient`; never free
/// concurrently with an in-flight call on this handle.
pub struct MarmotAgentPublisher {
    inner: Arc<AgentTextPublisher>,
    runtime: Handle,
}

impl CFree for MarmotAgentPublisher {
    unsafe fn free_in_place(&mut self) {}
}

/// Transcript record type. Pass the discriminant as uint32_t.
#[repr(u32)]
pub enum MarmotPublisherRecord {
    Text = 0,
    Status = 1,
    Progress = 2,
}

/// Broker trust policy. AllowLoopback is an explicit local-test opt-in.
#[repr(u32)]
pub enum MarmotPublisherTrust {
    PublicOnly = 0,
    AllowLoopback = 1,
}

/// Borrowed broker options. NULL certificate with zero length selects
/// platform trust. `trust` is a `MarmotPublisherTrust` discriminant.
#[repr(C)]
pub struct MarmotPublisherOptions {
    pub candidate: *const c_char,
    pub server_cert_der: *const u8,
    pub server_cert_der_len: usize,
    pub trust: u32,
}

c_mirror! {
    /// Stable stream and start-message identifiers.
    MarmotPublisherInfo from PublisherInfoFfi,
    free marmot_publisher_info_free {
        str stream_id_hex,
        str start_message_id_hex,
    }
}

c_mirror! {
    /// Accepted record receipt. A live preview error does not discard the
    /// transcript; finish still produces the durable final.
    MarmotPublisherAck from PublisherAckFfi,
    free marmot_publisher_ack_free {
        copy chunk_count: u64,
        /// NULL when no preview error occurred; otherwise an error string.
        /// Either is possible after a successful append; check before dereferencing.
        opt_str live_error,
    }
}

/// Anchor a new stream and return its publisher. Broker connection happens
/// in the background. Invalid inputs/out-pointers fail before anchoring.
///
/// # Safety
/// `client` is live; required strings and options are valid for this call;
/// certificate is NULL with zero length or references that many bytes;
/// `out` is writable. Input memory is neither retained nor freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_agent_publisher_new(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    options: *const MarmotPublisherOptions,
    out: *mut *mut MarmotAgentPublisher,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let client = try_arg!(unsafe { client_ref(client) });
        let account = try_arg!(unsafe { required_str(account_ref) });
        let group = try_arg!(unsafe { required_str(group_id_hex) });
        let Some(options) = (unsafe { options.as_ref() }) else {
            set_last_error("required publisher input was NULL");
            return MarmotStatus::NullPointer;
        };
        let candidate = try_arg!(unsafe { required_str(options.candidate) });
        let trust = match options.trust {
            0 => PublisherTrustFfi::PublicOnly,
            1 => PublisherTrustFfi::AllowLoopback,
            _ => {
                set_last_error("invalid publisher trust policy");
                return MarmotStatus::InvalidArgument;
            }
        };
        let server_cert_der = if options.server_cert_der.is_null() {
            if options.server_cert_der_len != 0 {
                set_last_error("required publisher input was NULL");
                return MarmotStatus::NullPointer;
            }
            None
        } else {
            Some(
                unsafe {
                    std::slice::from_raw_parts(options.server_cert_der, options.server_cert_der_len)
                }
                .to_vec(),
            )
        };
        match client.block_on(client.marmot.open_agent_publisher(
            account,
            group,
            PublisherOptionsFfi {
                candidate,
                server_cert_der,
                trust,
            },
        )) {
            Ok(inner) => {
                unsafe {
                    out.write(boxed(MarmotAgentPublisher {
                        inner,
                        runtime: client.runtime.handle().clone(),
                    }))
                };
                MarmotStatus::Ok
            }
            Err(error) => status_from_error(&error),
        }
    })
}

/// Read stream identifiers. Free with `marmot_publisher_info_free`.
///
/// # Safety
/// `publisher` is live and `out` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_agent_publisher_info(
    publisher: *const MarmotAgentPublisher,
    out: *mut *mut MarmotPublisherInfo,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let Some(publisher) = (unsafe { publisher.as_ref() }) else {
            set_last_error("required publisher input was NULL");
            return MarmotStatus::NullPointer;
        };
        unsafe { deliver(Ok(publisher.inner.info()), out) }
    })
}

/// Append one text/status/progress record; free the receipt with
/// `marmot_publisher_ack_free`. Unknown record types fail before appending.
///
/// # Safety
/// `publisher` is live, `text` is valid UTF-8/NUL-terminated, `out` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_agent_publisher_append(
    publisher: *const MarmotAgentPublisher,
    kind: u32,
    text: *const c_char,
    out: *mut *mut MarmotPublisherAck,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let Some(publisher) = (unsafe { publisher.as_ref() }) else {
            set_last_error("required publisher input was NULL");
            return MarmotStatus::NullPointer;
        };
        let kind = match kind {
            0 => PublisherRecordFfi::Text,
            1 => PublisherRecordFfi::Status,
            2 => PublisherRecordFfi::Progress,
            _ => {
                set_last_error("invalid publisher record type");
                return MarmotStatus::InvalidArgument;
            }
        };
        let text = try_arg!(unsafe { required_str(text) });
        unsafe {
            deliver(
                block_on_handle(&publisher.runtime, publisher.inner.append(kind, text)),
                out,
            )
        }
    })
}

/// Seal and send the final transcript. Failed sends retain the sealed
/// request for retry; a successful repeated call returns the original receipt.
/// Free with `marmot_send_summary_free`. Inspect its delivery disposition.
///
/// # Safety
/// `publisher` is live and `out` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_agent_publisher_finish(
    publisher: *const MarmotAgentPublisher,
    out: *mut *mut MarmotSendSummary,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let Some(publisher) = (unsafe { publisher.as_ref() }) else {
            set_last_error("required publisher input was NULL");
            return MarmotStatus::NullPointer;
        };
        unsafe {
            deliver(
                block_on_handle(&publisher.runtime, publisher.inner.finish()),
                out,
            )
        }
    })
}

/// Cancel the preview. Does not retract a final already being published.
///
/// # Safety
/// `publisher` is a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_agent_publisher_cancel(
    publisher: *const MarmotAgentPublisher,
) -> MarmotStatus {
    ffi_guard(|| {
        let Some(publisher) = (unsafe { publisher.as_ref() }) else {
            set_last_error("required publisher input was NULL");
            return MarmotStatus::NullPointer;
        };
        block_on_handle(&publisher.runtime, publisher.inner.cancel());
        MarmotStatus::Ok
    })
}

/// Release a publisher, requesting preview cancellation. NULL is a no-op.
///
/// # Safety
/// `publisher` is NULL or a live root returned by this library, with no
/// concurrent call using it. Free before the creating client.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_agent_publisher_free(publisher: *mut MarmotAgentPublisher) {
    ffi_guard(|| {
        unsafe { free_boxed(publisher) };
        MarmotStatus::Ok
    });
}

#[cfg(all(test, feature = "alloc-audit"))]
mod tests {
    use super::*;
    use crate::memory::audit;

    #[test]
    fn receipts_deep_free() {
        let _lock = audit::test_lock();
        let before = audit::live_allocations();
        let info = boxed(MarmotPublisherInfo::from(PublisherInfoFfi {
            stream_id_hex: "01".repeat(32),
            start_message_id_hex: "02".repeat(32),
        }));
        let ack = boxed(MarmotPublisherAck::from(PublisherAckFfi {
            chunk_count: 2,
            live_error: Some("connection lost".into()),
        }));
        unsafe {
            marmot_publisher_info_free(info);
            marmot_publisher_ack_free(ack);
            marmot_publisher_info_free(std::ptr::null_mut());
            marmot_publisher_ack_free(std::ptr::null_mut());
        }
        assert_eq!(audit::live_allocations(), before);
    }
}
