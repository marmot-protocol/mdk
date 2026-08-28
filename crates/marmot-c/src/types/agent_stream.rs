//! C mirrors of the agent text stream conversions.

use std::ffi::c_char;

use marmot_uniffi::conversions::{AgentStreamStartFfi, AgentStreamUpdateFfi};

use crate::macros::c_mirror;
use crate::memory::{CFree, free_c_string, owned_c_string};

c_mirror! {
    /// Result of starting (anchoring) an agent text stream.
    MarmotAgentStreamStart from AgentStreamStartFfi,
    free marmot_agent_stream_start_free {
        str stream_id_hex,
        copy published: u32,
        str_vec message_ids/message_ids_len,
    }
}

/// One live agent-stream update. `Chunk`s arrive incrementally; a
/// terminal `Finished` / `Failed` precedes stream close.
#[repr(C)]
pub enum MarmotAgentStreamUpdate {
    Chunk {
        seq: u64,
        text: *mut c_char,
    },
    Status {
        seq: u64,
        status: *mut c_char,
    },
    Progress {
        seq: u64,
        text: *mut c_char,
    },
    Record {
        seq: u64,
        record_type: u8,
        text: *mut c_char,
    },
    Finished {
        text: *mut c_char,
        transcript_hash_hex: *mut c_char,
        chunk_count: u64,
    },
    Failed {
        message: *mut c_char,
    },
}

impl From<AgentStreamUpdateFfi> for MarmotAgentStreamUpdate {
    fn from(value: AgentStreamUpdateFfi) -> Self {
        use AgentStreamUpdateFfi as F;
        match value {
            F::Chunk { seq, text } => Self::Chunk {
                seq,
                text: owned_c_string(text),
            },
            F::Status { seq, status } => Self::Status {
                seq,
                status: owned_c_string(status),
            },
            F::Progress { seq, text } => Self::Progress {
                seq,
                text: owned_c_string(text),
            },
            F::Record {
                seq,
                record_type,
                text,
            } => Self::Record {
                seq,
                record_type,
                text: owned_c_string(text),
            },
            F::Finished {
                text,
                transcript_hash_hex,
                chunk_count,
            } => Self::Finished {
                text: owned_c_string(text),
                transcript_hash_hex: owned_c_string(transcript_hash_hex),
                chunk_count,
            },
            F::Failed { message } => Self::Failed {
                message: owned_c_string(message),
            },
        }
    }
}

impl CFree for MarmotAgentStreamUpdate {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            match self {
                Self::Chunk { text, .. }
                | Self::Progress { text, .. }
                | Self::Record { text, .. } => free_c_string(*text),
                Self::Status { status, .. } => free_c_string(*status),
                Self::Finished {
                    text,
                    transcript_hash_hex,
                    ..
                } => {
                    free_c_string(*text);
                    free_c_string(*transcript_hash_hex);
                }
                Self::Failed { message } => free_c_string(*message),
            }
        }
    }
}

/// Free an agent-stream update returned by this library. NULL is a no-op.
///
/// # Safety
/// `update` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_agent_stream_update_free(update: *mut MarmotAgentStreamUpdate) {
    crate::memory::free_guard(|| unsafe { crate::memory::free_boxed(update) });
}
