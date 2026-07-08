//! C mirrors of the agent-text-stream conversions
//! (`marmot-uniffi/src/conversions/agent_stream.rs`).

use std::ffi::c_char;

use marmot_uniffi::conversions::{AgentStreamStartFfi, AgentStreamUpdateFfi};

use crate::memory::{CFree, free_boxed, free_c_string, free_vec, owned_c_string, owned_vec};

/// Result of anchoring a live agent text stream start in the encrypted
/// group history (`marmot_start_agent_text_stream`).
#[repr(C)]
pub struct MarmotAgentStreamStart {
    /// Hex-encoded 32-byte stream id (generated when the caller omitted one).
    pub stream_id_hex: *mut c_char,
    /// Number of relays the anchor was published to.
    pub published: u32,
    /// Ids of the published anchor message(s).
    pub message_ids: *mut *mut c_char,
    pub message_ids_len: usize,
}

impl From<AgentStreamStartFfi> for MarmotAgentStreamStart {
    fn from(value: AgentStreamStartFfi) -> Self {
        let (message_ids, message_ids_len) = owned_vec(
            value
                .message_ids
                .into_iter()
                .map(owned_c_string)
                .collect::<Vec<_>>(),
        );
        Self {
            stream_id_hex: owned_c_string(value.stream_id_hex),
            published: value.published,
            message_ids,
            message_ids_len,
        }
    }
}

impl CFree for MarmotAgentStreamStart {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_c_string(self.stream_id_hex);
            free_vec(self.message_ids, self.message_ids_len);
        }
    }
}

/// Free an agent stream start root. NULL is a no-op.
///
/// # Safety
/// `start` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_agent_stream_start_free(start: *mut MarmotAgentStreamStart) {
    crate::memory::free_guard(|| unsafe { free_boxed(start) });
}

/// One update from a live agent-text-stream watch. `Chunk.text` is an
/// incremental fragment; `Finished.text` is the complete transcript.
#[repr(C)]
pub enum MarmotAgentStreamUpdate {
    /// Incremental transcript fragment.
    Chunk { seq: u64, text: *mut c_char },
    /// Out-of-band status line from the agent.
    Status { seq: u64, status: *mut c_char },
    /// Progress note from the agent.
    Progress { seq: u64, text: *mut c_char },
    /// Typed record frame from the agent.
    Record {
        seq: u64,
        record_type: u8,
        text: *mut c_char,
    },
    /// Terminal success; `text` is the complete transcript.
    Finished {
        text: *mut c_char,
        transcript_hash_hex: *mut c_char,
        chunk_count: u64,
    },
    /// Terminal failure.
    Failed { message: *mut c_char },
}

impl From<AgentStreamUpdateFfi> for MarmotAgentStreamUpdate {
    fn from(value: AgentStreamUpdateFfi) -> Self {
        match value {
            AgentStreamUpdateFfi::Chunk { seq, text } => Self::Chunk {
                seq,
                text: owned_c_string(text),
            },
            AgentStreamUpdateFfi::Status { seq, status } => Self::Status {
                seq,
                status: owned_c_string(status),
            },
            AgentStreamUpdateFfi::Progress { seq, text } => Self::Progress {
                seq,
                text: owned_c_string(text),
            },
            AgentStreamUpdateFfi::Record {
                seq,
                record_type,
                text,
            } => Self::Record {
                seq,
                record_type,
                text: owned_c_string(text),
            },
            AgentStreamUpdateFfi::Finished {
                text,
                transcript_hash_hex,
                chunk_count,
            } => Self::Finished {
                text: owned_c_string(text),
                transcript_hash_hex: owned_c_string(transcript_hash_hex),
                chunk_count,
            },
            AgentStreamUpdateFfi::Failed { message } => Self::Failed {
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

/// Free an agent stream update root (delivered by the agent-stream
/// subscription). NULL is a no-op.
///
/// # Safety
/// `update` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_agent_stream_update_free(update: *mut MarmotAgentStreamUpdate) {
    crate::memory::free_guard(|| unsafe { free_boxed(update) });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::boxed;

    #[test]
    fn agent_stream_start_deep_roundtrip() {
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let mirror: MarmotAgentStreamStart = AgentStreamStartFfi {
            stream_id_hex: "ab".repeat(32),
            published: 2,
            message_ids: vec!["m1".into(), "m2".into()],
        }
        .into();
        assert!(!mirror.stream_id_hex.is_null());
        assert_eq!(mirror.published, 2);
        assert_eq!(mirror.message_ids_len, 2);
        let first = unsafe { std::ffi::CStr::from_ptr(*mirror.message_ids) }
            .to_str()
            .unwrap();
        assert_eq!(first, "m1");
        let root = boxed(mirror);
        unsafe { marmot_agent_stream_start_free(root) };

        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn agent_stream_update_all_variants_roundtrip() {
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let chunk = MarmotAgentStreamUpdate::from(AgentStreamUpdateFfi::Chunk {
            seq: 1,
            text: "hello".into(),
        });
        match &chunk {
            MarmotAgentStreamUpdate::Chunk { seq, text } => {
                assert_eq!(*seq, 1);
                let s = unsafe { std::ffi::CStr::from_ptr(*text) }.to_str().unwrap();
                assert_eq!(s, "hello");
            }
            _ => panic!("expected Chunk"),
        }
        unsafe { marmot_agent_stream_update_free(boxed(chunk)) };

        let status = MarmotAgentStreamUpdate::from(AgentStreamUpdateFfi::Status {
            seq: 2,
            status: "thinking".into(),
        });
        match &status {
            MarmotAgentStreamUpdate::Status { seq, status } => {
                assert_eq!(*seq, 2);
                assert!(!status.is_null());
            }
            _ => panic!("expected Status"),
        }
        unsafe { marmot_agent_stream_update_free(boxed(status)) };

        let progress = MarmotAgentStreamUpdate::from(AgentStreamUpdateFfi::Progress {
            seq: 3,
            text: "step 1".into(),
        });
        match &progress {
            MarmotAgentStreamUpdate::Progress { seq, text } => {
                assert_eq!(*seq, 3);
                assert!(!text.is_null());
            }
            _ => panic!("expected Progress"),
        }
        unsafe { marmot_agent_stream_update_free(boxed(progress)) };

        let record = MarmotAgentStreamUpdate::from(AgentStreamUpdateFfi::Record {
            seq: 4,
            record_type: 7,
            text: "payload".into(),
        });
        match &record {
            MarmotAgentStreamUpdate::Record {
                seq,
                record_type,
                text,
            } => {
                assert_eq!(*seq, 4);
                assert_eq!(*record_type, 7);
                assert!(!text.is_null());
            }
            _ => panic!("expected Record"),
        }
        unsafe { marmot_agent_stream_update_free(boxed(record)) };

        let finished = MarmotAgentStreamUpdate::from(AgentStreamUpdateFfi::Finished {
            text: "full transcript".into(),
            transcript_hash_hex: "ee".repeat(32),
            chunk_count: 42,
        });
        match &finished {
            MarmotAgentStreamUpdate::Finished {
                text,
                transcript_hash_hex,
                chunk_count,
            } => {
                assert_eq!(*chunk_count, 42);
                assert!(!text.is_null());
                assert!(!transcript_hash_hex.is_null());
            }
            _ => panic!("expected Finished"),
        }
        unsafe { marmot_agent_stream_update_free(boxed(finished)) };

        let failed = MarmotAgentStreamUpdate::from(AgentStreamUpdateFfi::Failed {
            message: "broker unreachable".into(),
        });
        match &failed {
            MarmotAgentStreamUpdate::Failed { message } => assert!(!message.is_null()),
            _ => panic!("expected Failed"),
        }
        unsafe { marmot_agent_stream_update_free(boxed(failed)) };

        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn empty_message_ids_convert_to_null() {
        let _guard = crate::memory::audit::test_lock();
        let mirror: MarmotAgentStreamStart = AgentStreamStartFfi {
            stream_id_hex: "00".into(),
            published: 0,
            message_ids: Vec::new(),
        }
        .into();
        assert!(mirror.message_ids.is_null());
        assert_eq!(mirror.message_ids_len, 0);
        let root = boxed(mirror);
        unsafe { marmot_agent_stream_start_free(root) };
    }
}
