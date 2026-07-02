//! Agent-text-stream start and live-update FFI conversions.

use marmot_app::{RuntimeAgentStreamUpdate, SendSummary};

#[derive(Clone, Debug, uniffi::Record)]
pub struct AgentStreamStartFfi {
    pub stream_id_hex: String,
    pub published: u32,
    pub message_ids: Vec<String>,
}

impl AgentStreamStartFfi {
    pub(crate) fn new(stream_id_hex: String, summary: SendSummary) -> Self {
        Self {
            stream_id_hex,
            published: summary.published as u32,
            message_ids: summary.message_ids,
        }
    }
}

/// One update from a live agent-text-stream watch. `Chunk.text` is an
/// incremental fragment; `Finished.text` is the complete transcript.
#[derive(Clone, Debug, uniffi::Enum)]
pub enum AgentStreamUpdateFfi {
    Chunk {
        seq: u64,
        text: String,
    },
    Status {
        seq: u64,
        status: String,
    },
    Progress {
        seq: u64,
        text: String,
    },
    Record {
        seq: u64,
        record_type: u8,
        text: String,
    },
    Finished {
        text: String,
        transcript_hash_hex: String,
        chunk_count: u64,
    },
    Failed {
        message: String,
    },
}

impl From<RuntimeAgentStreamUpdate> for AgentStreamUpdateFfi {
    fn from(value: RuntimeAgentStreamUpdate) -> Self {
        match value {
            RuntimeAgentStreamUpdate::Chunk { seq, text } => Self::Chunk { seq, text },
            RuntimeAgentStreamUpdate::Status { seq, status } => Self::Status { seq, status },
            RuntimeAgentStreamUpdate::Progress { seq, text } => Self::Progress { seq, text },
            RuntimeAgentStreamUpdate::Record {
                seq,
                record_type,
                text,
            } => Self::Record {
                seq,
                record_type,
                text,
            },
            RuntimeAgentStreamUpdate::Finished {
                text,
                transcript_hash_hex,
                chunk_count,
            } => Self::Finished {
                text,
                transcript_hash_hex,
                chunk_count,
            },
            RuntimeAgentStreamUpdate::Failed { message } => Self::Failed { message },
        }
    }
}
