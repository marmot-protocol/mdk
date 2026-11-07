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
            published: super::saturating_u32(summary.published),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preview_updates_keep_incremental_status_record_and_terminal_tags() {
        assert!(
            matches!(AgentStreamUpdateFfi::from(RuntimeAgentStreamUpdate::Chunk { seq: 2, text: "fragment".into() }), AgentStreamUpdateFfi::Chunk { seq: 2, text } if text == "fragment")
        );
        assert!(
            matches!(AgentStreamUpdateFfi::from(RuntimeAgentStreamUpdate::Status { seq: 3, status: "working".into() }), AgentStreamUpdateFfi::Status { seq: 3, status } if status == "working")
        );
        assert!(
            matches!(AgentStreamUpdateFfi::from(RuntimeAgentStreamUpdate::Progress { seq: 4, text: "step completed".into() }), AgentStreamUpdateFfi::Progress { seq: 4, text } if text == "step completed")
        );
        // Checkpoint text is decoded and forwarded as a non-delta record.
        assert!(
            matches!(AgentStreamUpdateFfi::from(RuntimeAgentStreamUpdate::Record { seq: 5, record_type: 4, text: "record body".into() }), AgentStreamUpdateFfi::Record { seq: 5, record_type: 4, text } if text == "record body")
        );
        let mut transcript = cgka_traits::AgentTextStreamTranscriptV1::new(
            vec![1; cgka_traits::agent_text_stream::AGENT_TEXT_STREAM_PROFILE_STREAM_ID_LEN],
            cgka_traits::MessageId::new(vec![2; 32]),
        );
        for (index, fragment) in ["complete ", "tran", "s", "cri", "p", "t"]
            .into_iter()
            .enumerate()
        {
            transcript.append(index as u64 + 1, 1, fragment.as_bytes());
        }
        let hash = hex::encode(transcript.hash());
        assert!(
            matches!(AgentStreamUpdateFfi::from(RuntimeAgentStreamUpdate::Finished { text: "complete transcript".into(), transcript_hash_hex: hash.clone(), chunk_count: 6 }), AgentStreamUpdateFfi::Finished { text, transcript_hash_hex, chunk_count: 6 } if text == "complete transcript" && transcript_hash_hex == hash)
        );
        assert!(
            matches!(AgentStreamUpdateFfi::from(RuntimeAgentStreamUpdate::Failed { message: "broker disconnected".into() }), AgentStreamUpdateFfi::Failed { message } if message == "broker disconnected")
        );
    }
}
