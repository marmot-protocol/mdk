//! Receive-side bounds on record count and accumulated plaintext, with the
//! accumulator that enforces them and the limit-breach error type.

use std::time::Duration;

use cgka_traits::agent_text_stream::{
    AGENT_TEXT_STREAM_DEFAULT_MAX_PLAINTEXT_BYTES, AGENT_TEXT_STREAM_DEFAULT_MAX_RECORDS,
    AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN, AgentTextStreamRecordV1,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AgentTextStreamReceiveLimits {
    pub max_records: u64,
    pub max_plaintext_bytes: usize,
    /// Group policy `max_plaintext_frame_len` when available. Receive paths
    /// reject wire frames above this value plus the spec-pinned 1024-byte
    /// allowance; the app-profile constant is the ceiling and default.
    pub max_plaintext_frame_len: u32,
    /// Application-level deadline for each inbound stream/read step. `0`
    /// disables the deadline for tests or specialized callers.
    pub read_timeout: Duration,
}

impl Default for AgentTextStreamReceiveLimits {
    fn default() -> Self {
        Self {
            max_records: AGENT_TEXT_STREAM_DEFAULT_MAX_RECORDS,
            max_plaintext_bytes: AGENT_TEXT_STREAM_DEFAULT_MAX_PLAINTEXT_BYTES,
            max_plaintext_frame_len: AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN,
            read_timeout: Duration::from_secs(15),
        }
    }
}

#[derive(Clone, Debug)]
pub struct AgentTextStreamReceiveAccumulator {
    limits: AgentTextStreamReceiveLimits,
    wire_records: u64,
    records: u64,
    plaintext_bytes: usize,
}

impl AgentTextStreamReceiveAccumulator {
    pub fn new(limits: AgentTextStreamReceiveLimits) -> Self {
        Self {
            limits,
            wire_records: 0,
            records: 0,
            plaintext_bytes: 0,
        }
    }

    pub fn observe_wire_record(&mut self) -> Result<(), AgentTextStreamReceiveLimitError> {
        // Direct point-to-point streams do not expect legitimate in-stream
        // replay/backlog volume, so every decoded wire record spends the same
        // `max_records` budget before duplicate or low-sequence discard.
        let wire_records = self.wire_records.checked_add(1).ok_or(
            AgentTextStreamReceiveLimitError::RecordLimitExceeded {
                attempted: u64::MAX,
                limit: self.limits.max_records,
            },
        )?;
        if wire_records > self.limits.max_records {
            return Err(AgentTextStreamReceiveLimitError::RecordLimitExceeded {
                attempted: wire_records,
                limit: self.limits.max_records,
            });
        }
        self.wire_records = wire_records;
        Ok(())
    }

    pub fn observe(
        &mut self,
        record: &AgentTextStreamRecordV1,
    ) -> Result<(), AgentTextStreamReceiveLimitError> {
        let records = self.records.checked_add(1).ok_or(
            AgentTextStreamReceiveLimitError::RecordLimitExceeded {
                attempted: u64::MAX,
                limit: self.limits.max_records,
            },
        )?;
        if records > self.limits.max_records {
            return Err(AgentTextStreamReceiveLimitError::RecordLimitExceeded {
                attempted: records,
                limit: self.limits.max_records,
            });
        }

        let plaintext_bytes = self
            .plaintext_bytes
            .checked_add(record.plaintext_frame.len())
            .ok_or(
                AgentTextStreamReceiveLimitError::PlaintextByteLimitExceeded {
                    attempted: usize::MAX,
                    limit: self.limits.max_plaintext_bytes,
                },
            )?;
        if plaintext_bytes > self.limits.max_plaintext_bytes {
            return Err(
                AgentTextStreamReceiveLimitError::PlaintextByteLimitExceeded {
                    attempted: plaintext_bytes,
                    limit: self.limits.max_plaintext_bytes,
                },
            );
        }

        self.records = records;
        self.plaintext_bytes = plaintext_bytes;
        Ok(())
    }

    pub fn records(&self) -> u64 {
        self.records
    }

    pub fn wire_records(&self) -> u64 {
        self.wire_records
    }

    pub fn plaintext_bytes(&self) -> usize {
        self.plaintext_bytes
    }
}

impl Default for AgentTextStreamReceiveAccumulator {
    fn default() -> Self {
        Self::new(AgentTextStreamReceiveLimits::default())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AgentTextStreamReceiveLimitError {
    #[error("agent text stream record limit exceeded: {attempted} > {limit}")]
    RecordLimitExceeded { attempted: u64, limit: u64 },
    #[error("agent text stream plaintext byte limit exceeded: {attempted} > {limit}")]
    PlaintextByteLimitExceeded { attempted: usize, limit: usize },
}
