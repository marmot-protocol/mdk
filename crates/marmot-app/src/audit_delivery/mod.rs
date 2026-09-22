//! Experimental, inactive audit-journal delivery metadata foundation.
//!
//! This module owns bounded manifest/cursor operations over an already-created
//! private JSONL journal. It neither creates audit bodies nor sends them. The
//! existing recorder and runtime do not call this module; enabling the Cargo
//! feature only makes the Rust API available for integration work in a later
//! change. The foundation is currently Unix-only so its payload identity and
//! descriptor-relative confinement contracts have one explicit platform model.
//!
//! This state is intentionally separate from the existing lossy upload
//! checkpoint: it supports exact prepared-range recovery rather than merely
//! avoiding repeat work for the legacy best-effort snapshot uploader.
//!
//! A store has one process-local owner. It deliberately adds no lifetime file
//! lock: app ownership must eventually come from the existing root runtime
//! lease. Mutations use private staging files, file sync, atomic replacement,
//! and directory sync. A directory-sync failure fences that owner until the
//! store is reopened because publication may already have committed.
//! A cursor carries both a full acknowledged-prefix record-chain commitment and
//! a boundary digest over at most the final 64 KiB before its byte offset.
//! Stable device/inode identity detects pathname replacement. Sealed segments
//! are checked at their exact final length and digest on first use in a store
//! lifetime and again on reopen, rather than being rehashed for every prepared
//! range. Live verification caches are bound to the observed device, inode,
//! length, modification time, and change time, so an observed in-place mutation
//! forces the corresponding full-prefix validation. The acknowledged-prefix
//! commitment is then advanced incrementally after the current cached prefix is
//! proved, rather than rehashed from byte zero for every range. Acknowledgement
//! and sealing independently validate that durable commitment before they
//! publish replacement metadata.

mod recovery;
mod state;

pub use state::{
    AttemptToken, AuditDeliveryError, AuditDeliveryStore, DestinationProfile, JournalId,
    PreparedRange, SegmentId, SegmentStatus,
};

#[cfg(test)]
mod tests;
