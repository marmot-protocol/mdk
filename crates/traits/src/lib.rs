//! # cgka-traits
//!
//! Shared trait surface and cross-boundary value types for the CGKA engine,
//! transport peeler, and storage backends.
//!
//! This crate is the one dependency anything crossing a seam should import.

pub mod capabilities;
pub mod engine;
pub mod engine_state;
pub mod error;
pub mod group;
pub mod group_context;
pub mod ingest;
pub mod message;
pub mod peeler;
pub mod storage;
pub mod transport;
pub mod types;
pub mod welcome;

pub use capabilities::{
    Capability, CapabilityRequirement, Feature, FeatureStatus, GroupCapabilities, RequirementLevel,
    TransportKind,
};
pub use engine::{
    CgkaEngine, CommitOrderingKey, CreateGroupRequest, GroupEvent, KeyPackage, SendIntent,
    SendResult,
};
pub use engine_state::{
    EpochState, InvalidTransition, Merging, PendingPublish, PendingStateRef, PendingWelcomeState,
    Recovering, StagedCommitHandle, WelcomeState,
};
pub use error::{EngineError, PeelerError};
pub use group::{Group, Member};
pub use group_context::{GroupContext, GroupContextSnapshot};
pub use ingest::{IngestOutcome, PeeledContent, PeeledMessage, StaleReason};
pub use message::{MessageRecord, MessageState};
pub use peeler::TransportPeeler;
pub use storage::{
    CapabilityStorage, GroupStorage, MessageStorage, StorageError, StorageProvider, StorageResult,
    WelcomeStorage,
};
pub use transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
pub use types::{Backend, EpochId, GroupId, MemberId, MessageId};
pub use welcome::PendingWelcome;

// ── Compile-time witness (Task 5.7 started early) ───────────────────────────
//
// If anyone reintroduces a `&dyn GroupContext` across an `.await` on the
// `CgkaEngine` trait (the spike's E0195 regression — see
// `docs/learnings.md:44`), this constant will fail to compile because the
// trait object becomes non-Send.
const _: fn(Box<dyn CgkaEngine + Send + Sync>) = |_| {};
const _: fn(Box<dyn TransportPeeler + Send + Sync>) = |_| {};
