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
pub mod transport_adapter;
pub mod types;
pub mod welcome;

pub use capabilities::{
    Capability, CapabilityRequirement, Feature, FeatureStatus, GroupCapabilities, RequirementLevel,
    TransportKind,
};
pub use engine::{
    AutoPublish, CgkaEngine, CommitOrderingKey, CreateGroupRequest, GroupEvent, KeyPackage,
    SendIntent, SendResult,
};
pub use engine_state::{
    EpochState, InvalidTransition, Merging, PendingPublish, PendingStateRef, PendingWelcomeState,
    Recovering, StagedCommitHandle, WelcomeState,
};
pub use error::{EngineError, PeelerError};
pub use group::{Group, Member};
pub use group_context::{GroupContext, GroupContextSnapshot};
pub use ingest::{IngestOutcome, PeeledContent, PeeledMessage, StaleReason};
pub use message::{MessageRecord, MessageState, StoredMessagePayload};
pub use peeler::TransportPeeler;
pub use storage::{
    CapabilityStorage, GroupStorage, MessageStorage, OutboundIntentStorage, QueuedOutboundIntent,
    StorageError, StorageProvider, StorageResult, WelcomeStorage,
};
pub use transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
pub use transport_adapter::{
    TransportAccountActivation, TransportAdapter, TransportAdapterError, TransportDelivery,
    TransportDeliveryPlane, TransportDeliverySource, TransportEndpoint, TransportEndpointFailure,
    TransportEndpointReceipt, TransportGroupSubscription, TransportGroupSync,
    TransportPublishReport, TransportPublishRequest, TransportPublishTarget,
};
pub use types::{Backend, EpochId, GroupId, MemberId, MessageId};
pub use welcome::PendingWelcome;

// ── Compile-time witnesses ─────────────────────────────────────────────────
//
// If `CgkaEngine` or `TransportPeeler` stop being object-safe and Send, these
// witnesses fail at compile time.
const _: fn(Box<dyn CgkaEngine + Send + Sync>) = |_| {};
const _: fn(Box<dyn TransportPeeler + Send + Sync>) = |_| {};
const _: fn(Box<dyn TransportAdapter + Send + Sync>) = |_| {};
