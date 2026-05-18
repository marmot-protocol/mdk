//! # cgka-traits
//!
//! Shared trait surface and cross-boundary value types for the CGKA engine,
//! transport peeler, and storage backends.
//!
//! This crate is the one dependency anything crossing a seam should import.

pub mod agent_text_stream;
pub mod app_components;
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

pub use agent_text_stream::{
    AGENT_TEXT_STREAM_APP_PAYLOAD_V1, AGENT_TEXT_STREAM_KEY_CONTEXT_VERSION,
    AGENT_TEXT_STREAM_MAX_PADDING_BUCKET_BYTES, AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN,
    AGENT_TEXT_STREAM_MAX_REPLAY_TTL_SECS, AGENT_TEXT_STREAM_MAX_STREAM_ID_LEN,
    AGENT_TEXT_STREAM_QUIC_FANOUT_FEATURE, AGENT_TEXT_STREAM_QUIC_RECEIVE_FEATURE,
    AGENT_TEXT_STREAM_QUIC_SEND_FEATURE, AGENT_TEXT_STREAM_RECORD_ABORT,
    AGENT_TEXT_STREAM_RECORD_CHECKPOINT, AGENT_TEXT_STREAM_RECORD_FINAL_NOTICE,
    AGENT_TEXT_STREAM_RECORD_STATUS, AGENT_TEXT_STREAM_RECORD_TEXT_DELTA,
    AGENT_TEXT_STREAM_RECORD_TOOL_DELTA, AGENT_TEXT_STREAM_RECORD_VERSION,
    AGENT_TEXT_STREAM_ROLE_FANOUT, AGENT_TEXT_STREAM_ROLE_MASK, AGENT_TEXT_STREAM_ROLE_RECEIVE,
    AGENT_TEXT_STREAM_ROLE_SEND, AGENT_TEXT_STREAM_ROUTE_BROKERED_QUIC,
    AGENT_TEXT_STREAM_ROUTE_DIRECT_QUIC, AGENT_TEXT_STREAM_ROUTE_MASK,
    AGENT_TEXT_STREAM_TRANSCRIPT_HASH_CONTEXT, AgentTextStreamAppPayloadEnvelopeV1,
    AgentTextStreamAppPayloadError, AgentTextStreamAppPayloadV1, AgentTextStreamFinalPayloadV1,
    AgentTextStreamFinalV1, AgentTextStreamKeyContextV1, AgentTextStreamPolicyError,
    AgentTextStreamQuicPolicyV1, AgentTextStreamRecordError, AgentTextStreamRecordV1,
    AgentTextStreamRouteV1, AgentTextStreamStartPayloadV1, AgentTextStreamTranscriptV1,
};
pub use app_components::{
    AGENT_TEXT_STREAM_QUIC_COMPONENT, AGENT_TEXT_STREAM_QUIC_COMPONENT_ID,
    APP_COMPONENTS_COMPONENT_ID, AppComponentData, AppComponentId, AppComponentSet,
    GROUP_ADMIN_POLICY_COMPONENT, GROUP_ADMIN_POLICY_COMPONENT_ID, GROUP_BLOSSOM_IMAGE_COMPONENT,
    GROUP_BLOSSOM_IMAGE_COMPONENT_ID, GROUP_MESSAGE_RETENTION_COMPONENT,
    GROUP_MESSAGE_RETENTION_COMPONENT_ID, GROUP_PROFILE_COMPONENT, GROUP_PROFILE_COMPONENT_ID,
    NOSTR_ROUTING_COMPONENT, NOSTR_ROUTING_COMPONENT_ID, NostrRoutingV1, decode_components_list,
    decode_nostr_routing_v1, decode_quic_varint, default_group_components,
    encode_component_vectors, encode_components_list, encode_nostr_routing_v1,
};
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
