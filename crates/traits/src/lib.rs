//! # cgka-traits
//!
//! Shared trait surface and cross-boundary value types for the CGKA engine,
//! transport peeler, and storage backends.
//!
//! This crate is the one dependency anything crossing a seam should import.

pub mod agent_text_stream;
pub mod app_components;
pub mod app_event;
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
    AGENT_TEXT_STREAM_COMPONENT_STATE_LEN, AGENT_TEXT_STREAM_EXPORTER_CACHE_KEY,
    AGENT_TEXT_STREAM_KEY_CONTEXT_VERSION, AGENT_TEXT_STREAM_MAX_PADDING_BUCKET_BYTES,
    AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN, AGENT_TEXT_STREAM_MAX_REPLAY_TTL_SECS,
    AGENT_TEXT_STREAM_MAX_STREAM_ID_LEN, AGENT_TEXT_STREAM_QUIC_FANOUT_FEATURE,
    AGENT_TEXT_STREAM_QUIC_RECEIVE_FEATURE, AGENT_TEXT_STREAM_QUIC_SEND_FEATURE,
    AGENT_TEXT_STREAM_RECORD_ABORT, AGENT_TEXT_STREAM_RECORD_CHECKPOINT,
    AGENT_TEXT_STREAM_RECORD_FINAL_NOTICE, AGENT_TEXT_STREAM_RECORD_PROGRESS_DELTA,
    AGENT_TEXT_STREAM_RECORD_STATUS, AGENT_TEXT_STREAM_RECORD_TEXT_DELTA,
    AGENT_TEXT_STREAM_RECORD_VERSION, AGENT_TEXT_STREAM_ROLE_FANOUT, AGENT_TEXT_STREAM_ROLE_MASK,
    AGENT_TEXT_STREAM_ROLE_RECEIVE, AGENT_TEXT_STREAM_ROLE_SEND,
    AGENT_TEXT_STREAM_TRANSCRIPT_HASH_CONTEXT, AgentTextStreamKeyContextV1,
    AgentTextStreamPolicyError, AgentTextStreamQuicPolicyV1, AgentTextStreamRecordError,
    AgentTextStreamRecordV1, AgentTextStreamTranscriptV1,
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
pub use app_event::{
    AGENT_ACTIVITY_STATUS_TAG, AGENT_OPERATION_NAME_TAG, AGENT_OPERATION_STATUS_TAG,
    AGENT_OPERATION_TYPE_TAG, EVENT_REF_TAG, GROUP_SYSTEM_TYPE_TAG,
    MARMOT_APP_EVENT_KIND_AGENT_ACTIVITY, MARMOT_APP_EVENT_KIND_AGENT_OPERATION,
    MARMOT_APP_EVENT_KIND_AGENT_STREAM_START, MARMOT_APP_EVENT_KIND_CHAT,
    MARMOT_APP_EVENT_KIND_DELETE, MARMOT_APP_EVENT_KIND_GROUP_SYSTEM,
    MARMOT_APP_EVENT_KIND_REACTION, MarmotAppEvent, MarmotAppEventError, QUOTE_REF_TAG,
    STREAM_BROKER_TAG, STREAM_CHUNKS_TAG, STREAM_FINAL_KIND_TAG, STREAM_HASH_TAG,
    STREAM_PARENT_TAG, STREAM_ROUTE_TAG, STREAM_START_TAG, STREAM_TAG, STREAM_TYPE_TAG,
    canonical_event_id,
};
pub use capabilities::{
    Capability, CapabilityRequirement, Feature, FeatureStatus, GroupCapabilities, RequirementLevel,
    TransportKind,
};
pub use engine::{
    AutoPublish, CgkaEngine, CommitOrderingKey, CommitOrderingPriority, CreateGroupRequest,
    GroupEvent, GroupStateChange, KeyPackage, KeyPackageSource, SendIntent, SendResult,
    WelcomeMetadata,
};
pub use engine_state::{
    EpochState, InvalidTransition, Merging, PendingPublish, PendingStateRef, PendingWelcomeState,
    Recovering, StagedCommitHandle, WelcomeState,
};
pub use error::{EngineError, PeelerError};
pub use group::{Group, Member};
pub use group_context::{GroupContext, GroupContextSnapshot, SecretBytes};
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
