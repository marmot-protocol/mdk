//! # cgka-traits
//!
//! Shared trait surface and cross-boundary value types for the CGKA engine,
//! transport peeler, and storage backends.
//!
//! This crate is the one dependency anything crossing a seam should import.

pub mod agent_events;
pub mod agent_text_stream;
pub mod app_components;
pub mod app_event;
pub mod capabilities;
pub mod convergence_pass;
pub mod engine;
pub mod engine_state;
pub mod error;
pub mod group;
pub mod group_context;
pub mod group_recovery;
pub mod ingest;
pub mod maintenance;
pub mod message;
pub mod peeler;
pub mod polls;
pub mod storage;
pub mod threads;
pub mod transport;
pub mod transport_adapter;
pub mod types;
pub mod welcome;

pub use agent_events::{
    AGENT_EVENT_MAX_BYTES, AgentEventError, AgentItem, AgentItemState, AgentRequest,
    MARMOT_APP_EVENT_KIND_AGENT_ITEM, MARMOT_APP_EVENT_KIND_AGENT_REQUEST, agent_item_reply_target,
    agent_item_thread_parent, is_agent_own_thread_comment,
};
pub use agent_text_stream::{
    AGENT_TEXT_STREAM_COMPONENT_STATE_LEN, AGENT_TEXT_STREAM_MAX_PADDING_BUCKET_BYTES,
    AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN, AGENT_TEXT_STREAM_MAX_REPLAY_TTL_SECS,
    AGENT_TEXT_STREAM_QUIC_FANOUT_FEATURE, AGENT_TEXT_STREAM_QUIC_RECEIVE_FEATURE,
    AGENT_TEXT_STREAM_QUIC_SEND_FEATURE, AGENT_TEXT_STREAM_ROLE_FANOUT,
    AGENT_TEXT_STREAM_ROLE_MASK, AGENT_TEXT_STREAM_ROLE_RECEIVE, AGENT_TEXT_STREAM_ROLE_SEND,
    AgentTextStreamPolicyError, AgentTextStreamQuicPolicyV1,
};
pub use app_components::{
    AGENT_TEXT_STREAM_QUIC_COMPONENT, AGENT_TEXT_STREAM_QUIC_COMPONENT_ID,
    APP_COMPONENTS_COMPONENT_ID, AppComponentData, AppComponentId, AppComponentSet,
    GROUP_ADMIN_POLICY_COMPONENT, GROUP_ADMIN_POLICY_COMPONENT_ID, GROUP_BLOSSOM_IMAGE_COMPONENT,
    GROUP_BLOSSOM_IMAGE_COMPONENT_ID, GROUP_MESSAGE_RETENTION_COMPONENT,
    GROUP_MESSAGE_RETENTION_COMPONENT_ID, GROUP_PROFILE_COMPONENT, GROUP_PROFILE_COMPONENT_ID,
    NOSTR_ROUTING_COMPONENT, NOSTR_ROUTING_COMPONENT_ID, NostrRoutingV1, SAFE_AAD_COMPONENT_ID,
    decode_components_list, decode_nostr_routing_v1, decode_quic_varint, default_group_components,
    encode_component_vectors, encode_components_list, encode_nostr_routing_v1,
};
pub use app_event::{
    AppMessageRetentionDecision, EVENT_REF_TAG, GROUP_SYSTEM_TYPE_GROUP_DISBANDED,
    GROUP_SYSTEM_TYPE_TAG, MARMOT_APP_EVENT_KIND_AGENT_STREAM_START, MARMOT_APP_EVENT_KIND_CHAT,
    MARMOT_APP_EVENT_KIND_DELETE, MARMOT_APP_EVENT_KIND_GROUP_SYSTEM,
    MARMOT_APP_EVENT_KIND_REACTION, MarmotAppEvent, MarmotAppEventError, QUOTE_REF_TAG,
    canonical_event_id, group_system_canonical_id, group_system_event_material,
};
pub use capabilities::{
    Capability, CapabilityRequirement, Feature, FeatureStatus, GroupCapabilities, RequirementLevel,
    TransportKind,
};
pub use convergence_pass::{
    ConvergenceCutoffCause, ConvergencePassMember, ConvergencePassMemberRole, ConvergencePassPhase,
    ConvergencePassRetry, ConvergencePassStep, DurableConvergencePass,
};
pub use engine::{
    AutoPublish, CgkaEngine, CommitOrderingKey, CommitOrderingPriority, CreateGroupRequest,
    EncryptedMediaSecret, EpochPin, GroupEvent, GroupStateChange, KeyPackage, KeyPackageSource,
    OutboundWelcome, SealedWelcome, SendAcceptDisposition, SendIntent, SendResult, WelcomeMetadata,
};
pub use engine_state::{
    Disbanded, EpochState, GroupLifecycleState, InvalidTransition, Merging, PendingPublish,
    PendingStateRef, PendingWelcomeState, Recovering, StagedCommitHandle, WelcomeState,
};
pub use error::{EngineError, PeelerError};
pub use group::{DisbandTombstone, Group, Member};
pub use group_context::{GroupContext, GroupContextSnapshot, SecretBytes};
pub use group_recovery::{
    AuthenticatedGroupRecovery, GroupMemberRecovery, GroupRecoveryBody, GroupRecoveryMessage,
    GroupRecoverySource, MAX_GROUP_RECOVERY_BODY_BYTES, MAX_GROUP_RECOVERY_GROUP_ID_BYTES,
    MAX_GROUP_RECOVERY_KEY_PACKAGE_BYTES, group_recovery_grant_bytes,
};
pub use ingest::{
    DeferredStallEvidence, DeferredStallRow, IngestOutcome, InputRejectionCategory,
    LocalIngestState, PeeledContent, PeeledMessage, ProposalRejectionCategory, StaleReason,
};
pub use maintenance::{
    DurableGroupEvolution, DurableTransportFanout, EntropySource, GroupEvolutionPhase,
    GroupEvolutionSemantic, GroupMaintenanceState, GroupMaintenanceStatus,
    KEY_PACKAGE_REPLACEMENT_GRACE_SECS, KeyPackageLifecycleState, MaintenanceObligation,
    MaintenancePhase, MaintenanceRunSummary, MaintenanceTrigger, MonotonicClock, OsEntropy,
    PendingKeyPackageReplacement, PeriodicMaintenancePolicy, PostJoinHistoryFetch,
    PostJoinHistoryFetchCompletion, PostJoinHistoryFetchOutcome, RetainedKeyPackagePrivateMaterial,
    SendMaintenanceDisposition, SignedPublicationArtifact, SystemWallClock,
    TransportFanoutAttemptState, TransportFanoutTarget, WallClock,
};
pub use message::{
    MessageRecord, MessageState, OwnApplicationConvergenceStamp, OwnCommitConvergenceStamp,
    StoredMessagePayload,
};
pub use peeler::{GroupMessageMetadata, InboxSealer, TransportPeeler};
pub use polls::{
    MARMOT_APP_EVENT_KIND_POLL, MARMOT_APP_EVENT_KIND_POLL_RESPONSE, PollDefinition, PollError,
    PollOptionDefinition, PollOptionResult, PollProjection, PollType, PollVote, PollVotePage,
    parse_poll, parse_poll_response, poll_response_tags, poll_tags, validate_poll_response,
    validate_poll_selection,
};
pub use storage::{
    CapabilityStorage, CommittedMembers, CommittedRoster, CommittedRosterStorage,
    CommittedRosterWrite, ConvergencePassStorage, DisbandCandidate, DisbandCandidateStorage,
    DisbandFailureReason, DisbandRequest, DisbandRequestStatus, DisbandRequestStorage,
    DisbandTombstoneStorage, GroupStorage, LeaveRequest, LeaveRequestStorage, MaintenanceStorage,
    MessageStorage, OpenMlsContentFilter, OutboundFanoutStorage, OutboundIntentStorage,
    QueuedOutboundIntent, RosterRevision, StorageError, StorageProvider, StorageResult,
    WelcomeStorage,
};
pub use threads::{
    NIP22_COMMENT_KIND, is_chat_message, is_nip22_comment, thread_message_parent, thread_root_tag,
};
pub use transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
pub use transport_adapter::{
    CommitRefusalCause, EventSizeClass, FanoutAcknowledgement, FanoutMlsState, FanoutPendingKind,
    FanoutTargetStatus, OutboundApplicationMessage, OutboundFanout, OutboundFanoutOutcome,
    OversizedArtifact, PublicationObservation, RefusedTarget, TransportAccountActivation,
    TransportAdapter, TransportAdapterError, TransportDelivery, TransportDeliveryPlane,
    TransportDeliverySource, TransportEndpoint, TransportEndpointAckKind, TransportEndpointFailure,
    TransportEndpointFailureKind, TransportEndpointReceipt, TransportEndpointRejectionCategory,
    TransportGroupSubscription, TransportGroupSync, TransportPublishFailure,
    TransportPublishReport, TransportPublishRequest, TransportPublishTarget, TransportReadBack,
    TransportWireMetadata, WelcomeSizeCheck, collapse_publish_failure_summaries,
};
pub use types::{Backend, EpochId, GroupId, MemberId, MessageId};
pub use welcome::PendingWelcome;

pub mod reporting;
