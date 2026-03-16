//! Mesh Calls module for MIP-06 Group Voice & Video Calling
//!
//! This module implements Tier 1 mesh calling (2-4 participants for video, 2-8 for audio)
//! using WebRTC with SFrame end-to-end encryption derived from MLS group state.
//!
//! ## Architecture
//!
//! - **SFrame Encryption**: Media frames are encrypted using SFrame (RFC 9605) with keys
//!   derived from the MLS exporter secret.
//! - **Mesh Topology**: Each participant sends media directly to all other participants
//!   without an SFU (Selective Forwarding Unit).
//! - **Signaling**: Call setup and control messages are sent via MLS application messages
//!   (kinds 450-454).
//!
//! ## Example Usage
//!
//! ```rust,ignore
//! use mdk_core::MDK;
//! use mdk_core::mesh_calls::{MeshCallManager, CallInitiation};
//!
//! // Create mesh call manager from MDK instance
//! let call_manager = mdk.mesh_call_manager();
//!
//! // Initiate a call
//! let call_id = call_manager.initiate_call(
//!     &group_id,
//!     CallInitiation::new_video(),
//! ).await?;
//! ```

mod types;
mod sframe;
pub mod keys;
mod signaling;
pub mod webrtc;
mod manager;
pub mod codec;

// Re-export public API
pub use types::{
    CallId, CallType, MediaType, CallState, CallParticipant, SFrameBits,
    CallInitiation, CallAnswer, CallAnswerStatus, WebRTCSessionDescription,
    SessionDescriptionType, ICECandidate, CallStateUpdate, CallAction,
};
pub use manager::{MeshCallManager, ActiveCall, OutboundSignaling, CallEventCallback};
pub use sframe::{SFrameContext, SFrameKey, SFrameCounter, derive_sframe_base_key, derive_sframe_key, encode_header, parse_header};
pub use keys::{CallKeyDerivation, SfuAuthToken};
pub use signaling::{
    CallSignalingEvent, CallInitiationEvent, CallAnswerEvent,
    WebRTCSessionEvent, ICECandidateEvent, CallStateUpdateEvent,
    KIND_CALL_INITIATION, KIND_CALL_ANSWER, KIND_WEBRTC_SESSION,
    KIND_ICE_CANDIDATE, KIND_CALL_STATE_UPDATE,
};

// Re-export errors
pub use types::MeshCallError;
