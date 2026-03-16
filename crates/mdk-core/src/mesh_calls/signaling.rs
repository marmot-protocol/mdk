//! Call signaling events (kinds 450-454)
//!
//! All call signaling is carried as MLS Application Messages inside `kind: 445`
//! Group Events per MIP-03. Inner application messages use unsigned Nostr event
//! kinds 450-454.

use nostr::{Kind, PublicKey, Timestamp};
use serde::{Deserialize, Serialize};

use super::types::{
    CallAction, CallAnswerStatus, CallId, CallType, MeshCallError, SessionDescriptionType,
};

/// Kind 450: Call Initiation
pub const KIND_CALL_INITIATION: Kind = Kind::Custom(450);
/// Kind 451: Call Answer
pub const KIND_CALL_ANSWER: Kind = Kind::Custom(451);
/// Kind 452: WebRTC Session Description
pub const KIND_WEBRTC_SESSION: Kind = Kind::Custom(452);
/// Kind 453: ICE Candidate
pub const KIND_ICE_CANDIDATE: Kind = Kind::Custom(453);
/// Kind 454: Call State Update
pub const KIND_CALL_STATE_UPDATE: Kind = Kind::Custom(454);

/// Base trait for all call signaling events
pub trait CallSignalingEvent {
    /// Get the call ID
    fn call_id(&self) -> &CallId;
    /// Get the event kind
    fn kind() -> Kind;
}

/// Kind 450: Call Initiation Event
///
/// Sent by the caller to start a new call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallInitiationEvent {
    /// Event kind (always 450)
    pub kind: u64,
    /// Unix timestamp
    pub created_at: u64,
    /// Caller's Nostr public key (hex)
    pub pubkey: String,
    /// Empty content
    pub content: String,
    /// Event tags
    pub tags: Vec<Vec<String>>,
}

impl CallInitiationEvent {
    /// Create a new call initiation event
    pub fn new(
        caller_pubkey: &PublicKey,
        call_id: &CallId,
        call_type: CallType,
        sframe_bits: u8,
        turn_uri: Option<&str>,
        turn_username: Option<&str>,
        turn_credential: Option<&str>,
    ) -> Self {
        let mut tags = vec![
            vec!["call_id".to_string(), call_id.to_hex()],
            vec!["call_type".to_string(), match call_type {
                CallType::Audio => "audio".to_string(),
                CallType::Video => "video".to_string(),
            }],
            vec!["sframe_bits".to_string(), sframe_bits.to_string()],
            vec!["codec".to_string(), "audio/opus".to_string()],
            vec!["codec".to_string(), "video/vp8".to_string()],
        ];

        if let (Some(uri), Some(username), Some(cred)) = (turn_uri, turn_username, turn_credential) {
            tags.push(vec!["turn".to_string(), uri.to_string(), username.to_string(), cred.to_string()]);
        }

        Self {
            kind: 450,
            created_at: Timestamp::now().as_secs(),
            pubkey: caller_pubkey.to_hex(),
            content: String::new(),
            tags,
        }
    }

    /// Get the call ID from tags
    pub fn get_call_id(&self) -> Result<CallId, MeshCallError> {
        for tag in &self.tags {
            if tag.len() >= 2 && tag[0] == "call_id" {
                return CallId::from_hex(&tag[1]);
            }
        }
        Err(MeshCallError::Signaling("Missing call_id tag".into()))
    }

    /// Get the call type from tags
    pub fn get_call_type(&self) -> Result<CallType, MeshCallError> {
        for tag in &self.tags {
            if tag.len() >= 2 && tag[0] == "call_type" {
                return match tag[1].as_str() {
                    "audio" => Ok(CallType::Audio),
                    "video" => Ok(CallType::Video),
                    _ => Err(MeshCallError::Signaling("Invalid call_type".into())),
                };
            }
        }
        Err(MeshCallError::Signaling("Missing call_type tag".into()))
    }

    /// Get sframe bits from tags
    pub fn get_sframe_bits(&self) -> Result<u8, MeshCallError> {
        for tag in &self.tags {
            if tag.len() >= 2 && tag[0] == "sframe_bits" {
                return tag[1].parse()
                    .map_err(|_| MeshCallError::Signaling("Invalid sframe_bits".into()));
            }
        }
        Ok(6) // Default
    }
}

/// Kind 451: Call Answer Event
///
/// Sent by callee to accept, decline, or report busy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallAnswerEvent {
    /// Event kind (always 451)
    pub kind: u64,
    /// Unix timestamp
    pub created_at: u64,
    /// Callee's Nostr public key (hex)
    pub pubkey: String,
    /// Empty content
    pub content: String,
    /// Event tags
    pub tags: Vec<Vec<String>>,
}

impl CallAnswerEvent {
    /// Create a new call answer event
    pub fn new(
        callee_pubkey: &PublicKey,
        call_id: &CallId,
        status: CallAnswerStatus,
        reason: Option<&str>,
    ) -> Self {
        let mut tags = vec![
            vec!["call_id".to_string(), call_id.to_hex()],
            vec!["status".to_string(), match status {
                CallAnswerStatus::Accept => "accept".to_string(),
                CallAnswerStatus::Decline => "decline".to_string(),
                CallAnswerStatus::Busy => "busy".to_string(),
            }],
        ];

        if let Some(r) = reason {
            tags.push(vec!["reason".to_string(), r.to_string()]);
        }

        Self {
            kind: 451,
            created_at: Timestamp::now().as_secs(),
            pubkey: callee_pubkey.to_hex(),
            content: String::new(),
            tags,
        }
    }

    /// Get the call ID from tags
    pub fn get_call_id(&self) -> Result<CallId, MeshCallError> {
        for tag in &self.tags {
            if tag.len() >= 2 && tag[0] == "call_id" {
                return CallId::from_hex(&tag[1]);
            }
        }
        Err(MeshCallError::Signaling("Missing call_id tag".into()))
    }

    /// Get the answer status from tags
    pub fn get_status(&self) -> Result<CallAnswerStatus, MeshCallError> {
        for tag in &self.tags {
            if tag.len() >= 2 && tag[0] == "status" {
                return match tag[1].as_str() {
                    "accept" => Ok(CallAnswerStatus::Accept),
                    "decline" => Ok(CallAnswerStatus::Decline),
                    "busy" => Ok(CallAnswerStatus::Busy),
                    _ => Err(MeshCallError::Signaling("Invalid status".into())),
                };
            }
        }
        Err(MeshCallError::Signaling("Missing status tag".into()))
    }

    /// Get the reason from tags (optional)
    pub fn get_reason(&self) -> Option<String> {
        for tag in &self.tags {
            if tag.len() >= 2 && tag[0] == "reason" {
                return Some(tag[1].clone());
            }
        }
        None
    }
}

/// Kind 452: WebRTC Session Description Event
///
/// SDP offer/answer exchange.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebRTCSessionEvent {
    /// Event kind (always 452)
    pub kind: u64,
    /// Unix timestamp
    pub created_at: u64,
    /// Sender's Nostr public key (hex)
    pub pubkey: String,
    /// SDP string
    pub content: String,
    /// Event tags
    pub tags: Vec<Vec<String>>,
}

impl WebRTCSessionEvent {
    /// Create a new WebRTC session event
    pub fn new(
        sender_pubkey: &PublicKey,
        call_id: &CallId,
        sdp_type: SessionDescriptionType,
        sdp: String,
        target_leaf: Option<u32>,
    ) -> Self {
        let mut tags = vec![
            vec!["call_id".to_string(), call_id.to_hex()],
            vec!["sdp_type".to_string(), match sdp_type {
                SessionDescriptionType::Offer => "offer".to_string(),
                SessionDescriptionType::Answer => "answer".to_string(),
            }],
        ];

        if let Some(leaf) = target_leaf {
            tags.push(vec!["target_leaf".to_string(), leaf.to_string()]);
        }

        Self {
            kind: 452,
            created_at: Timestamp::now().as_secs(),
            pubkey: sender_pubkey.to_hex(),
            content: sdp,
            tags,
        }
    }

    /// Get the call ID from tags
    pub fn get_call_id(&self) -> Result<CallId, MeshCallError> {
        for tag in &self.tags {
            if tag.len() >= 2 && tag[0] == "call_id" {
                return CallId::from_hex(&tag[1]);
            }
        }
        Err(MeshCallError::Signaling("Missing call_id tag".into()))
    }

    /// Get the SDP type from tags
    pub fn get_sdp_type(&self) -> Result<SessionDescriptionType, MeshCallError> {
        for tag in &self.tags {
            if tag.len() >= 2 && tag[0] == "sdp_type" {
                return match tag[1].as_str() {
                    "offer" => Ok(SessionDescriptionType::Offer),
                    "answer" => Ok(SessionDescriptionType::Answer),
                    _ => Err(MeshCallError::Signaling("Invalid sdp_type".into())),
                };
            }
        }
        Err(MeshCallError::Signaling("Missing sdp_type tag".into()))
    }

    /// Get the target leaf from tags (optional, None means SFU)
    pub fn get_target_leaf(&self) -> Option<u32> {
        for tag in &self.tags {
            if tag.len() >= 2 && tag[0] == "target_leaf" {
                return tag[1].parse().ok();
            }
        }
        None
    }
}

/// Kind 453: ICE Candidate Event
///
/// Trickle ICE candidate exchange.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ICECandidateEvent {
    /// Event kind (always 453)
    pub kind: u64,
    /// Unix timestamp
    pub created_at: u64,
    /// Sender's Nostr public key (hex)
    pub pubkey: String,
    /// ICE candidate JSON string
    pub content: String,
    /// Event tags
    pub tags: Vec<Vec<String>>,
}

impl ICECandidateEvent {
    /// Create a new ICE candidate event
    pub fn new(
        sender_pubkey: &PublicKey,
        call_id: &CallId,
        candidate: String,
        target_leaf: Option<u32>,
    ) -> Self {
        let mut tags = vec![
            vec!["call_id".to_string(), call_id.to_hex()],
        ];

        if let Some(leaf) = target_leaf {
            tags.push(vec!["target_leaf".to_string(), leaf.to_string()]);
        }

        Self {
            kind: 453,
            created_at: Timestamp::now().as_secs(),
            pubkey: sender_pubkey.to_hex(),
            content: candidate,
            tags,
        }
    }

    /// Get the call ID from tags
    pub fn get_call_id(&self) -> Result<CallId, MeshCallError> {
        for tag in &self.tags {
            if tag.len() >= 2 && tag[0] == "call_id" {
                return CallId::from_hex(&tag[1]);
            }
        }
        Err(MeshCallError::Signaling("Missing call_id tag".into()))
    }

    /// Get the target leaf from tags (optional)
    pub fn get_target_leaf(&self) -> Option<u32> {
        for tag in &self.tags {
            if tag.len() >= 2 && tag[0] == "target_leaf" {
                return tag[1].parse().ok();
            }
        }
        None
    }

    /// Check if this is an end-of-candidates signal
    pub fn is_end_of_candidates(&self) -> bool {
        self.content.is_empty()
    }
}

/// Kind 454: Call State Update Event
///
/// Mute, leave, end, screen share, etc.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallStateUpdateEvent {
    /// Event kind (always 454)
    pub kind: u64,
    /// Unix timestamp
    pub created_at: u64,
    /// Sender's Nostr public key (hex)
    pub pubkey: String,
    /// Empty content (or verification data)
    pub content: String,
    /// Event tags
    pub tags: Vec<Vec<String>>,
}

impl CallStateUpdateEvent {
    /// Create a new call state update event
    pub fn new(
        sender_pubkey: &PublicKey,
        call_id: &CallId,
        action: CallAction,
        reason: Option<&str>,
    ) -> Self {
        let mut tags = vec![
            vec!["call_id".to_string(), call_id.to_hex()],
            vec!["action".to_string(), match action {
                CallAction::MuteAudio => "mute_audio".to_string(),
                CallAction::UnmuteAudio => "unmute_audio".to_string(),
                CallAction::MuteVideo => "mute_video".to_string(),
                CallAction::UnmuteVideo => "unmute_video".to_string(),
                CallAction::Leave => "leave".to_string(),
                CallAction::End => "end".to_string(),
                CallAction::Hold => "hold".to_string(),
                CallAction::Resume => "resume".to_string(),
                CallAction::ScreenShareStart => "screen_share_start".to_string(),
                CallAction::ScreenShareStop => "screen_share_stop".to_string(),
                CallAction::Renegotiate => "renegotiate".to_string(),
                CallAction::SpeakerFocus => "speaker_focus".to_string(),
                CallAction::Verify => "verify".to_string(),
                CallAction::VerifyResponse => "verify_response".to_string(),
            }],
        ];

        if let Some(r) = reason {
            tags.push(vec!["reason".to_string(), r.to_string()]);
        }

        Self {
            kind: 454,
            created_at: Timestamp::now().as_secs(),
            pubkey: sender_pubkey.to_hex(),
            content: String::new(),
            tags,
        }
    }

    /// Get the call ID from tags
    pub fn get_call_id(&self) -> Result<CallId, MeshCallError> {
        for tag in &self.tags {
            if tag.len() >= 2 && tag[0] == "call_id" {
                return CallId::from_hex(&tag[1]);
            }
        }
        Err(MeshCallError::Signaling("Missing call_id tag".into()))
    }

    /// Get the action from tags
    pub fn get_action(&self) -> Result<CallAction, MeshCallError> {
        for tag in &self.tags {
            if tag.len() >= 2 && tag[0] == "action" {
                return match tag[1].as_str() {
                    "mute_audio" => Ok(CallAction::MuteAudio),
                    "unmute_audio" => Ok(CallAction::UnmuteAudio),
                    "mute_video" => Ok(CallAction::MuteVideo),
                    "unmute_video" => Ok(CallAction::UnmuteVideo),
                    "leave" => Ok(CallAction::Leave),
                    "end" => Ok(CallAction::End),
                    "hold" => Ok(CallAction::Hold),
                    "resume" => Ok(CallAction::Resume),
                    "screen_share_start" => Ok(CallAction::ScreenShareStart),
                    "screen_share_stop" => Ok(CallAction::ScreenShareStop),
                    "renegotiate" => Ok(CallAction::Renegotiate),
                    "speaker_focus" => Ok(CallAction::SpeakerFocus),
                    "verify" => Ok(CallAction::Verify),
                    "verify_response" => Ok(CallAction::VerifyResponse),
                    _ => Err(MeshCallError::Signaling("Invalid action".into())),
                };
            }
        }
        Err(MeshCallError::Signaling("Missing action tag".into()))
    }

    /// Get the reason from tags (optional)
    pub fn get_reason(&self) -> Option<String> {
        for tag in &self.tags {
            if tag.len() >= 2 && tag[0] == "reason" {
                return Some(tag[1].clone());
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::Keys;

    #[test]
    fn test_call_initiation_event() {
        let keys = Keys::generate();
        let call_id = CallId::new();

        let event = CallInitiationEvent::new(
            &keys.public_key(),
            &call_id,
            CallType::Video,
            6,
            None,
            None,
            None,
        );

        assert_eq!(event.kind, 450);
        assert_eq!(event.pubkey, keys.public_key().to_hex());
        assert_eq!(event.get_call_id().unwrap(), call_id);
        assert!(matches!(event.get_call_type().unwrap(), CallType::Video));
        assert_eq!(event.get_sframe_bits().unwrap(), 6);
    }

    #[test]
    fn test_call_answer_event() {
        let keys = Keys::generate();
        let call_id = CallId::new();

        let event = CallAnswerEvent::new(
            &keys.public_key(),
            &call_id,
            CallAnswerStatus::Accept,
            None,
        );

        assert_eq!(event.kind, 451);
        assert!(matches!(event.get_status().unwrap(), CallAnswerStatus::Accept));
    }

    #[test]
    fn test_webrtc_session_event() {
        let keys = Keys::generate();
        let call_id = CallId::new();

        let event = WebRTCSessionEvent::new(
            &keys.public_key(),
            &call_id,
            SessionDescriptionType::Offer,
            "v=0\r\n...".to_string(),
            Some(3),
        );

        assert_eq!(event.kind, 452);
        assert!(matches!(event.get_sdp_type().unwrap(), SessionDescriptionType::Offer));
        assert_eq!(event.get_target_leaf(), Some(3));
        assert_eq!(event.content, "v=0\r\n...");
    }

    #[test]
    fn test_ice_candidate_event() {
        let keys = Keys::generate();
        let call_id = CallId::new();

        let event = ICECandidateEvent::new(
            &keys.public_key(),
            &call_id,
            "{\"candidate\":\"candidate:...\"}".to_string(),
            Some(3),
        );

        assert_eq!(event.kind, 453);
        assert_eq!(event.get_target_leaf(), Some(3));
        assert!(!event.is_end_of_candidates());

        // Test end of candidates
        let end_event = ICECandidateEvent::new(
            &keys.public_key(),
            &call_id,
            String::new(),
            None,
        );
        assert!(end_event.is_end_of_candidates());
    }

    #[test]
    fn test_call_state_update_event() {
        let keys = Keys::generate();
        let call_id = CallId::new();

        let event = CallStateUpdateEvent::new(
            &keys.public_key(),
            &call_id,
            CallAction::MuteAudio,
            Some("background noise"),
        );

        assert_eq!(event.kind, 454);
        assert!(matches!(event.get_action().unwrap(), CallAction::MuteAudio));
        assert_eq!(event.get_reason(), Some("background noise".to_string()));
    }
}
