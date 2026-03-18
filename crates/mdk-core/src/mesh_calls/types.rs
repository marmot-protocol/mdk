//! Core types for mesh calls

use nostr::PublicKey;
use serde::{Deserialize, Serialize};

/// Unique identifier for a call (32 bytes random)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CallId([u8; 32]);

impl CallId {
    /// Create a new random call ID
    pub fn new() -> Self {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).expect("Failed to generate random call ID");
        Self(bytes)
    }

    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get the bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Get as hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse from hex string
    pub fn from_hex(hex: &str) -> Result<Self, MeshCallError> {
        let bytes = hex::decode(hex)
            .map_err(|_| MeshCallError::InvalidCallId)?;
        if bytes.len() != 32 {
            return Err(MeshCallError::InvalidCallId);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

impl Default for CallId {
    fn default() -> Self {
        Self::new()
    }
}

/// Type of call (audio or video)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CallType {
    /// Audio-only call
    Audio,
    /// Video call (includes audio)
    Video,
}

impl CallType {
    /// Maximum participants for mesh topology
    pub fn max_mesh_participants(&self) -> usize {
        match self {
            CallType::Audio => 8,
            CallType::Video => 4,
        }
    }
}

impl Default for CallType {
    fn default() -> Self {
        CallType::Video
    }
}

/// Media type for SFrame encryption
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MediaType {
    /// Audio (0x00)
    Audio = 0x00,
    /// Video (0x01)
    Video = 0x01,
    /// Screen share (0x02)
    ScreenShare = 0x02,
}

impl MediaType {
    /// Get the byte value
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }

    /// Parse from byte
    pub fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            0x00 => Some(MediaType::Audio),
            0x01 => Some(MediaType::Video),
            0x02 => Some(MediaType::ScreenShare),
            _ => None,
        }
    }
}

/// SFrame bits configuration for KID structure
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SFrameBits {
    /// Number of bits for epoch (default: 4)
    pub(crate) epoch_bits: u8,
    /// Number of bits for sender leaf index (default: 6)
    pub(crate) sender_bits: u8,
}

impl SFrameBits {
    /// Get epoch bits
    pub fn epoch_bits(&self) -> u8 { self.epoch_bits }
    /// Get sender bits
    pub fn sender_bits(&self) -> u8 { self.sender_bits }
}

impl Default for SFrameBits {
    fn default() -> Self {
        Self {
            epoch_bits: 4,
            sender_bits: 6,
        }
    }
}

impl SFrameBits {

    /// Create with custom values.
    /// Returns error if bits are out of range (both must be > 0, sum <= 62).
    pub fn new(epoch_bits: u8, sender_bits: u8) -> Result<Self, MeshCallError> {
        if epoch_bits == 0 || sender_bits == 0 {
            return Err(MeshCallError::InvalidSFrameConfig);
        }
        if (epoch_bits as u16) + (sender_bits as u16) > 62 {
            return Err(MeshCallError::InvalidSFrameConfig);
        }
        Ok(Self {
            epoch_bits,
            sender_bits,
        })
    }

    /// Calculate KID from components.
    /// Returns error if sender_leaf or epoch exceed their bit widths.
    pub fn make_kid(&self, media_type: MediaType, sender_leaf: u32, epoch: u8) -> Result<u64, MeshCallError> {
        let e = self.epoch_bits as u64;
        let s = self.sender_bits as u64;
        if sender_leaf as u64 >= (1u64 << s) {
            return Err(MeshCallError::InvalidKid);
        }
        if epoch as u64 >= (1u64 << e) {
            return Err(MeshCallError::InvalidKid);
        }
        let media = (media_type.as_u8() as u64) << (s + e);
        let sender = (sender_leaf as u64) << e;
        let epoch = epoch as u64;
        Ok(media | sender | epoch)
    }

    /// Serialize to wire format "epoch:sender"
    pub fn to_wire(&self) -> String {
        format!("{}:{}", self.epoch_bits, self.sender_bits)
    }

    /// Parse from wire format. Supports "epoch:sender" and legacy single-value format.
    pub fn from_wire_str(s: &str) -> Result<Self, MeshCallError> {
        if let Some((epoch_str, sender_str)) = s.split_once(':') {
            let epoch_bits: u8 = epoch_str.parse()
                .map_err(|_| MeshCallError::Signaling("Invalid sframe_bits epoch".into()))?;
            let sender_bits: u8 = sender_str.parse()
                .map_err(|_| MeshCallError::Signaling("Invalid sframe_bits sender".into()))?;
            Self::new(epoch_bits, sender_bits)
        } else {
            // Legacy: single value = epoch_bits(4) + sender_bits
            let total: u8 = s.parse()
                .map_err(|_| MeshCallError::Signaling("Invalid sframe_bits".into()))?;
            let sender = total.saturating_sub(4);
            if sender == 0 {
                // Legacy value too small for valid config — use default
                Ok(Self::default())
            } else {
                Self::new(4, sender)
            }
        }
    }

    /// Parse KID into components
    pub fn parse_kid(&self, kid: u64) -> Result<(MediaType, u32, u8), MeshCallError> {
        let e = self.epoch_bits as u64;
        let s = self.sender_bits as u64;
        let epoch = (kid & ((1u64 << e) - 1)) as u8;
        let sender = ((kid >> e) & ((1u64 << s) - 1)) as u32;
        let media_byte = (kid >> (s + e)) as u8;
        let media_type = MediaType::from_u8(media_byte)
            .ok_or(MeshCallError::InvalidMediaType)?;
        Ok((media_type, sender, epoch))
    }
}

/// State of a call
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallState {
    /// Call is being set up
    Setup,
    /// Call is ringing/waiting for answer
    Ringing,
    /// Call is active
    Active,
    /// Call is on hold
    OnHold,
    /// Call is ending
    Ending,
    /// Call has ended
    Ended,
}

/// Information about a call participant
#[derive(Debug, Clone)]
pub struct CallParticipant {
    /// Nostr public key
    pub pubkey: PublicKey,
    /// MLS leaf index
    pub leaf_index: u32,
    /// Whether audio is muted
    pub audio_muted: bool,
    /// Whether video is muted
    pub video_muted: bool,
    /// Whether this participant is sharing screen
    pub screen_sharing: bool,
    /// Whether this participant is the active speaker
    pub is_speaking: bool,
}

/// Call initiation parameters
#[derive(Debug, Clone)]
pub struct CallInitiation {
    /// Type of call
    pub call_type: CallType,
    /// SFrame bits configuration
    pub sframe_bits: SFrameBits,
    /// Preferred audio codec
    pub audio_codec: String,
    /// Preferred video codec
    pub video_codec: String,
    /// TURN server URI (optional)
    pub turn_uri: Option<String>,
    /// TURN username (optional)
    pub turn_username: Option<String>,
    /// TURN credential (optional)
    pub turn_credential: Option<String>,
}

impl CallInitiation {
    /// Create a new video call with defaults
    pub fn new_video() -> Self {
        Self {
            call_type: CallType::Video,
            sframe_bits: SFrameBits::default(),
            audio_codec: "audio/opus".to_string(),
            video_codec: "video/vp8".to_string(),
            turn_uri: None,
            turn_username: None,
            turn_credential: None,
        }
    }

    /// Create a new audio call with defaults
    pub fn new_audio() -> Self {
        Self {
            call_type: CallType::Audio,
            sframe_bits: SFrameBits::default(),
            audio_codec: "audio/opus".to_string(),
            video_codec: "video/vp8".to_string(),
            turn_uri: None,
            turn_username: None,
            turn_credential: None,
        }
    }
}

/// Status of a call answer
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CallAnswerStatus {
    /// Call was accepted
    Accept,
    /// Call was declined
    Decline,
    /// User is busy
    Busy,
}

/// Call answer parameters
#[derive(Debug, Clone)]
pub struct CallAnswer {
    /// Answer status
    pub status: CallAnswerStatus,
    /// Optional reason
    pub reason: Option<String>,
}

impl CallAnswer {
    /// Accept the call
    pub fn accept() -> Self {
        Self {
            status: CallAnswerStatus::Accept,
            reason: None,
        }
    }

    /// Decline the call
    pub fn decline(reason: impl Into<String>) -> Self {
        Self {
            status: CallAnswerStatus::Decline,
            reason: Some(reason.into()),
        }
    }

    /// Busy status
    pub fn busy() -> Self {
        Self {
            status: CallAnswerStatus::Busy,
            reason: None,
        }
    }
}

/// WebRTC session description (SDP)
#[derive(Debug, Clone)]
pub struct WebRTCSessionDescription {
    /// SDP type (offer or answer)
    pub sdp_type: SessionDescriptionType,
    /// SDP string
    pub sdp: String,
    /// Target leaf index (for peer-to-peer) or "sfu" for SFU mode
    pub target_leaf: Option<u32>,
}

/// Type of session description
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionDescriptionType {
    /// SDP offer
    Offer,
    /// SDP answer
    Answer,
}

/// ICE candidate for WebRTC
#[derive(Debug, Clone)]
pub struct ICECandidate {
    /// ICE candidate JSON string
    pub candidate: String,
    /// Target leaf index
    pub target_leaf: Option<u32>,
}

/// Call action types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallAction {
    /// Mute audio
    MuteAudio,
    /// Unmute audio
    UnmuteAudio,
    /// Mute video
    MuteVideo,
    /// Unmute video
    UnmuteVideo,
    /// Leave call
    Leave,
    /// End call
    End,
    /// Hold call
    Hold,
    /// Resume call
    Resume,
    /// Start screen share
    ScreenShareStart,
    /// Stop screen share
    ScreenShareStop,
    /// Renegotiate
    Renegotiate,
    /// Speaker focus
    SpeakerFocus,
    /// Verification challenge
    Verify,
    /// Verification response
    VerifyResponse,
}

/// Call state update
#[derive(Debug, Clone)]
pub struct CallStateUpdate {
    /// Action type
    pub action: CallAction,
    /// Optional reason or additional data
    pub reason: Option<String>,
}

/// Errors that can occur in mesh calls
#[derive(Debug, thiserror::Error)]
pub enum MeshCallError {
    /// Invalid call ID
    #[error("invalid call ID")]
    InvalidCallId,

    /// Call not found
    #[error("call not found")]
    CallNotFound,

    /// Call already exists
    #[error("call already exists")]
    CallAlreadyExists,

    /// Group not found
    #[error("group not found")]
    GroupNotFound,

    /// Not a member of the group
    #[error("not a member of the group")]
    NotGroupMember,

    /// Invalid SFrame configuration
    #[error("invalid SFrame configuration")]
    InvalidSFrameConfig,

    /// Too many participants for mesh
    #[error("too many participants for mesh topology: {0}")]
    TooManyParticipants(usize),

    /// WebRTC error
    #[error("WebRTC error: {0}")]
    WebRTC(String),

    /// SFrame encryption error
    #[error("SFrame encryption error: {0}")]
    SFrameEncryption(String),

    /// SFrame decryption error
    #[error("SFrame decryption error: {0}")]
    SFrameDecryption(String),

    /// Key derivation error
    #[error("key derivation error: {0}")]
    KeyDerivation(String),

    /// Signaling error
    #[error("signaling error: {0}")]
    Signaling(String),

    /// Invalid media type
    #[error("invalid media type")]
    InvalidMediaType,

    /// Invalid KID
    #[error("invalid KID")]
    InvalidKid,

    /// Epoch mismatch
    #[error("epoch mismatch: expected {expected}, got {received}")]
    EpochMismatch {
        /// Expected epoch
        expected: u8,
        /// Received epoch
        received: u8,
    },

    /// Unsupported codec
    #[error("unsupported codec: {0}")]
    UnsupportedCodec(String),

    /// SDP parsing error
    #[error("SDP parsing error: {0}")]
    SdpParseError(String),

    /// ICE error
    #[error("ICE error: {0}")]
    IceError(String),

    /// Not implemented
    #[error("not implemented: {0}")]
    NotImplemented(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_call_id_generation() {
        let id1 = CallId::new();
        let id2 = CallId::new();
        assert_ne!(id1, id2);
        assert_eq!(id1.as_bytes().len(), 32);
    }

    #[test]
    fn test_call_id_hex_roundtrip() {
        let id = CallId::new();
        let hex = id.to_hex();
        let id2 = CallId::from_hex(&hex).unwrap();
        assert_eq!(id, id2);
    }

    #[test]
    fn test_media_type_roundtrip() {
        assert_eq!(MediaType::from_u8(0x00), Some(MediaType::Audio));
        assert_eq!(MediaType::from_u8(0x01), Some(MediaType::Video));
        assert_eq!(MediaType::from_u8(0x02), Some(MediaType::ScreenShare));
        assert_eq!(MediaType::from_u8(0xFF), None);
    }

    #[test]
    fn test_sframe_bits_kid_encoding() {
        let bits = SFrameBits::default(); // E=4, S=6
        
        // Test KID encoding (from MIP-06 test vectors)
        let kid = bits.make_kid(MediaType::Audio, 3, 0).unwrap();
        assert_eq!(kid, 48); // 0x0030

        let kid = bits.make_kid(MediaType::Audio, 3, 14).unwrap();
        assert_eq!(kid, 62); // 0x003e

        let kid = bits.make_kid(MediaType::Video, 3, 14).unwrap();
        assert_eq!(kid, 1086); // 0x043e

        let kid = bits.make_kid(MediaType::ScreenShare, 3, 14).unwrap();
        assert_eq!(kid, 2110); // 0x083e

        let kid = bits.make_kid(MediaType::Audio, 63, 15).unwrap();
        assert_eq!(kid, 1023); // 0x03ff

        // Overflow must fail
        assert!(bits.make_kid(MediaType::Audio, 64, 0).is_err());
        assert!(bits.make_kid(MediaType::Audio, 0, 16).is_err());
    }

    #[test]
    fn test_sframe_bits_kid_parsing() {
        let bits = SFrameBits::default();

        // Parse KID=48 (0x0030)
        let (media, sender, epoch) = bits.parse_kid(48).unwrap();
        assert_eq!(media, MediaType::Audio);
        assert_eq!(sender, 3);
        assert_eq!(epoch, 0);

        // Parse KID=1086 (0x043e)
        let (media, sender, epoch) = bits.parse_kid(1086).unwrap();
        assert_eq!(media, MediaType::Video);
        assert_eq!(sender, 3);
        assert_eq!(epoch, 14);

        // Parse KID=2110 (0x083e)
        let (media, sender, epoch) = bits.parse_kid(2110).unwrap();
        assert_eq!(media, MediaType::ScreenShare);
        assert_eq!(sender, 3);
        assert_eq!(epoch, 14);
    }

    #[test]
    fn test_call_type_max_participants() {
        assert_eq!(CallType::Audio.max_mesh_participants(), 8);
        assert_eq!(CallType::Video.max_mesh_participants(), 4);
    }
}
