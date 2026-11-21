//! The retired agent text stream component (`0x8006`,
//! `marmot.group.agent-text-stream.quic.v1`).
//!
//! MDK no longer streams agent text previews or adds this component to new
//! groups. Every group MDK created before its retirement carries it as a
//! required app component that requires the `receive` role, and the engine
//! refuses invitees whose KeyPackage lacks the matching capability. This module keeps only what those existing groups need
//! to keep working: the component state codec and validation, the role bits,
//! and the role features and MLS capabilities.

use crate::app_components::AppComponentData;
pub use crate::app_components::{
    AGENT_TEXT_STREAM_QUIC_COMPONENT, AGENT_TEXT_STREAM_QUIC_COMPONENT_ID,
};
use crate::capabilities::{Capability, Feature, GroupCapabilities};
use serde::{Deserialize, Serialize};

pub const AGENT_TEXT_STREAM_QUIC_RECEIVE_FEATURE: Feature =
    Feature("marmot.feature.agent_text_stream_quic.receive.v1");
pub const AGENT_TEXT_STREAM_QUIC_SEND_FEATURE: Feature =
    Feature("marmot.feature.agent_text_stream_quic.send.v1");
pub const AGENT_TEXT_STREAM_QUIC_FANOUT_FEATURE: Feature =
    Feature("marmot.feature.agent_text_stream_quic.fanout.v1");

/// MLS leaf-capability backing each agent-text-stream-QUIC role
/// (`agent-text-stream-quic-v1.md`). Each role capability advertised by a
/// KeyPackage is a distinct private-use MLS extension type, so a member can
/// advertise `receive` without advertising `send`/`fanout`. This is what makes
/// `required_member_roles` enforceable per role rather than only at
/// component-support granularity. The component id (`0x8006`) stays separate: it
/// gates "understands the component", these gate "supports the role".
pub const AGENT_TEXT_STREAM_QUIC_RECEIVE_CAPABILITY: Capability = Capability::Extension(0xF2D1);
pub const AGENT_TEXT_STREAM_QUIC_SEND_CAPABILITY: Capability = Capability::Extension(0xF2D2);
pub const AGENT_TEXT_STREAM_QUIC_FANOUT_CAPABILITY: Capability = Capability::Extension(0xF2D4);

/// Map a role to its `(bit, Feature, Capability)` triple. The single source of
/// truth for the role bit -> capability mapping in
/// `agent-text-stream-quic-v1.md`, shared by the engine enforcement and the app
/// feature registration so they cannot drift.
pub const AGENT_TEXT_STREAM_QUIC_ROLES: [(u8, Feature, Capability); 3] = [
    (
        AGENT_TEXT_STREAM_ROLE_RECEIVE,
        AGENT_TEXT_STREAM_QUIC_RECEIVE_FEATURE,
        AGENT_TEXT_STREAM_QUIC_RECEIVE_CAPABILITY,
    ),
    (
        AGENT_TEXT_STREAM_ROLE_SEND,
        AGENT_TEXT_STREAM_QUIC_SEND_FEATURE,
        AGENT_TEXT_STREAM_QUIC_SEND_CAPABILITY,
    ),
    (
        AGENT_TEXT_STREAM_ROLE_FANOUT,
        AGENT_TEXT_STREAM_QUIC_FANOUT_FEATURE,
        AGENT_TEXT_STREAM_QUIC_FANOUT_CAPABILITY,
    ),
];

/// Translate a `required_member_roles` mask into the set of role capabilities
/// every member MUST advertise. Empty when the mask requires no roles. Unknown
/// bits are ignored here; component validation rejects unknown bits separately.
pub fn required_role_capabilities(required_member_roles: u8) -> GroupCapabilities {
    let mut out = GroupCapabilities::default();
    for (bit, _feature, capability) in AGENT_TEXT_STREAM_QUIC_ROLES {
        if required_member_roles & bit != 0 {
            out.insert(capability);
        }
    }
    out
}

pub const AGENT_TEXT_STREAM_ROLE_RECEIVE: u8 = 0x01;
pub const AGENT_TEXT_STREAM_ROLE_SEND: u8 = 0x02;
pub const AGENT_TEXT_STREAM_ROLE_FANOUT: u8 = 0x04;
pub const AGENT_TEXT_STREAM_ROLE_MASK: u8 =
    AGENT_TEXT_STREAM_ROLE_RECEIVE | AGENT_TEXT_STREAM_ROLE_SEND | AGENT_TEXT_STREAM_ROLE_FANOUT;

/// App-profile cap on `max_plaintext_frame_len` in the component state.
pub const AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN: u32 = 65519;
/// App-profile cap on `replay_ttl_secs` in the component state.
pub const AGENT_TEXT_STREAM_MAX_REPLAY_TTL_SECS: u32 = 5 * 60;
/// App-profile cap on `padding_bucket_bytes` in the component state.
pub const AGENT_TEXT_STREAM_MAX_PADDING_BUCKET_BYTES: u16 = 4096;

/// Encoded `0x8006` component state length in bytes: `required_member_roles`
/// (u8), `allowed_member_roles` (u8), `max_plaintext_frame_len` (u32),
/// `replay_ttl_secs` (u32), `padding_bucket_bytes` (u16).
pub const AGENT_TEXT_STREAM_COMPONENT_STATE_LEN: usize = 12;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentTextStreamQuicPolicyV1 {
    pub required_member_roles: u8,
    pub allowed_member_roles: u8,
    pub max_plaintext_frame_len: u32,
    pub replay_ttl_secs: u32,
    pub padding_bucket_bytes: u16,
}

impl AgentTextStreamQuicPolicyV1 {
    pub fn user_to_agent_default() -> Self {
        Self {
            required_member_roles: AGENT_TEXT_STREAM_ROLE_RECEIVE,
            allowed_member_roles: AGENT_TEXT_STREAM_ROLE_RECEIVE | AGENT_TEXT_STREAM_ROLE_SEND,
            max_plaintext_frame_len: 4096,
            replay_ttl_secs: 0,
            padding_bucket_bytes: 0,
        }
    }

    pub fn encode_component_state(&self) -> Result<Vec<u8>, AgentTextStreamPolicyError> {
        self.validate()?;
        let mut out = Vec::with_capacity(AGENT_TEXT_STREAM_COMPONENT_STATE_LEN);
        out.push(self.required_member_roles);
        out.push(self.allowed_member_roles);
        out.extend_from_slice(&self.max_plaintext_frame_len.to_be_bytes());
        out.extend_from_slice(&self.replay_ttl_secs.to_be_bytes());
        out.extend_from_slice(&self.padding_bucket_bytes.to_be_bytes());
        Ok(out)
    }

    pub fn decode_component_state(bytes: &[u8]) -> Result<Self, AgentTextStreamPolicyError> {
        if bytes.len() != AGENT_TEXT_STREAM_COMPONENT_STATE_LEN {
            return Err(AgentTextStreamPolicyError::InvalidComponentStateLength(
                bytes.len(),
            ));
        }
        let policy = Self {
            required_member_roles: bytes[0],
            allowed_member_roles: bytes[1],
            max_plaintext_frame_len: u32::from_be_bytes(
                bytes[2..6]
                    .try_into()
                    .expect("slice length checked by component state length"),
            ),
            replay_ttl_secs: u32::from_be_bytes(
                bytes[6..10]
                    .try_into()
                    .expect("slice length checked by component state length"),
            ),
            padding_bucket_bytes: u16::from_be_bytes(
                bytes[10..12]
                    .try_into()
                    .expect("slice length checked by component state length"),
            ),
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn to_app_component_data(&self) -> Result<AppComponentData, AgentTextStreamPolicyError> {
        Ok(AppComponentData {
            component_id: AGENT_TEXT_STREAM_QUIC_COMPONENT_ID,
            data: self.encode_component_state()?,
        })
    }

    pub fn validate(&self) -> Result<(), AgentTextStreamPolicyError> {
        if self.required_member_roles == 0 {
            return Err(AgentTextStreamPolicyError::EmptyRequiredRoles);
        }
        if self.required_member_roles & !AGENT_TEXT_STREAM_ROLE_MASK != 0 {
            return Err(AgentTextStreamPolicyError::UnknownRequiredRoleBits(
                self.required_member_roles,
            ));
        }
        if self.allowed_member_roles & !AGENT_TEXT_STREAM_ROLE_MASK != 0 {
            return Err(AgentTextStreamPolicyError::UnknownAllowedRoleBits(
                self.allowed_member_roles,
            ));
        }
        if self.required_member_roles & !self.allowed_member_roles != 0 {
            return Err(AgentTextStreamPolicyError::RequiredRolesNotAllowed);
        }
        if self.max_plaintext_frame_len == 0 {
            return Err(AgentTextStreamPolicyError::EmptyFrameLimit);
        }
        if self.max_plaintext_frame_len > AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN {
            return Err(AgentTextStreamPolicyError::FrameLimitTooLarge(
                self.max_plaintext_frame_len,
            ));
        }
        if self.replay_ttl_secs > AGENT_TEXT_STREAM_MAX_REPLAY_TTL_SECS {
            return Err(AgentTextStreamPolicyError::ReplayTtlTooLarge(
                self.replay_ttl_secs,
            ));
        }
        if self.padding_bucket_bytes > AGENT_TEXT_STREAM_MAX_PADDING_BUCKET_BYTES {
            return Err(AgentTextStreamPolicyError::PaddingBucketTooLarge(
                self.padding_bucket_bytes,
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AgentTextStreamPolicyError {
    #[error("required agent text stream roles cannot be empty")]
    EmptyRequiredRoles,
    #[error("required agent text stream role mask contains unknown bits: {0:#04x}")]
    UnknownRequiredRoleBits(u8),
    #[error("allowed agent text stream role mask contains unknown bits: {0:#04x}")]
    UnknownAllowedRoleBits(u8),
    #[error("required agent text stream roles must be a subset of allowed roles")]
    RequiredRolesNotAllowed,
    #[error("agent text stream plaintext frame limit cannot be zero")]
    EmptyFrameLimit,
    #[error("agent text stream component state must be 12 bytes, got {0}")]
    InvalidComponentStateLength(usize),
    #[error("agent text stream plaintext frame limit exceeds app profile max: {0}")]
    FrameLimitTooLarge(u32),
    #[error("agent text stream replay ttl exceeds app profile max: {0}")]
    ReplayTtlTooLarge(u32),
    #[error("agent text stream padding bucket exceeds app profile max: {0}")]
    PaddingBucketTooLarge(u16),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_to_agent_policy_encodes_component_state() {
        let bytes = AgentTextStreamQuicPolicyV1::user_to_agent_default()
            .encode_component_state()
            .unwrap();
        assert_eq!(
            bytes,
            vec![
                AGENT_TEXT_STREAM_ROLE_RECEIVE,
                AGENT_TEXT_STREAM_ROLE_RECEIVE | AGENT_TEXT_STREAM_ROLE_SEND,
                0x00,
                0x00,
                0x10,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
            ]
        );
        assert_eq!(bytes.len(), AGENT_TEXT_STREAM_COMPONENT_STATE_LEN);
        assert_eq!(
            AgentTextStreamQuicPolicyV1::decode_component_state(&bytes).unwrap(),
            AgentTextStreamQuicPolicyV1::user_to_agent_default()
        );
    }

    #[test]
    fn policy_validation_enforces_app_profile_caps() {
        let too_large_frame = AgentTextStreamQuicPolicyV1 {
            max_plaintext_frame_len: AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN + 1,
            ..AgentTextStreamQuicPolicyV1::user_to_agent_default()
        };
        assert!(matches!(
            too_large_frame.validate(),
            Err(AgentTextStreamPolicyError::FrameLimitTooLarge(_))
        ));

        let too_large_replay = AgentTextStreamQuicPolicyV1 {
            replay_ttl_secs: AGENT_TEXT_STREAM_MAX_REPLAY_TTL_SECS + 1,
            ..AgentTextStreamQuicPolicyV1::user_to_agent_default()
        };
        assert!(matches!(
            too_large_replay.validate(),
            Err(AgentTextStreamPolicyError::ReplayTtlTooLarge(_))
        ));

        let too_large_padding = AgentTextStreamQuicPolicyV1 {
            padding_bucket_bytes: AGENT_TEXT_STREAM_MAX_PADDING_BUCKET_BYTES + 1,
            ..AgentTextStreamQuicPolicyV1::user_to_agent_default()
        };
        assert!(matches!(
            too_large_padding.validate(),
            Err(AgentTextStreamPolicyError::PaddingBucketTooLarge(_))
        ));

        let required_role_not_allowed = AgentTextStreamQuicPolicyV1 {
            required_member_roles: AGENT_TEXT_STREAM_ROLE_SEND,
            allowed_member_roles: AGENT_TEXT_STREAM_ROLE_RECEIVE,
            ..AgentTextStreamQuicPolicyV1::user_to_agent_default()
        };
        assert!(matches!(
            required_role_not_allowed.validate(),
            Err(AgentTextStreamPolicyError::RequiredRolesNotAllowed)
        ));
    }

    #[test]
    fn decode_rejects_wrong_length_component_state() {
        assert!(matches!(
            AgentTextStreamQuicPolicyV1::decode_component_state(&[0u8; 14]),
            Err(AgentTextStreamPolicyError::InvalidComponentStateLength(14))
        ));
        assert!(matches!(
            AgentTextStreamQuicPolicyV1::decode_component_state(&[0u8; 11]),
            Err(AgentTextStreamPolicyError::InvalidComponentStateLength(11))
        ));
    }
}
