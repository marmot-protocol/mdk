//! Control-plane validation, hex/time helpers, request introspection, and invite-policy retry state.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use agent_control::AgentControlRequest;
use cgka_traits::{GroupId, MemberId};

use crate::error::ConnectorError;
use crate::{
    AGENT_SOCKET_DIR_MODE, AGENT_SOCKET_MODE, AgentConnectorConfig, INVITE_POLICY_RETRY_BASE,
    INVITE_POLICY_RETRY_MAX, MAX_PROFILE_NAME_CHARS,
};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct InvitePolicyKey {
    pub(crate) account_id_hex: String,
    pub(crate) group_id_hex: String,
}

impl InvitePolicyKey {
    pub(crate) fn new(account_id_hex: &str, group_id_hex: &str) -> Self {
        Self {
            account_id_hex: account_id_hex.to_owned(),
            group_id_hex: group_id_hex.to_owned(),
        }
    }
}

pub(crate) struct PendingInvitePolicyCandidate {
    pub(crate) key: InvitePolicyKey,
    pub(crate) group_id: GroupId,
    pub(crate) welcomer: Option<MemberId>,
}

#[derive(Default)]
pub(crate) struct InvitePolicyRetryState {
    pub(crate) failures: HashMap<InvitePolicyKey, InvitePolicyRetry>,
}

pub(crate) struct InvitePolicyRetry {
    pub(crate) attempts: u32,
    pub(crate) next_retry_at: tokio::time::Instant,
}

impl InvitePolicyRetryState {
    pub(crate) fn is_due(&self, key: &InvitePolicyKey, now: tokio::time::Instant) -> bool {
        match self.failures.get(key) {
            Some(retry) => now >= retry.next_retry_at,
            None => true,
        }
    }

    pub(crate) fn clear(&mut self, key: &InvitePolicyKey) {
        self.failures.remove(key);
    }

    pub(crate) fn retain_pending(&mut self, pending: &HashSet<InvitePolicyKey>) {
        self.failures.retain(|key, _| pending.contains(key));
    }

    pub(crate) fn record_failure(
        &mut self,
        key: InvitePolicyKey,
        now: tokio::time::Instant,
    ) -> (u32, Duration) {
        let attempts = self
            .failures
            .get(&key)
            .map(|retry| retry.attempts.saturating_add(1))
            .unwrap_or(1);
        let delay = invite_policy_retry_delay(attempts);
        self.failures.insert(
            key,
            InvitePolicyRetry {
                attempts,
                next_retry_at: now + delay,
            },
        );
        (attempts, delay)
    }
}

pub(crate) fn invite_policy_retry_delay(attempts: u32) -> Duration {
    let exponent = attempts.saturating_sub(1).min(10);
    let factor = 1_u32.checked_shl(exponent).unwrap_or(u32::MAX);
    let delay = INVITE_POLICY_RETRY_BASE
        .checked_mul(factor)
        .unwrap_or(INVITE_POLICY_RETRY_MAX);
    std::cmp::min(delay, INVITE_POLICY_RETRY_MAX)
}

pub(crate) fn unsupported_request_message(request: &AgentControlRequest) -> &'static str {
    match request {
        AgentControlRequest::SubscribeInbound { .. } => {
            "subscribe_inbound must be sent as the first request on a streaming connection"
        }
        _ => "request is not implemented by this connector slice",
    }
}

pub(crate) fn agent_control_request_type(request: &AgentControlRequest) -> &'static str {
    match request {
        AgentControlRequest::SubscribeInbound { .. } => "subscribe_inbound",
        AgentControlRequest::SendFinal { .. } => "send_final",
        AgentControlRequest::DeleteMessage { .. } => "delete_message",
        AgentControlRequest::StreamBegin { .. } => "stream_begin",
        AgentControlRequest::StreamAppend { .. } => "stream_append",
        AgentControlRequest::StreamStatus { .. } => "stream_status",
        AgentControlRequest::StreamProgress { .. } => "stream_progress",
        AgentControlRequest::StreamFinalize { .. } => "stream_finalize",
        AgentControlRequest::StreamCancel { .. } => "stream_cancel",
        AgentControlRequest::AccountList => "account_list",
        AgentControlRequest::AccountCreate { .. } => "account_create",
        AgentControlRequest::AccountPublishKeyPackage { .. } => "account_publish_key_package",
        AgentControlRequest::AccountPublishProfile { .. } => "account_publish_profile",
        AgentControlRequest::SendAgentActivity { .. } => "send_agent_activity",
        AgentControlRequest::SendAgentOperationEvent { .. } => "send_agent_operation_event",
        AgentControlRequest::SendGroupSystemEvent { .. } => "send_group_system_event",
        AgentControlRequest::GroupInfo { .. } => "group_info",
        AgentControlRequest::AllowlistList { .. } => "allowlist_list",
        AgentControlRequest::AllowlistAdd { .. } => "allowlist_add",
        AgentControlRequest::AllowlistRemove { .. } => "allowlist_remove",
        AgentControlRequest::DebugInjectInbound { .. } => "debug_inject_inbound",
        AgentControlRequest::DebugRecordedFinals => "debug_recorded_finals",
        AgentControlRequest::SendMedia { .. } => "send_media",
        AgentControlRequest::DownloadMedia { .. } => "download_media",
    }
}

pub(crate) fn validate_control_plane_config(
    config: &AgentConnectorConfig,
) -> Result<(), ConnectorError> {
    validate_control_plane_mode(config.socket_dir_mode, "socket directory mode")?;
    validate_control_plane_mode(config.socket_mode, "socket mode")?;

    if config.auth_token.as_deref().is_some_and(str::is_empty) {
        return Err(ConnectorError::UnsafeControlPlaneConfig(
            "auth token must not be empty",
        ));
    }

    if config.auth_token.is_none()
        && (config.socket_dir_mode != AGENT_SOCKET_DIR_MODE
            || config.socket_mode != AGENT_SOCKET_MODE)
    {
        return Err(ConnectorError::UnsafeControlPlaneConfig(
            "non-default socket modes require an auth token",
        ));
    }

    Ok(())
}

pub(crate) fn validate_control_plane_mode(
    mode: u32,
    field: &'static str,
) -> Result<(), ConnectorError> {
    if mode & !0o777 != 0 {
        return Err(ConnectorError::UnsafeControlPlaneConfig(field));
    }
    if mode & 0o007 != 0 {
        return Err(ConnectorError::UnsafeControlPlaneConfig(
            "world-accessible control sockets are not allowed",
        ));
    }
    Ok(())
}

pub(crate) fn auth_token_matches(expected: &str, provided: Option<&str>) -> bool {
    let Some(provided) = provided else {
        return false;
    };
    let expected = expected.as_bytes();
    let provided = provided.as_bytes();
    let max_len = expected.len().max(provided.len());
    let mut diff = expected.len() ^ provided.len();
    for i in 0..max_len {
        diff |= usize::from(
            expected.get(i).copied().unwrap_or_default()
                ^ provided.get(i).copied().unwrap_or_default(),
        );
    }
    diff == 0
}

pub(crate) fn endpoint(url: &str) -> cgka_traits::TransportEndpoint {
    cgka_traits::TransportEndpoint(url.to_owned())
}

pub(crate) fn validate_profile_name(value: String) -> Result<String, ConnectorError> {
    let value = value.split_whitespace().collect::<Vec<_>>().join(" ");
    if value.is_empty() {
        return Err(ConnectorError::InvalidProfileName("empty"));
    }
    if value.chars().count() > MAX_PROFILE_NAME_CHARS {
        return Err(ConnectorError::InvalidProfileName("too_long"));
    }
    Ok(value)
}

pub(crate) fn transcript_hash_from_hex(value: &str) -> Result<[u8; 32], ConnectorError> {
    let bytes = hex::decode(normalize_hex(value)?)?;
    let actual = bytes.len();
    bytes
        .try_into()
        .map_err(|_| ConnectorError::Stream(format!("invalid transcript hash length: {actual}")))
}

pub(crate) fn normalize_hex(value: &str) -> Result<String, ConnectorError> {
    Ok(hex::encode(hex::decode(value)?))
}

pub(crate) fn unix_now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
