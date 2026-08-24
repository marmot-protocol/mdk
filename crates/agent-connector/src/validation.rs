//! Control-plane validation, hex/time helpers, request introspection, and invite-policy retry state.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use agent_control::AgentControlRequest;
use cgka_traits::{GroupId, MemberId};

use crate::error::ConnectorError;
use crate::{
    AGENT_SOCKET_DIR_MODE, AGENT_SOCKET_MODE, AgentConnectorConfig, MAX_PROFILE_NAME_CHARS,
};
#[cfg(test)]
use crate::{INVITE_POLICY_RETRY_BASE, INVITE_POLICY_RETRY_MAX};

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

    /// Whether any failed candidate is still pending retry. Pending retries
    /// keep the invite-policy worker's safety enumeration at its base interval
    /// (mdk#1380).
    pub(crate) fn has_pending(&self) -> bool {
        !self.failures.is_empty()
    }

    /// Earliest retry wake-up across all failed candidates; `None` when no
    /// failure is pending. The worker sleeps until this instead of polling on
    /// a fixed cadence.
    pub(crate) fn next_due(&self) -> Option<tokio::time::Instant> {
        self.failures
            .values()
            .map(|retry| retry.next_retry_at)
            .min()
    }

    /// Record a failure on the production backoff constants. The worker uses
    /// [`Self::record_failure_with`] (its schedule is injectable for tests);
    /// this convenience remains for tests that pin the production constants.
    #[cfg(test)]
    pub(crate) fn record_failure(
        &mut self,
        key: InvitePolicyKey,
        now: tokio::time::Instant,
    ) -> (u32, Duration) {
        self.record_failure_with(key, now, INVITE_POLICY_RETRY_BASE, INVITE_POLICY_RETRY_MAX)
    }

    /// Record a failure with an explicit backoff schedule. Production callers
    /// use [`Self::record_failure`] (the crate constants); the worker passes
    /// its [`crate::invite_policy::InvitePolicySchedule`] through so tests can
    /// compress the schedule.
    pub(crate) fn record_failure_with(
        &mut self,
        key: InvitePolicyKey,
        now: tokio::time::Instant,
        retry_base: Duration,
        retry_max: Duration,
    ) -> (u32, Duration) {
        let attempts = self
            .failures
            .get(&key)
            .map(|retry| retry.attempts.saturating_add(1))
            .unwrap_or(1);
        let delay = invite_policy_retry_delay_with(attempts, retry_base, retry_max);
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

pub(crate) fn invite_policy_retry_delay_with(
    attempts: u32,
    retry_base: Duration,
    retry_max: Duration,
) -> Duration {
    let exponent = attempts.saturating_sub(1).min(10);
    let factor = 1_u32.checked_shl(exponent).unwrap_or(u32::MAX);
    let delay = retry_base.checked_mul(factor).unwrap_or(retry_max);
    std::cmp::min(delay, retry_max)
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
        AgentControlRequest::TimelineMessageGet { .. } => "timeline_message_get",
        AgentControlRequest::TimelineList { .. } => "timeline_list",
        AgentControlRequest::SendFinal { .. } => "send_final",
        AgentControlRequest::DeleteMessage { .. } => "delete_message",
        AgentControlRequest::SendReaction { .. } => "send_reaction",
        AgentControlRequest::RemoveReaction { .. } => "remove_reaction",
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
        AgentControlRequest::AccountProfileLookup { .. } => "account_profile_lookup",
        AgentControlRequest::SendAgentActivity { .. } => "send_agent_activity",
        AgentControlRequest::SendAgentOperationEvent { .. } => "send_agent_operation_event",
        AgentControlRequest::SendGroupSystemEvent { .. } => "send_group_system_event",
        AgentControlRequest::GroupInfo { .. } => "group_info",
        AgentControlRequest::MaintenanceStatus { .. } => "maintenance_status",
        AgentControlRequest::KeyPackageMaintenanceStatus { .. } => "key_package_maintenance_status",
        AgentControlRequest::MaintenanceScheduleSelfUpdate { .. } => {
            "maintenance_schedule_self_update"
        }
        AgentControlRequest::MaintenanceGetPolicy { .. } => "maintenance_get_policy",
        AgentControlRequest::MaintenanceSetPolicy { .. } => "maintenance_set_policy",
        AgentControlRequest::MaintenancePause { .. } => "maintenance_pause",
        AgentControlRequest::MaintenanceResume { .. } => "maintenance_resume",
        AgentControlRequest::MaintenanceRun { .. } => "maintenance_run",
        AgentControlRequest::AllowlistList { .. } => "allowlist_list",
        AgentControlRequest::AllowlistAdd { .. } => "allowlist_add",
        AgentControlRequest::AllowlistRemove { .. } => "allowlist_remove",
        AgentControlRequest::InvitePolicyGet { .. } => "invite_policy_get",
        AgentControlRequest::InvitePolicySet { .. } => "invite_policy_set",
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

    if config.max_connections == 0 {
        return Err(ConnectorError::UnsafeControlPlaneConfig(
            "max connections must be nonzero",
        ));
    }

    if config.dev_allow_any_invites && !config.debug_controls {
        return Err(ConnectorError::UnsafeControlPlaneConfig(
            "dev allow-any invites requires debug controls",
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
    if value.chars().any(char::is_control) {
        return Err(ConnectorError::InvalidProfileName("control_characters"));
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
