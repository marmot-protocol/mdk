use cgka_traits::{TransportAdapterError, storage::StorageError};
use marmot_account::{AccountError, AccountHomeError};

use crate::MissingRelayListKind;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error(transparent)]
    Account(#[from] marmot_account::AccountError),
    #[error(transparent)]
    AccountHome(#[from] AccountHomeError),
    #[error(transparent)]
    Session(#[from] cgka_session::SessionError),
    #[error(transparent)]
    Storage(#[from] cgka_traits::storage::StorageError),
    #[error(transparent)]
    Transport(TransportAdapterError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),
    #[error("no published key package for account")]
    MissingKeyPackage(String),
    #[error("unknown local group")]
    UnknownGroup(String),
    #[error("invalid group membership page: {0}")]
    InvalidGroupMembershipPage(String),
    #[error("invalid chat pin: {0}")]
    InvalidChatPin(String),
    #[error("group is disbanding or disbanded; outbound work is blocked")]
    GroupDisbanding(String),
    /// Host-supplied draft attachment metadata failed validation before storage.
    #[error("invalid message draft: {0}")]
    InvalidMessageDraft(String),
    #[error("no agent text stream start found for this group")]
    AgentStreamMissingStart,
    #[error("agent text stream start has no confirmed message id yet")]
    AgentStreamStartNotConfirmed,
    #[error("unsupported agent text stream route (only brokered QUIC is supported)")]
    AgentStreamUnsupportedRoute,
    #[error("agent text stream start has no usable quic:// candidate")]
    AgentStreamMissingCandidate,
    #[error("invalid quic candidate: {0}")]
    AgentStreamInvalidCandidate(String),
    #[error("publish failed: {0}")]
    Publish(String),
    #[error("default relays are required to publish account relay lists")]
    MissingDefaultRelays,
    #[error("missing account relay lists: {0:?}")]
    MissingRelayLists(Vec<MissingRelayListKind>),
    /// The selected relay set returned no current kind-3 contact-list event.
    ///
    /// Follow updates replace the entire list, so treating an absent event as
    /// an empty list could silently erase follows published elsewhere.
    #[error("current account follow list is unavailable")]
    FollowListUnavailable,
    #[error("relay directory fetch failed: {0}")]
    RelayDirectory(String),
    /// An account worker's transport catch-up failed (sync error or timeout).
    /// Deliberately distinct from [`AppError::RelayDirectory`]: catch-up
    /// failures were once wrapped as relay-directory errors, which sent an
    /// earlier investigation chasing the wrong subsystem.
    #[error("account catch-up failed: {0}")]
    AccountCatchUp(String),
    #[error("invalid Nostr public key")]
    InvalidPublicKey,
    #[error("this operation does not accept a private key")]
    UnexpectedPrivateKey,
    #[error("public identity does not match the imported private key")]
    IdentityKeyMismatch,
    #[error("external signer unavailable for account")]
    ExternalSignerUnavailable(String),
    #[error("external signer public key does not match account")]
    ExternalSignerMismatch,
    #[error("external signer request was rejected or cancelled by the user")]
    ExternalSignerRejected,
    #[error("invalid Marmot KeyPackage event: {0}")]
    InvalidKeyPackageEvent(String),
    #[error("no directory entry for account")]
    MissingDirectoryEntry(String),
    #[error("invalid user directory search: {0}")]
    InvalidDirectorySearch(String),
    #[error("invalid group profile: {0}")]
    InvalidGroupProfile(String),
    #[error("invalid Nostr routing component: {0}")]
    InvalidNostrRouting(String),
    #[error("invalid group avatar URL: {0}")]
    InvalidGroupAvatarUrl(String),
    #[error("invalid agent text stream policy: {0}")]
    InvalidAgentTextStreamPolicy(String),
    #[error("invalid encrypted media: {0}")]
    InvalidEncryptedMedia(String),
    #[error("blob store request failed: {0}")]
    BlobStore(String),
    /// Pre-dial rejection for untrusted profile/media fetch URLs (SSRF boundary).
    #[error("unsafe media fetch: {0}")]
    UnsafeMediaFetch(String),
    #[error("invalid app message payload: {0}")]
    InvalidAppMessagePayload(String),
    #[error("invalid push token")]
    InvalidPushToken(String),
    #[error("invalid push notification server")]
    InvalidPushServer(String),
    #[error("invalid push token gossip")]
    InvalidPushGossip(String),
    #[error("invalid relay telemetry settings: {0}")]
    InvalidRelayTelemetrySettings(String),
    #[error("invalid audit log file: {0}")]
    InvalidAuditLogFile(String),
    #[error("audit log upload failed: {0}")]
    AuditLogUpload(String),
    #[error("local notifications are disabled")]
    NotificationsDisabled,
    #[error("SQLCipher key derivation failed: {0}")]
    SqlcipherKeyDerivation(String),
    #[error("blocking app task failed: {0}")]
    BlockingTask(String),
    /// Another process or independently constructed production runtime owns
    /// the same Marmot root. Acquisition is intentionally nonblocking so an
    /// iOS notification extension can take its bounded fallback path.
    #[error("marmot runtime root is already in use")]
    RuntimeBusy,
    /// Another [`crate::AppClient`] from this [`crate::MarmotApp`] currently
    /// owns the account's in-memory engine session.
    #[error("marmot account session is already in use")]
    AccountSessionBusy,
    /// The managed account worker is in an exclusive catch-up phase and did
    /// not start this command. Retrying after the catch-up completes is safe.
    #[error("marmot account worker is busy catching up; operation was not started")]
    AccountWorkerBusy,
    /// The worker accepted the command, but its response did not arrive within
    /// the operation-class deadline. Completion is unknown; callers must
    /// refresh authoritative state before deciding whether to retry.
    #[error("marmot account worker response timed out; operation completion is unknown")]
    AccountWorkerResponseTimedOut,
    /// An account database predates the durable setup journal and has no
    /// recoverable stable KeyPackage slot. Local evidence cannot prove that a
    /// previously signed package was never exposed, so automatic rotation is
    /// forbidden. The host may offer the explicit incomplete-setup reset API.
    #[error(
        "incomplete account setup requires explicit recovery because prior KeyPackage exposure cannot be ruled out"
    )]
    AccountSetupRecoveryRequired,
    #[error("durable account setup can be resumed by retrying the original operation")]
    AccountSetupRetryRequired,
    #[error("account is not in the legacy incomplete-setup reset state")]
    AccountSetupResetNotApplicable,
    #[error("recoverable KeyPackage setup state exists; retry instead of resetting")]
    AccountSetupKeyPackageRecoveryAvailable,
    #[error("marmot runtime is shutting down")]
    RuntimeStopping,
    #[error("no matching reaction by this account to retract")]
    ReactionNotFound,
    #[error("transport event stream closed")]
    TransportClosed,
}

impl From<TransportAdapterError> for AppError {
    fn from(error: TransportAdapterError) -> Self {
        if error.to_string().contains(crate::EXTERNAL_SIGNER_REJECTED) {
            Self::ExternalSignerRejected
        } else {
            Self::Transport(error)
        }
    }
}

impl AppError {
    pub(crate) fn is_account_not_active(&self) -> bool {
        matches!(
            self,
            Self::Transport(TransportAdapterError::AccountNotActive(_))
                | Self::Account(AccountError::Transport(
                    TransportAdapterError::AccountNotActive(_)
                ))
        )
    }

    pub(crate) fn privacy_safe_kind(&self) -> &'static str {
        match self {
            Self::Account(error) => account_error_kind(error),
            Self::AccountHome(error) => account_home_error_kind(error),
            Self::Session(_) => "session",
            Self::Storage(error) => storage_error_kind(error),
            Self::Transport(_) => "transport",
            Self::Io(_) => "io",
            Self::Json(_) => "json",
            Self::Sqlite(_) => "sqlite",
            Self::Hex(_) => "hex",
            Self::MissingKeyPackage(_) => "missing_key_package",
            Self::UnknownGroup(_) => "unknown_group",
            Self::InvalidGroupMembershipPage(_) => "invalid_group_membership_page",
            Self::InvalidChatPin(_) => "invalid_chat_pin",
            Self::GroupDisbanding(_) => "group_disbanding",
            Self::InvalidMessageDraft(_) => "invalid_message_draft",
            Self::AgentStreamMissingStart => "agent_stream_missing_start",
            Self::AgentStreamStartNotConfirmed => "agent_stream_start_not_confirmed",
            Self::AgentStreamUnsupportedRoute => "agent_stream_unsupported_route",
            Self::AgentStreamMissingCandidate => "agent_stream_missing_candidate",
            Self::AgentStreamInvalidCandidate(_) => "agent_stream_invalid_candidate",
            Self::Publish(_) => "publish",
            Self::MissingDefaultRelays => "missing_default_relays",
            Self::MissingRelayLists(_) => "missing_relay_lists",
            Self::FollowListUnavailable => "follow_list_unavailable",
            Self::RelayDirectory(_) => "relay_directory",
            Self::AccountCatchUp(_) => "account_catch_up",
            Self::InvalidPublicKey => "invalid_public_key",
            Self::UnexpectedPrivateKey => "unexpected_private_key",
            Self::IdentityKeyMismatch => "identity_key_mismatch",
            Self::ExternalSignerUnavailable(_) => "external_signer_unavailable",
            Self::ExternalSignerMismatch => "external_signer_mismatch",
            Self::ExternalSignerRejected => "external_signer_rejected",
            Self::InvalidKeyPackageEvent(_) => "invalid_key_package_event",
            Self::MissingDirectoryEntry(_) => "missing_directory_entry",
            Self::InvalidDirectorySearch(_) => "invalid_directory_search",
            Self::InvalidGroupProfile(_) => "invalid_group_profile",
            Self::InvalidNostrRouting(_) => "invalid_nostr_routing",
            Self::InvalidGroupAvatarUrl(_) => "invalid_group_avatar_url",
            Self::InvalidAgentTextStreamPolicy(_) => "invalid_agent_text_stream_policy",
            Self::InvalidEncryptedMedia(_) => "invalid_encrypted_media",
            Self::BlobStore(_) => "blob_store",
            Self::UnsafeMediaFetch(_) => "unsafe_media_fetch",
            Self::InvalidAppMessagePayload(_) => "invalid_app_message_payload",
            Self::InvalidPushToken(_) => "invalid_push_token",
            Self::InvalidPushServer(_) => "invalid_push_server",
            Self::InvalidPushGossip(_) => "invalid_push_gossip",
            Self::InvalidRelayTelemetrySettings(_) => "invalid_relay_telemetry_settings",
            Self::InvalidAuditLogFile(_) => "invalid_audit_log_file",
            Self::AuditLogUpload(_) => "audit_log_upload",
            Self::NotificationsDisabled => "notifications_disabled",
            Self::SqlcipherKeyDerivation(_) => "sqlcipher_key_derivation",
            Self::BlockingTask(_) => "blocking_task",
            Self::RuntimeBusy => "runtime_busy",
            Self::AccountSessionBusy => "account_session_busy",
            Self::AccountWorkerBusy => "account_worker_busy",
            Self::AccountWorkerResponseTimedOut => "account_worker_response_timed_out",
            Self::AccountSetupRecoveryRequired => "account_setup_recovery_required",
            Self::AccountSetupRetryRequired => "account_setup_retry_required",
            Self::AccountSetupResetNotApplicable => "account_setup_reset_not_applicable",
            Self::AccountSetupKeyPackageRecoveryAvailable => {
                "account_setup_key_package_recovery_available"
            }
            Self::RuntimeStopping => "runtime_stopping",
            Self::ReactionNotFound => "reaction_not_found",
            Self::TransportClosed => "transport_closed",
        }
    }

    pub fn as_engine_error(&self) -> Option<&cgka_traits::error::EngineError> {
        match self {
            Self::Account(marmot_account::AccountError::Engine(err))
            | Self::Account(marmot_account::AccountError::Session(
                cgka_session::SessionError::Engine(err),
            ))
            | Self::Session(cgka_session::SessionError::Engine(err)) => Some(err),
            _ => None,
        }
    }
}

fn account_error_kind(error: &AccountError) -> &'static str {
    match error {
        AccountError::Session(_) => "account_session",
        AccountError::Engine(_) => "account_engine",
        AccountError::Transport(_) => "account_transport",
        AccountError::TransportRouting(_) => "account_transport_routing",
        AccountError::KeyPackage(_) => "account_key_package",
        AccountError::ClockSkewBlocked => "account_clock_skew_blocked",
        AccountError::KeyPackageRotationInProgress => "account_key_package_rotation_in_progress",
        AccountError::WrongAccountDelivery => "account_wrong_delivery",
        _ => "account_unknown",
    }
}

fn account_home_error_kind(error: &AccountHomeError) -> &'static str {
    match error {
        AccountHomeError::Io(_) => "account_home_io",
        AccountHomeError::Json(_) => "account_home_json",
        AccountHomeError::Hex(_) => "account_home_hex",
        AccountHomeError::AccountExists(_) => "account_home_account_exists",
        AccountHomeError::AccountIdInUse(_) => "account_home_account_id_in_use",
        AccountHomeError::UnknownAccount(_) => "account_home_unknown_account",
        AccountHomeError::InvalidSecretKey => "account_home_invalid_secret_key",
        AccountHomeError::InvalidPublicKey => "account_home_invalid_public_key",
        AccountHomeError::InvalidAccountLabel(_) => "account_home_invalid_account_label",
        AccountHomeError::AccountIdMismatch => "account_home_account_id_mismatch",
        AccountHomeError::AccountSetupStateMissing => "account_home_setup_state_missing",
        AccountHomeError::UnsupportedSecretBackend(_) => "account_home_unsupported_secret_backend",
        AccountHomeError::SecretStoreNotInitialized(_) => {
            "account_home_secret_store_not_initialized"
        }
        AccountHomeError::SecretStoreUnavailable(_) => "account_home_secret_store_unavailable",
        AccountHomeError::SecretStore(_) => "account_home_secret_store",
        AccountHomeError::SecretNotFound(_) => "account_home_secret_not_found",
        AccountHomeError::EmptyPassphrase => "account_home_empty_passphrase",
        AccountHomeError::EncryptedSecretExport(_) => "account_home_encrypted_secret_export",
        AccountHomeError::EmptySecretStoreService => "account_home_empty_secret_store_service",
    }
}

fn storage_error_kind(error: &StorageError) -> &'static str {
    match error {
        StorageError::NotFound => "storage_not_found",
        StorageError::AlreadyExists => "storage_already_exists",
        StorageError::SnapshotMissing(_) => "storage_snapshot_missing",
        StorageError::TimelineCursorExpired => "storage_timeline_cursor_expired",
        StorageError::Busy(_) => "storage_busy",
        StorageError::Closed(_) => "storage_closed",
        StorageError::UnsupportedSchemaVersion { .. } => "storage_unsupported_schema_version",
        StorageError::Backend(_) => "storage_backend",
        StorageError::Serialization(_) => "storage_serialization",
    }
}

#[cfg(test)]
mod tests {
    use super::AppError;

    // Kind strings leave the runtime: `account_error_message` interpolates
    // them into messages the CLI daemon persists and host apps log. Pin the
    // catch-up kind so the wire-visible string cannot drift silently — it is
    // the label operators will grep for after the RelayDirectory mislabel.
    #[test]
    fn account_catch_up_kind_is_stable() {
        let err = AppError::AccountCatchUp("runtime catch-up failed: account_session".into());
        assert_eq!(err.privacy_safe_kind(), "account_catch_up");
        assert_eq!(
            err.to_string(),
            "account catch-up failed: runtime catch-up failed: account_session"
        );
    }
}
