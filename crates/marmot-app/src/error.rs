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
    Transport(#[from] TransportAdapterError),
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
    #[error("relay directory fetch failed: {0}")]
    RelayDirectory(String),
    #[error("invalid Nostr public key")]
    InvalidPublicKey,
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
    #[error("marmot runtime is shutting down")]
    RuntimeStopping,
    #[error("no matching reaction by this account to retract")]
    ReactionNotFound,
    #[error("transport event stream closed")]
    TransportClosed,
}

impl AppError {
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
            Self::AgentStreamMissingStart => "agent_stream_missing_start",
            Self::AgentStreamStartNotConfirmed => "agent_stream_start_not_confirmed",
            Self::AgentStreamUnsupportedRoute => "agent_stream_unsupported_route",
            Self::AgentStreamMissingCandidate => "agent_stream_missing_candidate",
            Self::AgentStreamInvalidCandidate(_) => "agent_stream_invalid_candidate",
            Self::Publish(_) => "publish",
            Self::MissingDefaultRelays => "missing_default_relays",
            Self::MissingRelayLists(_) => "missing_relay_lists",
            Self::RelayDirectory(_) => "relay_directory",
            Self::InvalidPublicKey => "invalid_public_key",
            Self::InvalidKeyPackageEvent(_) => "invalid_key_package_event",
            Self::MissingDirectoryEntry(_) => "missing_directory_entry",
            Self::InvalidDirectorySearch(_) => "invalid_directory_search",
            Self::InvalidGroupProfile(_) => "invalid_group_profile",
            Self::InvalidNostrRouting(_) => "invalid_nostr_routing",
            Self::InvalidGroupAvatarUrl(_) => "invalid_group_avatar_url",
            Self::InvalidAgentTextStreamPolicy(_) => "invalid_agent_text_stream_policy",
            Self::InvalidEncryptedMedia(_) => "invalid_encrypted_media",
            Self::BlobStore(_) => "blob_store",
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
        AccountError::WrongAccountDelivery => "account_wrong_delivery",
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
        StorageError::Busy(_) => "storage_busy",
        StorageError::Backend(_) => "storage_backend",
        StorageError::Serialization(_) => "storage_serialization",
    }
}
