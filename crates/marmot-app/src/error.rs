use cgka_traits::TransportAdapterError;
use marmot_account::AccountHomeError;

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
    MissingRelayLists(Vec<String>),
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
