//! Crate-level error and result type aliases for account orchestration.

use cgka_session::SessionError;
use cgka_traits::TransportAdapterError;
use cgka_traits::error::EngineError;

use crate::key_package::KeyPackagePublishError;
use crate::routing::TransportRoutingError;

pub type AccountResult<T> = Result<T, AccountError>;

pub type AccountHomeResult<T> = Result<T, AccountHomeError>;

#[derive(Debug, thiserror::Error)]
pub enum AccountHomeError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),
    #[error("account already exists: {0}")]
    AccountExists(String),
    #[error("account id is already in use: {0}")]
    AccountIdInUse(String),
    #[error("unknown account: {0}")]
    UnknownAccount(String),
    #[error("invalid nsec or secret key")]
    InvalidSecretKey,
    #[error("invalid Nostr public key")]
    InvalidPublicKey,
    #[error("invalid account label: {0}")]
    InvalidAccountLabel(String),
    #[error("stored account id does not match stored secret key")]
    AccountIdMismatch,
    #[error("unsupported account secret storage backend: {0}")]
    UnsupportedSecretBackend(String),
    #[error("account secret store is not initialized: {0}")]
    SecretStoreNotInitialized(String),
    #[error("account secret store is unavailable: {0}")]
    SecretStoreUnavailable(String),
    #[error("account secret store operation failed: {0}")]
    SecretStore(String),
    #[error("account secret was not found")]
    SecretNotFound(String),
    #[error("passphrase cannot be empty")]
    EmptyPassphrase,
    #[error("encrypted secret-key export failed: {0}")]
    EncryptedSecretExport(String),
    #[error("account secret store service name cannot be empty")]
    EmptySecretStoreService,
}

#[derive(Debug, thiserror::Error)]
pub enum AccountError {
    #[error(transparent)]
    Session(#[from] SessionError),
    #[error(transparent)]
    Engine(#[from] EngineError),
    #[error(transparent)]
    Transport(#[from] TransportAdapterError),
    #[error(transparent)]
    TransportRouting(#[from] TransportRoutingError),
    #[error(transparent)]
    KeyPackage(#[from] KeyPackagePublishError),
    #[error("transport delivery was addressed to a different account")]
    WrongAccountDelivery,
}
