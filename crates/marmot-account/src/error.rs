//! Crate-level error and result type aliases for the account home.

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
    #[error("this device was unlinked from the account: {0}")]
    AccountUnlinked(String),
    #[error("invalid nsec or secret key")]
    InvalidSecretKey,
    #[error("invalid Nostr public key")]
    InvalidPublicKey,
    #[error("invalid account label: {0}")]
    InvalidAccountLabel(String),
    #[error("stored account id does not match stored secret key")]
    AccountIdMismatch,
    #[error("durable account setup state is missing")]
    AccountSetupStateMissing,
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
