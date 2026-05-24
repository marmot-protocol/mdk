use marmot_app::AppError;

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum MarmotKitError {
    #[error("identity already exists: {account}")]
    DuplicateIdentity { account: String },
    #[error("unknown account: {account_ref}")]
    UnknownAccount { account_ref: String },
    #[error("unknown group: {group_id_hex}")]
    UnknownGroup { group_id_hex: String },
    #[error("invalid hex: {details}")]
    InvalidHex { details: String },
    #[error("invalid nostr identity: {details}")]
    InvalidIdentity { details: String },
    #[error("missing key package for {account}")]
    MissingKeyPackage { account: String },
    #[error("publish failed: {details}")]
    Publish { details: String },
    #[error("transport closed")]
    TransportClosed,
    #[error("marmot runtime error: {details}")]
    Runtime { details: String },
}

impl From<AppError> for MarmotKitError {
    fn from(value: AppError) -> Self {
        match value {
            AppError::UnknownGroup(group_id_hex) => Self::UnknownGroup { group_id_hex },
            AppError::Hex(err) => Self::InvalidHex {
                details: err.to_string(),
            },
            AppError::MissingKeyPackage(account) => Self::MissingKeyPackage { account },
            AppError::InvalidPublicKey => Self::InvalidIdentity {
                details: "invalid nostr public key".into(),
            },
            AppError::InvalidKeyPackageEvent(details) => Self::InvalidIdentity { details },
            AppError::Publish(details) => Self::Publish { details },
            AppError::TransportClosed => Self::TransportClosed,
            other => Self::Runtime {
                details: other.to_string(),
            },
        }
    }
}
