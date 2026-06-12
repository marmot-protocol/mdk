use cgka_traits::error::EngineError;
use marmot_account::AccountHomeError;
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
    #[error("marmot runtime is shutting down")]
    RuntimeStopping,
    #[error("local account is not an admin of group {group_id_hex}")]
    NotGroupAdmin { group_id_hex: String },
    #[error("admin must self-demote before leaving group {group_id_hex}")]
    AdminCannotSelfRemove { group_id_hex: String },
    #[error("operation would remove the last admin from group {group_id_hex}")]
    WouldRemoveLastAdmin { group_id_hex: String },
    #[error("member {member_id_hex} is not in group {group_id_hex}")]
    MemberNotInGroup {
        group_id_hex: String,
        member_id_hex: String,
    },
    #[error("member {member_id_hex} is already an admin of group {group_id_hex}")]
    AlreadyAdmin {
        group_id_hex: String,
        member_id_hex: String,
    },
    #[error("member {member_id_hex} is not an admin of group {group_id_hex}")]
    NotAdmin {
        group_id_hex: String,
        member_id_hex: String,
    },
    #[error("marmot runtime error: {details}")]
    Runtime { details: String },
}

impl From<AppError> for MarmotKitError {
    fn from(value: AppError) -> Self {
        if let Some(err) = value.as_engine_error() {
            return Self::from_engine_error(err);
        }
        match value {
            AppError::AccountHome(AccountHomeError::UnknownAccount(account_ref)) => {
                Self::UnknownAccount { account_ref }
            }
            AppError::AccountHome(AccountHomeError::AccountExists(account)) => {
                Self::DuplicateIdentity { account }
            }
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
            AppError::RuntimeStopping => Self::RuntimeStopping,
            other => Self::Runtime {
                details: other.to_string(),
            },
        }
    }
}

impl MarmotKitError {
    fn from_engine_error(value: &EngineError) -> Self {
        match value {
            EngineError::UnknownGroup(group_id) => Self::UnknownGroup {
                group_id_hex: hex::encode(group_id.as_slice()),
            },
            EngineError::NotGroupAdmin { group_id } => Self::NotGroupAdmin {
                group_id_hex: hex::encode(group_id.as_slice()),
            },
            EngineError::AdminCannotSelfRemove { group_id } => Self::AdminCannotSelfRemove {
                group_id_hex: hex::encode(group_id.as_slice()),
            },
            EngineError::AdminDepletion { group_id } => Self::WouldRemoveLastAdmin {
                group_id_hex: hex::encode(group_id.as_slice()),
            },
            EngineError::UnknownMember { group_id, member } => Self::MemberNotInGroup {
                group_id_hex: hex::encode(group_id.as_slice()),
                member_id_hex: hex::encode(member.as_slice()),
            },
            other => Self::Runtime {
                details: other.to_string(),
            },
        }
    }
}
