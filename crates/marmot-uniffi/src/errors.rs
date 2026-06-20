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
    /// Transient storage lock contention (`SQLITE_BUSY` / "database is locked")
    /// that survived the storage layer's internal retry-with-backoff. It is a
    /// distinct, typed variant — separate from [`MarmotKitError::Runtime`] — so
    /// the app (#484) can recognise a *transient* condition worth a user retry
    /// or auto-retry instead of string-parsing "database is locked" and
    /// surfacing it as a fatal "Send failed".
    #[error("storage busy: {details}")]
    StorageBusy { details: String },
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
            // #484: a transient storage busy error can also surface directly at
            // the app layer (not only wrapped in an EngineError). Classify it
            // as the typed transient variant here too, so Android never sees
            // transient contention as an untyped fatal Runtime error.
            AppError::Storage(ref storage_err) if storage_err.is_transient() => Self::StorageBusy {
                details: storage_err.to_string(),
            },
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
            // #484: surface transient storage lock contention as a typed,
            // app-distinguishable variant rather than flattening it into the
            // untyped `Runtime` bucket. `StorageError::is_transient()` is the
            // single source of truth for which storage errors are transient.
            EngineError::Storage(storage_err) if storage_err.is_transient() => Self::StorageBusy {
                details: storage_err.to_string(),
            },
            other => Self::Runtime {
                details: other.to_string(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::MarmotKitError;
    use cgka_traits::error::EngineError;
    use cgka_traits::storage::StorageError;
    use marmot_account::AccountError;
    use marmot_app::AppError;

    // #484: a transient SQLITE_BUSY surfaced from a send must cross the UniFFI
    // boundary as the typed `StorageBusy` variant — never the untyped `Runtime`
    // bucket — so Android can distinguish transient contention from a fatal
    // failure without string-parsing "database is locked".
    #[test]
    fn storage_busy_crosses_ffi_as_typed_variant_via_engine() {
        // Send path: storage Busy wrapped in EngineError, wrapped in AppError
        // through the account/engine error chain (the real `do_send` shape).
        let app_err = AppError::Account(AccountError::Engine(EngineError::Storage(
            StorageError::Busy("database is locked".to_string()),
        )));
        let ffi: MarmotKitError = app_err.into();
        match ffi {
            MarmotKitError::StorageBusy { details } => {
                assert!(
                    details.contains("busy"),
                    "typed StorageBusy should carry the storage detail, got: {details}"
                );
            }
            other => panic!("expected StorageBusy, got {other:?}"),
        }
    }

    #[test]
    fn storage_busy_crosses_ffi_as_typed_variant_directly() {
        // A transient storage Busy can also surface directly at the app layer
        // (AppError::Storage) without an EngineError wrapper.
        let app_err = AppError::Storage(StorageError::Busy("database is locked".to_string()));
        let ffi: MarmotKitError = app_err.into();
        assert!(
            matches!(ffi, MarmotKitError::StorageBusy { .. }),
            "direct AppError::Storage(Busy) must map to StorageBusy, got {ffi:?}"
        );
    }

    #[test]
    fn non_transient_storage_error_stays_runtime() {
        // A durable backend fault must NOT be misclassified as transient.
        let app_err = AppError::Storage(StorageError::Backend("disk full".to_string()));
        let ffi: MarmotKitError = app_err.into();
        assert!(
            matches!(ffi, MarmotKitError::Runtime { .. }),
            "non-transient storage faults must stay Runtime, got {ffi:?}"
        );

        let engine_app_err = AppError::Account(AccountError::Engine(EngineError::Storage(
            StorageError::NotFound,
        )));
        let engine_ffi: MarmotKitError = engine_app_err.into();
        assert!(
            matches!(engine_ffi, MarmotKitError::Runtime { .. }),
            "non-transient engine storage faults must stay Runtime, got {engine_ffi:?}"
        );
    }
}
