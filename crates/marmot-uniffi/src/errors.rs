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
    /// The account exists but its raw private key could not be located in the
    /// keystore — e.g. a public-only / watch-only account, or a secret that was
    /// never loaded. Distinct, typed variant (#543) so a key-backup surface can
    /// tell "this account has no exportable key" apart from a generic runtime
    /// failure without string-parsing.
    #[error("account secret not found: {details}")]
    SecretNotFound { details: String },
    /// The platform secret store / keychain is locked, uninitialized, or
    /// otherwise unavailable, so the raw private key could not be read. Typed
    /// variant (#543) so a key-backup surface can prompt the user to unlock the
    /// keystore rather than reporting an opaque runtime error.
    #[error("account keystore unavailable: {details}")]
    KeystoreUnavailable { details: String },
    /// The user supplied an empty passphrase for NIP-49 encrypted key export.
    /// Distinct typed variant (#544) so backup UI can keep the user in the
    /// passphrase sheet instead of showing a generic runtime failure.
    #[error("passphrase cannot be empty")]
    EmptyPassphrase,
    /// NIP-49 encryption failed after keystore access succeeded. Carries only
    /// library/error classification text, never passphrase or key material.
    #[error("encrypted secret-key export failed: {details}")]
    EncryptionFailed { details: String },
    /// A filesystem IO error while reading the key, appending the reveal audit
    /// entry, or persisting the NIP-49 key-security byte. Typed variant (#543)
    /// so a key-backup surface can distinguish disk failures from arbitrary
    /// runtime faults.
    #[error("io error: {details}")]
    Io { details: String },
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
            // #543: reveal_nsec must surface its required failure modes as typed
            // FFI errors, not the untyped `Runtime` bucket, so a key-backup
            // surface can distinguish "no exportable key" / "keystore locked" /
            // "disk IO" without string-parsing.
            //
            // No raw key is loaded for this account (public-only / watch-only,
            // or the secret was never imported).
            AppError::AccountHome(ref err @ AccountHomeError::SecretNotFound(_)) => {
                Self::SecretNotFound {
                    details: err.to_string(),
                }
            }
            // The platform keystore is locked / uninitialized / unavailable.
            AppError::AccountHome(
                ref err @ (AccountHomeError::SecretStoreNotInitialized(_)
                | AccountHomeError::SecretStoreUnavailable(_)
                | AccountHomeError::SecretStore(_)),
            ) => Self::KeystoreUnavailable {
                details: err.to_string(),
            },
            AppError::AccountHome(AccountHomeError::EmptyPassphrase) => Self::EmptyPassphrase,
            AppError::AccountHome(AccountHomeError::EncryptedSecretExport(details)) => {
                Self::EncryptionFailed { details }
            }
            // A filesystem IO error reading the key, appending the reveal audit
            // entry, or persisting the key-security byte — surfaced either
            // directly at the app layer or wrapped in an AccountHomeError.
            AppError::Io(ref err) => Self::Io {
                details: err.to_string(),
            },
            AppError::AccountHome(ref err @ AccountHomeError::Io(_)) => Self::Io {
                details: err.to_string(),
            },
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
    use marmot_account::{AccountError, AccountHomeError};
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

    // #543: reveal_nsec must surface its required failure modes (no exportable
    // key / keystore locked-or-unavailable / disk IO) as typed FFI variants so
    // a key-backup surface can react without string-parsing a generic Runtime
    // error.
    #[test]
    fn reveal_secret_not_found_crosses_ffi_as_typed_variant() {
        let app_err = AppError::AccountHome(AccountHomeError::SecretNotFound(
            "no secret stored for account".to_string(),
        ));
        let ffi: MarmotKitError = app_err.into();
        assert!(
            matches!(ffi, MarmotKitError::SecretNotFound { .. }),
            "public-only / missing secret must map to SecretNotFound, got {ffi:?}"
        );
    }

    #[test]
    fn reveal_keystore_unavailable_crosses_ffi_as_typed_variant() {
        for app_err in [
            AppError::AccountHome(AccountHomeError::SecretStoreNotInitialized(
                "keychain not initialized".to_string(),
            )),
            AppError::AccountHome(AccountHomeError::SecretStoreUnavailable(
                "keychain locked".to_string(),
            )),
            AppError::AccountHome(AccountHomeError::SecretStore(
                "keychain query failed".to_string(),
            )),
        ] {
            let ffi: MarmotKitError = app_err.into();
            assert!(
                matches!(ffi, MarmotKitError::KeystoreUnavailable { .. }),
                "locked / unavailable keystore must map to KeystoreUnavailable, got {ffi:?}"
            );
        }
    }

    #[test]
    fn reveal_io_error_crosses_ffi_as_typed_variant() {
        // A direct app-layer IO error (e.g. appending the reveal audit line).
        let direct: MarmotKitError = AppError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "audit append failed",
        ))
        .into();
        assert!(
            matches!(direct, MarmotKitError::Io { .. }),
            "direct app-layer IO failure must map to Io, got {direct:?}"
        );

        // An IO error wrapped in AccountHomeError (e.g. persisting the
        // key-security byte or reading the keystore file).
        let wrapped: MarmotKitError = AppError::AccountHome(AccountHomeError::Io(
            std::io::Error::other("key-security write failed"),
        ))
        .into();
        assert!(
            matches!(wrapped, MarmotKitError::Io { .. }),
            "AccountHome IO failure must map to Io, got {wrapped:?}"
        );
    }

    #[test]
    fn encrypted_export_empty_passphrase_crosses_ffi_as_typed_variant() {
        let app_err = AppError::AccountHome(AccountHomeError::EmptyPassphrase);
        let ffi: MarmotKitError = app_err.into();
        assert!(
            matches!(ffi, MarmotKitError::EmptyPassphrase),
            "empty passphrase must map to EmptyPassphrase, got {ffi:?}"
        );
    }

    #[test]
    fn encrypted_export_failure_crosses_ffi_as_typed_variant() {
        let app_err = AppError::AccountHome(AccountHomeError::EncryptedSecretExport(
            "scrypt params rejected".to_string(),
        ));
        let ffi: MarmotKitError = app_err.into();
        assert!(
            matches!(
                ffi,
                MarmotKitError::EncryptionFailed { ref details }
                    if details == "scrypt params rejected"
            ),
            "NIP-49 encryption failures must map to EncryptionFailed without duplicating the AccountHomeError prefix, got {ffi:?}"
        );
    }
}
