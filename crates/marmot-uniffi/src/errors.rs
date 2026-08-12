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
    #[error("group membership page exceeds the maximum of {max_groups} groups")]
    InvalidGroupMembershipPage { max_groups: u64 },
    /// The group exists but its full hydration has not completed yet
    /// (mdk#1161). Retryable: the runtime's background pipeline promotes the
    /// group shortly after account readiness, and worker-routed reads wait
    /// for exactly the named group. Distinct from `UnknownGroup` so hosts can
    /// render "still loading" instead of "no such group".
    #[error("group hydration pending: {group_id_hex}")]
    GroupHydrationPending { group_id_hex: String },
    #[error("invalid chat pin: {details}")]
    InvalidChatPin { details: String },
    /// Host-supplied draft attachment metadata is malformed.
    #[error("invalid message draft: {details}")]
    InvalidMessageDraft { details: String },
    /// Host-supplied encrypted-media metadata is malformed or does not match
    /// the target group's selected media profile.
    #[error("invalid media reference: {details}")]
    InvalidMediaReference { details: String },
    #[error("invalid hex: {details}")]
    InvalidHex { details: String },
    #[error("invalid nostr identity: {details}")]
    InvalidIdentity { details: String },
    /// A fetched Nostr event exists for the recipient but cannot be used as a
    /// valid Marmot KeyPackage. Kept distinct from malformed recipient input so
    /// host apps can present a setup/invite state without string matching.
    #[error("invalid key package event: {details}")]
    InvalidKeyPackageEvent { details: String },
    #[error("missing key package for {account}")]
    MissingKeyPackage { account: String },
    #[error("publish failed: {details}")]
    Publish { details: String },
    /// No current kind-3 event was found on the account's known outbox/default
    /// relays. Retrying after directory/relay recovery is safe; publishing from
    /// an assumed empty list is not.
    #[error("current account follow list is unavailable")]
    FollowListUnavailable,
    #[error("transport closed")]
    TransportClosed,
    /// Another process or runtime owns the shared Marmot root. This is a typed,
    /// retryable/fallback signal for the iOS foreground app and NSE; neither
    /// host should open an unleased runtime after receiving it.
    #[error("marmot runtime root is already in use")]
    RuntimeBusy,
    /// Another client or managed worker in this runtime currently owns the
    /// account's in-memory engine session. Retry only after that owner closes.
    #[error("marmot account session is already in use")]
    AccountSessionBusy,
    /// A pre-journal account has an encrypted database but no recoverable
    /// stable KeyPackage slot. Automatic retry cannot prove non-exposure; the
    /// host may offer `reset_incomplete_account_setup` with explicit consent.
    #[error("incomplete account setup requires explicit recovery")]
    AccountSetupRecoveryRequired,
    #[error("durable account setup can be resumed by retrying")]
    AccountSetupRetryRequired,
    #[error("account is not eligible for incomplete-setup reset")]
    AccountSetupResetNotApplicable,
    #[error("recoverable KeyPackage setup state exists; retry instead of resetting")]
    AccountSetupKeyPackageRecoveryAvailable,
    #[error("marmot runtime is shutting down")]
    RuntimeStopping,
    /// An account worker's transport catch-up failed (sync error or timeout).
    /// Distinct, typed variant — separate from [`MarmotKitError::Runtime`] —
    /// so hosts (notably the NSE wake path) can tell a catch-up failure from
    /// a generic runtime error; the untyped bucket is what sent an earlier
    /// investigation chasing the wrong subsystem.
    #[error("account catch-up failed: {details}")]
    AccountCatchUp { details: String },
    #[error("local account is not an admin of group {group_id_hex}")]
    NotGroupAdmin { group_id_hex: String },
    #[error("admin must self-demote before leaving group {group_id_hex}")]
    AdminCannotSelfRemove { group_id_hex: String },
    /// A leave is already in flight for this group. The durable request survives
    /// restarts and the engine keeps re-proposing until a commit removes us, so
    /// this is not a failure to retry — surface progress instead. Check
    /// `GroupManagementStateFfi::leave_request_pending` before offering Leave.
    #[error("a leave request is already pending for group {group_id_hex}")]
    LeaveAlreadyRequested { group_id_hex: String },
    #[error("operation would remove the last admin from group {group_id_hex}")]
    WouldRemoveLastAdmin { group_id_hex: String },
    #[error("group {group_id_hex} cannot enable disbanding until all members support it")]
    DisbandingUnsupportedMembers {
        group_id_hex: String,
        member_ids_hex: Vec<String>,
    },
    #[error("group {group_id_hex} has not enabled disbanding")]
    DisbandingNotEnabled { group_id_hex: String },
    #[error("group {group_id_hex} is disbanding or disbanded")]
    GroupDisbanding { group_id_hex: String },
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
    /// The store has been closed by [`Marmot::shutdown_and_close`][crate::Marmot::shutdown_and_close]
    /// and this call reached a database that is no longer open.
    ///
    /// Typed, and deliberately not [`MarmotKitError::Runtime`], because it is
    /// an *expected* outcome rather than a fault: a host closing its store
    /// before suspension races whatever work was still in flight, and that work
    /// must be reportable as "we shut down" instead of as a storage failure the
    /// user gets told about. Never retryable — the handle is spent; construct a
    /// new `Marmot` when the app resumes.
    #[error("storage closed: {details}")]
    StorageClosed { details: String },
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
    /// The account is configured for external signing, but this runtime has no
    /// registered callback for it yet. Typed so clients can prompt the user to
    /// reconnect Amber instead of surfacing a generic runtime failure.
    #[error("external signer unavailable for account {account}")]
    ExternalSignerUnavailable { account: String },
    /// The external signer returned a different public key than the account it
    /// was registered for. Typed so clients can treat this as a hard account
    /// mismatch rather than a retryable runtime error.
    #[error("external signer public key does not match account")]
    ExternalSignerMismatch,
    /// The user rejected/cancelled an external signer prompt. Typed separately
    /// from runtime failures so clients can keep the user in the flow or offer a
    /// retry without treating the account as broken.
    #[error("external signer request was rejected or cancelled")]
    ExternalSignerRejected,
    /// The group's outbound retention queue is full
    /// (`MAX_QUEUED_OUTBOUND_INTENTS_PER_GROUP`), so this message was **not**
    /// accepted and nothing was queued for it. The app layer has already
    /// retracted the optimistic local row; this variant is typed rather than
    /// the untyped [`MarmotKitError::Runtime`] bucket so the host can say the
    /// group is stuck instead of reporting an opaque failure. Unlike
    /// [`MarmotKitError::StorageBusy`] it is not worth an automatic retry:
    /// whatever the group is waiting on — a stalled publication, unsettled
    /// convergence input, or an inactive transport — clears on its own schedule,
    /// not on a timer this call could pick. Prompt the user to resend once the
    /// group is sending again.
    #[error("group {group_id_hex} has too many messages waiting to be sent")]
    GroupSendQueueFull { group_id_hex: String },
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
            AppError::InvalidGroupMembershipPage(_) => Self::InvalidGroupMembershipPage {
                max_groups: marmot_app::MAX_GROUP_MEMBER_IDS_PAGE_SIZE as u64,
            },
            AppError::InvalidChatPin(details) => Self::InvalidChatPin { details },
            AppError::GroupDisbanding(group_id_hex) => Self::GroupDisbanding { group_id_hex },
            AppError::InvalidMessageDraft(details) => Self::InvalidMessageDraft { details },
            // Encrypted-media validation failures are always media-boundary
            // errors; map them to the typed variant so send/upload/download
            // agree with build/parse even when a call site uses `?`/`From`.
            AppError::InvalidEncryptedMedia(details) => Self::InvalidMediaReference { details },
            AppError::UnsafeMediaFetch(details) => Self::InvalidMediaReference { details },
            AppError::Hex(err) => Self::InvalidHex {
                details: err.to_string(),
            },
            AppError::MissingKeyPackage(account) => Self::MissingKeyPackage { account },
            AppError::InvalidPublicKey => Self::InvalidIdentity {
                details: "invalid nostr public key".into(),
            },
            AppError::UnexpectedPrivateKey => Self::InvalidIdentity {
                details: "this operation does not accept a private key".into(),
            },
            AppError::IdentityKeyMismatch => Self::InvalidIdentity {
                details: "public identity does not match the imported private key".into(),
            },
            AppError::InvalidKeyPackageEvent(details) => Self::InvalidKeyPackageEvent { details },
            AppError::Publish(details) => Self::Publish { details },
            AppError::FollowListUnavailable => Self::FollowListUnavailable,
            AppError::TransportClosed => Self::TransportClosed,
            AppError::RuntimeBusy => Self::RuntimeBusy,
            AppError::AccountSessionBusy => Self::AccountSessionBusy,
            AppError::AccountSetupRecoveryRequired => Self::AccountSetupRecoveryRequired,
            AppError::AccountSetupRetryRequired => Self::AccountSetupRetryRequired,
            AppError::AccountSetupResetNotApplicable => Self::AccountSetupResetNotApplicable,
            AppError::AccountSetupKeyPackageRecoveryAvailable => {
                Self::AccountSetupKeyPackageRecoveryAvailable
            }
            AppError::RuntimeStopping => Self::RuntimeStopping,
            AppError::AccountCatchUp(details) => Self::AccountCatchUp { details },
            // #484: a transient storage busy error can also surface directly at
            // the app layer (not only wrapped in an EngineError). Classify it
            // as the typed transient variant here too, so Android never sees
            // transient contention as an untyped fatal Runtime error.
            AppError::Storage(ref storage_err) if storage_err.is_transient() => Self::StorageBusy {
                details: storage_err.to_string(),
            },
            // A store closed for suspension is an orderly end state, not a
            // fault. Give it its own variant so hosts can drop the result
            // silently instead of surfacing an error while backgrounding.
            AppError::Storage(ref storage_err) if storage_err.is_closed() => Self::StorageClosed {
                details: storage_err.to_string(),
            },
            AppError::ExternalSignerUnavailable(account) => {
                Self::ExternalSignerUnavailable { account }
            }
            AppError::ExternalSignerMismatch => Self::ExternalSignerMismatch,
            AppError::ExternalSignerRejected => Self::ExternalSignerRejected,
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
            EngineError::GroupNotHydrated(group_id) => Self::GroupHydrationPending {
                group_id_hex: hex::encode(group_id.as_slice()),
            },
            EngineError::NotGroupAdmin { group_id } => Self::NotGroupAdmin {
                group_id_hex: hex::encode(group_id.as_slice()),
            },
            EngineError::AdminCannotSelfRemove { group_id } => Self::AdminCannotSelfRemove {
                group_id_hex: hex::encode(group_id.as_slice()),
            },
            // The authoritative already-leaving signal. `Marmot::leave_group`
            // prechecks the pending flag for fast UX, but that check is a
            // check-then-act race, so the engine's verdict must map to the same
            // named error rather than falling through to `Runtime`.
            EngineError::LeaveAlreadyRequested { group_id } => Self::LeaveAlreadyRequested {
                group_id_hex: hex::encode(group_id.as_slice()),
            },
            EngineError::AdminDepletion { group_id } => Self::WouldRemoveLastAdmin {
                group_id_hex: hex::encode(group_id.as_slice()),
            },
            EngineError::DisbandingUnsupportedMembers { group_id, members } => {
                Self::DisbandingUnsupportedMembers {
                    group_id_hex: hex::encode(group_id.as_slice()),
                    member_ids_hex: members
                        .iter()
                        .map(|member| hex::encode(member.as_slice()))
                        .collect(),
                }
            }
            EngineError::DisbandingNotEnabled { group_id } => Self::DisbandingNotEnabled {
                group_id_hex: hex::encode(group_id.as_slice()),
            },
            EngineError::UnknownMember { group_id, member } => Self::MemberNotInGroup {
                group_id_hex: hex::encode(group_id.as_slice()),
                member_id_hex: hex::encode(member.as_slice()),
            },
            // The send was refused, not deferred: the host must be able to say
            // so, and must not auto-retry a condition that cannot clear until
            // the group resolves.
            EngineError::QueuedOutboundAtCapacity { group_id } => Self::GroupSendQueueFull {
                group_id_hex: hex::encode(group_id.as_slice()),
            },
            // #484: surface transient storage lock contention as a typed,
            // app-distinguishable variant rather than flattening it into the
            // untyped `Runtime` bucket. `StorageError::is_transient()` is the
            // single source of truth for which storage errors are transient.
            EngineError::Storage(storage_err) if storage_err.is_transient() => Self::StorageBusy {
                details: storage_err.to_string(),
            },
            // Engine work racing a close for suspension: an orderly end state,
            // reported as such rather than as a runtime fault.
            EngineError::Storage(storage_err) if storage_err.is_closed() => Self::StorageClosed {
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

    #[test]
    fn oversized_membership_page_crosses_ffi_as_typed_variant() {
        let ffi: MarmotKitError =
            AppError::InvalidGroupMembershipPage("too many groups".into()).into();
        assert!(matches!(
            ffi,
            MarmotKitError::InvalidGroupMembershipPage { max_groups: 100 }
        ));
    }

    // #484: a transient SQLITE_BUSY surfaced from a send must cross the UniFFI
    // boundary as the typed `StorageBusy` variant — never the untyped `Runtime`
    // bucket — so Android can distinguish transient contention from a fatal
    // failure without string-parsing "database is locked".
    // An account catch-up failure must cross the UniFFI
    // boundary as the typed `AccountCatchUp` variant — never the untyped
    // `Runtime` bucket, and never `RelayDirectory` (the mislabel that sent an
    // earlier investigation chasing the wrong subsystem).
    #[test]
    fn account_catch_up_crosses_ffi_as_typed_variant() {
        let app_err = AppError::AccountCatchUp("runtime catch-up failed: account_session".into());
        let ffi: MarmotKitError = app_err.into();
        match ffi {
            MarmotKitError::AccountCatchUp { details } => {
                assert!(
                    details.contains("account_session"),
                    "typed AccountCatchUp should carry the worker detail, got: {details}"
                );
            }
            other => panic!("expected AccountCatchUp, got {other:?}"),
        }
    }

    #[test]
    fn runtime_busy_crosses_ffi_as_typed_variant() {
        let ffi: MarmotKitError = AppError::RuntimeBusy.into();
        assert!(
            matches!(ffi, MarmotKitError::RuntimeBusy),
            "exclusive-root contention must remain distinguishable at the host boundary"
        );
    }

    #[test]
    fn account_session_busy_crosses_ffi_as_typed_variant() {
        let ffi: MarmotKitError = AppError::AccountSessionBusy.into();
        assert!(
            matches!(ffi, MarmotKitError::AccountSessionBusy),
            "in-process account-session contention must remain distinguishable at the host boundary"
        );
    }

    // The `leave_group` precheck on `leave_request_pending` is not atomic with
    // the send it guards, so two concurrent leaves can both pass it. The engine
    // settles the race under its own lock, and the loser's verdict has to reach
    // the host as the same named error the precheck would have produced — never
    // the untyped `Runtime` bucket, which is exactly the opaque failure this
    // field was added to eliminate.
    // Asserted against `from_engine_error` directly rather than through an
    // `AppError`: a leave failure arrives wrapped as
    // `AppError::Session(SessionError::Engine(..))`, and `cgka-session` is not a
    // dependency of this crate. `From<AppError>` funnels every such error through
    // `as_engine_error()` into this same function (see above), so this covers the
    // mapping without pulling in a crate just to construct a wrapper.
    #[test]
    fn leave_already_requested_crosses_ffi_as_typed_variant() {
        let group_id = cgka_traits::GroupId::new(vec![0x11; 16]);
        let ffi = MarmotKitError::from_engine_error(&EngineError::LeaveAlreadyRequested {
            group_id: group_id.clone(),
        });
        match ffi {
            MarmotKitError::LeaveAlreadyRequested { group_id_hex } => {
                assert_eq!(group_id_hex, hex::encode(group_id.as_slice()));
            }
            other => panic!("expected LeaveAlreadyRequested, got {other:?}"),
        }
    }

    #[test]
    fn disbanding_not_enabled_crosses_ffi_as_typed_variant() {
        let group_id = cgka_traits::GroupId::new(vec![0x22; 16]);
        let ffi = MarmotKitError::from_engine_error(&EngineError::DisbandingNotEnabled {
            group_id: group_id.clone(),
        });
        match ffi {
            MarmotKitError::DisbandingNotEnabled { group_id_hex } => {
                assert_eq!(group_id_hex, hex::encode(group_id.as_slice()));
            }
            other => panic!("expected DisbandingNotEnabled, got {other:?}"),
        }
    }

    // A refused send is the one signal the retention feature owes the host: the
    // message was not accepted at all. Flattened into `Runtime` the host cannot
    // tell it from any other failure without string-parsing, and cannot explain
    // to the user why the group stopped accepting messages.
    #[test]
    fn queued_outbound_at_capacity_crosses_ffi_as_typed_variant() {
        let group_id = cgka_traits::GroupId::new(vec![0x33; 16]);
        let ffi = MarmotKitError::from_engine_error(&EngineError::QueuedOutboundAtCapacity {
            group_id: group_id.clone(),
        });
        match ffi {
            MarmotKitError::GroupSendQueueFull { group_id_hex } => {
                assert_eq!(group_id_hex, hex::encode(group_id.as_slice()));
            }
            other => panic!("expected GroupSendQueueFull, got {other:?}"),
        }
    }

    // The variant it replaced must not regress into the opaque bucket by way of
    // some future refactor reusing `InvalidTransition` for this case.
    #[test]
    fn invalid_transition_remains_the_untyped_engine_bug_signal() {
        let ffi = MarmotKitError::from_engine_error(&EngineError::InvalidTransition(
            cgka_traits::engine_state::InvalidTransition {
                from: "Leaving",
                to: "AppMessage",
                reason: "leave request is current",
            },
        ));
        assert!(
            matches!(ffi, MarmotKitError::Runtime { .. }),
            "InvalidTransition denotes an engine bug and stays untyped; got {ffi:?}"
        );
    }

    #[test]
    fn unsafe_media_fetch_crosses_ffi_as_typed_media_reference() {
        let app_err = AppError::UnsafeMediaFetch("unsafe profile image URL".into());
        let ffi: MarmotKitError = app_err.into();
        assert!(matches!(ffi, MarmotKitError::InvalidMediaReference { .. }));
    }

    #[test]
    fn invalid_encrypted_media_crosses_ffi_as_typed_media_reference() {
        let app_err =
            AppError::InvalidEncryptedMedia("group requires encrypted-media-v2 references".into());
        let ffi: MarmotKitError = app_err.into();
        match ffi {
            MarmotKitError::InvalidMediaReference { details } => {
                assert!(
                    details.contains("encrypted-media-v2"),
                    "typed InvalidMediaReference should carry the media detail, got: {details}"
                );
            }
            other => panic!("expected InvalidMediaReference, got {other:?}"),
        }
    }

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
    fn invalid_key_package_event_maps_to_typed_variant() {
        let app_err = AppError::InvalidKeyPackageEvent("unsupported cipher suite".to_string());
        let ffi: MarmotKitError = app_err.into();
        assert!(
            matches!(
                ffi,
                MarmotKitError::InvalidKeyPackageEvent { ref details }
                    if details == "unsupported cipher suite"
            ),
            "invalid KeyPackage events must not be flattened into InvalidIdentity, got {ffi:?}"
        );
    }

    #[test]
    fn incomplete_account_setup_crosses_ffi_as_typed_recovery() {
        let ffi: MarmotKitError = AppError::AccountSetupRecoveryRequired.into();
        assert!(matches!(ffi, MarmotKitError::AccountSetupRecoveryRequired));
    }

    #[test]
    fn account_setup_reset_refusals_cross_ffi_as_typed_variants() {
        assert!(matches!(
            MarmotKitError::from(AppError::AccountSetupRetryRequired),
            MarmotKitError::AccountSetupRetryRequired
        ));
        assert!(matches!(
            MarmotKitError::from(AppError::AccountSetupResetNotApplicable),
            MarmotKitError::AccountSetupResetNotApplicable
        ));
        assert!(matches!(
            MarmotKitError::from(AppError::AccountSetupKeyPackageRecoveryAvailable),
            MarmotKitError::AccountSetupKeyPackageRecoveryAvailable
        ));
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
