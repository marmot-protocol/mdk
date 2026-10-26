//! Every way the lower stack hands the app an error, and what each host
//! reports for it.
//!
//! What a host sees must depend on what an error is, not on which layers
//! wrapped it (mdk#2602). Each row builds one error through the conversions
//! the session and account layers use, and states the answers hosts read from
//! it. No one crate can see every classifier, so each checks its own columns
//! over these rows: `marmot-app` the sync class, the privacy kind and the wipe
//! reason, `marmot-uniffi` MarmotKit, `marmot-c` the C status and `wn-cli` the
//! CLI code. A call that moves between layers keeps its answers; a change to
//! any answer fails the crate that owns it.

use cgka_session::SessionError;
use cgka_traits::TransportAdapterError;
use cgka_traits::error::EngineError;
use cgka_traits::storage::StorageError;
use cgka_traits::types::GroupId;
use marmot_account::AccountError;

use crate::{AppError, EXTERNAL_SIGNER_REJECTED, SyncErrorClass};

/// One wrapping of one error, and the answers every host gives for it.
#[derive(Debug)]
pub struct ErrorKindRow {
    /// The error and how it was wrapped, for failure messages.
    pub name: String,
    pub error: AppError,
    pub expected: HostAnswers,
}

/// What each host reports for an error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostAnswers {
    /// The `MarmotKitError` variant name.
    pub marmotkit: &'static str,
    /// The `MarmotStatus` variant name.
    pub c_status: &'static str,
    /// The `code` field of the CLI's JSON error.
    pub cli_code: &'static str,
    pub sync_class: SyncErrorClass,
    pub privacy_kind: &'static str,
    /// The failure reason a `WipeOutcome` reports.
    pub wipe_reason: &'static str,
}

/// An external-signer rejection, wherever the lower stack meets it: the
/// answers a rejection on the transport path has always had.
const SIGNER_REJECTED: HostAnswers = HostAnswers {
    marmotkit: "ExternalSignerRejected",
    c_status: "ExternalSignerRejected",
    cli_code: "command_failed",
    sync_class: SyncErrorClass::Cancelled,
    privacy_kind: "external_signer_rejected",
    wipe_reason: "operation failed",
};

/// The rows. Each call builds fresh errors, since `AppError` is not `Clone`.
pub fn lower_stack_rows() -> Vec<ErrorKindRow> {
    let mut rows = Vec::new();
    let storage_kinds: [(&str, fn() -> StorageError, HostAnswers); 5] = [
        (
            "busy",
            || StorageError::Busy("database is locked".into()),
            HostAnswers {
                marmotkit: "StorageBusy",
                c_status: "StorageBusy",
                cli_code: "engine_error",
                sync_class: SyncErrorClass::StorageBusy,
                privacy_kind: "storage_busy",
                wipe_reason: "local storage error",
            },
        ),
        (
            "closed",
            || StorageError::Closed("closed for suspension".into()),
            HostAnswers {
                marmotkit: "StorageClosed",
                c_status: "StorageClosed",
                cli_code: "engine_error",
                sync_class: SyncErrorClass::Storage,
                privacy_kind: "storage_closed",
                wipe_reason: "local storage error",
            },
        ),
        (
            "full",
            || StorageError::Capacity("disk full".into()),
            HostAnswers {
                marmotkit: "StorageFull",
                c_status: "StorageFull",
                cli_code: "engine_error",
                sync_class: SyncErrorClass::StorageCapacity,
                privacy_kind: "storage_capacity",
                wipe_reason: "local storage error",
            },
        ),
        (
            "corruption",
            || StorageError::Corruption("malformed page".into()),
            HostAnswers {
                marmotkit: "Runtime",
                c_status: "Runtime",
                cli_code: "engine_error",
                sync_class: SyncErrorClass::StorageCorruption,
                privacy_kind: "storage_corruption",
                wipe_reason: "local storage error",
            },
        ),
        (
            "other",
            || StorageError::Backend("io failure".into()),
            HostAnswers {
                marmotkit: "Runtime",
                c_status: "Runtime",
                cli_code: "engine_error",
                sync_class: SyncErrorClass::Storage,
                privacy_kind: "storage_backend",
                wipe_reason: "local storage error",
            },
        ),
    ];
    for (kind, storage, expected) in storage_kinds {
        // The session meets a bare storage failure when it opens or reads the
        // database itself; the engine meets one inside its own calls.
        rows.push(row(
            format!("storage {kind} from the session"),
            AppError::from(SessionError::from(storage())),
            expected,
        ));
        rows.push(row(
            format!("storage {kind} from the session, through the account"),
            AppError::from(AccountError::from(SessionError::from(storage()))),
            expected,
        ));
        push_engine_wrappings(
            &mut rows,
            &format!("storage {kind} from the engine"),
            || EngineError::from(storage()),
            expected,
        );
    }

    push_engine_wrappings(
        &mut rows,
        "unknown group",
        || EngineError::UnknownGroup(GroupId::new(vec![7; 16])),
        HostAnswers {
            marmotkit: "UnknownGroup",
            c_status: "UnknownGroup",
            cli_code: "unknown_group",
            sync_class: SyncErrorClass::Unknown,
            privacy_kind: "unknown_group",
            wipe_reason: "unknown local group",
        },
    );
    push_engine_wrappings(
        &mut rows,
        "invalid welcome",
        || EngineError::InvalidWelcome,
        HostAnswers {
            marmotkit: "Runtime",
            c_status: "Runtime",
            cli_code: "engine_error",
            sync_class: SyncErrorClass::Protocol,
            privacy_kind: "invalid_welcome",
            wipe_reason: "session error",
        },
    );

    // The signing hook reports a rejection as an identity-proof failure.
    // Opening the session reports the hook's error again, as text inside
    // `Other`, because the engine builds the device identity with a `String`
    // error.
    let hook_rejection = || {
        EngineError::InvalidAccountIdentityProof(format!(
            "signing failed: {EXTERNAL_SIGNER_REJECTED}"
        ))
    };
    push_engine_wrappings(
        &mut rows,
        "signer rejection from the signing hook",
        hook_rejection,
        SIGNER_REJECTED,
    );
    push_engine_wrappings(
        &mut rows,
        "signer rejection at session open",
        || EngineError::Other(hook_rejection().to_string()),
        SIGNER_REJECTED,
    );
    let transport_rejection =
        || TransportAdapterError::Publish(format!("signer: {EXTERNAL_SIGNER_REJECTED}"));
    rows.push(row(
        "signer rejection from the transport".into(),
        AppError::from(transport_rejection()),
        SIGNER_REJECTED,
    ));
    rows.push(row(
        "signer rejection from the transport, through the account".into(),
        AppError::from(AccountError::from(transport_rejection())),
        SIGNER_REJECTED,
    ));

    // Without the sentinel, an identity failure keeps the answers of the
    // engine variant that carries it.
    push_engine_wrappings(
        &mut rows,
        "identity proof failure",
        || {
            EngineError::InvalidAccountIdentityProof(
                "signing failed: request account identity does not match local Nostr key".into(),
            )
        },
        HostAnswers {
            marmotkit: "Runtime",
            c_status: "Runtime",
            cli_code: "engine_error",
            sync_class: SyncErrorClass::Protocol,
            privacy_kind: "invalid_account_identity_proof",
            wipe_reason: "session error",
        },
    );
    push_engine_wrappings(
        &mut rows,
        "identity failure at session open",
        || EngineError::Other("signing failed: signer unavailable".into()),
        HostAnswers {
            marmotkit: "Runtime",
            c_status: "Runtime",
            cli_code: "engine_error",
            sync_class: SyncErrorClass::Unknown,
            privacy_kind: "other",
            wipe_reason: "session error",
        },
    );
    rows
}

/// The three ways an engine error reaches the app: through the session,
/// through the account runtime, and through the session inside the runtime.
fn push_engine_wrappings(
    rows: &mut Vec<ErrorKindRow>,
    name: &str,
    engine: impl Fn() -> EngineError,
    expected: HostAnswers,
) {
    rows.push(row(
        format!("{name}, through the session"),
        AppError::from(SessionError::from(engine())),
        expected,
    ));
    rows.push(row(
        format!("{name}, through the account"),
        AppError::from(AccountError::from(engine())),
        expected,
    ));
    rows.push(row(
        format!("{name}, through the session and the account"),
        AppError::from(AccountError::from(SessionError::from(engine()))),
        expected,
    ));
}

fn row(name: String, error: AppError, expected: HostAnswers) -> ErrorKindRow {
    ErrorKindRow {
        name,
        error,
        expected,
    }
}

#[cfg(test)]
mod tests {
    use super::lower_stack_rows;
    use crate::runtime::wipe_failure_reason;

    #[test]
    fn app_answers_follow_the_error_not_its_wrapping() {
        let mismatches: Vec<String> = lower_stack_rows()
            .into_iter()
            .filter_map(|row| {
                let actual = (
                    row.error.sync_error_class(),
                    row.error.privacy_safe_kind(),
                    wipe_failure_reason(&row.error),
                );
                let expected = (
                    row.expected.sync_class,
                    row.expected.privacy_kind,
                    row.expected.wipe_reason.to_owned(),
                );
                (actual != expected)
                    .then(|| format!("{}: {actual:?}, expected {expected:?}", row.name))
            })
            .collect();
        assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
    }
}
