//! C ABI status codes and the thread-local last-error detail channel.
//!
//! Every fallible `extern "C"` function returns a [`MarmotStatus`]. The
//! numeric values are part of the stable C ABI — append new codes, never
//! renumber existing ones.

use std::cell::RefCell;

use marmot_uniffi::MarmotKitError;

/// Status code returned by every fallible `marmot_*` function.
///
/// `MARMOT_STATUS_OK` (0) means success. Codes 1-9 are binding-level
/// failures raised by `marmot-c` itself; codes 10+ mirror the runtime's
/// typed error variants one-to-one. Retrieve the human-readable detail for
/// the most recent failure on the current thread with
/// `marmot_last_error_message()`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarmotStatus {
    Ok = 0,

    // Binding-level codes (raised by marmot-c, not the runtime).
    /// A required pointer argument was NULL.
    NullPointer = 1,
    /// A string argument was not valid UTF-8.
    InvalidUtf8 = 2,
    /// A Rust panic was caught at the FFI boundary. State may be
    /// inconsistent; treat as fatal.
    PanicCaught = 3,
    /// A blocking subscription read timed out; no item was produced.
    Timeout = 4,
    /// The subscription is closed (runtime shutdown or sender dropped);
    /// no further items will be produced.
    Closed = 5,

    // Runtime error variants (mirror marmot_uniffi::MarmotKitError).
    DuplicateIdentity = 10,
    UnknownAccount = 11,
    UnknownGroup = 12,
    InvalidHex = 13,
    InvalidIdentity = 14,
    MissingKeyPackage = 15,
    Publish = 16,
    TransportClosed = 17,
    RuntimeStopping = 18,
    NotGroupAdmin = 19,
    AdminCannotSelfRemove = 20,
    WouldRemoveLastAdmin = 21,
    MemberNotInGroup = 22,
    AlreadyAdmin = 23,
    NotAdmin = 24,
    StorageBusy = 25,
    SecretNotFound = 26,
    KeystoreUnavailable = 27,
    EmptyPassphrase = 28,
    EncryptionFailed = 29,
    Io = 30,
    Runtime = 31,
    ExternalSignerUnavailable = 32,
    ExternalSignerMismatch = 33,
    ExternalSignerRejected = 34,
}

thread_local! {
    static LAST_ERROR: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// Record the detail string for the current thread's most recent failure.
pub(crate) fn set_last_error(message: impl Into<String>) {
    LAST_ERROR.with(|slot| *slot.borrow_mut() = Some(message.into()));
}

/// Take (and clear) the current thread's most recent failure detail.
pub(crate) fn take_last_error() -> Option<String> {
    LAST_ERROR.with(|slot| slot.borrow_mut().take())
}

/// Map a runtime error to its status code and record its detail string.
pub(crate) fn status_from_error(err: &MarmotKitError) -> MarmotStatus {
    set_last_error(err.to_string());
    match err {
        MarmotKitError::DuplicateIdentity { .. } => MarmotStatus::DuplicateIdentity,
        MarmotKitError::UnknownAccount { .. } => MarmotStatus::UnknownAccount,
        MarmotKitError::UnknownGroup { .. } => MarmotStatus::UnknownGroup,
        MarmotKitError::InvalidHex { .. } => MarmotStatus::InvalidHex,
        MarmotKitError::InvalidIdentity { .. } => MarmotStatus::InvalidIdentity,
        MarmotKitError::MissingKeyPackage { .. } => MarmotStatus::MissingKeyPackage,
        MarmotKitError::Publish { .. } => MarmotStatus::Publish,
        MarmotKitError::TransportClosed => MarmotStatus::TransportClosed,
        MarmotKitError::RuntimeStopping => MarmotStatus::RuntimeStopping,
        MarmotKitError::NotGroupAdmin { .. } => MarmotStatus::NotGroupAdmin,
        MarmotKitError::AdminCannotSelfRemove { .. } => MarmotStatus::AdminCannotSelfRemove,
        MarmotKitError::WouldRemoveLastAdmin { .. } => MarmotStatus::WouldRemoveLastAdmin,
        MarmotKitError::MemberNotInGroup { .. } => MarmotStatus::MemberNotInGroup,
        MarmotKitError::AlreadyAdmin { .. } => MarmotStatus::AlreadyAdmin,
        MarmotKitError::NotAdmin { .. } => MarmotStatus::NotAdmin,
        MarmotKitError::StorageBusy { .. } => MarmotStatus::StorageBusy,
        MarmotKitError::SecretNotFound { .. } => MarmotStatus::SecretNotFound,
        MarmotKitError::KeystoreUnavailable { .. } => MarmotStatus::KeystoreUnavailable,
        MarmotKitError::EmptyPassphrase => MarmotStatus::EmptyPassphrase,
        MarmotKitError::EncryptionFailed { .. } => MarmotStatus::EncryptionFailed,
        MarmotKitError::Io { .. } => MarmotStatus::Io,
        MarmotKitError::Runtime { .. } => MarmotStatus::Runtime,
        MarmotKitError::ExternalSignerUnavailable { .. } => {
            MarmotStatus::ExternalSignerUnavailable
        }
        MarmotKitError::ExternalSignerMismatch => MarmotStatus::ExternalSignerMismatch,
        MarmotKitError::ExternalSignerRejected => MarmotStatus::ExternalSignerRejected,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_runtime_error_variant_maps_to_a_distinct_status() {
        let _guard = crate::memory::audit::test_lock();
        let variants: Vec<MarmotKitError> = vec![
            MarmotKitError::DuplicateIdentity {
                account: "a".into(),
            },
            MarmotKitError::UnknownAccount {
                account_ref: "a".into(),
            },
            MarmotKitError::UnknownGroup {
                group_id_hex: "aa".into(),
            },
            MarmotKitError::InvalidHex {
                details: "d".into(),
            },
            MarmotKitError::InvalidIdentity {
                details: "d".into(),
            },
            MarmotKitError::MissingKeyPackage {
                account: "a".into(),
            },
            MarmotKitError::Publish {
                details: "d".into(),
            },
            MarmotKitError::TransportClosed,
            MarmotKitError::RuntimeStopping,
            MarmotKitError::NotGroupAdmin {
                group_id_hex: "aa".into(),
            },
            MarmotKitError::AdminCannotSelfRemove {
                group_id_hex: "aa".into(),
            },
            MarmotKitError::WouldRemoveLastAdmin {
                group_id_hex: "aa".into(),
            },
            MarmotKitError::MemberNotInGroup {
                group_id_hex: "aa".into(),
                member_id_hex: "bb".into(),
            },
            MarmotKitError::AlreadyAdmin {
                group_id_hex: "aa".into(),
                member_id_hex: "bb".into(),
            },
            MarmotKitError::NotAdmin {
                group_id_hex: "aa".into(),
                member_id_hex: "bb".into(),
            },
            MarmotKitError::StorageBusy {
                details: "d".into(),
            },
            MarmotKitError::SecretNotFound {
                details: "d".into(),
            },
            MarmotKitError::KeystoreUnavailable {
                details: "d".into(),
            },
            MarmotKitError::EmptyPassphrase,
            MarmotKitError::EncryptionFailed {
                details: "d".into(),
            },
            MarmotKitError::Io {
                details: "d".into(),
            },
            MarmotKitError::Runtime {
                details: "d".into(),
            },
            MarmotKitError::ExternalSignerUnavailable {
                account: "a".into(),
            },
            MarmotKitError::ExternalSignerMismatch,
            MarmotKitError::ExternalSignerRejected,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for err in &variants {
            let status = status_from_error(err);
            assert_ne!(status, MarmotStatus::Ok);
            assert!(
                seen.insert(status as i32),
                "duplicate status code for {err:?}"
            );
        }
        // Detail string was recorded for the last variant.
        assert!(take_last_error().is_some());
        assert!(take_last_error().is_none());
    }
}
