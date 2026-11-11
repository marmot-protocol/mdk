//! Crate-level error and result type aliases for account orchestration.

use cgka_traits::TransportAdapterError;
use cgka_traits::error::EngineError;

use crate::key_package::KeyPackagePublishError;
use crate::routing::TransportRoutingError;
use crate::session::SessionError;

pub type AccountResult<T> = Result<T, AccountError>;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
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
    #[error("key package replacement is blocked by local clock skew")]
    ClockSkewBlocked,
    #[error("key package rotation is already in progress")]
    KeyPackageRotationInProgress,
    /// This device's roster entry in its device group does not name the
    /// KeyPackage yet, so it may not reach the slot (mdk#2628 3.4).
    #[error("key package is not announced in the device group yet")]
    KeyPackageAnnouncementPending,
    /// A roster label/settings edit needs a fresh rename id; a non-user edit
    /// must preserve the existing id. Rejected before staging or publication.
    #[error("device roster edit violates the user-edit marker contract")]
    InvalidDeviceRosterEdit,
    #[error("transport delivery was addressed to a different account")]
    WrongAccountDelivery,
}

impl AccountError {
    /// The privacy-safe kind a KeyPackage maintenance failure is logged as:
    /// `event_too_large` when every relay refused the KeyPackage for size
    /// (mdk#2334), and `otherwise` for anything else.
    pub(crate) fn key_package_failure_kind(&self, otherwise: &'static str) -> &'static str {
        match self {
            Self::KeyPackage(error) if error.event_size_class.is_some() => "event_too_large",
            _ => otherwise,
        }
    }

    /// The engine error inside this one, whether the runtime met it directly
    /// or through the session.
    #[must_use]
    pub fn as_engine_error(&self) -> Option<&EngineError> {
        match self {
            Self::Engine(error) => Some(error),
            Self::Session(error) => Some(error.as_engine_error()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// KeyPackage maintenance logs a KeyPackage every relay refused for size
    /// as `event_too_large`, and any other failure under its own kind
    /// (mdk#2334).
    #[test]
    fn key_package_maintenance_logs_a_size_refusal_as_too_large() {
        let refused = KeyPackagePublishError::exposed("refused")
            .with_event_size_class(Some(cgka_traits::EventSizeClass::Under64Kib));
        let failed = KeyPackagePublishError::exposed("failed");
        assert_eq!(
            AccountError::from(refused).key_package_failure_kind("key_package_retry"),
            "event_too_large"
        );
        assert_eq!(
            AccountError::from(failed).key_package_failure_kind("key_package_retry"),
            "key_package_retry"
        );
    }
}
