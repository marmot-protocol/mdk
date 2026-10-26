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
    #[error("transport delivery was addressed to a different account")]
    WrongAccountDelivery,
}

impl AccountError {
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
