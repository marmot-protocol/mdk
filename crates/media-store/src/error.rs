use std::io;

use crate::catalog::CatalogError;
use crate::format::MediaFormatError;

/// Store errors. Messages are fixed and aggregate: never ids, paths or keys.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MediaError {
    /// The store or its catalog closed; terminal.
    #[error("media store is closed")]
    Closed,
    /// The disk (or the catalog's database) is full.
    #[error("media store is full")]
    Capacity,
    /// The supplied body failed its declared length or digest. Retrying the
    /// same input cannot succeed.
    #[error("invalid media body: {0}")]
    InvalidBody(&'static str),
    /// A stored file failed verification.
    #[error("media file corrupted: {0}")]
    Corruption(&'static str),
    #[error("media publish cancelled")]
    Cancelled,
    #[error("media file I/O failed")]
    Io(io::ErrorKind),
    #[error("media randomness unavailable")]
    Random,
    #[error("media file cipher failed")]
    Cipher,
    #[error("media catalog failed: {0}")]
    Catalog(String),
}

pub type MediaResult<T> = Result<T, MediaError>;

pub(crate) fn io_error(error: &io::Error) -> MediaError {
    match error.kind() {
        io::ErrorKind::StorageFull => MediaError::Capacity,
        kind => MediaError::Io(kind),
    }
}

impl From<CatalogError> for MediaError {
    fn from(error: CatalogError) -> Self {
        match error {
            CatalogError::Closed => Self::Closed,
            CatalogError::Capacity => Self::Capacity,
            CatalogError::Backend(message) => Self::Catalog(message),
        }
    }
}

impl From<MediaFormatError> for MediaError {
    fn from(error: MediaFormatError) -> Self {
        match error {
            MediaFormatError::Io(error) => io_error(&error),
            MediaFormatError::Backend => Self::Cipher,
            MediaFormatError::Poisoned => Self::Io(io::ErrorKind::Other),
            _ => Self::Corruption("media file failed verification"),
        }
    }
}
