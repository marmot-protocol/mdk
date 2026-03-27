//! Error types for the messages module

use thiserror::Error;

/// Error types for the messages module
#[derive(Debug, Error)]
pub enum MessageError {
    /// Invalid parameters
    #[error("Invalid parameters: {0}")]
    InvalidParameters(String),
    /// Database error
    #[error("Database error: {0}")]
    DatabaseError(String),
    /// Message not found or not in expected state
    #[error("Message not found or not in expected state")]
    NotFound,
}
