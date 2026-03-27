//! Error types for the welcomes module

use thiserror::Error;

/// Error types for the welcomes module
#[derive(Debug, Error)]
pub enum WelcomeError {
    /// Invalid parameters
    #[error("Invalid parameters: {0}")]
    InvalidParameters(String),
    /// Database error
    #[error("Database error: {0}")]
    DatabaseError(String),
}
