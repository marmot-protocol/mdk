//! Error types for the groups module

use std::fmt;
use thiserror::Error;

/// Invalid group state
#[derive(Debug, PartialEq, Eq)]
pub enum InvalidGroupState {
    /// Group has no admins
    NoAdmins,
    /// Group has no relays
    NoRelays,
}

impl fmt::Display for InvalidGroupState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoAdmins => write!(f, "group has no admins"),
            Self::NoRelays => write!(f, "group has no relays"),
        }
    }
}

/// Error types for the groups module
#[derive(Debug, Error)]
pub enum GroupError {
    /// Invalid parameters
    #[error("Invalid parameters: {0}")]
    InvalidParameters(String),
    /// Database error
    #[error("Database error: {0}")]
    DatabaseError(String),
    /// Invalid state
    #[error("Invalid state: {0}")]
    InvalidState(InvalidGroupState),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_group_state_equality() {
        assert_eq!(InvalidGroupState::NoAdmins, InvalidGroupState::NoAdmins);
        assert_eq!(InvalidGroupState::NoRelays, InvalidGroupState::NoRelays);
        assert_ne!(InvalidGroupState::NoAdmins, InvalidGroupState::NoRelays);
    }
}
