//! Error types for the groups module

use std::fmt;

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

storage_error! {
    /// Error types for the groups module
    pub enum GroupError {
        /// Invalid state
        #[error("Invalid state: {0}")]
        InvalidState(InvalidGroupState),
    }
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
