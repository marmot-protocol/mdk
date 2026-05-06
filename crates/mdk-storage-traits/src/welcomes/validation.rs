//! Shared validation logic for welcome storage operations.
//!
//! These functions are backend-agnostic and can be called by any storage
//! implementation to enforce domain constraints before persisting data.

use std::collections::BTreeSet;

use nostr::RelayUrl;

use super::error::WelcomeError;

/// Validates a welcome's relay and admin fields before saving.
///
/// Checks relay count, individual URL lengths, and admin count against the
/// provided limits. Both storage backends should call this before persisting.
pub fn validate_welcome_fields(
    group_relays: &BTreeSet<RelayUrl>,
    group_admin_count: usize,
    max_relays: usize,
    max_url_length: usize,
    max_admins: usize,
) -> Result<(), WelcomeError> {
    if group_relays.len() > max_relays {
        return Err(WelcomeError::InvalidParameters(format!(
            "Welcome relay count exceeds maximum of {} (got {})",
            max_relays,
            group_relays.len()
        )));
    }

    for relay in group_relays {
        if relay.as_str().len() > max_url_length {
            return Err(WelcomeError::InvalidParameters(format!(
                "Relay URL exceeds maximum length of {} bytes",
                max_url_length
            )));
        }
    }

    if group_admin_count > max_admins {
        return Err(WelcomeError::InvalidParameters(format!(
            "Welcome admin count exceeds maximum of {} (got {})",
            max_admins, group_admin_count
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::str::FromStr;

    use nostr::RelayUrl;

    use super::*;

    fn relay(url: &str) -> RelayUrl {
        RelayUrl::from_str(url).unwrap()
    }

    #[test]
    fn validate_welcome_fields_accepts_values_within_limits() {
        let mut relays = BTreeSet::new();
        relays.insert(relay("wss://relay.example.com"));

        assert!(validate_welcome_fields(&relays, 1, 1, 24, 1).is_ok());
    }

    #[test]
    fn validate_welcome_fields_rejects_relay_count_url_length_and_admin_overflow() {
        let mut relays = BTreeSet::new();
        relays.insert(relay("wss://a.example.com"));
        relays.insert(relay("wss://b.example.com"));
        assert!(matches!(
            validate_welcome_fields(&relays, 0, 1, 64, 0),
            Err(WelcomeError::InvalidParameters(message))
                if message.contains("Welcome relay count exceeds maximum")
        ));

        let mut relays = BTreeSet::new();
        relays.insert(relay("wss://relay.example.com"));
        assert!(matches!(
            validate_welcome_fields(&relays, 0, 1, 5, 0),
            Err(WelcomeError::InvalidParameters(message))
                if message.contains("Relay URL exceeds maximum length")
        ));

        assert!(matches!(
            validate_welcome_fields(&BTreeSet::new(), 1, 0, 64, 0),
            Err(WelcomeError::InvalidParameters(message))
                if message.contains("Welcome admin count exceeds maximum")
        ));
    }
}
