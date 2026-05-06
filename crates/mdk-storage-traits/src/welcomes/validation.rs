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
