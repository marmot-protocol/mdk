//! Shared validation logic for group storage operations.
//!
//! These functions are backend-agnostic and can be called by any storage
//! implementation to enforce domain constraints before persisting data.

use std::collections::BTreeSet;

use nostr::RelayUrl;

use super::error::GroupError;
use super::types::Group;

/// Validates a group's domain fields before saving.
///
/// Checks name length, description length, and admin count against the
/// provided limits. Both storage backends should call this before persisting.
pub fn validate_group_fields(
    group: &Group,
    max_name_length: usize,
    max_description_length: usize,
    max_admins: usize,
) -> Result<(), GroupError> {
    if group.name.len() > max_name_length {
        return Err(GroupError::InvalidParameters(format!(
            "Group name exceeds maximum length of {} bytes (got {} bytes)",
            max_name_length,
            group.name.len()
        )));
    }

    if group.description.len() > max_description_length {
        return Err(GroupError::InvalidParameters(format!(
            "Group description exceeds maximum length of {} bytes (got {} bytes)",
            max_description_length,
            group.description.len()
        )));
    }

    if group.admin_pubkeys.len() > max_admins {
        return Err(GroupError::InvalidParameters(format!(
            "Group admin count exceeds maximum of {} (got {})",
            max_admins,
            group.admin_pubkeys.len()
        )));
    }

    Ok(())
}

/// Validates relay URLs before replacing a group's relay set.
///
/// Checks relay count and individual URL lengths against the provided limits.
pub fn validate_relay_set(
    relays: &BTreeSet<RelayUrl>,
    max_relays: usize,
    max_url_length: usize,
) -> Result<(), GroupError> {
    if relays.len() > max_relays {
        return Err(GroupError::InvalidParameters(format!(
            "Relay count exceeds maximum of {} (got {})",
            max_relays,
            relays.len()
        )));
    }

    for relay in relays {
        if relay.as_str().len() > max_url_length {
            return Err(GroupError::InvalidParameters(format!(
                "Relay URL exceeds maximum length of {} bytes",
                max_url_length
            )));
        }
    }

    Ok(())
}
