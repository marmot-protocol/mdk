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

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::str::FromStr;

    use nostr::{PublicKey, RelayUrl};

    use super::*;
    use crate::GroupId;
    use crate::groups::types::{GroupState, SelfUpdateState};

    fn make_group(name: &str, description: &str, admin_pubkeys: BTreeSet<PublicKey>) -> Group {
        Group {
            mls_group_id: GroupId::from_slice(&[1, 2, 3, 4]),
            nostr_group_id: [0u8; 32],
            name: name.to_string(),
            description: description.to_string(),
            image_hash: None,
            image_key: None,
            image_nonce: None,
            admin_pubkeys,
            last_message_id: None,
            last_message_at: None,
            last_message_processed_at: None,
            epoch: 0,
            state: GroupState::Active,
            self_update_state: SelfUpdateState::Required,
        }
    }

    fn public_key() -> PublicKey {
        PublicKey::from_hex("8a9de562cbbed225b6ea0118dd3997a02df92c0bffd2224f71081a7450c3e549")
            .unwrap()
    }

    fn relay(url: &str) -> RelayUrl {
        RelayUrl::from_str(url).unwrap()
    }

    #[test]
    fn validate_group_fields_accepts_values_within_limits() {
        let group = make_group("hello", "world", BTreeSet::new());

        assert!(validate_group_fields(&group, 5, 5, 0).is_ok());
    }

    #[test]
    fn validate_group_fields_rejects_name_description_and_admin_overflow() {
        let group = make_group("too long", "ok", BTreeSet::new());
        assert!(matches!(
            validate_group_fields(&group, 3, 10, 0),
            Err(GroupError::InvalidParameters(message))
                if message.contains("Group name exceeds maximum length")
        ));

        let group = make_group("ok", "too long", BTreeSet::new());
        assert!(matches!(
            validate_group_fields(&group, 10, 3, 0),
            Err(GroupError::InvalidParameters(message))
                if message.contains("Group description exceeds maximum length")
        ));

        let mut admin_pubkeys = BTreeSet::new();
        admin_pubkeys.insert(public_key());
        let group = make_group("ok", "ok", admin_pubkeys);
        assert!(matches!(
            validate_group_fields(&group, 10, 10, 0),
            Err(GroupError::InvalidParameters(message))
                if message.contains("Group admin count exceeds maximum")
        ));
    }

    #[test]
    fn validate_relay_set_accepts_values_within_limits() {
        let mut relays = BTreeSet::new();
        relays.insert(relay("wss://relay.example.com"));

        assert!(validate_relay_set(&relays, 1, 24).is_ok());
    }

    #[test]
    fn validate_relay_set_rejects_count_and_url_length_overflow() {
        let mut relays = BTreeSet::new();
        relays.insert(relay("wss://a.example.com"));
        relays.insert(relay("wss://b.example.com"));
        assert!(matches!(
            validate_relay_set(&relays, 1, 64),
            Err(GroupError::InvalidParameters(message))
                if message.contains("Relay count exceeds maximum")
        ));

        let mut relays = BTreeSet::new();
        relays.insert(relay("wss://relay.example.com"));
        assert!(matches!(
            validate_relay_set(&relays, 1, 5),
            Err(GroupError::InvalidParameters(message))
                if message.contains("Relay URL exceeds maximum length")
        ));
    }
}
