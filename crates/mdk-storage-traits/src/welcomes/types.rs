//! Types for the welcomes module

use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

use nostr::{EventId, PublicKey, RelayUrl, Timestamp, UnsignedEvent};
use serde::{Deserialize, Serialize};

use super::error::WelcomeError;
use crate::{GroupId, Secret};

/// A processed welcome, this stores data about whether we have processed a welcome or not
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ProcessedWelcome {
    /// The event id of the processed welcome
    pub wrapper_event_id: EventId,
    /// The event id of the rumor event (kind 444 welcome message)
    pub welcome_event_id: Option<EventId>,
    /// The timestamp of when the welcome was processed
    pub processed_at: Timestamp,
    /// The state of the welcome
    pub state: ProcessedWelcomeState,
    /// The reason the welcome failed to be processed
    pub failure_reason: Option<String>,
}

impl fmt::Debug for ProcessedWelcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProcessedWelcome").finish_non_exhaustive()
    }
}

/// A welcome message
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Welcome {
    /// The event id of the kind 444 welcome
    pub id: EventId,
    /// The event that contains the welcome message
    pub event: UnsignedEvent,
    /// MLS group id
    pub mls_group_id: GroupId,
    /// Nostr group id (from NostrGroupDataExtension)
    pub nostr_group_id: [u8; 32],
    /// Group name (from NostrGroupDataExtension)
    pub group_name: String,
    /// Group description (from NostrGroupDataExtension)
    pub group_description: String,
    /// Group image hash (from NostrGroupDataExtension)
    pub group_image_hash: Option<[u8; 32]>,
    /// Group image key (from NostrGroupDataExtension)
    pub group_image_key: Option<Secret<[u8; 32]>>,
    /// Group image nonce (from NostrGroupDataExtension)
    pub group_image_nonce: Option<Secret<[u8; 12]>>,
    /// Group admin pubkeys (from NostrGroupDataExtension)
    pub group_admin_pubkeys: BTreeSet<PublicKey>,
    /// Group relays (from NostrGroupDataExtension)
    pub group_relays: BTreeSet<RelayUrl>,
    /// Pubkey of the user that sent the welcome
    pub welcomer: PublicKey,
    /// Member count of the group
    pub member_count: u32,
    /// The state of the welcome
    pub state: WelcomeState,
    /// The event id of the 1059 event that contained the welcome
    pub wrapper_event_id: EventId,
}

impl fmt::Debug for Welcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Welcome").finish_non_exhaustive()
    }
}

string_enum! {
    /// The processing state of a welcome
    pub enum ProcessedWelcomeState => WelcomeError, "Invalid processed welcome state: {}" {
        /// The welcome was successfully processed and stored in the database
        Processed => "processed",
        /// The welcome failed to be processed and stored in the database
        Failed => "failed",
    }
}

string_enum! {
    /// The state of a welcome
    pub enum WelcomeState => WelcomeError, "Invalid welcome state: {}" {
        /// The welcome is pending
        Pending => "pending",
        /// The welcome was accepted
        Accepted => "accepted",
        /// The welcome was declined
        Declined => "declined",
        /// The welcome was ignored
        Ignored => "ignored",
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn test_processed_welcome_serialization() {
        // Create a processed welcome to test serialization
        let processed_welcome = ProcessedWelcome {
            wrapper_event_id: EventId::all_zeros(), // Using all_zeros for testing
            welcome_event_id: None,
            processed_at: Timestamp::now(),
            state: ProcessedWelcomeState::Processed,
            failure_reason: None,
        };

        let serialized = serde_json::to_value(&processed_welcome).unwrap();
        assert_eq!(serialized["state"], json!("processed"));
        assert_eq!(serialized["failure_reason"], json!(null));
    }

    #[test]
    fn test_welcome_serialization_with_secret_is_rejected() {
        let pubkey =
            PublicKey::from_hex("8a9de562cbbed225b6ea0118dd3997a02df92c0bffd2224f71081a7450c3e549")
                .unwrap();
        let now = Timestamp::now();
        let welcome = Welcome {
            id: EventId::all_zeros(),
            event: UnsignedEvent::new(
                pubkey,
                now,
                nostr::Kind::MlsWelcome,
                nostr::Tags::new(),
                "private welcome event body".to_string(),
            ),
            mls_group_id: GroupId::from_slice(&[1, 2, 3]),
            nostr_group_id: [0u8; 32],
            group_name: "Private Group".to_string(),
            group_description: "Private Description".to_string(),
            group_image_hash: Some([8u8; 32]),
            group_image_key: Some(Secret::new([7u8; 32])),
            group_image_nonce: Some(Secret::new([6u8; 12])),
            group_admin_pubkeys: BTreeSet::new(),
            group_relays: BTreeSet::new(),
            welcomer: pubkey,
            member_count: 3,
            state: WelcomeState::Pending,
            wrapper_event_id: EventId::all_zeros(),
        };

        let err = serde_json::to_value(&welcome)
            .expect_err("Welcome serialization should fail when secrets are present");
        let err = err.to_string();

        assert!(err.contains("Secret values cannot be serialized"));
        assert!(!err.contains("[7"));
        assert!(!err.contains("[6"));
    }

    #[test]
    fn test_welcome_deserialization_with_secret_fields_is_accepted() {
        let pubkey =
            PublicKey::from_hex("8a9de562cbbed225b6ea0118dd3997a02df92c0bffd2224f71081a7450c3e549")
                .unwrap();
        let now = Timestamp::from_secs(1_677_721_600);
        let event = UnsignedEvent::new(
            pubkey,
            now,
            nostr::Kind::MlsWelcome,
            nostr::Tags::new(),
            "private welcome event body".to_string(),
        );
        let mls_group_id = GroupId::from_slice(&[1, 2, 3]);
        let nostr_group_id = [0u8; 32];
        let image_hash = [8u8; 32];
        let image_key = [7u8; 32];
        let image_nonce = [6u8; 12];
        let mut group_admin_pubkeys = BTreeSet::new();
        group_admin_pubkeys.insert(pubkey);
        let mut group_relays = BTreeSet::new();
        group_relays.insert(RelayUrl::from_str("wss://relay.example.com").unwrap());

        let serialized = json!({
            "id": EventId::all_zeros(),
            "event": event,
            "mls_group_id": mls_group_id,
            "nostr_group_id": nostr_group_id,
            "group_name": "Private Group",
            "group_description": "Private Description",
            "group_image_hash": image_hash,
            "group_image_key": image_key,
            "group_image_nonce": image_nonce,
            "group_admin_pubkeys": group_admin_pubkeys,
            "group_relays": group_relays,
            "welcomer": pubkey,
            "member_count": 3,
            "state": "pending",
            "wrapper_event_id": EventId::all_zeros(),
        });

        let welcome: Welcome = serde_json::from_value(serialized).unwrap();

        assert_eq!(
            welcome
                .group_image_key
                .as_ref()
                .map(|secret| secret.as_ref()),
            Some(&image_key)
        );
        assert_eq!(
            welcome
                .group_image_nonce
                .as_ref()
                .map(|secret| secret.as_ref()),
            Some(&image_nonce)
        );
    }

    #[test]
    fn test_processed_welcome_debug_redacts_sensitive_values() {
        let processed_welcome = ProcessedWelcome {
            wrapper_event_id: EventId::all_zeros(),
            welcome_event_id: Some(EventId::all_zeros()),
            processed_at: Timestamp::now(),
            state: ProcessedWelcomeState::Failed,
            failure_reason: Some("failure with private context".to_string()),
        };

        let debug_str = format!("{:?}", processed_welcome);

        assert!(!debug_str.contains("failure with private context"));
    }

    #[test]
    fn test_welcome_debug_redacts_sensitive_values() {
        let pubkey =
            PublicKey::from_hex("8a9de562cbbed225b6ea0118dd3997a02df92c0bffd2224f71081a7450c3e549")
                .unwrap();
        let now = Timestamp::now();
        let mut group_relays = BTreeSet::new();
        group_relays.insert(RelayUrl::from_str("wss://relay.example.com").unwrap());
        let welcome = Welcome {
            id: EventId::all_zeros(),
            event: UnsignedEvent::new(
                pubkey,
                now,
                nostr::Kind::MlsWelcome,
                nostr::Tags::new(),
                "private welcome event body".to_string(),
            ),
            mls_group_id: GroupId::from_slice(&[222, 173, 190, 239]),
            nostr_group_id: [9u8; 32],
            group_name: "Private Group".to_string(),
            group_description: "Private Description".to_string(),
            group_image_hash: Some([8u8; 32]),
            group_image_key: Some(Secret::new([7u8; 32])),
            group_image_nonce: Some(Secret::new([6u8; 12])),
            group_admin_pubkeys: BTreeSet::new(),
            group_relays,
            welcomer: pubkey,
            member_count: 3,
            state: WelcomeState::Pending,
            wrapper_event_id: EventId::all_zeros(),
        };

        let debug_str = format!("{:?}", welcome);

        assert!(!debug_str.contains("mls_group_id"));
        assert!(!debug_str.contains("nostr_group_id"));
        assert!(!debug_str.contains("GroupId"));
        assert!(!debug_str.contains("deadbeef"));
        assert!(!debug_str.contains("[9, 9"));
        assert!(!debug_str.contains("Private Group"));
        assert!(!debug_str.contains("Private Description"));
        assert!(!debug_str.contains("private welcome event body"));
        assert!(!debug_str.contains("[8, 8"));
        assert!(!debug_str.contains("[7, 7"));
        assert!(!debug_str.contains("[6, 6"));
    }
}
