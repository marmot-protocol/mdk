//! Types for the welcomes module

use std::collections::BTreeSet;
use std::str::FromStr;

use crate::{GroupId, Secret};
use nostr::{EventId, PublicKey, RelayUrl, Timestamp, UnsignedEvent};
use serde::{Deserialize, Serialize};

use super::error::WelcomeError;

/// A processed welcome, this stores data about whether we have processed a welcome or not
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
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

/// A welcome message
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
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
}
