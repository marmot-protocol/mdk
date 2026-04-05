//! UniFFI bindings for mdk-core with SQLite storage
//!
//! This crate provides foreign language bindings for mdk-core using UniFFI.
//! It wraps the MDK core functionality with SQLite storage backend.

#![warn(missing_docs)]

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Mutex;

use mdk_core::encrypted_media::{EncryptedMediaUpload, MediaProcessingOptions, MediaReference};
use mdk_core::{
    Error as MdkError, MDK, MdkConfig as CoreMdkConfig,
    extension::group_image::{
        decrypt_group_image as core_decrypt_group_image,
        derive_upload_keypair as core_derive_upload_keypair,
        prepare_group_image_for_upload as core_prepare_group_image_for_upload,
        prepare_group_image_for_upload_with_options as core_prepare_group_image_for_upload_with_options,
    },
    groups::{NostrGroupConfigData, NostrGroupDataUpdate},
    messages::{EventTag, MessageProcessingResult},
};
use mdk_sqlite_storage::{EncryptionConfig, MdkSqliteStorage};
use mdk_storage_traits::{
    GroupId,
    groups::{MessageSortOrder, Pagination as MessagePagination, types as group_types},
    messages::types as message_types,
    welcomes::{Pagination as WelcomePagination, types as welcome_types},
};
use nostr::{Event, EventBuilder, EventId, Kind, PublicKey, RelayUrl, Tag, TagKind, UnsignedEvent};

uniffi::setup_scaffolding!();

/// Main MDK instance with SQLite storage
#[derive(uniffi::Object)]
pub struct Mdk {
    mdk: Mutex<MDK<MdkSqliteStorage>>,
}

/// Configuration for MDK behavior
///
/// This struct allows customization of various MDK parameters including
/// message validation and MLS sender ratchet settings. All fields are optional
/// and default to sensible values when not provided.
#[derive(uniffi::Record)]
pub struct MdkConfig {
    /// Maximum age for accepted events in seconds.
    /// Default: 3888000 (45 days)
    pub max_event_age_secs: Option<u64>,

    /// Maximum future timestamp skew allowed in seconds.
    /// Default: 300 (5 minutes)
    pub max_future_skew_secs: Option<u64>,

    /// Number of past message decryption secrets to retain for out-of-order delivery.
    /// Higher values improve tolerance for reordered messages but reduce forward secrecy.
    /// Default: 100
    pub out_of_order_tolerance: Option<u32>,

    /// Maximum number of messages that can be skipped before decryption fails.
    /// Default: 1000
    pub maximum_forward_distance: Option<u32>,

    /// Number of past MLS epochs for which application messages can be decrypted.
    /// When a commit advances the group to epoch N+1, messages from epoch N that arrive
    /// late can still be decrypted if the epoch delta is within this window.
    /// Default: 5
    pub max_past_epochs: Option<u32>,

    /// Number of epoch snapshots to retain for rollback support.
    /// Default: 5
    pub epoch_snapshot_retention: Option<u32>,

    /// Time-to-live for snapshots in seconds.
    /// Snapshots older than this will be pruned on startup.
    /// Default: 604800 (1 week)
    pub snapshot_ttl_seconds: Option<u64>,
}

impl From<MdkConfig> for CoreMdkConfig {
    fn from(config: MdkConfig) -> Self {
        let d = CoreMdkConfig::default();
        Self {
            max_event_age_secs: config.max_event_age_secs.unwrap_or(d.max_event_age_secs),
            max_future_skew_secs: config
                .max_future_skew_secs
                .unwrap_or(d.max_future_skew_secs),
            out_of_order_tolerance: config
                .out_of_order_tolerance
                .unwrap_or(d.out_of_order_tolerance),
            maximum_forward_distance: config
                .maximum_forward_distance
                .unwrap_or(d.maximum_forward_distance),
            max_past_epochs: config
                .max_past_epochs
                .map(|v| v as usize)
                .unwrap_or(d.max_past_epochs),
            epoch_snapshot_retention: config
                .epoch_snapshot_retention
                .map(|v| v as usize)
                .unwrap_or(d.epoch_snapshot_retention),
            snapshot_ttl_seconds: config
                .snapshot_ttl_seconds
                .unwrap_or(d.snapshot_ttl_seconds),
        }
    }
}

/// Error type for MDK UniFFI operations
#[derive(uniffi::Enum, Debug, thiserror::Error)]
pub enum MdkUniffiError {
    /// Storage-related error
    #[error("Storage error: {0}")]
    Storage(String),
    /// MDK core error
    #[error("MDK error: {0}")]
    Mdk(String),
    /// Invalid input parameter error
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

impl From<mdk_sqlite_storage::error::Error> for MdkUniffiError {
    fn from(err: mdk_sqlite_storage::error::Error) -> Self {
        Self::Storage(err.to_string())
    }
}

impl From<MdkError> for MdkUniffiError {
    fn from(err: MdkError) -> Self {
        Self::Mdk(err.to_string())
    }
}

// Helper functions

/// Generates parsing helper functions that map errors to `MdkUniffiError::InvalidInput`.
macro_rules! parse_with_invalid_input {
    ($(
        $(#[$meta:meta])*
        $fn_name:ident($input:ident) -> $ret:ty = $parse:expr, $msg:literal
    );* $(;)?) => {
        $(
            $(#[$meta])*
            fn $fn_name($input: &str) -> Result<$ret, MdkUniffiError> {
                $parse.map_err(|e| MdkUniffiError::InvalidInput(format!(concat!($msg, ": {}"), e)))
            }
        )*
    };
}

parse_with_invalid_input! {
    parse_group_id(hex) -> GroupId =
        hex::decode(hex).map(|bytes| GroupId::from_slice(&bytes)),
        "Invalid group ID hex";
    parse_event_id(hex) -> EventId =
        EventId::from_hex(hex),
        "Invalid event ID";
    parse_public_key(hex) -> PublicKey =
        PublicKey::from_hex(hex),
        "Invalid public key";
}

fn parse_relay_urls(relays: &[String]) -> Result<Vec<RelayUrl>, MdkUniffiError> {
    relays
        .iter()
        .map(|r| RelayUrl::parse(r))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| MdkUniffiError::InvalidInput(format!("Invalid relay URL: {e}")))
}

fn parse_json<T>(json: &str, context: &str) -> Result<T, MdkUniffiError>
where
    T: serde::de::DeserializeOwned,
{
    serde_json::from_str(json)
        .map_err(|e| MdkUniffiError::InvalidInput(format!("Invalid {context}: {e}")))
}

fn vec_to_array<const N: usize>(vec: Option<Vec<u8>>) -> Result<Option<[u8; N]>, MdkUniffiError> {
    match vec {
        Some(bytes) if bytes.len() == N => {
            let mut arr = [0u8; N];
            arr.copy_from_slice(&bytes);
            Ok(Some(arr))
        }
        Some(bytes) => Err(MdkUniffiError::InvalidInput(format!(
            "Expected {} bytes, got {} bytes",
            N,
            bytes.len()
        ))),
        None => Ok(None),
    }
}

fn parse_message_sort_order(
    sort_order: Option<&str>,
) -> Result<Option<MessageSortOrder>, MdkUniffiError> {
    match sort_order {
        None => Ok(None),
        Some("created_at_first") => Ok(Some(MessageSortOrder::CreatedAtFirst)),
        Some("processed_at_first") => Ok(Some(MessageSortOrder::ProcessedAtFirst)),
        Some(other) => Err(MdkUniffiError::InvalidInput(format!(
            "Invalid sort order: {other}. Expected \"created_at_first\" or \"processed_at_first\""
        ))),
    }
}

fn parse_tags(tags: Vec<Vec<String>>) -> Result<Vec<Tag>, MdkUniffiError> {
    tags.into_iter()
        .map(|tag_vec| {
            Tag::parse(tag_vec)
                .map_err(|e| MdkUniffiError::InvalidInput(format!("Failed to parse tag: {e}")))
        })
        .collect()
}

fn parse_event_tags(tags: Vec<Vec<String>>) -> Result<Vec<EventTag>, MdkUniffiError> {
    tags.into_iter()
        .map(|tag_vec| {
            let kind = tag_vec
                .first()
                .ok_or_else(|| MdkUniffiError::InvalidInput("Empty tag".to_string()))?
                .as_str();

            match kind {
                "expiration" => {
                    let value = tag_vec.get(1).ok_or_else(|| {
                        MdkUniffiError::InvalidInput(
                            "expiration tag requires a timestamp value".to_string(),
                        )
                    })?;
                    let timestamp: u64 = value.parse().map_err(|_| {
                        MdkUniffiError::InvalidInput(format!(
                            "Invalid expiration timestamp: {value}"
                        ))
                    })?;
                    Ok(EventTag::expiration(nostr::Timestamp::from(timestamp)))
                }
                other => Err(MdkUniffiError::InvalidInput(format!(
                    "Tag '{other}' is not allowed on wrapper events. Allowed: expiration"
                ))),
            }
        })
        .collect()
}

fn welcome_from_uniffi(w: Welcome) -> Result<welcome_types::Welcome, MdkUniffiError> {
    let id = parse_event_id(&w.id)?;
    let event: UnsignedEvent = parse_json(&w.event_json, "welcome event JSON")?;
    let mls_group_id = parse_group_id(&w.mls_group_id)?;

    let nostr_group_id_vec = hex::decode(&w.nostr_group_id)
        .map_err(|e| MdkUniffiError::InvalidInput(format!("Invalid nostr group ID hex: {e}")))?;
    let nostr_group_id: [u8; 32] = nostr_group_id_vec
        .try_into()
        .map_err(|_| MdkUniffiError::InvalidInput("Nostr group ID must be 32 bytes".to_string()))?;

    let group_image_hash = vec_to_array::<32>(w.group_image_hash)?;
    let group_image_key =
        vec_to_array::<32>(w.group_image_key)?.map(mdk_storage_traits::Secret::new);
    let group_image_nonce =
        vec_to_array::<12>(w.group_image_nonce)?.map(mdk_storage_traits::Secret::new);

    let group_admin_pubkeys: Result<BTreeSet<PublicKey>, _> = w
        .group_admin_pubkeys
        .into_iter()
        .map(|pk| parse_public_key(&pk))
        .collect();
    let group_admin_pubkeys = group_admin_pubkeys?;

    let group_relays = parse_relay_urls(&w.group_relays)?.into_iter().collect();

    let welcomer = parse_public_key(&w.welcomer)?;
    let wrapper_event_id = parse_event_id(&w.wrapper_event_id)?;

    let state = welcome_types::WelcomeState::from_str(&w.state)
        .map_err(|e| MdkUniffiError::InvalidInput(format!("Invalid welcome state: {e}")))?;

    Ok(welcome_types::Welcome {
        id,
        event,
        mls_group_id,
        nostr_group_id,
        group_name: w.group_name,
        group_description: w.group_description,
        group_image_hash,
        group_image_key,
        group_image_nonce,
        group_admin_pubkeys,
        group_relays,
        welcomer,
        member_count: w.member_count,
        state,
        wrapper_event_id,
    })
}

/// Convert a core [`mdk_core::groups::UpdateGroupResult`] into the UniFFI-exported
/// [`UpdateGroupResult`], serializing the evolution event and welcome rumors to JSON.
fn message_processing_result_to_uniffi(
    result: MessageProcessingResult,
) -> Result<ProcessMessageResult, MdkUniffiError> {
    Ok(match result {
        MessageProcessingResult::ApplicationMessage(message) => {
            ProcessMessageResult::ApplicationMessage {
                message: Message::from(message),
            }
        }
        MessageProcessingResult::Proposal(update_result) => ProcessMessageResult::Proposal {
            result: update_group_result_to_uniffi(update_result)?,
        },
        MessageProcessingResult::PendingProposal { mls_group_id } => {
            ProcessMessageResult::PendingProposal {
                mls_group_id: hex::encode(mls_group_id.as_slice()),
            }
        }
        MessageProcessingResult::ExternalJoinProposal { mls_group_id } => {
            ProcessMessageResult::ExternalJoinProposal {
                mls_group_id: hex::encode(mls_group_id.as_slice()),
            }
        }
        MessageProcessingResult::Commit { mls_group_id } => ProcessMessageResult::Commit {
            mls_group_id: hex::encode(mls_group_id.as_slice()),
        },
        MessageProcessingResult::Unprocessable { mls_group_id } => {
            ProcessMessageResult::Unprocessable {
                mls_group_id: hex::encode(mls_group_id.as_slice()),
            }
        }
        MessageProcessingResult::IgnoredProposal {
            mls_group_id,
            reason,
        } => ProcessMessageResult::IgnoredProposal {
            mls_group_id: hex::encode(mls_group_id.as_slice()),
            reason,
        },
        MessageProcessingResult::PreviouslyFailed => ProcessMessageResult::PreviouslyFailed,
    })
}

fn update_group_result_to_uniffi(
    result: mdk_core::groups::UpdateGroupResult,
) -> Result<UpdateGroupResult, MdkUniffiError> {
    let evolution_event_json = serde_json::to_string(&result.evolution_event).map_err(|e| {
        MdkUniffiError::InvalidInput(format!("Failed to serialize evolution event: {e}"))
    })?;

    let welcome_rumors_json: Option<Vec<String>> = result
        .welcome_rumors
        .map(|rumors| {
            rumors
                .iter()
                .map(|rumor| {
                    serde_json::to_string(rumor).map_err(|e| {
                        MdkUniffiError::InvalidInput(format!(
                            "Failed to serialize welcome rumor: {e}"
                        ))
                    })
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?;

    Ok(UpdateGroupResult {
        evolution_event_json,
        welcome_rumors_json,
        mls_group_id: hex::encode(result.mls_group_id.as_slice()),
    })
}

impl Mdk {
    /// Lock the internal MDK instance for exclusive access.
    /// Returns an error if the mutex is poisoned.
    /// Using MDK correctly (do NOT share memory across threads) should never result in a poisoned mutex.
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, MDK<MdkSqliteStorage>>, MdkUniffiError> {
        self.mdk.lock().map_err(|_| {
            MdkUniffiError::Mdk(
                "MDK mutex poisoned. This indicates a critical internal error. Using MDK correctly (do NOT share memory across threads) should never result in a poisoned mutex.".to_string(),
            )
        })
    }
}

/// Wrap a storage backend and optional config into a [`Mdk`] instance.
fn mdk_from_storage(storage: MdkSqliteStorage, config: Option<MdkConfig>) -> Mdk {
    let mdk = match config {
        Some(c) => MDK::builder(storage).with_config(c.into()).build(),
        None => MDK::new(storage),
    };
    Mdk {
        mdk: Mutex::new(mdk),
    }
}

/// Create a new MDK instance with encrypted SQLite storage using automatic key management.
///
/// This is the recommended constructor for production use. The database encryption key
/// is automatically retrieved from (or generated and stored in) the platform's native
/// keyring (Keychain on macOS/iOS, Keystore on Android, etc.).
///
/// # Prerequisites
///
/// The host application must initialize a platform-specific keyring store before calling
/// this function:
///
/// - **macOS/iOS**: `keyring_core::set_default_store(AppleStore::new())`
/// - **Android**: Initialize from Kotlin (see Android documentation)
/// - **Windows**: `keyring_core::set_default_store(WindowsStore::new())`
/// - **Linux**: `keyring_core::set_default_store(KeyutilsStore::new())`
///
/// # Arguments
///
/// * `db_path` - Path to the SQLite database file
/// * `service_id` - A stable, host-defined application identifier (e.g., "com.example.myapp")
/// * `db_key_id` - A stable identifier for this database's key (e.g., "mdk.db.key.default")
/// * `config` - Optional MDK configuration. If None, uses default configuration.
///
/// # Errors
///
/// Returns an error if:
/// - No keyring store has been initialized
/// - The keyring is unavailable or inaccessible
/// - The database cannot be opened or created
#[uniffi::export]
pub fn new_mdk(
    db_path: String,
    service_id: String,
    db_key_id: String,
    config: Option<MdkConfig>,
) -> Result<Mdk, MdkUniffiError> {
    let storage = MdkSqliteStorage::new(PathBuf::from(db_path), &service_id, &db_key_id)?;
    Ok(mdk_from_storage(storage, config))
}

/// Create a new MDK instance with encrypted SQLite storage using a directly provided key.
///
/// Use this when you want to manage encryption keys yourself rather than using the
/// platform keyring. For most applications, prefer `new_mdk` which handles key
/// management automatically.
///
/// # Arguments
///
/// * `db_path` - Path to the SQLite database file
/// * `encryption_key` - 32-byte encryption key (must be exactly 32 bytes)
/// * `config` - Optional MDK configuration. If None, uses default configuration.
///
/// # Errors
///
/// Returns an error if the key is not 32 bytes or if the database cannot be opened.
#[uniffi::export]
pub fn new_mdk_with_key(
    db_path: String,
    encryption_key: Vec<u8>,
    config: Option<MdkConfig>,
) -> Result<Mdk, MdkUniffiError> {
    let encryption_config = EncryptionConfig::from_slice(&encryption_key)
        .map_err(|e| MdkUniffiError::InvalidInput(format!("Invalid encryption key: {}", e)))?;
    let storage = MdkSqliteStorage::new_with_key(PathBuf::from(db_path), encryption_config)?;
    Ok(mdk_from_storage(storage, config))
}

/// Create a new MDK instance with unencrypted SQLite storage.
///
/// ⚠️ **WARNING**: This creates an unencrypted database. Sensitive MLS state
/// including exporter secrets will be stored in plaintext.
///
/// Only use this for development or testing. For production use, use `new_mdk`
/// with an encryption key.
///
/// # Arguments
///
/// * `db_path` - Path to the SQLite database file
/// * `config` - Optional MDK configuration. If None, uses default configuration.
#[cfg(any(test, feature = "test-utils"))]
#[uniffi::export]
pub fn new_mdk_unencrypted(
    db_path: String,
    config: Option<MdkConfig>,
) -> Result<Mdk, MdkUniffiError> {
    let storage = MdkSqliteStorage::new_unencrypted(PathBuf::from(db_path))?;
    Ok(mdk_from_storage(storage, config))
}

#[uniffi::export]
impl Mdk {
    /// Create a key package for a Nostr event
    ///
    /// This function does NOT add the NIP-70 protected tag, ensuring maximum relay
    /// compatibility. Many popular relays (Damus, Primal, nos.lol) reject protected events.
    /// If you need the protected tag, use `create_key_package_for_event_with_options` instead.
    pub fn create_key_package_for_event(
        &self,
        public_key: String,
        relays: Vec<String>,
    ) -> Result<KeyPackageResult, MdkUniffiError> {
        let pubkey = parse_public_key(&public_key)?;
        let relay_urls = parse_relay_urls(&relays)?;

        let mdk = self.lock()?;
        let mdk_core::key_packages::KeyPackageEventData {
            content: key_package_hex,
            tags_30443: tags,
            tags_443,
            hash_ref,
            d_tag,
        } = mdk.create_key_package_for_event(&pubkey, relay_urls)?;

        let tags: Vec<Vec<String>> = tags.iter().map(|tag| tag.as_slice().to_vec()).collect();
        let tags_legacy: Vec<Vec<String>> =
            tags_443.iter().map(|tag| tag.as_slice().to_vec()).collect();

        Ok(KeyPackageResult {
            key_package: key_package_hex,
            tags,
            tags_legacy,
            hash_ref,
            d_tag,
        })
    }

    /// Create a key package for a Nostr event with additional options
    ///
    /// # Arguments
    ///
    /// * `public_key` - The Nostr public key (hex) for the credential
    /// * `relays` - Relay URLs where the key package will be published
    /// * `protected` - Whether to add the NIP-70 protected tag. When `true`, relays that
    ///   implement NIP-70 will reject republishing by third parties. However, many popular
    ///   relays reject protected events entirely. Set to `false` for maximum relay
    ///   compatibility.
    pub fn create_key_package_for_event_with_options(
        &self,
        public_key: String,
        relays: Vec<String>,
        protected: bool,
    ) -> Result<KeyPackageResult, MdkUniffiError> {
        let pubkey = parse_public_key(&public_key)?;
        let relay_urls = parse_relay_urls(&relays)?;

        let mdk = self.lock()?;
        let mdk_core::key_packages::KeyPackageEventData {
            content: key_package_hex,
            tags_30443: tags,
            tags_443,
            hash_ref,
            d_tag,
        } = mdk.create_key_package_for_event_with_options(&pubkey, relay_urls, protected)?;

        let tags: Vec<Vec<String>> = tags.iter().map(|tag| tag.as_slice().to_vec()).collect();
        let tags_legacy: Vec<Vec<String>> =
            tags_443.iter().map(|tag| tag.as_slice().to_vec()).collect();

        Ok(KeyPackageResult {
            key_package: key_package_hex,
            tags,
            tags_legacy,
            hash_ref,
            d_tag,
        })
    }

    /// Parse a key package from a Nostr event
    pub fn parse_key_package(&self, event_json: String) -> Result<String, MdkUniffiError> {
        let event: Event = parse_json(&event_json, "event JSON")?;
        self.lock()?.parse_key_package(&event)?;
        Ok(event.content)
    }

    /// Get all groups
    pub fn get_groups(&self) -> Result<Vec<Group>, MdkUniffiError> {
        Ok(self
            .lock()?
            .get_groups()?
            .into_iter()
            .map(Group::from)
            .collect())
    }

    /// Get a group by MLS group ID
    pub fn get_group(&self, mls_group_id: String) -> Result<Option<Group>, MdkUniffiError> {
        let group_id = parse_group_id(&mls_group_id)?;
        Ok(self.lock()?.get_group(&group_id)?.map(Group::from))
    }

    /// Get group IDs that need a self-update (post-join or stale rotation).
    pub fn groups_needing_self_update(
        &self,
        threshold_secs: u64,
    ) -> Result<Vec<String>, MdkUniffiError> {
        Ok(self
            .lock()?
            .groups_needing_self_update(threshold_secs)?
            .into_iter()
            .map(|id| hex::encode(id.as_slice()))
            .collect())
    }

    /// Get members of a group
    pub fn get_members(&self, mls_group_id: String) -> Result<Vec<String>, MdkUniffiError> {
        let group_id = parse_group_id(&mls_group_id)?;
        Ok(self
            .lock()?
            .get_members(&group_id)?
            .into_iter()
            .map(|pk| pk.to_hex())
            .collect())
    }

    /// Get messages for a group with optional pagination
    ///
    /// # Arguments
    ///
    /// * `mls_group_id` - Hex-encoded MLS group ID
    /// * `limit` - Optional maximum number of messages to return (defaults to 1000 if None)
    /// * `offset` - Optional number of messages to skip (defaults to 0 if None)
    /// * `sort_order` - Optional sort order: `"created_at_first"` (default) or `"processed_at_first"`
    ///
    /// # Returns
    ///
    /// Returns a vector of messages in the requested sort order
    pub fn get_messages(
        &self,
        mls_group_id: String,
        limit: Option<u32>,
        offset: Option<u32>,
        sort_order: Option<String>,
    ) -> Result<Vec<Message>, MdkUniffiError> {
        let group_id = parse_group_id(&mls_group_id)?;
        let sort = parse_message_sort_order(sort_order.as_deref())?;
        let pagination = match (limit, offset, sort) {
            (None, None, None) => None,
            _ => {
                let mut p =
                    MessagePagination::new(limit.map(|l| l as usize), offset.map(|o| o as usize));
                p.sort_order = sort;
                Some(p)
            }
        };
        Ok(self
            .lock()?
            .get_messages(&group_id, pagination)?
            .into_iter()
            .map(Message::from)
            .collect())
    }

    /// Get a message by event ID within a specific group
    ///
    /// # Arguments
    ///
    /// * `mls_group_id` - The MLS group ID the message belongs to (hex-encoded)
    /// * `event_id` - The Nostr event ID to look up (hex-encoded)
    ///
    /// # Returns
    ///
    /// Returns the message if found, None otherwise
    pub fn get_message(
        &self,
        mls_group_id: String,
        event_id: String,
    ) -> Result<Option<Message>, MdkUniffiError> {
        let group_id = parse_group_id(&mls_group_id)?;
        let event_id = parse_event_id(&event_id)?;
        Ok(self
            .lock()?
            .get_message(&group_id, &event_id)?
            .map(Message::from))
    }

    /// Get the most recent message in a group according to the given sort order
    ///
    /// This is useful for clients that use `"processed_at_first"` sort order and need
    /// a "last message" value that is consistent with their `get_messages()` ordering.
    /// The cached `group.last_message_id` always reflects `"created_at_first"` ordering.
    ///
    /// # Arguments
    ///
    /// * `mls_group_id` - Hex-encoded MLS group ID
    /// * `sort_order` - Sort order: `"created_at_first"` or `"processed_at_first"`
    ///
    /// # Returns
    ///
    /// Returns the most recent message under the given ordering, or None if the group has no messages
    pub fn get_last_message(
        &self,
        mls_group_id: String,
        sort_order: String,
    ) -> Result<Option<Message>, MdkUniffiError> {
        let group_id = parse_group_id(&mls_group_id)?;
        let sort = parse_message_sort_order(Some(&sort_order))?
            .ok_or_else(|| MdkUniffiError::InvalidInput("sort_order is required".to_string()))?;
        Ok(self
            .lock()?
            .get_last_message(&group_id, sort)?
            .map(Message::from))
    }

    /// Get pending welcomes with optional pagination
    ///
    /// # Arguments
    ///
    /// * `limit` - Optional maximum number of welcomes to return (defaults to 1000 if None)
    /// * `offset` - Optional number of welcomes to skip (defaults to 0 if None)
    ///
    /// # Returns
    ///
    /// Returns a vector of pending welcomes ordered by ID (descending)
    pub fn get_pending_welcomes(
        &self,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Result<Vec<Welcome>, MdkUniffiError> {
        let pagination = match (limit, offset) {
            (None, None) => None,
            _ => Some(WelcomePagination::new(
                limit.map(|l| l as usize),
                offset.map(|o| o as usize),
            )),
        };
        Ok(self
            .lock()?
            .get_pending_welcomes(pagination)?
            .into_iter()
            .map(Welcome::from)
            .collect())
    }

    /// Get a welcome by event ID
    pub fn get_welcome(&self, event_id: String) -> Result<Option<Welcome>, MdkUniffiError> {
        let event_id = parse_event_id(&event_id)?;
        Ok(self.lock()?.get_welcome(&event_id)?.map(Welcome::from))
    }

    /// Process a welcome message
    pub fn process_welcome(
        &self,
        wrapper_event_id: String,
        rumor_event_json: String,
    ) -> Result<Welcome, MdkUniffiError> {
        let wrapper_id = parse_event_id(&wrapper_event_id)?;
        let rumor_event: UnsignedEvent = parse_json(&rumor_event_json, "rumor event JSON")?;
        Ok(Welcome::from(
            self.lock()?.process_welcome(&wrapper_id, &rumor_event)?,
        ))
    }

    /// Accept a welcome message
    pub fn accept_welcome(&self, welcome: Welcome) -> Result<(), MdkUniffiError> {
        let welcome = welcome_from_uniffi(welcome)?;
        self.lock()?.accept_welcome(&welcome)?;
        Ok(())
    }

    /// Accept a welcome message from JSON
    pub fn accept_welcome_json(&self, welcome_json: String) -> Result<(), MdkUniffiError> {
        let welcome: welcome_types::Welcome = parse_json(&welcome_json, "welcome JSON")?;
        self.lock()?.accept_welcome(&welcome)?;
        Ok(())
    }

    /// Decline a welcome message
    pub fn decline_welcome(&self, welcome: Welcome) -> Result<(), MdkUniffiError> {
        let welcome = welcome_from_uniffi(welcome)?;
        self.lock()?.decline_welcome(&welcome)?;
        Ok(())
    }

    /// Decline a welcome message from JSON
    pub fn decline_welcome_json(&self, welcome_json: String) -> Result<(), MdkUniffiError> {
        let welcome: welcome_types::Welcome = parse_json(&welcome_json, "welcome JSON")?;
        self.lock()?.decline_welcome(&welcome)?;
        Ok(())
    }

    /// Get relays for a group
    pub fn get_relays(&self, mls_group_id: String) -> Result<Vec<String>, MdkUniffiError> {
        let group_id = parse_group_id(&mls_group_id)?;
        Ok(self
            .lock()?
            .get_relays(&group_id)?
            .into_iter()
            .map(|r| r.to_string())
            .collect())
    }

    /// Create a new group
    pub fn create_group(
        &self,
        creator_public_key: String,
        member_key_package_events_json: Vec<String>,
        name: String,
        description: String,
        relays: Vec<String>,
        admins: Vec<String>,
    ) -> Result<CreateGroupResult, MdkUniffiError> {
        let creator_pubkey = parse_public_key(&creator_public_key)?;
        let relay_urls = parse_relay_urls(&relays)?;
        let admin_pubkeys: Vec<PublicKey> = admins
            .iter()
            .map(|a| parse_public_key(a))
            .collect::<Result<_, _>>()?;

        let member_key_package_events: Vec<Event> = member_key_package_events_json
            .iter()
            .map(|json| parse_json(json, "key package event JSON"))
            .collect::<Result<_, _>>()?;

        let config = NostrGroupConfigData::new(
            name,
            description,
            None, // image_hash
            None, // image_key
            None, // image_nonce
            relay_urls,
            admin_pubkeys,
        );

        let mdk = self.lock()?;
        let result = mdk.create_group(&creator_pubkey, member_key_package_events, config)?;

        let welcome_rumors_json: Vec<String> = result
            .welcome_rumors
            .iter()
            .map(|rumor| {
                serde_json::to_string(rumor).map_err(|e| {
                    MdkUniffiError::InvalidInput(format!("Failed to serialize welcome rumor: {e}"))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(CreateGroupResult {
            group: Group::from(result.group),
            welcome_rumors_json,
        })
    }

    /// Add members to a group
    pub fn add_members(
        &self,
        mls_group_id: String,
        key_package_events_json: Vec<String>,
    ) -> Result<UpdateGroupResult, MdkUniffiError> {
        let group_id = parse_group_id(&mls_group_id)?;

        let key_package_events: Vec<Event> = key_package_events_json
            .iter()
            .map(|json| parse_json(json, "key package event JSON"))
            .collect::<Result<_, _>>()?;

        let mdk = self.lock()?;
        let result = mdk.add_members(&group_id, &key_package_events)?;
        update_group_result_to_uniffi(result)
    }

    /// Remove members from a group
    pub fn remove_members(
        &self,
        mls_group_id: String,
        member_public_keys: Vec<String>,
    ) -> Result<UpdateGroupResult, MdkUniffiError> {
        let group_id = parse_group_id(&mls_group_id)?;

        let pubkeys: Vec<PublicKey> = member_public_keys
            .iter()
            .map(|pk| parse_public_key(pk))
            .collect::<Result<_, _>>()?;

        let mdk = self.lock()?;
        let result = mdk.remove_members(&group_id, &pubkeys)?;
        update_group_result_to_uniffi(result)
    }

    /// Merge pending commit for a group
    pub fn merge_pending_commit(&self, mls_group_id: String) -> Result<(), MdkUniffiError> {
        let group_id = parse_group_id(&mls_group_id)?;
        self.lock()?.merge_pending_commit(&group_id)?;
        Ok(())
    }

    /// Clear pending commit for a group
    ///
    /// This rolls back the group to its pre-commit state — no epoch advance, no member changes.
    /// Call this when publish exhausts retries to recover from failed relay publishes.
    ///
    /// # Arguments
    /// * `mls_group_id` - The MLS group ID to clear the pending commit for (hex-encoded)
    ///
    /// # Returns
    /// * `Ok(())` - if the pending commit was cleared successfully
    /// * `Err` - if the group doesn't exist or another error occurs
    pub fn clear_pending_commit(&self, mls_group_id: String) -> Result<(), MdkUniffiError> {
        let group_id = parse_group_id(&mls_group_id)?;
        self.lock()?.clear_pending_commit(&group_id)?;
        Ok(())
    }

    /// Sync group metadata from MLS
    pub fn sync_group_metadata_from_mls(&self, mls_group_id: String) -> Result<(), MdkUniffiError> {
        let group_id = parse_group_id(&mls_group_id)?;
        self.lock()?.sync_group_metadata_from_mls(&group_id)?;
        Ok(())
    }

    /// Create a message in a group.
    ///
    /// `tags` are appended to the rumor and therefore are encrypted.
    ///
    /// `event_tags` are appended to the outer kind:445 wrapper event. Only a subset
    /// of tags are allowed; see [`EventTag`] for the full list.
    pub fn create_message(
        &self,
        mls_group_id: String,
        sender_public_key: String,
        content: String,
        kind: u16,
        tags: Option<Vec<Vec<String>>>,
        event_tags: Option<Vec<Vec<String>>>,
    ) -> Result<String, MdkUniffiError> {
        let group_id = parse_group_id(&mls_group_id)?;
        let sender_pubkey = parse_public_key(&sender_public_key)?;
        let mdk = self.lock()?;

        let mut builder = EventBuilder::new(Kind::Custom(kind), content);

        if let Some(tags_vec) = tags {
            let parsed_tags = parse_tags(tags_vec)?;
            builder = builder.tags(parsed_tags);
        }

        let parsed_event_tags = event_tags.map(parse_event_tags).transpose()?;

        let rumor = builder.build(sender_pubkey);

        let event = mdk.create_message(&group_id, rumor, parsed_event_tags)?;

        let event_json = serde_json::to_string(&event)
            .map_err(|e| MdkUniffiError::InvalidInput(format!("Failed to serialize event: {e}")))?;

        Ok(event_json)
    }

    /// Update the current member's leaf node in an MLS group
    pub fn self_update(&self, mls_group_id: String) -> Result<UpdateGroupResult, MdkUniffiError> {
        let group_id = parse_group_id(&mls_group_id)?;
        let mdk = self.lock()?;
        let result = mdk.self_update(&group_id)?;
        update_group_result_to_uniffi(result)
    }

    /// Create a proposal to leave the group
    pub fn leave_group(&self, mls_group_id: String) -> Result<UpdateGroupResult, MdkUniffiError> {
        let group_id = parse_group_id(&mls_group_id)?;
        let mdk = self.lock()?;
        let result = mdk.leave_group(&group_id)?;
        update_group_result_to_uniffi(result)
    }

    /// Self-demote from admin status before leaving a group.
    ///
    /// Per MIP-03, admins must call this before leave_group(). If the caller is
    /// the last admin, they must designate a successor via update_group_data first.
    pub fn self_demote(&self, mls_group_id: String) -> Result<UpdateGroupResult, MdkUniffiError> {
        let group_id = parse_group_id(&mls_group_id)?;
        let mdk = self.lock()?;
        let result = mdk.self_demote(&group_id)?;

        let evolution_event_json = serde_json::to_string(&result.evolution_event).map_err(|e| {
            MdkUniffiError::InvalidInput(format!("Failed to serialize evolution event: {e}"))
        })?;

        Ok(UpdateGroupResult {
            evolution_event_json,
            welcome_rumors_json: None,
            mls_group_id: hex::encode(result.mls_group_id.as_slice()),
        })
    }

    /// Update group data (name, description, image, relays, admins)
    pub fn update_group_data(
        &self,
        mls_group_id: String,
        update: GroupDataUpdate,
    ) -> Result<UpdateGroupResult, MdkUniffiError> {
        let group_id = parse_group_id(&mls_group_id)?;

        let mut group_update = NostrGroupDataUpdate::new();

        if let Some(name) = update.name {
            group_update = group_update.name(name);
        }

        if let Some(description) = update.description {
            group_update = group_update.description(description);
        }

        if let Some(image_hash) = update.image_hash {
            group_update = group_update.image_hash(vec_to_array::<32>(image_hash)?);
        }

        if let Some(image_key) = update.image_key {
            group_update = group_update.image_key(vec_to_array::<32>(image_key)?);
        }

        if let Some(image_nonce) = update.image_nonce {
            group_update = group_update.image_nonce(vec_to_array::<12>(image_nonce)?);
        }

        if let Some(relays) = update.relays {
            let relay_urls = parse_relay_urls(&relays)?;
            group_update = group_update.relays(relay_urls);
        }

        if let Some(admins) = update.admins {
            let admin_pubkeys: Vec<PublicKey> = admins
                .iter()
                .map(|a| parse_public_key(a))
                .collect::<Result<_, _>>()?;
            group_update = group_update.admins(admin_pubkeys);
        }

        let mdk = self.lock()?;
        let result = mdk.update_group_data(&group_id, group_update)?;
        update_group_result_to_uniffi(result)
    }

    /// Process an incoming MLS message
    pub fn process_message(
        &self,
        event_json: String,
    ) -> Result<ProcessMessageResult, MdkUniffiError> {
        let event: Event = parse_json(&event_json, "event JSON")?;
        let mdk = self.lock()?;
        let result = mdk.process_message(&event)?;
        message_processing_result_to_uniffi(result)
    }

    /// Process an incoming MLS message and return the result with additional MLS context
    ///
    /// Unlike `process_message`, this method also returns transient MLS context
    /// such as the sender's leaf index, which is useful for UI display or
    /// verification purposes.
    ///
    /// # Arguments
    ///
    /// * `event_json` - JSON-encoded Nostr event containing the MLS message
    pub fn process_message_with_context(
        &self,
        event_json: String,
    ) -> Result<ProcessMessageWithContextResult, MdkUniffiError> {
        let event: Event = parse_json(&event_json, "event JSON")?;
        let mdk = self.lock()?;
        let outcome = mdk.process_message_with_context(&event)?;

        Ok(ProcessMessageWithContextResult {
            result: message_processing_result_to_uniffi(outcome.result)?,
            sender_leaf_index: outcome.context.sender_leaf_index,
        })
    }

    /// Delete a key package from MLS storage using a key package Nostr event
    ///
    /// Parses the key package from the given kind-443 event and removes it
    /// from the MLS provider's storage.
    ///
    /// # Arguments
    ///
    /// * `key_package_event_json` - JSON-encoded Nostr key package event (kind 443)
    pub fn delete_key_package_from_storage(
        &self,
        key_package_event_json: String,
    ) -> Result<(), MdkUniffiError> {
        let event: Event = parse_json(&key_package_event_json, "key package event JSON")?;
        let mdk = self.lock()?;
        let key_package = mdk.parse_key_package(&event)?;
        mdk.delete_key_package_from_storage(&key_package)?;
        Ok(())
    }

    /// Delete a key package from storage using previously serialized hash_ref bytes
    ///
    /// The `hash_ref` should be the bytes returned as the third element of
    /// `create_key_package_for_event`.
    ///
    /// # Arguments
    ///
    /// * `hash_ref` - Serialized hash reference bytes from key package creation
    pub fn delete_key_package_from_storage_by_hash_ref(
        &self,
        hash_ref: Vec<u8>,
    ) -> Result<(), MdkUniffiError> {
        let mdk = self.lock()?;
        mdk.delete_key_package_from_storage_by_hash_ref(&hash_ref)?;
        Ok(())
    }

    /// Get public information about the ratchet tree of an MLS group
    ///
    /// This includes a SHA-256 fingerprint of the TLS-serialized ratchet tree,
    /// the full serialized tree as hex, and a list of leaf nodes with their
    /// indices and public keys.
    ///
    /// # Arguments
    ///
    /// * `group_id_hex` - Hex-encoded MLS group ID
    pub fn get_ratchet_tree_info(
        &self,
        group_id_hex: String,
    ) -> Result<UniffiRatchetTreeInfo, MdkUniffiError> {
        let group_id = parse_group_id(&group_id_hex)?;
        let mdk = self.lock()?;
        let info = mdk.get_ratchet_tree_info(&group_id)?;

        Ok(UniffiRatchetTreeInfo {
            tree_hash: info.tree_hash,
            serialized_tree: info.serialized_tree,
            leaf_nodes: info
                .leaf_nodes
                .into_iter()
                .map(|n| UniffiLeafNodeInfo {
                    index: n.index,
                    encryption_key: n.encryption_key,
                    signature_key: n.signature_key,
                    credential_identity: n.credential_identity,
                })
                .collect(),
        })
    }

    /// Returns the current active MLS leaf positions and their bound Nostr public keys
    ///
    /// Returns a list of (leaf_index, public_key_hex) pairs. Removed-member tree
    /// holes are omitted.
    ///
    /// # Arguments
    ///
    /// * `group_id_hex` - Hex-encoded MLS group ID
    pub fn group_leaf_map(
        &self,
        group_id_hex: String,
    ) -> Result<Vec<LeafMapEntry>, MdkUniffiError> {
        let group_id = parse_group_id(&group_id_hex)?;
        let mdk = self.lock()?;
        let map = mdk.group_leaf_map(&group_id)?;

        Ok(map
            .into_iter()
            .map(|(index, pubkey)| LeafMapEntry {
                leaf_index: index,
                public_key: pubkey.to_hex(),
            })
            .collect())
    }

    /// Returns the local member's current MLS leaf index for a group
    ///
    /// # Arguments
    ///
    /// * `group_id_hex` - Hex-encoded MLS group ID
    pub fn own_leaf_index(&self, group_id_hex: String) -> Result<u32, MdkUniffiError> {
        let group_id = parse_group_id(&group_id_hex)?;
        let mdk = self.lock()?;
        Ok(mdk.own_leaf_index(&group_id)?)
    }

    /// Gets the public keys of members that will be added from pending proposals
    ///
    /// Returns hex-encoded public keys of members in pending Add proposals.
    ///
    /// # Arguments
    ///
    /// * `group_id_hex` - Hex-encoded MLS group ID
    pub fn pending_added_members_pubkeys(
        &self,
        group_id_hex: String,
    ) -> Result<Vec<String>, MdkUniffiError> {
        let group_id = parse_group_id(&group_id_hex)?;
        let mdk = self.lock()?;
        let pubkeys = mdk.pending_added_members_pubkeys(&group_id)?;
        Ok(pubkeys.iter().map(|pk| pk.to_hex()).collect())
    }

    /// Gets all pending member changes (additions and removals) from pending proposals
    ///
    /// Returns a combined view of all pending member changes in a group.
    ///
    /// # Arguments
    ///
    /// * `group_id_hex` - Hex-encoded MLS group ID
    pub fn pending_member_changes(
        &self,
        group_id_hex: String,
    ) -> Result<UniffiPendingMemberChanges, MdkUniffiError> {
        let group_id = parse_group_id(&group_id_hex)?;
        let mdk = self.lock()?;
        let changes = mdk.pending_member_changes(&group_id)?;

        Ok(UniffiPendingMemberChanges {
            additions: changes.additions.iter().map(|pk| pk.to_hex()).collect(),
            removals: changes.removals.iter().map(|pk| pk.to_hex()).collect(),
        })
    }

    /// Gets the public keys of members that will be removed from pending proposals
    ///
    /// Returns hex-encoded public keys of members in pending Remove proposals.
    ///
    /// # Arguments
    ///
    /// * `group_id_hex` - Hex-encoded MLS group ID
    pub fn pending_removed_members_pubkeys(
        &self,
        group_id_hex: String,
    ) -> Result<Vec<String>, MdkUniffiError> {
        let group_id = parse_group_id(&group_id_hex)?;
        let mdk = self.lock()?;
        let pubkeys = mdk.pending_removed_members_pubkeys(&group_id)?;
        Ok(pubkeys.iter().map(|pk| pk.to_hex()).collect())
    }
}

/// Result of creating a key package
#[derive(uniffi::Record)]
pub struct KeyPackageResult {
    /// Base64-encoded key package content
    pub key_package: String,
    /// Tags for the kind:30443 key package event in UniFFI wire format (includes the `d` tag)
    pub tags: Vec<Vec<String>>,
    /// Tags for the legacy kind:443 event (omits the `d` tag)
    pub tags_legacy: Vec<Vec<String>>,
    /// Serialized hash_ref bytes for the key package (for lifecycle tracking)
    pub hash_ref: Vec<u8>,
    /// The `d` tag value (32-byte hex string) for this KeyPackage slot.
    /// Callers SHOULD store this and, when rotating, replace the generated
    /// `["d", ...]` entry in `tags` with the stored value before signing.
    /// Reusing the same `(kind, pubkey, d)` tuple lets relays replace the old event.
    pub d_tag: String,
}

/// Result of creating a group
#[derive(uniffi::Record)]
pub struct CreateGroupResult {
    /// The created group
    pub group: Group,
    /// JSON-encoded welcome rumors to be published
    pub welcome_rumors_json: Vec<String>,
}

/// Result of updating a group
#[derive(uniffi::Record)]
pub struct UpdateGroupResult {
    /// JSON-encoded evolution event to be published
    pub evolution_event_json: String,
    /// Optional JSON-encoded welcome rumors to be published
    pub welcome_rumors_json: Option<Vec<String>>,
    /// Hex-encoded MLS group ID
    pub mls_group_id: String,
}

/// Configuration for updating group data with optional fields
#[derive(uniffi::Record)]
pub struct GroupDataUpdate {
    /// Group name (optional)
    pub name: Option<String>,
    /// Group description (optional)
    pub description: Option<String>,
    /// Group image hash (optional, use Some(None) to clear)
    pub image_hash: Option<Option<Vec<u8>>>,
    /// Group image encryption key (optional, use Some(None) to clear)
    pub image_key: Option<Option<Vec<u8>>>,
    /// Group image encryption nonce (optional, use Some(None) to clear)
    pub image_nonce: Option<Option<Vec<u8>>>,
    /// Relays used by the group (optional)
    pub relays: Option<Vec<String>>,
    /// Group admins (optional)
    pub admins: Option<Vec<String>>,
}

/// Result of processing a message
#[derive(uniffi::Enum)]
pub enum ProcessMessageResult {
    /// An application message (usually a chat message)
    ApplicationMessage {
        /// The processed message
        message: Message,
    },
    /// A proposal message that was auto-committed by an admin receiver
    Proposal {
        /// The proposal result containing evolution event and welcome rumors
        result: UpdateGroupResult,
    },
    /// A pending proposal stored but not committed (receiver is not admin)
    PendingProposal {
        /// Hex-encoded MLS group ID this pending proposal belongs to
        mls_group_id: String,
    },
    /// External join proposal
    ExternalJoinProposal {
        /// Hex-encoded MLS group ID this proposal belongs to
        mls_group_id: String,
    },
    /// Commit message
    Commit {
        /// Hex-encoded MLS group ID this commit applies to
        mls_group_id: String,
    },
    /// Unprocessable message
    Unprocessable {
        /// Hex-encoded MLS group ID of the message that could not be processed
        mls_group_id: String,
    },
    /// Proposal was ignored and not stored
    IgnoredProposal {
        /// Hex-encoded MLS group ID this proposal was for
        mls_group_id: String,
        /// Reason the proposal was ignored
        reason: String,
    },
    /// Message was previously marked as failed and cannot be reprocessed
    ///
    /// This is returned when attempting to process a message that previously
    /// failed. Unlike throwing an error, this allows clients to handle the
    /// case gracefully without crashing.
    PreviouslyFailed,
}

/// Result of processing a message with additional MLS context
#[derive(uniffi::Record)]
pub struct ProcessMessageWithContextResult {
    /// The primary processing result
    pub result: ProcessMessageResult,
    /// The MLS sender leaf index, if the sender is a group member
    pub sender_leaf_index: Option<u32>,
}

/// An entry in the group leaf map
#[derive(uniffi::Record)]
pub struct LeafMapEntry {
    /// The leaf index in the ratchet tree
    pub leaf_index: u32,
    /// Hex-encoded Nostr public key bound to this leaf
    pub public_key: String,
}

/// Public information about a leaf node in the ratchet tree
#[derive(uniffi::Record)]
pub struct UniffiLeafNodeInfo {
    /// The leaf index in the ratchet tree
    pub index: u32,
    /// The member's public HPKE encryption key (hex-encoded)
    pub encryption_key: String,
    /// The member's public signature key (hex-encoded)
    pub signature_key: String,
    /// The member's credential identity (hex-encoded, typically a Nostr public key)
    pub credential_identity: String,
}

/// Public information about the ratchet tree of an MLS group
#[derive(uniffi::Record)]
pub struct UniffiRatchetTreeInfo {
    /// SHA-256 fingerprint of the TLS-serialized ratchet tree (hex-encoded)
    pub tree_hash: String,
    /// The full ratchet tree serialized via TLS encoding (hex-encoded)
    pub serialized_tree: String,
    /// Leaf nodes with their indices and public keys
    pub leaf_nodes: Vec<UniffiLeafNodeInfo>,
}

/// Pending member changes from proposals that need admin approval
#[derive(uniffi::Record)]
pub struct UniffiPendingMemberChanges {
    /// Hex-encoded public keys of members that will be added when proposals are committed
    pub additions: Vec<String>,
    /// Hex-encoded public keys of members that will be removed when proposals are committed
    pub removals: Vec<String>,
}

/// Group representation
#[derive(uniffi::Record)]
pub struct Group {
    /// Hex-encoded MLS group ID
    pub mls_group_id: String,
    /// Hex-encoded Nostr group ID
    pub nostr_group_id: String,
    /// Group name
    pub name: String,
    /// Group description
    pub description: String,
    /// Optional group image hash
    pub image_hash: Option<Vec<u8>>,
    /// Optional group image encryption key
    pub image_key: Option<Vec<u8>>,
    /// Optional group image encryption nonce
    pub image_nonce: Option<Vec<u8>>,
    /// List of admin public keys (hex-encoded)
    pub admin_pubkeys: Vec<String>,
    /// Last message event ID (hex-encoded)
    pub last_message_id: Option<String>,
    /// Timestamp of last message (Unix timestamp, sender's `created_at`)
    pub last_message_at: Option<u64>,
    /// Timestamp when the last message was processed/received (Unix timestamp)
    ///
    /// This differs from `last_message_at` which reflects the sender's timestamp.
    /// `last_message_processed_at` reflects when this client received the message,
    /// which may differ due to network delays or clock skew.
    pub last_message_processed_at: Option<u64>,
    /// Current epoch number
    pub epoch: u64,
    /// Group state (e.g., "active", "archived")
    pub state: String,
    /// Self-update tracking state.
    /// - `"required"`: Must perform a post-join self-update (MIP-02).
    /// - `"completed_at:<unix_timestamp>"`: Last self-update merged at this time (MIP-00).
    pub self_update_state: String,
}

impl From<group_types::Group> for Group {
    fn from(g: group_types::Group) -> Self {
        Self {
            mls_group_id: hex::encode(g.mls_group_id.as_slice()),
            nostr_group_id: hex::encode(g.nostr_group_id),
            name: g.name.clone(),
            description: g.description.clone(),
            image_hash: g.image_hash.map(Into::into),
            image_key: g.image_key.map(|k| k.as_ref().to_vec()),
            image_nonce: g.image_nonce.map(|n| n.as_ref().to_vec()),
            admin_pubkeys: g.admin_pubkeys.iter().map(|pk| pk.to_hex()).collect(),
            last_message_id: g.last_message_id.map(|id| id.to_hex()),
            last_message_at: g.last_message_at.map(|ts| ts.as_secs()),
            last_message_processed_at: g.last_message_processed_at.map(|ts| ts.as_secs()),
            epoch: g.epoch,
            state: g.state.as_str().to_string(),
            self_update_state: match g.self_update_state {
                group_types::SelfUpdateState::Required => "required".to_string(),
                group_types::SelfUpdateState::CompletedAt(ts) => {
                    format!("completed_at:{}", ts.as_secs())
                }
            },
        }
    }
}

/// Message representation
#[derive(uniffi::Record)]
pub struct Message {
    /// Message ID (hex-encoded event ID)
    pub id: String,
    /// Hex-encoded MLS group ID
    pub mls_group_id: String,
    /// Hex-encoded Nostr group ID
    pub nostr_group_id: String,
    /// Event ID (hex-encoded)
    pub event_id: String,
    /// Sender public key (hex-encoded)
    pub sender_pubkey: String,
    /// JSON representation of the event
    pub event_json: String,
    /// Timestamp when message was created by the sender (Unix timestamp).
    /// Note: This timestamp comes from the sender's device and may differ
    /// from `processed_at` due to clock skew between devices.
    pub created_at: u64,
    /// Timestamp when this client processed/received the message (Unix timestamp).
    /// This is useful for clients that want to display messages in the order
    /// they were received locally, rather than in the order they were created.
    pub processed_at: u64,
    /// Message kind
    pub kind: u16,
    /// Message state (e.g., "processed", "pending")
    pub state: String,
}

impl From<message_types::Message> for Message {
    fn from(m: message_types::Message) -> Self {
        let nostr_group_id = m
            .event
            .tags
            .iter()
            .find(|t| t.kind() == TagKind::h())
            .and_then(|t| t.content())
            .unwrap_or_default()
            .to_string();

        let event_json = serde_json::to_string(&m.event).unwrap_or_else(|e| {
            tracing::error!(target: "mdk_uniffi::message", "Failed to serialize message event: {}", e);
            "{}".to_string()
        });

        Self {
            id: m.id.to_hex(),
            mls_group_id: hex::encode(m.mls_group_id.as_slice()),
            nostr_group_id,
            event_id: m.wrapper_event_id.to_hex(),
            sender_pubkey: m.pubkey.to_hex(),
            event_json,
            created_at: m.created_at.as_secs(),
            processed_at: m.processed_at.as_secs(),
            kind: m.kind.as_u16(),
            state: m.state.as_str().to_string(),
        }
    }
}

/// Welcome representation
#[derive(uniffi::Record)]
pub struct Welcome {
    /// Welcome ID (hex-encoded event ID)
    pub id: String,
    /// JSON representation of the welcome event
    pub event_json: String,
    /// Hex-encoded MLS group ID
    pub mls_group_id: String,
    /// Hex-encoded Nostr group ID
    pub nostr_group_id: String,
    /// Group name
    pub group_name: String,
    /// Group description
    pub group_description: String,
    /// Optional group image hash
    pub group_image_hash: Option<Vec<u8>>,
    /// Optional group image encryption key
    pub group_image_key: Option<Vec<u8>>,
    /// Optional group image encryption nonce
    pub group_image_nonce: Option<Vec<u8>>,
    /// List of admin public keys (hex-encoded)
    pub group_admin_pubkeys: Vec<String>,
    /// List of relay URLs for the group
    pub group_relays: Vec<String>,
    /// Welcomer public key (hex-encoded)
    pub welcomer: String,
    /// Current member count
    pub member_count: u32,
    /// Welcome state (e.g., "pending", "accepted", "declined")
    pub state: String,
    /// Wrapper event ID (hex-encoded)
    pub wrapper_event_id: String,
}

impl From<welcome_types::Welcome> for Welcome {
    fn from(w: welcome_types::Welcome) -> Self {
        let event_json = serde_json::to_string(&w.event).unwrap_or_else(|e| {
            tracing::error!(target: "mdk_uniffi::welcome", "Failed to serialize welcome event: {}", e);
            "{}".to_string()
        });

        Self {
            id: w.id.to_hex(),
            event_json,
            mls_group_id: hex::encode(w.mls_group_id.as_slice()),
            nostr_group_id: hex::encode(w.nostr_group_id),
            group_name: w.group_name.clone(),
            group_description: w.group_description.clone(),
            group_image_hash: w.group_image_hash.map(Into::into),
            group_image_key: w.group_image_key.map(|k| k.as_ref().to_vec()),
            group_image_nonce: w.group_image_nonce.map(|n| n.as_ref().to_vec()),
            group_admin_pubkeys: w.group_admin_pubkeys.iter().map(|pk| pk.to_hex()).collect(),
            group_relays: w.group_relays.iter().map(|r| r.to_string()).collect(),
            welcomer: w.welcomer.to_hex(),
            member_count: w.member_count,
            state: w.state.as_str().to_string(),
            wrapper_event_id: w.wrapper_event_id.to_hex(),
        }
    }
}

/// Prepared group image data ready for upload to Blossom
#[derive(uniffi::Record)]
pub struct GroupImageUpload {
    /// Encrypted image data (ready to upload to Blossom)
    pub encrypted_data: Vec<u8>,
    /// SHA256 hash of encrypted data (verify against Blossom response)
    pub encrypted_hash: Vec<u8>,
    /// Encryption key (store in extension)
    pub image_key: Vec<u8>,
    /// Encryption nonce (store in extension)
    pub image_nonce: Vec<u8>,
    /// Derived keypair secret for Blossom authentication (hex encoded)
    pub upload_secret_key: String,
    /// Original image size before encryption
    pub original_size: u64,
    /// Size after encryption
    pub encrypted_size: u64,
    /// Validated and canonical MIME type
    pub mime_type: String,
    /// Image dimensions (width, height) if available
    pub dimensions: Option<ImageDimensions>,
    /// Blurhash for preview if generated
    pub blurhash: Option<String>,
    /// Thumbhash for preview if generated
    pub thumbhash: Option<String>,
}

/// Image dimensions
#[derive(uniffi::Record)]
pub struct ImageDimensions {
    /// Width in pixels
    pub width: u32,
    /// Height in pixels
    pub height: u32,
}

/// Prepare group image for upload
#[uniffi::export]
pub fn prepare_group_image_for_upload(
    image_data: Vec<u8>,
    mime_type: String,
) -> Result<GroupImageUpload, MdkUniffiError> {
    let prepared = core_prepare_group_image_for_upload(&image_data, &mime_type)
        .map_err(|e| MdkUniffiError::Mdk(e.to_string()))?;

    Ok(GroupImageUpload {
        encrypted_data: prepared.encrypted_data.as_ref().clone(),
        encrypted_hash: prepared.encrypted_hash.to_vec(),
        image_key: prepared.image_key.as_ref().to_vec(),
        image_nonce: prepared.image_nonce.as_ref().to_vec(),
        upload_secret_key: prepared.upload_keypair.secret_key().to_secret_hex(),
        original_size: prepared.original_size as u64,
        encrypted_size: prepared.encrypted_size as u64,
        mime_type: prepared.mime_type.clone(),
        dimensions: prepared.dimensions.map(|(w, h)| ImageDimensions {
            width: w,
            height: h,
        }),
        blurhash: prepared.blurhash.clone(),
        thumbhash: prepared.thumbhash.clone(),
    })
}

/// Prepare group image for upload with custom processing options
///
/// Like `prepare_group_image_for_upload`, but allows customizing validation
/// and processing behavior such as EXIF stripping, blurhash generation,
/// and size limits.
#[uniffi::export]
pub fn prepare_group_image_for_upload_with_options(
    image_data: Vec<u8>,
    mime_type: String,
    options: MediaProcessingOptionsInput,
) -> Result<GroupImageUpload, MdkUniffiError> {
    let core_options = MediaProcessingOptions::try_from(options)
        .map_err(|e| MdkUniffiError::InvalidInput(format!("Invalid processing options: {e}")))?;
    let prepared =
        core_prepare_group_image_for_upload_with_options(&image_data, &mime_type, &core_options)
            .map_err(|e| MdkUniffiError::Mdk(e.to_string()))?;

    Ok(GroupImageUpload {
        encrypted_data: prepared.encrypted_data.as_ref().clone(),
        encrypted_hash: prepared.encrypted_hash.to_vec(),
        image_key: prepared.image_key.as_ref().to_vec(),
        image_nonce: prepared.image_nonce.as_ref().to_vec(),
        upload_secret_key: prepared.upload_keypair.secret_key().to_secret_hex(),
        original_size: prepared.original_size as u64,
        encrypted_size: prepared.encrypted_size as u64,
        mime_type: prepared.mime_type.clone(),
        dimensions: prepared.dimensions.map(|(w, h)| ImageDimensions {
            width: w,
            height: h,
        }),
        blurhash: prepared.blurhash.clone(),
        thumbhash: prepared.thumbhash.clone(),
    })
}

/// Decrypt group image
#[uniffi::export]
pub fn decrypt_group_image(
    encrypted_data: Vec<u8>,
    expected_hash: Option<Vec<u8>>,
    image_key: Vec<u8>,
    image_nonce: Vec<u8>,
) -> Result<Vec<u8>, MdkUniffiError> {
    let hash_arr_opt: Option<[u8; 32]> = expected_hash
        .map(|hash| {
            hash.try_into().map_err(|_| {
                MdkUniffiError::InvalidInput("Expected hash must be 32 bytes".to_string())
            })
        })
        .transpose()?;

    let key_arr: [u8; 32] = image_key
        .try_into()
        .map_err(|_| MdkUniffiError::InvalidInput("Image key must be 32 bytes".to_string()))?;

    let nonce_arr: [u8; 12] = image_nonce
        .try_into()
        .map_err(|_| MdkUniffiError::InvalidInput("Image nonce must be 12 bytes".to_string()))?;

    core_decrypt_group_image(
        &encrypted_data,
        hash_arr_opt.as_ref(),
        &mdk_storage_traits::Secret::new(key_arr),
        &mdk_storage_traits::Secret::new(nonce_arr),
    )
    .map_err(|e| MdkUniffiError::Mdk(e.to_string()))
}

/// Derive upload keypair for group image
#[uniffi::export]
pub fn derive_upload_keypair(image_key: Vec<u8>, version: u16) -> Result<String, MdkUniffiError> {
    let key_arr: [u8; 32] = image_key
        .try_into()
        .map_err(|_| MdkUniffiError::InvalidInput("Image key must be 32 bytes".to_string()))?;

    let keys = core_derive_upload_keypair(&mdk_storage_traits::Secret::new(key_arr), version)
        .map_err(|e| MdkUniffiError::Mdk(e.to_string()))?;

    Ok(keys.secret_key().to_secret_hex())
}

// ── MIP-04: Encrypted Media ──────────────────────────────────────────────────

/// Options for controlling media processing during encryption
///
/// `max_dimension`, `max_file_size`, and `max_filename_length` are optional and
/// fall back to sensible, privacy-first defaults when `None`.
/// `sanitize_exif`, `generate_blurhash`, and `generate_thumbhash` are explicit
/// toggles; pass `None` to accept the privacy-first defaults (`true` for all
/// preview hashes).
/// To use all defaults without constructing this struct, call
/// `encrypt_media_for_upload`.
#[derive(Debug, Clone, uniffi::Record)]
pub struct MediaProcessingOptionsInput {
    /// Strip EXIF and other metadata from images for privacy (default: `true`)
    pub sanitize_exif: Option<bool>,
    /// Generate a blurhash preview string for images (default: `true`)
    pub generate_blurhash: Option<bool>,
    /// Generate a thumbhash preview string for images (default: `true`)
    pub generate_thumbhash: Option<bool>,
    /// Maximum allowed image dimension in pixels (default: 16384)
    pub max_dimension: Option<u32>,
    /// Maximum allowed file size in bytes (default: 100 MiB)
    pub max_file_size: Option<u64>,
    /// Maximum allowed filename length in characters (default: 210)
    pub max_filename_length: Option<u64>,
}

impl TryFrom<MediaProcessingOptionsInput> for MediaProcessingOptions {
    type Error = std::num::TryFromIntError;

    fn try_from(o: MediaProcessingOptionsInput) -> Result<Self, Self::Error> {
        Ok(Self {
            sanitize_exif: o.sanitize_exif.unwrap_or(true),
            generate_blurhash: o.generate_blurhash.unwrap_or(true),
            generate_thumbhash: o.generate_thumbhash.unwrap_or(true),
            max_dimension: o.max_dimension,
            max_file_size: o.max_file_size.map(usize::try_from).transpose()?,
            max_filename_length: o.max_filename_length.map(usize::try_from).transpose()?,
        })
    }
}

/// Result of encrypting media for upload
///
/// Contains the encrypted bytes ready for upload to a Blossom server, along
/// with the metadata required to build the IMETA tag and later decrypt the file.
#[derive(Debug, Clone, uniffi::Record)]
pub struct EncryptedMediaUploadResult {
    /// Encrypted media bytes — upload these to your Blossom server
    pub encrypted_data: Vec<u8>,
    /// SHA-256 hash of the original (pre-encryption, post-sanitization) data
    pub original_hash: Vec<u8>,
    /// SHA-256 hash of the encrypted data — verify against the Blossom server response
    pub encrypted_hash: Vec<u8>,
    /// Canonical MIME type of the original media (e.g. `"image/webp"`)
    pub mime_type: String,
    /// Original filename
    pub filename: String,
    /// Size of the original data in bytes
    pub original_size: u64,
    /// Size of the encrypted data in bytes
    pub encrypted_size: u64,
    /// Image dimensions `[width, height]` if the media is an image, otherwise `None`
    pub dimensions: Option<Vec<u32>>,
    /// Blurhash preview string if generated, otherwise `None`
    pub blurhash: Option<String>,
    /// Thumbhash preview string if generated, otherwise `None`
    pub thumbhash: Option<String>,
    /// 12-byte ChaCha20-Poly1305 nonce used for encryption
    pub nonce: Vec<u8>,
}

impl TryFrom<EncryptedMediaUpload> for EncryptedMediaUploadResult {
    type Error = MdkUniffiError;

    fn try_from(u: EncryptedMediaUpload) -> Result<Self, Self::Error> {
        Ok(Self {
            encrypted_data: u.encrypted_data,
            original_hash: u.original_hash.to_vec(),
            encrypted_hash: u.encrypted_hash.to_vec(),
            mime_type: u.mime_type,
            filename: u.filename,
            original_size: u.original_size,
            encrypted_size: u.encrypted_size,
            dimensions: u.dimensions.map(|(w, h)| vec![w, h]),
            blurhash: u.blurhash,
            thumbhash: u.thumbhash,
            nonce: u.nonce.to_vec(),
        })
    }
}

/// A reference to an encrypted media file stored on a Blossom server
///
/// This is parsed from an IMETA tag (via `parse_media_imeta_tag`) and passed
/// to `decrypt_media_from_download` to retrieve the original file.
#[derive(Debug, Clone, uniffi::Record)]
pub struct MediaReferenceRecord {
    /// URL where the encrypted file is stored
    pub url: String,
    /// SHA-256 hash of the original (pre-encryption) data — 32 bytes
    pub original_hash: Vec<u8>,
    /// MIME type of the original media
    pub mime_type: String,
    /// Original filename
    pub filename: String,
    /// Image dimensions `[width, height]` if the media is an image, otherwise `None`
    pub dimensions: Option<Vec<u32>>,
    /// Encryption scheme version (e.g. `"mip04-v2"`)
    pub scheme_version: String,
    /// 12-byte ChaCha20-Poly1305 nonce — 12 bytes
    pub nonce: Vec<u8>,
}

impl TryFrom<MediaReferenceRecord> for MediaReference {
    type Error = MdkUniffiError;

    fn try_from(r: MediaReferenceRecord) -> Result<Self, Self::Error> {
        let original_hash: [u8; 32] = r.original_hash.try_into().map_err(|_| {
            MdkUniffiError::InvalidInput("original_hash must be 32 bytes".to_string())
        })?;
        let nonce: [u8; 12] = r
            .nonce
            .try_into()
            .map_err(|_| MdkUniffiError::InvalidInput("nonce must be 12 bytes".to_string()))?;
        let dimensions = r
            .dimensions
            .map(|d| {
                if d.len() == 2 {
                    Ok((d[0], d[1]))
                } else {
                    Err(MdkUniffiError::InvalidInput(
                        "dimensions must be a two-element array [width, height]".to_string(),
                    ))
                }
            })
            .transpose()?;
        Ok(Self {
            url: r.url,
            original_hash,
            mime_type: r.mime_type,
            filename: r.filename,
            dimensions,
            scheme_version: r.scheme_version,
            nonce,
        })
    }
}

impl From<MediaReference> for MediaReferenceRecord {
    fn from(r: MediaReference) -> Self {
        Self {
            url: r.url,
            original_hash: r.original_hash.to_vec(),
            mime_type: r.mime_type,
            filename: r.filename,
            dimensions: r.dimensions.map(|(w, h)| vec![w, h]),
            scheme_version: r.scheme_version,
            nonce: r.nonce.to_vec(),
        }
    }
}

// ── MIP-04 methods on Mdk ────────────────────────────────────────────────────

#[uniffi::export]
impl Mdk {
    /// Encrypt media for upload using default processing options
    ///
    /// Encrypts the supplied media file with the group's current MLS epoch key,
    /// producing ciphertext ready to upload to a Blossom server. Images are
    /// automatically EXIF-sanitized and blurhash/thumbhash preview hashes are
    /// generated.
    ///
    /// After uploading the encrypted bytes, call `create_media_imeta_tag` with
    /// the returned result and the Blossom URL to build the IMETA tag to attach
    /// to the group message.
    ///
    /// # Arguments
    ///
    /// * `mls_group_id` - Hex-encoded MLS group ID
    /// * `data` - Raw media file bytes
    /// * `mime_type` - MIME type of the media (e.g. `"image/jpeg"`)
    /// * `filename` - Original filename (used as AAD in the encryption)
    pub fn encrypt_media_for_upload(
        &self,
        mls_group_id: String,
        data: Vec<u8>,
        mime_type: String,
        filename: String,
    ) -> Result<EncryptedMediaUploadResult, MdkUniffiError> {
        let group_id = parse_group_id(&mls_group_id)?;
        let mdk = self.lock()?;
        let upload = mdk
            .media_manager(group_id)
            .encrypt_for_upload(&data, &mime_type, &filename)
            .map_err(|e| MdkUniffiError::Mdk(e.to_string()))?;
        EncryptedMediaUploadResult::try_from(upload)
    }

    /// Encrypt media for upload with custom processing options
    ///
    /// Same as `encrypt_media_for_upload` but lets you override EXIF
    /// sanitization, preview hash generation, and size/dimension limits.
    ///
    /// # Arguments
    ///
    /// * `mls_group_id` - Hex-encoded MLS group ID
    /// * `data` - Raw media file bytes
    /// * `mime_type` - MIME type of the media (e.g. `"image/jpeg"`)
    /// * `filename` - Original filename (used as AAD in the encryption)
    /// * `options` - Custom processing options
    pub fn encrypt_media_for_upload_with_options(
        &self,
        mls_group_id: String,
        data: Vec<u8>,
        mime_type: String,
        filename: String,
        options: MediaProcessingOptionsInput,
    ) -> Result<EncryptedMediaUploadResult, MdkUniffiError> {
        let group_id = parse_group_id(&mls_group_id)?;
        let core_options = MediaProcessingOptions::try_from(options)
            .map_err(|e| MdkUniffiError::InvalidInput(e.to_string()))?;
        let mdk = self.lock()?;
        let upload = mdk
            .media_manager(group_id)
            .encrypt_for_upload_with_options(&data, &mime_type, &filename, &core_options)
            .map_err(|e| MdkUniffiError::Mdk(e.to_string()))?;
        EncryptedMediaUploadResult::try_from(upload)
    }

    /// Decrypt media downloaded from a Blossom server
    ///
    /// Decrypts the encrypted bytes using the key derived from the group's MLS
    /// epoch that was active when the file was encrypted (looked up automatically
    /// via the epoch hint stored alongside the message). Falls back to the current
    /// epoch if no hint is available.
    ///
    /// The `reference` parameter is typically obtained by calling
    /// `parse_media_imeta_tag` on the IMETA tag attached to the message.
    ///
    /// # Arguments
    ///
    /// * `mls_group_id` - Hex-encoded MLS group ID
    /// * `encrypted_data` - Encrypted bytes downloaded from the Blossom server
    /// * `reference` - Parsed media reference (from `parse_media_imeta_tag`)
    pub fn decrypt_media_from_download(
        &self,
        mls_group_id: String,
        encrypted_data: Vec<u8>,
        reference: MediaReferenceRecord,
    ) -> Result<Vec<u8>, MdkUniffiError> {
        let group_id = parse_group_id(&mls_group_id)?;
        let core_reference = MediaReference::try_from(reference)?;
        let mdk = self.lock()?;
        mdk.media_manager(group_id)
            .decrypt_from_download(&encrypted_data, &core_reference)
            .map_err(|e| MdkUniffiError::Mdk(e.to_string()))
    }

    /// Build an IMETA tag for an encrypted media upload
    ///
    /// Creates the IMETA Nostr tag per the MIP-04 specification. Attach this tag
    /// to the group message event after uploading the encrypted bytes to Blossom.
    ///
    /// Returns the tag as a `Vec<Vec<String>>` (the standard UniFFI tag format).
    ///
    /// # Arguments
    ///
    /// * `mls_group_id` - Hex-encoded MLS group ID
    /// * `upload` - The result returned by `encrypt_media_for_upload`
    /// * `uploaded_url` - The URL returned by the Blossom server after upload
    pub fn create_media_imeta_tag(
        &self,
        mls_group_id: String,
        upload: EncryptedMediaUploadResult,
        uploaded_url: String,
    ) -> Result<Vec<Vec<String>>, MdkUniffiError> {
        let group_id = parse_group_id(&mls_group_id)?;
        let core_upload = EncryptedMediaUpload::try_from(upload)?;
        let mdk = self.lock()?;
        let tag = mdk
            .media_manager(group_id)
            .create_imeta_tag(&core_upload, &uploaded_url);
        Ok(vec![tag.as_slice().to_vec()])
    }

    /// Parse an IMETA tag into a `MediaReferenceRecord` for decryption
    ///
    /// Validates and decodes the IMETA tag fields according to the MIP-04
    /// specification. The returned record can be passed directly to
    /// `decrypt_media_from_download`.
    ///
    /// The tag must be provided as a single-element `Vec<Vec<String>>` — the
    /// same format returned by `create_media_imeta_tag` and the standard UniFFI
    /// tag wire format.
    ///
    /// # Arguments
    ///
    /// * `mls_group_id` - Hex-encoded MLS group ID
    /// * `imeta_tag` - IMETA tag as `Vec<Vec<String>>`
    pub fn parse_media_imeta_tag(
        &self,
        mls_group_id: String,
        imeta_tag: Vec<Vec<String>>,
    ) -> Result<MediaReferenceRecord, MdkUniffiError> {
        let group_id = parse_group_id(&mls_group_id)?;
        let tags = parse_tags(imeta_tag)?;
        if tags.len() != 1 {
            return Err(MdkUniffiError::InvalidInput(
                "Expected exactly one IMETA tag".to_string(),
            ));
        }
        let tag = tags.into_iter().next().ok_or_else(|| {
            MdkUniffiError::InvalidInput("Expected exactly one IMETA tag".to_string())
        })?;
        let mdk = self.lock()?;
        let reference = mdk
            .media_manager(group_id)
            .parse_imeta_tag(&tag)
            .map_err(|e| MdkUniffiError::Mdk(e.to_string()))?;
        Ok(MediaReferenceRecord::from(reference))
    }
}

// ── MIP-04 TryFrom for EncryptedMediaUpload (reverse direction for imeta tag) ─

impl TryFrom<EncryptedMediaUploadResult> for EncryptedMediaUpload {
    type Error = MdkUniffiError;

    fn try_from(r: EncryptedMediaUploadResult) -> Result<Self, Self::Error> {
        let original_hash: [u8; 32] = r.original_hash.try_into().map_err(|_| {
            MdkUniffiError::InvalidInput("original_hash must be 32 bytes".to_string())
        })?;
        let encrypted_hash: [u8; 32] = r.encrypted_hash.try_into().map_err(|_| {
            MdkUniffiError::InvalidInput("encrypted_hash must be 32 bytes".to_string())
        })?;
        let nonce: [u8; 12] = r
            .nonce
            .try_into()
            .map_err(|_| MdkUniffiError::InvalidInput("nonce must be 12 bytes".to_string()))?;
        let dimensions = r
            .dimensions
            .map(|d| {
                if d.len() == 2 {
                    Ok((d[0], d[1]))
                } else {
                    Err(MdkUniffiError::InvalidInput(
                        "dimensions must be a two-element array [width, height]".to_string(),
                    ))
                }
            })
            .transpose()?;
        Ok(Self {
            encrypted_data: r.encrypted_data,
            original_hash,
            encrypted_hash,
            mime_type: r.mime_type,
            filename: r.filename,
            original_size: r.original_size,
            encrypted_size: r.encrypted_size,
            dimensions,
            blurhash: r.blurhash,
            thumbhash: r.thumbhash,
            nonce,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::{EventBuilder, JsonUtil, Keys, Kind, Tag, UnsignedEvent};
    use tempfile::TempDir;

    fn create_test_mdk() -> Mdk {
        new_mdk_unencrypted(":memory:".to_string(), None).unwrap()
    }

    #[test]
    fn test_new_mdk_with_key_creates_instance() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");

        // Test encrypted constructor with direct key
        let key = vec![0u8; 32];
        let result = new_mdk_with_key(db_path.to_string_lossy().to_string(), key, None);
        assert!(result.is_ok());
        let mdk = result.unwrap();
        // Should be able to get groups (empty initially)
        let groups = mdk.get_groups().unwrap();
        assert_eq!(groups.len(), 0);
    }

    #[test]
    fn test_new_mdk_with_key_invalid_key_length() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test_invalid_key.db");

        // Test with wrong key length
        let short_key = vec![0u8; 16];
        let result = new_mdk_with_key(db_path.to_string_lossy().to_string(), short_key, None);
        assert!(result.is_err());

        match result {
            Err(MdkUniffiError::InvalidInput(msg)) => {
                assert!(msg.contains("Invalid encryption key"));
            }
            _ => panic!("Expected InvalidInput error"),
        }
    }

    #[test]
    fn test_new_mdk_unencrypted_creates_instance() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test_unencrypted.db");
        let result = new_mdk_unencrypted(db_path.to_string_lossy().to_string(), None);
        assert!(result.is_ok());
        let mdk = result.unwrap();
        // Should be able to get groups (empty initially)
        let groups = mdk.get_groups().unwrap();
        assert_eq!(groups.len(), 0);
    }

    #[test]
    fn test_new_mdk_with_custom_config() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test_custom_config.db");

        // Test with all fields specified
        let config = MdkConfig {
            max_event_age_secs: Some(86400),     // 1 day
            max_future_skew_secs: Some(60),      // 1 minute
            out_of_order_tolerance: Some(50),    // 50 past messages
            maximum_forward_distance: Some(500), // 500 forward messages
            max_past_epochs: Some(5),            // 5 past epochs
            epoch_snapshot_retention: Some(5),   // 5 snapshots
            snapshot_ttl_seconds: Some(604800),  // 1 week
        };

        let result = new_mdk_unencrypted(db_path.to_string_lossy().to_string(), Some(config));
        assert!(result.is_ok());
        let mdk = result.unwrap();
        let groups = mdk.get_groups().unwrap();
        assert_eq!(groups.len(), 0);
    }

    #[test]
    fn test_new_mdk_with_partial_config() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test_partial_config.db");

        // Test with only some fields specified - others should use defaults
        let config = MdkConfig {
            max_event_age_secs: None,
            max_future_skew_secs: None,
            out_of_order_tolerance: Some(200), // Only override this one
            maximum_forward_distance: None,
            max_past_epochs: None,
            epoch_snapshot_retention: None,
            snapshot_ttl_seconds: None,
        };

        let result = new_mdk_unencrypted(db_path.to_string_lossy().to_string(), Some(config));
        assert!(result.is_ok());
        let mdk = result.unwrap();
        let groups = mdk.get_groups().unwrap();
        assert_eq!(groups.len(), 0);
    }

    #[test]
    fn test_mdk_config_defaults() {
        // Verify that the From implementation uses correct defaults
        let config = MdkConfig {
            max_event_age_secs: None,
            max_future_skew_secs: None,
            out_of_order_tolerance: None,
            maximum_forward_distance: None,
            max_past_epochs: None,
            epoch_snapshot_retention: None,
            snapshot_ttl_seconds: None,
        };

        let core_config: CoreMdkConfig = config.into();
        assert_eq!(core_config.max_event_age_secs, 3888000);
        assert_eq!(core_config.max_future_skew_secs, 300);
        assert_eq!(core_config.out_of_order_tolerance, 100);
        assert_eq!(core_config.maximum_forward_distance, 1000);
        assert_eq!(core_config.max_past_epochs, 5);
        assert_eq!(core_config.epoch_snapshot_retention, 5);
        assert_eq!(core_config.snapshot_ttl_seconds, 604800);
    }

    #[test]
    fn test_create_key_package_for_event() {
        let mdk = create_test_mdk();
        let keys = Keys::generate();
        let pubkey_hex = keys.public_key().to_hex();
        let relays = vec!["wss://relay.example.com".to_string()];

        let result = mdk.create_key_package_for_event(pubkey_hex, relays);
        assert!(result.is_ok());
        let key_package_result = result.unwrap();
        assert!(!key_package_result.key_package.is_empty());
        assert!(!key_package_result.tags.is_empty());
        assert!(
            !key_package_result.hash_ref.is_empty(),
            "hash_ref should be non-empty"
        );
    }

    #[test]
    fn test_create_key_package_invalid_public_key() {
        let mdk = create_test_mdk();
        let invalid_pubkey = "not_a_valid_hex".to_string();
        let relays = vec!["wss://relay.example.com".to_string()];

        let result = mdk.create_key_package_for_event(invalid_pubkey, relays);
        assert!(matches!(result, Err(MdkUniffiError::InvalidInput(_))));
    }

    #[test]
    fn test_create_key_package_invalid_relay() {
        let mdk = create_test_mdk();
        let keys = Keys::generate();
        let pubkey_hex = keys.public_key().to_hex();
        let invalid_relays = vec!["not_a_valid_url".to_string()];

        let result = mdk.create_key_package_for_event(pubkey_hex, invalid_relays);
        assert!(matches!(result, Err(MdkUniffiError::InvalidInput(_))));
    }

    #[test]
    fn test_get_groups_empty_initially() {
        let mdk = create_test_mdk();
        let groups = mdk.get_groups().unwrap();
        assert_eq!(groups.len(), 0);
    }

    #[test]
    fn test_get_group_nonexistent() {
        let mdk = create_test_mdk();
        let fake_group_id = hex::encode([0u8; 32]);
        let result = mdk.get_group(fake_group_id);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_get_group_invalid_hex() {
        let mdk = create_test_mdk();
        let invalid_group_id = "not_valid_hex".to_string();
        let result = mdk.get_group(invalid_group_id);
        assert!(matches!(result, Err(MdkUniffiError::InvalidInput(_))));
    }

    #[test]
    fn test_get_members_nonexistent_group() {
        let mdk = create_test_mdk();
        let fake_group_id = hex::encode([0u8; 32]);
        let result = mdk.get_members(fake_group_id);
        // Should return error for non-existent group
        assert!(result.is_err());
    }

    #[test]
    fn test_get_messages_empty_group() {
        let mdk = create_test_mdk();
        let fake_group_id = hex::encode([0u8; 32]);
        let result = mdk.get_messages(fake_group_id, None, None, None);
        // Should return error for non-existent group
        assert!(result.is_err());
    }

    #[test]
    fn test_get_messages_with_pagination() {
        let mdk = create_test_mdk();
        let creator_keys = Keys::generate();
        let member_keys = Keys::generate();

        let member_pubkey_hex = member_keys.public_key().to_hex();
        let relays = vec!["wss://relay.example.com".to_string()];

        // Create key package for member
        let kp_result = mdk
            .create_key_package_for_event(member_pubkey_hex.clone(), relays.clone())
            .unwrap();

        let kp_event = EventBuilder::new(Kind::Custom(30443), kp_result.key_package)
            .tags(
                kp_result
                    .tags
                    .into_iter()
                    .map(|t| Tag::parse(&t).unwrap())
                    .collect::<Vec<_>>(),
            )
            .sign_with_keys(&member_keys)
            .unwrap();

        // Create group
        let create_result = mdk
            .create_group(
                creator_keys.public_key().to_hex(),
                vec![kp_event.as_json()],
                "Test Group".to_string(),
                "Test Description".to_string(),
                relays.clone(),
                vec![creator_keys.public_key().to_hex()],
            )
            .unwrap();

        mdk.merge_pending_commit(create_result.group.mls_group_id.clone())
            .unwrap();

        // Create a message
        mdk.create_message(
            create_result.group.mls_group_id.clone(),
            creator_keys.public_key().to_hex(),
            "Test message".to_string(),
            1,
            None,
            None,
        )
        .unwrap();

        // Test 1: Get with default pagination (None, None)
        let default_messages = mdk
            .get_messages(create_result.group.mls_group_id.clone(), None, None, None)
            .unwrap();
        assert_eq!(default_messages.len(), 1, "Should have 1 message");

        // Test 2: Get with explicit limit and offset
        let paginated = mdk
            .get_messages(
                create_result.group.mls_group_id.clone(),
                Some(10),
                Some(0),
                None,
            )
            .unwrap();
        assert_eq!(paginated.len(), 1, "Should have 1 message with pagination");

        // Test 3: Get with offset beyond available messages
        let empty_page = mdk
            .get_messages(
                create_result.group.mls_group_id.clone(),
                Some(10),
                Some(100),
                None,
            )
            .unwrap();
        assert_eq!(
            empty_page.len(),
            0,
            "Should return empty when offset is beyond available"
        );

        // Test 4: Get with limit 1
        let limited = mdk
            .get_messages(
                create_result.group.mls_group_id.clone(),
                Some(1),
                Some(0),
                None,
            )
            .unwrap();
        assert_eq!(
            limited.len(),
            1,
            "Should return exactly 1 message with limit 1"
        );
    }

    #[test]
    fn test_get_message_invalid_event_id() {
        let mdk = create_test_mdk();
        let fake_group_id = hex::encode([0u8; 32]);
        let invalid_event_id = "not_valid_hex".to_string();
        let result = mdk.get_message(fake_group_id, invalid_event_id);
        assert!(matches!(result, Err(MdkUniffiError::InvalidInput(_))));
    }

    #[test]
    fn test_get_pending_welcomes_empty() {
        let mdk = create_test_mdk();
        let welcomes = mdk.get_pending_welcomes(None, None).unwrap();
        assert_eq!(welcomes.len(), 0);
    }

    #[test]
    fn test_get_pending_welcomes_with_pagination() {
        let mdk = create_test_mdk();
        let creator_keys = Keys::generate();
        let member_keys = Keys::generate();

        let member_pubkey_hex = member_keys.public_key().to_hex();
        let relays = vec!["wss://relay.example.com".to_string()];

        // Create key package for member
        let kp_result = mdk
            .create_key_package_for_event(member_pubkey_hex.clone(), relays.clone())
            .unwrap();

        let kp_event = EventBuilder::new(Kind::Custom(30443), kp_result.key_package)
            .tags(
                kp_result
                    .tags
                    .into_iter()
                    .map(|t| Tag::parse(&t).unwrap())
                    .collect::<Vec<_>>(),
            )
            .sign_with_keys(&member_keys)
            .unwrap();

        // Create group
        let create_result = mdk
            .create_group(
                creator_keys.public_key().to_hex(),
                vec![kp_event.as_json()],
                "Test Group".to_string(),
                "Test Description".to_string(),
                relays.clone(),
                vec![creator_keys.public_key().to_hex()],
            )
            .unwrap();

        mdk.merge_pending_commit(create_result.group.mls_group_id.clone())
            .unwrap();

        // Process welcome for member
        let welcome_rumor_json = &create_result.welcome_rumors_json[0];
        let wrapper_event_id = EventId::all_zeros().to_hex();
        mdk.process_welcome(wrapper_event_id, welcome_rumor_json.clone())
            .unwrap();

        // Test 1: Get with default pagination (None, None)
        let default_welcomes = mdk.get_pending_welcomes(None, None).unwrap();
        assert_eq!(default_welcomes.len(), 1, "Should have 1 pending welcome");

        // Test 2: Get with explicit limit and offset
        let paginated = mdk.get_pending_welcomes(Some(10), Some(0)).unwrap();
        assert_eq!(paginated.len(), 1, "Should have 1 welcome with pagination");

        // Test 3: Get with offset beyond available welcomes
        let empty_page = mdk.get_pending_welcomes(Some(10), Some(100)).unwrap();
        assert_eq!(
            empty_page.len(),
            0,
            "Should return empty when offset is beyond available"
        );

        // Test 4: Get with limit 1
        let limited = mdk.get_pending_welcomes(Some(1), Some(0)).unwrap();
        assert_eq!(
            limited.len(),
            1,
            "Should return exactly 1 welcome with limit 1"
        );
    }

    #[test]
    fn test_accept_welcome_with_object() {
        let mdk = create_test_mdk();
        let creator_keys = Keys::generate();
        let member_keys = Keys::generate();

        let member_pubkey_hex = member_keys.public_key().to_hex();
        let relays = vec!["wss://relay.example.com".to_string()];
        let key_package_result = mdk
            .create_key_package_for_event(member_pubkey_hex.clone(), relays.clone())
            .unwrap();

        let key_package_event =
            EventBuilder::new(Kind::Custom(30443), key_package_result.key_package)
                .tags(
                    key_package_result
                        .tags
                        .iter()
                        .map(|t| Tag::parse(t.clone()).unwrap())
                        .collect::<Vec<_>>(),
                )
                .sign_with_keys(&member_keys)
                .unwrap();

        let key_package_event_json = serde_json::to_string(&key_package_event).unwrap();

        let creator_pubkey_hex = creator_keys.public_key().to_hex();
        let create_result = mdk
            .create_group(
                creator_pubkey_hex,
                vec![key_package_event_json],
                "Test Group".to_string(),
                "Test Description".to_string(),
                relays.clone(),
                vec![creator_keys.public_key().to_hex()],
            )
            .unwrap();

        // Get the welcome rumor from the create result
        let welcome_rumor_json = create_result.welcome_rumors_json.first().unwrap();

        // Process the welcome to get a Welcome object
        let wrapper_event_id = EventId::all_zeros();
        let welcome = mdk
            .process_welcome(wrapper_event_id.to_hex(), welcome_rumor_json.clone())
            .unwrap();

        // Verify welcome is pending
        assert_eq!(welcome.state, "pending");

        // Accept the welcome using the new method that takes a Welcome object
        let result = mdk.accept_welcome(welcome);
        assert!(result.is_ok());

        // Verify the welcome was accepted by checking pending welcomes
        let pending_welcomes = mdk.get_pending_welcomes(None, None).unwrap();
        assert_eq!(pending_welcomes.len(), 0);
    }

    #[test]
    fn test_decline_welcome_with_object() {
        let mdk = create_test_mdk();
        let creator_keys = Keys::generate();
        let member_keys = Keys::generate();

        let member_pubkey_hex = member_keys.public_key().to_hex();
        let relays = vec!["wss://relay.example.com".to_string()];
        let key_package_result = mdk
            .create_key_package_for_event(member_pubkey_hex.clone(), relays.clone())
            .unwrap();

        let key_package_event =
            EventBuilder::new(Kind::Custom(30443), key_package_result.key_package)
                .tags(
                    key_package_result
                        .tags
                        .iter()
                        .map(|t| Tag::parse(t.clone()).unwrap())
                        .collect::<Vec<_>>(),
                )
                .sign_with_keys(&member_keys)
                .unwrap();

        let key_package_event_json = serde_json::to_string(&key_package_event).unwrap();

        let creator_pubkey_hex = creator_keys.public_key().to_hex();
        let create_result = mdk
            .create_group(
                creator_pubkey_hex,
                vec![key_package_event_json],
                "Test Group".to_string(),
                "Test Description".to_string(),
                relays.clone(),
                vec![creator_keys.public_key().to_hex()],
            )
            .unwrap();

        // Get the welcome rumor from the create result
        let welcome_rumor_json = create_result.welcome_rumors_json.first().unwrap();

        // Process the welcome to get a Welcome object
        let wrapper_event_id = EventId::all_zeros();
        let welcome = mdk
            .process_welcome(wrapper_event_id.to_hex(), welcome_rumor_json.clone())
            .unwrap();

        // Verify welcome is pending
        assert_eq!(welcome.state, "pending");

        // Decline the welcome using the new method that takes a Welcome object
        let result = mdk.decline_welcome(welcome);
        assert!(result.is_ok());

        // Verify the welcome was declined by checking pending welcomes
        let pending_welcomes = mdk.get_pending_welcomes(None, None).unwrap();
        assert_eq!(pending_welcomes.len(), 0);
    }

    #[test]
    fn test_accept_welcome_invalid_event_id() {
        let mdk = create_test_mdk();
        let welcome = Welcome {
            id: "invalid_hex".to_string(),
            event_json: "{}".to_string(),
            mls_group_id: hex::encode([0u8; 32]),
            nostr_group_id: hex::encode([0u8; 32]),
            group_name: "Test".to_string(),
            group_description: "Test".to_string(),
            group_image_hash: None,
            group_image_key: None,
            group_image_nonce: None,
            group_admin_pubkeys: vec![],
            group_relays: vec![],
            welcomer: "invalid_hex".to_string(),
            member_count: 0,
            state: "pending".to_string(),
            wrapper_event_id: hex::encode([0u8; 32]),
        };

        let result = mdk.accept_welcome(welcome);
        assert!(matches!(result, Err(MdkUniffiError::InvalidInput(_))));
    }

    #[test]
    fn test_accept_welcome_invalid_event_json() {
        let mdk = create_test_mdk();
        let keys = Keys::generate();
        let event_id = EventId::all_zeros();
        let welcome = Welcome {
            id: event_id.to_hex(),
            event_json: "invalid_json".to_string(),
            mls_group_id: hex::encode([0u8; 32]),
            nostr_group_id: hex::encode([0u8; 32]),
            group_name: "Test".to_string(),
            group_description: "Test".to_string(),
            group_image_hash: None,
            group_image_key: None,
            group_image_nonce: None,
            group_admin_pubkeys: vec![keys.public_key().to_hex()],
            group_relays: vec!["wss://relay.example.com".to_string()],
            welcomer: keys.public_key().to_hex(),
            member_count: 0,
            state: "pending".to_string(),
            wrapper_event_id: event_id.to_hex(),
        };

        let result = mdk.accept_welcome(welcome);
        assert!(matches!(result, Err(MdkUniffiError::InvalidInput(_))));
    }

    #[test]
    fn test_accept_welcome_invalid_nostr_group_id() {
        let mdk = create_test_mdk();
        let keys = Keys::generate();
        let event_id = EventId::all_zeros();
        let event = UnsignedEvent {
            id: Some(event_id),
            pubkey: keys.public_key(),
            created_at: nostr::Timestamp::now(),
            kind: Kind::Custom(444),
            tags: nostr::Tags::new(),
            content: "test".to_string(),
        };
        let event_json = serde_json::to_string(&event).unwrap();

        let welcome = Welcome {
            id: event_id.to_hex(),
            event_json,
            mls_group_id: hex::encode([0u8; 32]),
            nostr_group_id: "invalid_hex".to_string(),
            group_name: "Test".to_string(),
            group_description: "Test".to_string(),
            group_image_hash: None,
            group_image_key: None,
            group_image_nonce: None,
            group_admin_pubkeys: vec![keys.public_key().to_hex()],
            group_relays: vec!["wss://relay.example.com".to_string()],
            welcomer: keys.public_key().to_hex(),
            member_count: 0,
            state: "pending".to_string(),
            wrapper_event_id: event_id.to_hex(),
        };

        let result = mdk.accept_welcome(welcome);
        assert!(matches!(result, Err(MdkUniffiError::InvalidInput(_))));
    }

    #[test]
    fn test_accept_welcome_invalid_state() {
        let mdk = create_test_mdk();
        let keys = Keys::generate();
        let event_id = EventId::all_zeros();
        let event = UnsignedEvent {
            id: Some(event_id),
            pubkey: keys.public_key(),
            created_at: nostr::Timestamp::now(),
            kind: Kind::Custom(444),
            tags: nostr::Tags::new(),
            content: "test".to_string(),
        };
        let event_json = serde_json::to_string(&event).unwrap();

        let welcome = Welcome {
            id: event_id.to_hex(),
            event_json,
            mls_group_id: hex::encode([0u8; 32]),
            nostr_group_id: hex::encode([0u8; 32]),
            group_name: "Test".to_string(),
            group_description: "Test".to_string(),
            group_image_hash: None,
            group_image_key: None,
            group_image_nonce: None,
            group_admin_pubkeys: vec![keys.public_key().to_hex()],
            group_relays: vec!["wss://relay.example.com".to_string()],
            welcomer: keys.public_key().to_hex(),
            member_count: 0,
            state: "invalid_state".to_string(),
            wrapper_event_id: event_id.to_hex(),
        };

        let result = mdk.accept_welcome(welcome);
        assert!(matches!(result, Err(MdkUniffiError::InvalidInput(_))));
    }

    #[test]
    fn test_accept_welcome_invalid_image_hash_size() {
        let mdk = create_test_mdk();
        let keys = Keys::generate();
        let event_id = EventId::all_zeros();
        let event = UnsignedEvent {
            id: Some(event_id),
            pubkey: keys.public_key(),
            created_at: nostr::Timestamp::now(),
            kind: Kind::Custom(444),
            tags: nostr::Tags::new(),
            content: "test".to_string(),
        };
        let event_json = serde_json::to_string(&event).unwrap();

        let welcome = Welcome {
            id: event_id.to_hex(),
            event_json,
            mls_group_id: hex::encode([0u8; 32]),
            nostr_group_id: hex::encode([0u8; 32]),
            group_name: "Test".to_string(),
            group_description: "Test".to_string(),
            group_image_hash: Some(vec![0u8; 31]), // Wrong size
            group_image_key: None,
            group_image_nonce: None,
            group_admin_pubkeys: vec![keys.public_key().to_hex()],
            group_relays: vec!["wss://relay.example.com".to_string()],
            welcomer: keys.public_key().to_hex(),
            member_count: 0,
            state: "pending".to_string(),
            wrapper_event_id: event_id.to_hex(),
        };

        let result = mdk.accept_welcome(welcome);
        assert!(matches!(result, Err(MdkUniffiError::InvalidInput(_))));
    }

    #[test]
    fn test_decline_welcome_invalid_event_id() {
        let mdk = create_test_mdk();
        let welcome = Welcome {
            id: "invalid_hex".to_string(),
            event_json: "{}".to_string(),
            mls_group_id: hex::encode([0u8; 32]),
            nostr_group_id: hex::encode([0u8; 32]),
            group_name: "Test".to_string(),
            group_description: "Test".to_string(),
            group_image_hash: None,
            group_image_key: None,
            group_image_nonce: None,
            group_admin_pubkeys: vec![],
            group_relays: vec![],
            welcomer: "invalid_hex".to_string(),
            member_count: 0,
            state: "pending".to_string(),
            wrapper_event_id: hex::encode([0u8; 32]),
        };

        let result = mdk.decline_welcome(welcome);
        assert!(matches!(result, Err(MdkUniffiError::InvalidInput(_))));
    }

    #[test]
    fn test_get_relays_nonexistent_group() {
        let mdk = create_test_mdk();
        let fake_group_id = hex::encode([0u8; 32]);
        let result = mdk.get_relays(fake_group_id);
        // Should return error for non-existent group
        assert!(result.is_err());
    }

    #[test]
    fn test_create_group_basic() {
        let mdk = create_test_mdk();
        let creator_keys = Keys::generate();
        let member_keys = Keys::generate();

        let member_pubkey_hex = member_keys.public_key().to_hex();
        let relays = vec!["wss://relay.example.com".to_string()];
        let key_package_result = mdk
            .create_key_package_for_event(member_pubkey_hex.clone(), relays.clone())
            .unwrap();

        let key_package_event =
            EventBuilder::new(Kind::Custom(30443), key_package_result.key_package)
                .tags(
                    key_package_result
                        .tags
                        .iter()
                        .map(|t| Tag::parse(t.clone()).unwrap())
                        .collect::<Vec<_>>(),
                )
                .sign_with_keys(&member_keys)
                .unwrap();

        let key_package_event_json = serde_json::to_string(&key_package_event).unwrap();

        let creator_pubkey_hex = creator_keys.public_key().to_hex();
        let result = mdk.create_group(
            creator_pubkey_hex,
            vec![key_package_event_json],
            "Test Group".to_string(),
            "Test Description".to_string(),
            relays,
            vec![creator_keys.public_key().to_hex()],
        );

        assert!(result.is_ok());
        let create_result = result.unwrap();
        assert_eq!(create_result.group.name, "Test Group");
        assert_eq!(create_result.group.description, "Test Description");
        assert!(!create_result.welcome_rumors_json.is_empty());
    }

    #[test]
    fn test_create_group_invalid_creator_key() {
        let mdk = create_test_mdk();
        let invalid_pubkey = "not_valid_hex".to_string();
        let result = mdk.create_group(
            invalid_pubkey,
            vec![],
            "Test".to_string(),
            "Test".to_string(),
            vec!["wss://relay.example.com".to_string()],
            vec![],
        );
        assert!(matches!(result, Err(MdkUniffiError::InvalidInput(_))));
    }

    #[test]
    fn test_create_group_invalid_admin_key() {
        let mdk = create_test_mdk();
        let creator_keys = Keys::generate();
        let creator_pubkey_hex = creator_keys.public_key().to_hex();
        let result = mdk.create_group(
            creator_pubkey_hex,
            vec![],
            "Test".to_string(),
            "Test".to_string(),
            vec!["wss://relay.example.com".to_string()],
            vec!["not_valid_hex".to_string()],
        );
        assert!(matches!(result, Err(MdkUniffiError::InvalidInput(_))));
    }

    #[test]
    fn test_create_group_invalid_relay() {
        let mdk = create_test_mdk();
        let creator_keys = Keys::generate();
        let creator_pubkey_hex = creator_keys.public_key().to_hex();
        let result = mdk.create_group(
            creator_pubkey_hex,
            vec![],
            "Test".to_string(),
            "Test".to_string(),
            vec!["not_a_valid_url".to_string()],
            vec![],
        );
        assert!(matches!(result, Err(MdkUniffiError::InvalidInput(_))));
    }

    #[test]
    fn test_create_group_invalid_key_package_json() {
        let mdk = create_test_mdk();
        let creator_keys = Keys::generate();
        let creator_pubkey_hex = creator_keys.public_key().to_hex();
        let result = mdk.create_group(
            creator_pubkey_hex,
            vec!["not_valid_json".to_string()],
            "Test".to_string(),
            "Test".to_string(),
            vec!["wss://relay.example.com".to_string()],
            vec![],
        );
        assert!(matches!(result, Err(MdkUniffiError::InvalidInput(_))));
    }

    #[test]
    fn test_add_members_invalid_group_id() {
        let mdk = create_test_mdk();
        let invalid_group_id = "not_valid_hex".to_string();
        let result = mdk.add_members(invalid_group_id, vec![]);
        assert!(matches!(result, Err(MdkUniffiError::InvalidInput(_))));
    }

    #[test]
    fn test_remove_members_invalid_group_id() {
        let mdk = create_test_mdk();
        let invalid_group_id = "not_valid_hex".to_string();
        let result = mdk.remove_members(invalid_group_id, vec![]);
        assert!(matches!(result, Err(MdkUniffiError::InvalidInput(_))));
    }

    #[test]
    fn test_remove_members_invalid_public_key() {
        let mdk = create_test_mdk();
        let fake_group_id = hex::encode([0u8; 32]);
        let result = mdk.remove_members(fake_group_id, vec!["not_valid_hex".to_string()]);
        assert!(matches!(result, Err(MdkUniffiError::InvalidInput(_))));
    }

    #[test]
    fn test_create_message_invalid_group_id() {
        let mdk = create_test_mdk();
        let keys = Keys::generate();
        let invalid_group_id = "not_valid_hex".to_string();
        let result = mdk.create_message(
            invalid_group_id,
            keys.public_key().to_hex(),
            "Hello".to_string(),
            1,
            None,
            None,
        );
        assert!(matches!(result, Err(MdkUniffiError::InvalidInput(_))));
    }

    #[test]
    fn test_create_message_invalid_sender_key() {
        let mdk = create_test_mdk();
        let fake_group_id = hex::encode([0u8; 32]);
        let result = mdk.create_message(
            fake_group_id,
            "not_valid_hex".to_string(),
            "Hello".to_string(),
            1,
            None,
            None,
        );
        assert!(matches!(result, Err(MdkUniffiError::InvalidInput(_))));
    }

    #[test]
    fn test_create_message_with_event_tags() {
        let mdk = create_test_mdk();
        let creator_keys = Keys::generate();
        let member_keys = Keys::generate();

        let member_pubkey_hex = member_keys.public_key().to_hex();
        let relays = vec!["wss://relay.example.com".to_string()];

        let kp_result = mdk
            .create_key_package_for_event(member_pubkey_hex.clone(), relays.clone())
            .unwrap();

        let kp_event = EventBuilder::new(Kind::Custom(443), kp_result.key_package)
            .tags(
                kp_result
                    .tags
                    .into_iter()
                    .map(|t| Tag::parse(&t).unwrap())
                    .collect::<Vec<_>>(),
            )
            .sign_with_keys(&member_keys)
            .unwrap();

        let create_result = mdk
            .create_group(
                creator_keys.public_key().to_hex(),
                vec![kp_event.as_json()],
                "Test Group".to_string(),
                "Test Description".to_string(),
                relays,
                vec![creator_keys.public_key().to_hex()],
            )
            .unwrap();

        mdk.merge_pending_commit(create_result.group.mls_group_id.clone())
            .unwrap();

        let event_json = mdk
            .create_message(
                create_result.group.mls_group_id,
                creator_keys.public_key().to_hex(),
                "Ephemeral update".to_string(),
                1,
                None,
                Some(vec![vec![
                    "expiration".to_string(),
                    "1231006505".to_string(),
                ]]),
            )
            .unwrap();

        let event: Event =
            serde_json::from_str(&event_json).expect("returned JSON should be valid");

        assert!(
            event.tags.iter().any(|t| t.kind() == TagKind::Expiration),
            "Wrapper event must contain the expiration tag"
        );

        let exp_tag = event
            .tags
            .iter()
            .find(|t| t.kind() == TagKind::Expiration)
            .unwrap();
        assert_eq!(
            exp_tag.content().unwrap(),
            "1231006505",
            "Expiration value must match"
        );
    }

    #[test]
    fn test_create_message_with_invalid_event_tag() {
        let mdk = create_test_mdk();
        let keys = Keys::generate();
        let fake_group_id = hex::encode([0u8; 32]);

        let result = mdk.create_message(
            fake_group_id,
            keys.public_key().to_hex(),
            "Hello".to_string(),
            1,
            None,
            Some(vec![vec!["p".to_string(), "abc".to_string()]]),
        );

        assert!(
            matches!(result, Err(MdkUniffiError::InvalidInput(ref msg)) if msg.contains("not allowed")),
            "Disallowed tag should be rejected"
        );
    }

    #[test]
    fn test_process_message_invalid_json() {
        let mdk = create_test_mdk();
        let result = mdk.process_message("not_valid_json".to_string());
        assert!(matches!(result, Err(MdkUniffiError::InvalidInput(_))));
    }

    #[test]
    fn test_update_group_data_invalid_group_id() {
        let mdk = create_test_mdk();
        let invalid_group_id = "not_valid_hex".to_string();
        let update = GroupDataUpdate {
            name: Some("New Name".to_string()),
            description: None,
            image_hash: None,
            image_key: None,
            image_nonce: None,
            relays: None,
            admins: None,
        };
        let result = mdk.update_group_data(invalid_group_id, update);
        assert!(matches!(result, Err(MdkUniffiError::InvalidInput(_))));
    }

    #[test]
    fn test_update_group_data_invalid_relays() {
        let mdk = create_test_mdk();
        let fake_group_id = hex::encode([0u8; 32]);
        let update = GroupDataUpdate {
            name: None,
            description: None,
            image_hash: None,
            image_key: None,
            image_nonce: None,
            relays: Some(vec!["not_a_valid_url".to_string()]),
            admins: None,
        };
        let result = mdk.update_group_data(fake_group_id, update);
        assert!(matches!(result, Err(MdkUniffiError::InvalidInput(_))));
    }

    #[test]
    fn test_update_group_data_invalid_admin() {
        let mdk = create_test_mdk();
        let fake_group_id = hex::encode([0u8; 32]);
        let update = GroupDataUpdate {
            name: None,
            description: None,
            image_hash: None,
            image_key: None,
            image_nonce: None,
            relays: None,
            admins: Some(vec!["not_valid_hex".to_string()]),
        };
        let result = mdk.update_group_data(fake_group_id, update);
        assert!(matches!(result, Err(MdkUniffiError::InvalidInput(_))));
    }

    #[test]
    fn test_vec_to_array_image_key() {
        let vec = Some(vec![0u8; 32]);
        let result = vec_to_array::<32>(vec);
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn test_vec_to_array_image_nonce() {
        let vec = Some(vec![0u8; 12]);
        let result = vec_to_array::<12>(vec);
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn test_vec_to_array_wrong_size() {
        let vec = Some(vec![0u8; 31]); // Wrong size for 32-byte array
        let result = vec_to_array::<32>(vec);
        assert!(matches!(result, Err(MdkUniffiError::InvalidInput(_))));
    }

    #[test]
    fn test_vec_to_array_none() {
        let vec: Option<Vec<u8>> = None;
        let result = vec_to_array::<32>(vec);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_error_conversion_storage() {
        use mdk_sqlite_storage::error::Error as StorageError;
        let storage_err = StorageError::Database("test error".to_string());
        let mdk_err: MdkUniffiError = storage_err.into();
        assert!(matches!(mdk_err, MdkUniffiError::Storage(_)));
    }

    #[test]
    fn test_parse_relay_urls_valid() {
        let valid_urls = vec![
            "wss://relay.example.com".to_string(),
            "wss://another.relay.com".to_string(),
        ];
        let result = parse_relay_urls(&valid_urls);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 2);
    }

    #[test]
    fn test_parse_relay_urls_invalid() {
        let invalid_urls = vec!["not_a_valid_url".to_string()];
        let result = parse_relay_urls(&invalid_urls);
        assert!(matches!(result, Err(MdkUniffiError::InvalidInput(_))));
    }

    #[test]
    fn test_parse_relay_urls_empty() {
        let empty_urls: Vec<String> = vec![];
        let result = parse_relay_urls(&empty_urls);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0);
    }

    #[test]
    fn test_parse_tags_valid() {
        let keys = Keys::generate();
        let event_id =
            EventId::from_hex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
                .unwrap();
        let tags = vec![
            vec!["p".to_string(), keys.public_key().to_hex()],
            vec!["e".to_string(), event_id.to_hex()],
        ];
        let result = parse_tags(tags);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 2);
    }

    #[test]
    fn test_parse_tags_empty() {
        let tags: Vec<Vec<String>> = vec![];
        let result = parse_tags(tags);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0);
    }

    // ── Helpers for multi-party tests ──────────────────────────────────────

    /// Create a two-party group (Alice + Bob) across separate Mdk instances.
    /// Returns (alice_mdk, bob_mdk, group_id, alice_keys, bob_keys).
    fn create_two_party_group() -> (Mdk, Mdk, String, Keys, Keys) {
        let alice_mdk = create_test_mdk();
        let bob_mdk = create_test_mdk();
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();
        let relays = vec!["wss://relay.example.com".to_string()];

        // Bob creates a key package on his own Mdk
        let bob_kp = bob_mdk
            .create_key_package_for_event(bob_keys.public_key().to_hex(), relays.clone())
            .unwrap();
        let bob_kp_event = EventBuilder::new(Kind::MlsKeyPackage, bob_kp.key_package)
            .tags(
                bob_kp
                    .tags
                    .into_iter()
                    .map(|t| Tag::parse(&t).unwrap())
                    .collect::<Vec<_>>(),
            )
            .sign_with_keys(&bob_keys)
            .unwrap();

        // Alice creates the group containing Bob
        let create_result = alice_mdk
            .create_group(
                alice_keys.public_key().to_hex(),
                vec![bob_kp_event.as_json()],
                "Test Group".to_string(),
                "Test Description".to_string(),
                relays,
                vec![alice_keys.public_key().to_hex()],
            )
            .unwrap();

        let group_id = create_result.group.mls_group_id.clone();
        alice_mdk.merge_pending_commit(group_id.clone()).unwrap();

        // Bob joins via welcome
        let welcome = bob_mdk
            .process_welcome(
                EventId::all_zeros().to_hex(),
                create_result.welcome_rumors_json[0].clone(),
            )
            .unwrap();
        bob_mdk.accept_welcome(welcome).unwrap();

        (alice_mdk, bob_mdk, group_id, alice_keys, bob_keys)
    }

    // ── Scenario A: Two-party message processing with context ────────────

    #[test]
    fn test_process_message_with_context_two_party() {
        let (alice_mdk, bob_mdk, group_id, alice_keys, bob_keys) = create_two_party_group();

        // Alice sends a message
        let alice_msg = alice_mdk
            .create_message(
                group_id.clone(),
                alice_keys.public_key().to_hex(),
                "Hello Bob!".to_string(),
                1,
                None,
                None,
            )
            .unwrap();

        // Bob processes Alice's message through the UniFFI boundary
        let outcome = bob_mdk.process_message_with_context(alice_msg).unwrap();

        // Verify the result variant and message content
        let message = match &outcome.result {
            ProcessMessageResult::ApplicationMessage { message } => message,
            other => panic!(
                "Expected ApplicationMessage, got {:?}",
                std::mem::discriminant(other)
            ),
        };
        assert_eq!(message.sender_pubkey, alice_keys.public_key().to_hex());
        // Verify the message content survives the UniFFI boundary
        let event: serde_json::Value = serde_json::from_str(&message.event_json).unwrap();
        assert_eq!(event["content"].as_str().unwrap(), "Hello Bob!");

        // Alice is leaf 0 (group creator)
        assert_eq!(outcome.sender_leaf_index, Some(0));

        // Now Bob sends a message back
        let bob_msg = bob_mdk
            .create_message(
                group_id,
                bob_keys.public_key().to_hex(),
                "Hello Alice!".to_string(),
                1,
                None,
                None,
            )
            .unwrap();

        let outcome = alice_mdk.process_message_with_context(bob_msg).unwrap();

        let message = match &outcome.result {
            ProcessMessageResult::ApplicationMessage { message } => message,
            other => panic!(
                "Expected ApplicationMessage, got {:?}",
                std::mem::discriminant(other)
            ),
        };
        assert_eq!(message.sender_pubkey, bob_keys.public_key().to_hex());
        let event: serde_json::Value = serde_json::from_str(&message.event_json).unwrap();
        assert_eq!(event["content"].as_str().unwrap(), "Hello Alice!");
        // Bob is leaf 1
        assert_eq!(outcome.sender_leaf_index, Some(1));
    }

    // ── Scenario B: Topology inspection ──────────────────────────────────

    #[test]
    fn test_topology_inspection_two_party() {
        let (alice_mdk, bob_mdk, group_id, alice_keys, bob_keys) = create_two_party_group();

        // own_leaf_index: Alice is the creator → leaf 0
        assert_eq!(alice_mdk.own_leaf_index(group_id.clone()).unwrap(), 0);
        // Bob joined second → leaf 1
        assert_eq!(bob_mdk.own_leaf_index(group_id.clone()).unwrap(), 1);

        // group_leaf_map: verify both members at correct indices with correct pubkeys
        let leaf_map = alice_mdk.group_leaf_map(group_id.clone()).unwrap();
        assert_eq!(leaf_map.len(), 2);

        let alice_entry = leaf_map.iter().find(|e| e.leaf_index == 0).unwrap();
        assert_eq!(alice_entry.public_key, alice_keys.public_key().to_hex());

        let bob_entry = leaf_map.iter().find(|e| e.leaf_index == 1).unwrap();
        assert_eq!(bob_entry.public_key, bob_keys.public_key().to_hex());

        // Bob sees the same topology
        let bob_leaf_map = bob_mdk.group_leaf_map(group_id.clone()).unwrap();
        assert_eq!(bob_leaf_map.len(), 2);
        assert_eq!(
            bob_leaf_map
                .iter()
                .find(|e| e.leaf_index == 0)
                .unwrap()
                .public_key,
            alice_keys.public_key().to_hex()
        );

        // get_ratchet_tree_info: verify structure and leaf count
        let tree_info = alice_mdk.get_ratchet_tree_info(group_id.clone()).unwrap();
        assert!(!tree_info.tree_hash.is_empty());
        assert!(!tree_info.serialized_tree.is_empty());
        assert_eq!(tree_info.leaf_nodes.len(), 2);

        // Each leaf node should have non-empty crypto material and a credential
        // identity that corresponds to one of the known group members
        let known_pubkeys: std::collections::HashSet<String> = [
            alice_keys.public_key().to_hex(),
            bob_keys.public_key().to_hex(),
        ]
        .into_iter()
        .collect();

        for node in &tree_info.leaf_nodes {
            assert!(!node.encryption_key.is_empty());
            assert!(!node.signature_key.is_empty());
            assert!(
                known_pubkeys.contains(&node.credential_identity),
                "credential_identity {} doesn't match any known member pubkey",
                node.credential_identity
            );
        }
        // Verify both members are represented (no duplicates, no missing)
        let tree_identities: std::collections::HashSet<&str> = tree_info
            .leaf_nodes
            .iter()
            .map(|n| n.credential_identity.as_str())
            .collect();
        assert_eq!(
            tree_identities.len(),
            2,
            "ratchet tree should contain exactly 2 distinct member identities"
        );

        // pending_member_changes: clean group has no pending proposals.
        // Note: non-empty pending proposals are structurally unreachable through
        // the UniFFI API because MDK always creates commits (not standalone
        // proposals), and SelfRemove proposals are auto-committed by receivers.
        let changes = alice_mdk.pending_member_changes(group_id.clone()).unwrap();
        assert!(changes.additions.is_empty());
        assert!(changes.removals.is_empty());

        assert!(
            alice_mdk
                .pending_added_members_pubkeys(group_id.clone())
                .unwrap()
                .is_empty()
        );
        assert!(
            alice_mdk
                .pending_removed_members_pubkeys(group_id)
                .unwrap()
                .is_empty()
        );
    }

    // ── Scenario C: Key package lifecycle (deletion has observable effect) ─

    #[test]
    fn test_key_package_deletion_prevents_welcome_processing() {
        let alice_mdk = create_test_mdk();
        let bob_mdk = create_test_mdk();
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();
        let relays = vec!["wss://relay.example.com".to_string()];

        // Bob creates a key package
        let bob_kp = bob_mdk
            .create_key_package_for_event(bob_keys.public_key().to_hex(), relays.clone())
            .unwrap();
        let bob_kp_event = EventBuilder::new(Kind::MlsKeyPackage, bob_kp.key_package)
            .tags(
                bob_kp
                    .tags
                    .into_iter()
                    .map(|t| Tag::parse(&t).unwrap())
                    .collect::<Vec<_>>(),
            )
            .sign_with_keys(&bob_keys)
            .unwrap();

        // Delete Bob's key package by hash_ref BEFORE the group is created
        bob_mdk
            .delete_key_package_from_storage_by_hash_ref(bob_kp.hash_ref)
            .unwrap();

        // Alice creates a group referencing Bob's (now-deleted) key package
        let create_result = alice_mdk
            .create_group(
                alice_keys.public_key().to_hex(),
                vec![bob_kp_event.as_json()],
                "Test Group".to_string(),
                "Test Description".to_string(),
                relays,
                vec![alice_keys.public_key().to_hex()],
            )
            .unwrap();
        alice_mdk
            .merge_pending_commit(create_result.group.mls_group_id.clone())
            .unwrap();

        // Bob tries to process the welcome — should fail because the private
        // key material was deleted from storage
        let welcome_result = bob_mdk.process_welcome(
            EventId::all_zeros().to_hex(),
            create_result.welcome_rumors_json[0].clone(),
        );
        assert!(
            welcome_result.is_err(),
            "Welcome should fail after key package deletion, but got: {:?}",
            welcome_result.unwrap().group_name
        );
    }

    #[test]
    fn test_delete_key_package_via_event_prevents_welcome() {
        let alice_mdk = create_test_mdk();
        let bob_mdk = create_test_mdk();
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();
        let relays = vec!["wss://relay.example.com".to_string()];

        // Bob creates a key package
        let bob_kp = bob_mdk
            .create_key_package_for_event(bob_keys.public_key().to_hex(), relays.clone())
            .unwrap();
        let bob_kp_event = EventBuilder::new(Kind::MlsKeyPackage, bob_kp.key_package)
            .tags(
                bob_kp
                    .tags
                    .into_iter()
                    .map(|t| Tag::parse(&t).unwrap())
                    .collect::<Vec<_>>(),
            )
            .sign_with_keys(&bob_keys)
            .unwrap();

        // Delete via event JSON (tests the JSON→Event→KeyPackage parsing path)
        bob_mdk
            .delete_key_package_from_storage(bob_kp_event.as_json())
            .unwrap();

        // Alice creates a group referencing Bob's deleted key package
        let create_result = alice_mdk
            .create_group(
                alice_keys.public_key().to_hex(),
                vec![bob_kp_event.as_json()],
                "Test Group".to_string(),
                "Test Description".to_string(),
                relays,
                vec![alice_keys.public_key().to_hex()],
            )
            .unwrap();
        alice_mdk
            .merge_pending_commit(create_result.group.mls_group_id.clone())
            .unwrap();

        // Bob can't process the welcome — private key material is gone
        let welcome_result = bob_mdk.process_welcome(
            EventId::all_zeros().to_hex(),
            create_result.welcome_rumors_json[0].clone(),
        );
        assert!(
            welcome_result.is_err(),
            "Welcome should fail after event-based key package deletion"
        );
    }

    // ── Scenario D: Group image option mapping ───────────────────────────

    #[test]
    fn test_prepare_group_image_options_mapping() {
        // Minimal valid 1×1 red PNG, hand-assembled from the PNG spec
        let png = build_minimal_png();

        // With blurhash/thumbhash disabled: verify None fields
        let result_no_hashes = prepare_group_image_for_upload_with_options(
            png.clone(),
            "image/png".into(),
            MediaProcessingOptionsInput {
                sanitize_exif: Some(true),
                generate_blurhash: Some(false),
                generate_thumbhash: Some(false),
                max_dimension: None,
                max_file_size: None,
                max_filename_length: None,
            },
        )
        .unwrap();

        assert_eq!(result_no_hashes.mime_type, "image/png");
        assert!(
            result_no_hashes.blurhash.is_none(),
            "blurhash should be None when disabled"
        );
        assert!(
            result_no_hashes.thumbhash.is_none(),
            "thumbhash should be None when disabled"
        );
        assert!(!result_no_hashes.encrypted_data.is_empty());
        assert!(!result_no_hashes.image_key.is_empty());
        assert!(!result_no_hashes.image_nonce.is_empty());
        assert!(result_no_hashes.encrypted_size > 0);
        assert!(result_no_hashes.original_size > 0);

        // Dimensions should be 1×1
        let dims = result_no_hashes
            .dimensions
            .expect("dimensions should be present for a valid PNG");
        assert_eq!(dims.width, 1);
        assert_eq!(dims.height, 1);

        // With thumbhash enabled: verify it's populated
        let result_with_thumbhash = prepare_group_image_for_upload_with_options(
            png,
            "image/png".into(),
            MediaProcessingOptionsInput {
                sanitize_exif: Some(true),
                generate_blurhash: Some(false),
                generate_thumbhash: Some(true),
                max_dimension: None,
                max_file_size: None,
                max_filename_length: None,
            },
        )
        .unwrap();

        assert!(
            result_with_thumbhash.thumbhash.is_some(),
            "thumbhash should be present when enabled"
        );

        // Both calls should produce different encrypted data (different random keys)
        assert_ne!(
            result_no_hashes.encrypted_data, result_with_thumbhash.encrypted_data,
            "each call should use fresh encryption keys"
        );
    }

    /// Build a minimal valid 1×1 red PNG from raw bytes.
    fn build_minimal_png() -> Vec<u8> {
        fn crc32(data: &[u8]) -> u32 {
            let mut crc: u32 = 0xFFFF_FFFF;
            for &b in data {
                crc ^= b as u32;
                for _ in 0..8 {
                    crc = if crc & 1 != 0 {
                        (crc >> 1) ^ 0xEDB8_8320
                    } else {
                        crc >> 1
                    };
                }
            }
            !crc
        }
        fn adler32(data: &[u8]) -> u32 {
            let (mut a, mut b): (u32, u32) = (1, 0);
            for &byte in data {
                a = (a + byte as u32) % 65521;
                b = (b + a) % 65521;
            }
            (b << 16) | a
        }

        let mut v = Vec::new();
        v.extend_from_slice(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]);
        // IHDR
        let ihdr: [u8; 13] = [0, 0, 0, 1, 0, 0, 0, 1, 8, 2, 0, 0, 0];
        v.extend_from_slice(&(ihdr.len() as u32).to_be_bytes());
        v.extend_from_slice(b"IHDR");
        v.extend_from_slice(&ihdr);
        let mut buf = Vec::from(&b"IHDR"[..]);
        buf.extend_from_slice(&ihdr);
        v.extend_from_slice(&crc32(&buf).to_be_bytes());
        // IDAT
        let row: [u8; 4] = [0x00, 0xFF, 0x00, 0x00];
        let adler = adler32(&row);
        let mut zlib = Vec::new();
        zlib.extend_from_slice(&[0x78, 0x01, 0x01]);
        zlib.extend_from_slice(&(row.len() as u16).to_le_bytes());
        zlib.extend_from_slice(&(!(row.len() as u16)).to_le_bytes());
        zlib.extend_from_slice(&row);
        zlib.extend_from_slice(&adler.to_be_bytes());
        v.extend_from_slice(&(zlib.len() as u32).to_be_bytes());
        v.extend_from_slice(b"IDAT");
        v.extend_from_slice(&zlib);
        let mut buf = Vec::from(&b"IDAT"[..]);
        buf.extend_from_slice(&zlib);
        v.extend_from_slice(&crc32(&buf).to_be_bytes());
        // IEND
        v.extend_from_slice(&0u32.to_be_bytes());
        v.extend_from_slice(b"IEND");
        v.extend_from_slice(&crc32(b"IEND").to_be_bytes());
        v
    }

    // ── MIP-04 encrypted media tests ─────────────────────────────────────────

    #[cfg(feature = "mip04")]
    mod mip04 {
        use nostr::{EventBuilder, Keys, Kind, Tag};

        use super::*;

        /// Small binary test payload — used as a stand-in for any file type that
        /// does NOT trigger image-specific metadata extraction (we use application/octet-stream).
        const TEST_PAYLOAD: &[u8] = b"hello encrypted media round-trip test payload";

        fn create_test_group(mdk: &Mdk) -> String {
            let creator_keys = Keys::generate();
            let member_keys = Keys::generate();
            let relays = vec!["wss://relay.example.com".to_string()];

            let key_package_result = mdk
                .create_key_package_for_event(member_keys.public_key().to_hex(), relays.clone())
                .unwrap();

            let key_package_event =
                EventBuilder::new(Kind::Custom(30443), key_package_result.key_package)
                    .tags(
                        key_package_result
                            .tags
                            .iter()
                            .map(|t| Tag::parse(t.clone()).unwrap())
                            .collect::<Vec<_>>(),
                    )
                    .sign_with_keys(&member_keys)
                    .unwrap();

            let result = mdk
                .create_group(
                    creator_keys.public_key().to_hex(),
                    vec![serde_json::to_string(&key_package_event).unwrap()],
                    "Test Group".to_string(),
                    "Test Description".to_string(),
                    relays,
                    vec![creator_keys.public_key().to_hex()],
                )
                .unwrap();

            result.group.mls_group_id
        }

        #[test]
        fn test_decrypt_media_invalid_nonce_length() {
            let mdk = create_test_mdk();
            let group_id = create_test_group(&mdk);

            let bad_reference = MediaReferenceRecord {
                url: "https://blossom.example.com/abc.jpg".to_string(),
                original_hash: vec![0u8; 32],
                mime_type: "image/jpeg".to_string(),
                filename: "test.jpg".to_string(),
                dimensions: None,
                scheme_version: "mip04-v2".to_string(),
                nonce: vec![0u8; 8], // wrong length — should be 12
            };

            let result = mdk.decrypt_media_from_download(group_id, vec![0u8; 64], bad_reference);
            assert!(matches!(result, Err(MdkUniffiError::InvalidInput(_))));
        }

        #[test]
        fn test_encrypt_media_for_upload_returns_encrypted_data() {
            let mdk = create_test_mdk();
            let group_id = create_test_group(&mdk);

            let result = mdk.encrypt_media_for_upload(
                group_id,
                TEST_PAYLOAD.to_vec(),
                "application/octet-stream".to_string(),
                "test.bin".to_string(),
            );

            assert!(
                result.is_ok(),
                "encrypt_media_for_upload failed: {result:?}"
            );
            let upload = result.unwrap();
            assert!(!upload.encrypted_data.is_empty());
            assert_eq!(upload.original_hash.len(), 32);
            assert_eq!(upload.encrypted_hash.len(), 32);
            assert_eq!(upload.nonce.len(), 12);
            assert_eq!(upload.mime_type, "application/octet-stream");
            assert_eq!(upload.filename, "test.bin");
        }

        #[test]
        fn test_encrypt_decrypt_round_trip() {
            let mdk = create_test_mdk();
            let group_id = create_test_group(&mdk);

            let upload = mdk
                .encrypt_media_for_upload(
                    group_id.clone(),
                    TEST_PAYLOAD.to_vec(),
                    "application/octet-stream".to_string(),
                    "payload.bin".to_string(),
                )
                .unwrap();

            // Build a MediaReferenceRecord directly from the upload result
            let reference = MediaReferenceRecord {
                url: "https://blossom.example.com/abc123.bin".to_string(),
                original_hash: upload.original_hash.clone(),
                mime_type: upload.mime_type.clone(),
                filename: upload.filename.clone(),
                dimensions: upload.dimensions.clone(),
                scheme_version: "mip04-v2".to_string(),
                nonce: upload.nonce.clone(),
            };

            let decrypted = mdk
                .decrypt_media_from_download(group_id, upload.encrypted_data.clone(), reference)
                .unwrap();

            // Decrypted data must not be empty and must not equal the ciphertext
            assert!(!decrypted.is_empty());
            assert_ne!(decrypted, upload.encrypted_data);
            assert_eq!(decrypted, TEST_PAYLOAD);
        }

        #[test]
        fn test_create_and_parse_imeta_tag_round_trip() {
            let mdk = create_test_mdk();
            let group_id = create_test_group(&mdk);

            let upload = mdk
                .encrypt_media_for_upload(
                    group_id.clone(),
                    TEST_PAYLOAD.to_vec(),
                    "application/octet-stream".to_string(),
                    "payload.bin".to_string(),
                )
                .unwrap();

            let uploaded_url = "https://blossom.example.com/abc123.bin".to_string();
            let imeta_tag = mdk
                .create_media_imeta_tag(group_id.clone(), upload.clone(), uploaded_url.clone())
                .unwrap();

            assert_eq!(imeta_tag.len(), 1, "Expected exactly one tag");
            let tag_inner = &imeta_tag[0];
            assert_eq!(tag_inner[0], "imeta");

            // Round-trip: parse the tag back into a MediaReferenceRecord
            let reference = mdk
                .parse_media_imeta_tag(group_id.clone(), imeta_tag)
                .unwrap();

            assert_eq!(reference.url, uploaded_url);
            assert_eq!(reference.mime_type, "application/octet-stream");
            assert_eq!(reference.filename, "payload.bin");
            assert_eq!(reference.original_hash, upload.original_hash);
            assert_eq!(reference.nonce, upload.nonce);
            assert_eq!(reference.scheme_version, "mip04-v2");
        }

        #[test]
        fn test_encrypt_with_options_no_preview_hashes() {
            let mdk = create_test_mdk();
            let group_id = create_test_group(&mdk);

            let options = MediaProcessingOptionsInput {
                sanitize_exif: Some(true),
                generate_blurhash: Some(false),
                generate_thumbhash: Some(false),
                max_dimension: None,
                max_file_size: None,
                max_filename_length: None,
            };

            let result = mdk.encrypt_media_for_upload_with_options(
                group_id,
                TEST_PAYLOAD.to_vec(),
                "application/octet-stream".to_string(),
                "test.bin".to_string(),
                options,
            );

            assert!(result.is_ok(), "{result:?}");
            let upload = result.unwrap();
            assert!(
                upload.blurhash.is_none(),
                "Expected no blurhash when generate_blurhash = false"
            );
            assert!(
                upload.thumbhash.is_none(),
                "Expected no thumbhash when generate_thumbhash = false"
            );
        }

        #[test]
        fn test_encrypt_media_invalid_group_id() {
            let mdk = create_test_mdk();
            let result = mdk.encrypt_media_for_upload(
                "not_valid_hex".to_string(),
                TEST_PAYLOAD.to_vec(),
                "application/octet-stream".to_string(),
                "test.bin".to_string(),
            );
            assert!(matches!(result, Err(MdkUniffiError::InvalidInput(_))));
        }
    }
}
