//! Database utilities for SQLite storage.

use std::collections::BTreeSet;
use std::io::{Error as IoError, ErrorKind};
use std::str::FromStr;

use mdk_storage_traits::GroupId;
use mdk_storage_traits::groups::types::{
    Group, GroupExporterSecret, GroupRelay, GroupState, SelfUpdateState,
};
use mdk_storage_traits::messages::types::{
    Message, MessageState, ProcessedMessage, ProcessedMessageState,
};
use mdk_storage_traits::welcomes::types::{ProcessedWelcome, Welcome, WelcomeState};
use nostr::{EventId, JsonUtil, Kind, PublicKey, RelayUrl, Tags, Timestamp, UnsignedEvent};
use rusqlite::types::{FromSql, FromSqlError, FromSqlResult, ToSql, ToSqlOutput, Type, ValueRef};
use rusqlite::{Error, Result as SqliteResult, Row};

/// Generates a fixed-size byte array newtype with `From`, `ToSql`, and `FromSql` impls.
macro_rules! sqlite_blob_newtype {
    ($name:ident, $len:expr) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $name([u8; $len]);

        impl From<[u8; $len]> for $name {
            fn from(arr: [u8; $len]) -> Self {
                Self(arr)
            }
        }

        impl From<$name> for [u8; $len] {
            fn from(val: $name) -> Self {
                val.0
            }
        }

        impl ToSql for $name {
            fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
                Ok(ToSqlOutput::from(self.0.as_slice()))
            }
        }

        impl FromSql for $name {
            fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
                match value {
                    ValueRef::Blob(blob) => {
                        if blob.len() == $len {
                            let mut arr = [0u8; $len];
                            arr.copy_from_slice(blob);
                            Ok(Self(arr))
                        } else {
                            Err(FromSqlError::InvalidBlobSize {
                                expected_size: $len,
                                blob_size: blob.len(),
                            })
                        }
                    }
                    _ => Err(FromSqlError::InvalidType),
                }
            }
        }
    };
}

sqlite_blob_newtype!(Hash32, 32);
sqlite_blob_newtype!(Nonce12, 12);

#[inline]
fn map_to_text_boxed_error<T>(e: T) -> Error
where
    T: std::error::Error + Send + Sync + 'static,
{
    Error::FromSqlConversionFailure(0, Type::Text, Box::new(e))
}

#[inline]
fn map_invalid_text_data(msg: &str) -> Error {
    Error::FromSqlConversionFailure(
        0,
        Type::Text,
        Box::new(IoError::new(ErrorKind::InvalidData, msg)),
    )
}

#[inline]
fn map_invalid_blob_data(msg: &str) -> Error {
    Error::FromSqlConversionFailure(
        0,
        Type::Blob,
        Box::new(IoError::new(ErrorKind::InvalidData, msg)),
    )
}

// ============================================================================
// Row extraction helpers
// ============================================================================

/// Extract a `GroupId` from a blob column.
fn blob_to_group_id(row: &Row, col: &str) -> SqliteResult<GroupId> {
    Ok(GroupId::from_slice(row.get_ref(col)?.as_blob()?))
}

/// Extract an `EventId` from a blob column.
fn blob_to_event_id(row: &Row, col: &str, label: &str) -> SqliteResult<EventId> {
    let blob = row.get_ref(col)?.as_blob()?;
    EventId::from_slice(blob).map_err(|_| map_invalid_blob_data(label))
}

/// Extract an optional `EventId` from a nullable blob column.
fn blob_to_optional_event_id(row: &Row, col: &str, label: &str) -> SqliteResult<Option<EventId>> {
    match row.get_ref(col)?.as_blob_or_null()? {
        Some(blob) => Ok(Some(
            EventId::from_slice(blob).map_err(|_| map_invalid_blob_data(label))?,
        )),
        None => Ok(None),
    }
}

/// Extract a `PublicKey` from a blob column.
fn blob_to_pubkey(row: &Row, col: &str, label: &str) -> SqliteResult<PublicKey> {
    let blob = row.get_ref(col)?.as_blob()?;
    PublicKey::from_slice(blob).map_err(|_| map_invalid_blob_data(label))
}

/// Parse a text column via `FromStr` with a standard "Invalid state" error.
fn text_to_state<T: FromStr>(row: &Row, col: &str) -> SqliteResult<T> {
    let s = row.get_ref(col)?.as_str()?;
    T::from_str(s).map_err(|_| map_invalid_text_data("Invalid state"))
}

/// Deserialize a JSON text column via serde.
fn text_to_json<T: serde::de::DeserializeOwned>(row: &Row, col: &str) -> SqliteResult<T> {
    let s = row.get_ref(col)?.as_str()?;
    serde_json::from_str(s).map_err(map_to_text_boxed_error)
}

/// Parse a text column via a custom parser function.
fn text_to_parsed<T, E>(
    row: &Row,
    col: &str,
    parser: impl FnOnce(&str) -> Result<T, E>,
) -> SqliteResult<T>
where
    E: std::error::Error + Send + Sync + 'static,
{
    let s = row.get_ref(col)?.as_str()?;
    parser(s).map_err(map_to_text_boxed_error)
}

/// Convert a row to a Group struct
pub fn row_to_group(row: &Row) -> SqliteResult<Group> {
    let mls_group_id = blob_to_group_id(row, "mls_group_id")?;
    let nostr_group_id: [u8; 32] = row.get("nostr_group_id")?;
    let name: String = row.get("name")?;
    let description: String = row.get("description")?;
    let image_hash: Option<[u8; 32]> = row
        .get::<_, Option<Hash32>>("image_hash")?
        .map(|h| h.into());
    let image_key: Option<mdk_storage_traits::Secret<[u8; 32]>> = row
        .get::<_, Option<Hash32>>("image_key")?
        .map(|h| mdk_storage_traits::Secret::new(h.into()));
    let image_nonce: Option<mdk_storage_traits::Secret<[u8; 12]>> = row
        .get::<_, Option<Nonce12>>("image_nonce")?
        .map(|n| mdk_storage_traits::Secret::new(n.into()));
    let admin_pubkeys: BTreeSet<PublicKey> = text_to_json(row, "admin_pubkeys")?;
    let last_message_id =
        blob_to_optional_event_id(row, "last_message_id", "Invalid last message ID")?;
    let last_message_at: Option<Timestamp> = row
        .get::<_, Option<u64>>("last_message_at")?
        .map(Timestamp::from_secs);
    let last_message_processed_at: Option<Timestamp> = row
        .get::<_, Option<u64>>("last_message_processed_at")?
        .map(Timestamp::from_secs);
    let state: GroupState = text_to_state(row, "state")?;
    let epoch: u64 = row.get("epoch")?;
    let self_update_state = match row.get::<_, u64>("last_self_update_at")? {
        0 => SelfUpdateState::Required,
        ts => SelfUpdateState::CompletedAt(Timestamp::from_secs(ts)),
    };
    let disappearing_message_secs: Option<u64> = row.get("disappearing_message_secs")?;

    Ok(Group {
        mls_group_id,
        nostr_group_id,
        name,
        description,
        admin_pubkeys,
        last_message_id,
        last_message_at,
        last_message_processed_at,
        epoch,
        state,
        image_hash,
        image_key,
        image_nonce,
        self_update_state,
        disappearing_message_secs,
    })
}

/// Convert a row to a GroupRelay struct
pub fn row_to_group_relay(row: &Row) -> SqliteResult<GroupRelay> {
    Ok(GroupRelay {
        mls_group_id: blob_to_group_id(row, "mls_group_id")?,
        relay_url: text_to_parsed(row, "relay_url", RelayUrl::parse)?,
    })
}

/// Convert a row to a GroupExporterSecret struct
pub fn row_to_group_exporter_secret(row: &Row) -> SqliteResult<GroupExporterSecret> {
    Ok(GroupExporterSecret {
        mls_group_id: blob_to_group_id(row, "mls_group_id")?,
        epoch: row.get("epoch")?,
        secret: mdk_storage_traits::Secret::new(row.get("secret")?),
    })
}

/// Convert a row to a Message struct
pub fn row_to_message(row: &Row) -> SqliteResult<Message> {
    let id = blob_to_event_id(row, "id", "Invalid event ID")?;
    let pubkey = blob_to_pubkey(row, "pubkey", "Invalid public key")?;
    let kind = Kind::from(row.get::<_, u16>("kind")?);
    let mls_group_id = blob_to_group_id(row, "mls_group_id")?;
    let created_at_value: u64 = row.get("created_at")?;
    // processed_at may be NULL for rows created before the migration
    let processed_at_value: Option<u64> = row.get("processed_at")?;
    let content: String = row.get("content")?;
    let tags: Tags = text_to_json(row, "tags")?;
    let event = text_to_parsed(row, "event", |s| UnsignedEvent::from_json(s))?;
    let wrapper_event_id = blob_to_event_id(row, "wrapper_event_id", "Invalid wrapper event ID")?;
    let epoch: Option<u64> = row.get("epoch")?;
    let state: MessageState = text_to_state(row, "state")?;

    let created_at = Timestamp::from(created_at_value);
    // Fall back to created_at if processed_at is NULL (for backward compatibility)
    let processed_at = Timestamp::from(processed_at_value.unwrap_or(created_at_value));

    Ok(Message {
        id,
        pubkey,
        kind,
        mls_group_id,
        created_at,
        processed_at,
        content,
        tags,
        event,
        wrapper_event_id,
        epoch,
        state,
    })
}

/// Convert a row to a ProcessedMessage struct
pub fn row_to_processed_message(row: &Row) -> SqliteResult<ProcessedMessage> {
    let wrapper_event_id = blob_to_event_id(row, "wrapper_event_id", "Invalid wrapper event ID")?;
    let message_event_id =
        blob_to_optional_event_id(row, "message_event_id", "Invalid message event ID")?;
    let processed_at = Timestamp::from_secs(row.get("processed_at")?);
    let epoch: Option<u64> = row.get("epoch")?;
    let mls_group_id: Option<GroupId> = row
        .get_ref("mls_group_id")?
        .as_blob_or_null()?
        .map(GroupId::from_slice);
    let state: ProcessedMessageState = text_to_state(row, "state")?;
    let failure_reason: Option<String> = row.get("failure_reason")?;

    Ok(ProcessedMessage {
        wrapper_event_id,
        message_event_id,
        processed_at,
        epoch,
        mls_group_id,
        state,
        failure_reason,
    })
}

/// Convert a row to a Welcome struct
pub fn row_to_welcome(row: &Row) -> SqliteResult<Welcome> {
    let id = blob_to_event_id(row, "id", "Invalid event ID")?;
    let event = text_to_parsed(row, "event", |s| UnsignedEvent::from_json(s))?;
    let mls_group_id = blob_to_group_id(row, "mls_group_id")?;
    let nostr_group_id: [u8; 32] = row.get("nostr_group_id")?;
    let group_name: String = row.get("group_name")?;
    let group_description: String = row.get("group_description")?;
    let group_image_hash: Option<[u8; 32]> = row
        .get::<_, Option<Hash32>>("group_image_hash")?
        .map(|h| h.into());
    let group_image_key: Option<mdk_storage_traits::Secret<[u8; 32]>> = row
        .get::<_, Option<Hash32>>("group_image_key")?
        .map(|h| mdk_storage_traits::Secret::new(h.into()));
    let group_image_nonce: Option<mdk_storage_traits::Secret<[u8; 12]>> = row
        .get::<_, Option<Nonce12>>("group_image_nonce")?
        .map(|n| mdk_storage_traits::Secret::new(n.into()));
    let group_admin_pubkeys: BTreeSet<PublicKey> = text_to_json(row, "group_admin_pubkeys")?;
    let group_relays: BTreeSet<RelayUrl> = text_to_json(row, "group_relays")?;
    let welcomer = blob_to_pubkey(row, "welcomer", "Invalid welcomer public key")?;
    let member_count: u64 = row.get("member_count")?;
    let state: WelcomeState = text_to_state(row, "state")?;
    let wrapper_event_id = blob_to_event_id(row, "wrapper_event_id", "Invalid wrapper event ID")?;

    Ok(Welcome {
        id,
        event,
        mls_group_id,
        nostr_group_id,
        group_name,
        group_description,
        group_image_hash,
        group_image_key,
        group_image_nonce,
        group_admin_pubkeys,
        group_relays,
        welcomer,
        member_count: member_count as u32,
        state,
        wrapper_event_id,
    })
}

/// Convert a row to a ProcessedWelcome struct
pub fn row_to_processed_welcome(row: &Row) -> SqliteResult<ProcessedWelcome> {
    Ok(ProcessedWelcome {
        wrapper_event_id: blob_to_event_id(row, "wrapper_event_id", "Invalid wrapper event ID")?,
        welcome_event_id: blob_to_optional_event_id(
            row,
            "welcome_event_id",
            "Invalid welcome event ID",
        )?,
        processed_at: Timestamp::from_secs(row.get("processed_at")?),
        state: text_to_state(row, "state")?,
        failure_reason: row.get("failure_reason")?,
    })
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;

    use super::*;

    /// Helper to create a test database with the groups table schema
    fn create_test_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE groups (
                mls_group_id BLOB PRIMARY KEY,
                nostr_group_id BLOB NOT NULL,
                name TEXT NOT NULL,
                description TEXT NOT NULL,
                image_hash BLOB,
                image_key BLOB,
                image_nonce BLOB,
                admin_pubkeys TEXT NOT NULL,
                last_message_id BLOB,
                last_message_at INTEGER,
                last_message_processed_at INTEGER,
                epoch INTEGER NOT NULL,
                state TEXT NOT NULL,
                last_self_update_at INTEGER NOT NULL DEFAULT 0,
                disappearing_message_secs INTEGER
            )",
        )
        .unwrap();
        conn
    }

    #[test]
    fn test_row_to_group_with_valid_last_message_id() {
        let conn = create_test_db();

        // A valid EventId is 32 bytes
        let valid_event_id = [0xabu8; 32];

        conn.execute(
            "INSERT INTO groups VALUES (?, ?, ?, ?, NULL, NULL, NULL, ?, ?, NULL, NULL, ?, ?, 0, NULL)",
            rusqlite::params![
                &[1u8, 2, 3, 4][..], // mls_group_id
                &[0u8; 32][..],      // nostr_group_id
                "Test Group",        // name
                "Description",       // description
                "[]",                // admin_pubkeys (empty JSON array)
                &valid_event_id[..], // last_message_id (valid 32-byte blob)
                0i64,                // epoch
                "active",            // state
            ],
        )
        .unwrap();

        let mut stmt = conn.prepare("SELECT * FROM groups").unwrap();
        let result = stmt.query_row([], row_to_group);

        assert!(result.is_ok());
        let group = result.unwrap();
        assert!(group.last_message_id.is_some());
    }

    #[test]
    fn test_row_to_group_with_null_last_message_id() {
        let conn = create_test_db();

        conn.execute(
            "INSERT INTO groups VALUES (?, ?, ?, ?, NULL, NULL, NULL, ?, NULL, NULL, NULL, ?, ?, 0, NULL)",
            rusqlite::params![
                &[1u8, 2, 3, 4][..], // mls_group_id
                &[0u8; 32][..],      // nostr_group_id
                "Test Group",        // name
                "Description",       // description
                "[]",                // admin_pubkeys (empty JSON array)
                0i64,                // epoch
                "active",            // state
            ],
        )
        .unwrap();

        let mut stmt = conn.prepare("SELECT * FROM groups").unwrap();
        let result = stmt.query_row([], row_to_group);

        assert!(result.is_ok());
        let group = result.unwrap();
        assert!(group.last_message_id.is_none());
    }

    #[test]
    fn test_row_to_group_with_invalid_last_message_id_length() {
        let conn = create_test_db();

        // An invalid EventId - wrong length (16 bytes instead of 32)
        let invalid_event_id = [0xabu8; 16];

        conn.execute(
            "INSERT INTO groups VALUES (?, ?, ?, ?, NULL, NULL, NULL, ?, ?, NULL, NULL, ?, ?, 0, NULL)",
            rusqlite::params![
                &[1u8, 2, 3, 4][..],   // mls_group_id
                &[0u8; 32][..],        // nostr_group_id
                "Test Group",          // name
                "Description",         // description
                "[]",                  // admin_pubkeys (empty JSON array)
                &invalid_event_id[..], // last_message_id (invalid 16-byte blob)
                0i64,                  // epoch
                "active",              // state
            ],
        )
        .unwrap();

        let mut stmt = conn.prepare("SELECT * FROM groups").unwrap();
        let result = stmt.query_row([], row_to_group);

        // Should fail with an error, not silently return None
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("Invalid last message ID"),
            "Expected error message to contain 'Invalid last message ID', got: {}",
            err
        );
    }

    #[test]
    fn test_row_to_group_with_empty_last_message_id_blob() {
        let conn = create_test_db();

        // An empty blob is also invalid for EventId
        let empty_blob: [u8; 0] = [];

        conn.execute(
            "INSERT INTO groups VALUES (?, ?, ?, ?, NULL, NULL, NULL, ?, ?, NULL, NULL, ?, ?, 0, NULL)",
            rusqlite::params![
                &[1u8, 2, 3, 4][..], // mls_group_id
                &[0u8; 32][..],      // nostr_group_id
                "Test Group",        // name
                "Description",       // description
                "[]",                // admin_pubkeys (empty JSON array)
                &empty_blob[..],     // last_message_id (empty blob)
                0i64,                // epoch
                "active",            // state
            ],
        )
        .unwrap();

        let mut stmt = conn.prepare("SELECT * FROM groups").unwrap();
        let result = stmt.query_row([], row_to_group);

        // Should fail with an error, not silently return None
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("Invalid last message ID"),
            "Expected error message to contain 'Invalid last message ID', got: {}",
            err
        );
    }
}
