//! Migration 0142: small state shared with this account's other devices
//! (mdk#2628 item 4.3).
//!
//! - `small_state_items`: one row per chat and item (`read`, `pin`, `mute`,
//!   `archive`), holding the account's winning value as this device knows it.
//!   A chat is its MLS group id, and rows outlive the chat's `account_groups`
//!   row: a chat this device joins later starts from them.
//!   - `read` rows hold a read position (`read_epoch`, `read_at`,
//!     `read_message_id_hex`) and no version.
//!   - `pin`, `mute` and `archive` rows hold `version`, a 16-byte `change_id`
//!     and the value: `flag` (pinned, muted, archived) and, for a mute,
//!     `mute_until` in seconds (NULL while muted until unmuted).
//!   - `observed` is this device's own state of the item as it last saw it,
//!     after applying the row's value; NULL until the value is applied to a
//!     chat this device holds. A local state that no longer matches it is a
//!     change the user made here.
//!   - `unsent` is 1 while this device still owes its siblings the value.
//! - `small_state_sync`: at most one row, written when this device starts to
//!   take part in small state. `snapshot_owed` is 1 while this device still
//!   has to ask its siblings for snapshots.
//! - `small_state_snapshot_requests`: one row per sibling (`to_slot`) whose
//!   whole snapshot this device still needs. `request` is the random id of
//!   the latest request to it and `asked_at` when, in seconds; NULL in both
//!   asks at once.
//! - `small_state_snapshot_parts`: the parts of the answer to a request merged
//!   so far, by the answer's number of parts.
//!
//! No rows are seeded.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE small_state_items (
            group_id_hex TEXT NOT NULL,
            item TEXT NOT NULL CHECK(item IN ('read', 'pin', 'mute', 'archive')),
            version INTEGER CHECK(version IS NULL OR version >= 1),
            change_id BLOB CHECK(change_id IS NULL OR length(change_id) = 16),
            flag INTEGER CHECK(flag IS NULL OR flag IN (0, 1)),
            mute_until INTEGER CHECK(mute_until IS NULL OR mute_until >= 0),
            read_epoch INTEGER CHECK(read_epoch IS NULL OR read_epoch >= 0),
            read_at INTEGER CHECK(read_at IS NULL OR read_at >= 0),
            read_message_id_hex TEXT,
            observed TEXT,
            unsent INTEGER NOT NULL CHECK(unsent IN (0, 1)),
            updated_at INTEGER NOT NULL CHECK(updated_at >= 0),
            PRIMARY KEY (group_id_hex, item),
            CHECK(
                (item = 'read'
                    AND version IS NULL AND change_id IS NULL AND flag IS NULL
                    AND mute_until IS NULL
                    AND read_epoch IS NOT NULL AND read_at IS NOT NULL
                    AND read_message_id_hex IS NOT NULL)
                OR (item != 'read'
                    AND version IS NOT NULL AND change_id IS NOT NULL AND flag IS NOT NULL
                    AND read_epoch IS NULL AND read_at IS NULL
                    AND read_message_id_hex IS NULL
                    AND (item = 'mute' OR mute_until IS NULL))
            )
        ) WITHOUT ROWID;

        CREATE INDEX idx_small_state_items_unsent
            ON small_state_items (unsent) WHERE unsent = 1;

        CREATE TABLE small_state_sync (
            id INTEGER PRIMARY KEY CHECK(id = 1),
            started_at INTEGER NOT NULL CHECK(started_at >= 0),
            snapshot_owed INTEGER NOT NULL CHECK(snapshot_owed IN (0, 1))
        );

        CREATE TABLE small_state_snapshot_requests (
            to_slot BLOB PRIMARY KEY CHECK(length(to_slot) = 32),
            request BLOB UNIQUE CHECK(request IS NULL OR length(request) = 16),
            asked_at INTEGER CHECK(asked_at IS NULL OR asked_at >= 0)
        ) WITHOUT ROWID;

        CREATE TABLE small_state_snapshot_parts (
            request BLOB NOT NULL REFERENCES small_state_snapshot_requests (request)
                ON DELETE CASCADE,
            parts INTEGER NOT NULL CHECK(parts >= 1),
            part INTEGER NOT NULL CHECK(part >= 1 AND part <= parts),
            PRIMARY KEY (request, parts, part)
        ) WITHOUT ROWID;",
    )
    .storage()
}
