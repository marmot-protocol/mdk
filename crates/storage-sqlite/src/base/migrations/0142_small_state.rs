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
//!   take part in small state. `broadcast_at` is when this device last sent
//!   every item it holds, in seconds, and `broadcast_tip` the device group's
//!   tip epoch then; NULL in both before its first broadcast.
//!   `request_owed` is 1 while it still has to ask its siblings to broadcast,
//!   and `answer_owed` is 1 when a sibling asked it to since its last
//!   broadcast.
//! - `device_group_messages`: the kind of each device-group message this
//!   device sent or read whose withdrawal a feature acts on, since the
//!   engine's withdrawal names only its message id: an own send's transport
//!   id, a received message's content id. One row per device group and app
//!   event id; `message_id_hex` is NULL until an own send's transport id is
//!   known. `recorded_at` is in seconds; rows
//!   go after a week, and only the newest 4,096 stay.
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
            broadcast_at INTEGER CHECK(broadcast_at IS NULL OR broadcast_at >= 0),
            broadcast_tip INTEGER CHECK(broadcast_tip IS NULL OR broadcast_tip >= 0),
            request_owed INTEGER NOT NULL CHECK(request_owed IN (0, 1)),
            answer_owed INTEGER NOT NULL CHECK(answer_owed IN (0, 1)),
            CHECK((broadcast_at IS NULL) = (broadcast_tip IS NULL))
        );

        CREATE TABLE device_group_messages (
            group_id_hex TEXT NOT NULL,
            app_event_id TEXT NOT NULL,
            message_id_hex TEXT,
            kind INTEGER NOT NULL CHECK(kind >= 0),
            recorded_at INTEGER NOT NULL CHECK(recorded_at >= 0),
            PRIMARY KEY (group_id_hex, app_event_id)
        );

        CREATE INDEX idx_device_group_messages_message
            ON device_group_messages (group_id_hex, message_id_hex);",
    )
    .storage()
}
