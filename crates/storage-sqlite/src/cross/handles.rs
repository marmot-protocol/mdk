//! The one place that turns the account handle into the app handle.

use crate::{SqliteAccountStorage, SqliteAppStorage, SqliteResultExt};
use cgka_traits::storage::StorageResult;
use rusqlite::{Connection, functions::FunctionFlags};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

pub(crate) fn notification_counter(conn: &Connection) -> StorageResult<Arc<AtomicU64>> {
    let revision = Arc::new(AtomicU64::new(0));
    let counter = revision.clone();
    conn.create_scalar_function(
        "marmot_notification_changed",
        0,
        FunctionFlags::SQLITE_UTF8,
        move |_| {
            counter.fetch_add(1, Ordering::Release);
            Ok(0i64)
        },
    )
    .storage()?;
    conn.execute_batch(
        "CREATE TEMP TRIGGER notification_group_insert AFTER INSERT ON main.account_groups
         BEGIN SELECT marmot_notification_changed(); END;
         CREATE TEMP TRIGGER notification_group_update AFTER UPDATE ON main.account_groups
         BEGIN SELECT marmot_notification_changed(); END;
         CREATE TEMP TRIGGER notification_group_delete AFTER DELETE ON main.account_groups
         BEGIN SELECT marmot_notification_changed(); END;
         CREATE TEMP TRIGGER notification_policy_insert AFTER INSERT ON main.notification_settings
         BEGIN SELECT marmot_notification_changed(); END;
         CREATE TEMP TRIGGER notification_policy_update AFTER UPDATE ON main.notification_settings
         WHEN OLD.account_label IS NOT NEW.account_label
           OR OLD.account_id_hex IS NOT NEW.account_id_hex
           OR OLD.local_notifications_enabled IS NOT NEW.local_notifications_enabled
           OR OLD.native_push_enabled IS NOT NEW.native_push_enabled
         BEGIN SELECT marmot_notification_changed(); END;
         CREATE TEMP TRIGGER notification_policy_delete AFTER DELETE ON main.notification_settings
         BEGIN SELECT marmot_notification_changed(); END;
         CREATE TEMP TRIGGER notification_mute_insert AFTER INSERT ON main.chat_notification_settings
         BEGIN SELECT marmot_notification_changed(); END;
         CREATE TEMP TRIGGER notification_mute_update AFTER UPDATE ON main.chat_notification_settings
         WHEN OLD.group_id_hex IS NOT NEW.group_id_hex
           OR OLD.muted_until_ms IS NOT NEW.muted_until_ms
         BEGIN SELECT marmot_notification_changed(); END;
         CREATE TEMP TRIGGER notification_mute_delete AFTER DELETE ON main.chat_notification_settings
         BEGIN SELECT marmot_notification_changed(); END;",
    ).storage()?;
    Ok(revision)
}

impl SqliteAccountStorage {
    /// The app side's handle on this account database, over the same
    /// connection: it opens nothing and closes with this storage.
    pub fn app_storage(&self) -> SqliteAppStorage {
        SqliteAppStorage {
            connection: self.connection.clone(),
            notification_revision: self.notification_revision.clone(),
        }
    }
}
