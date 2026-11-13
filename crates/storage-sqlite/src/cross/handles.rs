//! The one place that turns the account handle into the app handle.

use crate::{SqliteAccountStorage, SqliteAppStorage, SqliteResultExt};
use cgka_traits::storage::{StorageError, StorageResult};
use rusqlite::{Connection, functions::FunctionFlags};
use std::borrow::Cow;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, LazyLock, Mutex, Weak,
    atomic::{AtomicU64, Ordering},
};

static NOTIFICATION_REVISIONS: LazyLock<Mutex<HashMap<PathBuf, Weak<AtomicU64>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// The canonical path of `conn`'s main database, which every connection to
/// that file in this process shares; `None` for an in-memory database.
pub(crate) fn database_file(conn: &Connection) -> StorageResult<Option<PathBuf>> {
    let path = match conn.path() {
        Some(path) => Cow::Borrowed(Path::new(path)),
        None => {
            // path() rejects non-UTF-8 Unix filenames; SQLite retains their bytes.
            let filename: Vec<u8> = conn
                .query_row(
                    "SELECT CAST(file AS BLOB) FROM pragma_database_list WHERE name = 'main'",
                    [],
                    |row| row.get(0),
                )
                .storage()?;
            #[cfg(unix)]
            let path = {
                use std::os::unix::ffi::OsStringExt;
                PathBuf::from(std::ffi::OsString::from_vec(filename))
            };
            #[cfg(not(unix))]
            let path = PathBuf::from(
                String::from_utf8(filename)
                    .map_err(|_| StorageError::Backend("invalid database filename".into()))?,
            );
            Cow::Owned(path)
        }
    };
    if path.as_os_str().is_empty() {
        return Ok(None);
    }
    path.canonicalize()
        .map(Some)
        .map_err(|error| StorageError::Backend(format!("database identity: {error}")))
}

fn database_revision(conn: &Connection) -> StorageResult<Arc<AtomicU64>> {
    let Some(path) = database_file(conn)? else {
        return Ok(Arc::new(AtomicU64::new(0)));
    };
    let mut revisions = NOTIFICATION_REVISIONS
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    revisions.retain(|_, revision| revision.strong_count() > 0);
    if let Some(revision) = revisions.get(&path).and_then(Weak::upgrade) {
        return Ok(revision);
    }
    let revision = Arc::new(AtomicU64::new(0));
    revisions.insert(path, Arc::downgrade(&revision));
    Ok(revision)
}

pub(crate) fn notification_counter(conn: &Connection) -> StorageResult<Arc<AtomicU64>> {
    let revision = database_revision(conn)?;
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
