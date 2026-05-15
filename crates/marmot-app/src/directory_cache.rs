use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, params};

use crate::{AppError, DirectoryEntry};

pub(crate) struct DirectoryCache {
    conn: Connection,
}

impl DirectoryCache {
    pub(crate) fn open(path: PathBuf) -> Result<Self, AppError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS directory_entries (
                account_id_hex TEXT PRIMARY KEY NOT NULL,
                entry_json TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            );",
        )?;
        Ok(Self { conn })
    }

    pub(crate) fn entry(&self, account_id_hex: &str) -> Result<Option<DirectoryEntry>, AppError> {
        self.conn
            .query_row(
                "SELECT entry_json FROM directory_entries WHERE account_id_hex = ?1",
                [account_id_hex],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .map(|json| serde_json::from_str(&json).map_err(AppError::from))
            .transpose()
    }

    pub(crate) fn entries(&self) -> Result<Vec<DirectoryEntry>, AppError> {
        let mut statement = self.conn.prepare(
            "SELECT entry_json FROM directory_entries
             ORDER BY account_id_hex",
        )?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        let mut entries = Vec::new();
        for row in rows {
            entries.push(serde_json::from_str(&row?)?);
        }
        Ok(entries)
    }

    pub(crate) fn put(&self, entry: &DirectoryEntry) -> Result<(), AppError> {
        self.conn.execute(
            "INSERT INTO directory_entries (account_id_hex, entry_json, updated_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(account_id_hex) DO UPDATE SET
                entry_json = excluded.entry_json,
                updated_at = excluded.updated_at",
            params![
                &entry.account_id_hex,
                serde_json::to_string(entry)?,
                unix_now_seconds() as i64
            ],
        )?;
        Ok(())
    }
}

fn unix_now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
