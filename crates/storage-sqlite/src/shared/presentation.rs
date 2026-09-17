//! Snapshot accepted profile bytes and their local revision under one shared-store transaction.
use super::{SharedSqliteResultExt, SqliteSharedStorage};
use crate::{CHAT_PRESENTATION_BATCH_LIMIT, ChatPresentationVersion, u64_to_i64};
use cgka_traits::storage::StorageResult;
use rusqlite::params;

#[derive(Clone)]
pub struct DirectoryPresentation {
    pub member_id_hex: String,
    pub profile_json: Option<String>,
    pub version: ChatPresentationVersion,
}
#[derive(Clone)]
pub struct DirectoryPresentationChanges {
    pub head: ChatPresentationVersion,
    pub changes: Vec<DirectoryPresentation>,
}
fn version(conn: &rusqlite::Connection) -> StorageResult<ChatPresentationVersion> {
    conn.query_row(
        "SELECT store_epoch, revision FROM directory_presentation_meta WHERE id=1",
        [],
        |r| {
            Ok(ChatPresentationVersion {
                store_epoch: r.get(0)?,
                revision: r.get::<_, i64>(1)? as u64,
            })
        },
    )
    .storage()
}
impl SqliteSharedStorage {
    pub fn directory_presentation_version(&self) -> StorageResult<ChatPresentationVersion> {
        let conn = self.lock()?;
        version(&conn)
    }
    pub fn directory_presentation(&self, member: &str) -> StorageResult<DirectoryPresentation> {
        let conn = self.lock()?;
        conn.prepare_cached(
            "SELECT m.store_epoch, COALESCE(c.revision, 0), u.profile_json
             FROM directory_presentation_meta m
             LEFT JOIN directory_presentation_changes c ON c.member_id_hex=?1
             LEFT JOIN directory_users u ON u.account_id_hex=?1
             WHERE m.id=1",
        )
        .storage()?
        .query_row([member], |r| {
            Ok(DirectoryPresentation {
                member_id_hex: member.to_owned(),
                profile_json: r.get(2)?,
                version: ChatPresentationVersion {
                    store_epoch: r.get(0)?,
                    revision: r.get::<_, i64>(1)? as u64,
                },
            })
        })
        .storage()
    }
    pub fn directory_presentation_changes(
        &self,
        after: u64,
    ) -> StorageResult<DirectoryPresentationChanges> {
        let mut conn = self.lock()?;
        let tx = conn.transaction().storage()?;
        let head = version(&tx)?;
        let changes = {
            let mut stmt = tx.prepare_cached("SELECT c.member_id_hex, c.revision, u.profile_json
                FROM directory_presentation_changes c LEFT JOIN directory_users u ON u.account_id_hex=c.member_id_hex
                WHERE c.revision>?1 AND c.revision<=?2 ORDER BY c.revision LIMIT ?3").storage()?;
            stmt.query_map(
                params![
                    u64_to_i64(after)?,
                    u64_to_i64(head.revision)?,
                    CHAT_PRESENTATION_BATCH_LIMIT as i64
                ],
                |r| {
                    Ok(DirectoryPresentation {
                        member_id_hex: r.get(0)?,
                        profile_json: r.get(2)?,
                        version: ChatPresentationVersion {
                            store_epoch: head.store_epoch.clone(),
                            revision: r.get::<_, i64>(1)? as u64,
                        },
                    })
                },
            )
            .storage()?
            .collect::<rusqlite::Result<Vec<_>>>()
            .storage()?
        };
        tx.commit().storage()?;
        Ok(DirectoryPresentationChanges { head, changes })
    }
}

#[cfg(test)]
mod tests {
    use crate::SqliteSharedStorage;
    #[test]
    fn missing_profile_keeps_epoch() {
        let store = SqliteSharedStorage::in_memory().unwrap();
        store
            .put_public_directory_user(&record("other", "Other"))
            .unwrap();
        let missing = store.directory_presentation("missing").unwrap();
        assert_eq!(missing.member_id_hex, "missing");
        assert!(missing.profile_json.is_none());
        assert_eq!(missing.version.revision, 0);
        assert_eq!(
            missing.version.store_epoch,
            store.directory_presentation_version().unwrap().store_epoch
        );
    }

    #[test]
    fn profile_read_is_one_statement() {
        use rusqlite::trace::{TraceEvent, TraceEventCodes};
        use std::cell::Cell;
        thread_local! { static QUERIES: Cell<usize> = const { Cell::new(0) }; }
        fn trace(event: TraceEvent<'_>) {
            if matches!(event, TraceEvent::Stmt(..)) {
                QUERIES.with(|count| count.set(count.get() + 1));
            }
        }
        let store = SqliteSharedStorage::in_memory().unwrap();
        store
            .put_public_directory_user(&record("aa", "Alice"))
            .unwrap();
        store
            .lock()
            .unwrap()
            .trace_v2(TraceEventCodes::SQLITE_TRACE_STMT, Some(trace));
        QUERIES.with(|count| count.set(0));
        let profile = store.directory_presentation("aa").unwrap();
        store
            .lock()
            .unwrap()
            .trace_v2(TraceEventCodes::empty(), None);
        assert_eq!(profile.profile_json, record("aa", "Alice").profile_json);
        assert_eq!(QUERIES.with(Cell::get), 1);
    }
    #[test]
    fn accepted_profile_changes_have_a_durable_revision_domain() {
        let store = SqliteSharedStorage::in_memory().unwrap();
        let exists: bool = store.lock().unwrap().query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name = 'directory_presentation_changes')", [], |r| r.get(0)).unwrap();
        assert!(
            exists,
            "accepted profiles need a durable coalesced change index"
        );
    }
    fn record(member: &str, name: &str) -> crate::PublicDirectoryUserRecord {
        crate::PublicDirectoryUserRecord {
            account_id_hex: member.into(),
            npub: "fixture".into(),
            profile_json: Some(format!("{{\"name\":\"{name}\"}}")),
            relay_lists_json: "{}".into(),
            key_package_json: None,
            event_id_hex: None,
            event_kind: None,
            event_created_at: None,
            follows: vec![],
        }
    }
    #[test]
    fn writes_coalesce_and_raw_import_removal_and_rollback_share_the_revision() {
        let store = SqliteSharedStorage::in_memory().unwrap();
        let first = record("aa", "First");
        store.put_public_directory_user(&first).unwrap();
        let v = store.directory_presentation_version().unwrap();
        store.put_public_directory_user(&first).unwrap();
        let mut metadata_only = first.clone();
        metadata_only.profile_json=Some(r#"{"name":"First","about":"changed","source_relays":["wss://relay.example"],"created_at":99}"#.into());
        store.put_public_directory_user(&metadata_only).unwrap();
        assert_eq!(store.directory_presentation_version().unwrap(), v);
        store
            .put_public_directory_user(&record("aa", "Second"))
            .unwrap();
        let changes = store.directory_presentation_changes(0).unwrap();
        assert_eq!(changes.changes.len(), 1);
        assert_eq!(
            changes.changes[0].profile_json,
            record("aa", "Second").profile_json
        );
        assert!(changes.changes[0].version.revision > v.revision);
        let v = store.directory_presentation_version().unwrap();
        store
            .lock()
            .unwrap()
            .execute_batch("BEGIN; UPDATE directory_users SET profile_json=NULL; ROLLBACK;")
            .unwrap();
        assert_eq!(store.directory_presentation_version().unwrap(), v);
        store
            .lock()
            .unwrap()
            .execute("DELETE FROM directory_users WHERE account_id_hex='aa'", [])
            .unwrap();
        let deletion = store.directory_presentation_changes(v.revision).unwrap();
        assert_eq!(deletion.changes.len(), 1);
        assert!(deletion.changes[0].profile_json.is_none());
        assert!(
            store
                .directory_presentation("aa")
                .unwrap()
                .profile_json
                .is_none()
        );
    }
    #[test]
    fn bounded_changes_and_epoch_survive_reopen() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("shared.db");
        let store = SqliteSharedStorage::open(&path).unwrap();
        for i in 0..65 {
            store
                .put_public_directory_user(&record(&format!("{i:04x}"), "Profile"))
                .unwrap();
        }
        let version = store.directory_presentation_version().unwrap();
        let batch = store.directory_presentation_changes(0).unwrap();
        assert_eq!(batch.changes.len(), 50);
        drop(store);
        let store = SqliteSharedStorage::open(&path).unwrap();
        assert_eq!(store.directory_presentation_version().unwrap(), version);
        assert_eq!(
            store
                .directory_presentation_changes(batch.changes.last().unwrap().version.revision)
                .unwrap()
                .changes
                .len(),
            15
        );
        assert_ne!(
            SqliteSharedStorage::in_memory()
                .unwrap()
                .directory_presentation_version()
                .unwrap()
                .store_epoch,
            version.store_epoch
        );
    }
}
