//! The local-forget wipe: one transaction that deletes a group's app data and,
//! when the engine forgets the group, its engine rows and forget marker. A
//! local delete must be atomic, so it spans both sides. `GroupStorage`'s
//! `forget_group_local` (protocol) and `delete_local_group_data` (app) both
//! call it.

use crate::app::account_projection::{
    SECURE_DELETE_LOCAL_GROUP_OPERATION, combine_secure_delete_operation_and_restore,
    finish_secure_delete_checkpoint_intent, merge_local_group_delete_intent_tx,
    restore_secure_delete_pragma, secure_delete_pragma,
};
use crate::base::connection::CachedSql;
use crate::{
    SqliteAccountStorage, SqliteResultExt, app::account_projection::DeleteLocalGroupDataResult,
    app::encrypted_media_secrets::retire_all_encrypted_media_secrets_for_group_tx,
    base::connection::retry_on_busy, u64_to_i64,
};
use cgka_traits::storage::{StorageError, StorageResult};
use rusqlite::{OptionalExtension, TransactionBehavior, params};

impl SqliteAccountStorage {
    /// Transactionally removes all app-local data for one group without touching
    /// the stored MLS/OpenMLS group state. This is the storage primitive for the
    /// local delete/wipe UX: it drops the chat-list/account projection, plaintext
    /// app events, timeline rows, agent-stream start projection rows, cached
    /// encrypted-media epoch secrets, and group push-token rows keyed by
    /// `group_id_hex`. A metadata-only media-secret retirement barrier remains
    /// because protocol/MLS state is intentionally retained; without it that
    /// state could immediately rederive wiped key bytes. `seen_events` and
    /// protocol/MLS tables are left intact for active groups. A durable local
    /// deletion frontier distinguishes the intentionally absent projection from
    /// a torn write, suppressing historical relay replay while allowing a
    /// causally newer chat message to re-create it. A terminal group is
    /// different: its live MLS state is already erased, so this transaction also
    /// removes the full `cgka_groups` row and retains only
    /// `cgka_disband_tombstones` as the permanent anti-resurrection guard. The
    /// logical wipe and a durable WAL checkpoint intent commit together under
    /// `secure_delete = ON`. If `wal_checkpoint(TRUNCATE)` is blocked by a reader,
    /// the committed result is returned with `erasure_pending`; a retry recovers
    /// the accumulated result from the intent and attempts truncation again.
    pub fn delete_local_group_data(
        &self,
        group_id_hex: &str,
    ) -> StorageResult<DeleteLocalGroupDataResult> {
        self.delete_local_group_data_inner(group_id_hex, None)
    }

    pub(crate) fn forget_group_local_data(
        &self,
        group_id_hex: &str,
        at: cgka_traits::Timestamp,
    ) -> StorageResult<bool> {
        use cgka_traits::storage::GroupStorage;
        let id = cgka_traits::GroupId::new(
            hex::decode(group_id_hex)
                .map_err(|_| StorageError::Serialization("invalid local group id".into()))?,
        );
        let already_forgotten = self.is_group_forgotten(&id)?;
        self.delete_local_group_data_inner(group_id_hex, Some(at))?;
        Ok(!already_forgotten)
    }

    pub(crate) fn delete_local_group_data_inner(
        &self,
        group_id_hex: &str,
        forgotten_at: Option<cgka_traits::Timestamp>,
    ) -> StorageResult<DeleteLocalGroupDataResult> {
        let forget = forgotten_at.is_some();
        if group_id_hex.trim().is_empty() {
            return Err(StorageError::Backend(
                "local group delete id must not be empty".to_owned(),
            ));
        }
        let group_id = hex::decode(group_id_hex).map_err(|error| {
            StorageError::Serialization(format!("invalid local group id: {error}"))
        })?;

        let newly_deleted = retry_on_busy(|| {
            let mut conn = self.lock()?;
            let original = secure_delete_pragma(&conn)?;
            conn.execute_batch("PRAGMA secure_delete = ON;").storage()?;
            let delete_result = (|| {
                let tx = conn
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .storage()?;
                let mut deleted =
                    retire_all_encrypted_media_secrets_for_group_tx(&tx, group_id_hex)?;
                let prior_nostr_routes_json = tx
                    .query_row_cached(
                        "SELECT prior_nostr_routes_json
                         FROM account_groups
                         WHERE group_id_hex = ?1",
                        params![group_id_hex],
                        |row| row.get::<_, String>(0),
                    )
                    .optional()
                    .storage()?
                    .unwrap_or_else(|| "[]".to_owned());
                deleted = deleted.saturating_add(
                    tx.execute_cached(
                        "DELETE FROM pending_application_events WHERE group_id = ?1",
                        params![&group_id],
                    )
                    .storage()?,
                );
                for table in [
                    "app_events",
                    "message_timeline",
                    "agent_stream_starts",
                    "conversation_read_state",
                    "chat_list_rows",
                    "account_group_app_components",
                    "group_push_tokens",
                    "group_push_token_tombstones",
                    "pending_push_registration_shares",
                    "chat_notification_settings",
                    "encrypted_media_epoch_secret_references",
                    "encrypted_media_epoch_secrets",
                    "account_groups",
                ] {
                    deleted = deleted.saturating_add(
                        tx.execute_cached(
                            &format!("DELETE FROM {table} WHERE group_id_hex = ?1"),
                            params![group_id_hex],
                        )
                        .storage()?,
                    );
                }
                let (terminal, active, message_insert_order) = tx
                    .query_row_cached(
                        "SELECT
                            EXISTS(SELECT 1 FROM cgka_disband_tombstones WHERE group_id = ?1),
                            EXISTS(SELECT 1 FROM cgka_groups WHERE id = ?1),
                            COALESCE(
                                (SELECT MAX(insert_order) FROM cgka_messages WHERE group_id = ?1),
                                0
                            )",
                        params![&group_id],
                        |row| {
                            Ok((
                                row.get::<_, i64>(0)? != 0,
                                row.get::<_, i64>(1)? != 0,
                                row.get::<_, i64>(2)?,
                            ))
                        },
                    )
                    .storage()?;
                if active && !terminal && !forget {
                    tx.execute_cached(
                        "INSERT INTO local_group_deletion_frontiers (
                            group_id_hex, message_insert_order, prior_nostr_routes_json
                         ) VALUES (?1, ?2, ?3)
                         ON CONFLICT(group_id_hex) DO UPDATE SET
                            message_insert_order = MAX(
                                local_group_deletion_frontiers.message_insert_order,
                                excluded.message_insert_order
                            ),
                            prior_nostr_routes_json = CASE
                                WHEN excluded.prior_nostr_routes_json = '[]'
                                    THEN local_group_deletion_frontiers.prior_nostr_routes_json
                                ELSE excluded.prior_nostr_routes_json
                            END",
                        params![
                            hex::encode(&group_id),
                            message_insert_order,
                            prior_nostr_routes_json
                        ],
                    )
                    .storage()?;
                }
                if terminal && !forget {
                    tx.execute_cached(
                        "DELETE FROM local_group_deletion_frontiers WHERE group_id_hex = ?1",
                        params![hex::encode(&group_id)],
                    )
                    .storage()?;
                    deleted = deleted.saturating_add(
                        tx.execute_cached(
                            "DELETE FROM cgka_groups WHERE id = ?1",
                            params![&group_id],
                        )
                        .storage()?,
                    );
                }
                if let Some(at) = forgotten_at {
                    deleted += tx.execute_cached(
                        "INSERT INTO locally_forgotten_groups(group_id, forgotten_at, awaiting_welcome)
                         VALUES (?1, ?2, 1) ON CONFLICT(group_id) DO UPDATE SET
                         forgotten_at = MAX(locally_forgotten_groups.forgotten_at, excluded.forgotten_at),
                         awaiting_welcome = 1 WHERE locally_forgotten_groups.awaiting_welcome = 0",
                        params![&group_id, u64_to_i64(at.0)?],
                    ).storage()?;
                    crate::protocol::storage::groups::delete_group_tx(
                        &tx,
                        &cgka_traits::GroupId::new(group_id.clone()),
                    )?;
                    for table in ["cgka_welcomes", "cgka_disband_tombstones"] {
                        tx.execute_cached(
                            &format!("DELETE FROM {table} WHERE group_id = ?1"),
                            params![&group_id],
                        )
                        .storage()?;
                    }
                    for table in [
                        "local_group_deletion_frontiers",
                        "app_pending_welcome_delivery",
                        "pending_push_registration_removals",
                        "app_prepared_group_image_upload",
                        "message_drafts",
                        "chat_pin_positions",
                    ] {
                        tx.execute_cached(
                            &format!("DELETE FROM {table} WHERE group_id_hex = ?1"),
                            params![group_id_hex],
                        )
                        .storage()?;
                    }
                    self.connection.note_openmls_write();
                }
                if deleted > 0 {
                    merge_local_group_delete_intent_tx(&tx, group_id_hex, deleted)?;
                }
                tx.commit().storage()?;
                Ok(deleted)
            })();
            let restore = restore_secure_delete_pragma(&conn, original);
            combine_secure_delete_operation_and_restore(delete_result, restore)
        })?;

        let finish = match finish_secure_delete_checkpoint_intent::<DeleteLocalGroupDataResult>(
            &self.app_storage(),
            SECURE_DELETE_LOCAL_GROUP_OPERATION,
            group_id_hex,
        ) {
            Ok(finish) => finish,
            Err(_) => {
                // The logical deletion and its checkpoint intent committed before
                // this best-effort finish step. Report that committed outcome and
                // leave the durable intent for a later retry instead of inviting
                // the caller to restore projection state that was already erased.
                tracing::warn!(
                    target: "storage_sqlite::cross::wipe",
                    method = "delete_local_group_data",
                    "secure-delete checkpoint cleanup remains pending after committed local deletion"
                );
                return Ok(DeleteLocalGroupDataResult {
                    deleted_rows: newly_deleted,
                    completed_pending_checkpoint: false,
                    erasure_pending: true,
                });
            }
        };
        match finish.result {
            Some(mut result) => {
                result.completed_pending_checkpoint =
                    newly_deleted == 0 && result.deleted_rows > 0 && !finish.erasure_pending;
                result.erasure_pending = finish.erasure_pending;
                Ok(result)
            }
            // Another process may have checkpointed and consumed this intent
            // after our logical deletion committed. In that case erasure is
            // complete, and this caller must still report its locally known
            // deletion instead of incorrectly returning "nothing existed".
            None => Ok(DeleteLocalGroupDataResult {
                deleted_rows: newly_deleted,
                completed_pending_checkpoint: false,
                erasure_pending: false,
            }),
        }
    }
}
