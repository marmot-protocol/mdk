//! Bounded account-side application and durable restart positions. No shared-store locks here.
use super::*;

#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatPresentationActivePeer {
    pub member_id_hex: String,
    pub revision: u64,
    pub after_group: Option<String>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatPresentationCatchUp {
    pub shared_epoch: Vec<u8>,
    pub revision: u64,
    pub active: Option<ChatPresentationActivePeer>,
    pub reconciling: bool,
    pub reconcile_after: Option<String>,
}
impl Default for ChatPresentationCatchUp {
    fn default() -> Self {
        Self {
            shared_epoch: Vec::new(),
            revision: 0,
            active: None,
            reconciling: true,
            reconcile_after: None,
        }
    }
}
#[derive(Clone)]
pub struct ChatPresentationCheckpoint {
    pub generation: u64,
    pub state: ChatPresentationCatchUp,
}
impl SqliteAccountStorage {
    pub fn chat_presentation_checkpoint(&self) -> StorageResult<ChatPresentationCheckpoint> {
        let conn = self.lock()?;
        let (generation, bytes): (i64, Option<Vec<u8>>) = conn
            .query_row(
                "SELECT generation,state FROM chat_presentation_checkpoint WHERE id=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .storage()?;
        let state = bytes
            .map(|bytes| {
                serde_json::from_slice(&bytes)
                    .map_err(|_| invalid("invalid presentation checkpoint"))
            })
            .transpose()?
            .unwrap_or_default();
        Ok(ChatPresentationCheckpoint {
            generation: generation as u64,
            state,
        })
    }
    /// The checkpoint and up to 50 selected rows commit together.
    /// Returns true only if the checkpoint state or a row advanced. A rejected
    /// checkpoint CAS or an entirely stale/unchanged batch returns false so the
    /// caller can wait for a later wakeup instead of spinning without progress.
    pub fn commit_chat_presentation_batch(
        &self,
        expected: &ChatPresentationCheckpoint,
        next: &ChatPresentationCatchUp,
        values: &[(ChatPresentationInput, StoredChatPresentation)],
    ) -> StorageResult<bool> {
        if values.len() > CHAT_PRESENTATION_BATCH_LIMIT {
            return Err(invalid("oversized presentation batch"));
        }
        self.connection.with_transaction(|| {
            let current = self.chat_presentation_checkpoint()?;
            if current.generation != expected.generation || current.state != expected.state {
                return Ok(false);
            }
            // Prevent pre-reset work from moving a checkpoint back to a previous directory incarnation.
            for (_, value) in values {
                if value.profile_version.as_ref().is_some_and(|v| v.store_epoch != next.shared_epoch) {
                    return Err(invalid("presentation batch directory epoch mismatch"));
                }
            }
            let state_changed = current.state != *next;
            if state_changed {
                let conn = self.lock()?;
                conn.execute(
                    "UPDATE chat_presentation_checkpoint SET generation=generation+1,state=?1 WHERE id=1",
                    [serialize(next)?],
                ).storage()?;
            }
            // Stale source rows remain on the pending worklist; they must not hold up unrelated fanout.
            let mut applied = false;
            for (input, value) in values {
                applied |= self.store_chat_presentation(input, value)? == ChatPresentationWrite::Applied;
            }
            if applied && !state_changed {
                self.lock()?.execute(
                    "UPDATE chat_presentation_checkpoint SET generation=generation+1 WHERE id=1", [],
                ).storage()?;
            }
            Ok(state_changed || applied)
        })
    }
    pub fn chat_presentation_inputs_after(
        &self,
        after: Option<&str>,
    ) -> StorageResult<Vec<ChatPresentationInput>> {
        self.connection.with_transaction(|| {
            let groups = {
                let conn = self.lock()?;
                let mut query = conn
                    .prepare_cached(
                        "SELECT group_id_hex FROM chat_list_rows WHERE group_id_hex>?1
                     ORDER BY group_id_hex LIMIT ?2",
                    )
                    .storage()?;
                query
                    .query_map(
                        params![after.unwrap_or(""), CHAT_PRESENTATION_BATCH_LIMIT as i64],
                        |row| row.get::<_, String>(0),
                    )
                    .storage()?
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .storage()?
            };
            groups
                .iter()
                .map(|group| {
                    self.chat_presentation_input(group)?
                        .ok_or_else(|| invalid("presentation row disappeared"))
                })
                .collect()
        })
    }

    /// Refresh and complete one queued initialization in the same transaction.
    /// Returns false if another operation already completed or removed the work.
    /// Tolerates queued work overlapping an existing row without depending on
    /// the INSERT-only completion trigger, including unexpected recovery state.
    pub fn initialize_chat_presentation_row(
        &self,
        local_account_id_hex: &str,
        group_id_hex: &str,
        mention_classifier: &crate::chat_list::MentionClassifier<'_>,
    ) -> StorageResult<bool> {
        self.connection.with_transaction(|| {
            let queued = || -> StorageResult<bool> {
                self.lock()?.query_row(
                    "SELECT EXISTS(SELECT 1 FROM chat_presentation_row_work WHERE group_id_hex=?1)",
                    [group_id_hex], |row| row.get(0),
                ).storage()
            };
            if !queued()? {
                return Ok(false);
            }
            self.refresh_chat_list_row(local_account_id_hex, group_id_hex, mention_classifier)?;
            self.lock()?
                .execute_cached(
                    "DELETE FROM chat_presentation_row_work WHERE group_id_hex=?1",
                    [group_id_hex],
                )
                .storage()?;
            if queued()? {
                return Err(invalid("presentation initialization did not complete"));
            }
            Ok(true)
        })
    }

    /// Read at most one bounded page of groups needing legacy row initialization.
    /// A queued group may already have a chat row; initialization also handles upserts.
    pub fn pending_chat_presentation_rows(&self) -> StorageResult<Vec<String>> {
        let conn = self.lock()?;
        let mut q = conn.prepare_cached(
            "SELECT group_id_hex FROM chat_presentation_row_work ORDER BY group_id_hex LIMIT ?1",
        ).storage()?;
        q.query_map([CHAT_PRESENTATION_BATCH_LIMIT as i64], |r| {
            r.get::<_, String>(0)
        })
        .storage()?
        .collect::<rusqlite::Result<Vec<_>>>()
        .storage()
    }
}
