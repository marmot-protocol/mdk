//! The relays that refused this device's confirmed commits (mdk#2333). See
//! migration 0206. The table is outside every snapshot, so rewinding a group
//! neither drops nor restores a refusal; its rows go with the group's
//! `cgka_groups` row.
//!
//! Inherent methods for the session's own storage handle, not a storage
//! trait: the engine never reads or writes refusals.

use crate::base::connection::{CachedSql, retry_on_busy};
use crate::{SqliteAccountStorage, SqliteResultExt, deserialize, serialize};
use cgka_traits::maintenance::CommitRefusal;
use cgka_traits::storage::{OutboundFanoutStorage, StorageResult};
use cgka_traits::types::{GroupId, MessageId};
use rusqlite::{OptionalExtension, params};

impl SqliteAccountStorage {
    /// Every stored refusal record in the account.
    pub fn commit_refusals(&self) -> StorageResult<Vec<CommitRefusal>> {
        self.read_commit_refusals("SELECT record FROM cgka_commit_refusals", params![])
    }

    /// The group's stored refusal records.
    fn commit_refusals_for_group(&self, group_id: &GroupId) -> StorageResult<Vec<CommitRefusal>> {
        self.read_commit_refusals(
            "SELECT record FROM cgka_commit_refusals WHERE group_id = ?1",
            params![group_id.as_slice()],
        )
    }

    /// Merge `refusal`'s relays into the stored record for its commit,
    /// creating the record when there is none. An existing record keeps its
    /// `acknowledged` flag and every relay it already lists.
    pub fn merge_commit_refusal(&self, refusal: &CommitRefusal) -> StorageResult<()> {
        self.connection
            .with_savepoint(|| self.merge_commit_refusal_in_transaction(refusal))
    }

    /// Delete the frozen fanout `fanout_id`, first merging `refusal` into its
    /// commit's record, in one transaction. An acknowledged record goes with
    /// the fanout: nothing can merge into it any more.
    pub fn retire_outbound_fanout(
        &self,
        fanout_id: &MessageId,
        refusal: Option<&CommitRefusal>,
    ) -> StorageResult<()> {
        self.connection.with_savepoint(|| {
            if let Some(refusal) = refusal {
                self.merge_commit_refusal_in_transaction(refusal)?;
            }
            self.delete_outbound_fanout(fanout_id)?;
            let acknowledged = self
                .commit_refusal(fanout_id)?
                .is_some_and(|stored| stored.acknowledged);
            if acknowledged {
                self.delete_commit_refusal(fanout_id)?;
            }
            Ok(())
        })
    }

    /// Acknowledge every refusal record of the group, in one transaction. A
    /// record whose fanout is gone is deleted; one whose fanout remains is
    /// kept, marked, so a later refusal of the same commit does not warn again.
    pub fn acknowledge_commit_refusals(&self, group_id: &GroupId) -> StorageResult<()> {
        self.connection.with_savepoint(|| {
            for mut refusal in self.commit_refusals_for_group(group_id)? {
                if self.outbound_fanout(&refusal.fanout_id)?.is_none() {
                    self.delete_commit_refusal(&refusal.fanout_id)?;
                } else if !refusal.acknowledged {
                    refusal.acknowledged = true;
                    self.write_commit_refusal(&refusal)?;
                }
            }
            Ok(())
        })
    }

    /// Delete one commit's refusal record.
    pub fn delete_commit_refusal(&self, fanout_id: &MessageId) -> StorageResult<()> {
        let delete = || {
            self.lock()?
                .execute_cached(
                    "DELETE FROM cgka_commit_refusals WHERE fanout_id = ?1",
                    params![fanout_id.as_slice()],
                )
                .storage()
        };
        if self.connection.is_current_thread_transaction_owner() {
            delete()?;
        } else {
            retry_on_busy(delete)?;
        }
        Ok(())
    }

    fn merge_commit_refusal_in_transaction(&self, refusal: &CommitRefusal) -> StorageResult<()> {
        match self.commit_refusal(&refusal.fanout_id)? {
            None => self.write_commit_refusal(refusal),
            Some(mut stored) => {
                if stored.merge(refusal.refused.iter().cloned()) {
                    self.write_commit_refusal(&stored)?;
                }
                Ok(())
            }
        }
    }

    fn commit_refusal(&self, fanout_id: &MessageId) -> StorageResult<Option<CommitRefusal>> {
        self.lock()?
            .query_row_cached(
                "SELECT record FROM cgka_commit_refusals WHERE fanout_id = ?1",
                params![fanout_id.as_slice()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .storage()?
            .map(|bytes| deserialize(&bytes))
            .transpose()
    }

    fn write_commit_refusal(&self, refusal: &CommitRefusal) -> StorageResult<()> {
        let record = serialize(refusal)?;
        self.lock()?
            .execute_cached(
                "INSERT INTO cgka_commit_refusals (fanout_id, group_id, record)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(fanout_id) DO UPDATE SET record = excluded.record",
                params![
                    refusal.fanout_id.as_slice(),
                    refusal.group_id.as_slice(),
                    record
                ],
            )
            .storage()?;
        Ok(())
    }

    fn read_commit_refusals(
        &self,
        sql: &str,
        params: impl rusqlite::Params,
    ) -> StorageResult<Vec<CommitRefusal>> {
        let connection = self.lock()?;
        let mut statement = connection.prepare_cached(sql).storage()?;
        let records = statement
            .query_map(params, |row| row.get::<_, Vec<u8>>(0))
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        records.iter().map(|bytes| deserialize(bytes)).collect()
    }
}
