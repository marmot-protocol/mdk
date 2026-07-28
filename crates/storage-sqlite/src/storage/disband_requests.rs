use crate::{SqliteAccountStorage, SqliteResultExt, deserialize, serialize};
use cgka_traits::DisbandTombstone;
use cgka_traits::storage::{
    DisbandCandidate, DisbandCandidateStorage, DisbandRequest, DisbandRequestStatus,
    DisbandRequestStorage, DisbandTombstoneStorage, StorageResult,
};
use cgka_traits::types::{GroupId, MessageId};
use rusqlite::{Connection, OptionalExtension, params};
use std::collections::{HashMap, HashSet};

/// Every durable disband request keyed by lowercase hex MLS group id.
///
/// Requests are read through rather than denormalized into app projections:
/// the engine can replace or clear them during convergence without an
/// intervening app-layer write.
pub(crate) fn disband_requests_by_group_hex_tx(
    tx: &Connection,
) -> StorageResult<HashMap<String, DisbandRequest>> {
    let mut statement = tx
        .prepare("SELECT group_id, record FROM cgka_disband_requests")
        .storage()?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })
        .storage()?
        .collect::<rusqlite::Result<Vec<_>>>()
        .storage()?;
    rows.into_iter()
        .map(|(group_id, record)| Ok((hex::encode(group_id), deserialize(&record)?)))
        .collect()
}

/// Groups whose ordinary outbound work is currently gated by either a local
/// request or an authenticated terminal candidate awaiting convergence.
pub(crate) fn disbanding_group_ids_hex_tx(tx: &Connection) -> StorageResult<HashSet<String>> {
    let requests = disband_requests_by_group_hex_tx(tx)?;
    disbanding_group_ids_hex_with_requests_tx(tx, &requests)
}

pub(crate) fn disbanding_group_ids_hex_with_requests_tx(
    tx: &Connection,
    requests: &HashMap<String, DisbandRequest>,
) -> StorageResult<HashSet<String>> {
    let mut group_ids = requests
        .iter()
        .filter_map(|(group_id, request)| {
            (request.status == DisbandRequestStatus::Pending).then_some(group_id.clone())
        })
        .collect::<HashSet<_>>();
    let mut statement = tx
        .prepare("SELECT DISTINCT group_id FROM cgka_disband_candidates")
        .storage()?;
    let candidate_group_ids = statement
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .storage()?
        .collect::<rusqlite::Result<Vec<_>>>()
        .storage()?;
    group_ids.extend(candidate_group_ids.into_iter().map(hex::encode));
    Ok(group_ids)
}

impl SqliteAccountStorage {
    pub fn disband_requests_by_group_hex(&self) -> StorageResult<HashMap<String, DisbandRequest>> {
        let conn = self.lock()?;
        disband_requests_by_group_hex_tx(&conn)
    }

    pub fn disbanding_group_ids_hex(&self) -> StorageResult<HashSet<String>> {
        let conn = self.lock()?;
        disbanding_group_ids_hex_tx(&conn)
    }
}

impl DisbandRequestStorage for SqliteAccountStorage {
    fn put_disband_request(&self, request: &DisbandRequest) -> StorageResult<()> {
        let serialized = serialize(request)?;
        self.lock()?
            .execute(
                "INSERT OR REPLACE INTO cgka_disband_requests (group_id, record)
                 VALUES (?1, ?2)",
                params![request.group_id.as_slice(), serialized],
            )
            .storage()?;
        Ok(())
    }

    fn disband_request(&self, group_id: &GroupId) -> StorageResult<Option<DisbandRequest>> {
        self.lock()?
            .query_row(
                "SELECT record FROM cgka_disband_requests WHERE group_id = ?1",
                params![group_id.as_slice()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .storage()?
            .map(|bytes| deserialize(&bytes))
            .transpose()
    }

    fn clear_disband_request(&self, group_id: &GroupId) -> StorageResult<()> {
        self.lock()?
            .execute(
                "DELETE FROM cgka_disband_requests WHERE group_id = ?1",
                params![group_id.as_slice()],
            )
            .storage()?;
        Ok(())
    }
}

impl DisbandCandidateStorage for SqliteAccountStorage {
    fn put_disband_candidate(&self, candidate: &DisbandCandidate) -> StorageResult<()> {
        self.lock()?
            .execute(
                "INSERT OR REPLACE INTO cgka_disband_candidates (group_id, commit_id, record)
                 VALUES (?1, ?2, ?3)",
                params![
                    candidate.group_id.as_slice(),
                    candidate.commit_id.as_slice(),
                    serialize(candidate)?
                ],
            )
            .storage()?;
        Ok(())
    }

    fn disband_candidate(
        &self,
        group_id: &GroupId,
        commit_id: &MessageId,
    ) -> StorageResult<Option<DisbandCandidate>> {
        self.lock()?
            .query_row(
                "SELECT record FROM cgka_disband_candidates
                 WHERE group_id = ?1 AND commit_id = ?2",
                params![group_id.as_slice(), commit_id.as_slice()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .storage()?
            .map(|bytes| deserialize(&bytes))
            .transpose()
    }

    fn list_disband_candidates(&self, group_id: &GroupId) -> StorageResult<Vec<DisbandCandidate>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT record FROM cgka_disband_candidates
                 WHERE group_id = ?1 ORDER BY rowid",
            )
            .storage()?;
        let records = stmt
            .query_map(params![group_id.as_slice()], |row| row.get::<_, Vec<u8>>(0))
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        records
            .into_iter()
            .map(|record| deserialize(&record))
            .collect()
    }

    fn clear_disband_candidates(&self, group_id: &GroupId) -> StorageResult<()> {
        self.lock()?
            .execute(
                "DELETE FROM cgka_disband_candidates WHERE group_id = ?1",
                params![group_id.as_slice()],
            )
            .storage()?;
        Ok(())
    }
}

impl DisbandTombstoneStorage for SqliteAccountStorage {
    fn put_disband_tombstone(
        &self,
        group_id: &GroupId,
        tombstone: &DisbandTombstone,
    ) -> StorageResult<()> {
        self.lock()?
            .execute(
                "INSERT OR REPLACE INTO cgka_disband_tombstones (group_id, record)
                 VALUES (?1, ?2)",
                params![group_id.as_slice(), serialize(tombstone)?],
            )
            .storage()?;
        Ok(())
    }

    fn disband_tombstone(&self, group_id: &GroupId) -> StorageResult<Option<DisbandTombstone>> {
        self.lock()?
            .query_row(
                "SELECT record FROM cgka_disband_tombstones WHERE group_id = ?1",
                params![group_id.as_slice()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .storage()?
            .map(|bytes| deserialize(&bytes))
            .transpose()
    }

    fn list_disband_tombstones(&self) -> StorageResult<Vec<(GroupId, DisbandTombstone)>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare("SELECT group_id, record FROM cgka_disband_tombstones ORDER BY group_id")
            .storage()?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        rows.into_iter()
            .map(|(group_id, record)| Ok((GroupId::new(group_id), deserialize(&record)?)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use crate::SqliteAccountStorage;
    use crate::storage::test_support::{gid, member_id, mid, sample_group};
    use cgka_traits::DisbandTombstone;
    use cgka_traits::storage::{
        DisbandCandidate, DisbandCandidateStorage, DisbandRequest, DisbandRequestStatus,
        DisbandRequestStorage, DisbandTombstoneStorage, GroupStorage,
    };
    use cgka_traits::types::EpochId;

    #[test]
    fn disband_request_roundtrips_and_cascades_with_group() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let group = sample_group(gid(1), 3, 0);
        store.put_group(&group).unwrap();
        let request = DisbandRequest {
            group_id: group.id.clone(),
            requested_at_ms: 42,
            status: DisbandRequestStatus::Pending,
            last_prepared_epoch: Some(EpochId(3)),
        };
        store.put_disband_request(&request).unwrap();
        assert_eq!(
            store.disband_request(&group.id).unwrap(),
            Some(request.clone())
        );
        assert_eq!(
            store
                .disband_requests_by_group_hex()
                .unwrap()
                .get(&hex::encode(group.id.as_slice())),
            Some(&request)
        );
        assert!(
            store
                .disbanding_group_ids_hex()
                .unwrap()
                .contains(&hex::encode(group.id.as_slice()))
        );
        store.delete_group(&group.id).unwrap();
        assert_eq!(store.disband_request(&group.id).unwrap(), None);
    }

    #[test]
    fn candidate_roundtrips_and_terminal_tombstone_survives_local_history_deletion() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let group = sample_group(gid(2), 7, 2);
        store.put_group(&group).unwrap();
        let candidate = DisbandCandidate {
            group_id: group.id.clone(),
            source_epoch: EpochId(7),
            commit_id: mid(9),
            content_commit_id: mid(10),
            commit_digest: [0xA5; 32],
            actor: member_id(0),
            local_was_committer_leaf: true,
            former_members: group.members.clone(),
        };
        store.put_disband_candidate(&candidate).unwrap();
        assert_eq!(
            store
                .disband_candidate(&group.id, &candidate.commit_id)
                .unwrap(),
            Some(candidate.clone())
        );
        assert_eq!(
            store.list_disband_candidates(&group.id).unwrap(),
            vec![candidate.clone()]
        );
        assert!(
            store
                .disbanding_group_ids_hex()
                .unwrap()
                .contains(&hex::encode(group.id.as_slice())),
            "an inbound candidate gates sending without a local request"
        );

        let tombstone = DisbandTombstone {
            epoch: EpochId(8),
            actor: candidate.actor,
            origin_commit_id: Some(candidate.commit_id),
            commit_digest: candidate.commit_digest,
            local_was_committer_leaf: true,
            former_members: candidate.former_members,
        };
        store.put_disband_tombstone(&group.id, &tombstone).unwrap();
        assert!(
            store
                .delete_local_group_data(&hex::encode(group.id.as_slice()))
                .unwrap()
        );

        assert!(store.list_disband_candidates(&group.id).unwrap().is_empty());
        assert!(matches!(
            store.get_group(&group.id),
            Err(cgka_traits::storage::StorageError::NotFound)
        ));
        assert_eq!(
            store.disband_tombstone(&group.id).unwrap(),
            Some(tombstone.clone()),
            "minimal terminal guard must outlive optional local history"
        );
        assert_eq!(
            store.list_disband_tombstones().unwrap(),
            vec![(group.id, tombstone)]
        );
    }
}
