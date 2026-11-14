//! Each group's committed roster and its revision (mdk#3273 B). See migration
//! 0205. The tables are outside every snapshot, so rolling a group back keeps
//! its roster; deleting the group's record deletes it.

use crate::base::connection::CachedSql;
use crate::{SqliteAccountStorage, SqliteResultExt};
use cgka_traits::storage::{
    CommittedMembers, CommittedRoster, CommittedRosterStorage, CommittedRosterWrite,
    RosterRevision, StorageError, StorageResult,
};
use cgka_traits::types::{GroupId, MemberId};
use rusqlite::{Connection, OptionalExtension, params};
use std::collections::BTreeSet;

impl CommittedRosterStorage for SqliteAccountStorage {
    fn committed_roster(&self, group_id: &GroupId) -> StorageResult<Option<CommittedRoster>> {
        let conn = self.lock()?;
        let Some(revision) = revision_on(&conn, group_id)? else {
            return Ok(None);
        };
        let members = members_on(&conn, group_id)?;
        Ok(Some(CommittedRoster {
            revision,
            members: CommittedMembers::from_ids(members.into_iter().map(MemberId::new)),
        }))
    }

    fn committed_roster_revision(
        &self,
        group_id: &GroupId,
    ) -> StorageResult<Option<RosterRevision>> {
        let conn = self.lock()?;
        revision_on(&conn, group_id)
    }

    fn put_committed_roster(
        &self,
        group_id: &GroupId,
        members: &CommittedMembers,
    ) -> StorageResult<CommittedRosterWrite> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            write_committed_roster(&conn, group_id, members)
        })
    }
}

fn revision_on(conn: &Connection, group_id: &GroupId) -> StorageResult<Option<RosterRevision>> {
    conn.query_row_cached(
        "SELECT revision FROM cgka_committed_rosters WHERE group_id = ?1",
        params![group_id.as_slice()],
        |row| row.get::<_, i64>(0),
    )
    .optional()
    .storage()?
    .map(revision_from_sql)
    .transpose()
}

fn members_on(conn: &Connection, group_id: &GroupId) -> StorageResult<BTreeSet<Vec<u8>>> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT member_id FROM cgka_committed_roster_members WHERE group_id = ?1
             ORDER BY member_id",
        )
        .storage()?;
    stmt.query_map(params![group_id.as_slice()], |row| row.get::<_, Vec<u8>>(0))
        .storage()?
        .collect::<Result<BTreeSet<_>, _>>()
        .storage()
}

fn revision_from_sql(revision: i64) -> StorageResult<RosterRevision> {
    u64::try_from(revision)
        .map(RosterRevision)
        .map_err(|_| StorageError::Backend("negative committed roster revision".into()))
}

/// Make `group_id`'s committed roster hold exactly `members`, in the caller's
/// transaction. Writes nothing when it already does; otherwise takes the
/// next account-wide revision and changes only the rows that differ.
pub(crate) fn write_committed_roster(
    conn: &Connection,
    group_id: &GroupId,
    members: &CommittedMembers,
) -> StorageResult<CommittedRosterWrite> {
    let wanted: BTreeSet<Vec<u8>> = members
        .ids()
        .iter()
        .map(|member| member.as_slice().to_vec())
        .collect();
    let previous = revision_on(conn, group_id)?;
    let stored = members_on(conn, group_id)?;
    if let Some(revision) = previous
        && stored == wanted
    {
        return Ok(CommittedRosterWrite::Unchanged(revision));
    }
    let revision = revision_from_sql(
        conn.query_row_cached(
            "UPDATE cgka_committed_roster_revision SET last = last + 1 WHERE id = 1
             RETURNING last",
            [],
            |row| row.get::<_, i64>(0),
        )
        .storage()?,
    )?;
    conn.execute_cached(
        "INSERT INTO cgka_committed_rosters (group_id, revision) VALUES (?1, ?2)
         ON CONFLICT(group_id) DO UPDATE SET revision = excluded.revision",
        params![group_id.as_slice(), crate::u64_to_i64(revision.0)?],
    )
    .storage()?;
    for gone in stored.difference(&wanted) {
        conn.execute_cached(
            "DELETE FROM cgka_committed_roster_members WHERE group_id = ?1 AND member_id = ?2",
            params![group_id.as_slice(), gone],
        )
        .storage()?;
    }
    for added in wanted.difference(&stored) {
        conn.execute_cached(
            "INSERT INTO cgka_committed_roster_members (group_id, member_id) VALUES (?1, ?2)",
            params![group_id.as_slice(), added],
        )
        .storage()?;
    }
    Ok(match previous {
        Some(_) => CommittedRosterWrite::Replaced(revision),
        None => CommittedRosterWrite::Recorded(revision),
    })
}

#[cfg(test)]
mod tests {
    use crate::SqliteAccountStorage;
    use crate::base::test_support::{TestGroupState, gid, member_id, sample_group};
    use cgka_traits::storage::{
        CommittedMembers, CommittedRosterStorage, CommittedRosterWrite, GroupStorage,
        MessageStorage, StorageError, StorageProvider,
    };
    use cgka_traits::transport::Timestamp;
    use openmls_traits::storage::StorageProvider as OpenMlsStorageProvider;

    fn members(ids: &[u8]) -> CommittedMembers {
        CommittedMembers::from_ids(ids.iter().map(|id| member_id(*id)))
    }

    fn revision(write: CommittedRosterWrite) -> u64 {
        match write {
            CommittedRosterWrite::Unchanged(revision)
            | CommittedRosterWrite::Recorded(revision)
            | CommittedRosterWrite::Replaced(revision) => revision.0,
        }
    }

    /// A roster write changes the revision exactly when it changes the
    /// members, and a known empty roster differs from no roster.
    #[test]
    fn a_roster_moves_its_revision_only_when_its_members_change() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let group = sample_group(gid(1), 1, 3);
        store
            .put_group_with_roster(&group, &CommittedMembers::of_members(&group.members))
            .unwrap();
        let recorded = store.committed_roster(&group.id).unwrap().unwrap();
        assert_eq!(recorded.members, members(&[0, 1, 2]));

        let again = store
            .put_committed_roster(&group.id, &members(&[2, 0, 1, 0]))
            .unwrap();
        assert_eq!(again, CommittedRosterWrite::Unchanged(recorded.revision));

        let replaced = store
            .put_committed_roster(&group.id, &members(&[0, 3]))
            .unwrap();
        assert!(
            matches!(replaced, CommittedRosterWrite::Replaced(revision) if revision > recorded.revision),
            "{replaced:?}"
        );
        let stored = store.committed_roster(&group.id).unwrap().unwrap();
        assert_eq!(stored.members, members(&[0, 3]));
        assert_eq!(revision(replaced), stored.revision.0);

        let emptied = store
            .put_committed_roster(&group.id, &members(&[]))
            .unwrap();
        let stored = store.committed_roster(&group.id).unwrap().unwrap();
        assert!(stored.members.ids().is_empty());
        assert_eq!(revision(emptied), stored.revision.0);
        assert!(stored.revision.0 > revision(replaced));

        let unknown = sample_group(gid(2), 1, 2);
        store.put_group_keeping_roster(&unknown).unwrap();
        assert_eq!(store.committed_roster(&unknown.id).unwrap(), None);
        assert_eq!(store.committed_roster_revision(&unknown.id).unwrap(), None);
    }

    /// A group forgotten or deleted and then joined again gets a revision no
    /// earlier copy held, so a reader that recorded an earlier revision never
    /// matches the new copy's roster.
    #[test]
    fn a_forgotten_or_deleted_group_joined_again_never_reuses_a_revision() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let group = sample_group(gid(1), 1, 1);
        store.put_group_with_roster(&group, &members(&[0])).unwrap();
        let mut highest = revision(
            store
                .put_committed_roster(&group.id, &members(&[0, 1]))
                .unwrap(),
        );

        assert!(store.forget_group_local(&group.id, Timestamp(10)).unwrap());
        assert_eq!(store.committed_roster(&group.id).unwrap(), None);
        store.complete_group_local_reset(&group.id).unwrap();
        store.put_group_with_roster(&group, &members(&[0])).unwrap();
        let rejoined = store.committed_roster(&group.id).unwrap().unwrap();
        assert!(
            rejoined.revision.0 > highest,
            "{rejoined:?} after {highest}"
        );
        highest = rejoined.revision.0;

        store.delete_group(&group.id).unwrap();
        assert_eq!(store.committed_roster(&group.id).unwrap(), None);
        store.put_group_with_roster(&group, &members(&[0])).unwrap();
        let rejoined = store.committed_roster(&group.id).unwrap().unwrap();
        assert!(
            rejoined.revision.0 > highest,
            "{rejoined:?} after {highest}"
        );
    }

    /// Rolling a group back onto a snapshot restores its record and MLS
    /// state, never its committed roster.
    #[test]
    fn a_group_rollback_leaves_its_committed_roster() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let anchor = sample_group(gid(1), 1, 1);
        store
            .put_group_with_roster(&anchor, &CommittedMembers::of_members(&anchor.members))
            .unwrap();
        let mls_id = openmls::group::GroupId::from_slice(anchor.id.as_slice());
        store
            .mls_storage()
            .write_group_state(&mls_id, &TestGroupState(vec![1]))
            .unwrap();
        store.create_group_snapshot(&anchor.id, "anchor").unwrap();

        let live = sample_group(gid(1), 2, 2);
        store
            .put_group_with_roster(&live, &CommittedMembers::of_members(&live.members))
            .unwrap();
        let roster = store.committed_roster(&live.id).unwrap().unwrap();
        store
            .rollback_group_to_snapshot(&anchor.id, "anchor")
            .unwrap();

        assert_eq!(store.get_group(&anchor.id).unwrap(), anchor);
        assert_eq!(store.committed_roster(&anchor.id).unwrap(), Some(roster));
    }

    /// A record write that merges membership commits with its roster or not
    /// at all.
    #[test]
    fn a_failed_roster_write_leaves_no_record_behind() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store
            .lock()
            .unwrap()
            .execute_batch(
                "CREATE TEMP TRIGGER refuse_roster_member BEFORE INSERT ON cgka_committed_roster_members
                 BEGIN SELECT RAISE(ABORT, 'roster member refused'); END;",
            )
            .unwrap();
        let group = sample_group(gid(1), 1, 1);
        let result =
            store.put_group_with_roster(&group, &CommittedMembers::of_members(&group.members));
        assert!(
            matches!(&result, Err(StorageError::Backend(reason)) if reason.contains("roster member refused")),
            "{result:?}"
        );
        assert!(matches!(
            store.get_group(&group.id),
            Err(StorageError::NotFound)
        ));
        assert_eq!(store.committed_roster(&group.id).unwrap(), None);
    }

    /// The roster write joins the caller's transaction: a later step that
    /// fails takes the record and its roster back together.
    #[test]
    fn a_roster_write_rolls_back_with_its_callers_transaction() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let group = sample_group(gid(1), 1, 2);
        let result: Result<(), StorageError> = store.with_transaction(|store| {
            store.put_group_with_roster(&group, &CommittedMembers::of_members(&group.members))?;
            Err(StorageError::Backend("later step refused".into()))
        });
        assert!(
            matches!(&result, Err(StorageError::Backend(reason)) if reason == "later step refused"),
            "{result:?}"
        );
        assert!(matches!(
            store.get_group(&group.id),
            Err(StorageError::NotFound)
        ));
        assert_eq!(store.committed_roster(&group.id).unwrap(), None);
    }
}
