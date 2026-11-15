//! The committed rosters the app trusts (mdk#3273 PR 6): an app read of the
//! engine's roster tables, bound to the `(group, revision)` pairs one version
//! of the app's published read state names. A roster matches only where its
//! stored revision is the named one, so a group that version leaves out, or
//! recorded at another revision, never matches: a reader between the
//! engine's roster write and the next publish sees a revision mismatch, never
//! a roster the read state has not validated. One statement reads every
//! roster, so its rows come from one snapshot and no roster is torn.

use crate::{SqliteAppStorage, SqliteResultExt, u64_to_i64};
use cgka_traits::storage::{CommittedMembers, RosterRevision, StorageResult};
use cgka_traits::types::{GroupId, MemberId};
use rusqlite::params;

/// Each trusted pair's roster and members. A roster with no members still
/// matches, with a NULL member: it is known.
const TRUSTED_ROSTER_MEMBERS_SQL: &str = "SELECT roster.group_id, member.member_id
     FROM json_each(?1) AS trusted
     JOIN cgka_committed_rosters AS roster
       ON roster.group_id = unhex(json_extract(trusted.value, '$[0]'))
      AND roster.revision = json_extract(trusted.value, '$[1]')
     LEFT JOIN cgka_committed_roster_members AS member
       ON member.group_id = roster.group_id
     ORDER BY roster.group_id, member.member_id";

impl SqliteAppStorage {
    /// The members of each roster in `trusted` whose stored revision is the
    /// one named, in group id order. A pair naming a group with no roster,
    /// or with another revision, is left out; a matching roster with no
    /// members is returned empty.
    pub fn trusted_roster_members(
        &self,
        trusted: &[(GroupId, RosterRevision)],
    ) -> StorageResult<Vec<(GroupId, CommittedMembers)>> {
        if trusted.is_empty() {
            return Ok(Vec::new());
        }
        let pairs = trusted
            .iter()
            .map(|(group_id, revision)| {
                Ok(serde_json::json!([
                    hex::encode(group_id.as_slice()),
                    u64_to_i64(revision.0)?
                ]))
            })
            .collect::<StorageResult<Vec<_>>>()?;
        let pairs = serde_json::Value::Array(pairs).to_string();
        let conn = self.lock()?;
        let mut statement = conn.prepare_cached(TRUSTED_ROSTER_MEMBERS_SQL).storage()?;
        let rows = statement
            .query_map(params![pairs], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Option<Vec<u8>>>(1)?))
            })
            .storage()?;
        let mut rosters: Vec<(Vec<u8>, Vec<MemberId>)> = Vec::new();
        for row in rows {
            let (group_id, member_id) = row.storage()?;
            if rosters.last().is_none_or(|(last, _)| *last != group_id) {
                rosters.push((group_id, Vec::new()));
            }
            if let (Some(member_id), Some((_, members))) = (member_id, rosters.last_mut()) {
                members.push(MemberId::new(member_id));
            }
        }
        Ok(rosters
            .into_iter()
            .map(|(group_id, members)| {
                (GroupId::new(group_id), CommittedMembers::from_ids(members))
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use crate::SqliteAccountStorage;
    use crate::base::test_support::{gid, member_id, sample_group};
    use cgka_traits::storage::{
        CommittedMembers, CommittedRosterStorage, GroupStorage, RosterRevision,
    };

    fn members(ids: &[u8]) -> CommittedMembers {
        CommittedMembers::from_ids(ids.iter().map(|id| member_id(*id)))
    }

    /// A roster matches only at the revision named: a replaced roster's old
    /// revision, a group with no roster and a group no one stores never
    /// match, and a known empty roster matches with no members. Matches come
    /// back in group id order, each once, whatever order or repeats the
    /// pairs have.
    #[test]
    fn a_roster_matches_only_at_the_revision_named() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let app = store.app_storage();
        let first = sample_group(gid(1), 1, 2);
        let second = sample_group(gid(2), 1, 3);
        let unknown = sample_group(gid(3), 1, 2);
        for group in [&first, &second] {
            store
                .put_group_with_roster(group, &CommittedMembers::of_members(&group.members))
                .unwrap();
        }
        store.put_group_keeping_roster(&unknown).unwrap();
        let revision = |group| {
            store
                .committed_roster_revision(group)
                .unwrap()
                .expect("a recorded roster")
        };
        let (first_at, second_at) = (revision(&first.id), revision(&second.id));
        assert!(app.trusted_roster_members(&[]).unwrap().is_empty());

        let named = [
            (second.id.clone(), second_at),
            (first.id.clone(), first_at),
            (second.id.clone(), second_at),
            (unknown.id.clone(), RosterRevision(first_at.0)),
            (gid(4), first_at),
        ];
        assert_eq!(
            app.trusted_roster_members(&named).unwrap(),
            vec![
                (first.id.clone(), members(&[0, 1])),
                (second.id.clone(), members(&[0, 1, 2])),
            ]
        );

        store
            .put_committed_roster(&first.id, &members(&[]))
            .unwrap();
        let emptied = revision(&first.id);
        assert!(emptied > first_at);
        assert_eq!(
            app.trusted_roster_members(&[(first.id.clone(), first_at)])
                .unwrap(),
            Vec::new(),
            "a replaced roster matched at its old revision"
        );
        assert_eq!(
            app.trusted_roster_members(&[(first.id.clone(), emptied)])
                .unwrap(),
            vec![(first.id.clone(), members(&[]))]
        );
    }
}
