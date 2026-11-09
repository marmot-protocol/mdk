//! Migration 0153: the local copy of each group the recovery ledger last
//! settled, and the one-time notice a rejoin raises (mdk#2660 row 11).
//!
//! A replacement Welcome installs a new copy of a group. The recovery runner
//! retires what the group's routes owed below the new copy's floor and raises
//! one notice per new copy. To do that once, it records the copy (its install
//! epoch) it settled, a rejoined copy's floor, each of the group's routes the
//! floor holds on (relays or not), and each relay of those routes that has
//! retired what lay below it, so a relay that joins a route later, or returns
//! to it, retires it too. Every goal or coverage write reads a route's floor
//! through the route index. Every group that exists now is seeded with the
//! copy its
//! engine record holds at this migration, so a rejoin before it raises no
//! notice and one applied after it, even before the runner's first turn (a
//! waiting Welcome the startup catch-up ingests), moves the epoch past the
//! seed. A record that does not decode is seeded unknown, and the runner
//! records its copy silently.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::{Transaction, params};
use serde::Deserialize;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE account_recovery_copies (
            group_id BLOB PRIMARY KEY CHECK (typeof(group_id) = 'blob' AND length(group_id) > 0),
            install_epoch INTEGER CHECK (install_epoch >= 0),
            floor_seconds INTEGER CHECK (floor_seconds >= 0),
            notice_revision INTEGER CHECK (notice_revision > 0),
            noticed_at_seconds INTEGER CHECK (noticed_at_seconds >= 0),
            CHECK ((notice_revision IS NULL) = (noticed_at_seconds IS NULL)),
            CHECK (notice_revision IS NULL OR floor_seconds IS NOT NULL),
            CHECK (floor_seconds IS NULL OR install_epoch IS NOT NULL)
        ) WITHOUT ROWID;
        CREATE TABLE account_recovery_copy_units (
            group_id BLOB NOT NULL CHECK (typeof(group_id) = 'blob' AND length(group_id) > 0),
            route_kind INTEGER NOT NULL CHECK (route_kind IN (0, 1)),
            route_id BLOB NOT NULL,
            relay TEXT NOT NULL CHECK (length(relay) > 0),
            PRIMARY KEY (group_id, route_kind, route_id, relay)
        ) WITHOUT ROWID;
        CREATE TABLE account_recovery_copy_routes (
            group_id BLOB NOT NULL CHECK (typeof(group_id) = 'blob' AND length(group_id) > 0),
            route_kind INTEGER NOT NULL CHECK (route_kind IN (0, 1)),
            route_id BLOB NOT NULL,
            PRIMARY KEY (group_id, route_kind, route_id)
        ) WITHOUT ROWID;
        CREATE INDEX account_recovery_copy_routes_by_route
            ON account_recovery_copy_routes (route_kind, route_id);",
    )
    .storage()?;
    let copies = {
        let mut statement = tx.prepare("SELECT id, record FROM cgka_groups").storage()?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .storage()?;
        rows.map(|row| {
            row.map(|(group_id, record)| (group_id, install_epoch(&record)))
                .storage()
        })
        .collect::<StorageResult<Vec<_>>>()?
    };
    let mut insert = tx
        .prepare("INSERT INTO account_recovery_copies (group_id, install_epoch) VALUES (?1, ?2)")
        .storage()?;
    for (group_id, install_epoch) in copies {
        insert.execute(params![group_id, install_epoch]).storage()?;
    }
    Ok(())
}

#[derive(Deserialize)]
struct EngineGroupRecord {
    /// Absent on records from before the field existed, which read as 0.
    #[serde(default)]
    local_copy_install_epoch: u64,
}

/// The install epoch `record` holds, or `None` when it does not decode or the
/// epoch is beyond SQLite's integers.
fn install_epoch(record: &[u8]) -> Option<i64> {
    serde_json::from_slice::<EngineGroupRecord>(record)
        .ok()
        .and_then(|record| i64::try_from(record.local_copy_install_epoch).ok())
}

#[cfg(test)]
mod tests {
    use crate::base::migrations::run_through;
    use crate::base::test_support::{gid, sample_group};
    use cgka_traits::EpochId;
    use rusqlite::{Connection, params};

    /// Every existing group starts with the copy its engine record holds (0 for
    /// a record from before the field existed), unknown only when the record
    /// does not decode, and with no rejoin floor or notice; a notice always
    /// names its rejoin's floor and when it was raised, and a floor its copy.
    #[test]
    fn existing_groups_start_with_their_recorded_copy() {
        let mut conn = Connection::open_in_memory().unwrap();
        run_through(&mut conn, 152).unwrap();
        let mut rejoined = sample_group(gid(1), 9, 2);
        rejoined.join_epoch = EpochId(0);
        rejoined.local_copy_install_epoch = EpochId(7);
        let mut legacy = serde_json::to_value(sample_group(gid(2), 3, 2)).unwrap();
        legacy
            .as_object_mut()
            .unwrap()
            .remove("local_copy_install_epoch")
            .unwrap();
        for (id, epoch, record) in [
            (vec![1_u8], 9, crate::serialize(&rejoined).unwrap()),
            (vec![2], 3, serde_json::to_vec(&legacy).unwrap()),
            (vec![3], 0, Vec::new()),
        ] {
            conn.execute(
                "INSERT INTO cgka_groups (id, epoch, record) VALUES (?1, ?2, ?3)",
                params![id, epoch, record],
            )
            .unwrap();
        }
        run_through(&mut conn, 153).unwrap();
        type CopyRow = (Vec<u8>, Option<i64>, Option<i64>, Option<i64>);
        let rows: Vec<CopyRow> = conn
            .prepare(
                "SELECT group_id, install_epoch, floor_seconds, notice_revision
                 FROM account_recovery_copies ORDER BY group_id",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            rows,
            [
                (vec![1], Some(7), None, None),
                (vec![2], Some(0), None, None),
                (vec![3], None, None, None)
            ]
        );
        let insert = |sql: &str| conn.execute(sql, []);
        assert!(
            insert(
                "INSERT INTO account_recovery_copies
                 (group_id, install_epoch, floor_seconds, notice_revision) VALUES (x'04', 4, 5, 1)"
            )
            .is_err(),
            "a notice needs its time"
        );
        assert!(
            insert(
                "INSERT INTO account_recovery_copies
                 (group_id, install_epoch, notice_revision, noticed_at_seconds)
                 VALUES (x'04', 4, 1, 9)"
            )
            .is_err(),
            "a notice needs its rejoin's floor"
        );
        assert!(
            insert(
                "INSERT INTO account_recovery_copies (group_id, floor_seconds) VALUES (x'04', 5)"
            )
            .is_err(),
            "a floor needs its copy"
        );
        assert!(
            insert("INSERT INTO account_recovery_copies (group_id) VALUES (x'')").is_err(),
            "a group id is never empty"
        );
        insert(
            "INSERT INTO account_recovery_copies
             (group_id, install_epoch, floor_seconds, notice_revision, noticed_at_seconds)
             VALUES (x'04', 4, 5, 1, 9)",
        )
        .unwrap();
        assert!(
            insert(
                "INSERT INTO account_recovery_copy_units (group_id, route_kind, route_id, relay)
                 VALUES (x'04', 1, x'05', '')"
            )
            .is_err(),
            "a settled relay has a name"
        );
        insert(
            "INSERT INTO account_recovery_copy_units (group_id, route_kind, route_id, relay)
             VALUES (x'04', 1, x'05', 'wss://a.example')",
        )
        .unwrap();
    }
}
