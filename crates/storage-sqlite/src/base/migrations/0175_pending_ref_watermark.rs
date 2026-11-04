//! Migration 0175: independent account-device pending-reference reservation.
//!
//! Legacy artifacts have no independent bound. An undecodable retained row
//! therefore aborts this transaction: guessing or skipping could reuse a saved
//! reference when its group hydrates later. After seeding, artifact corruption
//! is handled by per-group hydration, not account construction.
//!
//! The schema ledger also gates the origin-bearing ordinary Welcome payload
//! (stored-message tag 13). Pre-0175 readers cannot decode it, and pre-0175
//! writers cannot maintain the independent pending-reference bound. The runner
//! refuses both on the newer schema before exposing application tables.

use crate::{SqliteResultExt, deserialize};
use cgka_traits::OutboundFanout;
use cgka_traits::maintenance::DurableGroupEvolution;
use cgka_traits::storage::{StorageError, StorageResult};
use rusqlite::{Transaction, params};

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    let mut high_water = 0;
    for (query, fanout) in [
        ("SELECT record FROM cgka_outbound_fanout", true),
        ("SELECT record FROM cgka_group_evolutions", false),
    ] {
        let mut statement = tx.prepare(query).storage()?;
        let mut rows = statement.query([]).storage()?;
        while let Some(row) = rows.next().storage()? {
            let bytes = row.get_ref(0).storage()?.as_blob().map_err(|_| {
                StorageError::Backend(
                    "cannot establish legacy pending reference high-water: invalid artifact".into(),
                )
            })?;
            let pending = if fanout {
                deserialize::<OutboundFanout>(bytes).map(|record| record.pending_ref())
            } else {
                deserialize::<DurableGroupEvolution>(bytes).map(|record| record.pending_ref)
            }
            .map_err(|_| {
                StorageError::Backend(
                    "cannot establish legacy pending reference high-water: undecodable artifact"
                        .into(),
                )
            })?;
            if let Some(pending) = pending {
                high_water = high_water.max(pending.as_u64());
            }
        }
    }
    // Fixed-width big-endian BLOBs preserve u64::MAX and order numerically.
    // This account singleton is intentionally outside every group snapshot.
    tx.execute_batch(
        "CREATE TABLE IF NOT EXISTS cgka_pending_ref_watermark (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            high_water BLOB NOT NULL CHECK (typeof(high_water) = 'blob' AND length(high_water) = 8)
        );",
    )
    .storage()?;
    tx.execute(
        "INSERT INTO cgka_pending_ref_watermark (singleton, high_water) VALUES (1, ?1)
         ON CONFLICT(singleton) DO UPDATE SET high_water = max(high_water, excluded.high_water)",
        params![high_water.to_be_bytes().as_slice()],
    )
    .storage()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::base::migrations::run_through;
    use crate::base::test_support::{gid, mid, sample_group};
    use crate::serialize;
    use cgka_traits::engine_state::PendingStateRef;
    use cgka_traits::maintenance::{
        DurableGroupEvolution, GroupEvolutionPhase, GroupEvolutionSemantic, MaintenanceTrigger,
    };
    use cgka_traits::storage::StorageError;
    use cgka_traits::{
        EpochId, MemberId, OutboundFanout, Timestamp, TransportEndpoint, TransportEnvelope,
        TransportMessage, TransportPublishRequest, TransportPublishTarget, TransportSource,
    };
    use rusqlite::{Connection, params};

    const FANOUT_INSERT: &str = "INSERT INTO cgka_outbound_fanout
        (message_id, group_id, record) VALUES (X'01', ?1, ?2)";
    const EVOLUTION_INSERT: &str = "INSERT INTO cgka_group_evolutions
        (id, group_id, insert_order, record) VALUES (X'02', ?1, 1, ?2)";

    fn legacy_connection() -> Connection {
        let mut connection = Connection::open_in_memory().unwrap();
        run_through(&mut connection, 174).unwrap();
        connection
            .execute(
                "INSERT INTO cgka_groups (id, epoch, record) VALUES (?1, 0, ?2)",
                params![
                    gid(1).as_slice(),
                    serialize(&sample_group(gid(1), 0, 0)).unwrap()
                ],
            )
            .unwrap();
        connection
    }

    #[test]
    fn legacy_refs_seed_full_u64() {
        let fanout = OutboundFanout::stage(
            TransportPublishRequest {
                account_id: MemberId::new(vec![1; 32]),
                message: TransportMessage {
                    id: mid(1),
                    payload: vec![3],
                    timestamp: Timestamp(0),
                    causal_deps: vec![],
                    source: TransportSource("fixture".into()),
                    envelope: TransportEnvelope::GroupMessage {
                        transport_group_id: vec![2; 32],
                    },
                },
                target: TransportPublishTarget::Group {
                    group_id: gid(1),
                    transport_group_id: vec![2; 32],
                    endpoints: vec![TransportEndpoint("wss://migration.example".into())],
                },
                required_acks: 1,
            },
            Some(PendingStateRef::new(u64::MAX)),
            Some(gid(1)),
            0,
        )
        .unwrap();
        let evolution = DurableGroupEvolution {
            id: mid(2),
            group_id: gid(1),
            source_epoch: EpochId(0),
            target_epoch: EpochId(1),
            phase: GroupEvolutionPhase::Prepared,
            semantic: GroupEvolutionSemantic::SelfUpdate {
                trigger: MaintenanceTrigger::Manual,
                obligation_id: None,
            },
            own_leaf_before_hash: None,
            removal_members: vec![],
            signed_message_id: None,
            pending_ref: Some(PendingStateRef::new(u64::MAX)),
        };
        for (insert, record) in [
            (FANOUT_INSERT, serialize(&fanout).unwrap()),
            (EVOLUTION_INSERT, serialize(&evolution).unwrap()),
        ] {
            let mut connection = legacy_connection();
            connection
                .execute(insert, params![gid(1).as_slice(), record])
                .unwrap();
            run_through(&mut connection, 175).unwrap();
            let bound: Vec<u8> = connection
                .query_row(
                    "SELECT high_water FROM cgka_pending_ref_watermark WHERE singleton = 1",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(bound, u64::MAX.to_be_bytes());
        }
    }

    #[test]
    fn schema_175_blocks_old_writers() {
        let mut connection = legacy_connection();
        run_through(&mut connection, 175).unwrap();
        let before = connection.total_changes();
        assert!(matches!(
            run_through(&mut connection, 174),
            Err(StorageError::UnsupportedSchemaVersion {
                found: 175,
                latest_supported: 174
            })
        ));
        assert_eq!(connection.total_changes(), before);
        let bound: Vec<u8> = connection
            .query_row(
                "SELECT high_water FROM cgka_pending_ref_watermark WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(bound, 0u64.to_be_bytes());
    }

    #[test]
    fn legacy_corruption_is_closed() {
        for insert in [FANOUT_INSERT, EVOLUTION_INSERT] {
            let mut connection = legacy_connection();
            connection
                .execute(insert, params![gid(1).as_slice(), [0xffu8].as_slice()])
                .unwrap();
            let error = run_through(&mut connection, 175).unwrap_err();
            assert!(matches!(error, StorageError::Backend(_)));
            let version: i64 = connection
                .query_row(
                    "SELECT max(version) FROM cgka_schema_migrations",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(version, 174);
            let tables: i64 = connection
                .query_row(
                    "SELECT count(*) FROM sqlite_master WHERE name = 'cgka_pending_ref_watermark'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(tables, 0);
        }
    }
}
