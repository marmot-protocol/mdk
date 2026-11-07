//! Parked recovery that hosts show as "history may be incomplete", and its
//! explicit, user-authorized retirement.
use super::*;
#[cfg(test)]
use crate::SqliteAccountStorage;
use crate::SqliteAppStorage;

/// `incomplete_reason` recorded with `state = 2` when the user retires a parked
/// obligation: the history may be incomplete. Retirement is its own outcome and
/// is never coverage. The value is meaningful only while `state = 2`; any new
/// demand that reopens the row clears it.
pub(crate) const RETIRED_HISTORY_MAY_BE_INCOMPLETE: i64 = 0;

/// One parked occurrence: automatic recovery stopped without proving this
/// history complete and waits for new evidence, an explicit deep repair, or a
/// retirement. `ticket.revision` identifies the occurrence; new evidence rearms
/// the obligation under a newer revision, so a later parking is a new
/// occurrence. These identities are account-private and never belong in logs.
pub struct ParkedRecoveryObligation {
    pub ticket: RecoveryDemandTicket,
    pub cause: RecoveryCause,
    /// Set for group-scoped demand, such as an epoch gap.
    pub group_id: Option<Vec<u8>>,
    /// Wall-clock milliseconds when it parked; `None` for rows parked before
    /// the time was recorded.
    pub parked_at_ms: Option<u64>,
}

type ParkedRow = (Vec<u8>, i64, i64, Option<Vec<u8>>, Option<i64>);

fn parked(rows: Vec<ParkedRow>) -> StorageResult<Vec<ParkedRecoveryObligation>> {
    rows.into_iter()
        .map(|(id, revision, cause, group_id, parked_at)| {
            Ok(ParkedRecoveryObligation {
                ticket: RecoveryDemandTicket {
                    id: id.try_into().map_err(|_| demand::invalid_demand())?,
                    revision: i64_to_u64(revision)?,
                },
                cause: demand::recovery_cause(cause)?,
                group_id,
                parked_at_ms: parked_at.map(i64_to_u64).transpose()?,
            })
        })
        .collect()
}

impl SqliteAppStorage {
    /// Every pending obligation parked for explicit deep repair, oldest first.
    /// The set is input-relative to unresolved demand keys, never a history log.
    pub fn parked_recovery_obligations(&self) -> StorageResult<Vec<ParkedRecoveryObligation>> {
        let conn = self.lock()?;
        let rows = conn
            .prepare_cached(
                "SELECT id,revision,cause,group_id,parked_at_ms FROM account_recovery_obligations
                 WHERE state=0 AND eligibility=4 ORDER BY parked_at_ms,id",
            )
            .storage()?
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            })
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        parked(rows)
    }

    /// Parked occurrences scoped to one group, oldest first. Account-wide
    /// demand (loss, incremental or explicit history) is not included.
    pub fn parked_group_recovery_obligations(
        &self,
        group_id: &[u8],
    ) -> StorageResult<Vec<ParkedRecoveryObligation>> {
        let conn = self.lock()?;
        let rows = conn
            .prepare_cached(
                "SELECT id,revision,cause,group_id,parked_at_ms FROM account_recovery_obligations
                 WHERE state=0 AND eligibility=4 AND group_id=?1 ORDER BY parked_at_ms,id",
            )
            .storage()?
            .query_map([group_id], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            })
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        parked(rows)
    }

    /// Retire exactly one parked occurrence because the user accepted that its
    /// history may be incomplete. In one transaction, and only while the
    /// obligation still has this revision and is still parked, this records
    /// `state = 2` with [`RETIRED_HISTORY_MAY_BE_INCOMPLETE`] and a new revision.
    /// It never marks coverage.
    ///
    /// Only the obligations that stay under the recovery runner (epoch gap,
    /// maintenance, known event) retire here. The account-open conversion
    /// turns every other cause into ledger debt, whose dismissal is the
    /// ledger's, so a row of such a cause the conversion has not reached yet
    /// is refused rather than retired without its loss evidence.
    ///
    /// Returns false for an unknown, stale or no-longer-parked notice. A later
    /// new demand for the same key (a higher epoch, a new join or request)
    /// reopens the row as fresh pending debt.
    pub fn retire_parked_recovery_obligation(
        &self,
        id: [u8; 16],
        revision: u64,
        now_ms: u64,
    ) -> StorageResult<bool> {
        let revision = sqlite_integer(revision)?;
        let now = sqlite_integer(now_ms)?;
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let retired = conn
                .execute_cached(
                    "UPDATE account_recovery_obligations SET state=2,incomplete_reason=?3,urgency=0,
                         revision=revision+1,updated_at_ms=MAX(updated_at_ms,?4)
                     WHERE id=?1 AND revision=?2 AND state=0 AND eligibility=4 AND cause IN (1,2,4)",
                    params![id.as_slice(), revision, RETIRED_HISTORY_MAY_BE_INCOMPLETE, now],
                )
                .storage()?;
            Ok(retired == 1)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SqlCipherKey;
    use crate::TransportReconciliationRoute;
    use crate::base::test_support::{gid, sample_group};
    use cgka_traits::storage::GroupStorage;

    fn fixture() -> SqliteAccountStorage {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store
            .app_storage()
            .ensure_account_projection("alice")
            .unwrap();
        store
    }

    fn arm(store: &SqliteAccountStorage, epoch: u64) {
        store
            .app_storage()
            .arm_epoch_backfill_intents(&[crate::StoredEpochBackfillIntent {
                group_id_hex: hex::encode(gid(1).as_slice()),
                stalled_epoch: epoch,
            }])
            .unwrap();
    }

    /// An armed epoch gap on group 1, at epoch 7.
    fn epoch_gap(store: &SqliteAccountStorage) -> [u8; 16] {
        store.put_group(&sample_group(gid(1), 7, 2)).unwrap();
        arm(store, 7);
        store.app_storage().pending_recovery_demands().unwrap()[0]
            .ticket
            .id
    }

    /// Park `id` the way the recovery runner does when an epoch gap's return
    /// visits run out.
    fn park(store: &SqliteAccountStorage, id: [u8; 16], now_seconds: u64) -> RecoveryDemandTicket {
        let app = store.app_storage();
        let ticket = app
            .pending_recovery_demands()
            .unwrap()
            .into_iter()
            .find(|demand| demand.ticket.id == id)
            .expect("a pending obligation")
            .ticket;
        let floors = [(TransportReconciliationRoute::Group([3; 32]), 0)];
        assert!(
            app.begin_recovery_epoch_gap_retry(ticket, &floors, now_seconds)
                .unwrap()
        );
        let visits = app
            .recovery_epoch_gap_retry(ticket)
            .unwrap()
            .unwrap()
            .visits;
        assert!(
            app.finish_recovery_epoch_gap_retry(ticket, visits, now_seconds, 0, true)
                .unwrap()
        );
        let notice = app
            .parked_recovery_obligations()
            .unwrap()
            .into_iter()
            .find(|notice| notice.ticket.id == id)
            .expect("parked occurrence");
        notice.ticket
    }

    fn row(store: &SqliteAccountStorage, id: [u8; 16]) -> (i64, Option<i64>, i64) {
        store
            .lock()
            .unwrap()
            .query_row(
                "SELECT state,incomplete_reason,revision FROM account_recovery_obligations WHERE id=?1",
                [id.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap()
    }

    #[test]
    fn parking_lists_one_occurrence_with_cause_and_time() {
        let store = fixture();
        let app = store.app_storage();
        let id = epoch_gap(&store);
        assert!(app.parked_recovery_obligations().unwrap().is_empty());
        let ticket = park(&store, id, 5);
        let notices = app.parked_recovery_obligations().unwrap();
        assert_eq!(notices.len(), 1);
        assert!(notices[0].ticket == ticket);
        assert_eq!(notices[0].cause, RecoveryCause::EpochGap);
        assert_eq!(notices[0].group_id.as_deref(), Some(gid(1).as_slice()));
        assert_eq!(notices[0].parked_at_ms, Some(5_000));
        let group = app
            .parked_group_recovery_obligations(gid(1).as_slice())
            .unwrap();
        assert_eq!(group.len(), 1);
        assert!(group[0].ticket == ticket);
        assert!(
            app.parked_group_recovery_obligations(gid(2).as_slice())
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn retirement_is_its_own_outcome_and_never_coverage() {
        let store = fixture();
        let app = store.app_storage();
        let id = epoch_gap(&store);
        let ticket = park(&store, id, 1);
        assert!(
            !app.retire_parked_recovery_obligation(id, ticket.revision + 1, 2_000)
                .unwrap(),
            "an unknown occurrence changes nothing"
        );
        assert!(
            app.retire_parked_recovery_obligation(id, ticket.revision, 2_000)
                .unwrap()
        );
        assert_eq!(
            row(&store, id),
            (
                2,
                Some(RETIRED_HISTORY_MAY_BE_INCOMPLETE),
                ticket.revision as i64 + 1
            )
        );
        assert!(app.parked_recovery_obligations().unwrap().is_empty());
        assert!(app.pending_recovery_demands().unwrap().is_empty());
        assert!(
            !app.retire_parked_recovery_obligation(id, ticket.revision, 2_000)
                .unwrap(),
            "a second dismissal of the same occurrence is stale"
        );
    }

    /// A parked row of a cause the account-open conversion turns into ledger
    /// debt is refused: retiring it here would leave its loss evidence behind.
    #[test]
    fn a_cause_awaiting_conversion_is_never_retired_here() {
        let store = fixture();
        let app = store.app_storage();
        app.execute_batch_for_test(&format!(
            "INSERT INTO account_recovery_obligations (id, demand_key, cause, account_label, marker_token, pending_since, dropped_count, created_at_ms, updated_at_ms, eligibility, parked_at_ms)
             VALUES (x'{id}', 'overflow:alice', 0, 'alice', 7, 1, 3, 1, 1, 4, 1);",
            id = "42".repeat(16),
        ))
        .unwrap();
        let notice = app.parked_recovery_obligations().unwrap().remove(0);
        assert_eq!(notice.cause, RecoveryCause::QueueLoss);
        let before = row(&store, notice.ticket.id);
        assert!(
            !app.retire_parked_recovery_obligation(notice.ticket.id, notice.ticket.revision, 2_000)
                .unwrap()
        );
        assert_eq!(row(&store, notice.ticket.id), before);
    }

    #[test]
    fn retirement_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("retire.sqlite");
        let key = SqlCipherKey::raw([0x51; 32]);
        let (id, ticket) = {
            let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
            store
                .app_storage()
                .ensure_account_projection("alice")
                .unwrap();
            let id = epoch_gap(&store);
            let ticket = park(&store, id, 1);
            assert!(
                store
                    .app_storage()
                    .retire_parked_recovery_obligation(id, ticket.revision, 2_000)
                    .unwrap()
            );
            (id, ticket)
        };
        let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        let app = store.app_storage();
        assert_eq!(row(&store, id).0, 2);
        assert!(app.parked_recovery_obligations().unwrap().is_empty());
        assert!(app.pending_recovery_demands().unwrap().is_empty());
        assert!(
            !app.retire_parked_recovery_obligation(id, ticket.revision, 3_000)
                .unwrap()
        );
    }

    #[test]
    fn retired_epoch_gap_reopens_only_for_a_higher_epoch() {
        let store = fixture();
        let app = store.app_storage();
        let id = epoch_gap(&store);
        let ticket = park(&store, id, 1);
        assert!(
            app.retire_parked_recovery_obligation(id, ticket.revision, 2_000)
                .unwrap()
        );
        arm(&store, 7);
        assert_eq!(row(&store, id).0, 2);
        assert!(app.pending_epoch_backfill_intents().unwrap().is_empty());
        arm(&store, 8);
        assert_eq!(row(&store, id).0, 0);
        assert_eq!(app.pending_epoch_backfill_intents().unwrap().len(), 1);
        assert!(
            app.parked_group_recovery_obligations(gid(1).as_slice())
                .unwrap()
                .is_empty()
        );
    }

    /// mdk#2258: an unresolved epoch gap says the group moved past the epoch
    /// it stalled at. Pending, parked and user-retired gaps all keep it open,
    /// with the time it was first armed: dismissing the notice changes no MLS
    /// state. Only a cleared intent or the device leaving that epoch closes it.
    #[test]
    fn epoch_gap_stays_open_at_its_stalled_epoch_until_cleared_or_left_behind() {
        let store = fixture();
        let app = store.app_storage();
        let group = gid(1);
        let open_since = |group: &cgka_traits::GroupId, epoch| {
            app.epoch_gap_recovery_open_since(group.as_slice(), epoch)
                .unwrap()
        };
        assert_eq!(open_since(&group, 7), None);
        let before = crate::base::codec::unix_now_seconds_i64() as u64 * 1_000;
        let id = epoch_gap(&store);
        let since = open_since(&group, 7).expect("an armed gap is open");
        assert!(since >= before);
        // A reorg back below the stalled epoch is still behind.
        assert_eq!(open_since(&group, 6), Some(since));
        // Having left the stalled epoch, the device no longer stands on it.
        assert_eq!(open_since(&group, 8), None);
        assert_eq!(open_since(&gid(2), 7), None);

        let ticket = park(&store, id, 1);
        assert_eq!(
            open_since(&group, 7),
            Some(since),
            "parked recovery has not proven the device caught up"
        );
        assert!(
            app.retire_parked_recovery_obligation(id, ticket.revision, 2_000)
                .unwrap()
        );
        assert_eq!(
            open_since(&group, 7),
            Some(since),
            "dismissing the notice leaves the device on the stalled epoch"
        );
        assert_eq!(open_since(&group, 8), None);
        app.clear_epoch_backfill_intents(&[crate::StoredEpochBackfillIntent {
            group_id_hex: hex::encode(group.as_slice()),
            stalled_epoch: 7,
        }])
        .unwrap();
        assert_eq!(open_since(&group, 7), None);
    }
}
