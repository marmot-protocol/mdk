//! Per-group holds on epoch advancement while comparison still knows of
//! history the account has not downloaded (mdk#2086).
//!
//! A hold keeps the exact event ids a comparison named as missing on one
//! route (its debt). Recording an event as durably admitted removes it from
//! every active debt, so a hold ends exactly when everything it waited for is
//! held. A group is held while it has any active debt. Debt the stall
//! backstop abandoned no longer holds the epoch but still keeps its route
//! from certifying. The engine only reads whether a group is held; the app
//! owns installing, settling and releasing holds.
use crate::connection::CachedSql;
use crate::{SqliteAccountStorage, SqliteResultExt};
use cgka_traits::storage::{HistoryAcquisitionHoldStorage, StorageResult};
use cgka_traits::types::GroupId;
use rusqlite::{OptionalExtension, params};

/// Settled passes in a row on which every relay of the route answered but
/// none served any of its active debt, after which that debt is abandoned and
/// stops holding the epoch. A pass with any relay down never counts: that
/// relay may be the one holding the named history, so the hold waits it out.
/// Reaching the limit means every relay is reachable yet none serves the
/// named events. A late admission may then already be too late to decrypt,
/// so it no longer clears abandoned debt, the route never certifies again,
/// and recovery ends with its "history may be incomplete" notice. Newly named
/// events are still active debt and hold the group again.
pub const HISTORY_ACQUISITION_STALL_PASSES: u64 = 6;

/// What settling one compared route's hold found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HistoryAcquisitionSettlement {
    /// The route holds nothing.
    Unheld,
    /// Every event the hold waited for is admitted and the hold is gone.
    /// `group_unheld` says this released the group's last active hold.
    Complete { group_unheld: bool },
    /// Named events are still missing, or were abandoned, so the route must
    /// not certify. `group_unheld` says the stall backstop just released the
    /// group's last active hold.
    Outstanding { group_unheld: bool },
}

impl HistoryAcquisitionHoldStorage for SqliteAccountStorage {
    fn history_acquisition_held(&self, group_id: &GroupId) -> StorageResult<bool> {
        let conn = self.lock()?;
        group_held(&conn, group_id.as_slice())
    }
}

impl SqliteAccountStorage {
    /// Hold `group_id`'s epoch until every event in `event_ids` that route
    /// `transport_group_id` named is durably admitted. Events already admitted
    /// are not debt, and an event the backstop abandoned stays abandoned. A
    /// newly named event restarts the route's stall count. A hold left with
    /// no debt is removed.
    pub fn hold_history_acquisition(
        &self,
        group_id: &GroupId,
        transport_group_id: &[u8; 32],
        event_ids: &[[u8; 32]],
    ) -> StorageResult<()> {
        if event_ids.is_empty() {
            return Ok(());
        }
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            conn.execute_cached(
                "INSERT OR IGNORE INTO cgka_history_acquisition_holds
                 (group_id, transport_group_id) VALUES (?1, ?2)",
                params![group_id.as_slice(), transport_group_id.as_slice()],
            )
            .storage()?;
            let mut named = 0usize;
            for event_id in event_ids {
                named += conn
                    .execute_cached(
                        "INSERT OR IGNORE INTO cgka_history_acquisition_debt
                         (transport_group_id, event_id, group_id)
                         SELECT ?1, ?2, ?3 WHERE NOT EXISTS (
                             SELECT 1 FROM transport_reconciliation_items
                             WHERE route_kind = 1 AND route_id = ?1 AND event_id = ?2
                         )",
                        params![
                            transport_group_id.as_slice(),
                            event_id.as_slice(),
                            group_id.as_slice()
                        ],
                    )
                    .storage()?;
            }
            if named > 0 {
                conn.execute_cached(
                    "UPDATE cgka_history_acquisition_holds
                     SET stalled_passes = 0, admitted_since_settle = 0
                     WHERE group_id = ?1 AND transport_group_id = ?2",
                    params![group_id.as_slice(), transport_group_id.as_slice()],
                )
                .storage()?;
            }
            if debt(&conn, group_id.as_slice(), transport_group_id, false)? == 0 {
                delete_hold(&conn, group_id.as_slice(), transport_group_id)?;
            }
            Ok(())
        })
    }

    /// Settle the hold `transport_group_id` places on `group_id` after a
    /// comparison pass. `every_relay_answered` says every one of the route's
    /// relays answered; only such passes count toward the stall backstop.
    pub fn settle_history_acquisition_route(
        &self,
        group_id: &GroupId,
        transport_group_id: &[u8; 32],
        every_relay_answered: bool,
    ) -> StorageResult<HistoryAcquisitionSettlement> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let group = group_id.as_slice();
            let row: Option<(i64, i64)> = conn
                .query_row_cached(
                    "SELECT stalled_passes, admitted_since_settle
                     FROM cgka_history_acquisition_holds
                     WHERE group_id = ?1 AND transport_group_id = ?2",
                    params![group, transport_group_id.as_slice()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .storage()?;
            let Some((stalled, admitted)) = row else {
                return Ok(HistoryAcquisitionSettlement::Unheld);
            };
            let held_before = group_held(&conn, group)?;
            if debt(&conn, group, transport_group_id, false)? == 0 {
                delete_hold(&conn, group, transport_group_id)?;
                return Ok(HistoryAcquisitionSettlement::Complete {
                    group_unheld: held_before && !group_held(&conn, group)?,
                });
            }
            let active = debt(&conn, group, transport_group_id, true)?;
            let stalled = if admitted > 0 || active == 0 {
                0
            } else if every_relay_answered {
                stalled.saturating_add(1)
            } else {
                stalled
            };
            let stall_limit = i64::try_from(HISTORY_ACQUISITION_STALL_PASSES).unwrap_or(i64::MAX);
            let abandon = active > 0 && stalled >= stall_limit;
            if abandon {
                conn.execute_cached(
                    "UPDATE cgka_history_acquisition_debt SET abandoned = 1
                     WHERE group_id = ?1 AND transport_group_id = ?2",
                    params![group, transport_group_id.as_slice()],
                )
                .storage()?;
            }
            conn.execute_cached(
                "UPDATE cgka_history_acquisition_holds
                 SET stalled_passes = ?3, admitted_since_settle = 0
                 WHERE group_id = ?1 AND transport_group_id = ?2",
                params![
                    group,
                    transport_group_id.as_slice(),
                    if abandon { 0 } else { stalled }
                ],
            )
            .storage()?;
            Ok(HistoryAcquisitionSettlement::Outstanding {
                group_unheld: held_before && !group_held(&conn, group)?,
            })
        })
    }

    /// Remove the hold `transport_group_id` places on `group_id`, with its
    /// debt. Returns whether this released the group's last active hold.
    pub fn release_history_acquisition_hold(
        &self,
        group_id: &GroupId,
        transport_group_id: &[u8; 32],
    ) -> StorageResult<bool> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let held_before = group_held(&conn, group_id.as_slice())?;
            delete_hold(&conn, group_id.as_slice(), transport_group_id)?;
            Ok(held_before && !group_held(&conn, group_id.as_slice())?)
        })
    }

    /// Remove every hold, with its debt, whose route no automatic recovery
    /// still owes: no open obligation that can still run a pass has a scope on
    /// it. A parked obligation is already a "history may be incomplete"
    /// notice; a satisfied or retired one has nothing left to fetch. Returns
    /// the groups this left with no active hold.
    pub fn release_unowed_history_acquisition_holds(&self) -> StorageResult<Vec<GroupId>> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let unowed = conn
                .prepare_cached(
                    "SELECT hold.group_id, hold.transport_group_id
                     FROM cgka_history_acquisition_holds hold
                     WHERE NOT EXISTS (
                         SELECT 1 FROM account_recovery_scopes scope
                         JOIN account_recovery_obligations obligation
                             ON obligation.id = scope.obligation_id
                         WHERE scope.transport_group_id = hold.transport_group_id
                             AND obligation.state = 0
                             AND obligation.eligibility IN (0, 1, 2)
                     )
                     ORDER BY hold.group_id, hold.transport_group_id",
                )
                .storage()?
                .query_map([], |row| {
                    Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
                })
                .storage()?
                .collect::<Result<Vec<_>, _>>()
                .storage()?;
            let mut released = Vec::new();
            for (group_id, transport_group_id) in unowed {
                let held_before = group_held(&conn, &group_id)?;
                conn.execute_cached(
                    "DELETE FROM cgka_history_acquisition_holds
                     WHERE group_id = ?1 AND transport_group_id = ?2",
                    params![group_id, transport_group_id],
                )
                .storage()?;
                if held_before
                    && released.last() != Some(&group_id)
                    && !group_held(&conn, &group_id)?
                {
                    released.push(group_id);
                }
            }
            Ok(released.into_iter().map(GroupId::new).collect())
        })
    }
}

/// Remove `event_id` from every active debt on `transport_group_id` once it
/// is durably admitted, inside the transaction that records the admission.
/// Abandoned debt stays. Only the holds that owed the event count it as
/// progress. A hold left with no debt ends here, whether or not a comparison
/// pass follows; returns the groups this left with no active hold.
pub(crate) fn admit_history_acquisition_debt_tx(
    conn: &rusqlite::Connection,
    transport_group_id: &[u8],
    event_id: &[u8; 32],
) -> StorageResult<Vec<GroupId>> {
    let owed_by = conn
        .prepare_cached(
            "SELECT group_id FROM cgka_history_acquisition_debt
             WHERE transport_group_id = ?1 AND event_id = ?2 AND abandoned = 0
             ORDER BY group_id",
        )
        .storage()?
        .query_map(params![transport_group_id, event_id.as_slice()], |row| {
            row.get::<_, Vec<u8>>(0)
        })
        .storage()?
        .collect::<Result<Vec<_>, _>>()
        .storage()?;
    let mut released = Vec::new();
    for group_id in owed_by {
        let held_before = group_held(conn, &group_id)?;
        conn.execute_cached(
            "DELETE FROM cgka_history_acquisition_debt
             WHERE transport_group_id = ?1 AND event_id = ?2 AND group_id = ?3",
            params![transport_group_id, event_id.as_slice(), group_id],
        )
        .storage()?;
        conn.execute_cached(
            "UPDATE cgka_history_acquisition_holds
             SET admitted_since_settle = admitted_since_settle + 1
             WHERE transport_group_id = ?1 AND group_id = ?2",
            params![transport_group_id, group_id],
        )
        .storage()?;
        let remaining: i64 = conn
            .query_row_cached(
                "SELECT count(*) FROM cgka_history_acquisition_debt
                 WHERE transport_group_id = ?1 AND group_id = ?2",
                params![transport_group_id, group_id],
                |row| row.get(0),
            )
            .storage()?;
        if remaining == 0 {
            conn.execute_cached(
                "DELETE FROM cgka_history_acquisition_holds
                 WHERE transport_group_id = ?1 AND group_id = ?2",
                params![transport_group_id, group_id],
            )
            .storage()?;
        }
        if held_before && !group_held(conn, &group_id)? {
            released.push(GroupId::new(group_id));
        }
    }
    Ok(released)
}

fn group_held(conn: &rusqlite::Connection, group_id: &[u8]) -> StorageResult<bool> {
    Ok(conn
        .query_row_cached(
            "SELECT 1 FROM cgka_history_acquisition_debt
             WHERE group_id = ?1 AND abandoned = 0 LIMIT 1",
            params![group_id],
            |_| Ok(()),
        )
        .optional()
        .storage()?
        .is_some())
}

/// Debt `transport_group_id` holds for `group_id`: only the active part when
/// `active_only`, otherwise abandoned debt too.
fn debt(
    conn: &rusqlite::Connection,
    group_id: &[u8],
    transport_group_id: &[u8; 32],
    active_only: bool,
) -> StorageResult<i64> {
    conn.query_row_cached(
        "SELECT count(*) FROM cgka_history_acquisition_debt
         WHERE group_id = ?1 AND transport_group_id = ?2 AND (abandoned = 0 OR NOT ?3)",
        params![group_id, transport_group_id.as_slice(), active_only],
        |row| row.get(0),
    )
    .storage()
}

fn delete_hold(
    conn: &rusqlite::Connection,
    group_id: &[u8],
    transport_group_id: &[u8; 32],
) -> StorageResult<()> {
    conn.execute_cached(
        "DELETE FROM cgka_history_acquisition_holds
         WHERE group_id = ?1 AND transport_group_id = ?2",
        params![group_id, transport_group_id.as_slice()],
    )
    .storage()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::test_support::{gid, sample_group};
    use crate::{TransportReconciliationItem, TransportReconciliationRoute};
    use cgka_traits::storage::GroupStorage;

    fn admit(store: &SqliteAccountStorage, route: [u8; 32], event_id: [u8; 32]) -> Vec<GroupId> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        store
            .record_transport_reconciliation_item(
                &TransportReconciliationRoute::Group(route),
                &TransportReconciliationItem {
                    event_id,
                    created_at: now,
                },
            )
            .unwrap()
    }

    fn settle(
        store: &SqliteAccountStorage,
        group: &GroupId,
        route: [u8; 32],
        every_relay_answered: bool,
    ) -> HistoryAcquisitionSettlement {
        store
            .settle_history_acquisition_route(group, &route, every_relay_answered)
            .unwrap()
    }

    #[test]
    fn a_hold_ends_exactly_when_its_named_events_are_admitted() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let group = sample_group(gid(1), 4, 0);
        store.put_group(&group).unwrap();
        assert!(!store.history_acquisition_held(&group.id).unwrap());

        // An event admitted before the hold is not debt.
        admit(&store, [7; 32], [3; 32]);
        store
            .hold_history_acquisition(&group.id, &[7; 32], &[[1; 32], [2; 32], [3; 32]])
            .unwrap();
        assert!(store.history_acquisition_held(&group.id).unwrap());

        admit(&store, [7; 32], [1; 32]);
        assert_eq!(
            settle(&store, &group.id, [7; 32], true),
            HistoryAcquisitionSettlement::Outstanding {
                group_unheld: false
            }
        );
        assert!(store.history_acquisition_held(&group.id).unwrap());

        // The last admission ends the hold without waiting for a comparison
        // pass, and reports the group whose convergence is now due.
        assert_eq!(admit(&store, [7; 32], [2; 32]), vec![group.id.clone()]);
        assert!(!store.history_acquisition_held(&group.id).unwrap());
        assert_eq!(
            settle(&store, &group.id, [7; 32], true),
            HistoryAcquisitionSettlement::Unheld
        );

        // Nothing left to wait for installs no hold.
        store
            .hold_history_acquisition(&group.id, &[7; 32], &[[1; 32]])
            .unwrap();
        assert!(!store.history_acquisition_held(&group.id).unwrap());

        store
            .hold_history_acquisition(&group.id, &[7; 32], &[[4; 32]])
            .unwrap();
        store.delete_group(&group.id).unwrap();
        assert!(!store.history_acquisition_held(&group.id).unwrap());
    }

    #[test]
    fn a_group_stays_held_while_any_route_waits() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let group = sample_group(gid(1), 4, 0);
        store.put_group(&group).unwrap();
        store
            .hold_history_acquisition(&group.id, &[7; 32], &[[1; 32]])
            .unwrap();
        store
            .hold_history_acquisition(&group.id, &[8; 32], &[[2; 32]])
            .unwrap();
        assert!(
            admit(&store, [7; 32], [1; 32]).is_empty(),
            "the other route still holds the group"
        );
        assert!(store.history_acquisition_held(&group.id).unwrap());
        assert!(
            store
                .release_history_acquisition_hold(&group.id, &[8; 32])
                .unwrap()
        );
        assert!(!store.history_acquisition_held(&group.id).unwrap());
    }

    #[test]
    fn stalled_passes_release_the_epoch_but_keep_the_debt() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let group = sample_group(gid(1), 4, 0);
        store.put_group(&group).unwrap();
        store
            .hold_history_acquisition(&group.id, &[7; 32], &[[1; 32], [2; 32]])
            .unwrap();
        // Passes on which a relay was down never count.
        for _ in 0..HISTORY_ACQUISITION_STALL_PASSES * 2 {
            settle(&store, &group.id, [7; 32], false);
        }
        assert!(store.history_acquisition_held(&group.id).unwrap());
        // Admitting any debt restarts the count.
        for _ in 1..HISTORY_ACQUISITION_STALL_PASSES {
            settle(&store, &group.id, [7; 32], true);
        }
        admit(&store, [7; 32], [1; 32]);
        for _ in 0..HISTORY_ACQUISITION_STALL_PASSES {
            assert_eq!(
                settle(&store, &group.id, [7; 32], true),
                HistoryAcquisitionSettlement::Outstanding {
                    group_unheld: false
                }
            );
        }
        assert_eq!(
            settle(&store, &group.id, [7; 32], true),
            HistoryAcquisitionSettlement::Outstanding { group_unheld: true }
        );
        assert!(!store.history_acquisition_held(&group.id).unwrap());
        // The abandoned debt still blocks certification.
        assert_eq!(
            settle(&store, &group.id, [7; 32], true),
            HistoryAcquisitionSettlement::Outstanding {
                group_unheld: false
            }
        );
        // A late arrival may be too late to decrypt, so it does not clear
        // abandoned debt: the route stays uncertified until recovery parks.
        assert!(admit(&store, [7; 32], [2; 32]).is_empty());
        assert_eq!(
            settle(&store, &group.id, [7; 32], true),
            HistoryAcquisitionSettlement::Outstanding {
                group_unheld: false
            }
        );
    }

    #[test]
    fn holds_on_routes_no_open_obligation_owes_are_released() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let owed = sample_group(gid(1), 4, 0);
        let parked = sample_group(gid(2), 4, 0);
        let unowed = sample_group(gid(3), 4, 0);
        for group in [&owed, &parked, &unowed] {
            store.put_group(group).unwrap();
        }
        let conn = store.lock().unwrap();
        for (id, eligibility, route) in [(1_u8, 1_i64, [1_u8; 32]), (2, 4, [2; 32])] {
            conn.execute(
                "INSERT INTO account_recovery_obligations
                 (id, demand_key, cause, predicate, created_at_ms, updated_at_ms, eligibility)
                 VALUES (?1, ?2, 5, 0, 0, 0, ?3)",
                params![vec![id; 16], format!("test:{id}"), eligibility],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO account_recovery_scopes
                 (obligation_id, scope_id, route_kind, transport_group_id)
                 VALUES (?1, 0, 1, ?2)",
                params![vec![id; 16], route.as_slice()],
            )
            .unwrap();
        }
        drop(conn);
        store
            .hold_history_acquisition(&owed.id, &[1; 32], &[[9; 32]])
            .unwrap();
        store
            .hold_history_acquisition(&parked.id, &[2; 32], &[[9; 32]])
            .unwrap();
        store
            .hold_history_acquisition(&unowed.id, &[3; 32], &[[9; 32]])
            .unwrap();
        // A second route that is still owed keeps this group held.
        store
            .hold_history_acquisition(&unowed.id, &[1; 32], &[[8; 32]])
            .unwrap();

        let released = store.release_unowed_history_acquisition_holds().unwrap();
        assert_eq!(released, vec![parked.id.clone()]);
        assert!(store.history_acquisition_held(&owed.id).unwrap());
        assert!(!store.history_acquisition_held(&parked.id).unwrap());
        assert!(store.history_acquisition_held(&unowed.id).unwrap());
    }

    fn stall_out(store: &SqliteAccountStorage, group: &GroupId, route: [u8; 32]) {
        for _ in 0..HISTORY_ACQUISITION_STALL_PASSES {
            settle(store, group, route, true);
        }
    }

    #[test]
    fn new_history_after_the_backstop_holds_the_group_again() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let group = sample_group(gid(1), 4, 0);
        store.put_group(&group).unwrap();
        store
            .hold_history_acquisition(&group.id, &[7; 32], &[[1; 32]])
            .unwrap();
        stall_out(&store, &group.id, [7; 32]);
        assert!(!store.history_acquisition_held(&group.id).unwrap());

        // A comparison that names only the abandoned event again does not
        // hold the group: nothing new is known to be missing.
        store
            .hold_history_acquisition(&group.id, &[7; 32], &[[1; 32]])
            .unwrap();
        assert!(!store.history_acquisition_held(&group.id).unwrap());

        // A newly named event is protected like any other missing history.
        store
            .hold_history_acquisition(&group.id, &[7; 32], &[[1; 32], [2; 32]])
            .unwrap();
        assert!(store.history_acquisition_held(&group.id).unwrap());
        // Its stall count starts over rather than inheriting the backstop.
        for _ in 1..HISTORY_ACQUISITION_STALL_PASSES {
            settle(&store, &group.id, [7; 32], true);
        }
        assert!(store.history_acquisition_held(&group.id).unwrap());

        // Its arrival releases the group, but the abandoned event still keeps
        // the route from certifying.
        assert_eq!(admit(&store, [7; 32], [2; 32]), vec![group.id.clone()]);
        assert!(!store.history_acquisition_held(&group.id).unwrap());
        assert_eq!(
            settle(&store, &group.id, [7; 32], true),
            HistoryAcquisitionSettlement::Outstanding {
                group_unheld: false
            }
        );
        assert!(admit(&store, [7; 32], [1; 32]).is_empty());
        assert_eq!(
            settle(&store, &group.id, [7; 32], true),
            HistoryAcquisitionSettlement::Outstanding {
                group_unheld: false
            }
        );
    }

    #[test]
    fn an_admission_only_counts_for_holds_that_owed_it() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let owed = sample_group(gid(1), 4, 0);
        let other = sample_group(gid(2), 4, 0);
        store.put_group(&owed).unwrap();
        store.put_group(&other).unwrap();
        store
            .hold_history_acquisition(&owed.id, &[7; 32], &[[1; 32], [2; 32]])
            .unwrap();
        store
            .hold_history_acquisition(&other.id, &[7; 32], &[[3; 32]])
            .unwrap();
        for _ in 1..HISTORY_ACQUISITION_STALL_PASSES {
            settle(&store, &other.id, [7; 32], true);
        }
        // An event only `owed` waited for must not reset `other`'s count.
        admit(&store, [7; 32], [1; 32]);
        assert_eq!(
            settle(&store, &other.id, [7; 32], true),
            HistoryAcquisitionSettlement::Outstanding { group_unheld: true }
        );
    }
}
