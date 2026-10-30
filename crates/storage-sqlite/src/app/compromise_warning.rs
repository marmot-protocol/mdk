//! What the account's compromise warning gathers on this device, and what the
//! user has seen (mdk#2628 item 3.7a, D53). See migration 0148 for the
//! columns.
//!
//! The app decides what counts; this module keeps one row per item. A row is
//! added once and stays once seen, so a rejection that branch selection drops
//! and restores does not warn again. Every gather is one transaction, and a
//! device's first roster is taken in the same transaction as its trust
//! (`SqliteAppStorage::trust_device_group`).

use std::collections::BTreeSet;

use crate::base::connection::CachedSql;
use crate::{SqliteAppStorage, SqliteResultExt, i64_to_u64, u64_to_i64};
use cgka_traits::storage::{StorageError, StorageResult};
use rusqlite::params;

/// How long this device keeps a seen rejected KeyPackage, counted from both
/// when the user saw it and the latest rejection of it this device gathered:
/// the longest a KeyPackage can be valid. An unseen one stays until
/// dismissed.
pub const COMPROMISE_WARNING_KEY_PACKAGE_RETENTION_SECS: u64 = 7_261_200;

/// The most items this device keeps. Only a misbehaving sibling gets near
/// it: rejected sign-ins each take a user's answer, and the roster holds at
/// most eight rejected KeyPackages for each slot for 30 days. Past it, the
/// oldest seen items go first.
pub const COMPROMISE_WARNING_ITEM_CAP: usize = 4096;

/// Why an item is in the warning.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CompromiseWarningReason {
    /// A slot rejected as `not_me`. The subject is the slot.
    RejectedSignIn,
    /// A rejected KeyPackage. The subject is its `KeyPackageRef`.
    RejectedKeyPackage,
}

impl CompromiseWarningReason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::RejectedSignIn => "rejected_sign_in",
            Self::RejectedKeyPackage => "rejected_key_package",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "rejected_sign_in" => Some(Self::RejectedSignIn),
            "rejected_key_package" => Some(Self::RejectedKeyPackage),
            _ => None,
        }
    }
}

/// One item as a gather found it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedWarningItem {
    pub reason: CompromiseWarningReason,
    /// Lowercase hex of the slot or `KeyPackageRef` the reason names.
    pub subject: String,
    pub slot_id_hex: String,
    /// When the rejection was made, as its maker wrote it.
    pub occurred_at: u64,
}

/// One gather. Each list is complete: an unseen rejected sign-in in neither
/// has ended.
#[derive(Clone, Copy, Debug)]
pub struct CompromiseWarningGather<'a> {
    /// Rejections this device made itself. A new one is unseen.
    pub own: &'a [ObservedWarningItem],
    /// Rejections in the trusted device group's roster. A new one is unseen,
    /// unless this device trusted that group before migration 0148 and
    /// took no baseline then: the first such gather takes its roster as seen.
    pub roster: &'a [ObservedWarningItem],
    /// The trusted device group, as lowercase hex of its group id.
    pub device_group_id_hex: Option<&'a str>,
    pub now: u64,
}

/// The rejections a device group's roster holds as this device comes to
/// trust it, and this device's own, for
/// [`SqliteAppStorage::trust_device_group`]. Each list is complete, as in a
/// gather.
#[derive(Clone, Copy, Debug)]
pub struct FirstTrustedRoster<'a> {
    /// Rejections this device made itself. A new one is unseen (D68).
    pub own: &'a [ObservedWarningItem],
    /// Rejections in the roster this device now trusts. They count as seen:
    /// the user saw them on the devices that were there (D68).
    pub roster: &'a [ObservedWarningItem],
    pub now: u64,
}

/// An unseen item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompromiseWarningRecord {
    pub reason: CompromiseWarningReason,
    pub subject: String,
    pub slot_id_hex: String,
    pub occurred_at: u64,
    pub recorded_at: u64,
}

impl SqliteAppStorage {
    /// Record one gather, then apply the bounds. Returns whether the unseen
    /// items changed.
    ///
    /// A trusted device group's first roster was taken with its trust. Only
    /// one trusted before migration 0148 has no baseline at all; its first
    /// gather takes the baseline then.
    pub fn record_compromise_warning(
        &self,
        gather: &CompromiseWarningGather<'_>,
    ) -> StorageResult<bool> {
        let now = u64_to_i64(gather.now)?;
        let mut conn = self.lock()?;
        let tx = conn.transaction().storage()?;
        let baseline = match gather.device_group_id_hex {
            Some(group) => {
                let taken: bool = tx
                    .query_row_cached(
                        "SELECT EXISTS(SELECT 1 FROM account_compromise_warning_baseline)",
                        [],
                        |row| row.get(0),
                    )
                    .storage()?;
                (!taken).then_some(group)
            }
            None => None,
        };
        let changed = record_gather(&tx, gather.own, gather.roster, baseline, now)?;
        tx.commit().storage()?;
        Ok(changed)
    }

    /// The items the open warning gathers, the earliest recorded first. Empty
    /// when no warning is open.
    pub fn compromise_warning(&self) -> StorageResult<Vec<CompromiseWarningRecord>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare_cached(
                "SELECT reason, subject, slot_id_hex, occurred_at, recorded_at
                 FROM account_compromise_warning_items
                 WHERE seen_at IS NULL
                 ORDER BY recorded_at ASC, reason ASC, subject ASC",
            )
            .storage()?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            })
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        let mut records = Vec::with_capacity(rows.len());
        for (reason, subject, slot_id_hex, occurred_at, recorded_at) in rows {
            // A reason this build does not know stays stored and unshown.
            let Some(reason) = CompromiseWarningReason::parse(&reason) else {
                continue;
            };
            records.push(CompromiseWarningRecord {
                reason,
                subject,
                slot_id_hex,
                occurred_at: i64_to_u64(occurred_at)?,
                recorded_at: i64_to_u64(recorded_at)?,
            });
        }
        Ok(records)
    }

    /// Mark everything the open warning gathers as seen. Returns whether a
    /// warning was open.
    pub fn dismiss_compromise_warning(&self, now: u64) -> StorageResult<bool> {
        let changed = self
            .lock()?
            .execute_cached(
                "UPDATE account_compromise_warning_items SET seen_at = ?1 WHERE seen_at IS NULL",
                params![u64_to_i64(now)?],
            )
            .storage()?;
        Ok(changed != 0)
    }
}

/// Record `first`, taken as `group` comes to trust, in `tx`: the trust
/// write's transaction. Returns whether the unseen items changed.
pub(crate) fn record_first_trusted_roster(
    tx: &rusqlite::Transaction<'_>,
    group_id_hex: &str,
    first: &FirstTrustedRoster<'_>,
) -> StorageResult<bool> {
    record_gather(
        tx,
        first.own,
        first.roster,
        Some(group_id_hex),
        u64_to_i64(first.now)?,
    )
}

/// Record one gather in `tx`, then apply the bounds. With `baseline`, the
/// roster is that device group's first: its rejections go in seen and the
/// group becomes the baseline. Returns whether the unseen items changed.
fn record_gather(
    tx: &rusqlite::Transaction<'_>,
    own: &[ObservedWarningItem],
    roster: &[ObservedWarningItem],
    baseline: Option<&str>,
    now: i64,
) -> StorageResult<bool> {
    let mut changed = false;
    // Own rejections first, so one the roster also holds stays unseen.
    for item in own {
        changed |= insert_item(tx, item, now, None)?;
    }
    let roster_seen_at = baseline.is_some().then_some(now);
    for item in roster {
        changed |= insert_item(tx, item, now, roster_seen_at)?;
    }
    if let Some(group) = baseline {
        tx.execute_cached(
            "INSERT INTO account_compromise_warning_baseline (id, device_group_id_hex, taken_at)
             VALUES (1, ?1, ?2)
             ON CONFLICT(id) DO UPDATE SET
                 device_group_id_hex = excluded.device_group_id_hex,
                 taken_at = excluded.taken_at",
            params![group, now],
        )
        .storage()?;
    }
    changed |= drop_ended_sign_in_rejections(tx, own, roster)?;
    changed |= prune(tx, now)?;
    Ok(changed)
}

/// Add `item` unless a row for its reason and subject exists, seen or not.
/// A seen rejected KeyPackage gathered again keeps the later rejection time,
/// so its retention runs from that. Returns whether it added an unseen row.
fn insert_item(
    tx: &rusqlite::Transaction<'_>,
    item: &ObservedWarningItem,
    now: i64,
    seen_at: Option<i64>,
) -> StorageResult<bool> {
    // A sibling writes any `u64`; one past the column's range is the latest
    // time there is, never a reason to fail the gather.
    let occurred_at = i64::try_from(item.occurred_at).unwrap_or(i64::MAX);
    // A KeyPackage rejected longer ago than any KeyPackage can be valid is
    // past harm, and its seen mark may already be gone: a roster that still
    // holds it must not warn again.
    if item.reason == CompromiseWarningReason::RejectedKeyPackage
        && occurred_at <= now - u64_to_i64(COMPROMISE_WARNING_KEY_PACKAGE_RETENTION_SECS)?
    {
        return Ok(false);
    }
    let inserted = tx
        .execute_cached(
            "INSERT OR IGNORE INTO account_compromise_warning_items
                 (reason, subject, slot_id_hex, occurred_at, recorded_at, seen_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                item.reason.as_str(),
                item.subject,
                item.slot_id_hex,
                occurred_at,
                now,
                seen_at,
            ],
        )
        .storage()?;
    if inserted == 0 && item.reason == CompromiseWarningReason::RejectedKeyPackage {
        tx.execute_cached(
            "UPDATE account_compromise_warning_items SET occurred_at = ?3
             WHERE reason = ?1 AND subject = ?2 AND seen_at IS NOT NULL AND occurred_at < ?3",
            params![item.reason.as_str(), item.subject, occurred_at],
        )
        .storage()?;
    }
    Ok(inserted != 0 && seen_at.is_none())
}

/// Drop every unseen rejected sign-in that neither this device nor the
/// roster holds now: a link the user confirmed ended it, or a branch the
/// device group dropped carried it. One that stands again warns again. A seen
/// one stays, so it never warns twice.
fn drop_ended_sign_in_rejections(
    tx: &rusqlite::Transaction<'_>,
    own: &[ObservedWarningItem],
    roster: &[ObservedWarningItem],
) -> StorageResult<bool> {
    let standing: BTreeSet<&str> = own
        .iter()
        .chain(roster)
        .filter(|item| item.reason == CompromiseWarningReason::RejectedSignIn)
        .map(|item| item.subject.as_str())
        .collect();
    let unseen: Vec<String> = {
        let mut stmt = tx
            .prepare_cached(
                "SELECT subject FROM account_compromise_warning_items
                 WHERE reason = ?1 AND seen_at IS NULL",
            )
            .storage()?;
        stmt.query_map(
            params![CompromiseWarningReason::RejectedSignIn.as_str()],
            |row| row.get(0),
        )
        .storage()?
        .collect::<Result<_, _>>()
        .storage()?
    };
    let mut changed = false;
    for subject in unseen
        .iter()
        .filter(|subject| !standing.contains(subject.as_str()))
    {
        changed |= tx
            .execute_cached(
                "DELETE FROM account_compromise_warning_items
                 WHERE reason = ?1 AND subject = ?2 AND seen_at IS NULL",
                params![CompromiseWarningReason::RejectedSignIn.as_str(), subject],
            )
            .storage()?
            != 0;
    }
    Ok(changed)
}

/// Drop seen rejected KeyPackages once both their seen mark and their latest
/// rejection are past the retention. `insert_item` refuses a rejection that
/// old, so one that goes is not added again. Then drop the oldest items past
/// the cap, seen ones first. Returns whether an unseen item went.
fn prune(tx: &rusqlite::Transaction<'_>, now: i64) -> StorageResult<bool> {
    tx.execute_cached(
        "DELETE FROM account_compromise_warning_items
         WHERE reason = ?1 AND seen_at <= ?2 - ?3 AND occurred_at <= ?2 - ?3",
        params![
            CompromiseWarningReason::RejectedKeyPackage.as_str(),
            now,
            u64_to_i64(COMPROMISE_WARNING_KEY_PACKAGE_RETENTION_SECS)?
        ],
    )
    .storage()?;
    let count: i64 = tx
        .query_row_cached(
            "SELECT COUNT(*) FROM account_compromise_warning_items",
            [],
            |row| row.get(0),
        )
        .storage()?;
    let cap = i64::try_from(COMPROMISE_WARNING_ITEM_CAP)
        .map_err(|_| StorageError::Backend("compromise warning cap out of range".into()))?;
    let mut over_unseen = 0;
    if count > cap {
        let unseen_before: i64 = tx
            .query_row_cached(
                "SELECT COUNT(*) FROM account_compromise_warning_items WHERE seen_at IS NULL",
                [],
                |row| row.get(0),
            )
            .storage()?;
        tx.execute_cached(
            "DELETE FROM account_compromise_warning_items
             WHERE (reason, subject) IN (
                 SELECT reason, subject FROM account_compromise_warning_items
                 ORDER BY seen_at IS NULL ASC, recorded_at ASC, reason ASC, subject ASC
                 LIMIT ?1)",
            params![count - cap],
        )
        .storage()?;
        let unseen_after: i64 = tx
            .query_row_cached(
                "SELECT COUNT(*) FROM account_compromise_warning_items WHERE seen_at IS NULL",
                [],
                |row| row.get(0),
            )
            .storage()?;
        over_unseen = unseen_before - unseen_after;
    }
    Ok(over_unseen != 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SqliteAccountStorage;
    use CompromiseWarningReason::*;

    fn item(
        reason: CompromiseWarningReason,
        subject: &str,
        occurred_at: u64,
    ) -> ObservedWarningItem {
        ObservedWarningItem {
            reason,
            subject: subject.into(),
            slot_id_hex: format!("slot {subject}"),
            occurred_at,
        }
    }

    fn gather(
        store: &SqliteAppStorage,
        own: &[ObservedWarningItem],
        roster: &[ObservedWarningItem],
        group: Option<&str>,
        now: u64,
    ) -> bool {
        store
            .record_compromise_warning(&CompromiseWarningGather {
                own,
                roster,
                device_group_id_hex: group,
                now,
            })
            .unwrap()
    }

    /// Whether a row for `subject` is kept, seen or not.
    fn stored(store: &SqliteAppStorage, subject: &str) -> bool {
        store
            .lock()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM account_compromise_warning_items WHERE subject = ?1",
                [subject],
                |row| row.get::<_, i64>(0),
            )
            .unwrap()
            != 0
    }

    fn open(store: &SqliteAppStorage) -> Vec<(CompromiseWarningReason, String)> {
        store
            .compromise_warning()
            .unwrap()
            .into_iter()
            .map(|record| (record.reason, record.subject))
            .collect()
    }

    /// One warning gathers every unseen item; Dismiss marks them all seen, and
    /// an item seen once never warns again, even when a gather loses it and
    /// finds it again.
    #[test]
    fn a_seen_item_never_warns_again() {
        let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
        assert!(!gather(&store, &[], &[], None, 10));
        assert!(open(&store).is_empty());
        assert!(gather(
            &store,
            &[item(RejectedSignIn, "aa", 5)],
            &[],
            None,
            10
        ));
        // The same item again is no change.
        assert!(!gather(
            &store,
            &[item(RejectedSignIn, "aa", 5)],
            &[],
            None,
            20
        ));
        let records = store.compromise_warning().unwrap();
        assert_eq!(
            records,
            [CompromiseWarningRecord {
                reason: RejectedSignIn,
                subject: "aa".into(),
                slot_id_hex: "slot aa".into(),
                occurred_at: 5,
                recorded_at: 10,
            }]
        );
        assert!(store.dismiss_compromise_warning(30).unwrap());
        assert!(!store.dismiss_compromise_warning(31).unwrap());
        assert!(open(&store).is_empty());
        // Lost, then found again: still seen.
        assert!(!gather(&store, &[], &[], None, 40));
        assert!(!gather(
            &store,
            &[item(RejectedSignIn, "aa", 5)],
            &[],
            None,
            50
        ));
        assert!(open(&store).is_empty());
        // Something new opens the warning again, with only the new item.
        assert!(gather(
            &store,
            &[item(RejectedKeyPackage, "k1", 45)],
            &[],
            None,
            60
        ));
        assert_eq!(open(&store), [(RejectedKeyPackage, "k1".to_owned())]);
    }

    /// Trust `group` with `own` and `roster` as its first trusted roster.
    fn trust(
        store: &SqliteAppStorage,
        group: &str,
        own: &[ObservedWarningItem],
        roster: &[ObservedWarningItem],
        now: u64,
    ) -> Option<bool> {
        use crate::{DeviceGroupRecord, DeviceGroupTrust};
        for record in store.device_groups().unwrap() {
            store
                .delete_device_group(&record.group_id_hex, record.trust)
                .unwrap();
        }
        assert!(
            store
                .insert_device_group(&DeviceGroupRecord {
                    group_id_hex: group.into(),
                    trust: DeviceGroupTrust::AwaitingWelcome,
                    key_package_ref_hex: Some("ab".into()),
                    recorded_at: now,
                })
                .unwrap()
        );
        store
            .trust_device_group(
                group,
                DeviceGroupTrust::AwaitingWelcome,
                DeviceGroupTrust::Linked,
                None,
                now,
                &FirstTrustedRoster { own, roster, now },
            )
            .unwrap()
    }

    /// The roster a device trusts a group with counts as seen, taken in the
    /// trust write; this device's own rejections still warn, and later
    /// roster rejections warn. Trusting another group takes its roster the
    /// same way.
    #[test]
    fn the_roster_a_device_first_trusts_is_taken_as_seen() {
        let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
        let own = [item(RejectedSignIn, "aa", 5)];
        let roster = [item(RejectedSignIn, "aa", 6), item(RejectedSignIn, "bb", 7)];
        assert_eq!(trust(&store, "g1", &own, &roster, 10), Some(true));
        assert_eq!(open(&store), [(RejectedSignIn, "aa".to_owned())]);
        let later = [roster[1].clone(), item(RejectedKeyPackage, "k1", 8)];
        assert!(gather(&store, &own, &later, Some("g1"), 20));
        assert_eq!(
            open(&store),
            [
                (RejectedSignIn, "aa".to_owned()),
                (RejectedKeyPackage, "k1".to_owned())
            ]
        );
        let g2 = [item(RejectedSignIn, "cc", 9)];
        assert_eq!(trust(&store, "g2", &own, &g2, 30), Some(false));
        assert_eq!(open(&store).len(), 2);
        assert!(gather(
            &store,
            &own,
            &[g2[0].clone(), item(RejectedSignIn, "dd", 9)],
            Some("g2"),
            40
        ));
        assert_eq!(open(&store).len(), 3);
    }

    /// A trust write that does not move the row records nothing.
    #[test]
    fn a_trust_write_that_does_not_move_records_nothing() {
        use crate::DeviceGroupTrust::*;
        let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
        let own = [item(RejectedSignIn, "aa", 5)];
        let first = FirstTrustedRoster {
            own: &own,
            roster: &[],
            now: 10,
        };
        assert_eq!(
            store
                .trust_device_group("g1", AwaitingWelcome, Linked, None, 10, &first)
                .unwrap(),
            None
        );
        assert!(open(&store).is_empty());
        // No baseline either: a later gather is still a first one.
        assert!(!gather(
            &store,
            &[],
            &[item(RejectedSignIn, "bb", 6)],
            Some("g1"),
            20
        ));
        assert!(open(&store).is_empty());
    }

    /// Only a trusted group with no baseline at all, as one trusted before
    /// migration 0148, takes its first gather's roster as seen. Once any
    /// baseline exists, a roster from a group with no trust write warns.
    #[test]
    fn only_a_group_with_no_baseline_takes_its_first_gather_as_seen() {
        let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
        let bb = [item(RejectedSignIn, "bb", 7)];
        assert!(!gather(&store, &[], &bb, Some("g1"), 10));
        assert!(open(&store).is_empty());
        let cc = [item(RejectedSignIn, "cc", 8)];
        assert!(gather(&store, &[], &cc, Some("g2"), 20));
        assert_eq!(open(&store), [(RejectedSignIn, "cc".to_owned())]);
        // Without a trusted group no gather takes a baseline.
        let fresh = SqliteAccountStorage::in_memory().unwrap().app_storage();
        assert!(gather(&fresh, &cc, &[], None, 10));
        assert!(!gather(
            &fresh,
            &cc,
            &[item(RejectedSignIn, "dd", 9)],
            Some("g1"),
            20
        ));
        assert_eq!(open(&fresh), [(RejectedSignIn, "cc".to_owned())]);
    }

    /// A sibling can write a rejection time past what the column holds; the
    /// gather saturates it rather than failing.
    #[test]
    fn a_rejection_time_out_of_range_still_warns() {
        let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
        assert_eq!(trust(&store, "g1", &[], &[], 10), Some(false));
        let far = [
            item(RejectedSignIn, "aa", u64::MAX),
            item(RejectedKeyPackage, "k1", u64::MAX),
        ];
        assert!(gather(&store, &[], &far, Some("g1"), 20));
        let records = store.compromise_warning().unwrap();
        assert_eq!(records.len(), 2);
        assert!(
            records
                .iter()
                .all(|record| record.occurred_at == u64::try_from(i64::MAX).unwrap())
        );
    }

    /// An unseen rejected sign-in that neither this device nor the roster
    /// holds any more, as when the user links its slot, leaves the warning,
    /// and warns again if it stands again. A seen one stays seen.
    #[test]
    fn a_rejection_that_ends_leaves_the_warning_unless_seen() {
        let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
        let aa = [item(RejectedSignIn, "aa", 5)];
        let bb = [item(RejectedSignIn, "bb", 5)];
        assert!(gather(
            &store,
            &[aa[0].clone(), bb[0].clone()],
            &[],
            None,
            10
        ));
        assert!(gather(&store, &bb, &[], Some("g1"), 20));
        assert_eq!(open(&store), [(RejectedSignIn, "bb".to_owned())]);
        assert!(!gather(&store, &bb, &[], Some("g1"), 25));
        // The roster holds it again, after the device group's first roster.
        assert!(gather(&store, &bb, &aa, Some("g1"), 30));
        assert_eq!(open(&store).len(), 2);
        assert!(store.dismiss_compromise_warning(40).unwrap());
        assert!(!gather(&store, &[], &[], Some("g1"), 50));
        assert!(!gather(&store, &bb, &aa, Some("g1"), 60));
        assert!(open(&store).is_empty());
    }

    /// A seen rejected KeyPackage goes once both its seen mark and its
    /// rejection are older than a KeyPackage can be valid, and a roster that
    /// still holds it does not bring it back. An unseen one stays until
    /// dismissed; a rejected sign-in stays.
    #[test]
    fn a_seen_rejected_key_package_is_kept_for_a_key_packages_lifetime() {
        let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
        let aa = [item(RejectedSignIn, "aa", 5)];
        // Rejected on a clock ahead of this device's.
        let k1 = [item(RejectedKeyPackage, "k1", 15)];
        let k2 = [item(RejectedKeyPackage, "k2", 15)];
        assert!(gather(&store, &aa, &[], Some("g1"), 10));
        assert!(gather(&store, &aa, &k1, Some("g1"), 10));
        assert!(store.dismiss_compromise_warning(11).unwrap());
        assert!(gather(&store, &aa, &k2, Some("g1"), 12));
        let lapse = 15 + COMPROMISE_WARNING_KEY_PACKAGE_RETENTION_SECS;
        let roster = [k1[0].clone(), k2[0].clone()];
        assert!(!gather(&store, &aa, &roster, Some("g1"), lapse - 1));
        assert!(stored(&store, "k1"));
        assert!(!gather(&store, &aa, &roster, Some("g1"), lapse));
        assert_eq!(open(&store), [(RejectedKeyPackage, "k2".to_owned())]);
        assert!(!stored(&store, "k1"));
        assert!(stored(&store, "aa"));
        assert!(store.dismiss_compromise_warning(lapse + 1).unwrap());
        assert!(!gather(&store, &aa, &roster, Some("g1"), lapse + 2));
        assert!(open(&store).is_empty());
        // Seen just now, so kept for a KeyPackage's lifetime from here.
        assert!(stored(&store, "k2"));
        let seen_lapse = lapse + 1 + COMPROMISE_WARNING_KEY_PACKAGE_RETENTION_SECS;
        assert!(!gather(&store, &aa, &roster, Some("g1"), seen_lapse - 1));
        assert!(stored(&store, "k2"));
        assert!(!gather(&store, &aa, &roster, Some("g1"), seen_lapse));
        assert!(!stored(&store, "k2"));
        assert!(open(&store).is_empty());
    }

    /// A seen rejected KeyPackage recorded again with a later time, as after
    /// the roster dropped it and a device rejected it again, stays seen: its
    /// retention runs from the later rejection.
    #[test]
    fn a_seen_rejected_key_package_recorded_again_stays_seen() {
        let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
        assert_eq!(trust(&store, "g1", &[], &[], 10), Some(false));
        let first = [item(RejectedKeyPackage, "k1", 100)];
        assert!(gather(&store, &[], &first, Some("g1"), 100));
        assert!(store.dismiss_compromise_warning(101).unwrap());
        assert!(!gather(&store, &[], &[], Some("g1"), 200));
        let again = [item(RejectedKeyPackage, "k1", 1_000)];
        assert!(!gather(&store, &[], &again, Some("g1"), 1_000));
        // Past the first rejection's retention and the seen mark's: kept.
        let first_lapse = 101 + COMPROMISE_WARNING_KEY_PACKAGE_RETENTION_SECS;
        assert!(!gather(&store, &[], &again, Some("g1"), first_lapse));
        assert!(stored(&store, "k1"));
        assert!(open(&store).is_empty());
        // Past the later one: gone, and that rejection is not added again.
        let lapse = 1_000 + COMPROMISE_WARNING_KEY_PACKAGE_RETENTION_SECS;
        assert!(!gather(&store, &[], &again, Some("g1"), lapse));
        assert!(!stored(&store, "k1"));
        assert!(open(&store).is_empty());
    }

    /// Past the cap, the oldest seen items go first.
    #[test]
    fn the_cap_drops_the_oldest_seen_items_first() {
        let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
        let seen: Vec<_> = (0..COMPROMISE_WARNING_ITEM_CAP)
            .map(|index| item(RejectedSignIn, &format!("s{index:05}"), 1))
            .collect();
        assert!(gather(&store, &seen, &[], None, 10));
        assert!(store.dismiss_compromise_warning(11).unwrap());
        assert!(gather(
            &store,
            &[item(RejectedSignIn, "new", 2)],
            &[],
            None,
            20
        ));
        assert_eq!(open(&store), [(RejectedSignIn, "new".to_owned())]);
        let count: i64 = store
            .lock()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM account_compromise_warning_items",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, i64::try_from(COMPROMISE_WARNING_ITEM_CAP).unwrap());
        // The oldest seen one went (the first gather recorded them all at
        // once, so the lowest subject), and found again it warns again: the
        // cost of the cap.
        let new = item(RejectedSignIn, "new", 2);
        assert!(!gather(
            &store,
            &[new.clone(), item(RejectedSignIn, "s00001", 1)],
            &[],
            None,
            30
        ));
        assert!(gather(
            &store,
            &[new, item(RejectedSignIn, "s00000", 1)],
            &[],
            None,
            30
        ));
    }
}
