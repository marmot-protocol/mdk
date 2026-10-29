//! The account's sign-ins this device does not recognize (mdk#2628 item 3.2).
//! See migration 0131 for the columns.
//!
//! The app decides which slots are unrecognized; this module keeps what each
//! check found and this device's answers. Every check is one transaction, and
//! the first one takes the baseline in the same transaction as its rows.

use std::collections::BTreeSet;

use crate::base::connection::CachedSql;
use crate::{SqliteAppStorage, SqliteResultExt, i64_to_u64, u64_to_i64};
use cgka_traits::storage::{StorageError, StorageResult};
use rusqlite::{OptionalExtension, params};

/// This device's answer to a sign-in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignInAnswer {
    Unanswered,
    /// Listed as unrecognized, with no prompt.
    NotNow,
    /// Not this account's user. The rejection names the slot alone.
    Rejected,
    /// Answered on another device and seen here, or a rejection that a link
    /// of the slot ended.
    Dismissed,
}

impl SignInAnswer {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Unanswered => "none",
            Self::NotNow => "not_now",
            Self::Rejected => "rejected",
            Self::Dismissed => "dismissed",
        }
    }

    fn parse(value: &str) -> StorageResult<Self> {
        Ok(match value {
            "none" => Self::Unanswered,
            "not_now" => Self::NotNow,
            "rejected" => Self::Rejected,
            "dismissed" => Self::Dismissed,
            _ => return Err(StorageError::Backend("unknown sign-in answer".into())),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignInRecord {
    pub slot_id_hex: String,
    /// This device's first check found it.
    pub before_this_device: bool,
    /// The newest publication's self-reported client name; empty when it
    /// carried none.
    pub client: String,
    pub appeared_at: u64,
    pub last_published_at: u64,
    pub key_package_event_id_hex: String,
    pub key_package_ref_hex: String,
    /// Cleared once a complete read found no valid publication in the slot,
    /// fresh or not, and set again only by a complete read that finds one.
    pub signed_in: bool,
    pub answer: SignInAnswer,
    pub answered_at: Option<u64>,
    /// A rejection the device group's roster does not record yet.
    pub roster_pending: bool,
}

/// One unrecognized slot's newest fresh, valid publication, as a check found
/// it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedSignIn {
    pub slot_id_hex: String,
    pub client: String,
    pub published_at: u64,
    pub key_package_event_id_hex: String,
    pub key_package_ref_hex: String,
}

/// What one check of the account's KeyPackages found.
#[derive(Clone, Copy, Debug)]
pub struct SignInCheck<'a> {
    pub unrecognized: &'a [ObservedSignIn],
    /// Every slot the check found a valid publication in, fresh or not,
    /// recognized or not.
    pub present_slots: &'a BTreeSet<String>,
    /// Every slot the read returned, whether or not its publication counted.
    /// The first check keeps them as the baseline.
    pub returned_slots: &'a BTreeSet<String>,
    /// Whether the read was complete. Only a complete read changes
    /// `signed_in`.
    pub complete: bool,
    pub now: u64,
}

const COLUMNS: &str = "slot_id_hex, before_this_device, client, appeared_at, last_published_at,
     key_package_event_id_hex, key_package_ref_hex, signed_in, answer, answered_at,
     roster_pending";

impl SqliteAppStorage {
    /// When this device's first check took the baseline, if one has.
    pub fn sign_in_baseline(&self) -> StorageResult<Option<u64>> {
        self.lock()?
            .query_row_cached(
                "SELECT taken_at FROM account_sign_in_baseline WHERE id = 1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .storage()?
            .map(i64_to_u64)
            .transpose()
    }

    /// Record one check: take the baseline if none is taken, so every slot
    /// this check's read returned is a device that was here before this one,
    /// whenever it counts; add or refresh each unrecognized slot; and, on a
    /// complete read only, mark every listed slot in `present_slots`, now
    /// recognized or not, as signed in and every slot missing from it as no
    /// longer signed in. Returns whether anything a host shows changed.
    pub fn record_sign_in_check(&self, check: &SignInCheck<'_>) -> StorageResult<bool> {
        let now = u64_to_i64(check.now)?;
        let mut conn = self.lock()?;
        let tx = conn.transaction().storage()?;
        let baseline_taken: bool = tx
            .query_row_cached(
                "SELECT EXISTS(SELECT 1 FROM account_sign_in_baseline)",
                [],
                |row| row.get(0),
            )
            .storage()?;
        if !baseline_taken {
            tx.execute_cached(
                "INSERT INTO account_sign_in_baseline (id, taken_at) VALUES (1, ?1)",
                params![now],
            )
            .storage()?;
            for slot in check.returned_slots {
                tx.execute_cached(
                    "INSERT OR IGNORE INTO account_sign_in_baseline_slots (slot_id_hex)
                     VALUES (?1)",
                    params![slot],
                )
                .storage()?;
            }
        }
        let mut changed = false;
        for observed in check.unrecognized {
            let published_at = u64_to_i64(observed.published_at)?;
            changed |= tx
                .execute_cached(
                    UPSERT_SIGN_IN,
                    params![
                        observed.slot_id_hex,
                        !baseline_taken,
                        observed.client,
                        published_at,
                        now,
                        observed.key_package_event_id_hex,
                        observed.key_package_ref_hex,
                    ],
                )
                .storage()?
                != 0;
        }
        if check.complete {
            for slot in check.present_slots {
                changed |= tx
                    .execute_cached(
                        "UPDATE account_sign_ins SET signed_in = 1
                         WHERE slot_id_hex = ?1 AND signed_in = 0",
                        params![slot],
                    )
                    .storage()?
                    != 0;
            }
            let signed_in: Vec<String> = {
                let mut stmt = tx
                    .prepare_cached("SELECT slot_id_hex FROM account_sign_ins WHERE signed_in = 1")
                    .storage()?;
                stmt.query_map([], |row| row.get(0))
                    .storage()?
                    .collect::<Result<_, _>>()
                    .storage()?
            };
            for slot in signed_in
                .iter()
                .filter(|slot| !check.present_slots.contains(*slot))
            {
                tx.execute_cached(
                    "UPDATE account_sign_ins SET signed_in = 0 WHERE slot_id_hex = ?1",
                    params![slot],
                )
                .storage()?;
                changed = true;
            }
        }
        tx.commit().storage()?;
        Ok(changed)
    }

    /// Every sign-in row, the earliest to appear first.
    pub fn sign_ins(&self) -> StorageResult<Vec<SignInRecord>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare_cached(&format!(
                "SELECT {COLUMNS} FROM account_sign_ins ORDER BY appeared_at ASC, slot_id_hex ASC"
            ))
            .storage()?;
        let rows = stmt
            .query_map([], sign_in_row)
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        rows.into_iter().map(sign_in_record).collect()
    }

    pub fn sign_in(&self, slot_id_hex: &str) -> StorageResult<Option<SignInRecord>> {
        self.lock()?
            .query_row_cached(
                &format!("SELECT {COLUMNS} FROM account_sign_ins WHERE slot_id_hex = ?1"),
                params![slot_id_hex],
                sign_in_row,
            )
            .optional()
            .storage()?
            .map(sign_in_record)
            .transpose()
    }

    /// Move the sign-in's answer from one of `from` to `to`. A rejection is
    /// pending in the roster. Returns whether the answer moved.
    pub fn answer_sign_in(
        &self,
        slot_id_hex: &str,
        from: &[SignInAnswer],
        to: SignInAnswer,
        answered_at: u64,
    ) -> StorageResult<bool> {
        if to == SignInAnswer::Unanswered {
            return Err(StorageError::Backend(
                "a sign-in answer cannot be withdrawn".into(),
            ));
        }
        let from = from
            .iter()
            .map(|answer| format!("'{}'", answer.as_str()))
            .collect::<Vec<_>>()
            .join(", ");
        let changed = self
            .lock()?
            .execute_cached(
                &format!(
                    "UPDATE account_sign_ins SET
                         answer = ?2,
                         answered_at = ?3,
                         roster_pending = ?4
                     WHERE slot_id_hex = ?1 AND answer IN ({from})"
                ),
                params![
                    slot_id_hex,
                    to.as_str(),
                    u64_to_i64(answered_at)?,
                    to == SignInAnswer::Rejected
                ],
            )
            .storage()?;
        Ok(changed != 0)
    }

    /// The device group's roster records this rejection, or cannot name its
    /// slot. Returns whether it was pending.
    pub fn settle_sign_in_rejection(&self, slot_id_hex: &str) -> StorageResult<bool> {
        let changed = self
            .lock()?
            .execute_cached(
                "UPDATE account_sign_ins SET roster_pending = 0
                 WHERE slot_id_hex = ?1 AND roster_pending = 1",
                params![slot_id_hex],
            )
            .storage()?;
        Ok(changed != 0)
    }

    /// Check every rejection against the roster again: the device group
    /// changed, and its roster may have lost one. Returns how many it
    /// re-armed.
    pub fn rearm_sign_in_rejections(&self) -> StorageResult<usize> {
        self.lock()?
            .execute_cached(
                "UPDATE account_sign_ins SET roster_pending = 1
                 WHERE answer = 'rejected' AND roster_pending = 0",
                [],
            )
            .storage()
    }
}

/// Add a slot, or refresh it when anything shown changes. A later
/// publication, or an equally recent one with the lower event id (the one
/// NIP-01 keeps), replaces the slot's client and KeyPackage. `appeared_at`
/// is never later than the check that first found the slot.
const UPSERT_SIGN_IN: &str = "INSERT INTO account_sign_ins (
         slot_id_hex, before_this_device, client, appeared_at, last_published_at,
         key_package_event_id_hex, key_package_ref_hex, signed_in, answer, answered_at,
         roster_pending)
     VALUES (
         ?1,
         ?2 OR EXISTS(SELECT 1 FROM account_sign_in_baseline_slots WHERE slot_id_hex = ?1),
         ?3, MIN(?4, ?5), ?4, ?6, ?7, 1, 'none', NULL, 0)
     ON CONFLICT(slot_id_hex) DO UPDATE SET
         appeared_at = MIN(appeared_at, excluded.appeared_at),
         client = CASE WHEN (excluded.last_published_at > last_published_at
                 OR (excluded.last_published_at = last_published_at
                     AND excluded.key_package_event_id_hex < key_package_event_id_hex))
             THEN excluded.client ELSE client END,
         key_package_event_id_hex = CASE WHEN (excluded.last_published_at > last_published_at
                 OR (excluded.last_published_at = last_published_at
                     AND excluded.key_package_event_id_hex < key_package_event_id_hex))
             THEN excluded.key_package_event_id_hex ELSE key_package_event_id_hex END,
         key_package_ref_hex = CASE WHEN (excluded.last_published_at > last_published_at
                 OR (excluded.last_published_at = last_published_at
                     AND excluded.key_package_event_id_hex < key_package_event_id_hex))
             THEN excluded.key_package_ref_hex ELSE key_package_ref_hex END,
         last_published_at = MAX(last_published_at, excluded.last_published_at)
     WHERE excluded.appeared_at < appeared_at
         OR excluded.last_published_at > last_published_at
         OR (excluded.last_published_at = last_published_at
             AND excluded.key_package_event_id_hex < key_package_event_id_hex)";

type SignInRow = (
    String,
    bool,
    String,
    i64,
    i64,
    String,
    String,
    bool,
    String,
    Option<i64>,
    bool,
);

fn sign_in_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SignInRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
        row.get(10)?,
    ))
}

fn sign_in_record(
    (
        slot_id_hex,
        before_this_device,
        client,
        appeared_at,
        last_published_at,
        key_package_event_id_hex,
        key_package_ref_hex,
        signed_in,
        answer,
        answered_at,
        roster_pending,
    ): SignInRow,
) -> StorageResult<SignInRecord> {
    Ok(SignInRecord {
        slot_id_hex,
        before_this_device,
        client,
        appeared_at: i64_to_u64(appeared_at)?,
        last_published_at: i64_to_u64(last_published_at)?,
        key_package_event_id_hex,
        key_package_ref_hex,
        signed_in,
        answer: SignInAnswer::parse(&answer)?,
        answered_at: answered_at.map(i64_to_u64).transpose()?,
        roster_pending,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SqliteAccountStorage;
    use SignInAnswer::*;

    fn observed(slot: &str, published_at: u64, event: &str) -> ObservedSignIn {
        ObservedSignIn {
            slot_id_hex: slot.into(),
            client: format!("client {event}"),
            published_at,
            key_package_event_id_hex: event.into(),
            key_package_ref_hex: format!("ref {event}"),
        }
    }

    fn check(
        store: &SqliteAppStorage,
        unrecognized: &[ObservedSignIn],
        complete: bool,
        now: u64,
    ) -> bool {
        let present = unrecognized
            .iter()
            .map(|observed| observed.slot_id_hex.clone())
            .collect();
        store
            .record_sign_in_check(&SignInCheck {
                unrecognized,
                present_slots: &present,
                returned_slots: &present,
                complete,
                now,
            })
            .unwrap()
    }

    #[test]
    fn the_first_check_takes_the_baseline() {
        let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
        assert_eq!(store.sign_in_baseline().unwrap(), None);
        // A read that finds nothing still takes the baseline.
        assert!(!check(&store, &[], true, 100));
        assert_eq!(store.sign_in_baseline().unwrap(), Some(100));
        assert!(check(&store, &[observed("aa", 90, "e1")], true, 200));
        assert!(!store.sign_in("aa").unwrap().unwrap().before_this_device);

        let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
        assert!(check(&store, &[observed("aa", 90, "e1")], false, 100));
        assert!(check(&store, &[observed("bb", 150, "e2")], true, 200));
        let rows = store.sign_ins().unwrap();
        assert_eq!(
            rows.iter()
                .map(|row| (row.slot_id_hex.as_str(), row.before_this_device))
                .collect::<Vec<_>>(),
            [("aa", true), ("bb", false)]
        );
        assert_eq!(store.sign_in_baseline().unwrap(), Some(100));
    }

    /// A slot the first read returned was here first even when nothing in it
    /// counted then: freshness is a publication time, which never decides.
    #[test]
    fn a_slot_the_first_check_returned_was_here_first_whenever_it_counts() {
        let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
        assert!(
            !store
                .record_sign_in_check(&SignInCheck {
                    unrecognized: &[],
                    present_slots: &BTreeSet::new(),
                    returned_slots: &BTreeSet::from(["aa".to_owned()]),
                    complete: true,
                    now: 100,
                })
                .unwrap()
        );
        assert!(check(
            &store,
            &[observed("aa", 150, "e1"), observed("bb", 150, "e2")],
            true,
            200
        ));
        let rows = store.sign_ins().unwrap();
        assert_eq!(
            rows.iter()
                .map(|row| (row.slot_id_hex.as_str(), row.before_this_device))
                .collect::<Vec<_>>(),
            [("aa", true), ("bb", false)]
        );
    }

    #[test]
    fn a_check_keeps_the_earliest_appearance_and_the_newest_publication() {
        let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
        // A publication dated after the check appeared when the check saw it.
        assert!(check(&store, &[observed("aa", 500, "e5")], true, 100));
        let row = store.sign_in("aa").unwrap().unwrap();
        assert_eq!((row.appeared_at, row.last_published_at), (100, 500));

        // An older publication moves the appearance back, not the KeyPackage.
        assert!(check(&store, &[observed("aa", 50, "e0")], true, 200));
        let row = store.sign_in("aa").unwrap().unwrap();
        assert_eq!((row.appeared_at, row.last_published_at), (50, 500));
        assert_eq!(row.key_package_event_id_hex, "e5");

        // A newer one replaces the KeyPackage and the client.
        assert!(check(&store, &[observed("aa", 600, "e6")], true, 300));
        let row = store.sign_in("aa").unwrap().unwrap();
        assert_eq!(
            (
                row.appeared_at,
                row.last_published_at,
                row.key_package_ref_hex.as_str(),
                row.client.as_str()
            ),
            (50, 600, "ref e6", "client e6")
        );
        // The same publication again changes nothing.
        assert!(!check(&store, &[observed("aa", 600, "e6")], true, 400));
        // As recent, with the lower event id, is the one NIP-01 keeps.
        assert!(check(&store, &[observed("aa", 600, "e0")], true, 400));
        assert_eq!(
            store
                .sign_in("aa")
                .unwrap()
                .unwrap()
                .key_package_event_id_hex,
            "e0"
        );
        assert!(!check(&store, &[observed("aa", 600, "e9")], true, 400));
    }

    #[test]
    fn only_a_complete_read_signs_a_slot_out() {
        let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
        check(&store, &[observed("aa", 10, "e1")], true, 100);
        assert!(!check(&store, &[], false, 200));
        assert!(store.sign_in("aa").unwrap().unwrap().signed_in);
        // A slot the check recognized is still present.
        let present = BTreeSet::from(["aa".to_owned()]);
        assert!(
            !store
                .record_sign_in_check(&SignInCheck {
                    unrecognized: &[],
                    present_slots: &present,
                    returned_slots: &present,
                    complete: true,
                    now: 300,
                })
                .unwrap()
        );
        assert!(check(&store, &[], true, 400));
        assert!(!store.sign_in("aa").unwrap().unwrap().signed_in);
        assert!(check(&store, &[observed("aa", 10, "e1")], true, 500));
        assert!(store.sign_in("aa").unwrap().unwrap().signed_in);
        // A slot that returns recognized (another device linked it) is signed
        // in again, but only by a complete read.
        assert!(check(&store, &[], true, 600));
        let recognized = |complete, now| {
            store
                .record_sign_in_check(&SignInCheck {
                    unrecognized: &[],
                    present_slots: &present,
                    returned_slots: &present,
                    complete,
                    now,
                })
                .unwrap()
        };
        assert!(!recognized(false, 700));
        assert!(!store.sign_in("aa").unwrap().unwrap().signed_in);
        assert!(recognized(true, 800));
        assert!(store.sign_in("aa").unwrap().unwrap().signed_in);
    }

    #[test]
    fn answers_move_only_from_the_expected_states() {
        let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
        check(&store, &[observed("aa", 10, "e1")], true, 100);
        assert!(
            store
                .answer_sign_in("aa", &[Unanswered], NotNow, 200)
                .unwrap()
        );
        assert!(
            !store
                .answer_sign_in("aa", &[Unanswered], NotNow, 300)
                .unwrap()
        );
        assert!(
            store
                .answer_sign_in("aa", &[Unanswered], Unanswered, 300)
                .is_err()
        );

        // A rejection holds, even after the slot publishes another.
        assert!(
            store
                .answer_sign_in("aa", &[Unanswered, NotNow], Rejected, 300)
                .unwrap()
        );
        check(&store, &[observed("aa", 20, "e2")], true, 400);
        let row = store.sign_in("aa").unwrap().unwrap();
        assert_eq!(row.answer, Rejected);
        assert_eq!(row.answered_at, Some(300));
        assert_eq!(row.key_package_ref_hex, "ref e2");
        assert!(row.roster_pending);
        assert!(store.settle_sign_in_rejection("aa").unwrap());
        assert!(!store.settle_sign_in_rejection("aa").unwrap());
        assert!(!store.sign_in("aa").unwrap().unwrap().roster_pending);
        // Convergence dropped a roster update: every rejection is checked again.
        assert_eq!(store.rearm_sign_in_rejections().unwrap(), 1);
        assert!(store.sign_in("aa").unwrap().unwrap().roster_pending);
        assert_eq!(store.rearm_sign_in_rejections().unwrap(), 0);
        assert!(
            !store
                .answer_sign_in("aa", &[Unanswered, NotNow], Dismissed, 500)
                .unwrap()
        );
        assert!(
            !store
                .answer_sign_in("bb", &[Unanswered], Dismissed, 500)
                .unwrap()
        );
    }
}
