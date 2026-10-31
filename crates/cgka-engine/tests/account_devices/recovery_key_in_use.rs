//! The two engine facts `marmot-app` reads before it tells its user that
//! recovery words confirmed on this device are not in use (mdk#2628 4.4a).
//!
//! - `own_account_entry_change_retained`: one of this device's account-entry
//!   changes is queued, staged or kept as a record, which lasts, decided or
//!   not, until its source epoch is past the rewind horizon. Nothing acts on
//!   a decided record again.
//! - `recovery_key_selectable`: a key this device introduced may still be
//!   the account's, since the roster holds it, one of this device's
//!   account-entry changes is kept, or the oldest epoch a branch can still
//!   fork from held it. A missing anchor at that epoch, or an older one still
//!   stored, counts as selectable.

use super::activation::{buffer_unsettled, queued_intents};
use super::device_roster::{
    account, clocked_roster_device, found_device_group, now_wall_ms, race_roster_commits,
    refused_account_replacement, replace, roster, roster_device, set_account,
};
use super::*;
use cgka_engine::ManualConvergenceClock;
use cgka_engine::convergence::V1_MAX_REWIND_COMMITS;
use cgka_traits::app_components::AccountEntryV1;
use cgka_traits::engine::SupersededIntentOutcome;
use cgka_traits::storage::{OutboundIntentStorage as _, OwnCommitIntent};

fn account_entry_records(device: &Device, gid: &GroupId) -> Vec<OwnCommitIntent> {
    device
        .storage
        .list_own_commit_intents(Some(gid))
        .unwrap()
        .into_iter()
        .filter(|record| matches!(record.intent, SendIntent::ReplaceAccountEntry { .. }))
        .collect()
}

fn retained(device: &Device, gid: &GroupId) -> bool {
    device
        .engine
        .own_account_entry_change_retained(gid)
        .unwrap()
}

fn tip(device: &Device, gid: &GroupId) -> u64 {
    device.engine.epoch(gid).unwrap().0
}

fn anchor(epoch: u64) -> String {
    format!("openmls-retained-anchor-{epoch}")
}

/// A commit that records no intent, to move the group on.
async fn self_update(device: &mut Device, gid: &GroupId) {
    let intent = SendIntent::SelfUpdate {
        group_id: gid.clone(),
    };
    send_commit(device, intent, gid).await;
}

/// A decided supersession keeps the record, marked decided, until its source
/// epoch is past the rewind horizon, and nothing acts on it again: the
/// maintenance re-derivation reports and queues nothing, the event path
/// finds nothing to decide, and the commit gate's owed check passes it by.
/// Past the horizon the re-derivation collects it, as it does a confirmed
/// commit's record.
#[tokio::test]
async fn a_decided_account_entry_record_is_kept_until_the_horizon_and_never_acted_on_again() {
    let (mut loser, _winner, gid, report) = race_roster_commits(
        |phone, gid| set_account(phone, gid, 1, 7),
        |laptop, gid| set_account(laptop, gid, 2, 8),
    )
    .await;
    assert_eq!(report.outcome, SupersededIntentOutcome::Conflict);
    let records = account_entry_records(&loser, &gid);
    let [record] = records.as_slice() else {
        panic!("one account-entry record: {records:?}");
    };
    assert!(record.decided);
    assert!(queued_intents(&loser, &gid).is_empty());

    let source = record.source_epoch.0;
    while tip(&loser, &gid) <= source + V1_MAX_REWIND_COMMITS {
        let reports = loser
            .engine
            .reissue_superseded_own_commits_from_state()
            .unwrap();
        assert!(reports.is_empty(), "{reports:?}");
        assert_eq!(
            loser
                .engine
                .reissue_superseded_own_commit(&record.commit_id)
                .unwrap(),
            None
        );
        assert!(
            !loser
                .engine
                .owes_superseded_own_commit_reissue(&gid)
                .unwrap()
        );
        assert!(queued_intents(&loser, &gid).is_empty());
        assert_eq!(account_entry_records(&loser, &gid), records);
        assert!(retained(&loser, &gid));
        self_update(&mut loser, &gid).await;
    }
    let reports = loser
        .engine
        .reissue_superseded_own_commits_from_state()
        .unwrap();
    assert!(reports.is_empty(), "{reports:?}");
    assert!(account_entry_records(&loser, &gid).is_empty());
    assert!(!retained(&loser, &gid));
}

/// Only this device's account-entry changes count, queued, staged or
/// confirmed, until the rewind horizon: a rename counts for nothing, and a
/// queued change the drain refuses leaves nothing behind.
#[tokio::test]
async fn only_kept_own_account_entry_changes_are_retained() {
    let clock = ManualConvergenceClock::new(1_000_000, now_wall_ms());
    let mut phone = clocked_roster_device(b"alice", &clock);
    let mut laptop = roster_device(b"alice");
    let gid = found_device_group(
        &mut phone,
        &roster(&[(1, "Phone"), (2, "Laptop")]),
        &mut [&mut laptop],
    )
    .await;
    assert!(!retained(&phone, &gid));
    let rename = replace(&phone, &gid, 1, "Renamed");
    let rename = send_commit(&mut phone, rename, &gid).await;
    assert!(!retained(&phone, &gid));
    assert_accepted(&mut laptop, &rename, &gid).await;

    // Queued behind the laptop's change, still settling: kept, until the
    // drain refuses it.
    let by_laptop = set_account(&laptop, &gid, 2, 7);
    let by_laptop = send_commit(&mut laptop, by_laptop, &gid).await;
    buffer_unsettled(&mut phone, &by_laptop).await;
    let queued = phone
        .engine
        .send(set_account(&phone, &gid, 1, 8))
        .await
        .unwrap();
    assert!(matches!(queued, SendResult::Queued { .. }), "{queued:?}");
    assert!(retained(&phone, &gid));
    clock.advance_ms(30_000);
    phone.engine.advance_convergence(&gid).await.unwrap();
    assert!(refused_account_replacement(&phone.engine.drain_events()));
    assert!(!retained(&phone, &gid));

    // Staged and confirmed: kept until the rewind horizon.
    let by_phone = set_account(&phone, &gid, 1, 8);
    send_commit(&mut phone, by_phone, &gid).await;
    let source = tip(&phone, &gid) - 1;
    while tip(&phone, &gid) <= source + V1_MAX_REWIND_COMMITS {
        phone
            .engine
            .reissue_superseded_own_commits_from_state()
            .unwrap();
        assert!(retained(&phone, &gid));
        self_update(&mut phone, &gid).await;
    }
    phone
        .engine
        .reissue_superseded_own_commits_from_state()
        .unwrap();
    assert!(!retained(&phone, &gid));
}

/// A key the phone set is selectable while the roster holds it, while the
/// phone's commit setting it is kept, and while the oldest epoch a branch can
/// still fork from held it; only then is it not. A missing anchor at that
/// epoch, one that restores another epoch, or an older anchor still stored
/// makes it selectable again, and a group the engine does not hold is an
/// error.
#[tokio::test]
async fn a_key_is_selectable_until_no_selectable_epoch_can_hold_it() {
    let mut phone = roster_device(b"alice");
    let mut laptop = roster_device(b"alice");
    let gid = found_device_group(
        &mut phone,
        &roster(&[(1, "Phone"), (2, "Laptop")]),
        &mut [&mut laptop],
    )
    .await;
    let key = [7; 32];
    let selectable = |device: &Device| device.engine.recovery_key_selectable(&gid, &key).unwrap();

    // The phone sets the key and the laptop turns backups off.
    let on = set_account(&phone, &gid, 1, 7);
    let on = send_commit(&mut phone, on, &gid).await;
    let held_from = tip(&phone, &gid);
    assert!(selectable(&phone));
    assert_accepted(&mut laptop, &on, &gid).await;
    let off = SendIntent::ReplaceAccountEntry {
        group_id: gid.clone(),
        expected: Box::new(account(1, 7)),
        entry: Box::new(AccountEntryV1::default()),
    };
    let off = send_commit(&mut laptop, off, &gid).await;
    assert_accepted(&mut phone, &off, &gid).await;
    assert!(retained(&phone, &gid));
    assert!(selectable(&phone));

    // Past the commit's horizon, its record is gone, and the oldest
    // selectable epoch is the one that held the key.
    while tip(&phone, &gid) < held_from + V1_MAX_REWIND_COMMITS {
        assert!(selectable(&phone));
        self_update(&mut phone, &gid).await;
    }
    phone
        .engine
        .reissue_superseded_own_commits_from_state()
        .unwrap();
    assert!(!retained(&phone, &gid));
    assert!(
        selectable(&phone),
        "the oldest selectable epoch held the key"
    );

    // One epoch further, no selectable epoch held it.
    self_update(&mut phone, &gid).await;
    let oldest = tip(&phone, &gid) - V1_MAX_REWIND_COMMITS;
    assert!(!selectable(&phone));

    // An older anchor still stored.
    let stray = anchor(oldest - 1);
    phone.storage.create_group_snapshot(&gid, &stray).unwrap();
    assert!(selectable(&phone), "an older anchor is stored");
    phone.storage.release_group_snapshot(&gid, &stray).unwrap();
    assert!(!selectable(&phone));

    // The oldest selectable epoch's anchor restores another epoch.
    phone
        .storage
        .release_group_snapshot(&gid, &anchor(oldest))
        .unwrap();
    phone
        .storage
        .create_group_snapshot(&gid, &anchor(oldest))
        .unwrap();
    assert!(selectable(&phone), "the anchor restores another epoch");

    // The oldest selectable epoch's anchor is missing.
    phone
        .storage
        .release_group_snapshot(&gid, &anchor(oldest))
        .unwrap();
    assert!(selectable(&phone), "the anchor is missing");

    // A group the engine does not hold.
    assert!(
        phone
            .engine
            .recovery_key_selectable(&GroupId::new(vec![0x6b; 16]), &key)
            .is_err()
    );
}

/// A group younger on this device than the rewind horizon holds no anchor
/// for the oldest epoch a branch can fork from, so any key is selectable:
/// the founder never stored one for the group's first epoch, and the device
/// it added none before it joined.
#[tokio::test]
async fn every_key_is_selectable_in_a_group_younger_than_the_horizon() {
    let mut phone = roster_device(b"alice");
    let mut laptop = roster_device(b"alice");
    let gid = found_device_group(
        &mut phone,
        &roster(&[(1, "Phone"), (2, "Laptop")]),
        &mut [&mut laptop],
    )
    .await;
    for device in [&phone, &laptop] {
        assert!(tip(device, &gid) < V1_MAX_REWIND_COMMITS);
        assert!(!retained(device, &gid));
        assert!(
            device
                .engine
                .recovery_key_selectable(&gid, &[9; 32])
                .unwrap()
        );
    }
}
