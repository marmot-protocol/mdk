//! A kept recovery answer holds exactly while none of its inputs moved
//! (mdk#3273 decision 3). Each validity field has its own test: moving only
//! that field's input makes the next publish rebuild, and the rebuilt answer
//! is the live one; with the field left out of `read_holds` or
//! `status_holds`, the kept answer would be published instead. Every publish
//! here compares its answer with the live one, as A's oracle does.

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Arc;

use cgka_traits::GroupId;
use marmot_session::ChangeStamp;
use storage_sqlite::{SqliteAppStorage, TransportReconciliationRoute};

use super::super::ledger_tests::{catching_up, fixture, rejoin};
use super::super::{Fact, GroupFacts, LiveFacts};
use super::{RecoveryAnswer, RecoveryInputs};
use crate::client::AppClient;
use crate::{AccountRecoveryStatus, AppError};

/// A group's change stamp now, while the group is in the mirror.
fn stamp_now(client: &AppClient, group_id: &[u8]) -> Option<ChangeStamp> {
    let hex = hex::encode(group_id);
    client
        .state
        .groups
        .iter()
        .any(|record| record.group_id_hex == hex)
        .then(|| {
            client
                .runtime
                .group_change_generations([&GroupId::new(group_id.to_vec())])
                .pop()
                .map(|generation| generation.state)
        })
        .flatten()
}

/// Facts as A's group entries give them: a mirror group's stamp read before
/// its facts, the facts read live. `outside` reads as a group outside the
/// mirror and `unsettled` as a group whose checks failed on something other
/// than a fact about it.
#[derive(Default)]
struct EntryFacts<'a> {
    client: Option<&'a AppClient>,
    stamps: RefCell<HashMap<Vec<u8>, Option<ChangeStamp>>>,
    outside: Option<Vec<u8>>,
    unsettled: Option<Vec<u8>>,
}

impl<'a> EntryFacts<'a> {
    fn of(client: &'a AppClient) -> Self {
        Self {
            client: Some(client),
            ..Self::default()
        }
    }

    fn client(&self) -> &'a AppClient {
        self.client.unwrap()
    }

    fn settle(&self, group_id: &[u8], mut fact: Fact) -> Fact {
        self.stamp(group_id);
        if self.unsettled.as_deref() == Some(group_id) {
            fact.settled = false;
        }
        fact
    }
}

impl GroupFacts for EntryFacts<'_> {
    fn host_may_see(&self, group_id: &[u8]) -> Fact {
        self.stamp(group_id);
        self.settle(group_id, LiveFacts(self.client()).host_may_see(group_id))
    }

    fn unrecoverable(&self, group_id: &[u8]) -> Fact {
        self.stamp(group_id);
        self.settle(group_id, LiveFacts(self.client()).unrecoverable(group_id))
    }

    fn stamp(&self, group_id: &[u8]) -> Option<ChangeStamp> {
        if self.outside.as_deref() == Some(group_id) {
            return None;
        }
        self.stamps
            .borrow_mut()
            .entry(group_id.to_vec())
            .or_insert_with(|| stamp_now(self.client(), group_id))
            .clone()
    }
}

/// One publish as A runs it: the inputs first; the kept read while it
/// holds, else a fresh one; the kept status while it holds too, else one
/// built with `facts`. The answer published is compared with the live one
/// either way. Returns whether the status was built.
fn publish_with<'a>(
    client: &'a AppClient,
    kept: &mut Option<RecoveryAnswer>,
    facts: impl FnOnce(&'a AppClient) -> EntryFacts<'a>,
) -> bool {
    let inputs = client.recovery_inputs();
    let stamp = |group_id: &[u8]| stamp_now(client, group_id);
    let (answer, built) = match kept.take() {
        Some(answer) if answer.read_holds(&inputs) && answer.status_holds(&stamp) => {
            (answer, false)
        }
        Some(answer) if answer.read_holds(&inputs) => (answer.refresh(&facts(client)), true),
        _ => (
            RecoveryAnswer::build(
                inputs,
                client.read_recovery().map_err(Arc::new),
                &facts(client),
            ),
            true,
        ),
    };
    assert_eq!(differs(&answer, client), None);
    *kept = Some(answer);
    built
}

/// How the answer's own status differs from the live one now.
fn differs(answer: &RecoveryAnswer, client: &AppClient) -> Option<&'static str> {
    answer.differs_from_live(answer.status(), &client.account_recovery_status())
}

fn publish(client: &AppClient, kept: &mut Option<RecoveryAnswer>) -> bool {
    publish_with(client, kept, EntryFacts::of)
}

fn status(kept: &Option<RecoveryAnswer>) -> &AccountRecoveryStatus {
    kept.as_ref().unwrap().status().as_ref().unwrap()
}

/// Park an epoch-gap notice for `group`.
fn park_gap(client: &AppClient, app: &SqliteAppStorage, group: &GroupId) {
    app.arm_epoch_backfill_intents(&[storage_sqlite::StoredEpochBackfillIntent {
        group_id_hex: hex::encode(group.as_slice()),
        stalled_epoch: client.group_mls_state(group).unwrap().epoch,
    }])
    .unwrap();
    let storage = client.app.account_storage("alice").unwrap();
    for demand in app.pending_recovery_demands().unwrap() {
        if demand.group_id.as_deref() == Some(group.as_slice()) {
            super::super::park_recovery_for_test(&storage, demand.ticket.id);
        }
    }
}

/// What else the answer reads, to show a move changed only one field.
struct Others {
    inputs: RecoveryInputs,
    stamp: Option<ChangeStamp>,
}

impl Others {
    fn now(client: &AppClient, group: &GroupId) -> Self {
        Self {
            inputs: client.recovery_inputs(),
            stamp: stamp_now(client, group.as_slice()),
        }
    }
}

/// An answer that names a parked notice holds until a recovery obligation is
/// written: rewriting only the row's parked time, which the notice shows,
/// moves the recovery-notice write count alone, and the next publish
/// rebuilds.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_recovery_notice_write_ends_the_kept_answer() {
    let dir = tempfile::tempdir().unwrap();
    let (client, app, group, _) = fixture(&dir).await;
    park_gap(&client, &app, &group);
    let mut kept = None;
    assert!(publish(&client, &mut kept));
    assert!(!publish(&client, &mut kept), "nothing moved");
    let parked_at = status(&kept).notices[0].parked_at_ms;

    let before = Others::now(&client, &group);
    app.execute_batch_for_test(
        "UPDATE account_recovery_obligations SET parked_at_ms = parked_at_ms + 1000
         WHERE parked_at_ms IS NOT NULL",
    )
    .unwrap();
    let after = Others::now(&client, &group);
    assert_ne!(after.inputs.notice_writes, before.inputs.notice_writes);
    assert_eq!(after.inputs.routes, before.inputs.routes);
    assert!(after.stamp.unwrap().unchanged_since(&before.stamp.unwrap()));
    assert!(publish(&client, &mut kept));
    assert_eq!(
        status(&kept).notices[0].parked_at_ms,
        parked_at.map(|at| at + 1000)
    );
}

/// An answer that shows a rejoin notice holds until the routes change: the
/// group losing its routes in memory moves the routing version alone, and
/// the next publish rebuilds without the notice.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_route_change_ends_the_kept_answer() {
    let dir = tempfile::tempdir().unwrap();
    let (client, app, group, route) = fixture(&dir).await;
    rejoin(&app, &group, &route);
    let mut kept = None;
    assert!(publish(&client, &mut kept));
    assert!(!publish(&client, &mut kept), "nothing moved");
    assert_eq!(status(&kept).notices.len(), 1);
    let read = |kept: &Option<RecoveryAnswer>| {
        kept.as_ref()
            .unwrap()
            .read()
            .ok()
            .unwrap()
            .group_notices(&group)
            .clone()
    };
    let notices = read(&kept);

    let before = Others::now(&client, &group);
    assert!(client.routing.replace_group_routes(&group, Vec::new()));
    let after = Others::now(&client, &group);
    assert_ne!(after.inputs.routes, before.inputs.routes);
    assert_eq!(after.inputs.notice_writes, before.inputs.notice_writes);
    assert!(after.stamp.unwrap().unchanged_since(&before.stamp.unwrap()));
    assert!(publish(&client, &mut kept));
    assert!(status(&kept).notices.is_empty());
    assert!(
        read(&kept) != notices,
        "A compares each group's notices from the same read"
    );
}

/// An answer holds until the runner's survey changes what is catching up:
/// a survey alone ends it, and the next publish rebuilds with the new set.
/// The oracle's window would hide the kept answer here, so the rebuild is
/// what shows the survey is in the validity.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_survey_ends_the_kept_answer() {
    let dir = tempfile::tempdir().unwrap();
    let (client, _app, group, route) = fixture(&dir).await;
    catching_up(&client, &[&route]);
    let mut kept = None;
    assert!(publish(&client, &mut kept));
    assert!(!publish(&client, &mut kept), "nothing moved");
    assert_eq!(
        status(&kept).catching_up_group_ids_hex,
        vec![hex::encode(group.as_slice())]
    );

    let before = Others::now(&client, &group);
    catching_up(&client, &[]);
    let after = Others::now(&client, &group);
    assert_eq!(after.inputs, before.inputs);
    assert!(after.stamp.unwrap().unchanged_since(&before.stamp.unwrap()));
    assert!(publish(&client, &mut kept));
    assert!(status(&kept).catching_up_group_ids_hex.is_empty());
    assert_eq!(
        status(&kept),
        &client.account_recovery_status().unwrap(),
        "strictly the live status, no window"
    );
}

/// A terminal close between the recovery snapshot and its group-visibility
/// read must fail the status, rather than succeed with a catching-up group
/// silently hidden (mdk#3451). No survey changes during this read.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_close_during_recovery_facts_fails_the_status() {
    struct ClosingFacts<'a>(&'a AppClient);

    impl GroupFacts for ClosingFacts<'_> {
        fn host_may_see(&self, group_id: &[u8]) -> Fact {
            self.0.app.close_storage().unwrap();
            LiveFacts(self.0).host_may_see(group_id)
        }

        fn unrecoverable(&self, group_id: &[u8]) -> Fact {
            LiveFacts(self.0).unrecoverable(group_id)
        }

        fn stamp(&self, _group_id: &[u8]) -> Option<ChangeStamp> {
            None
        }
    }

    let dir = tempfile::tempdir().unwrap();
    let (client, _app, group, route) = fixture(&dir).await;
    catching_up(&client, &[&route]);
    assert_eq!(
        client
            .account_recovery_status()
            .unwrap()
            .catching_up_group_ids_hex,
        vec![hex::encode(group.as_slice())]
    );
    let answer = RecoveryAnswer::build(
        client.recovery_inputs(),
        client.read_recovery().map_err(Arc::new),
        &ClosingFacts(&client),
    );
    assert!(!answer.read().unwrap().survey().landed_since());
    assert!(
        matches!(answer.status(), Err(error)
            if matches!(error.as_ref(), AppError::Storage(cgka_traits::StorageError::Closed(_)))),
        "a close inside the visibility read must be reported: {:?}",
        answer.status()
    );
}

/// An answer that names a group holds until the group's change generation
/// moves: the group turning device group moves its stamp alone, and the next
/// publish rebuilds with its notice hidden.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_named_groups_change_ends_the_kept_answer() {
    let dir = tempfile::tempdir().unwrap();
    let (client, app, group, _) = fixture(&dir).await;
    park_gap(&client, &app, &group);
    let mut kept = None;
    assert!(publish(&client, &mut kept));
    assert!(!publish(&client, &mut kept), "nothing moved");
    assert_eq!(status(&kept).notices.len(), 1);

    let before = Others::now(&client, &group);
    assert!(
        app.insert_device_group(&storage_sqlite::DeviceGroupRecord {
            group_id_hex: hex::encode(group.as_slice()),
            trust: storage_sqlite::DeviceGroupTrust::Untrusted,
            key_package_ref_hex: None,
            recorded_at: crate::unix_now_seconds(),
        })
        .unwrap()
    );
    let after = Others::now(&client, &group);
    assert_eq!(after.inputs, before.inputs);
    assert!(!after.stamp.unwrap().unchanged_since(&before.stamp.unwrap()));
    assert!(publish(&client, &mut kept));
    assert!(status(&kept).notices.is_empty());
}

/// An answer is never kept when it names a group outside the mirror, used a
/// fact whose check failed on something other than a fact about the group,
/// or came from a failed read: each can change with no input moving.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_answer_that_can_change_unseen_is_never_kept() {
    let dir = tempfile::tempdir().unwrap();
    let (client, app, group, _) = fixture(&dir).await;
    park_gap(&client, &app, &group);
    let id = group.as_slice().to_vec();
    let outside = |client| EntryFacts {
        outside: Some(id.clone()),
        ..EntryFacts::of(client)
    };
    let unsettled = |client| EntryFacts {
        unsettled: Some(id.clone()),
        ..EntryFacts::of(client)
    };
    let mut kept = None;
    assert!(publish_with(&client, &mut kept, outside));
    assert!(
        publish_with(&client, &mut kept, outside),
        "outside the mirror"
    );
    kept = None;
    assert!(publish_with(&client, &mut kept, unsettled));
    assert!(
        publish_with(&client, &mut kept, unsettled),
        "an unsettled fact"
    );
    assert!(publish(&client, &mut kept));
    assert!(
        !publish(&client, &mut kept),
        "settled mirror facts are kept"
    );

    let failed = RecoveryAnswer::build(
        client.recovery_inputs(),
        Err(Arc::new(AppError::RuntimeBusy)),
        &EntryFacts::of(&client),
    );
    assert!(!failed.read_holds(&client.recovery_inputs()));
}

/// The oracle compares the notices strictly, and what is catching up
/// strictly unless a survey changed it after the answer's read (mdk#3273 decision 2):
/// with no survey since, a wrong catching-up set fails it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_oracle_excuses_only_a_catching_up_set_a_later_survey_changed() {
    let dir = tempfile::tempdir().unwrap();
    let (client, app, group, route) = fixture(&dir).await;
    park_gap(&client, &app, &group);
    let answer = |client: &AppClient| {
        RecoveryAnswer::build(
            client.recovery_inputs(),
            client.read_recovery().map_err(Arc::new),
            &EntryFacts::of(client),
        )
    };
    let wrong = |mut answer: RecoveryAnswer, edit: fn(&mut AccountRecoveryStatus)| {
        if let Ok(status) = &mut answer.status {
            edit(Arc::make_mut(status));
        }
        answer
    };
    let catching = |status: &mut AccountRecoveryStatus| {
        status.catching_up_group_ids_hex = vec!["00".repeat(16)];
    };
    let inbox = |status: &mut AccountRecoveryStatus| status.inbox_catching_up = true;
    let notices = |status: &mut AccountRecoveryStatus| status.notices.clear();

    assert_eq!(differs(&answer(&client), &client), None);
    for edit in [catching, inbox] {
        assert_eq!(
            differs(&wrong(answer(&client), edit), &client),
            Some("catching up")
        );
    }
    assert_eq!(
        differs(&wrong(answer(&client), notices), &client),
        Some("history notices")
    );

    let (catching_up_answer, inbox_answer, notices_answer) = (
        wrong(answer(&client), catching),
        wrong(answer(&client), inbox),
        wrong(answer(&client), notices),
    );
    catching_up(&client, &[&route, &TransportReconciliationRoute::Inbox]);
    assert_eq!(differs(&catching_up_answer, &client), None);
    assert_eq!(differs(&inbox_answer, &client), None);
    assert_eq!(differs(&notices_answer, &client), Some("history notices"));
}

/// A publish builds each group's recovery status from the account's
/// recovery read, so a group whose notices in the read changed is rebuilt
/// though nothing the group holds was written: here its routes go in
/// memory, which hides its rejoin notice and moves no write of the group.
/// A publish that moved nothing keeps the group's entry and the account's
/// answer. With the notices left out of the entry's validity, the stale
/// entry would be published, and the oracle that compares every publish
/// with the live reads fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_groups_notices_alone_rebuild_its_entry() {
    use crate::client::read_state::{GroupAnswers, UploadsInFlight, read_state_channel};

    let dir = tempfile::tempdir().unwrap();
    let (mut client, app, group, route) = fixture(&dir).await;
    rejoin(&app, &group, &route);
    client.start_read_state(read_state_channel().0, UploadsInFlight::default());
    let state = client.subscribe_read_state().unwrap();
    let entry = || Arc::clone(&state.borrow().groups[&group]);
    let ids = |entry: &GroupAnswers| {
        entry
            .recovery_status
            .as_ref()
            .unwrap()
            .history_notice_ids
            .clone()
    };
    let kept_status = || client.read_state_recovery_status().unwrap().unwrap();
    let noticed = entry();
    assert_eq!(ids(&noticed).len(), 1);
    let status = kept_status();
    assert_eq!(status.notices.len(), 1);

    client.publish_read_state();
    assert!(Arc::ptr_eq(&noticed, &entry()), "nothing moved");
    assert!(Arc::ptr_eq(&status, &kept_status()), "nothing moved");

    let before = Others::now(&client, &group);
    assert!(client.routing.replace_group_routes(&group, Vec::new()));
    let after = Others::now(&client, &group);
    assert!(after.stamp.unwrap().unchanged_since(&before.stamp.unwrap()));
    client.publish_read_state();
    let hidden = entry();
    assert!(!Arc::ptr_eq(&noticed, &hidden), "the notices moved");
    assert!(ids(&hidden).is_empty());
    assert!(kept_status().notices.is_empty());
    assert_eq!(
        hidden.recovery_status.as_ref().unwrap(),
        &client.group_recovery_status(&group).unwrap()
    );
}
