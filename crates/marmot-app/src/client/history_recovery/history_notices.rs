//! Worker-owned "history may be incomplete" notices and their explicit,
//! user-authorized retirement. Retirement is recorded as its own outcome,
//! never as coverage.
//!
//! Each rejoin raises a notice too ([`RejoinNotice`], mdk#2660 row 11), and
//! the account's recovery status reads what the recovery runner is catching
//! up (mdk#2660 phase 4). What the coverage ledger parks raises none: a
//! notice needs evidence that messages are missing or an action that helps,
//! and the runner probes its broken units quietly (mdk#3308).
use std::collections::{BTreeMap, BTreeSet, HashMap};

use cgka_traits::GroupId;
use storage_sqlite::{
    ParkedRecoveryObligation, RecoveryDemandTicket, SqliteAppStorage, TransportReconciliationRoute,
};

use crate::client::AppClient;
use crate::client::history_recovery::recovery_runner::UnitKey;
use crate::history_notices::{
    decode_notice_id, encode_notice_id, history_notice, rejoin_group_tag,
};
use crate::{AccountRecoveryStatus, AppError, HistoryNotice, HistoryNoticeCause};

/// One group's rejoin: one `BeforeRejoin` notice, whose ticket is the
/// group's tag and the notice's revision. Dismissing it retires nothing
/// further: the rejoin already retired what lay before the new copy. Not
/// `Debug`: it carries its group.
pub(crate) struct RejoinNotice {
    group_id: Vec<u8>,
    ticket: RecoveryDemandTicket,
    noticed_at_seconds: u64,
}

impl RejoinNotice {
    fn notice(&self) -> HistoryNotice {
        HistoryNotice {
            notice_id: encode_notice_id(self.ticket),
            cause: HistoryNoticeCause::BeforeRejoin,
            group_id_hex: Some(hex::encode(&self.group_id)),
            parked_at_ms: Some(self.noticed_at_seconds.saturating_mul(1000)),
        }
    }
}

/// The parked set as last announced: each occurrence's obligation id and
/// revision, with its group for group-scoped demand.
pub(crate) type HistoryNoticeBaseline = Vec<([u8; 16], u64, Option<Vec<u8>>)>;

/// What a group's notices depend on beyond a [`RecoveryRead`]: whether the
/// host may see the group, and whether its copy is Unrecoverable. Both read
/// only the group's own state, which its change generation counts, so A takes
/// them from the group's published entry (mdk#3273); [`LiveFacts`] reads them
/// now.
pub(crate) trait GroupFacts {
    fn host_may_see(&self, group_id: &[u8]) -> bool;
    fn unrecoverable(&self, group_id: &[u8]) -> bool;
}

/// [`GroupFacts`] read from the client when asked.
pub(crate) struct LiveFacts<'a>(pub(crate) &'a AppClient);

impl GroupFacts for LiveFacts<'_> {
    fn host_may_see(&self, group_id: &[u8]) -> bool {
        self.0.host_may_see_group(&GroupId::new(group_id.to_vec()))
    }

    fn unrecoverable(&self, group_id: &[u8]) -> bool {
        self.0.group_unrecoverable(group_id)
    }
}

/// One read of what the account's recovery answers come from: the parked
/// set, each rejoin's notice not yet dismissed whose group has a current
/// route, and the runner's last survey. It reads no group's state, which
/// [`GroupFacts`] supply, so A reads it at every publish for the cost of two
/// queries (mdk#3273). Not `Debug`: it carries groups.
pub(crate) struct RecoveryRead {
    parked: Vec<ParkedRecoveryObligation>,
    rejoins: Vec<RejoinNotice>,
    /// Each group's parked occurrences, oldest first, and its rejoin's.
    by_group: HashMap<Vec<u8>, GroupNotices>,
    /// The groups whose routes the survey found catching up, and whether the
    /// inbox's was.
    catching_up: BTreeSet<Vec<u8>>,
    inbox_catching_up: bool,
    survey: SurveyMark,
}

/// One group's occurrences in a [`RecoveryRead`], before any [`GroupFacts`]
/// apply: its parked ids oldest first, and its rejoin notice's id. A compares
/// them with those a group's published entry was built at, so a group whose
/// notices changed is rebuilt even when nothing it holds was written: a
/// parked or dismissed occurrence, a route gone (mdk#3273). The facts need no
/// comparison: what moves them moves the group's change generation.
#[derive(Clone, Default, PartialEq, Eq)]
pub(crate) struct GroupNotices {
    parked: Vec<String>,
    rejoin: Option<String>,
}

/// The runner's survey as a [`RecoveryRead`] read it. The runner's task
/// writes its survey off the worker, so a later live read can list other
/// groups catching up than answers built before it without either being
/// wrong. Only a survey that changed the set counts: the runner sends none
/// that would not (mdk#3273).
pub(crate) struct SurveyMark(tokio::sync::watch::Receiver<Option<BTreeSet<UnitKey>>>);

#[cfg_attr(not(test), allow(dead_code))] // A's oracle reads it (mdk#3273 PR 8).
impl SurveyMark {
    /// Whether a survey changed what is catching up since the read. A
    /// runner's watch gone counts as changed.
    pub(crate) fn landed_since(&self) -> bool {
        self.0.has_changed().unwrap_or(true)
    }
}

impl RecoveryRead {
    /// Every current occurrence the host may see: parked obligations oldest
    /// first, then rejoins oldest first.
    pub(crate) fn notices(&self, facts: &dyn GroupFacts) -> Vec<HistoryNotice> {
        let parked = self.parked.iter().filter(|parked| {
            parked
                .group_id
                .as_deref()
                .is_none_or(|group_id| facts.host_may_see(group_id))
        });
        let rejoins = self.rejoins.iter().filter(|notice| shown(notice, facts));
        parked
            .map(history_notice)
            .chain(rejoins.map(RejoinNotice::notice))
            .collect()
    }

    /// The account's recovery status: its notices, and the groups and inbox
    /// the runner's last survey found catching up. Until a runner has
    /// surveyed, nothing is.
    pub(crate) fn account_status(&self, facts: &dyn GroupFacts) -> AccountRecoveryStatus {
        AccountRecoveryStatus {
            notices: self.notices(facts),
            catching_up_group_ids_hex: self
                .catching_up
                .iter()
                .filter(|group_id| facts.host_may_see(group_id))
                .map(hex::encode)
                .collect(),
            inbox_catching_up: self.inbox_catching_up,
        }
    }

    /// The group's notice ids: its own parked occurrences oldest first, the
    /// host's view of its group aside, then its rejoin's while shown.
    pub(crate) fn group_notice_ids(
        &self,
        group_id: &GroupId,
        facts: &dyn GroupFacts,
    ) -> Vec<String> {
        let Some(notices) = self.by_group.get(group_id.as_slice()) else {
            return Vec::new();
        };
        let rejoin = notices.rejoin.as_ref().filter(|_| {
            !facts.unrecoverable(group_id.as_slice()) && facts.host_may_see(group_id.as_slice())
        });
        notices.parked.iter().chain(rejoin).cloned().collect()
    }

    /// The group's occurrences before any facts apply, as A compares them.
    #[cfg_attr(not(test), allow(dead_code))] // A compares them at every publish (mdk#3273 PR 8).
    pub(crate) fn group_notices(&self, group_id: &GroupId) -> GroupNotices {
        self.by_group
            .get(group_id.as_slice())
            .cloned()
            .unwrap_or_default()
    }

    #[cfg_attr(not(test), allow(dead_code))] // A's oracle reads it (mdk#3273 PR 8).
    pub(crate) fn survey(&self) -> &SurveyMark {
        &self.survey
    }
}

/// A rejoin's notice shows while its copy is not Unrecoverable (as the
/// runner's routes say) and the host may see its group.
fn shown(notice: &RejoinNotice, facts: &dyn GroupFacts) -> bool {
    !facts.unrecoverable(&notice.group_id) && facts.host_may_see(&notice.group_id)
}

impl AppClient {
    /// Every current occurrence: parked obligations oldest first, then
    /// rejoins oldest first.
    pub(crate) fn history_notices(&self) -> Result<Vec<HistoryNotice>, AppError> {
        Ok(self.read_recovery()?.notices(&LiveFacts(self)))
    }

    /// The account's recovery status ([`RecoveryRead::account_status`]).
    pub(crate) fn account_recovery_status(&self) -> Result<AccountRecoveryStatus, AppError> {
        Ok(self.read_recovery()?.account_status(&LiveFacts(self)))
    }

    /// Read what the recovery answers come from ([`RecoveryRead`]). The
    /// routes are read only when a rejoin notice or a unit catching up needs
    /// them, and without any group's record.
    pub(crate) fn read_recovery(&self) -> Result<RecoveryRead, AppError> {
        let app = self.app.account_storage(&self.state.label)?.app_storage();
        let parked = app.parked_recovery_obligations()?;
        let rejoin_rows = app.recovery_rejoin_notices()?;
        let mut survey = self.routing.subscribe_recovery_runner_catching_up();
        let units = survey
            .borrow_and_update()
            .clone()
            .filter(|units| !units.is_empty());
        let routes = if rejoin_rows.is_empty() && units.is_none() {
            BTreeMap::new()
        } else {
            self.current_route_groups().into_iter().collect()
        };
        let routed = routes.values().flatten().collect::<BTreeSet<_>>();
        let rejoins = rejoin_rows
            .into_iter()
            .filter(|notice| routed.contains(&notice.group_id))
            .map(|notice| RejoinNotice {
                ticket: RecoveryDemandTicket {
                    id: rejoin_group_tag(&notice.group_id),
                    revision: notice.revision,
                },
                group_id: notice.group_id,
                noticed_at_seconds: notice.noticed_at_seconds,
            })
            .collect::<Vec<_>>();
        let mut by_group = HashMap::<Vec<u8>, GroupNotices>::new();
        for parked in &parked {
            if let Some(group_id) = &parked.group_id {
                by_group
                    .entry(group_id.clone())
                    .or_default()
                    .parked
                    .push(encode_notice_id(parked.ticket));
            }
        }
        for notice in &rejoins {
            by_group.entry(notice.group_id.clone()).or_default().rejoin =
                Some(encode_notice_id(notice.ticket));
        }
        let mut catching_up = BTreeSet::new();
        let mut inbox_catching_up = false;
        for unit in units.into_iter().flatten() {
            if unit.route == TransportReconciliationRoute::Inbox {
                inbox_catching_up = true;
            } else if let Some(Some(group_id)) = routes.get(&unit.route) {
                catching_up.insert(group_id.clone());
            }
        }
        Ok(RecoveryRead {
            parked,
            rejoins,
            by_group,
            catching_up,
            inbox_catching_up,
            survey: SurveyMark(survey),
        })
    }

    /// Each rejoin's notice the host is shown, oldest first.
    fn rejoin_notices(&self) -> Result<Vec<RejoinNotice>, AppError> {
        let read = self.read_recovery()?;
        let facts = LiveFacts(self);
        Ok(read
            .rejoins
            .into_iter()
            .filter(|notice| shown(notice, &facts))
            .collect())
    }

    /// Whether hosts are owed a `RecoveryStatusChanged`: the runner's survey
    /// changed what is catching up ([`AppClient::recovery_status_owed`]), or `notices_changed`. Every
    /// survey change counts, even one a later survey undid, so a host never
    /// keeps a state it read in between.
    pub(crate) fn take_recovery_status_changed(&mut self, notices_changed: bool) -> bool {
        let owed = std::mem::take(&mut self.history_recovery.state.recovery_status_owed);
        owed || notices_changed
    }

    /// Retire exactly the dismissed occurrence as "history may be incomplete".
    /// Returns false, changing nothing, when the notice is stale: new evidence
    /// re-armed recovery (it is then pending again or a new occurrence), it
    /// was already dismissed, or it is a coverage-ledger notice an earlier
    /// release showed, which no longer exists.
    pub(crate) fn dismiss_history_notice(&mut self, notice_id: &str) -> Result<bool, AppError> {
        let ticket = decode_notice_id(notice_id)?;
        let storage = self.app.account_storage(&self.state.label)?;
        let app = storage.app_storage();
        // Newer loss joins the ledger first, and an unconverted account
        // converts, so a dismissal reads the notices hosts are shown.
        self.synchronize_recovery_loss(&app)?;
        let Some((cause, group)) = app
            .parked_recovery_obligations()?
            .into_iter()
            .find(|parked| parked.ticket == ticket)
            .map(|parked| (parked.cause, parked.group_id))
        else {
            if let Some(notice) = self
                .rejoin_notices()?
                .into_iter()
                .find(|notice| notice.ticket == ticket)
            {
                return self.dismiss_rejoin_notice(&app, &notice);
            }
            tracing::debug!(
                target: "marmot_app::recovery",
                method = "dismiss_history_notice",
                "history notice was stale; nothing retired",
            );
            return Ok(false);
        };
        if !app.retire_parked_recovery_obligation(
            ticket.id,
            ticket.revision,
            crate::client::recovery::wall_now_ms()?,
        )? {
            tracing::debug!(
                target: "marmot_app::recovery",
                method = "dismiss_history_notice",
                "history notice became stale during retirement; nothing retired",
            );
            return Ok(false);
        }
        self.wake_recovery_runner();
        self.record_need_changed(
            group.map(GroupId::new).as_ref(),
            crate::client::audit_recovery::obligation_cause(cause),
            marmot_forensics::RecoveryNeedChange::NoticeDismissed,
            ticket,
            None,
            None,
            None,
        );
        tracing::info!(
            target: "marmot_app::recovery",
            method = "dismiss_history_notice",
            cause = HistoryNoticeCause::from_recovery(cause).as_str(),
            remaining_notices = app.parked_recovery_obligations()
                .map_or(0, |parked| parked.len()),
            "retired a parked recovery occurrence; its history may be incomplete",
        );
        Ok(true)
    }

    /// Dismiss a rejoin's notice. It retires nothing: the rejoin already
    /// retired what lay before the new copy. Not audited: the forensic
    /// recovery vocabulary has no rejoin cause. Returns false when the notice
    /// went stale meanwhile.
    fn dismiss_rejoin_notice(
        &mut self,
        app: &SqliteAppStorage,
        notice: &RejoinNotice,
    ) -> Result<bool, AppError> {
        let dismissed =
            app.dismiss_recovery_rejoin_notice(&notice.group_id, notice.ticket.revision)?;
        tracing::info!(
            target: "marmot_app::recovery",
            method = "dismiss_history_notice",
            cause = HistoryNoticeCause::BeforeRejoin.as_str(),
            dismissed,
            "dismissed a rejoin notice; nothing more retired",
        );
        Ok(dismissed)
    }

    /// Re-read the parked set and return the groups whose own occurrences
    /// changed since the last call, or `None` when nothing changed. The first
    /// call only records the baseline. A failed read keeps the old baseline,
    /// so the next publication seam retries. An upgrade conversion that
    /// changed the notices is announced once, even when the set reads the
    /// same.
    pub(crate) fn take_history_notice_changes(&mut self) -> Option<Vec<GroupId>> {
        let mut causes = Vec::new();
        let mut converted = None;
        let current: HistoryNoticeBaseline = match self
            .app
            .account_storage(&self.state.label)
            .and_then(|storage| {
                let app = storage.app_storage();
                let parked = app.parked_recovery_obligations()?;
                let rejoins = self.rejoin_notices()?;
                if !app.recovery_conversion_pending()?
                    && app.recovery_conversion_notices_changed()?
                {
                    converted = Some(app);
                }
                Ok((parked, rejoins))
            }) {
            Ok((parked, rejoins)) => parked
                .into_iter()
                .map(|parked| {
                    let cause = crate::client::audit_recovery::obligation_cause(parked.cause);
                    (parked.ticket, parked.group_id, cause)
                })
                .map(|(ticket, group, cause)| {
                    causes.push((ticket.id, cause));
                    (ticket.id, ticket.revision, group)
                })
                // A rejoin has no forensic cause, so it shows unaudited.
                .chain(rejoins.into_iter().map(|notice| {
                    (
                        notice.ticket.id,
                        notice.ticket.revision,
                        Some(notice.group_id),
                    )
                }))
                .collect(),
            Err(_) => {
                tracing::debug!(
                    target: "marmot_app::recovery",
                    method = "take_history_notice_changes",
                    "history notice read failed; retrying at the next seam",
                );
                return None;
            }
        };
        // The announcement is the caller's, right after this; once the
        // baseline is set a lost one is only a missed event, and hosts read
        // the notices after every open.
        if let Some(app) = &converted
            && app.acknowledge_recovery_conversion_notices().is_err()
        {
            tracing::debug!(
                target: "marmot_app::recovery",
                method = "take_history_notice_changes",
                "conversion notice acknowledgement failed; announcing again at the next seam",
            );
        }
        let announce_all = converted.is_some();
        let previous = self
            .history_recovery
            .state
            .history_notice_baseline
            .replace(current)?;
        let current = self
            .history_recovery
            .state
            .history_notice_baseline
            .as_ref()?;
        if previous == *current && !announce_all {
            return None;
        }
        self.record_history_notice_changes(&previous, &causes);
        let current = self
            .history_recovery
            .state
            .history_notice_baseline
            .as_ref()?;
        let mut groups = previous
            .iter()
            .filter(|entry| announce_all || !current.contains(entry))
            .chain(
                current
                    .iter()
                    .filter(|entry| announce_all || !previous.contains(entry)),
            )
            .filter_map(|(_, _, group)| group.clone())
            .collect::<Vec<_>>();
        groups.sort();
        groups.dedup();
        Some(
            groups
                .into_iter()
                .map(GroupId::new)
                .filter(|group_id| self.host_may_see_group(group_id))
                .collect(),
        )
    }
}

impl AppClient {
    /// Audit the notice set's transitions: each newly parked obligation is a
    /// shown notice. Withdrawals are
    /// recorded where they happen: a dismissal, or new evidence resuming the
    /// demand.
    fn record_history_notice_changes(
        &self,
        previous: &HistoryNoticeBaseline,
        causes: &[([u8; 16], marmot_forensics::RecoveryObligationCause)],
    ) {
        if !self.audit_v5_enabled() {
            return;
        }
        let Some(current) = self.history_recovery.state.history_notice_baseline.as_ref() else {
            return;
        };
        for (id, revision, group) in current.iter().filter(|entry| !previous.contains(entry)) {
            let Some((_, cause)) = causes.iter().find(|(parked, _)| parked == id) else {
                continue;
            };
            self.record_need_changed(
                group.clone().map(GroupId::new).as_ref(),
                *cause,
                marmot_forensics::RecoveryNeedChange::NoticeShown,
                storage_sqlite::RecoveryDemandTicket {
                    id: *id,
                    revision: *revision,
                },
                None,
                None,
                None,
            );
        }
    }
}

/// Park one pending epoch gap the way the recovery runner does after its
/// last fruitless return visit: a begun visit over the group's routes,
/// finished exhausted.
#[cfg(test)]
pub(crate) fn park_recovery_for_test(storage: &storage_sqlite::SqliteAccountStorage, id: [u8; 16]) {
    use cgka_traits::storage::GroupStorage;
    let app = storage.app_storage();
    let demand = app
        .pending_recovery_demands()
        .unwrap()
        .into_iter()
        .find(|demand| demand.ticket.id == id)
        .expect("a pending obligation");
    assert_eq!(demand.cause, storage_sqlite::RecoveryCause::EpochGap);
    let group = demand.group_id.expect("an epoch gap names its group");
    let now = crate::unix_now_seconds();
    let floor = now.saturating_sub(storage_sqlite::TRANSPORT_RECONCILIATION_RETENTION_SECS);
    let floors = storage
        .list_transport_group_routes()
        .unwrap()
        .into_iter()
        .filter(|route| route.group_id.as_slice() == group.as_slice())
        .map(|route| {
            let id = route.transport_group_id.as_slice().try_into().unwrap();
            (TransportReconciliationRoute::Group(id), floor)
        })
        .collect::<Vec<_>>();
    assert!(
        app.begin_recovery_epoch_gap_retry(demand.ticket, &floors, now)
            .unwrap()
    );
    let visits = app
        .recovery_epoch_gap_retry(demand.ticket)
        .unwrap()
        .unwrap()
        .visits;
    assert!(
        app.finish_recovery_epoch_gap_retry(demand.ticket, visits, now, 0, true)
            .unwrap()
    );
}

#[cfg(test)]
mod ledger_tests;

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use storage_sqlite::{RecoveryCause, StoredEpochBackfillIntent};

    use super::park_recovery_for_test;
    use crate::tests::{ScriptedPushRelayClient, client_on_app_relay_plane};
    use crate::{AppError, HistoryNoticeCause, MarmotApp, MarmotAppRuntime};

    fn app(dir: &tempfile::TempDir) -> MarmotApp {
        crate::AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        // These tests own the legacy obligation-based notices; ledger notices
        // and runner status have their own real-boundary module below.
        MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()))
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn parked_history_surfaces_and_dismissal_retires_exactly_one_occurrence() {
        let dir = tempfile::tempdir().unwrap();
        let app = app(&dir);
        let mut client = client_on_app_relay_plane(&app, "alice").await;
        let group = client
            .create_group("history notices", &[])
            .await
            .unwrap()
            .operation
            .expect("eligible fixture members");
        let other = client
            .create_group("still parked", &[])
            .await
            .unwrap()
            .operation
            .expect("eligible fixture members");
        let storage = app.account_storage("alice").unwrap();
        let intents = [&group, &other]
            .into_iter()
            .map(|id| StoredEpochBackfillIntent {
                group_id_hex: hex::encode(id.as_slice()),
                stalled_epoch: client.group_mls_state(id).unwrap().epoch,
            })
            .collect::<Vec<_>>();
        storage
            .app_storage()
            .arm_epoch_backfill_intents(&intents)
            .unwrap();
        assert!(client.history_notices().unwrap().is_empty());
        let gaps = storage
            .app_storage()
            .pending_recovery_demands()
            .unwrap()
            .into_iter()
            .filter(|demand| demand.cause == RecoveryCause::EpochGap)
            .map(|demand| (demand.group_id.unwrap(), demand.ticket.id))
            .collect::<Vec<_>>();
        assert_eq!(gaps.len(), 2);
        for (_, gap) in &gaps {
            park_recovery_for_test(&storage, *gap);
        }

        let notices = client.history_notices().unwrap();
        assert_eq!(notices.len(), 2);
        assert!(
            notices
                .iter()
                .all(|notice| notice.cause == HistoryNoticeCause::EpochGap
                    && notice.parked_at_ms.is_some())
        );
        let gap_notice = notices
            .iter()
            .find(|notice| notice.group_id_hex == Some(hex::encode(group.as_slice())))
            .unwrap()
            .clone();
        let other_notice = notices
            .iter()
            .find(|notice| notice.group_id_hex == Some(hex::encode(other.as_slice())))
            .unwrap()
            .clone();
        let status = client.group_recovery_status(&group).unwrap();
        assert!(status.history_may_be_incomplete);
        assert_eq!(
            status.history_notice_ids,
            vec![gap_notice.notice_id.clone()]
        );
        // The open recorded the empty baseline; parking is one announced change.
        let mut changed = client.take_history_notice_changes().unwrap();
        changed.sort_by(|a, b| a.as_slice().cmp(b.as_slice()));
        let mut both = vec![group.clone(), other.clone()];
        both.sort_by(|a, b| a.as_slice().cmp(b.as_slice()));
        assert_eq!(changed, both);
        assert_eq!(client.take_history_notice_changes(), None);

        // Only the dismissed occurrence retires. It is its own outcome, not
        // coverage: the gap is neither pending nor parked any more.
        assert!(
            client
                .dismiss_history_notice(&gap_notice.notice_id)
                .unwrap()
        );
        assert_eq!(client.history_notices().unwrap(), vec![other_notice]);
        let status = client.group_recovery_status(&group).unwrap();
        assert!(!status.history_may_be_incomplete && status.history_notice_ids.is_empty());
        assert_eq!(
            client.take_history_notice_changes(),
            Some(vec![group.clone()])
        );
        let (_, gap) = gaps
            .iter()
            .find(|(id, _)| id.as_slice() == group.as_slice())
            .unwrap();
        assert!(
            storage
                .app_storage()
                .pending_recovery_demands()
                .unwrap()
                .iter()
                .all(|demand| demand.ticket.id != *gap)
        );
        assert_eq!(
            storage
                .app_storage()
                .pending_epoch_backfill_intents()
                .unwrap()
                .len(),
            1,
            "only the other group's gap stays owed"
        );
        assert!(
            !client
                .dismiss_history_notice(&gap_notice.notice_id)
                .unwrap(),
            "a dismissed occurrence is stale"
        );

        // The dismissal is durable: nothing reappears on reopen.
        drop(client);
        let client = client_on_app_relay_plane(&app, "alice").await;
        assert_eq!(client.history_notices().unwrap().len(), 1);
        assert!(
            !client
                .group_recovery_status(&group)
                .unwrap()
                .history_may_be_incomplete
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn runtime_serves_notices_and_dismissals_through_the_account_worker() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = MarmotAppRuntime::new(app(&dir));
        runtime.reconcile_accounts().await.unwrap();
        assert!(runtime.history_notices("alice").await.unwrap().is_empty());
        assert!(matches!(
            runtime.dismiss_history_notice("alice", "not hex").await,
            Err(AppError::Hex(_))
        ));
        assert!(matches!(
            runtime
                .dismiss_history_notice("alice", &"00".repeat(23))
                .await,
            Err(AppError::Hex(_))
        ));
        assert!(
            !runtime
                .dismiss_history_notice("alice", &"00".repeat(24))
                .await
                .unwrap(),
            "an unknown occurrence is stale, not an error"
        );
    }
}
