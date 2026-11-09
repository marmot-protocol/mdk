//! Worker-owned "history may be incomplete" notices and their explicit,
//! user-authorized retirement. Retirement is recorded as its own outcome,
//! never as coverage.
//!
//! Routes the coverage ledger parks raise notices too ([`LedgerNotice`]), as
//! does each rejoin ([`RejoinNotice`], mdk#2660 row 11), and the account's
//! recovery status reads what the recovery runner is catching up (mdk#2660
//! phase 4).
use std::collections::{BTreeMap, BTreeSet};

use cgka_traits::GroupId;
use storage_sqlite::{RecoveryDemandTicket, SqliteAppStorage, TransportReconciliationRoute};

use super::AppClient;
use crate::history_notices::{
    decode_notice_id, encode_notice_id, history_notice, ledger_route_tag, rejoin_group_tag,
};
use crate::{AccountRecoveryStatus, AppError, HistoryNotice, HistoryNoticeCause};

/// One route the coverage ledger parks: one `UnprovenHistory` notice, whose
/// ticket is the route's tag and its park revision (the newest among the
/// parks it shows and its remainder). Not `Debug`: it carries its route.
pub(crate) struct LedgerNotice {
    route: TransportReconciliationRoute,
    ticket: RecoveryDemandTicket,
    /// The relays whose broken units it shows: the ones its dismissal
    /// retires, with the route's remainder.
    relays: Vec<String>,
    /// The route's MLS group; `None` for the inbox.
    group_id: Option<Vec<u8>>,
    parked_at_seconds: u64,
}

impl LedgerNotice {
    fn notice(&self) -> HistoryNotice {
        HistoryNotice {
            notice_id: encode_notice_id(self.ticket),
            cause: HistoryNoticeCause::UnprovenHistory,
            group_id_hex: self.group_id.as_ref().map(hex::encode),
            parked_at_ms: Some(self.parked_at_seconds.saturating_mul(1000)),
        }
    }
}

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

impl AppClient {
    /// Every current occurrence: parked obligations oldest first, then the
    /// ledger's parked routes oldest first, then rejoins oldest first.
    pub(crate) fn history_notices(&self) -> Result<Vec<HistoryNotice>, AppError> {
        let app = self.app.account_storage(&self.state.label)?.app_storage();
        let mut notices = app
            .parked_recovery_obligations()?
            .iter()
            .filter(|parked| self.host_may_see_parked(parked.group_id.as_deref()))
            .map(history_notice)
            .collect::<Vec<_>>();
        notices.extend(self.ledger_notices(&app)?.iter().map(LedgerNotice::notice));
        notices.extend(self.rejoin_notices(&app)?.iter().map(RejoinNotice::notice));
        Ok(notices)
    }

    /// Each rejoin's notice not yet dismissed, oldest first, for a group with
    /// a current route that is not suspended and that the host may see.
    pub(crate) fn rejoin_notices(
        &self,
        app: &SqliteAppStorage,
    ) -> Result<Vec<RejoinNotice>, AppError> {
        let groups = self
            .recovery_runner_routes()
            .into_iter()
            .filter(|route| !route.suspended())
            .filter_map(|route| route.group_id)
            .collect::<BTreeSet<_>>();
        Ok(app
            .recovery_rejoin_notices()?
            .into_iter()
            .filter(|notice| {
                groups.contains(&notice.group_id)
                    && self.host_may_see_parked(Some(&notice.group_id))
            })
            .map(|notice| RejoinNotice {
                ticket: RecoveryDemandTicket {
                    id: rejoin_group_tag(&notice.group_id),
                    revision: notice.revision,
                },
                group_id: notice.group_id,
                noticed_at_seconds: notice.noticed_at_seconds,
            })
            .collect())
    }

    /// The routes the coverage ledger parks, one notice each, oldest first.
    /// What a notice shows, its
    /// revision and what dismissing it retires are one set: the route's
    /// broken units on relays it now requires, and its remainder. A remainder
    /// shows with a broken unit's notice, or alone once the window above it is
    /// covered, that is once the runner has surveyed and catches up none of
    /// the route's units. A broken unit on a relay the route carries only as
    /// best effort, or no longer, owes nothing, so it shows nowhere, moves no
    /// revision and is never dismissed. The revision is the newest park in
    /// the set. A park hidden that way keeps its revision, so once its relay
    /// is required again it joins the set: on a route with no other visible
    /// park it shows as a fresh notice, and beside a newer one it joins that
    /// notice without moving its revision, and dismissing the notice
    /// dismisses it too. A group route's notice names its group; one that is no
    /// current route's, a suspended group's, or one the host may not see, is
    /// left out.
    pub(crate) fn ledger_notices(
        &self,
        app: &SqliteAppStorage,
    ) -> Result<Vec<LedgerNotice>, AppError> {
        let routes = self
            .recovery_runner_routes()
            .into_iter()
            .filter(|route| !route.suspended())
            .map(|route| (route.route, (route.group_id, route.required)))
            .collect::<BTreeMap<_, _>>();
        let catching_up = self.routing.recovery_runner_catching_up_now();
        // Per route: the relays shown, the newest park, the oldest park time.
        let mut shown = BTreeMap::<TransportReconciliationRoute, (Vec<String>, u64, u64)>::new();
        for parked in app.parked_recovery_routes()? {
            let Some((_, required)) = routes.get(&parked.route) else {
                continue;
            };
            for relay in parked
                .relays
                .iter()
                .filter(|relay| required.contains(relay))
            {
                let Some(park) = app
                    .recovery_unit(&parked.route, relay)?
                    .and_then(|unit| unit.park)
                else {
                    continue;
                };
                let (relays, revision, parked_at) = shown.entry(parked.route.clone()).or_insert((
                    Vec::new(),
                    park.revision,
                    park.parked_at_seconds,
                ));
                relays.push(relay.clone());
                *revision = (*revision).max(park.revision);
                *parked_at = (*parked_at).min(park.parked_at_seconds);
            }
        }
        for remainder in app.recovery_coverage_remainders()? {
            if !routes.contains_key(&remainder.route) {
                continue;
            }
            if let Some((_, revision, parked_at)) = shown.get_mut(&remainder.route) {
                *revision = (*revision).max(remainder.revision);
                *parked_at = (*parked_at).min(remainder.parked_at_seconds);
            } else if catching_up
                .as_ref()
                .is_some_and(|units| !units.iter().any(|unit| unit.route == remainder.route))
            {
                shown.insert(
                    remainder.route,
                    (Vec::new(), remainder.revision, remainder.parked_at_seconds),
                );
            }
        }
        let mut notices = shown
            .into_iter()
            .filter_map(|(route, (relays, revision, parked_at_seconds))| {
                let group_id = match route {
                    TransportReconciliationRoute::Inbox => None,
                    TransportReconciliationRoute::Group(_) => Some(routes.get(&route)?.0.clone()?),
                };
                if !self.host_may_see_parked(group_id.as_deref()) {
                    return None;
                }
                Some(LedgerNotice {
                    ticket: RecoveryDemandTicket {
                        id: ledger_route_tag(&route),
                        revision,
                    },
                    route,
                    relays,
                    group_id,
                    parked_at_seconds,
                })
            })
            .collect::<Vec<_>>();
        notices.sort_by_key(|notice| notice.parked_at_seconds);
        Ok(notices)
    }

    /// The account's recovery status: the groups and inbox the runner's last
    /// survey found catching up. Until a runner has surveyed, nothing is.
    pub(crate) fn account_recovery_status(&self) -> Result<AccountRecoveryStatus, AppError> {
        let mut status = AccountRecoveryStatus {
            notices: self.history_notices()?,
            ..AccountRecoveryStatus::default()
        };
        let Some(units) = self.routing.recovery_runner_catching_up_now() else {
            return Ok(status);
        };
        let groups = self
            .recovery_runner_routes()
            .into_iter()
            .map(|route| (route.route, route.group_id))
            .collect::<BTreeMap<_, _>>();
        let mut catching_up = BTreeSet::new();
        for unit in units {
            if unit.route == TransportReconciliationRoute::Inbox {
                status.inbox_catching_up = true;
            } else if let Some(Some(group_id)) = groups.get(&unit.route)
                && self.host_may_see_group(&GroupId::new(group_id.clone()))
            {
                catching_up.insert(hex::encode(group_id));
            }
        }
        status.catching_up_group_ids_hex = catching_up.into_iter().collect();
        Ok(status)
    }

    /// Whether hosts are owed a `RecoveryStatusChanged`: the runner's survey
    /// changed what is catching up ([`AppClient::recovery_status_owed`]), or `notices_changed`. Every
    /// survey change counts, even one a later survey undid, so a host never
    /// keeps a state it read in between.
    pub(crate) fn take_recovery_status_changed(&mut self, notices_changed: bool) -> bool {
        let owed = std::mem::take(&mut self.recovery_status_owed);
        owed || notices_changed
    }

    /// A group-scoped occurrence reaches the host only for a group it may see.
    fn host_may_see_parked(&self, group_id: Option<&[u8]>) -> bool {
        group_id.is_none_or(|group_id| self.host_may_see_group(&GroupId::new(group_id.to_vec())))
    }

    /// Notice ids of this group's own parked occurrences, oldest first, then
    /// its routes' ledger notices, then its rejoin's.
    pub(crate) fn group_history_notice_ids(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<String>, AppError> {
        let app = self.app.account_storage(&self.state.label)?.app_storage();
        let mut ids = app
            .parked_group_recovery_obligations(group_id.as_slice())?
            .into_iter()
            .map(|parked| encode_notice_id(parked.ticket))
            .collect::<Vec<_>>();
        ids.extend(
            self.ledger_notices(&app)?
                .into_iter()
                .filter(|notice| notice.group_id.as_deref() == Some(group_id.as_slice()))
                .map(|notice| encode_notice_id(notice.ticket)),
        );
        ids.extend(
            self.rejoin_notices(&app)?
                .into_iter()
                .filter(|notice| notice.group_id == group_id.as_slice())
                .map(|notice| encode_notice_id(notice.ticket)),
        );
        Ok(ids)
    }

    /// Retire exactly the dismissed occurrence as "history may be incomplete".
    /// Returns false, changing nothing, when the notice is stale: new evidence
    /// re-armed recovery (it is then pending again or a new occurrence) or it
    /// was already dismissed.
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
                .rejoin_notices(&app)?
                .into_iter()
                .find(|notice| notice.ticket == ticket)
            {
                return self.dismiss_rejoin_notice(&app, &notice);
            }
            return self.dismiss_ledger_notice(&app, ticket);
        };
        if !app.retire_parked_recovery_obligation(
            ticket.id,
            ticket.revision,
            super::recovery::wall_now_ms()?,
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
            super::audit_recovery::obligation_cause(cause),
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

    /// Dismiss a ledger-parked route's notice: storage retires the parked
    /// spans of the broken units it shows and the route's remainder, never as
    /// coverage, and checks the notice's revision against exactly those
    /// ([`Self::ledger_notices`]). Returns false, changing nothing, when the
    /// notice is stale: the route re-armed, parked again under a newer
    /// revision, or was dismissed already.
    fn dismiss_ledger_notice(
        &mut self,
        app: &SqliteAppStorage,
        ticket: RecoveryDemandTicket,
    ) -> Result<bool, AppError> {
        let notice = self
            .ledger_notices(app)?
            .into_iter()
            .find(|notice| notice.ticket == ticket);
        let dismissed = match &notice {
            Some(notice) => {
                app.dismiss_recovery_route_park_on(&notice.route, &notice.relays, ticket.revision)?
            }
            None => false,
        };
        if !dismissed {
            tracing::debug!(
                target: "marmot_app::recovery",
                method = "dismiss_history_notice",
                "history notice was stale; nothing retired",
            );
            return Ok(false);
        }
        self.wake_recovery_runner();
        self.record_need_changed(
            notice
                .and_then(|notice| notice.group_id)
                .map(GroupId::new)
                .as_ref(),
            marmot_forensics::RecoveryObligationCause::UnprovenHistory,
            marmot_forensics::RecoveryNeedChange::NoticeDismissed,
            ticket,
            None,
            None,
            None,
        );
        tracing::info!(
            target: "marmot_app::recovery",
            method = "dismiss_history_notice",
            cause = HistoryNoticeCause::UnprovenHistory.as_str(),
            "retired a parked recovery route; its history may be incomplete",
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
    /// so the next publication seam retries. The ledger's parked routes count
    /// too, and an upgrade conversion that changed the notices is announced once, even
    /// when the set reads the same.
    pub(crate) fn take_history_notice_changes(&mut self) -> Option<Vec<GroupId>> {
        let mut causes = Vec::new();
        let mut converted = None;
        let current: HistoryNoticeBaseline = match self
            .app
            .account_storage(&self.state.label)
            .and_then(|storage| {
                let app = storage.app_storage();
                let parked = app.parked_recovery_obligations()?;
                let ledger = self.ledger_notices(&app)?;
                let rejoins = self.rejoin_notices(&app)?;
                if !app.recovery_conversion_pending()?
                    && app.recovery_conversion_notices_changed()?
                {
                    converted = Some(app);
                }
                Ok((parked, ledger, rejoins))
            }) {
            Ok((parked, ledger, rejoins)) => parked
                .into_iter()
                .map(|parked| {
                    let cause = super::audit_recovery::obligation_cause(parked.cause);
                    (parked.ticket, parked.group_id, cause)
                })
                .chain(ledger.into_iter().map(|notice| {
                    let cause = marmot_forensics::RecoveryObligationCause::UnprovenHistory;
                    (notice.ticket, notice.group_id, cause)
                }))
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
        let previous = self.history_notice_baseline.replace(current)?;
        let current = self.history_notice_baseline.as_ref()?;
        if previous == *current && !announce_all {
            return None;
        }
        self.record_history_notice_changes(&previous, &causes);
        let current = self.history_notice_baseline.as_ref()?;
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
    /// Audit the notice set's transitions: each newly parked occurrence, an
    /// obligation's or a ledger route's, is a shown notice. Withdrawals are
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
        let Some(current) = self.history_notice_baseline.as_ref() else {
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
        let group = client.create_group("history notices", &[]).await.unwrap();
        let other = client.create_group("still parked", &[]).await.unwrap();
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
