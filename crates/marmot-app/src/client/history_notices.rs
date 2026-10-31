//! Worker-owned "history may be incomplete" notices and their explicit,
//! user-authorized retirement. Retirement is recorded as its own outcome,
//! never as coverage, and releases a retired loss's cursor fence without
//! recording recovery success.
//!
//! Behind the internal `runner_owns_debt` gate (mdk#2660 phase 4), routes the
//! coverage ledger parks raise notices too ([`LedgerNotice`]), and the
//! account's recovery status reads what the recovery runner is catching up.
use std::collections::{BTreeMap, BTreeSet};

use cgka_traits::GroupId;
use storage_sqlite::{RecoveryDemandTicket, SqliteAppStorage, TransportReconciliationRoute};

use super::AppClient;
use crate::history_notices::{
    decode_notice_id, encode_notice_id, history_notice, ledger_route_tag,
};
use crate::{AccountRecoveryStatus, AppError, HistoryNotice, HistoryNoticeCause};

/// One route the coverage ledger parks: one `UnprovenHistory` notice, whose
/// ticket is the route's tag and its park revision (the newest among its
/// broken units' parks and its remainder). Not `Debug`: it carries its route.
pub(crate) struct LedgerNotice {
    route: TransportReconciliationRoute,
    ticket: RecoveryDemandTicket,
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

/// The parked set as last announced: each occurrence's obligation id and
/// revision, with its group for group-scoped demand.
pub(crate) type HistoryNoticeBaseline = Vec<([u8; 16], u64, Option<Vec<u8>>)>;

impl AppClient {
    /// Every current occurrence: parked obligations oldest first, then the
    /// ledger's parked routes oldest first.
    pub(crate) fn history_notices(&self) -> Result<Vec<HistoryNotice>, AppError> {
        let app = self.app.account_storage(&self.state.label)?.app_storage();
        let mut notices = app
            .parked_recovery_obligations()?
            .iter()
            .filter(|parked| self.host_may_see_parked(parked.group_id.as_deref()))
            .map(history_notice)
            .collect::<Vec<_>>();
        notices.extend(self.ledger_notices(&app)?.iter().map(LedgerNotice::notice));
        Ok(notices)
    }

    /// The routes the coverage ledger parks, one notice each, oldest first,
    /// behind the internal `runner_owns_debt` gate: a route with a broken
    /// unit on a relay it now requires, or with a parked remainder once the
    /// window above it is covered, that is once the runner has surveyed and
    /// catches up none of the route's units. A broken unit on a relay the
    /// route carries only as best effort, or no longer, owes nothing, so it
    /// raises none; a remainder is the route's, and its notice carries the
    /// route's whole park revision, so dismissing it also dismisses such a
    /// unit. A group route's notice names
    /// its group; one that is no current route's, a suspended group's, or one
    /// the host may not see, is left out.
    pub(crate) fn ledger_notices(
        &self,
        app: &SqliteAppStorage,
    ) -> Result<Vec<LedgerNotice>, AppError> {
        if !self.app.recovery_runner_owns_debt() {
            return Ok(Vec::new());
        }
        let routes = self
            .recovery_runner_routes()
            .into_iter()
            .filter(|route| !route.suspended())
            .map(|route| (route.route, (route.group_id, route.required)))
            .collect::<BTreeMap<_, _>>();
        let catching_up = self.routing.recovery_runner_catching_up_now();
        // Every notice carries its route's whole park revision, a park it
        // does not show included, as dismissal checks that.
        let mut revisions = BTreeMap::new();
        let mut parked = BTreeMap::new();
        for park in app.parked_recovery_routes()? {
            let shown = routes.get(&park.route).is_some_and(|(_, required)| {
                park.relays.iter().any(|relay| required.contains(relay))
            });
            if shown {
                parked.insert(park.route.clone(), (park.revision, park.parked_at_seconds));
            }
            revisions.insert(park.route, park.revision);
        }
        for remainder in app.recovery_coverage_remainders()? {
            if let Some((_, parked_at)) = parked.get_mut(&remainder.route) {
                // Its revision already counts the remainder's.
                *parked_at = (*parked_at).min(remainder.parked_at_seconds);
            } else if catching_up
                .as_ref()
                .is_some_and(|units| !units.iter().any(|unit| unit.route == remainder.route))
            {
                let revision = revisions
                    .get(&remainder.route)
                    .copied()
                    .unwrap_or(remainder.revision);
                parked.insert(remainder.route, (revision, remainder.parked_at_seconds));
            }
        }
        let mut notices = parked
            .into_iter()
            .filter_map(|(route, (revision, parked_at_seconds))| {
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
                    group_id,
                    parked_at_seconds,
                })
            })
            .collect::<Vec<_>>();
        notices.sort_by_key(|notice| notice.parked_at_seconds);
        Ok(notices)
    }

    /// The account's recovery status. Behind the internal `runner_owns_debt`
    /// gate, it reports the groups and inbox the runner's last survey found
    /// catching up; otherwise, and until a runner has surveyed, nothing is.
    pub(crate) fn account_recovery_status(&self) -> Result<AccountRecoveryStatus, AppError> {
        let mut status = AccountRecoveryStatus {
            notices: self.history_notices()?,
            ..AccountRecoveryStatus::default()
        };
        if !self.app.recovery_runner_owns_debt() {
            return Ok(status);
        }
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

    /// Whether hosts are owed a `RecoveryStatusChanged`, behind the internal
    /// `runner_owns_debt` gate: the runner's survey changed what is catching
    /// up ([`AppClient::recovery_status_owed`]), or `notices_changed`. Every
    /// survey change counts, even one a later survey undid, so a host never
    /// keeps a state it read in between.
    pub(crate) fn take_recovery_status_changed(&mut self, notices_changed: bool) -> bool {
        let owed = std::mem::take(&mut self.recovery_status_owed);
        self.app.recovery_runner_owns_debt() && (owed || notices_changed)
    }

    /// A group-scoped occurrence reaches the host only for a group it may see.
    fn host_may_see_parked(&self, group_id: Option<&[u8]>) -> bool {
        group_id.is_none_or(|group_id| self.host_may_see_group(&GroupId::new(group_id.to_vec())))
    }

    /// Notice ids of this group's own parked occurrences, oldest first, then
    /// its routes' ledger notices.
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
        Ok(ids)
    }

    /// Retire exactly the dismissed occurrence as "history may be incomplete".
    /// Returns false, changing nothing, when the notice is stale: new evidence
    /// re-armed recovery (it is then pending again or a new occurrence) or it
    /// was already dismissed. A retired loss obligation also releases the
    /// transport-cursor fence once no loss obligation remains pending, so the
    /// cursor can advance past the loss the user accepted.
    pub(crate) fn dismiss_history_notice(&mut self, notice_id: &str) -> Result<bool, AppError> {
        let ticket = decode_notice_id(notice_id)?;
        let storage = self.app.account_storage(&self.state.label)?;
        let app = storage.app_storage();
        // Newer loss joins first. It re-arms the obligation under a new
        // revision, so a dismissal of the older occurrence becomes stale.
        self.synchronize_recovery_loss(&app)?;
        let Some((cause, group)) = app
            .parked_recovery_obligations()?
            .into_iter()
            .find(|parked| parked.ticket == ticket)
            .map(|parked| (parked.cause, parked.group_id))
        else {
            return self.dismiss_ledger_notice(&app, ticket);
        };
        // The plane's pending generation before retirement. Releasing the
        // fence requires it to be unchanged afterwards.
        let observed = self.adapter.pending_delivery_overflow_generation();
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
        // The retirement is durable from here on; the dismissal succeeded
        // even if the in-memory fence cannot be released right now.
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
        let loss = matches!(
            cause,
            storage_sqlite::RecoveryCause::QueueLoss
                | storage_sqlite::RecoveryCause::NotificationLoss
        );
        let fence_released = loss
            && self
                .release_retired_delivery_loss(observed)
                .unwrap_or_else(|_| {
                    tracing::warn!(
                        target: "marmot_app::recovery",
                        method = "dismiss_history_notice",
                        error_kind = "loss_fence_release_failed",
                        "retired loss keeps its cursor fence until the next loss observation",
                    );
                    false
                });
        if fence_released && !self.delivery_loss_blocks_cursor() {
            // Every prefix drained while the fence held stayed on the old
            // cursor. The user accepted the loss, so promote the candidate as
            // qualified completion would, without recording coverage.
            let sealed = self.seal_transport_cursor();
            if self
                .save_state_with_pending_local_group_deletion_frontier_clears()
                .is_err()
            {
                self.abandon_transport_cursor(sealed);
                tracing::warn!(
                    target: "marmot_app::recovery",
                    method = "dismiss_history_notice",
                    error_kind = "cursor_checkpoint_failed",
                    "cursor advances at the next checkpoint instead",
                );
            } else {
                self.settle_transport_cursor(
                    sealed,
                    marmot_forensics::TransportCursorTrigger::NoticeRetired,
                );
            }
        }
        tracing::info!(
            target: "marmot_app::recovery",
            method = "dismiss_history_notice",
            cause = HistoryNoticeCause::from_recovery(cause).as_str(),
            loss_fence_released = fence_released,
            remaining_notices = app.parked_recovery_obligations()
                .map_or(0, |parked| parked.len()),
            "retired a parked recovery occurrence; its history may be incomplete",
        );
        Ok(true)
    }

    /// Dismiss a ledger-parked route's notice: storage retires the parked
    /// spans of the route's broken units and its remainder, never as
    /// coverage. Returns false, changing nothing, when the notice is stale:
    /// the route re-armed, parked again under a newer revision, or was
    /// dismissed already.
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
            Some(notice) => app.dismiss_recovery_route_park(&notice.route, ticket.revision)?,
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

    /// Re-read the parked set and return the groups whose own occurrences
    /// changed since the last call, or `None` when nothing changed. The first
    /// call only records the baseline. A failed read keeps the old baseline,
    /// so the next publication seam retries. Behind the internal
    /// `runner_owns_debt` gate the ledger's parked routes count too, and an
    /// upgrade conversion that changed the notices is announced once, even
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
                if self.app.recovery_runner_owns_debt()
                    && !app.recovery_conversion_pending()?
                    && app.recovery_conversion_notices_changed()?
                {
                    converted = Some(app);
                }
                Ok((parked, ledger))
            }) {
            Ok((parked, ledger)) => parked
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
    /// obligation's or a ledger route's, is a shown notice, and a withdrawn
    /// one whose obligation is now satisfied was closed with qualified
    /// coverage. Other withdrawals are recorded where they happen: a
    /// dismissal, or new evidence resuming the demand.
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
        let Ok(storage) = self.app.account_storage(&self.state.label) else {
            return;
        };
        for (id, revision, group) in previous.iter().filter(|entry| !current.contains(entry)) {
            let Ok(Some(status)) = storage.app_storage().recovery_obligation_status(*id) else {
                continue;
            };
            if status.state != storage_sqlite::RecoveryObligationState::Satisfied {
                continue;
            }
            self.record_need_changed(
                group.clone().map(GroupId::new).as_ref(),
                super::audit_recovery::obligation_cause(status.cause),
                marmot_forensics::RecoveryNeedChange::Closed,
                storage_sqlite::RecoveryDemandTicket {
                    id: *id,
                    revision: status.revision.max(*revision),
                },
                None,
                None,
                None,
            );
        }
    }
}

/// Park one obligation the way the owner does after its fruitless budget:
/// one reserved attempt whose checkpoint certifies nothing.
#[cfg(test)]
pub(crate) fn park_recovery_for_test(storage: &storage_sqlite::SqliteAccountStorage, id: [u8; 16]) {
    assert!(!settle_recovery_for_test(storage, id, false));
}

/// One reserved attempt for exactly `id`, checkpointed with synthetic finite
/// endpoint evidence: qualified coverage when `covered`, otherwise nothing,
/// which parks it. Returns whether the obligation is now satisfied.
/// The synthetic goal stays fixed across attempts of the same revision.
#[cfg(test)]
pub(crate) fn settle_recovery_for_test(
    storage: &storage_sqlite::SqliteAccountStorage,
    id: [u8; 16],
    covered: bool,
) -> bool {
    use storage_sqlite::{
        RecoveryEligibility, RecoveryEndpointCheckpoint, RecoveryScopeCheckpoint,
        RecoveryScopeOutcome, RecoveryScopePlan,
    };
    let mut fence = storage.app_storage().recovery_revision_fence().unwrap();
    fence.obligations.retain(|(candidate, _)| *candidate == id);
    let now = super::recovery::wall_now_ms().unwrap();
    let attempt = storage
        .app_storage()
        .reserve_recovery_attempt(&fence, now, 1, true)
        .unwrap()
        .expect("explicit reservation")
        .attempt_serial;
    let endpoint = "wss://relay.example".to_owned();
    let token = storage
        .app_storage()
        .install_recovery_scope_plan(
            &fence,
            attempt,
            id,
            &[RecoveryScopePlan {
                scope_id: 0,
                route_kind: 0,
                route_role: 0,
                group_id: None,
                transport_group_id: None,
                since_seconds: Some(1),
                until_seconds: 1,
                known_event_id: None,
                inventory_floor: Some(1),
                required_endpoints: vec![endpoint.clone()],
                admitted_endpoints: vec![endpoint.clone()],
            }],
        )
        .unwrap()
        .expect("fresh plan")
        .remove(0);
    storage
        .app_storage()
        .checkpoint_recovery_obligation(
            &fence,
            attempt,
            id,
            &[RecoveryScopeCheckpoint {
                token,
                endpoints: vec![RecoveryEndpointCheckpoint {
                    endpoint,
                    outcome: if covered {
                        RecoveryScopeOutcome::Covered
                    } else {
                        RecoveryScopeOutcome::Unknown
                    },
                    exhaustive: covered,
                    admission_complete: covered,
                    first_boundary: false,
                }],
                retained_known_event: false,
                replay_admitted: false,
            }],
            if covered {
                RecoveryEligibility::Retry
            } else {
                RecoveryEligibility::NeedsDeepRepair
            },
        )
        .unwrap()
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
        MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()))
    }

    fn pending(storage: &storage_sqlite::SqliteAccountStorage, cause: RecoveryCause) -> [u8; 16] {
        storage
            .app_storage()
            .pending_recovery_demands()
            .unwrap()
            .into_iter()
            .find(|demand| demand.cause == cause)
            .unwrap()
            .ticket
            .id
    }

    /// Durable loss plus the plane generation a finished, uncertified attempt
    /// leaves behind: the cursor stays fenced on both.
    fn fence_loss(client: &mut crate::AppClient, token: u64) {
        let storage = client.app.account_storage("alice").unwrap();
        storage
            .app_storage()
            .mark_account_delivery_recovery("alice", token, 1)
            .unwrap();
        client.delivery_overflow_recovery_pending = true;
        client.delivery_overflow_recovery_marker_token = Some(token);
        client.adapter.start_delivery_overflow_recovery(token);
        client.adapter.fail_delivery_overflow_recovery();
        assert!(client.delivery_loss_blocks_cursor());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn parked_history_surfaces_and_dismissal_retires_exactly_one_occurrence() {
        let dir = tempfile::tempdir().unwrap();
        let app = app(&dir);
        let mut client = client_on_app_relay_plane(&app, "alice").await;
        let group = client.create_group("history notices", &[]).await.unwrap();
        let epoch = client.group_mls_state(&group).unwrap().epoch;
        let storage = app.account_storage("alice").unwrap();
        storage
            .app_storage()
            .arm_epoch_backfill_intents(&[StoredEpochBackfillIntent {
                group_id_hex: hex::encode(group.as_slice()),
                stalled_epoch: epoch,
            }])
            .unwrap();
        fence_loss(&mut client, 42);
        assert!(client.history_notices().unwrap().is_empty());
        let loss = pending(&storage, RecoveryCause::QueueLoss);
        let gap = pending(&storage, RecoveryCause::EpochGap);
        park_recovery_for_test(&storage, loss);
        park_recovery_for_test(&storage, gap);

        let notices = client.history_notices().unwrap();
        assert_eq!(notices.len(), 2);
        let loss_notice = notices
            .iter()
            .find(|notice| notice.cause == HistoryNoticeCause::DeliveryLoss)
            .unwrap()
            .clone();
        let gap_notice = notices
            .iter()
            .find(|notice| notice.cause == HistoryNoticeCause::EpochGap)
            .unwrap()
            .clone();
        assert_eq!(loss_notice.group_id_hex, None);
        assert_eq!(gap_notice.group_id_hex, Some(hex::encode(group.as_slice())));
        assert!(loss_notice.parked_at_ms.is_some() && gap_notice.parked_at_ms.is_some());
        let status = client.group_recovery_status(&group).unwrap();
        assert!(status.history_may_be_incomplete);
        assert_eq!(
            status.history_notice_ids,
            vec![gap_notice.notice_id.clone()]
        );
        // The open recorded the empty baseline; parking is one announced change.
        assert_eq!(
            client.take_history_notice_changes(),
            Some(vec![group.clone()])
        );
        assert_eq!(client.take_history_notice_changes(), None);

        // Only the group's occurrence retires. It is its own outcome, not
        // coverage, and the account's loss keeps the cursor fenced.
        assert!(
            client
                .dismiss_history_notice(&gap_notice.notice_id)
                .unwrap()
        );
        assert_eq!(client.history_notices().unwrap(), vec![loss_notice.clone()]);
        let status = client.group_recovery_status(&group).unwrap();
        assert!(!status.history_may_be_incomplete && status.history_notice_ids.is_empty());
        assert_eq!(
            client.take_history_notice_changes(),
            Some(vec![group.clone()])
        );
        let gap_ticket = crate::history_notices::decode_notice_id(&gap_notice.notice_id).unwrap();
        for revision in [gap_ticket.revision, gap_ticket.revision + 1] {
            assert!(
                !storage
                    .app_storage()
                    .recovery_obligation_is_satisfied(gap, revision)
                    .unwrap()
            );
        }
        assert!(
            storage
                .app_storage()
                .pending_epoch_backfill_intents()
                .unwrap()
                .is_empty()
        );
        assert!(client.delivery_loss_blocks_cursor());
        assert!(
            !client
                .dismiss_history_notice(&gap_notice.notice_id)
                .unwrap(),
            "a dismissed occurrence is stale"
        );

        // Retiring the last loss releases the fence without recording success.
        let before = app.relay_plane.relay_health().await;
        assert!(
            client
                .dismiss_history_notice(&loss_notice.notice_id)
                .unwrap()
        );
        assert!(client.history_notices().unwrap().is_empty());
        assert!(!client.delivery_overflow_recovery_pending);
        assert!(
            client
                .adapter
                .pending_delivery_overflow_generation()
                .is_none()
        );
        assert!(!client.delivery_loss_blocks_cursor());
        assert_eq!(
            client.checkpointed_transport_timestamp,
            client.state.last_transport_timestamp
        );
        let after = app.relay_plane.relay_health().await;
        assert_eq!(
            after.account_delivery_recovery_successes,
            before.account_delivery_recovery_successes
        );
        assert!(
            storage
                .app_storage()
                .account_delivery_recovery("alice")
                .unwrap()
                .is_none()
        );
        assert_eq!(
            storage
                .app_storage()
                .restore_unacknowledged_recovery_loss()
                .unwrap(),
            0
        );
        assert_eq!(client.take_history_notice_changes(), Some(Vec::new()));

        // The dismissal is durable: nothing reappears or re-fences on reopen.
        drop(client);
        let client = client_on_app_relay_plane(&app, "alice").await;
        assert!(client.history_notices().unwrap().is_empty());
        assert!(!client.delivery_overflow_recovery_pending);
        assert!(!client.delivery_loss_blocks_cursor());
        assert!(
            !client
                .group_recovery_status(&group)
                .unwrap()
                .history_may_be_incomplete
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn new_loss_makes_a_notice_stale_and_after_dismissal_is_a_new_occurrence() {
        let dir = tempfile::tempdir().unwrap();
        let app = app(&dir);
        let mut client = client_on_app_relay_plane(&app, "alice").await;
        fence_loss(&mut client, 42);
        let storage = app.account_storage("alice").unwrap();
        let app = storage.app_storage();
        let loss = pending(&storage, RecoveryCause::QueueLoss);
        park_recovery_for_test(&storage, loss);
        let first = client.history_notices().unwrap().remove(0);

        // The off-worker writer recorded more loss that no import joined yet.
        // Dismissal imports it first, so the parked occurrence is stale.
        app.record_account_delivery_loss("alice", 42, 2, crate::unix_now_seconds())
            .unwrap();
        assert!(!client.dismiss_history_notice(&first.notice_id).unwrap());
        assert!(
            client.history_notices().unwrap().is_empty(),
            "the new evidence re-armed recovery"
        );
        assert!(client.delivery_loss_blocks_cursor());

        park_recovery_for_test(&storage, loss);
        let second = client.history_notices().unwrap().remove(0);
        assert_ne!(second.notice_id, first.notice_id);
        assert!(client.dismiss_history_notice(&second.notice_id).unwrap());
        assert!(!client.delivery_loss_blocks_cursor());

        // A late duplicate of the retired loss re-arms nothing.
        app.mark_account_delivery_recovery("alice", 42, 2).unwrap();
        app.synchronize_account_delivery_loss("alice").unwrap();
        assert!(app.account_delivery_recovery("alice").unwrap().is_none());
        assert!(client.history_notices().unwrap().is_empty());

        // New loss is a fresh pending obligation, and parks as a new notice.
        app.mark_account_delivery_recovery("alice", 77, 1).unwrap();
        assert_eq!(pending(&storage, RecoveryCause::QueueLoss), loss);
        assert!(client.history_notices().unwrap().is_empty());
        park_recovery_for_test(&storage, loss);
        let third = client.history_notices().unwrap().remove(0);
        assert_ne!(third.notice_id, second.notice_id);
        assert_ne!(third.notice_id, first.notice_id);
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
