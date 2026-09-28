//! Worker-owned "history may be incomplete" notices and their explicit,
//! user-authorized retirement. Retirement is recorded as its own outcome,
//! never as coverage, and releases a retired loss's cursor fence without
//! recording recovery success.
use cgka_traits::GroupId;

use super::AppClient;
use crate::history_notices::{decode_notice_id, encode_notice_id, history_notice};
use crate::{AppError, HistoryNotice, HistoryNoticeCause};

/// The parked set as last announced: each occurrence's obligation id and
/// revision, with its group for group-scoped demand.
pub(crate) type HistoryNoticeBaseline = Vec<([u8; 16], u64, Option<Vec<u8>>)>;

impl AppClient {
    /// Every current occurrence, oldest first.
    pub(crate) fn history_notices(&self) -> Result<Vec<HistoryNotice>, AppError> {
        Ok(self
            .app
            .account_storage(&self.state.label)?
            .parked_recovery_obligations()?
            .iter()
            .map(history_notice)
            .collect())
    }

    /// Notice ids of this group's own parked occurrences, oldest first.
    pub(crate) fn group_history_notice_ids(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<String>, AppError> {
        Ok(self
            .app
            .account_storage(&self.state.label)?
            .parked_group_recovery_obligations(group_id.as_slice())?
            .into_iter()
            .map(|parked| encode_notice_id(parked.ticket))
            .collect())
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
        // Newer loss joins first. It re-arms the obligation under a new
        // revision, so a dismissal of the older occurrence becomes stale.
        self.synchronize_recovery_loss(&storage)?;
        let Some((cause, group)) = storage
            .parked_recovery_obligations()?
            .into_iter()
            .find(|parked| parked.ticket == ticket)
            .map(|parked| (parked.cause, parked.group_id))
        else {
            tracing::debug!(
                target: "marmot_app::recovery",
                method = "dismiss_history_notice",
                "history notice was stale; nothing retired",
            );
            return Ok(false);
        };
        // The plane's pending generation before retirement. Releasing the
        // fence requires it to be unchanged afterwards.
        let observed = self.adapter.pending_delivery_overflow_generation();
        if !storage.retire_parked_recovery_obligation(
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
            remaining_notices = storage
                .parked_recovery_obligations()
                .map_or(0, |parked| parked.len()),
            "retired a parked recovery occurrence; its history may be incomplete",
        );
        Ok(true)
    }

    /// Re-read the parked set and return the groups whose own occurrences
    /// changed since the last call, or `None` when nothing changed. The first
    /// call only records the baseline. A failed read keeps the old baseline,
    /// so the next publication seam retries.
    pub(crate) fn take_history_notice_changes(&mut self) -> Option<Vec<GroupId>> {
        let mut causes = Vec::new();
        let current: HistoryNoticeBaseline = match self
            .app
            .account_storage(&self.state.label)
            .and_then(|storage| Ok(storage.parked_recovery_obligations()?))
        {
            Ok(parked) => parked
                .into_iter()
                .map(|parked| {
                    causes.push((parked.ticket.id, parked.cause));
                    (parked.ticket.id, parked.ticket.revision, parked.group_id)
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
        let previous = self.history_notice_baseline.replace(current)?;
        let current = self.history_notice_baseline.as_ref()?;
        if previous == *current {
            return None;
        }
        self.record_history_notice_changes(&previous, &causes);
        let current = self.history_notice_baseline.as_ref()?;
        let mut groups = previous
            .iter()
            .filter(|entry| !current.contains(entry))
            .chain(current.iter().filter(|entry| !previous.contains(entry)))
            .filter_map(|(_, _, group)| group.clone())
            .collect::<Vec<_>>();
        groups.sort();
        groups.dedup();
        Some(groups.into_iter().map(GroupId::new).collect())
    }
}

impl AppClient {
    /// Audit the notice set's transitions: each newly parked occurrence is a
    /// shown notice, and a withdrawn one whose obligation is now satisfied
    /// was closed with qualified coverage. Other withdrawals are recorded
    /// where they happen: a dismissal, or new evidence resuming the demand.
    fn record_history_notice_changes(
        &self,
        previous: &HistoryNoticeBaseline,
        causes: &[([u8; 16], storage_sqlite::RecoveryCause)],
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
                super::audit_recovery::obligation_cause(*cause),
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
            let Ok(Some(status)) = storage.recovery_obligation_status(*id) else {
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
    let mut fence = storage.recovery_revision_fence().unwrap();
    fence.obligations.retain(|(candidate, _)| *candidate == id);
    let now = super::recovery::wall_now_ms().unwrap();
    let attempt = storage
        .reserve_recovery_attempt(&fence, now, 1, true)
        .unwrap()
        .expect("explicit reservation")
        .attempt_serial;
    let endpoint = "wss://relay.example".to_owned();
    let token = storage
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
                until_seconds: now / 1000,
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
            .mark_account_delivery_recovery("alice", token, 1)
            .unwrap();
        client.delivery_overflow_recovery_pending = true;
        client.delivery_overflow_recovery_marker_token = Some(token);
        client.adapter.start_delivery_overflow_recovery(token);
        client.adapter.fail_delivery_overflow_recovery();
        assert!(client.delivery_loss_blocks_cursor());
    }

    #[tokio::test]
    async fn parked_history_surfaces_and_dismissal_retires_exactly_one_occurrence() {
        let dir = tempfile::tempdir().unwrap();
        let app = app(&dir);
        let mut client = client_on_app_relay_plane(&app, "alice").await;
        let group = client.create_group("history notices", &[]).await.unwrap();
        let epoch = client.group_mls_state(&group).unwrap().epoch;
        let storage = app.account_storage("alice").unwrap();
        storage
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
                    .recovery_obligation_is_satisfied(gap, revision)
                    .unwrap()
            );
        }
        assert!(storage.pending_epoch_backfill_intents().unwrap().is_empty());
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
                .account_delivery_recovery("alice")
                .unwrap()
                .is_none()
        );
        assert_eq!(storage.restore_unacknowledged_recovery_loss().unwrap(), 0);
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

    #[tokio::test]
    async fn new_loss_makes_a_notice_stale_and_after_dismissal_is_a_new_occurrence() {
        let dir = tempfile::tempdir().unwrap();
        let app = app(&dir);
        let mut client = client_on_app_relay_plane(&app, "alice").await;
        fence_loss(&mut client, 42);
        let storage = app.account_storage("alice").unwrap();
        let loss = pending(&storage, RecoveryCause::QueueLoss);
        park_recovery_for_test(&storage, loss);
        let first = client.history_notices().unwrap().remove(0);

        // The off-worker writer recorded more loss that no import joined yet.
        // Dismissal imports it first, so the parked occurrence is stale.
        storage
            .record_account_delivery_loss("alice", 42, 2, crate::unix_now_seconds())
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
        storage
            .mark_account_delivery_recovery("alice", 42, 2)
            .unwrap();
        storage.synchronize_account_delivery_loss("alice").unwrap();
        assert!(
            storage
                .account_delivery_recovery("alice")
                .unwrap()
                .is_none()
        );
        assert!(client.history_notices().unwrap().is_empty());

        // New loss is a fresh pending obligation, and parks as a new notice.
        storage
            .mark_account_delivery_recovery("alice", 77, 1)
            .unwrap();
        assert_eq!(pending(&storage, RecoveryCause::QueueLoss), loss);
        assert!(client.history_notices().unwrap().is_empty());
        park_recovery_for_test(&storage, loss);
        let third = client.history_notices().unwrap().remove(0);
        assert_ne!(third.notice_id, second.notice_id);
        assert_ne!(third.notice_id, first.notice_id);
    }

    #[tokio::test]
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
