//! Account recovery seams. The recovery runner owns every history fetch
//! (mdk#2660 phase 4); this module keeps the account's native replay ingress
//! and flushes the recovery observations each seam owes the ledger.
use std::time::Duration;

use super::AppClient;
use crate::{AppError, unix_now_seconds};

use cgka_traits::storage::{StorageError, StorageProvider, StorageResult};

pub(crate) struct AccountRecoveryOwner {
    pub(super) native_batch: Option<transport_nostr_adapter::ReplayBatch>,
    pub(super) native_ingress: Option<transport_nostr_adapter::ReplayIngress>,
    pub(super) retained_spill: std::collections::HashMap<cgka_traits::MessageId, i64>,
    pub(super) native_cursor_target: Option<u64>,
    pub(super) native_receive_pending: bool,
    replay_generation: Option<u64>,
    /// The replay generation the last full synchronization saw, authorized or
    /// not. The adapter bumps its generation only when its replay sources
    /// change; native progress re-sends the same one (mdk#2923 telemetry).
    replay_observed_generation: Option<u64>,
    replay_complete: bool,
    /// The generation the last full synchronization finished while the
    /// adapter was inactive (offline, or no relays). It never authorizes, but
    /// a repeat pass on it, still inactive, has nothing new to record
    /// (mdk#3238).
    replay_inactive_generation: Option<u64>,
    /// The adapter's fence ticket at the last synchronization. It moves when
    /// a live count is admitted, which can be after its generation was
    /// synchronized (mdk#3333).
    replay_fence_ticket: Option<transport_nostr_adapter::ReplayFenceTicket>,
}

/// Wall-clock milliseconds, the precision recovery timestamps are stored at.
pub(crate) fn wall_now_ms() -> StorageResult<u64> {
    duration_ms(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default(),
    )
}

fn duration_ms(value: Duration) -> StorageResult<u64> {
    u64::try_from(value.as_millis()).map_err(|_| {
        StorageError::Serialization("recovery duration outside supported range".into())
    })
}

impl AccountRecoveryOwner {
    pub(super) fn native_replay_authorizes(&self, generation: u64) -> bool {
        self.replay_generation == Some(generation) && self.replay_complete
    }

    /// Whether a full synchronization of `generation` would repeat the last
    /// one: it is authorized, or it was synchronized inactive and the adapter
    /// is still inactive. Activation re-runs it even without a new generation.
    fn native_replay_synchronized(&self, generation: u64, active: bool) -> bool {
        self.native_replay_authorizes(generation)
            || (!active && self.replay_inactive_generation == Some(generation))
    }

    pub(crate) fn open() -> Self {
        Self {
            native_batch: None,
            native_ingress: None,
            retained_spill: std::collections::HashMap::new(),
            native_cursor_target: None,
            native_receive_pending: false,
            replay_generation: None,
            replay_observed_generation: None,
            replay_complete: false,
            replay_inactive_generation: None,
            replay_fence_ticket: None,
        }
    }

    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(crate) fn test_replay_complete(&self) -> bool {
        self.replay_complete
    }
}

impl AppClient {
    /// Native ingress remains ordered. Its original windows become durable
    /// ledger debt, without legacy replay obligations or a coverage claim.
    /// The actual seal still checks this generation, placement and held frames
    /// under the plane's existing locks.
    async fn synchronize_runner_native_replay(
        &mut self,
        observation: transport_nostr_adapter::ReplayAdmissionStatus<'_>,
    ) -> Result<(), AppError> {
        let generation = observation.generation();
        let changed_generation = self.recovery_owner.replay_generation != Some(generation);
        self.recovery_owner.replay_generation = None;
        self.recovery_owner.replay_complete = false;
        self.recovery_owner.replay_inactive_generation = None;
        let active = observation.active();
        let floor = unix_now_seconds()
            .saturating_sub(storage_sqlite::TRANSPORT_RECONCILIATION_RETENTION_SECS);
        let routing = self.routing.snapshot();
        let mut goals = std::collections::BTreeMap::<u64, Vec<_>>::new();
        for source in observation.sources() {
            let routes = source
                .group_routes()
                .copied()
                .filter(|route| {
                    routing
                        .group_routes
                        .iter()
                        .any(|current| current.transport_group_id.as_slice() == route.as_slice())
                })
                .map(storage_sqlite::TransportReconciliationRoute::Group)
                .collect::<Vec<_>>();
            let routes = if source.group_routes().next().is_none() {
                vec![storage_sqlite::TransportReconciliationRoute::Inbox]
            } else {
                routes
            };
            goals
                .entry(source.since().max(floor))
                .or_default()
                .extend(routes);
        }
        drop(observation);
        #[cfg(test)]
        if let Some((reached, release)) = self.test_replay_sync_gate.take() {
            let _ = reached.send(());
            let _ = release.await;
        }
        let storage = self.app.account_storage(&self.state.label)?;
        let app = storage.app_storage();
        self.synchronize_recovery_loss(&app)?;
        self.finish_runner_loss_import()?;
        storage.with_transaction(|_| {
            for (since, routes) in &goals {
                app.widen_recovery_coverage_goals(
                    routes,
                    *since,
                    storage_sqlite::CopyFloorReason::Clamp,
                )?;
            }
            Ok::<_, StorageError>(())
        })?;
        if changed_generation {
            self.wake_recovery_runner();
        }
        self.record_native_coverage(&app).await;
        // Permission means the input is placed or durably owed, never that a
        // full live EOSE proved complete history. A stale generation cannot seal.
        self.recovery_owner.replay_generation = active.then_some(generation);
        self.recovery_owner.replay_complete = active;
        self.recovery_owner.replay_inactive_generation = (!active).then_some(generation);
        Ok(())
    }

    /// Copy limited native source facts, then persist without holding the
    /// adapter guard. The cursor seal rechecks the copied generation and current
    /// pending/loss facts; this is never exhaustive history or loss evidence.
    pub(crate) async fn synchronize_native_replay(&mut self) -> Result<(), AppError> {
        let adapter = self.adapter.clone();
        let observation = adapter.replay_admission().await;
        let generation = observation.generation();
        // The generation this pass synchronizes, recorded from the same
        // guarded snapshot it classifies and processes: the next full pass for
        // a later one counts as a source change (mdk#2923 telemetry).
        let previous = self
            .recovery_owner
            .replay_observed_generation
            .replace(generation);
        // A count admitted since the last look may have armed a fence, which
        // holds its groups' live frames until the runner answers it. Its EOSE
        // can arrive after the generation was synchronized, so wake the
        // runner even when the generation needs no new pass (mdk#3333).
        let ticket = observation.fence_ticket();
        if self.recovery_owner.replay_fence_ticket.replace(ticket) != Some(ticket) {
            self.wake_recovery_runner();
        }
        if self
            .recovery_owner
            .native_replay_synchronized(generation, observation.active())
            && !self.delivery_loss_blocks_cursor()
        {
            return Ok(());
        }
        // Each full synchronization is timed under its trigger: a changed
        // source set (a new generation) or a retry of one that did not
        // authorize, each with or without admission still pending. Success
        // means it authorized the generation (mdk#2923).
        let reason = match (
            previous == Some(generation),
            observation.pending || observation.spill_pending,
        ) {
            (false, false) => crate::RuntimePerformanceOperation::ReplaySyncSourcesChanged,
            (false, true) => crate::RuntimePerformanceOperation::ReplaySyncSourcesChangedPending,
            (true, false) => crate::RuntimePerformanceOperation::ReplaySyncRetry,
            (true, true) => crate::RuntimePerformanceOperation::ReplaySyncRetryPending,
        };
        let span = self
            .runtime_telemetry
            .as_ref()
            .map(|telemetry| telemetry.observe(reason));
        let result = self.synchronize_runner_native_replay(observation).await;
        if let Some(span) = span {
            // The adapter may have moved on while this ran; the pass succeeded
            // if the generation it holds now is authorized.
            let current = self.adapter.replay_admission().await.generation();
            span.finish(match &result {
                Err(_) => marmot_observability::Outcome::Failure,
                Ok(()) if self.recovery_owner.native_replay_authorizes(current) => {
                    marmot_observability::Outcome::Success
                }
                Ok(()) => marmot_observability::Outcome::NotReady,
            });
        }
        result
    }

    /// Floor of a joined group's post-join maintenance REQ: the creation of the
    /// Welcome that installed this copy, less the clock-skew allowance.
    ///
    /// The member cannot open anything older than its join epoch, and the
    /// commits it must see before its first self-update were made after that
    /// Welcome, however late the member processed it. So the anchor is the
    /// Welcome, which the engine clamps to no later than the join, and never
    /// the local join time. `None`, a full-history request, when the copy has
    /// no Welcome time.
    pub(crate) fn post_join_maintenance_since(
        &self,
        group_id: &cgka_traits::GroupId,
    ) -> Option<cgka_traits::transport::Timestamp> {
        self.runtime
            .group_record(group_id)
            .ok()?
            .local_copy_welcome_created_at
            .map(|created_at| crate::history_floor(created_at.0))
    }

    /// Imported ledger debt replaces the cursor's loss fence. This is a
    /// durable handoff, not proof of recovery and not a recovery-success metric.
    pub(crate) fn finish_runner_loss_import(&mut self) -> Result<bool, AppError> {
        let storage = self.app.account_storage(&self.state.label)?;
        let app = storage.app_storage();
        let entries = app
            .converted_recovery_loss()?
            .into_iter()
            .filter(|entry| entry.account_label == self.state.label)
            .collect::<Vec<_>>();
        let observed = self.adapter.pending_delivery_overflow_generation();
        if let Some(observed) = observed {
            self.delivery_overflow_recovery_pending = true;
            let contains = |cause, token, count| {
                entries.iter().any(|entry| {
                    entry.cause == cause
                        && entry.watermarks.iter().any(|watermark| {
                            watermark.marker_token == token && watermark.observed_count == count
                        })
                })
            };
            if (observed.dropped > 0
                && !contains(
                    storage_sqlite::RecoveryLossCause::Queue,
                    observed.marker_token,
                    observed.dropped,
                ))
                || (observed.notification_losses > 0
                    && !contains(
                        storage_sqlite::RecoveryLossCause::NotificationConsumer,
                        observed.notification_token,
                        0,
                    ))
            {
                return Ok(false);
            }
            // Exact current counters, durable marker, no marker writer still
            // running and no queued signal. The plane holds all these checks
            // under its own lock; a concurrent new omission keeps its guard.
            if self
                .adapter
                .finish_delivery_overflow_recovery(observed)
                .is_none()
            {
                return Ok(false);
            }
        }
        let restore_token = observed.map(|observed| observed.marker_token).or_else(|| {
            entries
                .iter()
                .flat_map(|entry| &entry.watermarks)
                .next()
                .map(|mark| mark.marker_token)
        });
        let reclaimed = storage.with_transaction(|_| {
            for entry in &entries {
                if !app.reclaim_converted_recovery_loss(entry)? {
                    return Err(StorageError::NotFound);
                }
            }
            Ok::<_, StorageError>(())
        });
        if let Err(error) = reclaimed {
            self.delivery_overflow_recovery_pending = true;
            if let Some(token) = restore_token {
                self.adapter.restore_delivery_overflow_guard(token);
            }
            return Err(error.into());
        }
        let pending = self.adapter.pending_delivery_overflow_generation();
        self.delivery_overflow_recovery_pending = pending.is_some();
        self.delivery_overflow_recovery_marker_token = pending.map(|pending| pending.marker_token);
        Ok(!self.delivery_overflow_recovery_pending)
    }

    /// Whether recovery may contact any relay of the account's routes. With
    /// none, no grant can be selected, so no caller should wait for a credit.
    pub(crate) fn recovery_endpoints_admitted(&self) -> bool {
        let routing = self.routing.snapshot();
        !self
            .adapter
            .recovery_admitted_endpoints(&routing.local_inbox_endpoints)
            .is_empty()
            || routing.group_routes.iter().any(|route| {
                !self
                    .adapter
                    .recovery_admitted_endpoints(&route.endpoints)
                    .is_empty()
            })
    }

    /// Flush recovery observations at a recovery seam: synchronize native
    /// replay facts, import loss, retry buffered epoch-gap arms and consume
    /// released receipts. A wake-collection
    /// (`CursorPersistence::Frozen`) process leaves them to an Advance runtime.
    /// The recovery runner owns every history fetch (mdk#2660 phase 4).
    pub(crate) async fn refresh_account_recovery(&mut self) -> Result<(), AppError> {
        self.synchronize_native_replay().await?;
        if self.app.cursor_persistence() == crate::CursorPersistence::Frozen {
            return Ok(());
        }
        let storage = self.app.account_storage(&self.state.label)?;
        self.synchronize_recovery_loss(&storage.app_storage())?;
        // Failed detector persistence is retried here. These observations
        // carry demand only; SQL remains the retry authority.
        let arms = self.history_recovery.buffered_epoch_gap_arms();
        self.arm_epoch_gap_recovery(&arms)?;
        self.history_recovery.clear_buffered_epoch_gap_arms();
        drop(self.transport_receipts()?);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    async fn native_fixture() -> (
        tempfile::TempDir,
        crate::MarmotApp,
        Arc<crate::tests::ScriptedPushRelayClient>,
        AppClient,
    ) {
        let dir = tempfile::tempdir().unwrap();
        crate::AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let relay = Arc::new(crate::tests::ScriptedPushRelayClient::default());
        // These tests answer each REQ themselves, to see the owner before
        // and after its EOSE.
        relay.hold_replies(Some(crate::tests::every_reply));
        let mut app = crate::MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(relay.clone());
        app.relay_plane = crate::MarmotRelayPlane::new_with_directory_fetcher_for_test(
            Some(Duration::from_secs(120)),
            relay.clone(),
            relay.clone(),
            app.config.allow_loopback_relay_endpoints,
        );
        relay.connect_relays(&["wss://relay.example"]).await;
        let client = crate::tests::client_on_app_relay_plane(&app, "alice").await;
        (dir, app, relay, client)
    }

    /// #2793: an unadmitted, unfloored inbox scope an earlier owner left
    /// behind must not broaden a newly current group's live REQ after
    /// conversion. The runner keeps the inbox debt without inheriting its
    /// query floor.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn runner_owned_inbox_debt_does_not_lower_a_new_groups_live_req() {
        use cgka_traits::transport::Timestamp;
        use transport_nostr_adapter::NostrSubscription;
        let dir = tempfile::tempdir().unwrap();
        crate::AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let relay = Arc::new(crate::tests::ScriptedPushRelayClient::default());
        relay.hold_replies(Some(crate::tests::every_reply));
        let mut app = crate::MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(relay.clone());
        app.relay_plane = crate::MarmotRelayPlane::new_with_directory_fetcher_for_test(
            Some(Duration::from_secs(120)),
            relay.clone(),
            relay.clone(),
            app.config.allow_loopback_relay_endpoints,
        );
        relay.connect_relays(&["wss://relay.example"]).await;
        // A nightly-shaped durable input, written as an earlier owner wrote
        // it before any runner opened the account: a newer saved cursor
        // beside a still-unadmitted native inbox scope with no floor.
        let ledger = app.account_storage("alice").unwrap().app_storage();
        let cursor = unix_now_seconds().saturating_sub(60);
        let payload = serde_json::json!({
            "required_endpoints": ["wss://relay.example"],
            "admitted_endpoints": ["wss://relay.example"],
            "checkpoints": [], "retained_known_event": false, "attempt_serial": 1,
            "obligation_revision": 1, "loss_revision": 0, "route_revision": 0,
            "inventory_revision": 0,
        });
        ledger
            .execute_batch_for_test(&format!(
                "INSERT INTO account_recovery_obligations (id, demand_key, cause, predicate,
                     created_at_ms, updated_at_ms)
                 VALUES (x'{id}', 'replay:{snapshot}', 7, 3, 0, 0);
                 INSERT INTO account_recovery_scopes (obligation_id, scope_id, route_kind,
                     route_role, until_seconds, snapshot_state, scope_format, scope_payload)
                 VALUES (x'{id}', 1, 0, 0, {cursor}, 1, 1, CAST('{payload}' AS BLOB));",
                id = "07".repeat(16),
                snapshot = "07".repeat(32),
            ))
            .unwrap();
        let mut state = app.load_state("alice").unwrap();
        state.last_transport_timestamp = Some(cursor);
        app.save_state(&state).unwrap();

        let mut client = crate::tests::client_on_app_relay_plane(&app, "alice").await;
        let before = relay.accepted_subscriptions().len();
        let group = client
            .create_group("new route while inbox owes", &[])
            .await
            .unwrap()
            .operation
            .expect("eligible fixture members");
        let live_since = relay
            .accepted_subscriptions()
            .into_iter()
            .skip(before)
            .filter_map(|subscription| match subscription {
                NostrSubscription::Group {
                    group_id, since, ..
                } if group_id == group => Some(since),
                NostrSubscription::GroupBatch { routes, since, .. }
                    if routes.iter().any(|route| route.group_id == group) =>
                {
                    Some(since)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(
            !live_since.is_empty(),
            "a real live group REQ must have been issued"
        );
        let expected = Some(Timestamp(cursor.saturating_sub(120)));
        assert!(
            live_since.iter().all(|since| *since == expected),
            "new group's live REQs {live_since:?}, expected {expected:?}"
        );
        let inbox = storage_sqlite::TransportReconciliationRoute::Inbox;
        assert!(!ledger.recovery_conversion_pending().unwrap());
        assert!(
            ledger.recovery_coverage_goal(&inbox).unwrap().unwrap() < cursor - 120,
            "conversion keeps older inbox debt beyond the new group's live range"
        );
        assert!(
            ledger
                .recovery_coverage_ranges(&inbox, "wss://relay.example")
                .unwrap()
                .is_empty(),
            "the inbox has not answered or proved coverage"
        );
        assert!(
            ledger
                .pending_recovery_demands()
                .unwrap()
                .iter()
                .all(|demand| demand.cause != storage_sqlite::RecoveryCause::SubscriptionReplay)
        );
    }

    /// Each full replay synchronization is timed under its trigger: opening
    /// the transport syncs a new generation, a sync on a generation that did
    /// not authorize is a retry, and an authorized generation records nothing
    /// (mdk#2923).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn native_replay_synchronization_is_timed_by_trigger() {
        use crate::RuntimePerformanceOperation as Op;
        let (_dir, _app, relay, mut client) = native_fixture().await;
        let telemetry = marmot_observability::PerformanceRecorder::default();
        client.runtime_telemetry = Some(telemetry.clone());
        let spans = |op: Op| {
            telemetry
                .snapshot()
                .runtime_operations
                .into_iter()
                .find(|snapshot| snapshot.operation == op)
                .map(|snapshot| (snapshot.completed, snapshot.successes))
                .unwrap()
        };
        client.prepare_transport().await.unwrap();
        assert!(
            spans(Op::ReplaySyncSourcesChanged).0 >= 1,
            "opening the transport syncs its first generation"
        );
        relay.answer_held_replies().await;
        client.synchronize_native_replay().await.unwrap();
        let generation = client.adapter.replay_admission().await.generation();
        assert!(client.recovery_owner.native_replay_authorizes(generation));

        let (retries, retry_successes) = spans(Op::ReplaySyncRetry);
        let changed = spans(Op::ReplaySyncSourcesChanged);
        client.recovery_owner.replay_generation = Some(generation.wrapping_sub(1));
        client.synchronize_native_replay().await.unwrap();
        assert_eq!(
            spans(Op::ReplaySyncRetry),
            (retries + 1, retry_successes + 1),
            "the same generation again is a retry, and it authorizes"
        );
        assert_eq!(spans(Op::ReplaySyncSourcesChanged), changed);

        client.synchronize_native_replay().await.unwrap();
        assert_eq!(
            spans(Op::ReplaySyncRetry),
            (retries + 1, retry_successes + 1),
            "an authorized generation records nothing"
        );
    }

    /// An inactive adapter's generation never authorizes, but a repeat pass
    /// on it while still inactive has nothing new to record and is skipped,
    /// so an offline account's idle ticks take no writer (mdk#3238).
    /// Activation re-runs the pass even on the same generation.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_inactive_generation_is_synchronized_once_until_activation() {
        use crate::RuntimePerformanceOperation as Op;
        let telemetry = marmot_observability::PerformanceRecorder::default();
        let passes = || {
            telemetry
                .snapshot()
                .runtime_operations
                .into_iter()
                .filter(|snapshot| {
                    matches!(
                        snapshot.operation,
                        Op::ReplaySyncSourcesChanged
                            | Op::ReplaySyncSourcesChangedPending
                            | Op::ReplaySyncRetry
                            | Op::ReplaySyncRetryPending
                    )
                })
                .map(|snapshot| snapshot.completed)
                .sum::<u64>()
        };
        let (_dir, app, relay, mut client) = native_fixture().await;
        client.runtime_telemetry = Some(telemetry.clone());
        client.prepare_transport().await.unwrap();
        relay.answer_held_replies().await;
        client.synchronize_native_replay().await.unwrap();
        // Offline: the account's route set is gone from the adapter.
        app.relay_plane
            .deactivate_account_context(client.adapter.account_id())
            .await
            .unwrap();
        let inactive = client.adapter.replay_admission().await;
        assert!(!inactive.active());
        let generation = inactive.generation();
        drop(inactive);
        let before = passes();
        client.synchronize_native_replay().await.unwrap();
        assert_eq!(passes(), before + 1, "the first inactive pass runs in full");
        assert!(!client.recovery_owner.native_replay_authorizes(generation));
        client.synchronize_native_replay().await.unwrap();
        assert_eq!(
            passes(),
            before + 1,
            "a repeat on the same inactive generation is skipped"
        );

        // Reconnecting synchronizes the account again until it authorizes.
        client.prepare_transport().await.unwrap();
        relay.answer_held_replies().await;
        client.synchronize_native_replay().await.unwrap();
        let generation = client.adapter.replay_admission().await.generation();
        assert!(client.recovery_owner.native_replay_authorizes(generation));
    }

    /// A pass records the generation it synchronized, not one the adapter
    /// moved to while it ran: the first full pass for the later generation
    /// still counts as a source change (mdk#2923).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_generation_change_during_a_pass_counts_as_a_source_change() {
        use crate::RuntimePerformanceOperation as Op;
        let (_dir, _app, relay, mut client) = native_fixture().await;
        let telemetry = marmot_observability::PerformanceRecorder::default();
        client.runtime_telemetry = Some(telemetry.clone());
        let changed = || {
            telemetry
                .snapshot()
                .runtime_operations
                .into_iter()
                .find(|snapshot| snapshot.operation == Op::ReplaySyncSourcesChanged)
                .unwrap()
                .completed
        };
        client.prepare_transport().await.unwrap();
        relay.answer_held_replies().await;
        client.synchronize_native_replay().await.unwrap();
        let first = client.adapter.replay_admission().await.generation();
        assert!(client.recovery_owner.native_replay_authorizes(first));

        // A full pass on the first generation, which the adapter leaves for
        // the second while the pass is paused after its snapshot.
        client.recovery_owner.replay_generation = Some(first.wrapping_sub(1));
        let (reached_tx, reached) = tokio::sync::oneshot::channel();
        let (release, release_rx) = tokio::sync::oneshot::channel();
        client.test_replay_sync_gate = Some((reached_tx, release_rx));
        let adapter = client.adapter.clone();
        let (pass, ()) = tokio::join!(client.synchronize_native_replay(), async move {
            reached.await.unwrap();
            adapter.change_replay_sources_for_test().await;
            release.send(()).unwrap();
        });
        pass.unwrap();
        let second = client.adapter.replay_admission().await.generation();
        assert_ne!(second, first, "the adapter moved on during the pass");
        assert_eq!(
            client.recovery_owner.replay_observed_generation,
            Some(first)
        );

        let before = changed();
        client.synchronize_native_replay().await.unwrap();
        assert_eq!(changed(), before + 1, "the second generation's first pass");
    }
}
