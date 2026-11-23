//! Inbound subscription drain loop, delivery of what was stored after a scope's durable mark,
//! and storage-backed replay after broadcast lag.

use agent_control::{
    AgentControlEnvelope, AgentControlError, AgentControlEvent, AgentControlRequest,
    AgentControlResponse, read_envelope,
};
use marmot_account::AccountSummary;
use marmot_app::{AppMessageQuery, AppMessageRecord, MarmotAppEvent};
use tokio::io::{AsyncBufRead, AsyncWrite};
use tokio::sync::broadcast;

use crate::AgentConnector;
use crate::DELIVERED_INBOUND_CURSOR_CAPACITY;
use crate::connection::write_control_frame;
use crate::error::ConnectorError;
use crate::event_projection::{
    DeliveredInboundCursor, InboundCatchUpEvent, control_event_from_debug_event,
    control_event_from_runtime_event_with_runtime, inbound_message_event_from_record_with_runtime,
    resync_required_event, runtime_replay_dedup_key,
};
use crate::reconcile_telemetry::ReconcileTelemetry;
use crate::validation::agent_control_request_type;

impl AgentConnector {
    pub(crate) async fn stream_inbound_events<R, W>(
        &self,
        request_id: Option<String>,
        account_id_hex: Option<String>,
        group_id_hex: Option<String>,
        reader: &mut R,
        writer: &mut W,
    ) -> Result<(), ConnectorError>
    where
        R: AsyncBufRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut runtime_events = self.runtime.subscribe();
        let mut debug_events = self.debug_events.subscribe();
        let (mut catch_up_events, _catch_up_subscription) = self.inbound_catch_up.subscribe();

        let response = AgentControlEnvelope::new(request_id.clone(), AgentControlResponse::Ack);
        write_control_frame(writer, &response).await?;

        // Tracks the durable storage row ids already delivered on this subscription so a
        // storage-backed replay after broadcast lag re-delivers only genuinely-missed
        // events (never re-flooding the agent with facts it already handled, and never
        // double-delivering one that raced live delivery). Bounded so a long-lived
        // subscription cannot grow this set without limit; the queue evicts the oldest ids.
        let mut delivered = DeliveredInboundCursor::new(DELIVERED_INBOUND_CURSOR_CAPACITY);

        // mdk#3551: hand over what was stored after this scope's mark while no subscriber was
        // attached, such as a message that arrived during a gateway restart. The runtime
        // receiver above was subscribed first, so nothing stored after this read is missed.
        match self.inbound_accounts(account_id_hex.as_deref()) {
            Ok(accounts) => {
                for account in accounts {
                    self.deliver_stored_inbound(
                        &request_id,
                        &account.label,
                        &account.account_id_hex,
                        group_id_hex.as_deref(),
                        &mut delivered,
                        writer,
                    )
                    .await?;
                }
            }
            Err(err) => {
                self.signal_stored_inbound_unread(
                    &request_id,
                    account_id_hex.as_deref(),
                    group_id_hex.as_deref(),
                    &err,
                    writer,
                )
                .await?;
            }
        }

        // Request the initial catch-up without blocking this drain loop. catch_up_accounts() can
        // block for as long as an account's startup keeps progressing, up to
        // APP_RUNTIME_ACCOUNT_READY_WAIT after it stalls, and can itself emit many runtime
        // events; keeping this loop live prevents the bounded broadcast channel from dropping
        // inbound user messages while catch-up is in flight.
        let catch_up_driver = self.inbound_catch_up.clone();
        let mut initial_catch_up = Box::pin(async move {
            catch_up_driver
                .request()
                .await
                .map_err(ConnectorError::from)
        });
        let mut initial_catch_up_pending = true;

        // The account of the last live message or group-state notice this subscription covers.
        // The notice wakes a read of what that account stored after its mark: MDK may store a
        // row before announcing it, or announce rows out of storage order, so the mark moves
        // only through what storage holds, never from the notice itself.
        let mut stored_account: Option<(String, String)> = None;
        loop {
            if let Some((account_label, account_id_hex)) = stored_account.take() {
                self.deliver_stored_inbound(
                    &request_id,
                    &account_label,
                    &account_id_hex,
                    group_id_hex.as_deref(),
                    &mut delivered,
                    writer,
                )
                .await?;
            }
            let event = tokio::select! {
                catch_up_result = &mut initial_catch_up, if initial_catch_up_pending => {
                    initial_catch_up_pending = false;
                    if let Err(err) = catch_up_result {
                        let response = AgentControlEnvelope::new(
                            request_id.clone(),
                            self.error_response("stream_inbound_events", &err),
                        );
                        write_control_frame(writer, &response).await?;
                        return Ok(());
                    }
                    continue;
                }
                // SubscribeInbound is read-only after the initial request: clients are only
                // expected to close the stream. read_envelope() uses read_until(), which is
                // not cancellation-safe for partial frames inside select!; switch this to a
                // cancellation-safe framed read before adding subscriber-side messages here.
                read = read_envelope(reader) => {
                    let read: Result<Option<AgentControlEnvelope<AgentControlRequest>>, AgentControlError> = read;
                    match read {
                        Ok(None) => return Ok(()),
                        Ok(Some(envelope)) => {
                            let request_type = agent_control_request_type(&envelope.payload);
                            tracing::warn!(
                                target: "agent_connector",
                                method = "stream_inbound_events",
                                request_type,
                                "additional request received after SubscribeInbound"
                            );
                            continue;
                        }
                        Err(err) => return Err(err.into()),
                    }
                }
                catch_up = catch_up_events.recv() => {
                    match catch_up {
                        Ok(InboundCatchUpEvent::Completed)
                        | Err(broadcast::error::RecvError::Lagged(_)) => {}
                        Err(broadcast::error::RecvError::Closed) => return Ok(()),
                    }
                    continue;
                }
                event = runtime_events.recv() => {
                    match event {
                        Ok(event) => {
                            let replay_id = runtime_replay_dedup_key(&event);
                            if replay_id.is_some() {
                                stored_account =
                                    runtime_event_account(&event, account_id_hex.as_deref());
                            }
                            match control_event_from_runtime_event_with_runtime(
                                &self.runtime,
                                event,
                                account_id_hex.as_deref(),
                                group_id_hex.as_deref(),
                            ) {
                                Ok(event) => event.map(|event| (event, replay_id)),
                                Err(err) => {
                                    // Hydration reads are best-effort at this live boundary.
                                    // A transient storage failure must not tear down the
                                    // subscription and strand the client outside the adjacent
                                    // lag-recovery path. Signal one undelivered event so the
                                    // consumer reconnects and lets durable replay retry it.
                                    let error_code =
                                        ConnectorError::from(err).privacy_safe_code();
                                    tracing::warn!(
                                        target: "agent_connector",
                                        method = "stream_inbound_events",
                                        dropped_events = 1_u64,
                                        error_code,
                                        "live inbound projection failed; emitting resync_required"
                                    );
                                    ReconcileTelemetry::bump(&self.reconcile_telemetry.resync_required);
                                    Some((
                                        resync_required_event(
                                            account_id_hex.as_deref(),
                                            group_id_hex.as_deref(),
                                            1,
                                        ),
                                        None,
                                    ))
                                }
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(dropped))
                            if dropped > crate::DELIVERED_INBOUND_CURSOR_CAPACITY as u64 =>
                        {
                            // The lag exceeded the bounded storage-replay window: the
                            // newest-window replay (capped at DELIVERED_INBOUND_CURSOR_CAPACITY
                            // rows) cannot be guaranteed to include every dropped message —
                            // missed messages older than that window fall outside it. Emit
                            // resync_required so the agent performs a full reconcile rather than
                            // resuming with older messages silently omitted, instead of treating
                            // a necessarily-partial replay as complete.
                            tracing::warn!(
                                target: "agent_connector",
                                method = "stream_inbound_events",
                                dropped_events = dropped,
                                replay_window = crate::DELIVERED_INBOUND_CURSOR_CAPACITY,
                                "inbound broadcast lag exceeded the bounded replay window; emitting resync_required"
                            );
                            ReconcileTelemetry::bump(&self.reconcile_telemetry.resync_required);
                            Some((
                                resync_required_event(
                                    account_id_hex.as_deref(),
                                    group_id_hex.as_deref(),
                                    dropped,
                                ),
                                None,
                            ))
                        }
                        Err(broadcast::error::RecvError::Lagged(dropped)) => {
                            // The broadcast channel overflowed: `dropped` events were evicted
                            // before we could deliver them and are gone from the channel for
                            // good (catch-up never re-emits already-broadcast messages). The
                            // drop count is within the bounded replay window (checked above), so
                            // the newest-window storage replay fully covers the gap. Recover the
                            // missed inbound messages from durable storage and re-deliver them on
                            // the existing InboundMessage path the consumer already handles, so a
                            // reconnect backlog never silently loses user messages. The
                            // delivered-id cursor guarantees we re-deliver only messages this
                            // subscription has not already emitted.
                            // Project each missed row just before writing it: a slow reader
                            // can hold an earlier frame while an author deletes a later
                            // message, and that message must then go out only as its deletion.
                            let observation = self.runtime.begin_product_operation(
                                marmot_app::ProductFamily::Agent,
                                "replay",
                                marmot_app::ProductUnit::Attempt,
                            );
                            let mut replayed_events = 0_usize;
                            let outcome = match self.missed_inbound(
                                account_id_hex.as_deref(),
                                group_id_hex.as_deref(),
                                &delivered,
                            ) {
                                Ok(mut missed) => loop {
                                    match missed.next_event(self, &mut delivered) {
                                        Ok(Some(replayed)) => {
                                            let envelope = AgentControlEnvelope::new(
                                                request_id.clone(),
                                                replayed,
                                            );
                                            write_control_frame(writer, &envelope).await?;
                                            replayed_events += 1;
                                        }
                                        Ok(None) => break Ok(()),
                                        Err(err) => break Err(err),
                                    }
                                },
                                Err(err) => Err(err),
                            };
                            if let Some(observation) = observation {
                                observation.finish(if outcome.is_ok() { "success" } else { "failure" });
                            }
                            match outcome {
                                Ok(()) => {
                                    tracing::warn!(
                                        target: "agent_connector",
                                        method = "stream_inbound_events",
                                        dropped_events = dropped,
                                        replayed_events,
                                        "inbound broadcast lagged; replayed missed events from storage"
                                    );
                                    continue;
                                }
                                Err(err) => {
                                    // Storage replay failed: fall back to the resync_required
                                    // signal so the agent still learns it must re-sync state
                                    // rather than silently losing the dropped messages.
                                    tracing::warn!(
                                        target: "agent_connector",
                                        method = "stream_inbound_events",
                                        dropped_events = dropped,
                                        error_code = err.privacy_safe_code(),
                                        "inbound broadcast lagged; storage replay failed, emitting resync_required"
                                    );
                                    ReconcileTelemetry::bump(&self.reconcile_telemetry.resync_required);
                                    Some((
                                        resync_required_event(
                                            account_id_hex.as_deref(),
                                            group_id_hex.as_deref(),
                                            dropped,
                                        ),
                                        None,
                                    ))
                                }
                            }
                        }
                        Err(broadcast::error::RecvError::Closed) => return Ok(()),
                    }
                }
                event = debug_events.recv() => {
                    match event {
                        Ok(event) => control_event_from_debug_event(
                            event,
                            account_id_hex.as_deref(),
                            group_id_hex.as_deref(),
                        )
                        .map(|event| (event, None)),
                        // Debug channel lag is not user-message loss; skip without resync.
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(broadcast::error::RecvError::Closed) => continue,
                    }
                }
            };
            let Some((event, replay_id)) = event else {
                continue;
            };
            // Track delivered storage row ids so a later replay re-delivers only genuinely-missed
            // events. Skip a live event the cursor already saw (e.g. one just recovered by a
            // replay) so it is never delivered twice. Debug-injected inbound messages have no
            // runtime replay id, so preserve the older message-id dedup behavior for them. If the
            // debug channel ever starts injecting delete/state-change events, they need a durable
            // replay id here before they can safely share storage-backed replay dedup.
            if let Some(replay_id) = replay_id {
                if delivered.contains(&replay_id) {
                    continue;
                }
                delivered.record(replay_id);
            } else if let AgentControlEvent::InboundMessage { message, .. } = &event {
                if delivered.contains(&message.message_id_hex) {
                    continue;
                }
                delivered.record(message.message_id_hex.clone());
            } else {
                debug_assert!(
                    !matches!(
                        &event,
                        AgentControlEvent::MessageEdited { .. }
                            | AgentControlEvent::MessageDeleted { .. }
                            | AgentControlEvent::ReactionAdded { .. }
                            | AgentControlEvent::ReactionRemoved { .. }
                            | AgentControlEvent::GroupStateChanged { .. }
                    ),
                    "debug-injected ambient events need a durable replay id before delivery"
                );
            }
            let envelope = AgentControlEnvelope::new(request_id.clone(), event);
            write_control_frame(writer, &envelope).await?;
        }
    }

    /// The accounts a subscription covers: the one it names, or every local account.
    fn inbound_accounts(
        &self,
        account_filter: Option<&str>,
    ) -> Result<Vec<AccountSummary>, ConnectorError> {
        Ok(match account_filter {
            Some(account_id_hex) => vec![self.local_account_for_account_id(account_id_hex)?],
            None => self.account_home.accounts()?,
        })
    }

    /// Delivers what `account` stored after this scope's durable mark and this subscription has
    /// not sent yet, then moves the mark past every row read (mdk#3551). The first subscriber of
    /// a scope starts at the newest stored row, so history is never replayed as new messages. A
    /// backlog larger than the replay window is signalled with `resync_required` instead of a
    /// partial replay, like broadcast lag. A storage failure leaves the mark where it was, so the
    /// rows are read again on the next notice or subscription. Only a failed write to the client
    /// is returned as an error.
    async fn deliver_stored_inbound<W>(
        &self,
        request_id: &Option<String>,
        account_label: &str,
        account_id_hex: &str,
        group_filter: Option<&str>,
        delivered: &mut DeliveredInboundCursor,
        writer: &mut W,
    ) -> Result<(), ConnectorError>
    where
        W: AsyncWrite + Unpin,
    {
        let read_through = match self.stored_inbound(account_label, account_id_hex, group_filter) {
            Ok(StoredInbound::Start { newest }) => Ok(newest),
            Ok(StoredInbound::Rows { mut rows, through }) => loop {
                match rows.next_event(self, delivered) {
                    Ok(Some(event)) => {
                        let envelope = AgentControlEnvelope::new(request_id.clone(), event);
                        write_control_frame(writer, &envelope).await?;
                    }
                    Ok(None) => break Ok(through),
                    Err(err) => break Err(err),
                }
            },
            Ok(StoredInbound::Overflow { newest, rows }) => {
                tracing::warn!(
                    target: "agent_connector",
                    method = "deliver_stored_inbound",
                    stored_rows = rows,
                    replay_window = DELIVERED_INBOUND_CURSOR_CAPACITY,
                    "stored inbound backlog exceeded the replay window; emitting resync_required"
                );
                ReconcileTelemetry::bump(&self.reconcile_telemetry.resync_required);
                let event = resync_required_event(Some(account_id_hex), group_filter, rows as u64);
                write_control_frame(
                    writer,
                    &AgentControlEnvelope::new(request_id.clone(), event),
                )
                .await?;
                Ok(newest)
            }
            Err(err) => Err(err),
        };
        match read_through {
            Ok(insert_order) => {
                if let Err(err) =
                    self.inbound_marks
                        .advance(account_id_hex, group_filter, insert_order)
                {
                    // Delivery already happened. A mark left behind only repeats those rows to
                    // the next subscriber, which deduplicates by message id.
                    tracing::warn!(
                        target: "agent_connector",
                        method = "deliver_stored_inbound",
                        error_code = err.privacy_safe_code(),
                        "failed to persist the inbound delivery mark"
                    );
                }
                Ok(())
            }
            Err(err) => {
                self.signal_stored_inbound_unread(
                    request_id,
                    Some(account_id_hex),
                    group_filter,
                    &err,
                    writer,
                )
                .await
            }
        }
    }

    /// Tells the client that stored rows could not be read, so it re-pages the timeline.
    async fn signal_stored_inbound_unread<W>(
        &self,
        request_id: &Option<String>,
        account_filter: Option<&str>,
        group_filter: Option<&str>,
        err: &ConnectorError,
        writer: &mut W,
    ) -> Result<(), ConnectorError>
    where
        W: AsyncWrite + Unpin,
    {
        tracing::warn!(
            target: "agent_connector",
            method = "deliver_stored_inbound",
            error_code = err.privacy_safe_code(),
            "stored inbound read failed; emitting resync_required"
        );
        ReconcileTelemetry::bump(&self.reconcile_telemetry.resync_required);
        let event = resync_required_event(account_filter, group_filter, 1);
        write_control_frame(
            writer,
            &AgentControlEnvelope::new(request_id.clone(), event),
        )
        .await
    }

    /// Reads what `account` stored after this scope's mark, in storage order.
    fn stored_inbound(
        &self,
        account_label: &str,
        account_id_hex: &str,
        group_filter: Option<&str>,
    ) -> Result<StoredInbound, ConnectorError> {
        let page = |after: i64| -> Result<Vec<AppMessageRecord>, ConnectorError> {
            let query = AppMessageQuery {
                group_id_hex: group_filter.map(str::to_owned),
                kinds: None,
                limit: Some(DELIVERED_INBOUND_CURSOR_CAPACITY + 1),
            };
            Ok(self
                .runtime
                .messages_after_insert_order(account_label, query, after)?)
        };
        // Pages on to the newest stored row, counting the rows passed.
        let newest_after = |mut after: i64| -> Result<(i64, usize), ConnectorError> {
            let mut rows = 0;
            loop {
                let page = page(after)?;
                let Some(last) = page.last() else {
                    return Ok((after, rows));
                };
                after = last.insert_order;
                rows += page.len();
                if page.len() <= DELIVERED_INBOUND_CURSOR_CAPACITY {
                    return Ok((after, rows));
                }
            }
        };
        let Some(mark) = self.inbound_marks.get(account_id_hex, group_filter)? else {
            let (newest, _) = newest_after(0)?;
            return Ok(StoredInbound::Start { newest });
        };
        let rows = page(mark)?;
        let through = rows.last().map_or(mark, |row| row.insert_order);
        if rows.len() > DELIVERED_INBOUND_CURSOR_CAPACITY {
            let (newest, more) = newest_after(through)?;
            return Ok(StoredInbound::Overflow {
                newest,
                rows: rows.len() + more,
            });
        }
        let rows = rows
            .into_iter()
            .map(|row| (account_label.to_owned(), account_id_hex.to_owned(), row))
            .collect::<Vec<_>>();
        Ok(StoredInbound::Rows {
            rows: MissedInbound {
                account_filter: Some(account_id_hex.to_owned()),
                group_filter: group_filter.map(str::to_owned),
                rows: rows.into_iter(),
            },
            through,
        })
    }

    /// Recover control events that were dropped from the broadcast channel by re-reading durable
    /// per-account storage. Returns the rows this subscription's filters cover and `delivered`
    /// has not recorded; [`MissedInbound::next_event`] projects them one at a time. This is how a
    /// lagged subscription recovers ambient inbound facts instead of silently losing them: the
    /// connector re-queries its own state, exactly the resync the agent could not perform on its
    /// own.
    pub(crate) fn missed_inbound(
        &self,
        account_filter: Option<&str>,
        group_filter: Option<&str>,
        delivered: &DeliveredInboundCursor,
    ) -> Result<MissedInbound, ConnectorError> {
        // Replay for the filtered account, or for every local account on an unscoped
        // subscription (mirroring the live path, which emits for all local accounts).
        let accounts = self.inbound_accounts(account_filter)?;
        let mut rows = Vec::new();
        for account in accounts {
            // #609/#747: bound the replay to the newest `DELIVERED_INBOUND_CURSOR_CAPACITY`
            // rows instead of `limit: None` (the entire per-account history). Lag
            // recovery only needs to look back as far as the delivered cursor can
            // dedup against (4096), and the broadcast ring that overflowed is far
            // smaller (1024) — so a window of the cursor capacity comfortably covers
            // anything that could have been dropped, while keeping replay O(window)
            // instead of O(history) on the same task that must keep draining the
            // broadcast channel. The `limit` path returns the newest N rows (see
            // `SqliteAppStorage::app_messages`), which is exactly the recent
            // window a lagged subscription missed.
            let query = AppMessageQuery {
                group_id_hex: group_filter.map(str::to_owned),
                kinds: None,
                limit: Some(crate::DELIVERED_INBOUND_CURSOR_CAPACITY),
            };
            let records = self.runtime.messages_with_query(&account.label, query)?;
            rows.extend(
                records
                    .into_iter()
                    .filter(|record| !delivered.contains(&record.message_id_hex))
                    .map(|record| {
                        (
                            account.label.clone(),
                            account.account_id_hex.clone(),
                            record,
                        )
                    }),
            );
        }
        Ok(MissedInbound {
            account_filter: account_filter.map(str::to_owned),
            group_filter: group_filter.map(str::to_owned),
            rows: rows.into_iter(),
        })
    }
}

/// What an account stored after a scope's mark.
enum StoredInbound {
    /// The scope had no mark: everything stored up to `newest` is history.
    Start { newest: i64 },
    /// The rows to deliver, and the position of the last row read.
    Rows { rows: MissedInbound, through: i64 },
    /// More rows than the replay window, up to `newest`.
    Overflow { newest: i64, rows: usize },
}

/// The account of a live message or group-state notice that `account_filter` covers.
fn runtime_event_account(
    event: &MarmotAppEvent,
    account_filter: Option<&str>,
) -> Option<(String, String)> {
    let (account_label, account_id_hex) = match event {
        MarmotAppEvent::MessageReceived(update) => (&update.account_label, &update.account_id_hex),
        MarmotAppEvent::GroupEvent(group_event) => {
            (&group_event.account_label, &group_event.account_id_hex)
        }
        _ => return None,
    };
    account_filter
        .is_none_or(|filter| filter == account_id_hex)
        .then(|| (account_label.clone(), account_id_hex.clone()))
}

/// Stored rows a lagged subscription missed, still unprojected. Each row is projected only when
/// the caller is ready to write it, so the projection sees the row's state at that moment (a
/// message deleted meanwhile yields nothing; its deletion is a row of its own).
pub(crate) struct MissedInbound {
    account_filter: Option<String>,
    group_filter: Option<String>,
    rows: std::vec::IntoIter<(String, String, marmot_app::AppMessageRecord)>,
}

impl MissedInbound {
    /// Project the next missed row this subscription should receive, recording it in
    /// `delivered`, or `None` once every row is done.
    pub(crate) fn next_event(
        &mut self,
        connector: &AgentConnector,
        delivered: &mut DeliveredInboundCursor,
    ) -> Result<Option<AgentControlEvent>, ConnectorError> {
        for (account_label, account_id_hex, record) in self.rows.by_ref() {
            let replay_id = record.message_id_hex.clone();
            if delivered.contains(&replay_id) {
                continue;
            }
            let Some(event) = inbound_message_event_from_record_with_runtime(
                &connector.runtime,
                &account_label,
                &account_id_hex,
                record,
                self.account_filter.as_deref(),
                self.group_filter.as_deref(),
            )?
            else {
                continue;
            };
            delivered.record(replay_id);
            return Ok(Some(event));
        }
        Ok(None)
    }
}
