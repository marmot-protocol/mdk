//! Inbound subscription drain loop, and delivery of what was stored after a scope's durable mark
//! on subscribe, after live notices and after broadcast lag.

use agent_control::{
    AgentControlEnvelope, AgentControlError, AgentControlEvent, AgentControlRequest,
    AgentControlResponse, read_envelope,
};
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
        self.deliver_stored_for_subscription(
            &request_id,
            account_id_hex.as_deref(),
            group_id_hex.as_deref(),
            &mut delivered,
            writer,
        )
        .await?;

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
                        Err(broadcast::error::RecvError::Lagged(dropped)) => {
                            // The broadcast channel overflowed: `dropped` events are gone from
                            // the channel for good. Deliver what storage holds after the
                            // delivery mark instead; the delivered-id cursor skips what this
                            // subscription already emitted.
                            tracing::warn!(
                                target: "agent_connector",
                                method = "stream_inbound_events",
                                dropped_events = dropped,
                                "inbound broadcast lagged; delivering missed events from storage"
                            );
                            let observation = self.runtime.begin_product_operation(
                                marmot_app::ProductFamily::Agent,
                                "replay",
                                marmot_app::ProductUnit::Attempt,
                            );
                            let read = self
                                .deliver_stored_for_subscription(
                                    &request_id,
                                    account_id_hex.as_deref(),
                                    group_id_hex.as_deref(),
                                    &mut delivered,
                                    writer,
                                )
                                .await?;
                            if let Some(observation) = observation {
                                observation.finish(if read { "success" } else { "failure" });
                            }
                            continue;
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

    /// Delivers what every account the subscription covers stored after its mark. Returns
    /// whether storage could be read; when it could not, `resync_required` was sent.
    async fn deliver_stored_for_subscription<W>(
        &self,
        request_id: &Option<String>,
        account_filter: Option<&str>,
        group_filter: Option<&str>,
        delivered: &mut DeliveredInboundCursor,
        writer: &mut W,
    ) -> Result<bool, ConnectorError>
    where
        W: AsyncWrite + Unpin,
    {
        let accounts = match account_filter {
            Some(account_id_hex) => self
                .local_account_for_account_id(account_id_hex)
                .map(|account| vec![account]),
            None => self.account_home.accounts().map_err(ConnectorError::from),
        };
        let accounts = match accounts {
            Ok(accounts) => accounts,
            Err(err) => {
                self.signal_stored_inbound_unread(
                    request_id,
                    account_filter,
                    group_filter,
                    &err,
                    writer,
                )
                .await?;
                return Ok(false);
            }
        };
        let mut read = true;
        for account in accounts {
            read &= self
                .deliver_stored_inbound(
                    request_id,
                    &account.label,
                    &account.account_id_hex,
                    group_filter,
                    delivered,
                    writer,
                )
                .await?;
        }
        Ok(read)
    }

    /// Delivers what an account stored after this scope's durable mark and this subscription has
    /// not sent yet, page by page in storage order, moving the mark past each page (mdk#3551).
    /// The first subscriber of a scope starts at the newest stored row, so history is never
    /// replayed as new messages. A storage failure leaves the mark where it was, so the rows are
    /// read again on the next notice or subscription, and sends `resync_required`. Returns
    /// whether storage could be read; only a failed write to the client is an error.
    async fn deliver_stored_inbound<W>(
        &self,
        request_id: &Option<String>,
        account_label: &str,
        account_id_hex: &str,
        group_filter: Option<&str>,
        delivered: &mut DeliveredInboundCursor,
        writer: &mut W,
    ) -> Result<bool, ConnectorError>
    where
        W: AsyncWrite + Unpin,
    {
        let read = 'read: {
            let mut mark = match self.inbound_marks.get(account_label, group_filter) {
                Ok(Some(mark)) => mark,
                // The first subscriber of the scope: everything stored so far is history.
                Ok(None) => {
                    break 'read self.start_at_newest(account_label, account_id_hex, group_filter);
                }
                // The marks were lost: restart the scope at the newest row and send
                // `resync_required`, so the client re-pages the timeline once.
                Err(err) => {
                    break 'read self
                        .start_at_newest(account_label, account_id_hex, group_filter)
                        .and(Err(err));
                }
            };
            loop {
                let mut page =
                    match self.stored_page(account_label, account_id_hex, group_filter, mark) {
                        Ok(page) => page,
                        Err(err) => break 'read Err(err),
                    };
                loop {
                    match page.next_event(self, delivered) {
                        Ok(Some(event)) => {
                            let envelope = AgentControlEnvelope::new(request_id.clone(), event);
                            write_control_frame(writer, &envelope).await?;
                        }
                        Ok(None) => break,
                        Err(err) => break 'read Err(err),
                    }
                }
                mark = page.through;
                if let Err(err) = self
                    .inbound_marks
                    .advance(account_label, group_filter, mark)
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
                if !page.more {
                    break 'read Ok(());
                }
            }
        };
        match read {
            Ok(()) => Ok(true),
            Err(err) => {
                self.signal_stored_inbound_unread(
                    request_id,
                    Some(account_id_hex),
                    group_filter,
                    &err,
                    writer,
                )
                .await?;
                Ok(false)
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

    /// Sets the scope's mark to the newest row the account stored in it.
    fn start_at_newest(
        &self,
        account_label: &str,
        account_id_hex: &str,
        group_filter: Option<&str>,
    ) -> Result<(), ConnectorError> {
        let mut after = 0;
        loop {
            let page = self.stored_page(account_label, account_id_hex, group_filter, after)?;
            after = page.through;
            if !page.more {
                return self
                    .inbound_marks
                    .advance(account_label, group_filter, after);
            }
        }
    }

    /// One page of what an account stored in the scope after `after`, in storage order.
    pub(crate) fn stored_page(
        &self,
        account_label: &str,
        account_id_hex: &str,
        group_filter: Option<&str>,
        after: i64,
    ) -> Result<StoredPage, ConnectorError> {
        let query = AppMessageQuery {
            group_id_hex: group_filter.map(str::to_owned),
            kinds: None,
            limit: Some(DELIVERED_INBOUND_CURSOR_CAPACITY),
        };
        let rows = self
            .runtime
            .messages_after_insert_order(account_label, query, after)?;
        Ok(StoredPage {
            account_label: account_label.to_owned(),
            account_id_hex: account_id_hex.to_owned(),
            group_filter: group_filter.map(str::to_owned),
            through: rows.last().map_or(after, |row| row.insert_order),
            more: rows.len() >= DELIVERED_INBOUND_CURSOR_CAPACITY,
            rows: rows.into_iter(),
        })
    }
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

/// A page of stored rows, still unprojected. Each row is read again and projected only when the
/// caller is ready to write it: a slow reader can hold an earlier frame while a later row is
/// deleted, expires or is pruned, and the copy read with the page must not go out then (a
/// deleted message yields nothing; its deletion is a row of its own).
pub(crate) struct StoredPage {
    account_label: String,
    account_id_hex: String,
    group_filter: Option<String>,
    rows: std::vec::IntoIter<AppMessageRecord>,
    /// The position of the last row read, where the next page starts.
    through: i64,
    /// Whether the page was full, so more rows may follow it.
    more: bool,
}

impl StoredPage {
    /// Project the next row this subscription should receive, recording it in `delivered`, or
    /// `None` once every row is done.
    pub(crate) fn next_event(
        &mut self,
        connector: &AgentConnector,
        delivered: &mut DeliveredInboundCursor,
    ) -> Result<Option<AgentControlEvent>, ConnectorError> {
        for record in self.rows.by_ref() {
            let replay_id = record.message_id_hex.clone();
            if delivered.contains(&replay_id) {
                continue;
            }
            // The row as storage shows it now, with the visibility and expiry rules of the
            // page read.
            let query = AppMessageQuery {
                group_id_hex: Some(record.group_id_hex.clone()),
                kinds: Some(vec![record.kind]),
                limit: Some(1),
            };
            let Some(record) = connector
                .runtime
                .messages_after_insert_order(
                    &self.account_label,
                    query,
                    record.insert_order.saturating_sub(1),
                )?
                .into_iter()
                .find(|current| current.message_id_hex == replay_id)
            else {
                continue;
            };
            let Some(event) = inbound_message_event_from_record_with_runtime(
                &connector.runtime,
                &self.account_label,
                &self.account_id_hex,
                record,
                Some(&self.account_id_hex),
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
