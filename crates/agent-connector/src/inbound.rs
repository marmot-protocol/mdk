//! Inbound subscription drain loop. Messages and group-state changes reach a subscriber only from
//! storage, read from the subscription's position in insert order; live notices, catch-up passes
//! and broadcast lag only wake that read (mdk#3551).

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

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
    control_event_from_runtime_event, inbound_message_event_from_record_with_runtime,
    resync_required_event,
};
use crate::inbound_marks::InboundMark;
use crate::reconcile_telemetry::ReconcileTelemetry;
use crate::validation::agent_control_request_type;

/// Rows read per page, and so the most a subscription is sent again after it closes partway
/// through a page: the scope's mark is saved after each page. Well inside the 2,048 recent
/// message ids the plugin clients deduplicate against.
pub(crate) const INBOUND_PAGE_ROWS: usize = 256;

/// One subscription's read of storage: when it began, how many rows it reads per page, and how
/// far it has read in each account.
pub(crate) struct StoredRead {
    subscribed_at: u64,
    page_rows: usize,
    positions: HashMap<String, i64>,
}

impl StoredRead {
    pub(crate) fn new(page_rows: usize) -> Self {
        Self {
            subscribed_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |since| since.as_secs()),
            page_rows,
            positions: HashMap::new(),
        }
    }
}

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
        let mut read = StoredRead::new(INBOUND_PAGE_ROWS);
        let mut runtime_events = self.runtime.subscribe();
        let mut debug_events = self.debug_events.subscribe();
        let (mut catch_up_events, _catch_up_subscription) = self.inbound_catch_up.subscribe();

        let response = AgentControlEnvelope::new(request_id.clone(), AgentControlResponse::Ack);
        write_control_frame(writer, &response).await?;

        // mdk#3551: hand over what was stored after this scope's mark while no subscriber was
        // attached, such as a message that arrived during a gateway restart. The runtime
        // receiver above was subscribed first, so every row stored later wakes another read.
        self.deliver_stored_for_subscription(
            &request_id,
            account_id_hex.as_deref(),
            group_id_hex.as_deref(),
            &mut read,
            writer,
        )
        .await?;

        // Request the initial catch-up without blocking this drain loop. catch_up_accounts() can
        // block for as long as an account's startup keeps progressing, up to
        // APP_RUNTIME_ACCOUNT_READY_WAIT after it stalls, and can itself emit many runtime
        // events; keeping this loop live keeps the bounded broadcast channel from lagging while
        // catch-up is in flight.
        let catch_up_driver = self.inbound_catch_up.clone();
        let mut initial_catch_up = Box::pin(async move {
            catch_up_driver
                .request()
                .await
                .map_err(ConnectorError::from)
        });
        let mut initial_catch_up_pending = true;

        // Debug-injected inbound messages have no stored row; a re-injected one is skipped.
        let mut debug_delivered = DeliveredInboundCursor::new(DELIVERED_INBOUND_CURSOR_CAPACITY);

        loop {
            // What to read from storage after this turn: the account of a live notice, or every
            // covered account after a catch-up pass or broadcast lag.
            let mut wake_account = None;
            let mut wake_all = false;
            let mut lagged = false;
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
                    None
                }
                // SubscribeInbound is read-only after the initial request: clients are only
                // expected to close the stream. read_envelope() uses read_until(), which is
                // not cancellation-safe for partial frames inside select!; switch this to a
                // cancellation-safe framed read before adding subscriber-side messages here.
                request = read_envelope(reader) => {
                    let request: Result<Option<AgentControlEnvelope<AgentControlRequest>>, AgentControlError> = request;
                    match request {
                        Ok(None) => return Ok(()),
                        Ok(Some(envelope)) => {
                            let request_type = agent_control_request_type(&envelope.payload);
                            tracing::warn!(
                                target: "agent_connector",
                                method = "stream_inbound_events",
                                request_type,
                                "additional request received after SubscribeInbound"
                            );
                            None
                        }
                        Err(err) => return Err(err.into()),
                    }
                }
                // A catch-up pass can store rows that no notice announces, such as a group
                // system row whose projection was retried.
                catch_up = catch_up_events.recv() => {
                    match catch_up {
                        Ok(InboundCatchUpEvent::Completed)
                        | Err(broadcast::error::RecvError::Lagged(_)) => wake_all = true,
                        Err(broadcast::error::RecvError::Closed) => return Ok(()),
                    }
                    None
                }
                event = runtime_events.recv() => {
                    match event {
                        Ok(event) => {
                            wake_account = runtime_event_account(&event, account_id_hex.as_deref());
                            control_event_from_runtime_event(
                                event,
                                account_id_hex.as_deref(),
                                group_id_hex.as_deref(),
                            )
                        }
                        Err(broadcast::error::RecvError::Lagged(dropped)) => {
                            // Dropped notices only woke reads; storage still holds their rows.
                            tracing::warn!(
                                target: "agent_connector",
                                method = "stream_inbound_events",
                                dropped_events = dropped,
                                "inbound broadcast lagged; delivering missed events from storage"
                            );
                            lagged = true;
                            None
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
                        ),
                        Err(broadcast::error::RecvError::Lagged(_))
                        | Err(broadcast::error::RecvError::Closed) => None,
                    }
                }
            };
            if let Some(event) = event {
                let repeated = match &event {
                    AgentControlEvent::InboundMessage { message, .. } => {
                        let repeated = debug_delivered.contains(&message.message_id_hex);
                        debug_delivered.record(message.message_id_hex.clone());
                        repeated
                    }
                    _ => false,
                };
                if !repeated {
                    let envelope = AgentControlEnvelope::new(request_id.clone(), event);
                    write_control_frame(writer, &envelope).await?;
                }
            }
            if lagged {
                let observation = self.runtime.begin_product_operation(
                    marmot_app::ProductFamily::Agent,
                    "replay",
                    marmot_app::ProductUnit::Attempt,
                );
                let read_ok = self
                    .deliver_stored_for_subscription(
                        &request_id,
                        account_id_hex.as_deref(),
                        group_id_hex.as_deref(),
                        &mut read,
                        writer,
                    )
                    .await?;
                if let Some(observation) = observation {
                    observation.finish(if read_ok { "success" } else { "failure" });
                }
            } else if wake_all {
                self.deliver_stored_for_subscription(
                    &request_id,
                    account_id_hex.as_deref(),
                    group_id_hex.as_deref(),
                    &mut read,
                    writer,
                )
                .await?;
            } else if let Some((account_label, account_id_hex)) = wake_account {
                self.deliver_stored_inbound(
                    &request_id,
                    &account_label,
                    &account_id_hex,
                    group_id_hex.as_deref(),
                    &mut read,
                    writer,
                )
                .await?;
            }
        }
    }

    /// Delivers what every account the subscription covers stored after its position. Returns
    /// whether storage could be read; when it could not, `resync_required` was sent.
    async fn deliver_stored_for_subscription<W>(
        &self,
        request_id: &Option<String>,
        account_filter: Option<&str>,
        group_filter: Option<&str>,
        read: &mut StoredRead,
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
        let mut read_ok = true;
        for account in accounts {
            read_ok &= self
                .deliver_stored_inbound(
                    request_id,
                    &account.label,
                    &account.account_id_hex,
                    group_filter,
                    read,
                    writer,
                )
                .await?;
        }
        Ok(read_ok)
    }

    /// Delivers what an account stored after this subscription's position, page by page in
    /// storage order, saving the scope's mark after each page (mdk#3551). The first read of an
    /// account starts at the scope's saved mark, or, without one, just before the first row
    /// received since the subscription began (or since an unreadable mark record was written),
    /// so history is not replayed and nothing that arrived meanwhile is skipped. A storage
    /// failure leaves the position where it was, so the rows are read again on the next wake,
    /// and sends `resync_required`. Returns whether storage could be read; only a failed write to
    /// the client is an error.
    pub(crate) async fn deliver_stored_inbound<W>(
        &self,
        request_id: &Option<String>,
        account_label: &str,
        account_id_hex: &str,
        group_filter: Option<&str>,
        read: &mut StoredRead,
        writer: &mut W,
    ) -> Result<bool, ConnectorError>
    where
        W: AsyncWrite + Unpin,
    {
        let outcome = 'read: {
            let mut position = match read.positions.get(account_label) {
                Some(&position) => position,
                None => {
                    let start = match self.inbound_marks.get(account_label, group_filter) {
                        Ok(InboundMark::After(mark)) => Ok(mark),
                        Ok(InboundMark::ReceivedSince(since)) => self.position_received_since(
                            account_label,
                            group_filter,
                            since.unwrap_or(read.subscribed_at),
                            read.page_rows,
                        ),
                        Err(err) => Err(err),
                    };
                    match start {
                        Ok(start) => start,
                        Err(err) => break 'read Err(err),
                    }
                }
            };
            loop {
                let rows =
                    match self.stored_rows(account_label, group_filter, position, read.page_rows) {
                        Ok(rows) => rows,
                        Err(err) => break 'read Err(err),
                    };
                let more = rows.len() >= read.page_rows;
                let through = rows.last().map_or(position, |row| row.insert_order);
                let mut page = StoredPage::new(account_label, account_id_hex, group_filter, rows);
                loop {
                    match page.next_event(self) {
                        Ok(Some(event)) => {
                            let envelope = AgentControlEnvelope::new(request_id.clone(), event);
                            write_control_frame(writer, &envelope).await?;
                        }
                        Ok(None) => break,
                        Err(err) => break 'read Err(err),
                    }
                }
                position = through;
                read.positions.insert(account_label.to_owned(), position);
                if let Err(err) = self
                    .inbound_marks
                    .advance(account_label, group_filter, position)
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
                if !more {
                    break 'read Ok(());
                }
            }
        };
        match outcome {
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

    /// The position just before the first row in the scope the account received at or after
    /// `since` (unix seconds), or after its last row when none was. A row received in the same
    /// second as `since` counts as new: delivering it again is safer than skipping it.
    pub(crate) fn position_received_since(
        &self,
        account_label: &str,
        group_filter: Option<&str>,
        since: u64,
        page_rows: usize,
    ) -> Result<i64, ConnectorError> {
        let mut after = 0;
        loop {
            let rows = self.stored_rows(account_label, group_filter, after, page_rows)?;
            let more = rows.len() >= page_rows;
            for row in rows {
                if row.received_at >= since {
                    return Ok(after);
                }
                after = row.insert_order;
            }
            if !more {
                return Ok(after);
            }
        }
    }

    /// A page of at most `page_rows` rows an account stored in the scope after `after`, in
    /// storage order.
    pub(crate) fn stored_rows(
        &self,
        account_label: &str,
        group_filter: Option<&str>,
        after: i64,
        page_rows: usize,
    ) -> Result<Vec<AppMessageRecord>, ConnectorError> {
        let query = AppMessageQuery {
            group_id_hex: group_filter.map(str::to_owned),
            kinds: None,
            limit: Some(page_rows),
        };
        Ok(self
            .runtime
            .messages_after_insert_order(account_label, query, after)?)
    }
}

/// The account of a runtime event that `account_filter` covers: a message or group notice wakes a
/// read of what that account stored.
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
}

impl StoredPage {
    pub(crate) fn new(
        account_label: &str,
        account_id_hex: &str,
        group_filter: Option<&str>,
        rows: Vec<AppMessageRecord>,
    ) -> Self {
        Self {
            account_label: account_label.to_owned(),
            account_id_hex: account_id_hex.to_owned(),
            group_filter: group_filter.map(str::to_owned),
            rows: rows.into_iter(),
        }
    }

    /// Project the next row of the page the subscription should receive, or `None` once every
    /// row is done.
    pub(crate) fn next_event(
        &mut self,
        connector: &AgentConnector,
    ) -> Result<Option<AgentControlEvent>, ConnectorError> {
        for record in self.rows.by_ref() {
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
                .find(|current| current.message_id_hex == record.message_id_hex)
            else {
                continue;
            };
            if let Some(event) = inbound_message_event_from_record_with_runtime(
                &connector.runtime,
                &self.account_label,
                &self.account_id_hex,
                record,
                Some(&self.account_id_hex),
                self.group_filter.as_deref(),
            )? {
                return Ok(Some(event));
            }
        }
        Ok(None)
    }
}
