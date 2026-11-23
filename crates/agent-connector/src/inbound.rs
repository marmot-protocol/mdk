//! Inbound subscription drain loop. Messages and group-state changes reach a subscriber only from
//! storage, read from the subscription's position in insert order; live notices, catch-up passes
//! and broadcast lag only wake that read (mdk#3551).

use std::collections::HashMap;

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

/// One subscription's read of storage: where each account it covered when it began stood, how
/// many rows it reads per page, and how far it has read in each account.
pub(crate) struct StoredRead {
    /// The newest stored position of each account the subscription covered when it began, read
    /// before it subscribed to runtime events; `None` when that read failed.
    starts: HashMap<String, Option<i64>>,
    /// Whether the accounts could be listed then, so an account missing from `starts` was
    /// created later.
    listed: bool,
    page_rows: usize,
    positions: HashMap<String, i64>,
}

/// Where a scope's first read starts when it has no usable mark.
enum Start {
    /// This position: everything at or before it is history.
    At(i64),
    /// Unknown: the newest position now, and the client is told it may have missed rows.
    Unknown,
}

impl StoredRead {
    fn start(&self, account_label: &str) -> Start {
        match self.starts.get(account_label) {
            Some(Some(start)) => Start::At(*start),
            Some(None) => Start::Unknown,
            // An account created after the subscription began has no history.
            None if self.listed => Start::At(0),
            None => Start::Unknown,
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
        // Read where each account stands before subscribing to its events: a row stored after
        // this read, even one received earlier and committed later, sorts after it and its
        // notice wakes a read.
        let mut read = self.stored_read(
            account_id_hex.as_deref(),
            group_id_hex.as_deref(),
            INBOUND_PAGE_ROWS,
        );
        let mut runtime_events = self.runtime.subscribe();
        let mut debug_events = self.debug_events.subscribe();
        let (mut catch_up_events, _catch_up_subscription) = self.inbound_catch_up.subscribe();

        let response = AgentControlEnvelope::new(request_id.clone(), AgentControlResponse::Ack);
        write_control_frame(writer, &response).await?;

        // mdk#3551: hand over what was stored after this scope's mark while no subscriber was
        // attached, such as a message that arrived during a gateway restart.
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

    /// The accounts a subscription covers: the one it names, or every local account.
    fn inbound_accounts(
        &self,
        account_filter: Option<&str>,
    ) -> Result<Vec<marmot_account::AccountSummary>, ConnectorError> {
        Ok(match account_filter {
            Some(account_id_hex) => vec![self.local_account_for_account_id(account_id_hex)?],
            None => self.account_home.accounts()?,
        })
    }

    /// A subscription's read of storage, starting where each covered account stands now.
    pub(crate) fn stored_read(
        &self,
        account_filter: Option<&str>,
        group_filter: Option<&str>,
        page_rows: usize,
    ) -> StoredRead {
        let accounts = self.inbound_accounts(account_filter);
        let listed = accounts.is_ok();
        let starts = accounts
            .unwrap_or_default()
            .into_iter()
            .map(|account| {
                let start = self
                    .runtime
                    .latest_message_insert_order(&account.label, group_filter)
                    .ok();
                (account.label, start)
            })
            .collect();
        StoredRead {
            starts,
            listed,
            page_rows,
            positions: HashMap::new(),
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
        let accounts = match self.inbound_accounts(account_filter) {
            Ok(accounts) => accounts,
            Err(err) => {
                tracing::warn!(
                    target: "agent_connector",
                    method = "deliver_stored_for_subscription",
                    error_code = err.privacy_safe_code(),
                    "inbound accounts could not be listed"
                );
                self.signal_stored_inbound_gap(
                    request_id,
                    account_filter,
                    group_filter,
                    "stored_read_failed",
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
    /// account starts at the scope's saved mark, or, without one, at the newest row stored when
    /// the subscription began, so history is not replayed and nothing stored since is skipped.
    /// When the mark was lost, or that position is unknown, it starts at the newest row and sends
    /// `resync_required`. A storage failure, or a mark that cannot be saved, stops the read at
    /// the last saved position, so the rows are read again on the next wake, and sends
    /// `resync_required`. Returns whether the read completed; only a failed write to the client
    /// is an error.
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
                        Ok(InboundMark::After(mark)) => Ok((mark, false)),
                        Ok(mark) => match read.start(account_label) {
                            Start::At(start) => Ok((start, mark == InboundMark::Lost)),
                            Start::Unknown => self
                                .runtime
                                .latest_message_insert_order(account_label, group_filter)
                                .map(|newest| (newest, true))
                                .map_err(ConnectorError::from),
                        },
                        Err(err) => Err(err),
                    };
                    let (start, gap) = match start {
                        Ok(start) => start,
                        Err(err) => break 'read Err(("stored_read_failed", err)),
                    };
                    if let Err(err) = self
                        .inbound_marks
                        .advance(account_label, group_filter, start)
                    {
                        break 'read Err(("mark_save_failed", err));
                    }
                    read.positions.insert(account_label.to_owned(), start);
                    if gap {
                        self.signal_stored_inbound_gap(
                            request_id,
                            Some(account_id_hex),
                            group_filter,
                            "inbound_mark_unknown",
                            writer,
                        )
                        .await?;
                    }
                    start
                }
            };
            loop {
                let rows =
                    match self.stored_rows(account_label, group_filter, position, read.page_rows) {
                        Ok(rows) => rows,
                        Err(err) => break 'read Err(("stored_read_failed", err)),
                    };
                let more = rows.len() >= read.page_rows;
                let through = rows.last().map_or(position, |row| row.insert_order);
                let mut page = StoredPage::new(account_label, account_id_hex, rows);
                loop {
                    match page.next_event(self) {
                        Ok(Some(event)) => {
                            let envelope = AgentControlEnvelope::new(request_id.clone(), event);
                            write_control_frame(writer, &envelope).await?;
                        }
                        Ok(None) => break,
                        Err(err) => break 'read Err(("stored_read_failed", err)),
                    }
                }
                // Move on only past a saved page, so a later page never saves a mark beyond
                // rows the client may not have.
                if let Err(err) = self
                    .inbound_marks
                    .advance(account_label, group_filter, through)
                {
                    break 'read Err(("mark_save_failed", err));
                }
                position = through;
                read.positions.insert(account_label.to_owned(), position);
                if !more {
                    break 'read Ok(());
                }
            }
        };
        match outcome {
            Ok(()) => Ok(true),
            Err((reason, err)) => {
                tracing::warn!(
                    target: "agent_connector",
                    method = "deliver_stored_inbound",
                    reason,
                    error_code = err.privacy_safe_code(),
                    "stored inbound read stopped"
                );
                self.signal_stored_inbound_gap(
                    request_id,
                    Some(account_id_hex),
                    group_filter,
                    reason,
                    writer,
                )
                .await?;
                Ok(false)
            }
        }
    }

    /// Tells the client it may have missed stored rows, so it re-pages the timeline.
    async fn signal_stored_inbound_gap<W>(
        &self,
        request_id: &Option<String>,
        account_filter: Option<&str>,
        group_filter: Option<&str>,
        reason: &'static str,
        writer: &mut W,
    ) -> Result<(), ConnectorError>
    where
        W: AsyncWrite + Unpin,
    {
        tracing::warn!(
            target: "agent_connector",
            method = "deliver_stored_inbound",
            reason,
            "emitting resync_required"
        );
        ReconcileTelemetry::bump(&self.reconcile_telemetry.resync_required);
        let event = resync_required_event(account_filter, group_filter, 1);
        write_control_frame(
            writer,
            &AgentControlEnvelope::new(request_id.clone(), event),
        )
        .await
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
    rows: std::vec::IntoIter<AppMessageRecord>,
}

impl StoredPage {
    pub(crate) fn new(
        account_label: &str,
        account_id_hex: &str,
        rows: Vec<AppMessageRecord>,
    ) -> Self {
        Self {
            account_label: account_label.to_owned(),
            account_id_hex: account_id_hex.to_owned(),
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
            )? {
                return Ok(Some(event));
            }
        }
        Ok(None)
    }
}
