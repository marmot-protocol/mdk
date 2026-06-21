//! Inbound subscription drain loop and storage-backed replay after broadcast lag.

use agent_control::{
    AgentControlEnvelope, AgentControlError, AgentControlEvent, AgentControlRequest,
    AgentControlResponse, read_envelope, write_frame,
};
use marmot_app::AppMessageQuery;
use tokio::io::{AsyncBufRead, AsyncWrite};
use tokio::sync::broadcast;

use crate::AgentConnector;
use crate::DELIVERED_INBOUND_CURSOR_CAPACITY;
use crate::error::ConnectorError;
use crate::event_projection::{
    DeliveredInboundCursor, InboundCatchUpEvent, control_event_from_debug_event,
    control_event_from_runtime_event, inbound_message_event_from_record, resync_required_event,
    runtime_replay_dedup_key,
};
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
        write_frame(writer, &response).await?;

        // Request the initial catch-up without blocking this drain loop. catch_up_accounts() can
        // block for up to APP_RUNTIME_ACCOUNT_READY_WAIT per account and can itself emit many
        // runtime events; keeping this loop live prevents the bounded broadcast channel from
        // dropping inbound user messages while catch-up is in flight.
        let catch_up_driver = self.inbound_catch_up.clone();
        let mut initial_catch_up = Box::pin(async move {
            catch_up_driver
                .request()
                .await
                .map_err(ConnectorError::from)
        });
        let mut initial_catch_up_pending = true;

        // Tracks the durable storage row ids already delivered on this subscription so a
        // storage-backed replay after broadcast lag re-delivers only genuinely-missed
        // events (never re-flooding the agent with facts it already handled, and never
        // double-delivering one that raced live delivery). Bounded so a long-lived
        // subscription cannot grow this set without limit; the queue evicts the oldest ids.
        let mut delivered = DeliveredInboundCursor::new(DELIVERED_INBOUND_CURSOR_CAPACITY);

        loop {
            let event = tokio::select! {
                catch_up_result = &mut initial_catch_up, if initial_catch_up_pending => {
                    initial_catch_up_pending = false;
                    if let Err(err) = catch_up_result {
                        let response = AgentControlEnvelope::new(
                            request_id.clone(),
                            self.error_response("stream_inbound_events", &err),
                        );
                        write_frame(writer, &response).await?;
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
                            control_event_from_runtime_event(
                                event,
                                account_id_hex.as_deref(),
                                group_id_hex.as_deref(),
                            )
                            .map(|event| (event, replay_id))
                        }
                        Err(broadcast::error::RecvError::Lagged(dropped)) => {
                            // The broadcast channel overflowed: `dropped` events were evicted
                            // before we could deliver them and are gone from the channel for
                            // good (catch-up never re-emits already-broadcast messages). Recover
                            // the missed inbound messages from durable storage and re-deliver
                            // them on the existing InboundMessage path the consumer already
                            // handles, so a reconnect backlog never silently loses user
                            // messages. The delivered-id cursor guarantees we re-deliver only
                            // messages this subscription has not already emitted.
                            match self.replay_missed_inbound(
                                account_id_hex.as_deref(),
                                group_id_hex.as_deref(),
                                &mut delivered,
                            ) {
                                Ok(missed) => {
                                    tracing::warn!(
                                        target: "agent_connector",
                                        method = "stream_inbound_events",
                                        dropped_events = dropped,
                                        replayed_events = missed.len(),
                                        "inbound broadcast lagged; replayed missed events from storage"
                                    );
                                    for replayed in missed {
                                        let envelope = AgentControlEnvelope::new(
                                            request_id.clone(),
                                            replayed,
                                        );
                                        write_frame(writer, &envelope).await?;
                                    }
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
            } else if let AgentControlEvent::InboundMessage { message_id_hex, .. } = &event {
                if delivered.contains(message_id_hex) {
                    continue;
                }
                delivered.record(message_id_hex.clone());
            } else {
                debug_assert!(
                    !matches!(
                        &event,
                        AgentControlEvent::MessageDeleted { .. }
                            | AgentControlEvent::GroupStateChanged { .. }
                    ),
                    "debug-injected ambient events need a durable replay id before delivery"
                );
            }
            let envelope = AgentControlEnvelope::new(request_id.clone(), event);
            write_frame(writer, &envelope).await?;
        }
    }

    /// Recover control events that were dropped from the broadcast channel by re-reading durable
    /// per-account storage. Returns missed chat/delete/group-state events scoped to this
    /// subscription's filters, skipping any storage row id already recorded in `delivered` and
    /// recording the ones it returns. This is how a lagged subscription recovers ambient inbound
    /// facts instead of silently losing them: the connector re-queries its own state, exactly the
    /// resync the agent could not perform on its own.
    pub(crate) fn replay_missed_inbound(
        &self,
        account_filter: Option<&str>,
        group_filter: Option<&str>,
        delivered: &mut DeliveredInboundCursor,
    ) -> Result<Vec<AgentControlEvent>, ConnectorError> {
        // Replay for the filtered account, or for every local account on an unscoped
        // subscription (mirroring the live path, which emits for all local accounts).
        let accounts = match account_filter {
            Some(account_id_hex) => vec![self.local_account_for_account_id(account_id_hex)?],
            None => self.account_home.accounts()?,
        };
        let mut events = Vec::new();
        for account in accounts {
            let query = AppMessageQuery {
                group_id_hex: group_filter.map(str::to_owned),
                limit: None,
            };
            let records = self.runtime.messages_with_query(&account.label, query)?;
            for record in records {
                let replay_id = record.message_id_hex.clone();
                if delivered.contains(&replay_id) {
                    continue;
                }
                let Some(event) = inbound_message_event_from_record(
                    &account.account_id_hex,
                    record,
                    account_filter,
                    group_filter,
                ) else {
                    continue;
                };
                delivered.record(replay_id);
                events.push(event);
            }
        }
        Ok(events)
    }
}
