//! QUIC text-stream preview session lifecycle and the idle-session sweeper.

use std::time::Instant;

use agent_control::AgentControlResponse;
use agent_stream_compose::{StreamComposeCommand, StreamComposeReport, run_stream_compose_session};
use cgka_traits::{GroupId, MessageId};
use marmot_app::AgentTextStreamFinishRequest;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, oneshot};
use transport_quic_broker::OpenBrokerTextPublisher;

use crate::error::ConnectorError;
use crate::quic::{
    broker_trust_for_addr, first_quic_candidate, parse_quic_candidate, resolve_quic_candidate_addr,
};
use crate::stream_session::ActiveStreamSession;
use crate::validation::{normalize_hex, transcript_hash_from_hex, unix_now_seconds};
use crate::{
    AgentConnector, STREAM_COMPOSE_CHANNEL_DEPTH, STREAM_COMPOSE_CHUNK_BYTES,
    STREAM_SESSION_IDLE_TIMEOUT, STREAM_SESSION_SWEEP_INTERVAL,
};

impl AgentConnector {
    pub(crate) async fn stream_begin_response(
        &self,
        account_id_hex: &str,
        group_id_hex: &str,
        stream_id_hex: Option<String>,
        quic_candidates: Vec<String>,
    ) -> Result<AgentControlResponse, ConnectorError> {
        let account = self.local_account_for_account_id(account_id_hex)?;
        let group_id_hex = normalize_hex(group_id_hex)?;
        let group_id = GroupId::new(hex::decode(&group_id_hex)?);
        let stream_id = stream_id_hex
            .map(|stream_id_hex| -> Result<Vec<u8>, ConnectorError> {
                Ok(hex::decode(normalize_hex(&stream_id_hex)?)?)
            })
            .transpose()?
            .unwrap_or_else(transport_quic_stream::random_stream_id);
        let stream_id_hex = hex::encode(&stream_id);
        let candidate = first_quic_candidate(&quic_candidates)?;
        let parsed_candidate = parse_quic_candidate(&candidate)?;
        let broker_addr = resolve_quic_candidate_addr(&parsed_candidate).await?;
        let trust = broker_trust_for_addr(broker_addr);
        let (_payload, summary) = self
            .runtime
            .start_agent_text_stream(
                &account.label,
                &group_id,
                &stream_id,
                unix_now_seconds(),
                quic_candidates.clone(),
            )
            .await?;
        let start_message_id_hex =
            summary.message_ids.first().cloned().ok_or_else(|| {
                ConnectorError::Stream("stream start returned no message id".into())
            })?;
        let crypto = self
            .runtime
            .agent_text_stream_crypto_for_start_event(
                Some(&account.label),
                Some(&group_id_hex),
                Some(&stream_id_hex),
                &start_message_id_hex,
            )
            .await?;

        let policy_max_plaintext_frame_len = crypto.policy_max_plaintext_frame_len;

        let (tx, rx) = mpsc::channel(STREAM_COMPOSE_CHANNEL_DEPTH);
        // Dedicated cancel signal: a separate, bounded channel that cannot be
        // starved behind queued append/status/progress commands, so an explicit
        // cancel always reaches the session and a live `Abort` is emitted.
        let (cancel_tx, cancel_rx) = mpsc::channel(1);
        let report = StreamComposeReport {
            account: Some(account.account_id_hex.clone()),
            group_id: group_id_hex.clone(),
            stream_id: stream_id_hex.clone(),
            start_message_id: start_message_id_hex.clone(),
            candidate: candidate.clone(),
            status: "streaming".to_owned(),
            text: String::new(),
            transcript_hash: None,
            chunk_count: 0,
            error: None,
        };
        let handle = tokio::spawn(run_stream_compose_session(
            OpenBrokerTextPublisher {
                broker_addr,
                server_name: parsed_candidate.server_name,
                trust,
                stream_id: stream_id.clone(),
                start_event_id: MessageId::new(hex::decode(&start_message_id_hex)?),
                crypto: Some(crypto.crypto),
                max_plaintext_frame_len: policy_max_plaintext_frame_len,
            },
            STREAM_COMPOSE_CHUNK_BYTES,
            rx,
            cancel_rx,
            report,
        ));
        self.streams.insert(
            stream_id_hex.clone(),
            ActiveStreamSession {
                account_label: account.label,
                group_id,
                stream_id,
                start_message_id_hex: start_message_id_hex.clone(),
                tx,
                cancel_tx,
                abort: handle.abort_handle(),
                last_activity: Instant::now(),
            },
        );
        Ok(AgentControlResponse::StreamBegun {
            stream_id_hex,
            start_message_id_hex,
            quic_candidates,
            policy_max_plaintext_frame_len,
        })
    }

    pub(crate) async fn stream_append_response(
        &self,
        stream_id_hex: &str,
        append_text: String,
    ) -> Result<AgentControlResponse, ConnectorError> {
        let session = self.streams.get(stream_id_hex)?;
        let (respond, response) = oneshot::channel();
        session
            .tx
            .send(StreamComposeCommand::Append {
                text: append_text,
                respond,
            })
            .await
            .map_err(|_| ConnectorError::Stream("stream compose session is closed".into()))?;
        response
            .await
            .map_err(|err| ConnectorError::Stream(err.to_string()))?
            .map_err(ConnectorError::Stream)?;
        Ok(AgentControlResponse::Ack)
    }

    pub(crate) async fn stream_status_response(
        &self,
        stream_id_hex: &str,
        status: String,
    ) -> Result<AgentControlResponse, ConnectorError> {
        let session = self.streams.get(stream_id_hex)?;
        let (respond, response) = oneshot::channel();
        session
            .tx
            .send(StreamComposeCommand::Status { status, respond })
            .await
            .map_err(|_| ConnectorError::Stream("stream compose session is closed".into()))?;
        response
            .await
            .map_err(|err| ConnectorError::Stream(err.to_string()))?
            .map_err(ConnectorError::Stream)?;
        Ok(AgentControlResponse::Ack)
    }

    pub(crate) async fn stream_progress_response(
        &self,
        stream_id_hex: &str,
        text: String,
    ) -> Result<AgentControlResponse, ConnectorError> {
        let session = self.streams.get(stream_id_hex)?;
        let (respond, response) = oneshot::channel();
        session
            .tx
            .send(StreamComposeCommand::Progress { text, respond })
            .await
            .map_err(|_| ConnectorError::Stream("stream compose session is closed".into()))?;
        response
            .await
            .map_err(|err| ConnectorError::Stream(err.to_string()))?
            .map_err(ConnectorError::Stream)?;
        Ok(AgentControlResponse::Ack)
    }

    pub(crate) async fn stream_finalize_response(
        &self,
        stream_id_hex: &str,
        final_text: String,
        transcript_hash_hex: &str,
        chunk_count: u64,
    ) -> Result<AgentControlResponse, ConnectorError> {
        let stream_id_hex = normalize_hex(stream_id_hex)?;
        let session = self.streams.remove(&stream_id_hex)?;
        let (respond, response) = oneshot::channel();
        if session
            .tx
            .send(StreamComposeCommand::Finish { respond })
            .await
            .is_err()
        {
            session.abort.abort();
            return Err(ConnectorError::Stream(
                "stream compose session is closed".into(),
            ));
        }
        let report = response
            .await
            .map_err(|err| ConnectorError::Stream(err.to_string()))?
            .map_err(ConnectorError::Stream)?;
        if report.text != final_text {
            return Err(ConnectorError::Stream(
                "stream final text does not match appended transcript".into(),
            ));
        }
        let transcript_hash = transcript_hash_from_hex(transcript_hash_hex)?;
        let expected_transcript_hash_hex = hex::encode(transcript_hash);
        let actual_transcript_hash_hex = report
            .transcript_hash
            .as_deref()
            .map(normalize_hex)
            .transpose()?;
        if actual_transcript_hash_hex.as_deref() != Some(expected_transcript_hash_hex.as_str()) {
            return Err(ConnectorError::Stream(
                "stream final transcript hash does not match appended transcript".into(),
            ));
        }
        if report.chunk_count != chunk_count {
            return Err(ConnectorError::Stream(
                "stream final chunk count does not match appended transcript".into(),
            ));
        }
        let (_payload, summary) = self
            .runtime
            .finish_agent_text_stream(
                &session.account_label,
                &session.group_id,
                AgentTextStreamFinishRequest {
                    stream_id: session.stream_id,
                    start_event_id: session.start_message_id_hex,
                    final_text_or_reference: final_text,
                    transcript_hash,
                    chunk_count,
                    finished_at: unix_now_seconds(),
                },
            )
            .await?;
        Ok(AgentControlResponse::StreamFinalized {
            stream_id_hex,
            message_ids_hex: summary.message_ids,
        })
    }

    pub(crate) fn stream_cancel_response(
        &self,
        stream_id_hex: &str,
    ) -> Result<AgentControlResponse, ConnectorError> {
        let session = self.streams.remove(stream_id_hex)?;
        // Send a graceful cancel over the dedicated cancel signal and let the
        // compose session drain it: the session emits a live `Abort` record (so
        // online subscribers observe the cancellation) and shuts itself down.
        // The cancel signal is its own bounded channel that cannot be starved by
        // queued append/status/progress commands, so it always lands. Do NOT
        // abort the task on a full *cancel* queue — a `Full` cancel channel means
        // a cancel is already pending, so the session will still publish its
        // Abort. Only fall back to a forced abort if the dedicated cancel channel
        // itself is gone (session not running), the only case where the session
        // can no longer publish an Abort.
        match session.cancel_tx.try_send(()) {
            Ok(()) | Err(TrySendError::Full(())) => {}
            Err(TrySendError::Closed(())) => session.abort.abort(),
        }
        Ok(AgentControlResponse::Ack)
    }

    pub(crate) fn spawn_stream_session_sweeper(&self) {
        let streams = self.streams.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(STREAM_SESSION_SWEEP_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                let swept = streams.sweep_idle(STREAM_SESSION_IDLE_TIMEOUT);
                if swept > 0 {
                    tracing::warn!(
                        target: "agent_connector",
                        method = "spawn_stream_session_sweeper",
                        swept,
                        "aborted idle stream compose sessions"
                    );
                }
            }
        });
    }
}
