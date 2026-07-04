//! QUIC text-stream preview session lifecycle and the idle-session sweeper.

use std::time::Instant;

use agent_control::AgentControlResponse;
use agent_stream_compose::{
    StreamComposeCommand, StreamComposeReport, StreamFinishExpectation, run_stream_compose_session,
};
use cgka_traits::{GroupId, MessageId};
use marmot_app::AgentTextStreamFinishRequest;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, oneshot};
use transport_quic_broker::OpenBrokerTextPublisher;

use crate::error::ConnectorError;
use crate::quic::{
    broker_trust_for_candidate, first_quic_candidate, parse_quic_candidate,
    resolve_quic_candidate_addr,
};
use crate::stream_session::{ActiveStreamSession, FinalizedStream};
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
        let broker_addr =
            resolve_quic_candidate_addr(&parsed_candidate, self.allow_insecure_local_broker)
                .await?;
        let trust = broker_trust_for_candidate(
            &parsed_candidate.server_name,
            self.allow_insecure_local_broker,
        );
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
                finalized: None,
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
        let transcript_hash = transcript_hash_from_hex(transcript_hash_hex)?;
        // Clone (not remove) the session: the final text/hash/chunk-count
        // expectation is validated inside the compose task, atomically with
        // its teardown. On mismatch the session stays registered and the
        // compose task keeps running, so finalize is retryable (#366).
        let session = self.streams.get(&stream_id_hex)?;

        // Retry fast-path: a prior finalize already validated the transcript and
        // the compose task exited, but the durable finish below failed. The
        // compose task is gone, so re-attempt the durable finish directly from
        // the retained transcript, rejecting a retry that disagrees with what
        // was frozen (a finalize cannot change after the transcript is sealed).
        if let Some(finalized) = &session.finalized {
            if finalized.final_text != final_text
                || finalized.transcript_hash != transcript_hash
                || finalized.chunk_count != chunk_count
            {
                return Err(ConnectorError::Stream(
                    "stream finalize does not match the already-finalized transcript".into(),
                ));
            }
            return self
                .finish_finalized_stream(
                    &stream_id_hex,
                    &session,
                    final_text,
                    transcript_hash,
                    chunk_count,
                )
                .await;
        }

        let (respond, response) = oneshot::channel();
        if session
            .tx
            .send(StreamComposeCommand::Finish {
                expected: Some(StreamFinishExpectation {
                    final_text: final_text.clone(),
                    transcript_hash_hex: hex::encode(transcript_hash),
                    chunk_count,
                }),
                respond,
            })
            .await
            .is_err()
        {
            // The compose task is gone: drop the dead registration (only if
            // it is still this session) and reclaim the task, preserving the
            // previous remove-then-abort cleanup semantics.
            let _ = self.streams.remove_if_same(&stream_id_hex, &session);
            session.abort.abort();
            return Err(ConnectorError::Stream(
                "stream compose session is closed".into(),
            ));
        }
        let report = match response.await {
            Ok(report) => report,
            Err(err) => {
                // The compose task died mid-command: same cleanup as the
                // send failure above.
                let _ = self.streams.remove_if_same(&stream_id_hex, &session);
                session.abort.abort();
                return Err(ConnectorError::Stream(err.to_string()));
            }
        };
        // An `Err` report is a validation mismatch: the compose task is still
        // running and the session stays registered, so do nothing else here
        // and the agent can append again and/or retry the finalize.
        report.map_err(ConnectorError::Stream)?;
        // Validation passed and the compose task has now exited. Freeze the
        // transcript on the still-registered session so a durable-finish
        // failure below leaves a retryable finalize (the compose task can no
        // longer be consulted).
        self.streams.mark_finalized(
            &stream_id_hex,
            &session,
            FinalizedStream {
                final_text: final_text.clone(),
                transcript_hash,
                chunk_count,
            },
        );
        self.finish_finalized_stream(
            &stream_id_hex,
            &session,
            final_text,
            transcript_hash,
            chunk_count,
        )
        .await
    }

    /// Publish the durable stream final for an already-validated finalize, and
    /// remove the session only once that publish succeeds. On failure the
    /// session stays registered with its frozen transcript so a re-issued
    /// `StreamFinalize` retries this step (#366).
    async fn finish_finalized_stream(
        &self,
        stream_id_hex: &str,
        session: &ActiveStreamSession,
        final_text: String,
        transcript_hash: [u8; 32],
        chunk_count: u64,
    ) -> Result<AgentControlResponse, ConnectorError> {
        let (_payload, summary) = self
            .runtime
            .finish_agent_text_stream(
                &session.account_label,
                &session.group_id,
                AgentTextStreamFinishRequest {
                    stream_id: session.stream_id.clone(),
                    start_event_id: session.start_message_id_hex.clone(),
                    final_text_or_reference: final_text,
                    transcript_hash,
                    chunk_count,
                    finished_at: unix_now_seconds(),
                },
            )
            .await?;
        // Durable final published: it is now safe to drop the session.
        let _ = self.streams.remove_if_same(stream_id_hex, session);
        Ok(AgentControlResponse::StreamFinalized {
            stream_id_hex: stream_id_hex.to_owned(),
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
