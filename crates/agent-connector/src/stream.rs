//! QUIC text-stream preview session lifecycle and the idle-session sweeper.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Instant;

use agent_control::AgentControlResponse;
use agent_stream_compose::{
    StreamComposeCommand, StreamComposeReport, StreamFinishExpectation,
    run_stream_compose_session_candidates, run_stream_compose_session_without_live,
};
use cgka_traits::{GroupId, MessageId};
use marmot_app::AgentTextStreamFinishRequest;
use rand::{RngCore, rngs::OsRng};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, oneshot};
use transport_quic_broker::{BrokerServerTrust, OpenBrokerTextPublisher};

use crate::error::ConnectorError;
use crate::quic::{broker_trust_for_candidate, parse_quic_candidate, resolve_quic_candidate_addr};
use crate::stream_session::{
    ActiveStreamSession, FinalizedStream, SendIdempotencyAcquisition, SendIdempotencyLeader,
    StreamBeginReceipt, StreamBeginReservation, normalize_stream_capability,
};
use crate::validation::{normalize_hex, transcript_hash_from_hex, unix_now_seconds};
use crate::{
    AgentConnector, STREAM_COMPOSE_CHANNEL_DEPTH, STREAM_COMPOSE_CHUNK_BYTES,
    STREAM_SESSION_IDLE_TIMEOUT, STREAM_SESSION_SWEEP_INTERVAL,
};

/// Current schema version for persisted `stream_finalize` request fingerprints.
pub(crate) const STREAM_FINALIZE_FINGERPRINT_VERSION: u8 = 2;
pub(crate) const STREAM_BEGIN_FINGERPRINT_VERSION: u8 = 1;

/// Server-derived fingerprint of a `stream_finalize` request. A retry can return
/// cached message ids only when the stream id and sealed transcript exactly
/// match the first successful finalize for the idempotency key.
pub(crate) fn stream_finalize_fingerprint(
    stream_id_hex: &str,
    stream_capability: &str,
    final_text: &str,
    transcript_hash: &[u8; 32],
    chunk_count: u64,
) -> String {
    use sha2::{Digest, Sha256};

    let preimage = serde_json::json!([
        STREAM_FINALIZE_FINGERPRINT_VERSION,
        stream_id_hex,
        stream_capability,
        final_text,
        hex::encode(transcript_hash),
        chunk_count,
    ]);
    let bytes =
        serde_json::to_vec(&preimage).expect("stream_finalize fingerprint preimage cannot fail");
    hex::encode(Sha256::digest(bytes))
}

fn stream_begin_fingerprint(
    account_id_hex: &str,
    group_id_hex: &str,
    requested_stream_id_hex: Option<&str>,
    parent_message_id_hex: Option<&str>,
    quic_candidates: &[String],
) -> String {
    use sha2::{Digest, Sha256};

    let preimage = serde_json::json!([
        STREAM_BEGIN_FINGERPRINT_VERSION,
        account_id_hex,
        group_id_hex,
        requested_stream_id_hex,
        parent_message_id_hex,
        quic_candidates,
    ]);
    let bytes = serde_json::to_vec(&preimage).expect("stream_begin fingerprint cannot fail");
    hex::encode(Sha256::digest(bytes))
}

fn begun_response(receipt: StreamBeginReceipt) -> AgentControlResponse {
    AgentControlResponse::StreamBegun {
        stream_id_hex: receipt.stream_id_hex,
        stream_capability: receipt.stream_capability,
        start_message_id_hex: receipt.start_message_id_hex,
        quic_candidates: receipt.quic_candidates,
        policy_max_plaintext_frame_len: receipt.policy_max_plaintext_frame_len,
    }
}

fn stream_finalize_idempotency_key(key: &str) -> String {
    format!("stream_finalize_v2:{key}")
}

struct StreamFinalizeIdempotency {
    key: String,
    fingerprint: String,
    reservation: SendIdempotencyLeader,
}

impl AgentConnector {
    pub(crate) async fn stream_begin_response(
        &self,
        request_id: Option<&str>,
        account_id_hex: &str,
        group_id_hex: &str,
        stream_id_hex: Option<String>,
        parent_message_id_hex: Option<String>,
        quic_candidates: Vec<String>,
    ) -> Result<AgentControlResponse, ConnectorError> {
        let request_id = request_id
            .map(str::trim)
            .filter(|request_id| !request_id.is_empty() && request_id.len() <= 128)
            .ok_or(ConnectorError::InvalidStreamBeginRequestId)?
            .to_owned();
        let account = self.local_account_for_account_id(account_id_hex)?;
        let group_id_hex = normalize_hex(group_id_hex)?;
        let group_id = GroupId::new(hex::decode(&group_id_hex)?);
        let requested_stream_id_hex = stream_id_hex
            .map(|stream_id_hex| -> Result<Vec<u8>, ConnectorError> {
                let stream_id = hex::decode(normalize_hex(&stream_id_hex)?)?;
                if stream_id.len() != 32 {
                    return Err(ConnectorError::Stream(
                        "stream id must be exactly 32 bytes".into(),
                    ));
                }
                Ok(stream_id)
            })
            .transpose()?;
        let parent_message_id_hex = parent_message_id_hex
            .map(|parent_message_id_hex| -> Result<String, ConnectorError> {
                let normalized = normalize_hex(&parent_message_id_hex)?;
                if normalized.len() != 64 {
                    return Err(ConnectorError::Stream(
                        "stream parent message id must be 32 bytes".into(),
                    ));
                }
                Ok(normalized)
            })
            .transpose()?;
        let requested_stream_id_hex = requested_stream_id_hex.as_deref().map(hex::encode);
        let fingerprint = stream_begin_fingerprint(
            &account.account_id_hex,
            &group_id_hex,
            requested_stream_id_hex.as_deref(),
            parent_message_id_hex.as_deref(),
            &quic_candidates,
        );

        // Reserve only the idempotency key and globally unique stream id under
        // the store's short synchronous critical section. DNS and runtime I/O
        // happen after it is released, so an unrelated begin cannot be stalled
        // by a slow candidate. Same-request followers wait for the leader's
        // receipt; cancellation-safe reservation guards wake them to retry.
        let (stream_id, stream_id_hex, begin_reservation) = loop {
            match self.streams.reserve_stream_begin(
                request_id.clone(),
                fingerprint.clone(),
                requested_stream_id_hex.clone(),
            )? {
                StreamBeginReservation::Completed(receipt) => {
                    return Ok(begun_response(receipt));
                }
                StreamBeginReservation::Wait(mut completion) => {
                    let already_completed = *completion.borrow();
                    if !already_completed {
                        let _ = completion.changed().await;
                    }
                }
                StreamBeginReservation::Leader {
                    stream_id,
                    stream_id_hex,
                    guard,
                } => break (stream_id, stream_id_hex, guard),
            }
        };
        let mut stream_capability = [0u8; 32];
        OsRng.fill_bytes(&mut stream_capability);
        let stream_capability_hex = hex::encode(stream_capability);
        let (_payload, summary) = self
            .runtime
            .start_agent_text_stream_with_parent(
                &account.label,
                &group_id,
                &stream_id,
                unix_now_seconds(),
                parent_message_id_hex,
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
        let mut live_candidates = Vec::new();
        for candidate in &quic_candidates {
            let Ok(parsed) = parse_quic_candidate(candidate) else {
                continue;
            };
            let Ok(addr) =
                resolve_quic_candidate_addr(&parsed, self.allow_insecure_local_broker).await
            else {
                continue;
            };
            live_candidates.push((
                candidate.clone(),
                addr,
                parsed.server_name.clone(),
                broker_trust_for_candidate(&parsed.server_name, self.allow_insecure_local_broker),
            ));
        }
        let candidate = live_candidates
            .first()
            .map(|(candidate, ..)| candidate.clone())
            .unwrap_or_default();

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
        let start_event_id = MessageId::new(hex::decode(&start_message_id_hex)?);
        let open = OpenBrokerTextPublisher {
            broker_addr: live_candidates
                .first()
                .map(|(_, addr, ..)| *addr)
                .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9)),
            server_name: live_candidates
                .first()
                .map(|(_, _, server_name, _)| server_name.clone())
                .unwrap_or_else(|| "localhost".to_owned()),
            trust: live_candidates
                .first()
                .map(|(_, _, _, trust)| trust.clone())
                .unwrap_or(BrokerServerTrust::InsecureLocal),
            stream_id: stream_id.clone(),
            start_event_id: start_event_id.clone(),
            crypto: Some(crypto.crypto.clone()),
            max_plaintext_frame_len: policy_max_plaintext_frame_len,
        };
        let candidate_opens = live_candidates
            .into_iter()
            .map(
                |(_, broker_addr, server_name, trust)| OpenBrokerTextPublisher {
                    broker_addr,
                    server_name,
                    trust,
                    stream_id: stream_id.clone(),
                    start_event_id: start_event_id.clone(),
                    crypto: Some(crypto.crypto.clone()),
                    max_plaintext_frame_len: policy_max_plaintext_frame_len,
                },
            )
            .collect::<Vec<_>>();
        let handle = if candidate_opens.is_empty() {
            tokio::spawn(run_stream_compose_session_without_live(
                open,
                STREAM_COMPOSE_CHUNK_BYTES,
                rx,
                cancel_rx,
                report,
            ))
        } else {
            tokio::spawn(run_stream_compose_session_candidates(
                open,
                candidate_opens,
                STREAM_COMPOSE_CHUNK_BYTES,
                rx,
                cancel_rx,
                report,
            ))
        };
        self.streams.insert_new(
            stream_id_hex.clone(),
            ActiveStreamSession {
                account_label: account.label,
                group_id,
                stream_id,
                stream_capability,
                start_message_id_hex: start_message_id_hex.clone(),
                tx,
                cancel_tx,
                abort: handle.abort_handle(),
                last_activity: Instant::now(),
                finalized: None,
            },
        )?;
        let receipt = StreamBeginReceipt {
            fingerprint,
            stream_id_hex,
            stream_capability: stream_capability_hex,
            start_message_id_hex,
            quic_candidates,
            policy_max_plaintext_frame_len,
        };
        begin_reservation.complete(receipt.clone());
        Ok(begun_response(receipt))
    }

    pub(crate) async fn stream_append_response(
        &self,
        stream_id_hex: &str,
        stream_capability: &str,
        append_text: String,
    ) -> Result<AgentControlResponse, ConnectorError> {
        let session = self
            .streams
            .get_authorized(stream_id_hex, stream_capability)?;
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
        stream_capability: &str,
        status: String,
    ) -> Result<AgentControlResponse, ConnectorError> {
        let session = self
            .streams
            .get_authorized(stream_id_hex, stream_capability)?;
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
        stream_capability: &str,
        text: String,
    ) -> Result<AgentControlResponse, ConnectorError> {
        let session = self
            .streams
            .get_authorized(stream_id_hex, stream_capability)?;
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
        stream_capability: &str,
        final_text: String,
        transcript_hash_hex: &str,
        chunk_count: u64,
        idempotency_key: Option<String>,
    ) -> Result<AgentControlResponse, ConnectorError> {
        let stream_id_hex = normalize_hex(stream_id_hex)?;
        let stream_capability = normalize_stream_capability(stream_capability)?;
        let transcript_hash = transcript_hash_from_hex(transcript_hash_hex)?;
        let fingerprint = stream_finalize_fingerprint(
            &stream_id_hex,
            &stream_capability,
            &final_text,
            &transcript_hash,
            chunk_count,
        );
        let idempotency_key = idempotency_key
            .as_deref()
            .map(str::trim)
            .filter(|key| !key.is_empty())
            .map(stream_finalize_idempotency_key);
        // Preserve the post-success retry path after its stream session has
        // been removed, but reject a cache miss with an invalid capability
        // before it can wait on or reserve an in-flight send gate.
        if let Some(key) = idempotency_key.as_deref()
            && let Some(message_ids_hex) = self.idempotency.get(key, &fingerprint)
        {
            return Ok(AgentControlResponse::StreamFinalized {
                stream_id_hex,
                message_ids_hex,
            });
        }
        let session = self
            .streams
            .get_authorized(&stream_id_hex, &stream_capability)?;
        let idempotency = if let Some(key) = idempotency_key {
            match self.idempotency.acquire(&key, &fingerprint).await? {
                SendIdempotencyAcquisition::Completed((message_ids_hex, _)) => {
                    return Ok(AgentControlResponse::StreamFinalized {
                        stream_id_hex,
                        message_ids_hex,
                    });
                }
                SendIdempotencyAcquisition::Leader(reservation) => {
                    Some(StreamFinalizeIdempotency {
                        key,
                        fingerprint,
                        reservation,
                    })
                }
            }
        } else {
            None
        };
        // Clone (not remove) the session: the final text/hash/chunk-count
        // expectation is validated inside the compose task, atomically with
        // its teardown. On mismatch the session stays registered and the
        // compose task keeps running, so finalize is retryable (#366).
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
                    idempotency,
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
        // longer be consulted). If the freeze does not land — the session was
        // superseded by a same-stream-id replacement between our `get` and now
        // — this clone is stale: proceeding would publish under a lost retry
        // handle, so bail and let the agent re-finalize against the live
        // session instead.
        if !self.streams.mark_finalized(
            &stream_id_hex,
            &session,
            FinalizedStream {
                final_text: final_text.clone(),
                transcript_hash,
                chunk_count,
            },
        ) {
            return Err(ConnectorError::Stream(
                "stream session was superseded during finalize".into(),
            ));
        }
        self.finish_finalized_stream(
            &stream_id_hex,
            &session,
            final_text,
            transcript_hash,
            chunk_count,
            idempotency,
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
        idempotency: Option<StreamFinalizeIdempotency>,
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
        if let Some(idempotency) = idempotency {
            let message_ids = summary.message_ids.clone();
            self.idempotency.record(
                idempotency.key,
                idempotency.fingerprint,
                message_ids.clone(),
            );
            idempotency.reservation.complete(
                message_ids,
                agent_control::AgentControlSendMaintenanceDisposition::Ready,
            );
        }
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
        stream_capability: &str,
    ) -> Result<AgentControlResponse, ConnectorError> {
        let session = self
            .streams
            .remove_authorized(stream_id_hex, stream_capability)?;
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
