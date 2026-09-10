//! QUIC text-stream preview session lifecycle and the idle-session sweeper.

use std::time::Instant;

use crate::error::ConnectorError;
use crate::stream_session::{
    ActiveStreamSession, SendIdempotencyAcquisition, SendIdempotencyLeader, StreamBeginReceipt,
    StreamBeginReservation, StrictIdempotencyAcquisition, normalize_stream_capability,
};
use crate::validation::{normalize_hex, transcript_hash_from_hex};
use crate::{
    AgentConnector, STREAM_COMPOSE_CHUNK_BYTES, STREAM_SESSION_IDLE_TIMEOUT,
    STREAM_SESSION_SWEEP_INTERVAL,
};
use agent_control::AgentControlResponse;
use agent_stream_compose::StreamFinishExpectation;
use cgka_traits::GroupId;
use marmot_app::{AgentPublisherOptions, AgentPublisherRecord, AgentPublisherRouting};
use rand::{RngCore, rngs::OsRng};

/// Current schema version for persisted `stream_finalize` request fingerprints.
pub(crate) const STREAM_FINALIZE_FINGERPRINT_VERSION: u8 = 2;
pub(crate) const STREAM_BEGIN_FINGERPRINT_VERSION: u8 = 1;
pub(crate) const STREAM_PREVIEW_FINGERPRINT_VERSION: u8 = 1;

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

fn stream_preview_fingerprint(
    operation: &str,
    stream_id_hex: &str,
    stream_capability: &str,
    payload_field: &str,
    payload: &str,
) -> String {
    use sha2::{Digest, Sha256};

    let preimage = serde_json::json!([
        STREAM_PREVIEW_FINGERPRINT_VERSION,
        operation,
        stream_id_hex,
        stream_capability,
        payload_field,
        payload,
    ]);
    let bytes = serde_json::to_vec(&preimage).expect("stream preview fingerprint cannot fail");
    hex::encode(Sha256::digest(bytes))
}

fn stream_preview_idempotency_key(operation: &str, key: String) -> Result<String, ConnectorError> {
    let key = key.trim();
    if key.is_empty() || key.len() > 128 {
        return Err(ConnectorError::Stream(
            "stream preview idempotency key must be 1..=128 bytes".into(),
        ));
    }
    Ok(format!("stream_preview_v1:{operation}:{key}"))
}

struct StreamPreviewIdempotency {
    key: String,
    fingerprint: String,
    reservation: SendIdempotencyLeader,
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
        let publisher = self
            .runtime
            .open_agent_publisher(
                account.label,
                group_id,
                stream_id,
                AgentPublisherOptions {
                    candidates: quic_candidates.clone(),
                    routing: AgentPublisherRouting::BestEffort,
                    parent_message_id: parent_message_id_hex,
                    chunk_bytes: STREAM_COMPOSE_CHUNK_BYTES,
                    server_cert_der: None,
                    insecure_local: self.allow_insecure_local_broker,
                },
            )
            .await?;
        let start_message_id_hex = publisher.start_id().to_owned();
        let policy_max_plaintext_frame_len = publisher.policy_frame_limit();
        self.streams.insert_new(
            stream_id_hex.clone(),
            ActiveStreamSession {
                publisher,
                stream_capability,
                last_activity: Instant::now(),
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

    pub(crate) async fn stream_record_response(
        &self,
        kind: AgentPublisherRecord,
        stream_id_hex: &str,
        stream_capability: &str,
        text: String,
        idempotency_key: Option<String>,
    ) -> Result<AgentControlResponse, ConnectorError> {
        let stream_id_hex = normalize_hex(stream_id_hex)?;
        let stream_capability = normalize_stream_capability(stream_capability)?;
        // Authenticate before consulting dedup receipts. Retaining the handle
        // also prevents idle eviction while a matching mutation is in flight.
        let session = self
            .streams
            .get_authorized(&stream_id_hex, &stream_capability)?;
        let idempotency = if let Some(key) = idempotency_key {
            let (operation, payload_field) = match kind {
                AgentPublisherRecord::Text => ("append", "append_text"),
                AgentPublisherRecord::Status => ("status", "status"),
                AgentPublisherRecord::Progress => ("progress", "text"),
            };
            let key = stream_preview_idempotency_key(operation, key)?;
            let fingerprint = stream_preview_fingerprint(
                operation,
                &stream_id_hex,
                &stream_capability,
                payload_field,
                &text,
            );
            match self
                .preview_idempotency
                .acquire_strict(&key, &fingerprint)
                .await?
            {
                StrictIdempotencyAcquisition::Completed => return Ok(AgentControlResponse::Ack),
                StrictIdempotencyAcquisition::Conflict => {
                    return Err(ConnectorError::StreamPreviewIdempotencyConflict);
                }
                StrictIdempotencyAcquisition::Leader(reservation) => {
                    Some(StreamPreviewIdempotency {
                        key,
                        fingerprint,
                        reservation,
                    })
                }
            }
        } else {
            None
        };
        session.publisher.append(kind, text).await?;
        if let Some(idempotency) = idempotency {
            self.preview_idempotency
                .record(idempotency.key, idempotency.fingerprint, Vec::new());
            idempotency.reservation.complete(
                Vec::new(),
                agent_control::AgentControlSendMaintenanceDisposition::Ready,
            );
        }
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
        self.finish_stream_response(
            stream_id_hex,
            stream_capability,
            StreamFinishExpectation {
                final_text,
                transcript_hash_hex: Some(hex::encode(transcript_hash)),
                chunk_count: Some(chunk_count),
            },
            fingerprint,
            idempotency_key
                .as_deref()
                .map(str::trim)
                .filter(|key| !key.is_empty())
                .map(stream_finalize_idempotency_key),
        )
        .await
    }

    pub(crate) async fn stream_finish_response(
        &self,
        stream_id_hex: &str,
        stream_capability: &str,
        final_text: String,
        idempotency_key: Option<String>,
    ) -> Result<AgentControlResponse, ConnectorError> {
        use sha2::{Digest, Sha256};
        let stream_id_hex = normalize_hex(stream_id_hex)?;
        let stream_capability = normalize_stream_capability(stream_capability)?;
        let fingerprint = hex::encode(Sha256::digest(
            serde_json::to_vec(&serde_json::json!([
                "stream_finish_v1",
                stream_id_hex,
                stream_capability,
                final_text,
            ]))
            .expect("stream finish fingerprint cannot fail"),
        ));
        self.finish_stream_response(
            stream_id_hex,
            stream_capability,
            StreamFinishExpectation {
                final_text,
                transcript_hash_hex: None,
                chunk_count: None,
            },
            fingerprint,
            idempotency_key
                .as_deref()
                .map(str::trim)
                .filter(|key| !key.is_empty())
                .map(|key| format!("stream_finish_v1:{key}")),
        )
        .await
    }

    async fn finish_stream_response(
        &self,
        stream_id_hex: String,
        stream_capability: String,
        expected: StreamFinishExpectation,
        fingerprint: String,
        idempotency_key: Option<String>,
    ) -> Result<AgentControlResponse, ConnectorError> {
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
        // The publisher retains the sealed transcript and successful receipt
        // across cancellation or a failed durable send. Keep the session until
        // the durable receipt is also recorded by the control layer.
        let summary = session.publisher.finish(Some(expected)).await?;
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
        let _ = self.streams.remove_if_same(&stream_id_hex, &session);
        Ok(AgentControlResponse::StreamFinalized {
            stream_id_hex: stream_id_hex.to_owned(),
            message_ids_hex: summary.message_ids,
        })
    }

    pub(crate) async fn stream_cancel_response(
        &self,
        stream_id_hex: &str,
        stream_capability: &str,
    ) -> Result<AgentControlResponse, ConnectorError> {
        let session = self
            .streams
            .remove_authorized(stream_id_hex, stream_capability)?;
        let observation = self.runtime.begin_product_operation(
            marmot_app::ProductFamily::Stream,
            "cancel",
            marmot_app::ProductUnit::Action,
        );
        session.publisher.cancel().await;
        if let Some(observation) = observation {
            observation.finish("performed");
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
                let swept = streams.sweep_idle(STREAM_SESSION_IDLE_TIMEOUT).await;
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
