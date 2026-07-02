//! Agent-text-stream discovery and the brokered-QUIC watch machinery, plus
//! the [`MarmotAppRuntime`] entry points that drive them.

use std::net::SocketAddr;

use cgka_traits::agent_text_stream::{
    AGENT_TEXT_STREAM_RECORD_PROGRESS_DELTA, AGENT_TEXT_STREAM_RECORD_STATUS,
    AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, AgentTextStreamKeyContextV1,
};
use cgka_traits::app_event::{
    MARMOT_APP_EVENT_KIND_AGENT_STREAM_START, STREAM_BROKER_TAG, STREAM_ROUTE_TAG, STREAM_TAG,
};
use cgka_traits::{GroupId, MemberId, MessageId};
use tokio::sync::{mpsc, oneshot};
use transport_quic_broker::{
    BrokerServerTrust, SubscribeTextFromBroker, subscribe_text_from_broker_with_limits,
};
use transport_quic_stream::{AgentTextStreamCrypto, AgentTextStreamReceiveLimits};

use super::{
    AgentStreamWatchOptions, AgentTextStreamCryptoContext, MarmotAppRuntime,
    RuntimeAgentStreamUpdate, RuntimeAgentStreamWatch, blocking_app_task,
    wait_for_runtime_shutdown,
};
use crate::ids::normalize_group_id_hex_app;
use crate::messages::{STREAM_ROUTE_QUIC, tag_value, tag_values};
use crate::{AGENT_STREAM_START_LOOKBACK_LIMIT, AppError, AppMessageQuery, AppMessageRecord};

impl MarmotAppRuntime {
    /// Watch a live agent text stream over the brokered QUIC channel. Resolves
    /// the latest `Start` payload for the group (or a specific `stream_id`),
    /// connects to the broker named in its `quic://` candidate, and streams
    /// incremental text chunks until the stream finishes. Must be called from
    /// within a tokio runtime (it spawns the QUIC subscriber task).
    pub async fn watch_agent_text_stream(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        options: AgentStreamWatchOptions,
    ) -> Result<RuntimeAgentStreamWatch, AppError> {
        self.shared.lifecycle().ensure_running()?;
        let group_id_hex = hex::encode(group_id.as_slice());
        let app = self.accounts.app.clone();
        let account_ref_for_query = account_ref.to_owned();
        let group_id_hex_for_query = group_id_hex.clone();
        let messages = blocking_app_task(move || {
            app.messages_with_query(
                &account_ref_for_query,
                AppMessageQuery {
                    group_id_hex: Some(group_id_hex_for_query),
                    limit: Some(AGENT_STREAM_START_LOOKBACK_LIMIT),
                },
            )
        })
        .await?;
        let normalized_stream_id_hex = options
            .stream_id_hex
            .as_deref()
            .map(normalize_hex_app)
            .transpose()?;
        let (start_message_id_hex, start, _sender_hex) =
            latest_agent_stream_start(messages, normalized_stream_id_hex.as_deref())?;
        if start_message_id_hex.is_empty() {
            // The latest start hasn't been echoed back with a message id yet, so
            // we can't reference it to the broker; surface that rather than
            // forwarding a zero-length MessageId.
            return Err(AppError::AgentStreamStartNotConfirmed);
        }
        if start.route != STREAM_ROUTE_QUIC {
            return Err(AppError::AgentStreamUnsupportedRoute);
        }
        let candidates = parse_quic_candidates(&start.quic_candidates)?;
        let server_cert_der = options.server_cert_der;
        let insecure_local = options.insecure_local;
        let stream_id_hex = normalize_hex_app(&start.stream_id_hex)?;
        let crypto_context = self
            .agent_text_stream_crypto_for_start_event(
                Some(account_ref),
                Some(&group_id_hex),
                Some(&stream_id_hex),
                &start_message_id_hex,
            )
            .await?;
        let policy_max_plaintext_frame_len = crypto_context.policy_max_plaintext_frame_len;

        let (updates_tx, updates_rx) = mpsc::channel(1024);
        let (terminal_tx, terminal_rx) = oneshot::channel();
        let mut stopping = self.shared.lifecycle().subscribe_shutdown();
        let handle = tokio::spawn(async move {
            let final_update = tokio::select! {
                _ = wait_for_runtime_shutdown(&mut stopping) => return,
                update = watch_broker_candidates(
                    BrokerWatch {
                        candidates,
                        server_cert_der,
                        insecure_local,
                        stream_id: crypto_context.stream_id,
                        start_event_id: crypto_context.start_event_id,
                        crypto: Some(crypto_context.crypto),
                        policy_max_plaintext_frame_len,
                    },
                    updates_tx.clone(),
                ) => update,
            };
            let _ = terminal_tx.send(final_update);
        });
        Ok(RuntimeAgentStreamWatch {
            stream_id_hex,
            updates: updates_rx,
            terminal: Some(terminal_rx),
            abort: handle.abort_handle(),
            stopping: self.shared.lifecycle().subscribe_shutdown(),
        })
    }

    pub async fn agent_text_stream_crypto_for_start_event(
        &self,
        account_ref: Option<&str>,
        group_id_hex: Option<&str>,
        stream_id_hex: Option<&str>,
        start_message_id_hex: &str,
    ) -> Result<AgentTextStreamCryptoContext, AppError> {
        self.shared.lifecycle().ensure_running()?;
        let start_message_id_hex = normalize_hex_app(start_message_id_hex)?;
        let group_id_hex = group_id_hex.map(normalize_group_id_hex_app).transpose()?;
        let stream_id_hex = stream_id_hex.map(normalize_hex_app).transpose()?;

        let accounts = if let Some(account_ref) =
            account_ref.filter(|account_ref| !account_ref.trim().is_empty())
        {
            vec![self.accounts.resolve(account_ref)?]
        } else {
            self.accounts.app.account_home().accounts()?
        };

        for account in accounts {
            if !account.is_active_local_signing() {
                continue;
            }
            let app = self.accounts.app.clone();
            let account_label = account.label.clone();
            let query_group_id_hex = group_id_hex.clone();
            let messages = blocking_app_task(move || {
                app.messages_with_query(
                    &account_label,
                    AppMessageQuery {
                        group_id_hex: query_group_id_hex,
                        limit: None,
                    },
                )
            })
            .await?;

            for message in messages.into_iter().rev() {
                if message.message_id_hex != start_message_id_hex {
                    continue;
                }
                let Some(start) = StreamStartView::from_event(message.kind, &message.tags) else {
                    continue;
                };
                let start_stream_id_hex = normalize_hex_app(&start.stream_id_hex)?;
                if stream_id_hex
                    .as_deref()
                    .is_some_and(|stream_id| stream_id != start_stream_id_hex)
                {
                    continue;
                }
                let group_id = GroupId::new(hex::decode(&message.group_id_hex)?);
                let stream_id = hex::decode(&start_stream_id_hex)?;
                let start_event_id = MessageId::new(hex::decode(&start_message_id_hex)?);
                let group_state = match self.group_mls_state(&account.label, &group_id).await {
                    Ok(group_state) => group_state,
                    Err(_) => continue,
                };
                let stream_secret = match self
                    .agent_text_stream_exporter_secret(&account.label, &group_id)
                    .await
                {
                    Ok(secret) => secret,
                    Err(_) => continue,
                };
                let crypto = AgentTextStreamCrypto::new(
                    stream_secret,
                    AgentTextStreamKeyContextV1::new(
                        group_id.clone(),
                        stream_id.clone(),
                        cgka_traits::EpochId(group_state.epoch),
                        MemberId::new(hex::decode(message.sender)?),
                        start_event_id.clone(),
                    ),
                );
                // Carry the group policy alongside the start-event-bound crypto
                // so send/watch/compose paths enforce the durable MLS component
                // instead of silently falling back to the app-profile ceiling.
                let app_for_policy = self.accounts.app.clone();
                let account_label_for_policy = account.label.clone();
                let group_id_hex_for_policy = message.group_id_hex.clone();
                let policy_max_plaintext_frame_len = blocking_app_task(move || {
                    app_for_policy.group(&account_label_for_policy, &group_id_hex_for_policy)
                })
                .await?
                .map(|group| group.agent_text_stream.max_plaintext_frame_len)
                .filter(|max_plaintext_frame_len| *max_plaintext_frame_len > 0);
                return Ok(AgentTextStreamCryptoContext {
                    account_id_hex: account.account_id_hex,
                    account_label: account.label,
                    group_id,
                    stream_id,
                    start_event_id,
                    crypto,
                    policy_max_plaintext_frame_len,
                });
            }
        }

        Err(AppError::AgentStreamMissingStart)
    }
}

pub(crate) struct ParsedQuicCandidate {
    pub(crate) authority: String,
    pub(crate) server_name: String,
}

struct ResolvedQuicCandidate {
    broker_addr: SocketAddr,
    server_name: String,
}

/// A kind-1200 agent text stream start, projected from its inner-event tags.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamStartView {
    pub stream_id_hex: String,
    pub route: String,
    pub quic_candidates: Vec<String>,
}

impl StreamStartView {
    /// Read the stream start view from a kind-1200 event's tags. Returns `None`
    /// if the event is not a stream start or is missing the `stream` tag.
    pub fn from_event(kind: u64, tags: &[Vec<String>]) -> Option<Self> {
        if kind != MARMOT_APP_EVENT_KIND_AGENT_STREAM_START {
            return None;
        }
        let stream_id_hex = tag_value(tags, STREAM_TAG)?.to_owned();
        let route = tag_value(tags, STREAM_ROUTE_TAG)
            .unwrap_or(STREAM_ROUTE_QUIC)
            .to_owned();
        let quic_candidates = tag_values(tags, STREAM_BROKER_TAG)
            .into_iter()
            .map(str::to_owned)
            .collect();
        Some(Self {
            stream_id_hex,
            route,
            quic_candidates,
        })
    }
}

/// Find the most recent kind-1200 stream start in a group's message history,
/// optionally constrained to a specific `stream_id`.
pub(crate) fn latest_agent_stream_start(
    messages: Vec<AppMessageRecord>,
    stream_id_hex: Option<&str>,
) -> Result<(String, StreamStartView, String), AppError> {
    let stream_id_hex = stream_id_hex.map(normalize_hex_app).transpose()?;
    messages
        .into_iter()
        .rev()
        .find_map(|message| {
            let start = StreamStartView::from_event(message.kind, &message.tags)?;
            let start_stream_id_hex = normalize_hex_app(&start.stream_id_hex).ok()?;
            if stream_id_hex
                .as_deref()
                .is_none_or(|stream_id| stream_id == start_stream_id_hex)
            {
                Some((message.message_id_hex, start, message.sender))
            } else {
                None
            }
        })
        .ok_or(AppError::AgentStreamMissingStart)
}

fn normalize_hex_app(value: &str) -> Result<String, AppError> {
    Ok(hex::encode(hex::decode(value)?))
}

pub(crate) fn parse_quic_candidate(candidate: &str) -> Result<ParsedQuicCandidate, AppError> {
    let trimmed = candidate.trim();
    let Some(rest) = trimmed.strip_prefix("quic://") else {
        return Err(AppError::AgentStreamInvalidCandidate(trimmed.to_owned()));
    };
    // Per transports/quic.md a receiver MUST ignore any path, query, or
    // fragment after the authority; the authority ends at the first of '/',
    // '?', or '#'.
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    if authority.is_empty() {
        return Err(AppError::AgentStreamInvalidCandidate(trimmed.to_owned()));
    }
    let server_name = candidate_server_name(authority)?;
    Ok(ParsedQuicCandidate {
        authority: authority.to_owned(),
        server_name,
    })
}

pub(crate) fn parse_quic_candidates(
    candidates: &[String],
) -> Result<Vec<ParsedQuicCandidate>, AppError> {
    let parsed = candidates
        .iter()
        .filter(|candidate| candidate.trim().starts_with("quic://"))
        .filter_map(|candidate| parse_quic_candidate(candidate).ok())
        .collect::<Vec<_>>();
    if parsed.is_empty() {
        return Err(AppError::AgentStreamMissingCandidate);
    }
    Ok(parsed)
}

fn candidate_server_name(authority: &str) -> Result<String, AppError> {
    if let Some(rest) = authority.strip_prefix('[') {
        let Some((host, _)) = rest.split_once(']') else {
            return Err(AppError::AgentStreamInvalidCandidate(authority.to_owned()));
        };
        return Ok(host.to_owned());
    }
    authority
        .rsplit_once(':')
        .map(|(host, _)| host.to_owned())
        .filter(|host| !host.is_empty())
        .ok_or_else(|| AppError::AgentStreamInvalidCandidate(authority.to_owned()))
}

/// One broker-watch attempt: every reachable candidate for one preview
/// stream, the trust inputs, the record crypto, and the group policy cap.
struct BrokerWatch {
    candidates: Vec<ParsedQuicCandidate>,
    server_cert_der: Option<Vec<u8>>,
    insecure_local: bool,
    stream_id: Vec<u8>,
    start_event_id: MessageId,
    crypto: Option<AgentTextStreamCrypto>,
    policy_max_plaintext_frame_len: Option<u32>,
}

async fn watch_broker_candidates(
    watch: BrokerWatch,
    updates_tx: mpsc::Sender<RuntimeAgentStreamUpdate>,
) -> RuntimeAgentStreamUpdate {
    // Receive validation uses the group policy frame cap when the component
    // is present; the app-profile constant stays the ceiling and fallback.
    let mut limits = AgentTextStreamReceiveLimits::default();
    if let Some(max_plaintext_frame_len) = watch.policy_max_plaintext_frame_len {
        limits.max_plaintext_frame_len =
            max_plaintext_frame_len.min(limits.max_plaintext_frame_len);
    }
    let mut last_error = None;
    for candidate in watch.candidates {
        match resolve_broker_addr(&candidate.authority).await {
            Ok(broker_addr) => {
                let resolved = ResolvedQuicCandidate {
                    broker_addr,
                    server_name: candidate.server_name,
                };
                let trust = broker_trust_for_addr(
                    resolved.broker_addr,
                    watch.server_cert_der.clone(),
                    watch.insecure_local,
                );
                let config = SubscribeTextFromBroker {
                    broker_addr: resolved.broker_addr,
                    server_name: resolved.server_name,
                    trust,
                    stream_id: watch.stream_id.clone(),
                    start_event_id: watch.start_event_id.clone(),
                    crypto: watch.crypto.clone(),
                };
                let chunk_tx = updates_tx.clone();
                match subscribe_text_from_broker_with_limits(config, limits, |chunk| {
                    let update = match chunk.record_type {
                        AGENT_TEXT_STREAM_RECORD_TEXT_DELTA => RuntimeAgentStreamUpdate::Chunk {
                            seq: chunk.seq,
                            text: chunk.text.clone(),
                        },
                        AGENT_TEXT_STREAM_RECORD_STATUS => RuntimeAgentStreamUpdate::Status {
                            seq: chunk.seq,
                            status: chunk.text.clone(),
                        },
                        AGENT_TEXT_STREAM_RECORD_PROGRESS_DELTA => {
                            RuntimeAgentStreamUpdate::Progress {
                                seq: chunk.seq,
                                text: chunk.text.clone(),
                            }
                        }
                        record_type => RuntimeAgentStreamUpdate::Record {
                            seq: chunk.seq,
                            record_type,
                            text: chunk.text.clone(),
                        },
                    };
                    match chunk_tx.try_send(update) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Full(_))
                            if chunk.record_type == AGENT_TEXT_STREAM_RECORD_TEXT_DELTA =>
                        {
                            tracing::warn!(
                                target: "marmot_app::agent_stream",
                                method = "watch_agent_text_stream",
                                "dropping live agent text stream delta; consumer is behind",
                            );
                        }
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            tracing::warn!(
                                target: "marmot_app::agent_stream",
                                method = "watch_agent_text_stream",
                                record_type = chunk.record_type,
                                dropped_record_class = "non_text",
                                "dropping non-text agent stream record; consumer is behind",
                            );
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => {}
                    }
                })
                .await
                {
                    Ok(received) => {
                        return RuntimeAgentStreamUpdate::Finished {
                            text: received.text,
                            transcript_hash_hex: hex::encode(received.transcript_hash),
                            chunk_count: received.chunk_count,
                        };
                    }
                    Err(err) => last_error = Some(err.to_string()),
                }
            }
            Err(err) => last_error = Some(err.to_string()),
        }
    }
    RuntimeAgentStreamUpdate::Failed {
        message: last_error.unwrap_or_else(|| AppError::AgentStreamMissingCandidate.to_string()),
    }
}

async fn resolve_broker_addr(authority: &str) -> Result<SocketAddr, AppError> {
    let mut addrs = tokio::net::lookup_host(authority)
        .await
        .map_err(|_| AppError::AgentStreamInvalidCandidate(authority.to_owned()))?;
    addrs
        .next()
        .ok_or_else(|| AppError::AgentStreamInvalidCandidate(authority.to_owned()))
}

pub(crate) fn broker_trust_for_addr(
    broker_addr: SocketAddr,
    server_cert_der: Option<Vec<u8>>,
    insecure_local: bool,
) -> BrokerServerTrust {
    if insecure_local && broker_addr.ip().is_loopback() {
        return BrokerServerTrust::InsecureLocal;
    }
    server_cert_der
        .map(BrokerServerTrust::CertificateDer)
        .unwrap_or(BrokerServerTrust::Platform)
}
