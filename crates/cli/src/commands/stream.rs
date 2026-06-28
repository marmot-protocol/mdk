//! `stream` command namespace handlers (QUIC agent text stream previews) and stream helpers.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use cgka_traits::app_event::{STREAM_CHUNKS_TAG, STREAM_HASH_TAG, STREAM_TAG};
use cgka_traits::{GroupId, MessageId};
use marmot_account::AccountHome;
use marmot_app::{
    AgentTextStreamFinishRequest, AppError, AppMessageQuery, AppMessageRecord, MarmotApp,
    MarmotAppRuntime, StreamStartView, tag_value,
};
use serde_json::{Value, json};
use transport_quic_broker::{
    BrokerServerTrust, PublishTextToBroker, SubscribeTextFromBroker, publish_text_to_broker,
    subscribe_text_from_broker_with_limits,
};
use transport_quic_stream::{
    AgentTextStreamReceiveLimits, QuicTextStreamReceiver, SendTextStream, ServerTrust,
    send_text_stream,
};

use crate::{
    AgentStreamDelta, CommandOutput, DmError, StreamCommand, agent_text_stream_payload_value,
    ensure_local_signing, normalize_group_id_hex, npub_for_account_id, resolve_account,
    resolve_account_ref, stream_route_label, unix_now_seconds, unsupported_command,
};

const AGENT_STREAM_START_LOOKBACK_LIMIT: usize = 200;

pub(crate) async fn stream_command_local(command: StreamCommand) -> Result<CommandOutput, DmError> {
    match command {
        StreamCommand::Receive {
            bind,
            start_event_id,
        } => {
            let (start_event_id, anchored) = stream_start_event_id(start_event_id)?;
            let receiver = QuicTextStreamReceiver::bind(bind)?;
            let local_addr = receiver.local_addr()?;
            let server_cert_der_hex = hex::encode(receiver.server_cert_der());
            let received = receiver.receive_once(start_event_id, None).await?;
            let stream_id = hex::encode(&received.stream_id);
            Ok(CommandOutput {
                plain: format!(
                    "received stream {stream_id} chunks={}\n{}",
                    received.chunk_count, received.text
                ),
                json: json!({
                    "local_addr": local_addr.to_string(),
                    "server_cert_der_hex": server_cert_der_hex,
                    "stream_id": stream_id,
                    "anchored": anchored,
                    "chunks": received.chunks.into_iter().map(|chunk| {
                        json!({
                            "seq": chunk.seq,
                            "record_type": chunk.record_type,
                            "flags": chunk.flags,
                            "text": chunk.text,
                        })
                    }).collect::<Vec<_>>(),
                    "text": received.text,
                    "transcript_hash": hex::encode(received.transcript_hash),
                    "chunk_count": received.chunk_count,
                }),
            })
        }
        StreamCommand::Send {
            broker,
            connect,
            server_name,
            server_cert_der_hex,
            insecure_local,
            stream_id,
            start_event_id,
            chunk_bytes,
            chunk_delay_ms,
            text,
        } => {
            if text.is_empty() {
                return Err(DmError::EmptyStreamText);
            }
            let text = text.join(" ");
            let stream_id = stream_id
                .map(hex::decode)
                .transpose()?
                .unwrap_or_else(transport_quic_stream::random_stream_id);
            let (start_event_id, anchored) = stream_start_event_id(start_event_id)?;
            if broker {
                let trust = broker_trust(connect, server_cert_der_hex, insecure_local)?;
                if !anchored {
                    return Err(DmError::MissingStreamStart);
                }
                let sent = publish_text_to_broker(PublishTextToBroker {
                    broker_addr: connect,
                    server_name: server_name.clone(),
                    trust: trust.clone(),
                    stream_id: stream_id.clone(),
                    start_event_id,
                    text: text.clone(),
                    max_chunk_bytes: chunk_bytes,
                    chunk_delay: Duration::from_millis(chunk_delay_ms),
                    crypto: None,
                    max_plaintext_frame_len: None,
                })
                .await?;
                return Ok(CommandOutput {
                    plain: format!(
                        "sent brokered stream {} chunks={}",
                        hex::encode(&stream_id),
                        sent.chunk_count
                    ),
                    json: json!({
                        "brokered": true,
                        "connect": connect.to_string(),
                        "server_name": server_name,
                        "trust": broker_trust_name(&trust),
                        "stream_id": hex::encode(sent.stream_id),
                        "anchored": anchored,
                        "text_bytes": text.len(),
                        "transcript_hash": hex::encode(sent.transcript_hash),
                        "chunk_count": sent.chunk_count,
                    }),
                });
            }
            let trust = stream_trust(connect, server_cert_der_hex, insecure_local)?;
            let sent = send_text_stream(SendTextStream {
                server_addr: connect,
                server_name: server_name.clone(),
                trust: trust.clone(),
                stream_id: stream_id.clone(),
                start_event_id,
                text: text.clone(),
                max_chunk_bytes: chunk_bytes,
                chunk_delay: Duration::from_millis(chunk_delay_ms),
                crypto: None,
                max_plaintext_frame_len: None,
            })
            .await?;
            Ok(CommandOutput {
                plain: format!(
                    "sent stream {} chunks={}",
                    hex::encode(&stream_id),
                    sent.chunk_count
                ),
                json: json!({
                    "brokered": false,
                    "connect": connect.to_string(),
                    "server_name": server_name,
                    "trust": stream_trust_name(&trust),
                    "stream_id": hex::encode(sent.stream_id),
                    "anchored": anchored,
                    "text_bytes": text.len(),
                    "transcript_hash": hex::encode(sent.transcript_hash),
                    "chunk_count": sent.chunk_count,
                }),
            })
        }
        StreamCommand::Start { .. }
        | StreamCommand::Watch { .. }
        | StreamCommand::ComposeOpen { .. }
        | StreamCommand::ComposeAppend { .. }
        | StreamCommand::ComposeFinish { .. }
        | StreamCommand::ComposeCancel { .. }
        | StreamCommand::Finish { .. }
        | StreamCommand::Verify { .. } => {
            unreachable!("durable stream commands require app setup")
        }
    }
}

pub(crate) async fn stream_command_app(
    account_home: &AccountHome,
    app: &MarmotApp,
    command: StreamCommand,
    account_flag: Option<String>,
) -> Result<CommandOutput, DmError> {
    let runtime = app.runtime();
    stream_command_app_with_runtime(account_home, app, &runtime, command, account_flag).await
}

pub(crate) async fn stream_command_app_with_runtime(
    account_home: &AccountHome,
    app: &MarmotApp,
    runtime: &MarmotAppRuntime,
    command: StreamCommand,
    account_flag: Option<String>,
) -> Result<CommandOutput, DmError> {
    match command {
        StreamCommand::Start {
            group,
            stream_id,
            quic_candidates,
        } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id = GroupId::new(hex::decode(group)?);
            let stream_id = stream_id
                .map(hex::decode)
                .transpose()?
                .unwrap_or_else(transport_quic_stream::random_stream_id);
            let (payload, summary) = runtime
                .start_agent_text_stream(
                    &account.label,
                    &group_id,
                    &stream_id,
                    unix_now_seconds(),
                    quic_candidates,
                )
                .await?;
            let agent_text_stream =
                agent_text_stream_payload_value(payload.kind, &payload.tags, &payload.content);
            Ok(CommandOutput {
                plain: format!(
                    "started stream {} published={}",
                    hex::encode(&stream_id),
                    summary.published
                ),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex)?,
                    "group_id": hex::encode(group_id.as_slice()),
                    "stream_id": hex::encode(stream_id),
                    "published": summary.published,
                    "message_ids": summary.message_ids,
                    "agent_text_stream": agent_text_stream,
                }),
            })
        }
        StreamCommand::Watch {
            group,
            stream_id,
            server_cert_der_hex,
            insecure_local,
            background,
        } => {
            stream_watch_command_app_with_runtime(
                account_home,
                app,
                runtime,
                StreamCommand::Watch {
                    group,
                    stream_id,
                    server_cert_der_hex,
                    insecure_local,
                    background,
                },
                account_flag,
                |_| {},
            )
            .await
        }
        StreamCommand::Send {
            broker,
            connect,
            server_name,
            server_cert_der_hex,
            insecure_local,
            stream_id,
            start_event_id,
            chunk_bytes,
            chunk_delay_ms,
            text,
        } => {
            if text.is_empty() {
                return Err(DmError::EmptyStreamText);
            }
            let text = text.join(" ");
            let selected_account = resolve_selected_account(account_home, account_flag)?;
            if let Some(account) = selected_account.as_ref() {
                ensure_local_signing(account)?;
            }
            let selected_account_id_hex = selected_account
                .as_ref()
                .map(|account| account.account_id_hex.as_str());
            let start_event_id_hex = start_event_id.ok_or(DmError::MissingStreamStart)?;
            let expected_stream_id_hex =
                stream_id.map(|value| normalize_hex(&value)).transpose()?;
            let (stream_id, crypto, policy_max_plaintext_frame_len) =
                stream_crypto_for_start_event(
                    runtime,
                    selected_account_id_hex,
                    None,
                    expected_stream_id_hex.as_deref(),
                    &start_event_id_hex,
                )
                .await?;
            let start_event_id = MessageId::new(hex::decode(normalize_hex(&start_event_id_hex)?)?);
            if broker {
                let trust = broker_trust(connect, server_cert_der_hex, insecure_local)?;
                let sent = publish_text_to_broker(PublishTextToBroker {
                    broker_addr: connect,
                    server_name: server_name.clone(),
                    trust: trust.clone(),
                    stream_id: stream_id.clone(),
                    start_event_id,
                    text: text.clone(),
                    max_chunk_bytes: chunk_bytes,
                    chunk_delay: Duration::from_millis(chunk_delay_ms),
                    crypto: Some(crypto),
                    max_plaintext_frame_len: policy_max_plaintext_frame_len,
                })
                .await?;
                return Ok(CommandOutput {
                    plain: format!(
                        "sent brokered stream {} chunks={}",
                        hex::encode(&stream_id),
                        sent.chunk_count
                    ),
                    json: json!({
                        "brokered": true,
                        "connect": connect.to_string(),
                        "server_name": server_name,
                        "trust": broker_trust_name(&trust),
                        "stream_id": hex::encode(sent.stream_id),
                        "anchored": true,
                        "text_bytes": text.len(),
                        "transcript_hash": hex::encode(sent.transcript_hash),
                        "chunk_count": sent.chunk_count,
                    }),
                });
            }
            let trust = stream_trust(connect, server_cert_der_hex, insecure_local)?;
            let sent = send_text_stream(SendTextStream {
                server_addr: connect,
                server_name: server_name.clone(),
                trust: trust.clone(),
                stream_id: stream_id.clone(),
                start_event_id,
                text: text.clone(),
                max_chunk_bytes: chunk_bytes,
                chunk_delay: Duration::from_millis(chunk_delay_ms),
                crypto: Some(crypto),
                max_plaintext_frame_len: policy_max_plaintext_frame_len,
            })
            .await?;
            Ok(CommandOutput {
                plain: format!(
                    "sent stream {} chunks={}",
                    hex::encode(&stream_id),
                    sent.chunk_count
                ),
                json: json!({
                    "brokered": false,
                    "connect": connect.to_string(),
                    "server_name": server_name,
                    "trust": stream_trust_name(&trust),
                    "stream_id": hex::encode(sent.stream_id),
                    "anchored": true,
                    "text_bytes": text.len(),
                    "transcript_hash": hex::encode(sent.transcript_hash),
                    "chunk_count": sent.chunk_count,
                }),
            })
        }
        StreamCommand::ComposeOpen { .. }
        | StreamCommand::ComposeAppend { .. }
        | StreamCommand::ComposeFinish { .. }
        | StreamCommand::ComposeCancel { .. } => unsupported_command(
            "stream compose",
            "stream compose sessions require the daemon",
        ),
        StreamCommand::Finish {
            group,
            stream_id,
            start_event_id,
            transcript_hash,
            chunk_count,
            text,
        } => {
            if text.is_empty() {
                return Err(DmError::EmptyStreamText);
            }
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id = GroupId::new(hex::decode(group)?);
            let stream_id = hex::decode(stream_id)?;
            let transcript_hash = transcript_hash_from_hex(&transcript_hash)?;
            let (payload, summary) = runtime
                .finish_agent_text_stream(
                    &account.label,
                    &group_id,
                    AgentTextStreamFinishRequest {
                        stream_id: stream_id.clone(),
                        start_event_id,
                        final_text_or_reference: text.join(" "),
                        transcript_hash,
                        chunk_count,
                        finished_at: unix_now_seconds(),
                    },
                )
                .await?;
            let agent_text_stream =
                agent_text_stream_payload_value(payload.kind, &payload.tags, &payload.content);
            Ok(CommandOutput {
                plain: format!(
                    "finished stream {} published={}",
                    hex::encode(&stream_id),
                    summary.published
                ),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex)?,
                    "group_id": hex::encode(group_id.as_slice()),
                    "stream_id": hex::encode(stream_id),
                    "published": summary.published,
                    "message_ids": summary.message_ids,
                    "agent_text_stream": agent_text_stream,
                }),
            })
        }
        StreamCommand::Verify {
            group,
            stream_id,
            transcript_hash,
            chunk_count,
        } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id_hex = normalize_group_id_hex(&group)?;
            let stream_id_hex = normalize_hex(&stream_id)?;
            let transcript_hash_hex = hex::encode(transcript_hash_from_hex(&transcript_hash)?);
            let messages = app.messages_with_query(
                &account.label,
                AppMessageQuery {
                    group_id_hex: Some(group_id_hex.clone()),
                    limit: None,
                },
            )?;
            let final_message = messages.into_iter().rev().find(|message| {
                marmot_app::is_stream_final_event(message.kind, &message.tags)
                    && tag_value(&message.tags, STREAM_TAG) == Some(stream_id_hex.as_str())
            });
            let (verified, final_message_json) = match final_message {
                Some(message) => {
                    let final_transcript_hash =
                        tag_value(&message.tags, STREAM_HASH_TAG).unwrap_or_default();
                    let final_chunk_count = tag_value(&message.tags, STREAM_CHUNKS_TAG)
                        .and_then(|count| count.parse::<u64>().ok())
                        .unwrap_or_default();
                    let transcript_hash_matches = final_transcript_hash == transcript_hash_hex;
                    let chunk_count_matches =
                        chunk_count.is_none_or(|count| count == final_chunk_count);
                    (
                        transcript_hash_matches && chunk_count_matches,
                        json!({
                            "message_id": message.message_id_hex,
                            "stream_id": stream_id_hex,
                            "transcript_hash": final_transcript_hash,
                            "chunk_count": final_chunk_count,
                            "final_text_or_reference": message.plaintext,
                            "checks": {
                                "transcript_hash": transcript_hash_matches,
                                "chunk_count": chunk_count_matches,
                            },
                        }),
                    )
                }
                None => (false, Value::Null),
            };
            Ok(CommandOutput {
                plain: format!("stream {stream_id_hex} verified={verified}"),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex)?,
                    "group_id": group_id_hex,
                    "stream_id": stream_id_hex,
                    "verified": verified,
                    "expected": {
                        "transcript_hash": transcript_hash_hex,
                        "chunk_count": chunk_count,
                    },
                    "final_message": final_message_json,
                }),
            })
        }
        StreamCommand::Receive { .. } => {
            unreachable!("local QUIC stream commands return before app setup")
        }
    }
}

pub(crate) async fn stream_watch_command_app_with_runtime<F>(
    account_home: &AccountHome,
    app: &MarmotApp,
    runtime: &MarmotAppRuntime,
    command: StreamCommand,
    account_flag: Option<String>,
    mut on_delta: F,
) -> Result<CommandOutput, DmError>
where
    F: FnMut(AgentStreamDelta) + Send,
{
    let StreamCommand::Watch {
        group,
        stream_id,
        server_cert_der_hex,
        insecure_local,
        background: _,
    } = command
    else {
        unreachable!("stream watch helper only accepts stream watch commands");
    };
    let account = resolve_account(account_home, account_flag.clone())?;
    ensure_local_signing(&account)?;
    app.status(&account.label)?;
    let group_id_hex = normalize_group_id_hex(&group)?;
    let expected_stream_id_hex = stream_id.map(|value| normalize_hex(&value)).transpose()?;
    let messages = app.messages_with_query(
        &account.label,
        AppMessageQuery {
            group_id_hex: Some(group_id_hex.clone()),
            limit: Some(AGENT_STREAM_START_LOOKBACK_LIMIT),
        },
    )?;
    let (start_message_id_hex, start_payload, _start_sender_hex) =
        latest_stream_start(messages, expected_stream_id_hex.as_deref())?;
    if start_message_id_hex.is_empty() {
        return Err(DmError::StreamStartNotConfirmed);
    }
    if start_payload.route != "quic" {
        return Err(DmError::UnsupportedStreamRoute(
            stream_route_label(&start_payload.route).to_owned(),
        ));
    }
    let candidate = start_payload
        .quic_candidates
        .iter()
        .find(|candidate| candidate.trim().starts_with("quic://"))
        .ok_or(DmError::MissingQuicCandidate)?;
    let candidate = parse_quic_candidate(candidate)?;
    let candidate_addr = resolve_quic_candidate_addr(&candidate).await?;
    let trust = broker_trust(candidate_addr, server_cert_der_hex, insecure_local)?;
    let stream_id_hex = start_payload.stream_id_hex.clone();
    let start_event_id = MessageId::new(hex::decode(&start_message_id_hex)?);
    let (stream_id, crypto, policy_max_plaintext_frame_len) = stream_crypto_for_start_event(
        runtime,
        Some(&account.account_id_hex),
        Some(&group_id_hex),
        Some(&stream_id_hex),
        &start_message_id_hex,
    )
    .await?;
    let crypto = Some(crypto);
    let mut limits = AgentTextStreamReceiveLimits::default();
    if let Some(max_plaintext_frame_len) = policy_max_plaintext_frame_len {
        limits.max_plaintext_frame_len =
            max_plaintext_frame_len.min(limits.max_plaintext_frame_len);
    }
    let delta_account = account_flag.or(Some(account.account_id_hex.clone()));
    let delta_group_id = group_id_hex.clone();
    let delta_stream_id = stream_id_hex.clone();
    let received = subscribe_text_from_broker_with_limits(
        SubscribeTextFromBroker {
            broker_addr: candidate_addr,
            server_name: candidate.server_name.clone(),
            trust: trust.clone(),
            stream_id,
            start_event_id,
            crypto,
        },
        limits,
        |chunk| {
            on_delta(AgentStreamDelta {
                account: delta_account.clone(),
                group_id: delta_group_id.clone(),
                stream_id: delta_stream_id.clone(),
                seq: chunk.seq,
                record_type: chunk.record_type,
                flags: chunk.flags,
                text: chunk.text.clone(),
            });
        },
    )
    .await?;
    Ok(CommandOutput {
        plain: format!(
            "received brokered stream {} chunks={}\n{}",
            hex::encode(&received.stream_id),
            received.chunk_count,
            received.text
        ),
        json: json!({
            "brokered": true,
            "candidate": candidate.original,
            "connect": candidate_addr.to_string(),
            "server_name": candidate.server_name,
            "trust": broker_trust_name(&trust),
            "stream_id": hex::encode(&received.stream_id),
            "start_message_id": start_message_id_hex,
            "chunks": received.chunks.into_iter().map(|chunk| {
                json!({
                    "seq": chunk.seq,
                    "record_type": chunk.record_type,
                    "flags": chunk.flags,
                    "text": chunk.text,
                })
            }).collect::<Vec<_>>(),
            "text": received.text,
            "transcript_hash": hex::encode(received.transcript_hash),
            "chunk_count": received.chunk_count,
        }),
    })
}

fn stream_start_event_id(start_event_id: Option<String>) -> Result<(MessageId, bool), DmError> {
    match start_event_id {
        Some(value) => Ok((MessageId::new(hex::decode(value)?), true)),
        None => Ok((MessageId::new(vec![0; 32]), false)),
    }
}

fn latest_stream_start(
    messages: Vec<AppMessageRecord>,
    stream_id_hex: Option<&str>,
) -> Result<(String, StreamStartView, String), DmError> {
    let stream_id_hex = stream_id_hex.map(normalize_hex).transpose()?;
    messages
        .into_iter()
        .rev()
        .find_map(|message| {
            let start = StreamStartView::from_event(message.kind, &message.tags)?;
            let start_stream_id_hex = normalize_hex(&start.stream_id_hex).ok()?;
            if stream_id_hex
                .as_deref()
                .is_none_or(|stream_id| stream_id == start_stream_id_hex)
            {
                Some((message.message_id_hex, start, message.sender))
            } else {
                None
            }
        })
        .ok_or(DmError::MissingStreamStart)
}

pub(crate) async fn stream_crypto_for_start_event(
    runtime: &MarmotAppRuntime,
    resolved_account_id_hex: Option<&str>,
    group_id_hex: Option<&str>,
    stream_id_hex: Option<&str>,
    start_message_id_hex: &str,
) -> Result<
    (
        Vec<u8>,
        transport_quic_stream::AgentTextStreamCrypto,
        Option<u32>,
    ),
    DmError,
> {
    let context = runtime
        .agent_text_stream_crypto_for_start_event(
            resolved_account_id_hex,
            group_id_hex,
            stream_id_hex,
            start_message_id_hex,
        )
        .await
        .map_err(map_agent_stream_crypto_error)?;
    Ok((
        context.stream_id,
        context.crypto,
        context.policy_max_plaintext_frame_len,
    ))
}

fn map_agent_stream_crypto_error(err: AppError) -> DmError {
    match err {
        AppError::AgentStreamMissingStart => DmError::MissingStreamStart,
        AppError::AgentStreamStartNotConfirmed => DmError::StreamStartNotConfirmed,
        AppError::AgentStreamUnsupportedRoute => {
            DmError::UnsupportedStreamRoute("non-quic".to_owned())
        }
        AppError::AgentStreamMissingCandidate => DmError::MissingQuicCandidate,
        AppError::AgentStreamInvalidCandidate(candidate) => {
            DmError::InvalidQuicCandidate(candidate)
        }
        AppError::Hex(err) => DmError::Hex(err),
        other => DmError::App(other),
    }
}

pub(crate) struct ParsedQuicCandidate {
    original: String,
    pub(crate) authority: String,
    pub(crate) server_name: String,
}

/// Extract the `host:port` (or `[ipv6]:port`) authority from a `quic://` URL
/// remainder, ignoring any path, query, or fragment after it. Per
/// `transports/quic.md` the authority ends at the first `/`, `?`, or `#`. Shared
/// by both quic-candidate parsers below (and mirrors `marmot_app`'s
/// `parse_quic_candidate`) so the rule cannot drift.
fn quic_authority(rest: &str) -> &str {
    rest.split(['/', '?', '#']).next().unwrap_or(rest)
}

pub(crate) fn parse_quic_candidate(candidate: &str) -> Result<ParsedQuicCandidate, DmError> {
    let trimmed = candidate.trim();
    let Some(rest) = trimmed.strip_prefix("quic://") else {
        return Err(DmError::InvalidQuicCandidate(trimmed.to_owned()));
    };
    let authority = quic_authority(rest);
    if authority.is_empty() {
        return Err(DmError::InvalidQuicCandidate(trimmed.to_owned()));
    }
    let server_name = candidate_server_name(authority)?;
    Ok(ParsedQuicCandidate {
        original: trimmed.to_owned(),
        authority: authority.to_owned(),
        server_name,
    })
}

pub(crate) async fn resolve_quic_candidate_addr(
    candidate: &ParsedQuicCandidate,
) -> Result<SocketAddr, DmError> {
    let mut addrs = tokio::net::lookup_host(&candidate.authority)
        .await
        .map_err(|source| DmError::QuicCandidateResolve {
            candidate: candidate.original.clone(),
            source,
        })?;
    addrs
        .next()
        .ok_or_else(|| DmError::InvalidQuicCandidate(candidate.original.clone()))
}

fn candidate_server_name(authority: &str) -> Result<String, DmError> {
    if let Some(rest) = authority.strip_prefix('[') {
        let Some((host, _)) = rest.split_once(']') else {
            return Err(DmError::InvalidQuicCandidate(authority.to_owned()));
        };
        return Ok(host.to_owned());
    }
    authority
        .rsplit_once(':')
        .map(|(host, _)| host.to_owned())
        .filter(|host| !host.is_empty())
        .ok_or_else(|| DmError::InvalidQuicCandidate(authority.to_owned()))
}

pub(crate) fn first_quic_candidate_is_loopback(candidates: &[String]) -> bool {
    candidates
        .iter()
        .find(|candidate| candidate.trim().starts_with("quic://"))
        .and_then(|candidate| quic_candidate_host(candidate))
        .is_some_and(|host| quic_host_is_loopback(&host))
}

pub(crate) fn quic_candidate_host(candidate: &str) -> Option<String> {
    let rest = candidate.trim().strip_prefix("quic://")?;
    let authority = quic_authority(rest);
    if let Some(rest) = authority.strip_prefix('[') {
        return rest.split_once(']').map(|(host, _)| host.to_owned());
    }
    authority
        .rsplit_once(':')
        .map(|(host, _)| host.to_owned())
        .filter(|host| !host.is_empty())
}

fn quic_host_is_loopback(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

fn transcript_hash_from_hex(value: &str) -> Result<[u8; 32], DmError> {
    let bytes = hex::decode(value)?;
    let actual = bytes.len();
    bytes
        .try_into()
        .map_err(|_| DmError::InvalidTranscriptHashLength(actual))
}

pub(crate) fn normalize_hex(value: &str) -> Result<String, DmError> {
    Ok(hex::encode(hex::decode(value)?))
}

pub(crate) fn broker_trust(
    server_addr: SocketAddr,
    server_cert_der_hex: Option<String>,
    insecure_local: bool,
) -> Result<BrokerServerTrust, DmError> {
    if insecure_local && server_cert_der_hex.is_some() {
        return Err(DmError::ConflictingStreamTrust);
    }
    if insecure_local {
        ensure_insecure_local_endpoint(server_addr)?;
        return Ok(BrokerServerTrust::InsecureLocal);
    }
    server_cert_der_hex
        .map(|value| hex::decode(value).map(BrokerServerTrust::CertificateDer))
        .transpose()
        .map(|trust| trust.unwrap_or(BrokerServerTrust::Platform))
        .map_err(Into::into)
}

fn broker_trust_name(trust: &BrokerServerTrust) -> &'static str {
    match trust {
        BrokerServerTrust::Platform => "platform",
        BrokerServerTrust::CertificateDer(_) => "certificate_der",
        BrokerServerTrust::InsecureLocal => "insecure_local",
    }
}

fn stream_trust(
    server_addr: SocketAddr,
    server_cert_der_hex: Option<String>,
    insecure_local: bool,
) -> Result<ServerTrust, DmError> {
    if insecure_local && server_cert_der_hex.is_some() {
        return Err(DmError::ConflictingStreamTrust);
    }
    if insecure_local {
        ensure_insecure_local_endpoint(server_addr)?;
        return Ok(ServerTrust::InsecureLocal);
    }
    server_cert_der_hex
        .map(|value| hex::decode(value).map(ServerTrust::CertificateDer))
        .transpose()
        .map(|trust| trust.unwrap_or(ServerTrust::Platform))
        .map_err(Into::into)
}

fn ensure_insecure_local_endpoint(server_addr: SocketAddr) -> Result<(), DmError> {
    if server_addr.ip().is_loopback() {
        return Ok(());
    }
    Err(DmError::InsecureLocalRequiresLoopback(server_addr))
}

fn stream_trust_name(trust: &ServerTrust) -> &'static str {
    match trust {
        ServerTrust::Platform => "platform",
        ServerTrust::CertificateDer(_) => "certificate_der",
        ServerTrust::InsecureLocal => "insecure_local",
    }
}

fn resolve_selected_account(
    account_home: &AccountHome,
    explicit: Option<String>,
) -> Result<Option<marmot_account::AccountSummary>, DmError> {
    let Some(account) = explicit
        .or_else(|| std::env::var("DM_ACCOUNT").ok())
        .filter(|account| !account.trim().is_empty())
    else {
        return Ok(None);
    };
    Ok(Some(resolve_account_ref(account_home, &account)?))
}
