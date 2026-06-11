//! Local control protocol DTOs and newline-delimited JSON framing for Marmot agents.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const AGENT_CONTROL_PROTOCOL_V1: &str = "marmot.agent-control.v1";
pub const MAX_AGENT_CONTROL_FRAME_BYTES: usize = 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum AgentControlError {
    #[error("agent control frame is empty")]
    EmptyFrame,
    #[error("agent control frame exceeds max size: {0}")]
    FrameTooLarge(usize),
    #[error("wrong agent control protocol: {0}")]
    WrongProtocol(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentControlEnvelope<T> {
    pub marmot_agent_control: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<String>,
    #[serde(flatten)]
    pub payload: T,
}

impl<T> AgentControlEnvelope<T> {
    pub fn new(id: Option<String>, payload: T) -> Self {
        Self {
            marmot_agent_control: AGENT_CONTROL_PROTOCOL_V1.to_owned(),
            id,
            auth_token: None,
            payload,
        }
    }

    pub fn request(id: Option<String>, payload: T) -> Self {
        Self::new(id, payload)
    }

    pub fn with_auth_token(mut self, auth_token: impl Into<String>) -> Self {
        self.auth_token = Some(auth_token.into());
        self
    }

    pub fn validate_protocol(&self) -> Result<(), AgentControlError> {
        if self.marmot_agent_control == AGENT_CONTROL_PROTOCOL_V1 {
            Ok(())
        } else {
            Err(AgentControlError::WrongProtocol(
                self.marmot_agent_control.clone(),
            ))
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentControlRequest {
    SubscribeInbound {
        account_id_hex: Option<String>,
        group_id_hex: Option<String>,
    },
    SendFinal {
        account_id_hex: String,
        group_id_hex: String,
        text: String,
        reply_to_message_id_hex: Option<String>,
    },
    StreamBegin {
        account_id_hex: String,
        group_id_hex: String,
        stream_id_hex: Option<String>,
        quic_candidates: Vec<String>,
    },
    StreamAppend {
        stream_id_hex: String,
        append_text: String,
    },
    StreamStatus {
        stream_id_hex: String,
        status: String,
    },
    StreamProgress {
        stream_id_hex: String,
        text: String,
    },
    StreamFinalize {
        stream_id_hex: String,
        final_text: String,
        transcript_hash_hex: String,
        chunk_count: u64,
    },
    StreamCancel {
        stream_id_hex: String,
        reason: Option<String>,
    },
    AccountList,
    AccountCreate {
        label: Option<String>,
        publish_key_package: bool,
    },
    AccountPublishKeyPackage {
        account_id_hex: String,
    },
    AccountPublishProfile {
        account_id_hex: String,
        name: String,
        display_name: Option<String>,
    },
    SendAgentActivity {
        account_id_hex: String,
        group_id_hex: String,
        status: String,
        text: String,
        reply_to_message_id_hex: Option<String>,
        extra: Option<Value>,
    },
    SendAgentOperationEvent {
        account_id_hex: String,
        group_id_hex: String,
        event_type: String,
        status: String,
        operation_id: Option<String>,
        run_id: Option<String>,
        turn_id: Option<String>,
        name: Option<String>,
        text: String,
        preview: Option<String>,
        details: Option<Value>,
        sequence: Option<u64>,
        ok: Option<bool>,
        duration_ms: Option<u64>,
        reply_to_message_id_hex: Option<String>,
    },
    SendGroupSystemEvent {
        account_id_hex: String,
        group_id_hex: String,
        system_type: String,
        text: String,
        data: Option<Value>,
    },
    AllowlistList {
        account_id_hex: String,
    },
    AllowlistAdd {
        account_id_hex: String,
        welcomer_account_id_hex: String,
    },
    AllowlistRemove {
        account_id_hex: String,
        welcomer_account_id_hex: String,
    },
    DebugInjectInbound {
        account_id_hex: String,
        group_id_hex: String,
        message_id_hex: String,
        sender_account_id_hex: String,
        text: String,
    },
    DebugRecordedFinals,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentControlResponse {
    Ack,
    Error {
        code: String,
        message: String,
    },
    AccountList {
        accounts: Vec<AgentControlAccount>,
    },
    AccountCreated {
        account: AgentControlAccount,
    },
    KeyPackagePublished {
        account_id_hex: String,
        key_package_bytes: usize,
    },
    ProfilePublished {
        account_id_hex: String,
        name: String,
        display_name: Option<String>,
    },
    FinalSent {
        message_ids_hex: Vec<String>,
    },
    AppEventSent {
        message_ids_hex: Vec<String>,
    },
    Allowlist {
        account_id_hex: String,
        welcomer_account_ids_hex: Vec<String>,
    },
    StreamBegun {
        stream_id_hex: String,
        start_message_id_hex: String,
        quic_candidates: Vec<String>,
    },
    StreamFinalized {
        stream_id_hex: String,
        message_ids_hex: Vec<String>,
    },
    DebugRecordedFinals {
        sends: Vec<AgentControlDebugFinalSend>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentControlAccount {
    pub account_id_hex: String,
    pub label: String,
    pub local_signing: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentControlDebugFinalSend {
    pub account_id_hex: String,
    pub group_id_hex: String,
    pub text: String,
    pub reply_to_message_id_hex: Option<String>,
    pub message_ids_hex: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentControlEvent {
    InboundMessage {
        account_id_hex: String,
        group_id_hex: String,
        message_id_hex: String,
        sender_account_id_hex: String,
        text: String,
    },
    GroupInvite {
        account_id_hex: String,
        group_id_hex: String,
        via_welcome_message_id_hex: String,
        welcomer_account_id_hex: Option<String>,
    },
    StreamUpdate {
        account_id_hex: String,
        group_id_hex: String,
        stream_id_hex: String,
        status: String,
    },
    /// The connector's inbound broadcast lagged and dropped events before they could be
    /// delivered on this subscription. Dropped inbound messages are gone from the channel and
    /// will not be re-emitted, so the agent must re-query/re-sync state (e.g. via its own
    /// message history) to recover anything it missed. `dropped_events` is the number of
    /// broadcast slots that overflowed (not necessarily all inbound messages).
    ResyncRequired {
        account_id_hex: Option<String>,
        group_id_hex: Option<String>,
        dropped_events: u64,
    },
}

pub fn encode_frame<T: Serialize>(message: &T) -> Result<Vec<u8>, AgentControlError> {
    let mut bytes = serde_json::to_vec(message)?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub fn decode_frame<T: DeserializeOwned>(frame: &[u8]) -> Result<T, AgentControlError> {
    let frame = trim_line_ending(frame);
    if frame.is_empty() {
        return Err(AgentControlError::EmptyFrame);
    }
    if frame.len() > MAX_AGENT_CONTROL_FRAME_BYTES {
        return Err(AgentControlError::FrameTooLarge(frame.len()));
    }
    Ok(serde_json::from_slice(frame)?)
}

pub fn decode_envelope<T: DeserializeOwned>(
    frame: &[u8],
) -> Result<AgentControlEnvelope<T>, AgentControlError> {
    let envelope: AgentControlEnvelope<T> = decode_frame(frame)?;
    envelope.validate_protocol()?;
    Ok(envelope)
}

pub async fn write_frame<W, T>(writer: &mut W, message: &T) -> Result<(), AgentControlError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let frame = encode_frame(message)?;
    writer.write_all(&frame).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn read_frame<R, T>(reader: &mut R) -> Result<Option<T>, AgentControlError>
where
    R: AsyncBufRead + Unpin,
    T: DeserializeOwned,
{
    let mut frame = Vec::new();
    // Cap the read itself so a client that never sends a newline cannot make us
    // buffer unbounded memory before the size check runs. We allow one byte past
    // the limit so an over-cap frame is detectable (read_until on a Take adapter
    // stops silently at the limit instead of erroring).
    let limit = (MAX_AGENT_CONTROL_FRAME_BYTES + 1) as u64;
    let read = {
        let mut limited = (&mut *reader).take(limit);
        limited.read_until(b'\n', &mut frame).await?
    };
    if read == 0 {
        return Ok(None);
    }
    if frame.len() > MAX_AGENT_CONTROL_FRAME_BYTES {
        return Err(AgentControlError::FrameTooLarge(frame.len()));
    }
    decode_frame(&frame).map(Some)
}

pub async fn read_envelope<R, T>(
    reader: &mut R,
) -> Result<Option<AgentControlEnvelope<T>>, AgentControlError>
where
    R: AsyncBufRead + Unpin,
    T: DeserializeOwned,
{
    match read_frame(reader).await? {
        Some(envelope) => {
            let envelope: AgentControlEnvelope<T> = envelope;
            envelope.validate_protocol()?;
            Ok(Some(envelope))
        }
        None => Ok(None),
    }
}

fn trim_line_ending(frame: &[u8]) -> &[u8] {
    let frame = frame.strip_suffix(b"\n").unwrap_or(frame);
    frame.strip_suffix(b"\r").unwrap_or(frame)
}

#[cfg(test)]
mod tests {
    use serde_json::Value;
    use tokio::io::AsyncReadExt;
    use tokio::io::BufReader;

    use crate::{
        AgentControlEnvelope, AgentControlError, AgentControlRequest, AgentControlResponse,
        MAX_AGENT_CONTROL_FRAME_BYTES, decode_envelope, encode_frame, read_envelope, read_frame,
        write_frame,
    };

    #[test]
    fn stream_append_frame_round_trips_as_append_only_text() {
        let frame = AgentControlEnvelope::request(
            Some("req-1".to_owned()),
            AgentControlRequest::StreamAppend {
                stream_id_hex: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_owned(),
                append_text: "lo".to_owned(),
            },
        );

        let encoded = encode_frame(&frame).unwrap();
        assert!(encoded.ends_with(b"\n"));
        let json: Value = serde_json::from_slice(&encoded[..encoded.len() - 1]).unwrap();
        assert_eq!(json["marmot_agent_control"], "marmot.agent-control.v1");
        assert_eq!(json["id"], "req-1");
        assert_eq!(json["type"], "stream_append");
        assert_eq!(json["append_text"], "lo");
        assert!(json.get("text").is_none());
        assert!(json.get("replace_text").is_none());

        let decoded: AgentControlEnvelope<AgentControlRequest> = decode_envelope(&encoded).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn envelope_auth_token_round_trips_when_present() {
        let frame = AgentControlEnvelope::request(
            Some("req-auth".to_owned()),
            AgentControlRequest::AccountList,
        )
        .with_auth_token("test-token");

        let encoded = encode_frame(&frame).unwrap();
        let json: Value = serde_json::from_slice(&encoded[..encoded.len() - 1]).unwrap();
        assert_eq!(json["auth_token"], "test-token");

        let decoded: AgentControlEnvelope<AgentControlRequest> = decode_envelope(&encoded).unwrap();
        assert_eq!(decoded, frame);
    }

    #[tokio::test]
    async fn async_frame_helpers_exchange_typed_requests_and_responses() {
        let (client, server) = tokio::io::duplex(4096);
        let (client_read, mut client_write) = tokio::io::split(client);
        let (server_read, mut server_write) = tokio::io::split(server);
        let mut client_read = BufReader::new(client_read);
        let mut server_read = BufReader::new(server_read);

        let request = AgentControlEnvelope::request(
            Some("req-2".to_owned()),
            AgentControlRequest::AccountList,
        );
        write_frame(&mut client_write, &request).await.unwrap();
        let received: AgentControlEnvelope<AgentControlRequest> =
            read_envelope(&mut server_read).await.unwrap().unwrap();
        assert_eq!(received, request);

        let response =
            AgentControlEnvelope::new(Some("req-2".to_owned()), AgentControlResponse::Ack);
        write_frame(&mut server_write, &response).await.unwrap();
        let received: AgentControlEnvelope<AgentControlResponse> =
            read_envelope(&mut client_read).await.unwrap().unwrap();
        assert_eq!(received, response);
    }

    #[tokio::test]
    async fn write_frame_emits_one_json_line() {
        let (mut writer, mut reader) = tokio::io::duplex(4096);
        let request = AgentControlEnvelope::request(
            Some("req-single-frame".to_owned()),
            AgentControlRequest::AccountList,
        );

        write_frame(&mut writer, &request).await.unwrap();
        drop(writer);

        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).await.unwrap();
        let lines = bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>();
        assert_eq!(lines.len(), 1, "write_frame should emit exactly one frame");
        let decoded: AgentControlEnvelope<AgentControlRequest> = decode_envelope(&bytes).unwrap();
        assert_eq!(decoded, request);
    }

    #[tokio::test]
    async fn read_frame_rejects_oversized_frame_without_buffering_unbounded() {
        // A client that streams data without a trailing newline must not be able
        // to make read_frame buffer past the cap. The read-side `.take()` adapter
        // stops at MAX + 1 bytes, so the post-read size check fires deterministically
        // instead of letting allocation grow unbounded (pre-auth OOM, darkmatter#212).
        let oversize = MAX_AGENT_CONTROL_FRAME_BYTES + 4096;
        let payload = vec![b'a'; oversize]; // no newline, intentionally over the cap
        let mut reader = BufReader::new(std::io::Cursor::new(payload));

        let result: Result<Option<AgentControlEnvelope<AgentControlRequest>>, _> =
            read_envelope(&mut reader).await;
        match result {
            Err(AgentControlError::FrameTooLarge(len)) => {
                // We buffer at most one byte past the cap, never the full payload.
                assert_eq!(len, MAX_AGENT_CONTROL_FRAME_BYTES + 1);
            }
            other => panic!("expected FrameTooLarge, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn read_frame_accepts_frame_at_the_cap_boundary() {
        // A frame whose encoded line is exactly MAX_AGENT_CONTROL_FRAME_BYTES
        // (including its trailing newline) must still round-trip; the read-side
        // limit allows one byte past the cap precisely so a legal max-size frame
        // is not truncated. We pad `append_text` with ASCII bytes (which serde
        // serializes 1:1 with no escaping) so we can hit the cap to the byte.
        let make = |append_text: String| {
            AgentControlEnvelope::request(
                Some("req-boundary".to_owned()),
                AgentControlRequest::StreamAppend {
                    stream_id_hex:
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                            .to_owned(),
                    append_text,
                },
            )
        };
        // Measure the frame size with an empty body, then pad the body so the
        // total encoded length (JSON + trailing newline) is exactly the cap.
        let base_len = encode_frame(&make(String::new())).unwrap().len();
        assert!(base_len < MAX_AGENT_CONTROL_FRAME_BYTES);
        let padding = MAX_AGENT_CONTROL_FRAME_BYTES - base_len;
        let request = make("a".repeat(padding));

        let mut encoded = encode_frame(&request).unwrap();
        assert!(encoded.ends_with(b"\n"));
        assert_eq!(
            encoded.len(),
            MAX_AGENT_CONTROL_FRAME_BYTES,
            "boundary frame must encode to exactly the cap"
        );
        // Append a following frame's bytes to prove read_frame stops at the first
        // newline and does not over-read past the cap into trailing data.
        encoded.extend_from_slice(b"trailing");
        let mut reader = BufReader::new(std::io::Cursor::new(encoded));

        let received: AgentControlEnvelope<AgentControlRequest> =
            read_envelope(&mut reader).await.unwrap().unwrap();
        assert_eq!(received, request);
    }

    #[tokio::test]
    async fn read_frame_returns_none_on_empty_stream() {
        let mut reader = BufReader::new(std::io::Cursor::new(Vec::<u8>::new()));
        let result: Option<AgentControlEnvelope<AgentControlRequest>> =
            read_frame(&mut reader).await.unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn all_initial_request_variants_have_stable_type_names() {
        let requests = vec![
            (
                AgentControlRequest::SubscribeInbound {
                    account_id_hex: None,
                    group_id_hex: None,
                },
                "subscribe_inbound",
            ),
            (
                AgentControlRequest::SendFinal {
                    account_id_hex: account(),
                    group_id_hex: group(),
                    text: "done".to_owned(),
                    reply_to_message_id_hex: None,
                },
                "send_final",
            ),
            (
                AgentControlRequest::StreamBegin {
                    account_id_hex: account(),
                    group_id_hex: group(),
                    stream_id_hex: None,
                    quic_candidates: vec!["quic://127.0.0.1:4450".to_owned()],
                },
                "stream_begin",
            ),
            (
                AgentControlRequest::StreamAppend {
                    stream_id_hex: stream(),
                    append_text: "hel".to_owned(),
                },
                "stream_append",
            ),
            (
                AgentControlRequest::StreamStatus {
                    stream_id_hex: stream(),
                    status: "thinking".to_owned(),
                },
                "stream_status",
            ),
            (
                AgentControlRequest::StreamProgress {
                    stream_id_hex: stream(),
                    text: "{\"v\":1,\"status\":\"started\"}".to_owned(),
                },
                "stream_progress",
            ),
            (
                AgentControlRequest::StreamFinalize {
                    stream_id_hex: stream(),
                    final_text: "hello".to_owned(),
                    transcript_hash_hex: hash(),
                    chunk_count: 1,
                },
                "stream_finalize",
            ),
            (
                AgentControlRequest::StreamCancel {
                    stream_id_hex: stream(),
                    reason: Some("gateway_replaced_text".to_owned()),
                },
                "stream_cancel",
            ),
            (AgentControlRequest::AccountList, "account_list"),
            (
                AgentControlRequest::AccountCreate {
                    label: Some("agent".to_owned()),
                    publish_key_package: true,
                },
                "account_create",
            ),
            (
                AgentControlRequest::AccountPublishKeyPackage {
                    account_id_hex: account(),
                },
                "account_publish_key_package",
            ),
            (
                AgentControlRequest::AccountPublishProfile {
                    account_id_hex: account(),
                    name: "agent".to_owned(),
                    display_name: Some("Agent".to_owned()),
                },
                "account_publish_profile",
            ),
            (
                AgentControlRequest::SendAgentActivity {
                    account_id_hex: account(),
                    group_id_hex: group(),
                    status: "thinking".to_owned(),
                    text: "Thinking".to_owned(),
                    reply_to_message_id_hex: Some(message()),
                    extra: None,
                },
                "send_agent_activity",
            ),
            (
                AgentControlRequest::SendAgentOperationEvent {
                    account_id_hex: account(),
                    group_id_hex: group(),
                    event_type: "tool_call".to_owned(),
                    status: "started".to_owned(),
                    operation_id: Some("call-1".to_owned()),
                    run_id: Some("run-1".to_owned()),
                    turn_id: Some("turn-1".to_owned()),
                    name: Some("search".to_owned()),
                    text: "Searching".to_owned(),
                    preview: Some("query".to_owned()),
                    details: None,
                    sequence: Some(1),
                    ok: None,
                    duration_ms: None,
                    reply_to_message_id_hex: Some(message()),
                },
                "send_agent_operation_event",
            ),
            (
                AgentControlRequest::SendGroupSystemEvent {
                    account_id_hex: account(),
                    group_id_hex: group(),
                    system_type: "member_added".to_owned(),
                    text: "Member added".to_owned(),
                    data: None,
                },
                "send_group_system_event",
            ),
            (
                AgentControlRequest::AllowlistList {
                    account_id_hex: account(),
                },
                "allowlist_list",
            ),
            (
                AgentControlRequest::AllowlistAdd {
                    account_id_hex: account(),
                    welcomer_account_id_hex: welcomer(),
                },
                "allowlist_add",
            ),
            (
                AgentControlRequest::AllowlistRemove {
                    account_id_hex: account(),
                    welcomer_account_id_hex: welcomer(),
                },
                "allowlist_remove",
            ),
            (
                AgentControlRequest::DebugInjectInbound {
                    account_id_hex: account(),
                    group_id_hex: group(),
                    message_id_hex: message(),
                    sender_account_id_hex: welcomer(),
                    text: "hello agent".to_owned(),
                },
                "debug_inject_inbound",
            ),
            (
                AgentControlRequest::DebugRecordedFinals,
                "debug_recorded_finals",
            ),
        ];

        for (request, expected_type) in requests {
            let value = serde_json::to_value(request).unwrap();
            assert_eq!(value["type"], expected_type);
        }
    }

    fn account() -> String {
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned()
    }

    fn welcomer() -> String {
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned()
    }

    fn group() -> String {
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_owned()
    }

    fn stream() -> String {
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_owned()
    }

    fn message() -> String {
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned()
    }

    fn hash() -> String {
        "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_owned()
    }
}
