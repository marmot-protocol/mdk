use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use agent_control::{
    AgentControlEnvelope, AgentControlEvent, AgentControlRequest, AgentControlResponse,
    read_envelope, write_frame,
};
use tokio::io::{AsyncWrite, BufReader};
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tracing::{debug, warn};

use crate::bridge::TRACE_TARGET;
use crate::error::{HarnessError, Result};

#[derive(Clone, Debug)]
pub(crate) struct ControlClient {
    socket: PathBuf,
    auth_token: Option<String>,
    request_timeout: Duration,
    request_seq: Arc<AtomicU64>,
}

impl ControlClient {
    pub(crate) fn new(
        socket: PathBuf,
        auth_token: Option<String>,
        request_timeout: Duration,
    ) -> Self {
        Self {
            socket,
            auth_token,
            request_timeout,
            request_seq: Arc::new(AtomicU64::new(0)),
        }
    }

    pub(crate) async fn account_list(&self) -> Result<Vec<agent_control::AgentControlAccount>> {
        match self
            .call("account_list", AgentControlRequest::AccountList)
            .await?
        {
            AgentControlResponse::AccountList { accounts } => Ok(accounts),
            AgentControlResponse::Error { code, .. } => Err(HarnessError::ControlRejected {
                method: "account_list",
                code,
            }),
            other => Err(unexpected_response("account_list", &other)),
        }
    }

    pub(crate) async fn allowlist_list(&self, account_ref: &str) -> Result<HashSet<String>> {
        match self
            .call(
                "allowlist_list",
                AgentControlRequest::AllowlistList {
                    account_id_hex: account_ref.to_owned(),
                },
            )
            .await?
        {
            AgentControlResponse::Allowlist {
                welcomer_account_ids_hex,
                ..
            } => Ok(welcomer_account_ids_hex.into_iter().collect()),
            AgentControlResponse::Error { code, .. } => Err(HarnessError::ControlRejected {
                method: "allowlist_list",
                code,
            }),
            other => Err(unexpected_response("allowlist_list", &other)),
        }
    }

    pub(crate) async fn allowlist_add(&self, account_ref: &str, welcomer_ref: &str) -> Result<()> {
        match self
            .call(
                "allowlist_add",
                AgentControlRequest::AllowlistAdd {
                    account_id_hex: account_ref.to_owned(),
                    welcomer_account_id_hex: welcomer_ref.to_owned(),
                },
            )
            .await?
        {
            AgentControlResponse::Ack | AgentControlResponse::Allowlist { .. } => Ok(()),
            AgentControlResponse::Error { code, .. } => Err(HarnessError::ControlRejected {
                method: "allowlist_add",
                code,
            }),
            other => Err(unexpected_response("allowlist_add", &other)),
        }
    }

    pub(crate) async fn send_final(
        &self,
        account_ref: &str,
        group_ref: &str,
        reply_to_ref: &str,
        text: &str,
        chunk_index: usize,
    ) -> Result<()> {
        let idempotency_key = format!("{reply_to_ref}:reply:{chunk_index}");
        match self
            .call(
                "send_final",
                AgentControlRequest::SendFinal {
                    account_id_hex: account_ref.to_owned(),
                    group_id_hex: group_ref.to_owned(),
                    text: text.to_owned(),
                    reply_to_message_id_hex: Some(reply_to_ref.to_owned()),
                    idempotency_key: Some(idempotency_key),
                },
            )
            .await?
        {
            AgentControlResponse::FinalSent { message_ids_hex } if !message_ids_hex.is_empty() => {
                Ok(())
            }
            AgentControlResponse::FinalSent { .. } => Err(HarnessError::UnexpectedResponse {
                method: "send_final",
                response: "empty_final_sent",
            }),
            AgentControlResponse::Error { code, .. } => Err(HarnessError::ControlRejected {
                method: "send_final",
                code,
            }),
            other => Err(unexpected_response("send_final", &other)),
        }
    }

    pub(crate) async fn subscribe(
        &self,
        account_ref: String,
    ) -> Result<mpsc::Receiver<AgentControlEvent>> {
        let stream = timeout(self.request_timeout, UnixStream::connect(&self.socket))
            .await
            .map_err(|_| HarnessError::ControlTimedOut {
                method: "subscribe_inbound",
            })??;
        let (read_half, mut write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);
        let request_id = self.next_request_id();
        let mut envelope = AgentControlEnvelope::request(
            Some(request_id.clone()),
            AgentControlRequest::SubscribeInbound {
                account_id_hex: Some(account_ref),
                group_id_hex: None,
            },
        );
        if let Some(token) = &self.auth_token {
            envelope = envelope.with_auth_token(token.clone());
        }
        write_request(
            "subscribe_inbound",
            &mut write_half,
            &envelope,
            self.request_timeout,
        )
        .await?;

        let ack = timeout(
            self.request_timeout,
            read_envelope::<_, AgentControlResponse>(&mut reader),
        )
        .await
        .map_err(|_| HarnessError::ControlTimedOut {
            method: "subscribe_inbound",
        })??
        .ok_or(HarnessError::ControlClosed)?;
        validate_response_id("subscribe_inbound", ack.id.as_deref(), &request_id)?;
        match ack.payload {
            AgentControlResponse::Ack => {}
            AgentControlResponse::Error { code, .. } => {
                return Err(HarnessError::ControlRejected {
                    method: "subscribe_inbound",
                    code,
                });
            }
            other => return Err(unexpected_response("subscribe_inbound", &other)),
        }

        let (evt_tx, evt_rx) = mpsc::channel::<AgentControlEvent>(256);
        tokio::spawn(async move {
            let _keep_write = write_half;
            loop {
                match read_envelope::<_, serde_json::Value>(&mut reader).await {
                    Ok(Some(envelope)) => {
                        match serde_json::from_value::<AgentControlEvent>(envelope.payload) {
                            Ok(event) => {
                                if evt_tx.send(event).await.is_err() {
                                    break;
                                }
                            }
                            Err(_) => {
                                debug!(
                                    target: TRACE_TARGET,
                                    method = "subscribe_inbound",
                                    error_kind = "event_decode",
                                    "dropping undecodable inbound event"
                                );
                            }
                        }
                    }
                    Ok(None) => {
                        warn!(
                            target: TRACE_TARGET,
                            method = "subscribe_inbound",
                            event = "closed",
                            "inbound subscription closed"
                        );
                        break;
                    }
                    Err(err) => {
                        let kind = HarnessError::from(err).privacy_safe_kind();
                        warn!(
                            target: TRACE_TARGET,
                            method = "subscribe_inbound",
                            error_kind = kind,
                            "inbound subscription read failed"
                        );
                        break;
                    }
                }
            }
        });

        Ok(evt_rx)
    }

    async fn call(
        &self,
        method: &'static str,
        request: AgentControlRequest,
    ) -> Result<AgentControlResponse> {
        let stream = timeout(self.request_timeout, UnixStream::connect(&self.socket))
            .await
            .map_err(|_| HarnessError::ControlTimedOut { method })??;
        let (read_half, mut write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);
        let request_id = self.next_request_id();
        let mut envelope = AgentControlEnvelope::request(Some(request_id.clone()), request);
        if let Some(token) = &self.auth_token {
            envelope = envelope.with_auth_token(token.clone());
        }
        write_request(method, &mut write_half, &envelope, self.request_timeout).await?;
        let response = timeout(
            self.request_timeout,
            read_envelope::<_, AgentControlResponse>(&mut reader),
        )
        .await
        .map_err(|_| HarnessError::ControlTimedOut { method })??
        .ok_or(HarnessError::ControlClosed)?;
        validate_response_id(method, response.id.as_deref(), &request_id)?;
        Ok(response.payload)
    }

    fn next_request_id(&self) -> String {
        let seq = self.request_seq.fetch_add(1, Ordering::Relaxed) + 1;
        format!("wn-opencode-{}-{seq}", std::process::id())
    }
}

async fn write_request<W>(
    method: &'static str,
    writer: &mut W,
    envelope: &AgentControlEnvelope<AgentControlRequest>,
    request_timeout: Duration,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    timeout(request_timeout, write_frame(writer, envelope))
        .await
        .map_err(|_| HarnessError::ControlTimedOut { method })??;
    Ok(())
}

fn validate_response_id(method: &'static str, actual: Option<&str>, expected: &str) -> Result<()> {
    if actual == Some(expected) {
        Ok(())
    } else {
        Err(HarnessError::ResponseIdMismatch { method })
    }
}

fn unexpected_response(method: &'static str, response: &AgentControlResponse) -> HarnessError {
    HarnessError::UnexpectedResponse {
        method,
        response: response_name(response),
    }
}

fn response_name(response: &AgentControlResponse) -> &'static str {
    match response {
        AgentControlResponse::Ack => "ack",
        AgentControlResponse::Error { .. } => "error",
        AgentControlResponse::AccountList { .. } => "account_list",
        AgentControlResponse::AccountCreated { .. } => "account_created",
        AgentControlResponse::KeyPackagePublished { .. } => "key_package_published",
        AgentControlResponse::ProfilePublished { .. } => "profile_published",
        AgentControlResponse::FinalSent { .. } => "final_sent",
        AgentControlResponse::DeliveryStatus { .. } => "delivery_status",
        AgentControlResponse::AppEventSent { .. } => "app_event_sent",
        AgentControlResponse::Allowlist { .. } => "allowlist",
        AgentControlResponse::GroupInfo { .. } => "group_info",
        AgentControlResponse::StreamBegun { .. } => "stream_begun",
        AgentControlResponse::StreamFinalized { .. } => "stream_finalized",
        AgentControlResponse::DebugRecordedFinals { .. } => "debug_recorded_finals",
        AgentControlResponse::MediaDownloaded { .. } => "media_downloaded",
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixListener as StdUnixListener;

    use agent_control::{AgentControlEnvelope, AgentControlRequest, AgentControlResponse};
    use tokio::net::UnixListener;

    use super::*;

    #[tokio::test]
    async fn call_rejects_mismatched_response_id() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("control.sock");
        let listener = StdUnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let listener = UnixListener::from_std(listener).unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (read_half, mut write_half) = stream.into_split();
            let mut reader = BufReader::new(read_half);
            let _request: AgentControlEnvelope<AgentControlRequest> =
                read_envelope(&mut reader).await.unwrap().unwrap();
            let response = AgentControlEnvelope::request(
                Some("wrong-response-id".to_owned()),
                AgentControlResponse::Ack,
            );
            write_frame(&mut write_half, &response).await.unwrap();
        });

        let client = ControlClient::new(socket, None, Duration::from_secs(5));
        let err = client
            .call("account_list", AgentControlRequest::AccountList)
            .await
            .unwrap_err();
        server.await.unwrap();
        assert_eq!(err.privacy_safe_kind(), "response_id_mismatch");
    }
}
