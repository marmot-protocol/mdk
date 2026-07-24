//! Per-connection accept loop, authorization, and control-request dispatch.

use agent_control::{
    AgentControlEnvelope, AgentControlRequest, AgentControlResponse, read_envelope, write_frame,
};
use serde::Serialize;
use tokio::io::{AsyncWrite, BufReader};
use tokio::net::UnixStream;

use crate::error::ConnectorError;
use crate::socket::current_effective_uid;
use crate::validation::{auth_token_matches, unsupported_request_message};
use crate::{
    AgentConnector, CONTROL_OPERATION_TIMEOUT, with_control_operation_timeout,
    with_control_operation_timeout_after,
};

pub(crate) fn try_acquire_inbound_subscription(
    request: &AgentControlRequest,
    limiter: &std::sync::Arc<tokio::sync::Semaphore>,
) -> Result<Option<tokio::sync::OwnedSemaphorePermit>, ()> {
    if !matches!(request, AgentControlRequest::SubscribeInbound { .. }) {
        return Ok(None);
    }
    std::sync::Arc::clone(limiter)
        .try_acquire_owned()
        .map(Some)
        .map_err(|_| ())
}

pub(crate) async fn write_control_frame<W, T>(
    writer: &mut W,
    message: &T,
) -> Result<(), ConnectorError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    write_control_frame_with_timeout(writer, message, CONTROL_OPERATION_TIMEOUT).await
}

pub(crate) async fn write_control_frame_with_timeout<W, T>(
    writer: &mut W,
    message: &T,
    timeout_after: std::time::Duration,
) -> Result<(), ConnectorError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    with_control_operation_timeout_after(
        "control_frame_write",
        timeout_after,
        write_frame(writer, message),
    )
    .await??;
    Ok(())
}

impl AgentConnector {
    pub(crate) async fn handle_connection(&self, stream: UnixStream) -> Result<(), ConnectorError> {
        let peer_uid = stream.peer_cred()?.uid();
        let peer_authorized_by_uid = peer_uid == current_effective_uid();
        let (read_half, mut write_half) = tokio::io::split(stream);
        let mut reader = BufReader::new(read_half);
        let Some(request): Option<AgentControlEnvelope<AgentControlRequest>> =
            with_control_operation_timeout(
                "initial_control_frame_read",
                read_envelope(&mut reader),
            )
            .await??
        else {
            return Ok(());
        };
        if let Err(err) =
            self.authorize_control_request(peer_authorized_by_uid, request.auth_token.as_deref())
        {
            let response = AgentControlEnvelope::new(
                request.id,
                self.error_response("authorize_control_request", &err),
            );
            write_control_frame(&mut write_half, &response).await?;
            return Ok(());
        }
        let subscription_permit =
            match try_acquire_inbound_subscription(&request.payload, &self.subscription_limiter) {
                Ok(permit) => permit,
                Err(()) => {
                    let response = AgentControlEnvelope::new(
                        request.id,
                        AgentControlResponse::Error {
                            code: "server_busy".to_owned(),
                            message: "agent connector subscription capacity is busy".to_owned(),
                        },
                    );
                    write_control_frame(&mut write_half, &response).await?;
                    return Ok(());
                }
            };
        if let AgentControlRequest::SubscribeInbound {
            account_id_hex,
            group_id_hex,
        } = request.payload
        {
            let _subscription_permit = subscription_permit
                .expect("SubscribeInbound admission must hold a subscription permit");
            return self
                .stream_inbound_events(
                    request.id,
                    account_id_hex,
                    group_id_hex,
                    &mut reader,
                    &mut write_half,
                )
                .await;
        }
        let envelope_request_id = request.id.clone();
        let response = match self
            .handle_request(envelope_request_id.as_deref(), request.payload)
            .await
        {
            Ok(response) => response,
            Err(err) => self.error_response("handle_connection", &err),
        };
        let response = AgentControlEnvelope::new(request.id, response);
        write_control_frame(&mut write_half, &response).await?;
        Ok(())
    }

    pub(crate) fn error_response(
        &self,
        method: &'static str,
        err: &ConnectorError,
    ) -> AgentControlResponse {
        tracing::warn!(
            target: "agent_connector",
            method = method,
            error_code = err.privacy_safe_code(),
            "control request failed"
        );
        AgentControlResponse::Error {
            code: err.code().to_owned(),
            message: err.client_message().to_owned(),
        }
    }

    fn authorize_control_request(
        &self,
        peer_authorized_by_uid: bool,
        auth_token: Option<&str>,
    ) -> Result<(), ConnectorError> {
        // A configured token deliberately replaces peer-UID authorization and
        // grants the whole local control API. There are no per-command or
        // per-account scopes: deployments that do not share one trust boundary
        // must use separate connector instances, sockets, homes, and tokens.
        if let Some(expected) = self.auth_token.as_deref() {
            if auth_token_matches(expected, auth_token) {
                return Ok(());
            }
            return Err(ConnectorError::Unauthorized);
        }

        if peer_authorized_by_uid {
            Ok(())
        } else {
            Err(ConnectorError::Unauthorized)
        }
    }

    async fn handle_request(
        &self,
        request_id: Option<&str>,
        request: AgentControlRequest,
    ) -> Result<AgentControlResponse, ConnectorError> {
        match request {
            AgentControlRequest::AccountList => self.account_list_response(),
            AgentControlRequest::AllowlistList { account_id_hex } => {
                self.allowlist_response(&account_id_hex)
            }
            AgentControlRequest::AllowlistAdd {
                account_id_hex,
                welcomer_account_id_hex,
            } => self.allowlist_add_response(&account_id_hex, &welcomer_account_id_hex),
            AgentControlRequest::AllowlistRemove {
                account_id_hex,
                welcomer_account_id_hex,
            } => self.allowlist_remove_response(&account_id_hex, &welcomer_account_id_hex),
            AgentControlRequest::GroupInfo {
                account_id_hex,
                group_id_hex,
            } => {
                self.group_info_response(&account_id_hex, &group_id_hex)
                    .await
            }
            AgentControlRequest::DebugInjectInbound {
                account_id_hex,
                group_id_hex,
                message_id_hex,
                sender_account_id_hex,
                text,
            } => self.debug_inject_inbound_response(
                &account_id_hex,
                &group_id_hex,
                &message_id_hex,
                &sender_account_id_hex,
                text,
            ),
            AgentControlRequest::DebugRecordedFinals => self.debug_recorded_finals_response(),
            AgentControlRequest::SendFinal {
                account_id_hex,
                group_id_hex,
                text,
                reply_to_message_id_hex,
                idempotency_key,
            } => {
                self.send_final_response(
                    &account_id_hex,
                    &group_id_hex,
                    text,
                    reply_to_message_id_hex,
                    idempotency_key,
                )
                .await
            }
            AgentControlRequest::DeliveryStatus { idempotency_key } => {
                Ok(self.delivery_status_response(&idempotency_key))
            }
            AgentControlRequest::DeleteMessage {
                account_id_hex,
                group_id_hex,
                target_message_id_hex,
            } => {
                self.delete_message_response(&account_id_hex, &group_id_hex, &target_message_id_hex)
                    .await
            }
            AgentControlRequest::StreamBegin {
                account_id_hex,
                group_id_hex,
                stream_id_hex,
                parent_message_id_hex,
                quic_candidates,
            } => {
                self.stream_begin_response(
                    request_id,
                    &account_id_hex,
                    &group_id_hex,
                    stream_id_hex,
                    parent_message_id_hex,
                    quic_candidates,
                )
                .await
            }
            AgentControlRequest::StreamAppend {
                stream_id_hex,
                stream_capability,
                append_text,
            } => {
                self.stream_append_response(&stream_id_hex, &stream_capability, append_text)
                    .await
            }
            AgentControlRequest::StreamStatus {
                stream_id_hex,
                stream_capability,
                status,
            } => {
                self.stream_status_response(&stream_id_hex, &stream_capability, status)
                    .await
            }
            AgentControlRequest::StreamProgress {
                stream_id_hex,
                stream_capability,
                text,
            } => {
                self.stream_progress_response(&stream_id_hex, &stream_capability, text)
                    .await
            }
            AgentControlRequest::StreamFinalize {
                stream_id_hex,
                stream_capability,
                final_text,
                transcript_hash_hex,
                chunk_count,
                idempotency_key,
            } => {
                self.stream_finalize_response(
                    &stream_id_hex,
                    &stream_capability,
                    final_text,
                    &transcript_hash_hex,
                    chunk_count,
                    idempotency_key,
                )
                .await
            }
            AgentControlRequest::StreamCancel {
                stream_id_hex,
                stream_capability,
                ..
            } => self.stream_cancel_response(&stream_id_hex, &stream_capability),
            AgentControlRequest::AccountCreate {
                label,
                publish_key_package,
            } => {
                self.create_account_response(label, publish_key_package)
                    .await
            }
            AgentControlRequest::AccountPublishKeyPackage { account_id_hex } => {
                let account = self.local_account_for_account_id(&account_id_hex)?;
                let key_package_bytes = self.runtime.publish_key_package(&account.label).await?;
                Ok(AgentControlResponse::KeyPackagePublished {
                    account_id_hex,
                    key_package_bytes,
                })
            }
            AgentControlRequest::AccountPublishProfile {
                account_id_hex,
                name,
                display_name,
            } => {
                self.publish_profile_response(&account_id_hex, name, display_name)
                    .await
            }
            AgentControlRequest::SendAgentActivity {
                account_id_hex,
                group_id_hex,
                status,
                text,
                reply_to_message_id_hex,
                extra,
            } => {
                self.send_agent_activity_response(
                    &account_id_hex,
                    &group_id_hex,
                    status,
                    text,
                    reply_to_message_id_hex,
                    extra,
                )
                .await
            }
            AgentControlRequest::SendAgentOperationEvent {
                account_id_hex,
                group_id_hex,
                event_type,
                status,
                operation_id,
                run_id,
                turn_id,
                name,
                text,
                preview,
                details,
                sequence,
                ok,
                duration_ms,
                reply_to_message_id_hex,
            } => {
                self.send_agent_operation_event_response(
                    &account_id_hex,
                    &group_id_hex,
                    event_type,
                    status,
                    operation_id,
                    run_id,
                    turn_id,
                    name,
                    text,
                    preview,
                    details,
                    sequence,
                    ok,
                    duration_ms,
                    reply_to_message_id_hex,
                )
                .await
            }
            AgentControlRequest::SendGroupSystemEvent {
                account_id_hex,
                group_id_hex,
                system_type,
                text,
                data,
            } => {
                self.send_group_system_event_response(
                    &account_id_hex,
                    &group_id_hex,
                    system_type,
                    text,
                    data,
                )
                .await
            }
            AgentControlRequest::SendMedia {
                account_id_hex,
                group_id_hex,
                attachments,
                caption,
            } => {
                self.send_media_response(&account_id_hex, &group_id_hex, attachments, caption)
                    .await
            }
            AgentControlRequest::DownloadMedia {
                account_id_hex,
                group_id_hex,
                media,
            } => {
                self.download_media_response(&account_id_hex, &group_id_hex, media)
                    .await
            }
            other => Ok(AgentControlResponse::Error {
                code: "unsupported_request".to_owned(),
                message: unsupported_request_message(&other).to_owned(),
            }),
        }
    }
}
