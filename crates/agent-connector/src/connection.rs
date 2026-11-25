//! Per-connection accept loop, authorization, and control-request dispatch.

use agent_control::{
    AGENT_CONTROL_PROTOCOL_V2, AgentControlEnvelope, AgentControlError, AgentControlRequest,
    AgentControlResponse, decode_envelope, read_frame_bytes, write_frame,
};
use serde::Serialize;
use tokio::io::{AsyncWrite, BufReader};
use tokio::net::UnixStream;

use crate::account::ProfileUpdateFields;
use crate::error::ConnectorError;
use crate::relays::RelayListEdit;
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

/// Longest request `id` a rejection echoes. Real ids are short; this keeps a
/// rejection of an oversized frame well inside the frame limit.
const MAX_ECHOED_REQUEST_ID_BYTES: usize = 256;

/// Why the first frame on a connection could not become a request, as the
/// `error` response reports it. A message never quotes a value from the frame;
/// it names at most a field of the request schema.
#[derive(Debug, PartialEq, Eq)]
struct RejectedFrame {
    id: Option<String>,
    code: &'static str,
    message: String,
}

impl RejectedFrame {
    fn invalid(id: Option<String>, message: impl Into<String>) -> Self {
        Self {
            id,
            code: "invalid_request",
            message: message.into(),
        }
    }

    /// The frame could not be read as one line: empty or oversized.
    fn unreadable(err: &AgentControlError) -> Self {
        Self::invalid(
            None,
            match err {
                AgentControlError::FrameTooLarge(_) => "control frame exceeds the size limit",
                AgentControlError::EmptyFrame => "control frame is empty",
                _ => "control frame is not valid JSON",
            },
        )
    }

    /// Explain why the typed decode refused `frame` with `err`. This never
    /// admits a request: it only chooses the error the client gets.
    fn explain(raw: &[u8], err: &AgentControlError) -> Self {
        let frame: serde_json::Value = match agent_control::decode_frame(raw) {
            Ok(frame) => frame,
            Err(err) => return Self::unreadable(&err),
        };
        let duplicate = schema_field(err, "duplicate field");
        // With a repeated `id` no single value is the client's id, whichever
        // duplicate the typed decode happened to report.
        let id = (top_level_key_count(raw, "id") == 1)
            .then(|| frame.get("id").and_then(serde_json::Value::as_str))
            .flatten()
            .filter(|id| id.len() <= MAX_ECHOED_REQUEST_ID_BYTES)
            .map(str::to_owned);
        let Some(fields) = frame.as_object() else {
            return Self::invalid(id, "control frame is not a JSON object");
        };
        if let Some(field) = duplicate {
            return Self::invalid(id, format!("duplicate field `{field}`"));
        }
        if fields
            .get("marmot_agent_control")
            .and_then(serde_json::Value::as_str)
            != Some(AGENT_CONTROL_PROTOCOL_V2)
        {
            return Self {
                id,
                code: "unsupported_protocol",
                message: "marmot_agent_control must be \"marmot.agent-control.v2\"".to_owned(),
            };
        }
        if !fields.get("type").is_some_and(serde_json::Value::is_string) {
            return Self::invalid(id, "missing field `type`");
        }
        // Decode the `type` on its own, so a known type with a bad field value
        // (which serde also reports as an unknown variant) stays invalid.
        let type_only = serde_json::json!({ "type": fields["type"] });
        if serde_json::from_value::<AgentControlRequest>(type_only)
            .is_err_and(|err| err.to_string().starts_with("unknown variant"))
        {
            return Self {
                id,
                code: "unknown_request",
                message: "unknown request type".to_owned(),
            };
        }
        match schema_field(err, "missing field") {
            Some(field) => Self::invalid(id, format!("missing field `{field}`")),
            None => Self::invalid(id, "a field has a value its request type does not accept"),
        }
    }
}

/// How many times `key` appears among the top-level keys of the JSON object in
/// `raw`. A `serde_json::Value` keeps only the last of repeated keys, so the
/// keys are counted as the object is read.
fn top_level_key_count(raw: &[u8], key: &str) -> usize {
    struct Count<'a>(&'a str);

    impl<'de> serde::de::DeserializeSeed<'de> for Count<'_> {
        type Value = usize;

        fn deserialize<D: serde::Deserializer<'de>>(
            self,
            deserializer: D,
        ) -> Result<usize, D::Error> {
            deserializer.deserialize_map(self)
        }
    }

    impl<'de> serde::de::Visitor<'de> for Count<'_> {
        type Value = usize;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a JSON object")
        }

        fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<usize, A::Error> {
            let mut count = 0;
            while let Some(name) = map.next_key::<std::borrow::Cow<'de, str>>()? {
                count += usize::from(name == self.0);
                map.next_value::<serde::de::IgnoredAny>()?;
            }
            Ok(count)
        }
    }

    let mut deserializer = serde_json::Deserializer::from_slice(raw);
    serde::de::DeserializeSeed::deserialize(Count(key), &mut deserializer).unwrap_or(0)
}

/// The field named in a serde error such as "missing field `account_id_hex`",
/// when it reads as a schema field name. serde names schema fields in missing
/// and duplicate field errors, never request values.
fn schema_field(err: &AgentControlError, kind: &str) -> Option<String> {
    let AgentControlError::Json(err) = err else {
        return None;
    };
    let text = err.to_string();
    let name = text
        .strip_prefix(kind)?
        .strip_prefix(" `")?
        .split('`')
        .next()?;
    (!name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'))
    .then(|| name.to_owned())
}

impl AgentConnector {
    pub(crate) async fn handle_connection(&self, stream: UnixStream) -> Result<(), ConnectorError> {
        let peer_uid = stream.peer_cred()?.uid();
        let peer_authorized_by_uid = peer_uid == current_effective_uid();
        let (read_half, mut write_half) = tokio::io::split(stream);
        let mut reader = BufReader::new(read_half);
        let frame = match with_control_operation_timeout(
            "initial_control_frame_read",
            read_frame_bytes(&mut reader),
        )
        .await?
        {
            Ok(Some(frame)) => Ok(frame),
            Ok(None) => return Ok(()),
            Err(AgentControlError::Io(err)) => return Err(AgentControlError::Io(err).into()),
            Err(err) => Err(RejectedFrame::unreadable(&err)),
        };
        // Only the typed decode decides what runs. A frame it refuses is read
        // again, loosely, only to explain the refusal.
        let request = match frame.and_then(|frame| {
            decode_envelope::<AgentControlRequest>(&frame)
                .map_err(|err| RejectedFrame::explain(&frame, &err))
        }) {
            Ok(request) => request,
            Err(rejected) => {
                // Answer a request that cannot be served instead of closing
                // silently, so a client can tell it from a crash (#2242).
                tracing::debug!(
                    target: "agent_connector",
                    method = "handle_connection",
                    error_code = rejected.code,
                    "rejected control frame"
                );
                let response = AgentControlEnvelope::new(
                    rejected.id,
                    AgentControlResponse::Error {
                        code: rejected.code.to_owned(),
                        message: rejected.message,
                        retryable: false,
                    },
                );
                write_control_frame(&mut write_half, &response).await?;
                return Ok(());
            }
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
                            retryable: true,
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
        let mut lease =
            crate::attachments::AttachmentReplyLease::new(self.runtime.clone(), &response);
        let response = AgentControlEnvelope::new(request.id, response);
        write_control_frame(&mut write_half, &response).await?;
        lease.delivered();
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
            retryable: err.retryable(),
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
        // Classify only reviewed commands; arguments and response contents never enter analytics.
        let operation = match &request {
            AgentControlRequest::AccountCreate { .. } => Some("bootstrap"),
            AgentControlRequest::AccountList
            | AgentControlRequest::TimelineMessageGet { .. }
            | AgentControlRequest::TimelineList { .. }
            | AgentControlRequest::AttachmentGet { .. }
            | AgentControlRequest::AccountProfileLookup { .. }
            | AgentControlRequest::AccountRelayLists { .. }
            | AgentControlRequest::DiagnosticStatus { .. }
            | AgentControlRequest::GroupInfo { .. }
            | AgentControlRequest::GroupAdmin {
                promote: false,
                add: false,
                remove: false,
                ..
            }
            | AgentControlRequest::MaintenanceStatus { .. }
            | AgentControlRequest::KeyPackageMaintenanceStatus { .. }
            | AgentControlRequest::MaintenanceGetPolicy { .. }
            | AgentControlRequest::AllowlistList { .. }
            | AgentControlRequest::InvitePolicyGet { .. } => Some("control_read"),
            AgentControlRequest::SendFinal { .. }
            | AgentControlRequest::DeleteMessage { .. }
            | AgentControlRequest::EditMessage { .. }
            | AgentControlRequest::SendReaction { .. }
            | AgentControlRequest::RemoveReaction { .. }
            | AgentControlRequest::AccountPublishKeyPackage { .. }
            | AgentControlRequest::AccountPublishProfile { .. }
            | AgentControlRequest::AccountRelayListAdd { .. }
            | AgentControlRequest::AccountRelayListRemove { .. }
            | AgentControlRequest::GroupProfileUpdate { .. }
            | AgentControlRequest::GroupAdmin { .. }
            | AgentControlRequest::SendMedia { .. }
            | AgentControlRequest::DownloadMedia { .. }
            | AgentControlRequest::DownloadAttachment { .. }
            | AgentControlRequest::ReleaseAttachment { .. }
            | AgentControlRequest::MaintenanceScheduleSelfUpdate { .. }
            | AgentControlRequest::MaintenanceSetPolicy { .. }
            | AgentControlRequest::MaintenancePause { .. }
            | AgentControlRequest::MaintenanceResume { .. }
            | AgentControlRequest::MaintenanceRun { .. }
            | AgentControlRequest::AllowlistAdd { .. }
            | AgentControlRequest::AllowlistRemove { .. }
            | AgentControlRequest::InvitePolicySet { .. } => Some("control_write"),
            _ => None,
        };
        let observation = operation.and_then(|operation| {
            self.runtime.begin_product_operation(
                marmot_app::ProductFamily::Agent,
                operation,
                marmot_app::ProductUnit::Attempt,
            )
        });
        let result = self.handle_request_unobserved(request_id, request).await;
        if let Some(observation) = observation {
            observation.finish(if result.is_ok() { "success" } else { "failure" });
        }
        result
    }

    async fn handle_request_unobserved(
        &self,
        request_id: Option<&str>,
        request: AgentControlRequest,
    ) -> Result<AgentControlResponse, ConnectorError> {
        match request {
            AgentControlRequest::AccountList => self.account_list_response(),
            AgentControlRequest::TimelineMessageGet {
                account_id_hex,
                group_id_hex,
                message_id_hex,
            } => self.timeline_message_response(&account_id_hex, &group_id_hex, &message_id_hex),
            AgentControlRequest::TimelineList {
                account_id_hex,
                group_id_hex,
                before,
                after,
                before_inclusive,
                limit,
            } => self.timeline_list_response(
                request_id,
                &account_id_hex,
                &group_id_hex,
                before,
                after,
                before_inclusive,
                limit,
            ),
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
            AgentControlRequest::InvitePolicyGet { account_id_hex } => {
                self.invite_policy_response(&account_id_hex)
            }
            AgentControlRequest::InvitePolicySet {
                account_id_hex,
                policy,
            } => self.invite_policy_set_response(&account_id_hex, policy),
            AgentControlRequest::DiagnosticStatus {
                account_id_hex,
                home_group_id_hex,
            } => {
                self.diagnostic_status_response(
                    account_id_hex.as_deref(),
                    home_group_id_hex.as_deref(),
                )
                .await
            }
            AgentControlRequest::GroupCreateCapabilities => {
                Ok(AgentControlResponse::GroupCreateCapabilities {
                    initial_admins: true,
                })
            }
            AgentControlRequest::GroupCreateWithAdmins {
                account_id_hex,
                name,
                members,
                admins,
                description,
                relays,
            } => {
                self.create_group_response(
                    &account_id_hex,
                    name,
                    members,
                    admins,
                    description,
                    relays,
                )
                .await
            }
            AgentControlRequest::GroupCreate {
                account_id_hex,
                name,
                members,
                description,
                relays,
            } => {
                self.create_group_response(
                    &account_id_hex,
                    name,
                    members,
                    Vec::new(),
                    description,
                    relays,
                )
                .await
            }
            AgentControlRequest::GroupLeave {
                account_id_hex,
                group_id_hex,
            } => {
                self.leave_group_response(&account_id_hex, &group_id_hex)
                    .await
            }
            AgentControlRequest::GroupAdmin {
                account_id_hex,
                group_id_hex,
                member_id_hex,
                promote,
                add,
                remove,
            } => {
                self.group_admin_response(
                    &account_id_hex,
                    &group_id_hex,
                    &member_id_hex,
                    crate::account::GroupAdminChange {
                        promote,
                        add,
                        remove,
                    },
                )
                .await
            }
            AgentControlRequest::GroupInfo {
                account_id_hex,
                group_id_hex,
            } => {
                self.group_info_response(&account_id_hex, &group_id_hex)
                    .await
            }
            AgentControlRequest::GroupProfileUpdate {
                account_id_hex,
                group_id_hex,
                name,
                description,
            } => {
                self.update_group_profile_response(
                    &account_id_hex,
                    &group_id_hex,
                    name,
                    description,
                )
                .await
            }
            AgentControlRequest::MaintenanceStatus {
                account_id_hex,
                group_id_hex,
            } => {
                self.maintenance_status_response(&account_id_hex, &group_id_hex)
                    .await
            }
            AgentControlRequest::KeyPackageMaintenanceStatus { account_id_hex } => {
                self.key_package_maintenance_status_response(&account_id_hex)
                    .await
            }
            AgentControlRequest::MaintenanceScheduleSelfUpdate {
                account_id_hex,
                group_id_hex,
            } => {
                self.maintenance_schedule_response(&account_id_hex, &group_id_hex)
                    .await
            }
            AgentControlRequest::MaintenanceGetPolicy { account_id_hex } => {
                self.maintenance_policy_response(&account_id_hex).await
            }
            AgentControlRequest::MaintenanceSetPolicy {
                account_id_hex,
                enabled_for_new_groups,
            } => {
                self.set_maintenance_policy_response(&account_id_hex, enabled_for_new_groups)
                    .await
            }
            AgentControlRequest::MaintenancePause { account_id_hex } => {
                self.pause_maintenance_response(&account_id_hex).await
            }
            AgentControlRequest::MaintenanceResume { account_id_hex } => {
                self.resume_maintenance_response(&account_id_hex).await
            }
            AgentControlRequest::MaintenanceRun { account_id_hex } => {
                self.run_maintenance_response(&account_id_hex).await
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
            AgentControlRequest::DeleteMessage {
                account_id_hex,
                group_id_hex,
                target_message_id_hex,
            } => {
                self.delete_message_response(&account_id_hex, &group_id_hex, &target_message_id_hex)
                    .await
            }
            AgentControlRequest::EditMessage {
                account_id_hex,
                group_id_hex,
                target_message_id_hex,
                text,
            } => {
                self.edit_message_response(
                    &account_id_hex,
                    &group_id_hex,
                    &target_message_id_hex,
                    &text,
                )
                .await
            }
            AgentControlRequest::SendReaction {
                account_id_hex,
                group_id_hex,
                target_message_id_hex,
                emoji,
            } => {
                self.send_reaction_response(
                    &account_id_hex,
                    &group_id_hex,
                    &target_message_id_hex,
                    &emoji,
                )
                .await
            }
            AgentControlRequest::RemoveReaction {
                account_id_hex,
                group_id_hex,
                target_message_id_hex,
                emoji,
            } => {
                self.remove_reaction_response(
                    &account_id_hex,
                    &group_id_hex,
                    &target_message_id_hex,
                    emoji.as_deref(),
                )
                .await
            }
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
                about,
                picture,
                nip05,
                lud16,
            } => {
                self.publish_profile_response(
                    &account_id_hex,
                    name,
                    display_name,
                    ProfileUpdateFields {
                        about,
                        picture,
                        nip05,
                        lud16,
                    },
                )
                .await
            }
            AgentControlRequest::AccountProfileLookup { account_id_hex } => {
                self.profile_lookup_response(&account_id_hex).await
            }
            AgentControlRequest::AccountRelayLists { account_id_hex } => {
                self.relay_lists_response(&account_id_hex)
            }
            AgentControlRequest::AccountRelayListAdd {
                account_id_hex,
                relay_type,
                url,
                direction,
            } => {
                self.relay_list_edit_response(RelayListEdit {
                    account_id_hex,
                    relay_type,
                    url,
                    direction,
                    add: true,
                })
                .await
            }
            AgentControlRequest::AccountRelayListRemove {
                account_id_hex,
                relay_type,
                url,
                direction,
            } => {
                self.relay_list_edit_response(RelayListEdit {
                    account_id_hex,
                    relay_type,
                    url,
                    direction,
                    add: false,
                })
                .await
            }
            // MDK no longer builds the old shape of kinds 1201 and 1202
            // (marmot-agents D-051). The old connectors that still ask for
            // them are told so and publish nothing.
            AgentControlRequest::SendAgentActivity { .. }
            | AgentControlRequest::SendAgentOperationEvent { .. } => {
                Err(ConnectorError::RetiredAgentEvent)
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
                reply_to_message_id_hex,
                idempotency_key,
            } => {
                self.send_media_response(
                    &account_id_hex,
                    &group_id_hex,
                    attachments,
                    caption,
                    reply_to_message_id_hex,
                    idempotency_key,
                )
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
            AgentControlRequest::AttachmentGet {
                account_id_hex,
                group_id_hex,
                message_id_hex,
                attachment_index,
            } => {
                with_control_operation_timeout(
                    "attachment_get",
                    self.attachment_response(
                        &account_id_hex,
                        &group_id_hex,
                        &message_id_hex,
                        attachment_index,
                        false,
                    ),
                )
                .await?
            }
            AgentControlRequest::DownloadAttachment {
                account_id_hex,
                group_id_hex,
                message_id_hex,
                attachment_index,
            } => {
                with_control_operation_timeout(
                    "download_attachment",
                    self.attachment_response(
                        &account_id_hex,
                        &group_id_hex,
                        &message_id_hex,
                        attachment_index,
                        true,
                    ),
                )
                .await?
            }
            AgentControlRequest::ReleaseAttachment { lease } => {
                with_control_operation_timeout(
                    "release_attachment",
                    self.runtime.release_attachment_handoff(&lease),
                )
                .await
                .map_err(|_| ConnectorError::AttachmentReleaseFailed)?
                .map_err(|error| match error {
                    marmot_app::AppError::Io(_) | marmot_app::AppError::BlockingTask(_) => {
                        ConnectorError::AttachmentReleaseFailed
                    }
                    other => ConnectorError::App(other),
                })?;
                Ok(AgentControlResponse::AttachmentReleased)
            }
            other => Ok(AgentControlResponse::Error {
                code: "unsupported_request".to_owned(),
                message: unsupported_request_message(&other).to_owned(),
                retryable: false,
            }),
        }
    }
}
