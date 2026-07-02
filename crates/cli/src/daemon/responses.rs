//! Daemon stream-response construction and subscription matching helpers.

use super::*;

pub(crate) fn app_message_record_json(
    message: marmot_app::AppMessageRecord,
    from_display_name: Option<String>,
) -> serde_json::Value {
    crate::commands::messages::message_record_json(message, from_display_name)
}

pub(crate) fn runtime_message_update_stream_response(
    update: marmot_app::RuntimeMessageUpdate,
) -> DaemonStreamResponse {
    match update {
        marmot_app::RuntimeMessageUpdate::Message(message) => message_stream_response(
            runtime_message_json(
                &message.message,
                &message.account_id_hex,
                &message.account_label,
            ),
            "MessageReceived",
        ),
        marmot_app::RuntimeMessageUpdate::AgentStreamStarted(message) => message_stream_response(
            runtime_message_json(
                &message.message,
                &message.account_id_hex,
                &message.account_label,
            ),
            "AgentStreamStarted",
        ),
    }
}

pub(crate) fn chat_stream_response(
    group: marmot_app::AppGroupRecord,
    trigger: &str,
) -> DaemonStreamResponse {
    let group_id = group.group_id_hex.clone();
    DaemonStreamResponse::ok(serde_json::json!({
        "trigger": trigger,
        "type": "chat",
        "chat": crate::group_json(group),
        "group_id": group_id,
    }))
}

pub(crate) fn group_state_stream_response(
    group: marmot_app::AppGroupRecord,
    trigger: &str,
    mls: Option<serde_json::Value>,
) -> DaemonStreamResponse {
    let group_id = group.group_id_hex.clone();
    let mut result = serde_json::json!({
        "trigger": trigger,
        "type": "group_state",
        "group": crate::group_json(group),
        "group_id": group_id,
    });
    if let Some(mls) = mls {
        result["mls"] = mls;
    }
    DaemonStreamResponse::ok(result)
}

pub(crate) fn cli_output_result(output: CliOutput) -> Result<serde_json::Value, String> {
    let value = serde_json::from_str::<serde_json::Value>(output.stdout.trim())
        .map_err(|err| format!("daemon command returned invalid JSON: {err}"))?;
    if output.code != 0 || value.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
        let message = value
            .get("error")
            .and_then(|error| error.get("message"))
            .and_then(serde_json::Value::as_str)
            .or_else(|| {
                if output.stderr.trim().is_empty() {
                    None
                } else {
                    Some(output.stderr.trim())
                }
            })
            .unwrap_or("daemon command failed");
        return Err(message.to_owned());
    }
    Ok(value
        .get("result")
        .cloned()
        .unwrap_or(serde_json::Value::Null))
}

pub(crate) fn stream_preview_fingerprint(preview: &serde_json::Value) -> String {
    let watch_id = preview
        .get("watch_id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let status = preview
        .get("status")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let text = preview
        .get("text")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let transcript_hash = preview
        .get("transcript_hash")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let error = preview
        .get("error")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    format!("{watch_id}:{status}:{text}:{transcript_hash}:{error}")
}

pub(crate) fn stream_preview_response(
    preview: serde_json::Value,
    initial: bool,
) -> DaemonStreamResponse {
    let trigger = if initial {
        "InitialStreamPreview"
    } else {
        match preview
            .get("status")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
        {
            "completed" => "StreamPreviewCompleted",
            "failed" => "StreamPreviewFailed",
            _ => "StreamPreviewUpdated",
        }
    };
    DaemonStreamResponse::ok(serde_json::json!({
        "trigger": trigger,
        "type": "stream_preview",
        "stream_preview": preview,
    }))
}

pub(crate) fn agent_stream_delta_response(delta: crate::AgentStreamDelta) -> DaemonStreamResponse {
    DaemonStreamResponse::ok(serde_json::json!({
        "trigger": "AgentStreamDelta",
        "type": "agent_stream_delta",
        "agent_stream_delta": delta,
    }))
}

pub(crate) fn agent_stream_update_response(
    update: marmot_app::AgentStreamUpdate,
    initial: bool,
) -> DaemonStreamResponse {
    match update {
        marmot_app::AgentStreamUpdate::WatchUpdated(report) => {
            let preview =
                serde_json::to_value(report).expect("stream preview serialization cannot fail");
            stream_preview_response(preview, initial)
        }
        marmot_app::AgentStreamUpdate::Delta(delta) => agent_stream_delta_response(delta),
    }
}

pub(crate) fn message_stream_response(
    message: serde_json::Value,
    trigger: &str,
) -> DaemonStreamResponse {
    DaemonStreamResponse::ok(serde_json::json!({
        "trigger": trigger,
        "type": message_stream_type(&message),
        "message": message,
    }))
}

pub(crate) fn timeline_page_stream_response(
    page: marmot_app::TimelinePage,
    trigger: &str,
    runtime: &marmot_app::MarmotAppRuntime,
    local_account_id_hex: &str,
) -> DaemonStreamResponse {
    let messages = page
        .messages
        .into_iter()
        .map(|message| {
            let mut display_name_for_account =
                |account_id: &str| runtime.display_name_for_account_id(account_id);
            crate::commands::messages::timeline_message_record_json(
                message,
                Some(local_account_id_hex),
                &mut display_name_for_account,
            )
        })
        .collect::<Vec<_>>();
    DaemonStreamResponse::ok(serde_json::json!({
        "trigger": trigger,
        "type": timeline_stream_type(trigger),
        "messages": messages,
        "has_more_before": page.has_more_before,
        "has_more_after": page.has_more_after,
    }))
}

pub(crate) fn timeline_projection_stream_response(
    update: marmot_app::RuntimeProjectionUpdate,
    runtime: &marmot_app::MarmotAppRuntime,
) -> DaemonStreamResponse {
    let local_account_id_hex = update.account_id_hex.clone();
    let changes = update
        .update
        .timeline_changes
        .into_iter()
        .map(|change| timeline_message_change_json(change, runtime, &local_account_id_hex))
        .collect::<Vec<_>>();
    let messages = update
        .update
        .timeline_messages
        .into_iter()
        .map(|message| {
            let mut display_name_for_account =
                |account_id: &str| runtime.display_name_for_account_id(account_id);
            crate::commands::messages::timeline_message_record_json(
                message,
                Some(&local_account_id_hex),
                &mut display_name_for_account,
            )
        })
        .collect::<Vec<_>>();
    DaemonStreamResponse::ok(serde_json::json!({
        "trigger": "TimelineProjectionUpdated",
        "type": "timeline_projection_updated",
        "account_id": update.account_id_hex,
        "account_label": update.account_label,
        "group_id": update.update.group_id_hex,
        "messages": messages,
        "changes": changes,
        "chat_list_row": update.update.chat_list_row,
        "chat_list_trigger": update.update.chat_list_trigger,
    }))
}

pub(crate) fn timeline_message_change_json(
    change: marmot_app::TimelineMessageChange,
    runtime: &marmot_app::MarmotAppRuntime,
    local_account_id_hex: &str,
) -> serde_json::Value {
    match change {
        marmot_app::TimelineMessageChange::Upsert { trigger, message } => {
            let mut display_name_for_account =
                |account_id: &str| runtime.display_name_for_account_id(account_id);
            serde_json::json!({
                "type": "upsert",
                "trigger": trigger,
                "message": crate::commands::messages::timeline_message_record_json(
                    *message,
                    Some(local_account_id_hex),
                    &mut display_name_for_account,
                ),
            })
        }
        marmot_app::TimelineMessageChange::Remove {
            message_id_hex,
            reason,
        } => serde_json::json!({
            "type": "remove",
            "message_id": message_id_hex,
            "reason": reason,
        }),
    }
}

pub(crate) fn timeline_stream_type(trigger: &str) -> &'static str {
    match trigger {
        "InitialTimelinePage" => "initial_timeline_page",
        "TimelineUpdated" => "timeline_updated",
        _ => "timeline",
    }
}

pub(crate) fn message_stream_type(message: &serde_json::Value) -> &'static str {
    // Agent text stream classification is derived from the inner-event tags and
    // exposed under `agent_text_stream`; prefer it so stream-final chats surface
    // as `agent_stream_final` rather than a bare `message`.
    if let Some(stream_kind) = message
        .get("agent_text_stream")
        .and_then(|stream| stream.get("kind"))
        .and_then(serde_json::Value::as_str)
    {
        return match stream_kind {
            "start" => "agent_stream_start",
            "final" => "agent_stream_final",
            _ => "message",
        };
    }
    let kind = message.get("kind").and_then(serde_json::Value::as_u64);
    let has_imeta = message
        .get("tags")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|tags| {
            tags.iter().any(|tag| {
                tag.as_array()
                    .and_then(|values| values.first())
                    .and_then(serde_json::Value::as_str)
                    == Some("imeta")
            })
        });
    match kind {
        Some(MARMOT_APP_EVENT_KIND_REACTION) => "reaction",
        Some(MARMOT_APP_EVENT_KIND_DELETE) => "message_delete",
        Some(MARMOT_APP_EVENT_KIND_CHAT) if has_imeta => "media",
        _ => "message",
    }
}

pub(crate) fn stream_response_matches_subscription(
    response: &DaemonStreamResponse,
    group_id: Option<&str>,
    account_id: &str,
) -> bool {
    let Some(result) = &response.result else {
        return true;
    };
    match result.get("type").and_then(serde_json::Value::as_str) {
        Some("message")
        | Some("reaction")
        | Some("message_delete")
        | Some("media")
        | Some("agent_stream_start")
        | Some("agent_stream_final") => {
            let Some(message) = result.get("message") else {
                return false;
            };
            value_matches_group_and_account(message, group_id, account_id)
        }
        Some("stream_preview") => {
            let Some(preview) = result.get("stream_preview") else {
                return false;
            };
            value_matches_group_and_account(preview, group_id, account_id)
        }
        Some("agent_stream_delta") => {
            let Some(delta) = result.get("agent_stream_delta") else {
                return false;
            };
            value_matches_group_and_account(delta, group_id, account_id)
        }
        _ => false,
    }
}

pub(crate) fn value_matches_group_and_account(
    value: &serde_json::Value,
    group_id: Option<&str>,
    account_id: &str,
) -> bool {
    group_id.is_none_or(|group_id| {
        value.get("group_id").and_then(serde_json::Value::as_str) == Some(group_id)
    }) && value
        .get("account")
        .or_else(|| value.get("account_id"))
        .and_then(serde_json::Value::as_str)
        .is_none_or(|event_account| event_account == account_id)
}

pub(crate) fn mark_stream_response_seen(
    response: &DaemonStreamResponse,
    seen_messages: &mut BoundedMessageSubscriptionIds,
    seen_stream_previews: &mut BoundedMessageSubscriptionIds,
) -> bool {
    let Some(result) = &response.result else {
        return true;
    };
    match result.get("type").and_then(serde_json::Value::as_str) {
        Some("message")
        | Some("reaction")
        | Some("message_delete")
        | Some("media")
        | Some("agent_stream_start")
        | Some("agent_stream_final") => result
            .get("message")
            .and_then(|message| message.get("message_id"))
            .and_then(serde_json::Value::as_str)
            .is_none_or(|message_id| seen_messages.insert(message_id.to_owned())),
        Some("stream_preview") => result
            .get("stream_preview")
            .map(stream_preview_fingerprint)
            .is_none_or(|fingerprint| seen_stream_previews.insert(fingerprint)),
        Some("agent_stream_delta") => true,
        _ => true,
    }
}

pub(crate) fn runtime_message_json(
    message: &marmot_app::ReceivedMessage,
    account_id_hex: &str,
    account_label: &str,
) -> serde_json::Value {
    let now = unix_now();
    let is_own_sender = message.sender == account_id_hex || message.sender == account_label;
    let from_display_name = if is_own_sender {
        None
    } else {
        message.sender_display_name.clone()
    };
    let mut value = serde_json::json!({
        "account_id": account_id_hex,
        "message_id": message.message_id_hex,
        "direction": if is_own_sender { "sent" } else { "received" },
        "from": message.sender,
        "from_display_name": from_display_name,
        "group_id": hex::encode(message.group_id.as_slice()),
        "plaintext": message.plaintext,
        "kind": message.kind,
        "tags": message.tags,
        "recorded_at": message.recorded_at,
        "received_at": now,
    });
    if let Some(agent_text_stream) =
        crate::agent_text_stream_payload_value(message.kind, &message.tags, &message.plaintext)
    {
        value["agent_text_stream"] = agent_text_stream;
    }
    value
}
