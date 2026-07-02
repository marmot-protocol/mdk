//! `messages` command namespace handlers (incl. the `timeline` subgroup) and message output helpers.

use std::collections::HashMap;

use cgka_traits::{
    GroupId,
    app_event::{
        GROUP_SYSTEM_TYPE_ADMIN_ADDED, GROUP_SYSTEM_TYPE_ADMIN_REMOVED,
        GROUP_SYSTEM_TYPE_GROUP_AVATAR_CHANGED, GROUP_SYSTEM_TYPE_GROUP_RENAMED,
        GROUP_SYSTEM_TYPE_MEMBER_ADDED, GROUP_SYSTEM_TYPE_MEMBER_LEFT,
        GROUP_SYSTEM_TYPE_MEMBER_REMOVED, MARMOT_APP_EVENT_KIND_GROUP_SYSTEM,
    },
};
use marmot_account::AccountHome;
use marmot_app::{
    AppMessageQuery, AppMessageRecord, MarmotApp, MarmotAppRuntime, TimelineMessageQuery,
    TimelineMessageRecord, TimelinePage, TimelinePagination, group_system_event_from_message,
};
use serde_json::{Value, json};

use crate::{
    CommandOutput, DmError, MessageCommand, MessageTimelineCommand,
    agent_text_stream_payload_value, display_name_for_sender, ensure_local_signing,
    normalize_group_id_hex, npub_for_account_id, resolve_account,
};

fn message_target_and_text(
    group_flag: Option<String>,
    mut args: Vec<String>,
) -> Result<(String, Vec<String>), DmError> {
    if let Some(group) = group_flag {
        return Ok((group, args));
    }
    if args.is_empty() {
        return Err(DmError::MissingGroupId);
    }
    let group = args.remove(0);
    Ok((group, args))
}

pub(crate) async fn message_command(
    account_home: &AccountHome,
    app: &MarmotApp,
    command: MessageCommand,
    account_flag: Option<String>,
) -> Result<CommandOutput, DmError> {
    let runtime = app.runtime();
    message_command_with_runtime(account_home, app, &runtime, command, account_flag).await
}

pub(crate) async fn message_command_with_runtime(
    account_home: &AccountHome,
    app: &MarmotApp,
    runtime: &MarmotAppRuntime,
    command: MessageCommand,
    account_flag: Option<String>,
) -> Result<CommandOutput, DmError> {
    match command {
        MessageCommand::Send { group_flag, args } => {
            let (group, text) = message_target_and_text(group_flag, args)?;
            if text.is_empty() {
                return Err(DmError::EmptyMessage);
            }
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id_hex = normalize_group_id_hex(&group)?;
            let group_id = GroupId::new(hex::decode(&group_id_hex)?);
            let payload = text.join(" ");
            let summary = runtime
                .send_message(&account.label, &group_id, payload.into_bytes())
                .await?;
            Ok(CommandOutput {
                plain: format!("sent message published={}", summary.published),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex)?,
                    "group_id": hex::encode(group_id.as_slice()),
                    "published": summary.published,
                    "message_ids": summary.message_ids,
                }),
            })
        }
        MessageCommand::Delete {
            group_id,
            message_id,
        } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id = GroupId::new(hex::decode(normalize_group_id_hex(&group_id)?)?);
            let summary = runtime
                .delete_message(&account.label, &group_id, &message_id)
                .await?;
            Ok(CommandOutput {
                plain: format!(
                    "deleted message {message_id} published={}",
                    summary.published
                ),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex)?,
                    "group_id": hex::encode(group_id.as_slice()),
                    "target_message_id": message_id,
                    "published": summary.published,
                    "message_ids": summary.message_ids,
                }),
            })
        }
        MessageCommand::Retry { group_id, event_id } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id = GroupId::new(hex::decode(normalize_group_id_hex(&group_id)?)?);
            let summary = runtime
                .retry_group_convergence(&account.label, &group_id)
                .await?;
            Ok(CommandOutput {
                plain: format!(
                    "retried group convergence for {event_id} published={}",
                    summary.published
                ),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex)?,
                    "group_id": hex::encode(group_id.as_slice()),
                    "target_event_id": event_id,
                    "retry_scope": "group_convergence",
                    "published": summary.published,
                    "message_ids": summary.message_ids,
                }),
            })
        }
        MessageCommand::React {
            group_id,
            message_id,
            emoji,
        } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id = GroupId::new(hex::decode(normalize_group_id_hex(&group_id)?)?);
            let summary = runtime
                .react_to_message(&account.label, &group_id, &message_id, &emoji)
                .await?;
            Ok(CommandOutput {
                plain: format!(
                    "reacted {emoji} to {message_id} published={}",
                    summary.published
                ),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex)?,
                    "group_id": hex::encode(group_id.as_slice()),
                    "target_message_id": message_id,
                    "emoji": emoji,
                    "published": summary.published,
                    "message_ids": summary.message_ids,
                }),
            })
        }
        MessageCommand::Unreact {
            group_id,
            message_id,
        } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id = GroupId::new(hex::decode(normalize_group_id_hex(&group_id)?)?);
            let summary = runtime
                .unreact_from_message(&account.label, &group_id, &message_id)
                .await?;
            Ok(CommandOutput {
                plain: format!(
                    "removed reaction from {message_id} published={}",
                    summary.published
                ),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex)?,
                    "group_id": hex::encode(group_id.as_slice()),
                    "target_message_id": message_id,
                    "published": summary.published,
                    "message_ids": summary.message_ids,
                }),
            })
        }
        MessageCommand::List {
            group_id,
            group,
            before,
            before_message_id,
            after,
            after_message_id,
            limit,
        } => {
            validate_message_list_cursors(
                before,
                before_message_id.as_deref(),
                after,
                after_message_id.as_deref(),
            )?;
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group = group.or(group_id);
            let uses_cursor = before.is_some()
                || before_message_id.is_some()
                || after.is_some()
                || after_message_id.is_some();
            let mut messages = app.messages_with_query(
                &account.label,
                AppMessageQuery {
                    group_id_hex: group
                        .map(|group| normalize_group_id_hex(&group))
                        .transpose()?,
                    limit: if uses_cursor { None } else { limit },
                },
            )?;
            if uses_cursor {
                messages = apply_message_cursors(
                    messages,
                    before,
                    before_message_id.as_deref(),
                    after,
                    after_message_id.as_deref(),
                    limit,
                );
            }
            Ok(CommandOutput {
                plain: message_list_plain(&messages),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex)?,
                    "messages": message_list_json_with_profiles(app, messages),
                }),
            })
        }
        MessageCommand::Timeline { command } => {
            handle_message_timeline_command(app, account_home, command, account_flag)
        }
        MessageCommand::Search {
            group_id,
            query,
            limit,
        } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let messages = search_messages(app, &account.label, Some(group_id), &query, limit)?;
            Ok(CommandOutput {
                plain: message_list_plain(&messages),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex)?,
                    "query": query,
                    "messages": message_list_json_with_profiles(app, messages),
                }),
            })
        }
        MessageCommand::SearchAll { query, limit } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let messages = search_messages(app, &account.label, None, &query, limit)?;
            Ok(CommandOutput {
                plain: message_list_plain(&messages),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex)?,
                    "query": query,
                    "messages": message_list_json_with_profiles(app, messages),
                }),
            })
        }
        MessageCommand::Subscribe { .. } => Err(DmError::MessagesSubscribeRequiresDaemon),
    }
}

fn handle_message_timeline_command(
    app: &MarmotApp,
    account_home: &AccountHome,
    command: MessageTimelineCommand,
    account_flag: Option<String>,
) -> Result<CommandOutput, DmError> {
    match command {
        MessageTimelineCommand::List {
            group_id,
            group,
            before,
            before_message_id,
            after,
            after_message_id,
            limit,
        } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group = group.or(group_id);
            let page = app.timeline_messages_with_query(
                &account.label,
                TimelineMessageQuery {
                    group_id_hex: group
                        .map(|group| normalize_group_id_hex(&group))
                        .transpose()?,
                    search: None,
                    pagination: TimelinePagination {
                        before,
                        before_message_id,
                        before_inclusive: false,
                        after,
                        after_message_id,
                        limit,
                    },
                },
            )?;
            timeline_page_output(app, &account.account_id_hex, page, None)
        }
        MessageTimelineCommand::Search {
            query,
            group_id,
            group,
            limit,
        } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group = group.or(group_id);
            let page = app.timeline_messages_with_query(
                &account.label,
                TimelineMessageQuery {
                    group_id_hex: group
                        .map(|group| normalize_group_id_hex(&group))
                        .transpose()?,
                    search: Some(query.clone()),
                    pagination: TimelinePagination {
                        limit,
                        ..TimelinePagination::default()
                    },
                },
            )?;
            timeline_page_output(app, &account.account_id_hex, page, Some(query))
        }
        MessageTimelineCommand::Subscribe { .. } => Err(DmError::MessagesSubscribeRequiresDaemon),
    }
}

fn search_messages(
    app: &MarmotApp,
    label: &str,
    group_id: Option<String>,
    query: &str,
    limit: Option<usize>,
) -> Result<Vec<AppMessageRecord>, DmError> {
    let group_id_hex = group_id
        .map(|group| normalize_group_id_hex(&group))
        .transpose()?;
    let mut matches = app
        .messages_with_query(
            label,
            AppMessageQuery {
                group_id_hex,
                limit: None,
            },
        )?
        .into_iter()
        .filter(|message| message.plaintext.contains(query))
        .collect::<Vec<_>>();
    if let Some(limit) = limit {
        matches.truncate(limit);
    }
    Ok(matches)
}

pub(crate) fn validate_message_list_cursors(
    before: Option<u64>,
    before_message_id: Option<&str>,
    after: Option<u64>,
    after_message_id: Option<&str>,
) -> Result<(), DmError> {
    if before.is_some() != before_message_id.is_some() {
        return Err(DmError::MessagePaginationCursorMismatch {
            timestamp_flag: "--before",
            message_id_flag: "--before-message-id",
        });
    }
    if after.is_some() != after_message_id.is_some() {
        return Err(DmError::MessagePaginationCursorMismatch {
            timestamp_flag: "--after",
            message_id_flag: "--after-message-id",
        });
    }
    if before.is_some() && after.is_some() {
        return Err(DmError::MessagePaginationConflictingCursors);
    }
    Ok(())
}

pub(crate) fn apply_message_cursors(
    mut messages: Vec<AppMessageRecord>,
    before: Option<u64>,
    before_message_id: Option<&str>,
    after: Option<u64>,
    after_message_id: Option<&str>,
    limit: Option<usize>,
) -> Vec<AppMessageRecord> {
    messages.retain(|message| {
        let before_matches = before.is_none_or(|cursor| {
            message.recorded_at < cursor
                || (message.recorded_at == cursor
                    && before_message_id
                        .is_some_and(|message_id| message.message_id_hex.as_str() < message_id))
        });
        let after_matches = after.is_none_or(|cursor| {
            message.recorded_at > cursor
                || (message.recorded_at == cursor
                    && after_message_id
                        .is_some_and(|message_id| message.message_id_hex.as_str() > message_id))
        });
        before_matches && after_matches
    });

    if let Some(limit) = limit
        && messages.len() > limit
    {
        if before.is_some() && after.is_none() {
            messages = messages.split_off(messages.len() - limit);
        } else {
            messages.truncate(limit);
        }
    }
    messages
}

fn message_list_plain(messages: &[AppMessageRecord]) -> String {
    if messages.is_empty() {
        return "no messages".to_owned();
    }
    messages
        .iter()
        .map(|message| {
            format!(
                "group={} from={}: {}",
                message.group_id_hex, message.sender, message.plaintext
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn message_list_json_with_profiles(app: &MarmotApp, messages: Vec<AppMessageRecord>) -> Vec<Value> {
    let mut display_names_by_sender: HashMap<String, Option<String>> = HashMap::new();
    messages
        .into_iter()
        .map(|message| {
            let from_display_name = display_names_by_sender
                .entry(message.sender.clone())
                .or_insert_with(|| display_name_for_sender(app, &message.sender))
                .clone();
            message_record_json(message, from_display_name)
        })
        .collect()
}

fn timeline_page_output(
    app: &MarmotApp,
    account_id_hex: &str,
    page: TimelinePage,
    query: Option<String>,
) -> Result<CommandOutput, DmError> {
    let messages = timeline_message_list_json_with_profiles(app, page.messages, account_id_hex);
    let plain = timeline_message_list_plain(&messages);
    let mut json = json!({
        "account_id": account_id_hex,
        "npub": npub_for_account_id(account_id_hex)?,
        "messages": messages,
        "has_more_before": page.has_more_before,
        "has_more_after": page.has_more_after,
    });
    if let Some(query) = query {
        json["query"] = json!(query);
    }
    Ok(CommandOutput { plain, json })
}

fn timeline_message_list_plain(messages: &[Value]) -> String {
    if messages.is_empty() {
        return "no timeline messages".to_owned();
    }
    messages
        .iter()
        .map(|message| {
            let deleted = if message
                .get("deleted")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                " deleted=true"
            } else {
                ""
            };
            format!(
                "group={} from={}: {}{}",
                message
                    .get("group_id")
                    .and_then(Value::as_str)
                    .unwrap_or("<unknown>"),
                message
                    .get("from")
                    .and_then(Value::as_str)
                    .unwrap_or("<unknown>"),
                timeline_message_display_text(message),
                deleted
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn timeline_message_list_json_with_profiles(
    app: &MarmotApp,
    messages: Vec<TimelineMessageRecord>,
    local_account_id_hex: &str,
) -> Vec<Value> {
    let mut display_names_by_account: HashMap<String, Option<String>> = HashMap::new();
    messages
        .into_iter()
        .map(|message| {
            let mut display_name_for_account = |account_id: &str| {
                display_names_by_account
                    .entry(account_id.to_owned())
                    .or_insert_with(|| display_name_for_sender(app, account_id))
                    .clone()
            };
            timeline_message_record_json(
                message,
                Some(local_account_id_hex),
                &mut display_name_for_account,
            )
        })
        .collect()
}

pub(crate) fn timeline_message_record_json(
    message: TimelineMessageRecord,
    local_account_id_hex: Option<&str>,
    display_name_for_account: &mut dyn FnMut(&str) -> Option<String>,
) -> Value {
    let from_display_name = display_name_for_account(&message.sender);
    let group_system = timeline_group_system_json(
        message.kind,
        &message.plaintext,
        local_account_id_hex,
        display_name_for_account,
    );
    json!({
        "message_id": message.message_id_hex,
        "source_message_id": message.source_message_id_hex,
        "direction": message.direction,
        "group_id": message.group_id_hex,
        "from": message.sender,
        "from_display_name": from_display_name,
        "plaintext": message.plaintext,
        "kind": message.kind,
        "tags": message.tags,
        "group_system": group_system,
        "timeline_at": message.timeline_at,
        "received_at": message.received_at,
        "reply_to_message_id": message.reply_to_message_id_hex,
        "reply_preview": message.reply_preview,
        "media": message.media,
        "agent_text_stream": message.agent_text_stream,
        "reactions": message.reactions,
        "deleted": message.deleted,
        "deleted_by_message_id": message.deleted_by_message_id_hex,
    })
}

pub(crate) fn timeline_message_display_text(message: &Value) -> String {
    if message.get("kind").and_then(Value::as_u64) == Some(MARMOT_APP_EVENT_KIND_GROUP_SYSTEM)
        && let Some(summary) = message
            .get("group_system")
            .and_then(|system| system.get("summary"))
            .and_then(Value::as_str)
            .filter(|summary| !summary.trim().is_empty())
    {
        return summary.to_owned();
    }
    message
        .get("plaintext")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn timeline_group_system_json(
    kind: u64,
    plaintext: &str,
    local_account_id_hex: Option<&str>,
    display_name_for_account: &mut dyn FnMut(&str) -> Option<String>,
) -> Option<Value> {
    let event = group_system_event_from_message(kind, plaintext)?;
    let actor_display_name = event
        .actor_account_id_hex
        .as_deref()
        .and_then(&mut *display_name_for_account);
    let subject_display_name = event
        .subject_account_id_hex
        .as_deref()
        .and_then(display_name_for_account);
    let subject_is_self = event
        .subject_account_id_hex
        .as_deref()
        .zip(local_account_id_hex)
        .is_some_and(|(subject, local)| subject == local);
    let summary = group_system_summary(
        &event.system_type,
        event.actor_account_id_hex.as_deref(),
        actor_display_name.as_deref(),
        event.subject_account_id_hex.as_deref(),
        subject_display_name.as_deref(),
        subject_is_self,
        event.name.as_deref(),
        &event.text,
    );
    Some(json!({
        "system_type": event.system_type,
        "text": event.text,
        "actor": event.actor_account_id_hex,
        "actor_display_name": actor_display_name,
        "subject": event.subject_account_id_hex,
        "subject_display_name": subject_display_name,
        "subject_is_self": subject_is_self,
        "name": event.name,
        "summary": summary,
    }))
}

#[allow(clippy::too_many_arguments)]
fn group_system_summary(
    system_type: &str,
    actor: Option<&str>,
    actor_display_name: Option<&str>,
    subject: Option<&str>,
    subject_display_name: Option<&str>,
    subject_is_self: bool,
    name: Option<&str>,
    fallback_text: &str,
) -> String {
    let actor = actor_label(actor, actor_display_name);
    let subject = subject_label(subject, subject_display_name, subject_is_self);
    let name = name.unwrap_or_default();
    match (system_type, actor.as_deref(), subject_is_self) {
        (GROUP_SYSTEM_TYPE_MEMBER_ADDED, Some(actor), _) => format!("{actor} added {subject}"),
        (GROUP_SYSTEM_TYPE_MEMBER_ADDED, None, _) => format!("{subject} was added"),
        (GROUP_SYSTEM_TYPE_MEMBER_REMOVED, Some(actor), true) => {
            format!("You were removed from the group by {actor}")
        }
        (GROUP_SYSTEM_TYPE_MEMBER_REMOVED, None, true) => {
            "You were removed from the group".to_owned()
        }
        (GROUP_SYSTEM_TYPE_MEMBER_REMOVED, Some(actor), false) => {
            format!("{actor} removed {subject}")
        }
        (GROUP_SYSTEM_TYPE_MEMBER_REMOVED, None, false) => format!("{subject} was removed"),
        (GROUP_SYSTEM_TYPE_MEMBER_LEFT, Some(actor), _) => format!("{actor} left"),
        (GROUP_SYSTEM_TYPE_MEMBER_LEFT, None, _) => format!("{subject} left"),
        (GROUP_SYSTEM_TYPE_ADMIN_ADDED, Some(actor), _) => {
            format!("{actor} made {subject} an admin")
        }
        (GROUP_SYSTEM_TYPE_ADMIN_ADDED, None, _) => format!("{subject} was made an admin"),
        (GROUP_SYSTEM_TYPE_ADMIN_REMOVED, Some(actor), _) => {
            format!("{actor} removed {subject} as admin")
        }
        (GROUP_SYSTEM_TYPE_ADMIN_REMOVED, None, _) => format!("{subject} is no longer an admin"),
        (GROUP_SYSTEM_TYPE_GROUP_RENAMED, Some(actor), _) => {
            format!("{actor} renamed the group to \"{name}\"")
        }
        (GROUP_SYSTEM_TYPE_GROUP_RENAMED, None, _) => {
            format!("the group was renamed to \"{name}\"")
        }
        (GROUP_SYSTEM_TYPE_GROUP_AVATAR_CHANGED, Some(actor), _) => {
            format!("{actor} changed the group avatar")
        }
        (GROUP_SYSTEM_TYPE_GROUP_AVATAR_CHANGED, None, _) => "the group avatar changed".to_owned(),
        _ => {
            if fallback_text.is_empty() {
                system_type.to_owned()
            } else {
                fallback_text.to_owned()
            }
        }
    }
}

fn actor_label(actor: Option<&str>, actor_display_name: Option<&str>) -> Option<String> {
    actor_display_name
        .filter(|name| !name.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| actor.map(|actor| shorten_account(actor, 12)))
}

fn subject_label(
    subject: Option<&str>,
    subject_display_name: Option<&str>,
    subject_is_self: bool,
) -> String {
    if subject_is_self {
        return "you".to_owned();
    }
    subject_display_name
        .filter(|name| !name.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| subject.map(|subject| shorten_account(subject, 12)))
        .unwrap_or_else(|| "someone".to_owned())
}

fn shorten_account(value: &str, max_len: usize) -> String {
    if value.len() <= max_len {
        value.to_owned()
    } else {
        value.chars().take(max_len).collect()
    }
}

pub(crate) fn message_record_json(
    message: AppMessageRecord,
    from_display_name: Option<String>,
) -> Value {
    let agent_text_stream =
        agent_text_stream_payload_value(message.kind, &message.tags, &message.plaintext);
    let mut value = json!({
        "message_id": message.message_id_hex,
        "direction": message.direction,
        "group_id": message.group_id_hex,
        "from": message.sender,
        "from_display_name": from_display_name,
        "plaintext": message.plaintext,
        "kind": message.kind,
        "tags": message.tags,
        "recorded_at": message.recorded_at,
        "received_at": message.received_at,
    });
    if let Some(agent_text_stream) = agent_text_stream {
        value["agent_text_stream"] = agent_text_stream;
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use marmot_app::TimelineReactionSummary;

    #[test]
    fn timeline_message_record_json_summarizes_self_removal() {
        let actor = "aa".repeat(32);
        let subject = "bb".repeat(32);
        let content = cgka_traits::app_event::GroupSystemEvent::new(
            GROUP_SYSTEM_TYPE_MEMBER_REMOVED,
            "Member removed",
            Some(json!({
                cgka_traits::app_event::GROUP_SYSTEM_DATA_ACTOR: actor.clone(),
                cgka_traits::app_event::GROUP_SYSTEM_DATA_SUBJECT: subject.clone(),
            })),
        )
        .to_content()
        .unwrap();
        let message = TimelineMessageRecord {
            message_id_hex: "system-1".to_owned(),
            source_message_id_hex: None,
            source_epoch: Some(3),
            direction: "system".to_owned(),
            group_id_hex: "11".repeat(32),
            sender: actor.clone(),
            plaintext: content,
            kind: MARMOT_APP_EVENT_KIND_GROUP_SYSTEM,
            tags: vec![vec!["system".to_owned(), "member_removed".to_owned()]],
            timeline_at: 10,
            received_at: 11,
            reply_to_message_id_hex: None,
            reply_preview: None,
            media: None,
            agent_text_stream: None,
            reactions: TimelineReactionSummary::default(),
            deleted: false,
            deleted_by_message_id_hex: None,
            invalidation_status: None,
        };
        let mut display_name_for_account = |account_id: &str| {
            if account_id == actor {
                Some("alice".to_owned())
            } else {
                None
            }
        };

        let value =
            timeline_message_record_json(message, Some(&subject), &mut display_name_for_account);

        assert_eq!(
            value["group_system"]["summary"].as_str(),
            Some("You were removed from the group by alice")
        );
        assert_eq!(
            timeline_message_display_text(&value),
            "You were removed from the group by alice"
        );
        assert_eq!(value["group_system"]["subject_is_self"], true);
    }

    #[test]
    fn timeline_message_display_text_ignores_blank_system_summary() {
        let message = json!({
            "kind": MARMOT_APP_EVENT_KIND_GROUP_SYSTEM,
            "plaintext": "fallback text",
            "group_system": {
                "summary": "   "
            }
        });

        assert_eq!(timeline_message_display_text(&message), "fallback text");
    }
}
