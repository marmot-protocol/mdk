//! `chats` command namespace handlers and chat-archive output helper.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use marmot_account::AccountHome;
use marmot_app::{
    AppGroupRecord, ChatListRow, ChatNotificationSettings, MarmotApp, MarmotAppRuntime,
};
use serde_json::{Value, json};

use crate::{
    ChatsCommand, CommandOutput, WnError, chat_json, ensure_local_signing, group_json,
    group_list_plain, group_show_output, insert_chat_projection, normalize_group_id_hex,
    npub_for_account_id, resolve_account,
};

pub(crate) async fn chats_command(
    account_home: &AccountHome,
    app: &MarmotApp,
    command: ChatsCommand,
    account_flag: Option<String>,
) -> Result<CommandOutput, WnError> {
    let runtime = app.runtime();
    chats_command_with_runtime(account_home, app, &runtime, command, account_flag).await
}

pub(crate) async fn chats_command_with_runtime(
    account_home: &AccountHome,
    app: &MarmotApp,
    runtime: &MarmotAppRuntime,
    command: ChatsCommand,
    account_flag: Option<String>,
) -> Result<CommandOutput, WnError> {
    match command {
        ChatsCommand::List { include_archived } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let chats = if include_archived {
                app.groups(&account.label)?
            } else {
                app.visible_groups(&account.label)?
            };
            let plain = group_list_plain(&chats);
            let chats_json = chat_rows_json(app, &account.label, include_archived, chats)?;
            Ok(CommandOutput {
                plain,
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex)?,
                    "include_archived": include_archived,
                    "chats": chats_json,
                }),
            })
        }
        ChatsCommand::Show { group } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            group_show_output(app, account, group, None)
        }
        ChatsCommand::Subscribe => Err(WnError::ChatsSubscribeRequiresDaemon),
        ChatsCommand::Archive { group } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            group_archive_output(runtime, account, group, true).await
        }
        ChatsCommand::Unarchive { group } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            group_archive_output(runtime, account, group, false).await
        }
        ChatsCommand::ListArchived => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let chats = app
                .groups(&account.label)?
                .into_iter()
                .filter(|group| group.archived)
                .collect::<Vec<_>>();
            let plain = group_list_plain(&chats);
            let chats_json = chat_rows_json(app, &account.label, true, chats)?;
            Ok(CommandOutput {
                plain,
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex)?,
                    "chats": chats_json,
                }),
            })
        }
        ChatsCommand::SubscribeArchived => Err(WnError::ChatsSubscribeRequiresDaemon),
        ChatsCommand::Mute { group, duration } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            let group_id = normalize_group_id_hex(&group)?;
            let muted_until_ms = parse_mute_duration(&duration)?;
            let settings = runtime.set_chat_muted(&account.label, &group_id, muted_until_ms)?;
            Ok(CommandOutput {
                plain: chat_notification_plain("muted", &settings),
                json: chat_notification_json(account.account_id_hex, settings),
            })
        }
        ChatsCommand::Unmute { group } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            let group_id = normalize_group_id_hex(&group)?;
            let settings = runtime.clear_chat_muted(&account.label, &group_id)?;
            Ok(CommandOutput {
                plain: chat_notification_plain("unmuted", &settings),
                json: chat_notification_json(account.account_id_hex, settings),
            })
        }
        ChatsCommand::MarkRead { group, message_id } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            let group_id = normalize_group_id_hex(&group)?;
            // An explicit message id marks the chat read up to that message; the
            // runtime's read marker is a forward-only high-water mark, so a
            // partial mark leaves any newer messages unread and re-marking an
            // older message never moves the marker backward. With no id, mark the
            // newest message read (the "clear on chat open" semantics): the newest
            // markable message is the chat-list projection's `last_message` (the
            // latest kind-9 preview), which is exactly what the marker operates on,
            // so we resolve it through the runtime rather than re-querying the
            // timeline. An empty chat has nothing to mark and is already fully
            // read; return its current (empty) projection unchanged rather than
            // erroring, matching how chats rows report empty defaults.
            let row = match message_id {
                Some(message_id) => {
                    runtime.mark_timeline_message_read(&account.label, &group_id, &message_id)?
                }
                None => {
                    let projection = runtime.chat_list_row(&account.label, &group_id)?;
                    match projection
                        .as_ref()
                        .and_then(|row| row.last_message.as_ref())
                    {
                        Some(message) => runtime.mark_timeline_message_read(
                            &account.label,
                            &group_id,
                            &message.message_id_hex,
                        )?,
                        None => projection,
                    }
                }
            };
            Ok(CommandOutput {
                plain: format!("marked chat {group_id} read"),
                json: chat_mark_read_json(&account.account_id_hex, &group_id, row)?,
            })
        }
    }
}

/// Render the `chats mark-read` response: the account/group identity plus the
/// refreshed chat-list projection (unread state, last-message preview, last-read
/// marker) via [`insert_chat_projection`], so the five projection keys are
/// byte-identical to the `chats list` rows and the `chats subscribe` feed.
fn chat_mark_read_json(
    account_id_hex: &str,
    group_id_hex: &str,
    chat_list_row: Option<ChatListRow>,
) -> Result<Value, WnError> {
    let mut value = json!({
        "account_id": account_id_hex,
        "npub": npub_for_account_id(account_id_hex)?,
        "group_id": group_id_hex,
    });
    insert_chat_projection(&mut value, chat_list_row);
    Ok(value)
}

/// Build the JSON rows for a `chats list`/`list-archived` response: each group
/// record enriched with its durable chat-list projection (unread state,
/// last-message preview, last-read marker) via [`chat_json`].
///
/// The projection is read through the batched `marmot-app` `chat_list` accessor
/// exactly once and indexed by `group_id_hex`, rather than an N+1 per-group
/// `chat_list_row` call — each of which re-runs the projection
/// ensure/completeness/hydration pass. A group absent from the index yields the
/// same empty defaults as an absent single-row read. `include_archived` matches
/// the caller's row set (the archived-only `list-archived` reads with it set) so
/// every rendered group is covered. A read failure propagates (one-shot),
/// matching the list command's error contract.
fn chat_rows_json(
    app: &MarmotApp,
    label: &str,
    include_archived: bool,
    chats: Vec<AppGroupRecord>,
) -> Result<Vec<Value>, WnError> {
    let mut projections: HashMap<String, ChatListRow> = app
        .chat_list(label, include_archived)?
        .into_iter()
        .map(|row| (row.group_id_hex.clone(), row))
        .collect();
    Ok(chats
        .into_iter()
        .map(|chat| {
            let projection = projections.remove(&chat.group_id_hex);
            chat_json(chat, projection)
        })
        .collect())
}

fn parse_mute_duration(duration: &str) -> Result<Option<i64>, WnError> {
    let trimmed = duration.trim();
    if trimmed.eq_ignore_ascii_case("forever") || trimmed.eq_ignore_ascii_case("always") {
        return Ok(None);
    }
    let Some((number, unit)) = trimmed.split_at_checked(trimmed.len().saturating_sub(1)) else {
        return Err(WnError::InvalidMuteDuration(duration.to_owned()));
    };
    let amount = number
        .parse::<i64>()
        .map_err(|_| WnError::InvalidMuteDuration(duration.to_owned()))?;
    if amount <= 0 {
        return Err(WnError::InvalidMuteDuration(duration.to_owned()));
    }
    let unit_seconds = match unit {
        "s" | "S" => 1,
        "m" | "M" => 60,
        "h" | "H" => 60 * 60,
        "d" | "D" => 24 * 60 * 60,
        "w" | "W" => 7 * 24 * 60 * 60,
        _ => return Err(WnError::InvalidMuteDuration(duration.to_owned())),
    };
    let duration_ms = amount
        .checked_mul(unit_seconds)
        .and_then(|seconds| seconds.checked_mul(1000))
        .ok_or_else(|| WnError::InvalidMuteDuration(duration.to_owned()))?;
    current_time_ms()
        .checked_add(duration_ms)
        .map(Some)
        .ok_or_else(|| WnError::InvalidMuteDuration(duration.to_owned()))
}

fn current_time_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or_default()
}

fn chat_notification_plain(verb: &str, settings: &ChatNotificationSettings) -> String {
    match settings.muted_until_ms {
        Some(until) if settings.muted => {
            format!("{} chat {} until {}", verb, settings.group_id_hex, until)
        }
        None if settings.muted => format!("{} chat {} forever", verb, settings.group_id_hex),
        _ => format!("{} chat {}", verb, settings.group_id_hex),
    }
}

fn chat_notification_json(account_id: String, settings: ChatNotificationSettings) -> Value {
    json!({
        "account_id": account_id,
        "account_ref": settings.account_ref,
        "group_id": settings.group_id_hex,
        "muted": settings.muted,
        "muted_until_ms": settings.muted_until_ms,
        "updated_at_ms": settings.updated_at_ms,
    })
}

async fn group_archive_output(
    runtime: &MarmotAppRuntime,
    account: marmot_account::AccountSummary,
    group: String,
    archived: bool,
) -> Result<CommandOutput, WnError> {
    let group_id = normalize_group_id_hex(&group)?;
    let group = runtime
        .set_group_archived(&account.label, &group_id, archived)
        .await?;
    let verb = if archived { "archived" } else { "unarchived" };
    Ok(CommandOutput {
        plain: format!("{verb} group {group_id}"),
        json: json!({
            "account_id": account.account_id_hex,
            "npub": npub_for_account_id(&account.account_id_hex)?,
            "group": group_json(group),
        }),
    })
}
