//! `chats` command namespace handlers and chat-archive output helper.

use std::time::{SystemTime, UNIX_EPOCH};

use marmot_account::AccountHome;
use marmot_app::{ChatNotificationSettings, MarmotApp, MarmotAppRuntime};
use serde_json::{Value, json};

use crate::{
    ChatsCommand, CommandOutput, WnError, ensure_local_signing, group_json, group_list_plain,
    group_show_output, normalize_group_id_hex, npub_for_account_id, resolve_account,
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
            Ok(CommandOutput {
                plain: group_list_plain(&chats),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex)?,
                    "include_archived": include_archived,
                    "chats": chats.into_iter().map(group_json).collect::<Vec<_>>(),
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
            Ok(CommandOutput {
                plain: group_list_plain(&chats),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex)?,
                    "chats": chats.into_iter().map(group_json).collect::<Vec<_>>(),
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
    }
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
