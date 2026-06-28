//! `chats` command namespace handlers and chat-archive output helper.

use marmot_account::AccountHome;
use marmot_app::{MarmotApp, MarmotAppRuntime};
use serde_json::json;

use crate::{
    ChatsCommand, CommandOutput, DmError, ensure_local_signing, group_json, group_list_plain,
    group_show_output, normalize_group_id_hex, npub_for_account_id, resolve_account,
    unsupported_command,
};

pub(crate) async fn chats_command(
    account_home: &AccountHome,
    app: &MarmotApp,
    command: ChatsCommand,
    account_flag: Option<String>,
) -> Result<CommandOutput, DmError> {
    let runtime = app.runtime();
    chats_command_with_runtime(account_home, app, &runtime, command, account_flag).await
}

pub(crate) async fn chats_command_with_runtime(
    account_home: &AccountHome,
    app: &MarmotApp,
    runtime: &MarmotAppRuntime,
    command: ChatsCommand,
    account_flag: Option<String>,
) -> Result<CommandOutput, DmError> {
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
        ChatsCommand::Subscribe => Err(DmError::ChatsSubscribeRequiresDaemon),
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
        ChatsCommand::SubscribeArchived => Err(DmError::ChatsSubscribeRequiresDaemon),
        ChatsCommand::Mute { .. } => unsupported_command(
            "chats mute",
            "chat notification mute state is not modeled in marmot-app yet",
        ),
        ChatsCommand::Unmute { .. } => unsupported_command(
            "chats unmute",
            "chat notification mute state is not modeled in marmot-app yet",
        ),
    }
}

async fn group_archive_output(
    runtime: &MarmotAppRuntime,
    account: marmot_account::AccountSummary,
    group: String,
    archived: bool,
) -> Result<CommandOutput, DmError> {
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
