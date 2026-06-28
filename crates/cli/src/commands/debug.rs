//! `debug` command namespace handlers.

use marmot_account::AccountHome;
use marmot_app::MarmotApp;
use serde_json::json;

use crate::{
    CommandOutput, DebugCommand, DmError, npub_for_account_id, relay_lists_json, resolve_account,
    unsupported_command,
};

pub(crate) fn debug_command(
    account_home: &AccountHome,
    app: &MarmotApp,
    command: DebugCommand,
    account_flag: Option<String>,
) -> Result<CommandOutput, DmError> {
    match command {
        DebugCommand::RelayControlState => {
            let accounts = account_home.accounts()?;
            let statuses = accounts
                .into_iter()
                .map(|account| {
                    let relay_lists = app
                        .account_relay_list_status_for_account_id(&account.account_id_hex)
                        .map(relay_lists_json)
                        .unwrap_or_else(|err| json!({"error": err.to_string()}));
                    Ok(json!({
                        "account_id": account.account_id_hex,
                        "npub": npub_for_account_id(&account.account_id_hex)?,
                        "relay_lists": relay_lists,
                    }))
                })
                .collect::<Result<Vec<_>, DmError>>()?;
            Ok(CommandOutput {
                plain: serde_json::to_string_pretty(&statuses)
                    .expect("JSON response serialization cannot fail"),
                json: json!({ "accounts": statuses }),
            })
        }
        DebugCommand::Health => {
            let account = resolve_account(account_home, account_flag)?;
            let status = app.status(&account.label)?;
            Ok(CommandOutput {
                plain: format!(
                    "healthy account={} groups={} messages={}",
                    account.account_id_hex, status.group_count, status.message_count
                ),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex)?,
                    "healthy": true,
                    "groups": status.group_count,
                    "messages": status.message_count,
                    "seen_events": status.seen_events,
                }),
            })
        }
        DebugCommand::RatchetTree { .. } => unsupported_command(
            "debug ratchet-tree",
            "ratchet-tree diagnostics are not exposed by marmot-app yet",
        ),
    }
}
