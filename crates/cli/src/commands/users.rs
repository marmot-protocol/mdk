//! `users` command namespace handlers.

use marmot_account::AccountHome;
use marmot_app::{AppError, MarmotApp, UserDirectorySearch};
use serde_json::json;

use crate::{
    CommandOutput, DmError, UsersCommand, npub_for_account_id, parse_public_key, resolve_account,
};

pub(crate) fn users_command(
    account_home: &AccountHome,
    app: &MarmotApp,
    command: UsersCommand,
    account_flag: Option<String>,
) -> Result<CommandOutput, DmError> {
    match command {
        UsersCommand::Show { pubkey } => {
            let account_id = parse_public_key(&pubkey)?;
            let entry = app
                .directory_entry_for_account_id(&account_id)?
                .ok_or_else(|| AppError::MissingDirectoryEntry(account_id.clone()))?;
            Ok(CommandOutput {
                plain: serde_json::to_string_pretty(&entry)
                    .expect("JSON response serialization cannot fail"),
                json: json!({ "user": entry }),
            })
        }
        UsersCommand::Search { query, radius } => {
            let account = resolve_account(account_home, account_flag)?;
            let results = app.search_user_directory(UserDirectorySearch {
                searcher_account_id_hex: account.account_id_hex.clone(),
                query: query.clone(),
                radius_start: radius.0,
                radius_end: radius.1,
                limit: None,
            })?;
            Ok(CommandOutput {
                plain: if results.is_empty() {
                    "no users".to_owned()
                } else {
                    results
                        .iter()
                        .map(|result| result.npub.clone())
                        .collect::<Vec<_>>()
                        .join("\n")
                },
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex)?,
                    "query": query,
                    "users": results,
                }),
            })
        }
    }
}
