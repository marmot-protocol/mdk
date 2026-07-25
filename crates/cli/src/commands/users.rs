//! `users` command namespace handlers.

use marmot_account::AccountHome;
use marmot_app::{
    AppError, MarmotApp, SearchUpdateTrigger, UserDirectorySearchResult, UserSearchParams,
    sort_user_search_results,
};
use serde_json::json;

use crate::{
    CommandOutput, UsersCommand, WnError, npub_for_account_id, parse_public_key, resolve_account,
};

pub(crate) async fn users_command(
    account_home: &AccountHome,
    app: &MarmotApp,
    command: UsersCommand,
    account_flag: Option<String>,
) -> Result<CommandOutput, WnError> {
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
            let results = collect_user_search(
                app,
                UserSearchParams {
                    searcher_account_id_hex: account.account_id_hex.clone(),
                    query: query.clone(),
                    radius_start: radius.0,
                    radius_end: radius.1,
                },
            )
            .await?;
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

/// Run a web-of-trust search to completion and collect every match.
///
/// One CLI invocation renders one result, so it consumes the whole stream
/// rather than reporting progress. Updates carry incremental batches and each
/// radius emits cached matches before fetched ones, so the aggregate is
/// re-ranked to recover best-first order.
///
/// A traversal that fails partway is reported as an error rather than as a
/// short result list: an incomplete search presented as a complete one is the
/// more expensive mistake.
async fn collect_user_search(
    app: &MarmotApp,
    params: UserSearchParams,
) -> Result<Vec<UserDirectorySearchResult>, WnError> {
    let mut subscription = app.search_users(params).await?;
    let mut results = Vec::new();
    while let Some(update) = subscription.next_update().await {
        if let SearchUpdateTrigger::Error { message } = update.trigger {
            return Err(WnError::UserSearch(message));
        }
        results.extend(update.new_results);
    }
    sort_user_search_results(&mut results);
    Ok(results)
}
