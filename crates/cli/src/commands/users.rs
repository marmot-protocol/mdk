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
            let (results, completeness) = collect_user_search(
                app,
                UserSearchParams {
                    searcher_account_id_hex: account.account_id_hex.clone(),
                    query: query.clone(),
                    radius_start: radius.0,
                    radius_end: radius.1,
                },
            )
            .await?;
            let mut plain = if results.is_empty() {
                "no users".to_owned()
            } else {
                results
                    .iter()
                    .map(|result| result.npub.clone())
                    .collect::<Vec<_>>()
                    .join("\n")
            };
            let mut json = json!({
                "account_id": account.account_id_hex,
                "npub": npub_for_account_id(&account.account_id_hex)?,
                "query": query,
                "users": results,
                "complete": completeness.reason().is_none(),
            });
            if let Some(reason) = completeness.reason() {
                json["incomplete_reason"] = json!(reason);
                plain.push_str(&format!("\n(partial results: {reason})"));
            }
            Ok(CommandOutput { plain, json })
        }
    }
}

/// Whether a traversal delivered everything it was asked for.
///
/// A radius that ran out of time or overflowed the candidate cap still yields
/// valid matches -- just not all of them. That is worth reporting rather than
/// failing on: dropping real results is worse than returning them labelled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SearchCompleteness {
    Complete,
    RadiusTimeout,
    RadiusTruncated,
}

impl SearchCompleteness {
    /// Fold one update's trigger in. The first shortfall sticks: a later radius
    /// finishing cleanly does not restore the results an earlier one lost, and
    /// the first reason is the one that explains the shape of the answer.
    fn observe(&mut self, trigger: &SearchUpdateTrigger) {
        if *self != Self::Complete {
            return;
        }
        *self = match trigger {
            SearchUpdateTrigger::RadiusTimeout { .. } => Self::RadiusTimeout,
            SearchUpdateTrigger::RadiusTruncated { .. } => Self::RadiusTruncated,
            _ => return,
        };
    }

    /// Why the result list is short, or `None` when it is not.
    fn reason(self) -> Option<&'static str> {
        match self {
            Self::Complete => None,
            Self::RadiusTimeout => Some("radius_timeout"),
            Self::RadiusTruncated => Some("radius_truncated"),
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
/// A traversal that *fails* is reported as an error rather than as a short
/// result list. A traversal that merely fell short -- a radius timed out, or a
/// layer hit the candidate cap -- returns its matches along with the reason,
/// because an incomplete search presented as a complete one is the more
/// expensive mistake either way.
async fn collect_user_search(
    app: &MarmotApp,
    params: UserSearchParams,
) -> Result<(Vec<UserDirectorySearchResult>, SearchCompleteness), WnError> {
    let mut subscription = app.search_users(params).await?;
    let mut results = Vec::new();
    let mut completeness = SearchCompleteness::Complete;
    while let Some(update) = subscription.next_update().await {
        if let SearchUpdateTrigger::Error { message } = update.trigger {
            return Err(WnError::UserSearch(message));
        }
        completeness.observe(&update.trigger);
        results.extend(update.new_results);
    }
    sort_user_search_results(&mut results);
    Ok((results, completeness))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_clean_traversal_reports_complete() {
        let mut completeness = SearchCompleteness::Complete;
        for trigger in [
            SearchUpdateTrigger::RadiusStarted { radius: 0 },
            SearchUpdateTrigger::ResultsFound { radius: 0 },
            SearchUpdateTrigger::RadiusCompleted { radius: 0 },
            SearchUpdateTrigger::SearchCompleted,
        ] {
            completeness.observe(&trigger);
        }

        assert_eq!(completeness, SearchCompleteness::Complete);
        assert_eq!(completeness.reason(), None);
    }

    /// A radius that timed out or overflowed the candidate cap curtailed the
    /// search. The matches already delivered are valid, so they are still
    /// returned -- but the caller has to be told the list is short, which is
    /// the whole point of the engine emitting these triggers.
    #[test]
    fn a_curtailed_traversal_keeps_the_first_reason_it_fell_short() {
        for (trigger, reason) in [
            (
                SearchUpdateTrigger::RadiusTimeout { radius: 1 },
                "radius_timeout",
            ),
            (
                SearchUpdateTrigger::RadiusTruncated { radius: 1 },
                "radius_truncated",
            ),
        ] {
            let mut completeness = SearchCompleteness::Complete;
            completeness.observe(&trigger);
            assert_eq!(completeness.reason(), Some(reason));

            // A later radius finishing cleanly does not undo the shortfall.
            completeness.observe(&SearchUpdateTrigger::RadiusCompleted { radius: 2 });
            completeness.observe(&SearchUpdateTrigger::SearchCompleted);
            assert_eq!(completeness.reason(), Some(reason));
        }
    }

    #[test]
    fn the_first_shortfall_is_not_overwritten_by_a_later_one() {
        let mut completeness = SearchCompleteness::Complete;
        completeness.observe(&SearchUpdateTrigger::RadiusTruncated { radius: 1 });
        completeness.observe(&SearchUpdateTrigger::RadiusTimeout { radius: 2 });

        assert_eq!(completeness.reason(), Some("radius_truncated"));
    }
}
