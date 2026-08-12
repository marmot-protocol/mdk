//! `users` command namespace handlers.

use marmot_account::{AccountHome, AccountSummary};
use marmot_app::{
    AppError, MarmotApp, MarmotAppRuntime, SearchUpdateTrigger, UserDirectorySearchResult,
    UserSearchParams, sort_user_search_results,
};
use serde_json::json;

use crate::{
    CommandOutput, UsersCommand, WnError, npub_for_account_id, parse_public_key, resolve_account,
};

/// `users` without a running app runtime.
///
/// Search still walks the follow graph; what it cannot do is widen radius 1
/// with group co-members, because membership is live MLS state and there is no
/// account worker here to ask. Running `wnd` routes the command through
/// [`users_command_with_runtime`] instead, which can.
pub(crate) async fn users_command(
    account_home: &AccountHome,
    app: &MarmotApp,
    command: UsersCommand,
    account_flag: Option<String>,
) -> Result<CommandOutput, WnError> {
    run_users_command(account_home, app, None, command, account_flag).await
}

/// `users` answered with the daemon's live app runtime.
///
/// The runtime already holds hydrated MLS sessions, so group co-members cost a
/// command-RPC rather than opening anything, and search can count the people
/// you share a group with as socially close.
pub(crate) async fn users_command_with_runtime(
    account_home: &AccountHome,
    app: &MarmotApp,
    runtime: &MarmotAppRuntime,
    command: UsersCommand,
    account_flag: Option<String>,
) -> Result<CommandOutput, WnError> {
    run_users_command(account_home, app, Some(runtime), command, account_flag).await
}

async fn run_users_command(
    account_home: &AccountHome,
    app: &MarmotApp,
    runtime: Option<&MarmotAppRuntime>,
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
                    radius_one_seeds: radius_one_seeds(runtime, &account, radius.1).await?,
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

/// Accounts to widen radius 1 with, when there is anyone to ask about.
///
/// Sharing a group is social proximity even when neither person has followed
/// the other, but that membership is live MLS state, so it takes both a running
/// runtime and an account that actually has sessions. Neither absence is a
/// degraded answer:
///
/// - no runtime (a standalone `wn` with no daemon) means this process cannot
///   know, so search covers the follow graph, which is everything it can know;
/// - a watch-only or signed-out account has no MLS sessions at all, so it
///   shares no groups. Asking anyway would make the runtime refuse and turn an
///   enhancement into a failed search for accounts that search fine today.
/// - a window that stops at radius 0 cannot use radius-1 seeds, and gathering
///   them costs a membership read per group.
async fn radius_one_seeds(
    runtime: Option<&MarmotAppRuntime>,
    account: &AccountSummary,
    radius_end: u8,
) -> Result<Vec<String>, WnError> {
    let usable = radius_end >= 1 && account.is_active_signing();
    let Some(runtime) = runtime.filter(|_| usable) else {
        return Ok(Vec::new());
    };
    Ok(runtime.group_co_members(&account.account_id_hex).await?)
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

    fn account(local_signing: bool, signed_out: bool) -> AccountSummary {
        AccountSummary {
            label: "alice".to_owned(),
            account_id_hex: "aa".repeat(32),
            local_signing,
            external_signing: false,
            signed_out,
        }
    }

    /// Group co-members come from live MLS sessions, which only an account
    /// with a usable signing identity has. Asking on behalf of a watch-only or
    /// signed-out account is a category error, and the runtime refuses it --
    /// so a search for one of those accounts must not ask, or the enhancement
    /// would turn into a failed search for people who can still search fine
    /// today.
    #[tokio::test]
    async fn an_account_that_cannot_sign_is_never_asked_for_co_members() {
        for summary in [account(false, false), account(true, true)] {
            let seeds = radius_one_seeds(None, &summary, 1)
                .await
                .expect("no MLS session means no co-members, not an error");
            assert!(seeds.is_empty());
        }
    }

    #[tokio::test]
    async fn a_search_without_a_runtime_asks_for_no_co_members() {
        let seeds = radius_one_seeds(None, &account(true, false), 1)
            .await
            .expect("no runtime yields no seeds rather than failing");
        assert!(seeds.is_empty());
    }

    /// Radius-1 seeds cannot affect a window that stops at radius 0, so the
    /// per-group membership read is skipped rather than paid for nothing.
    #[tokio::test]
    async fn a_radius_zero_window_asks_for_no_co_members() {
        let seeds = radius_one_seeds(None, &account(true, false), 0)
            .await
            .expect("a radius-0 window needs no seeds");
        assert!(seeds.is_empty());
    }

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
