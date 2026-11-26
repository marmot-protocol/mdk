//! What the account's held relay lists and the relay policy say about
//! invitations sent through its published inbox list. Nothing here dials,
//! waits on a relay or stores anything.
//!
//! A sender on another install sends an invitation (Welcome) to the relays of
//! the account's published inbox list (kind 10050); an MDK sender finds no
//! route when that list is empty or the policy allows none of it, and never
//! falls back to defaults. This device's inbox route is the entries of the
//! list the policy allows, or the configured defaults when it allows none. So
//! when the list allows no relay, an invitation sent through it cannot reach
//! this device. A sender on this same install (another local account, or this
//! account linking a new device) resolves the route through the same fallback
//! to the defaults and may still get through.
//!
//! The answer describes the route MDK builds from the held lists. A device
//! running with an older route takes the new one at its next routing refresh,
//! so a warning that clears says the lists are fixed, not yet that this device
//! listens on them.
//!
//! MDK keeps no record that a read found no inbox list: an account whose cache
//! holds none may simply not have loaded it yet. That answer is
//! [`RelayListPresence::Unknown`], never a warning. NIP-65 write relays get
//! rows but no warning: when none is allowed, this device publishes its
//! KeyPackages to its defaults and an MDK sender that allows none reads them
//! from its own, so what MDK holds cannot say that invitations will not arrive.
//!
//! An inbox check ([`checks`]) adds what the lists cannot say: whether a
//! relay serves this account's inbox when asked. Its results move a row's
//! state and raise warnings of their own.

use std::collections::{BTreeMap, BTreeSet};

use nostr_directory::AccountRelayListStatus;
use transport_nostr::{
    RelayEndpointClassification, RelayEndpointPolicy, RelayLivenessStatus, canonical_relay,
};

mod checks;
pub(crate) use checks::{
    CheckRecord, CheckSnapshot, RunInputs, RunOutcome, run as run_inbox_check,
};

/// The account's relay health: one row per relay it uses and the warnings
/// those rows raise. Relay URLs here are display data for the account's owner.
#[derive(Clone, PartialEq, Eq)]
pub struct AccountRelayHealth {
    /// Whether MDK holds the account's inbox list. Inbox warnings need it.
    pub inbox_list: RelayListPresence,
    /// One row per relay of the inbox and NIP-65 lists, ordered by URL.
    pub rows: Vec<RelayHealthRow>,
    /// Ordered from the most severe.
    pub warnings: Vec<AccountRelayWarning>,
    /// The severity of the first warning, `None` without warnings.
    pub highest_severity: Option<RelayWarningSeverity>,
    /// The inbox route MDK builds for this device from the held lists is the
    /// configured defaults, because no inbox relay it holds is allowed. Also
    /// true while the inbox list is [`RelayListPresence::Unknown`], when the
    /// real list may name those same relays, so on its own it says nothing
    /// about invitations; the warnings do.
    pub falls_back_to_defaults: bool,
}

impl std::fmt::Debug for AccountRelayHealth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountRelayHealth")
            .field("inbox_list", &self.inbox_list)
            .field("rows", &self.rows.len())
            .field("warnings", &self.warnings)
            .field("highest_severity", &self.highest_severity)
            .field("falls_back_to_defaults", &self.falls_back_to_defaults)
            .finish()
    }
}

/// Whether MDK holds one of the account's relay lists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayListPresence {
    /// No copy is held: it has not been loaded yet, or none was published.
    /// MDK cannot tell which from what it holds.
    Unknown,
    /// A published list is held, possibly an empty one.
    Published,
}

/// One relay the account's lists name.
#[derive(Clone, PartialEq, Eq)]
pub struct RelayHealthRow {
    /// The relay's canonical URL, the key of `account_relay_liveness` rows;
    /// an entry that does not parse appears as published, trimmed.
    pub url: String,
    /// The lists naming it, in the order Inbox, Write, Read.
    pub roles: Vec<RelayRole>,
    pub state: RelayHealthState,
    /// Why the relay is not allowed (`NotAllowed`), what it refused
    /// (`Failing`) or why the check could not verify it (`Suspected`). Set
    /// for those three states, never for `Unchecked` or `Healthy`.
    pub fault: Option<RelayHealthFault>,
    /// The connection state `account_relay_liveness` reports, passed through.
    pub liveness: RelayLivenessStatus,
    /// When the inbox check that decided `state` asked the relay, in Unix
    /// seconds; `None` while no check has established anything about it.
    pub checked_at_unix: Option<u64>,
    /// An inbox check of this relay is running.
    pub checking: bool,
}

impl std::fmt::Debug for RelayHealthRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayHealthRow")
            .field("url", &"<redacted>")
            .field("roles", &self.roles)
            .field("state", &self.state)
            .field("fault", &self.fault)
            .field("liveness", &self.liveness)
            .field("checked_at_unix", &self.checked_at_unix)
            .field("checking", &self.checking)
            .finish()
    }
}

/// A list that names a relay.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RelayRole {
    /// The inbox list (kind 10050), where senders send invitations.
    Inbox,
    /// A NIP-65 (kind 10002) write relay, marked write or unmarked.
    Write,
    /// A NIP-65 read relay, marked read or unmarked.
    Read,
}

/// What MDK knows of a relay. A check's states (`Healthy`, `Suspected`,
/// `Failing`) describe one read of the account's inbox at `checked_at_unix`
/// and apply to inbox rows only; a relay the lists name only for NIP-65 is
/// never checked. Results belong to the account worker's client and go with
/// it: they last while the account runs and are never stored. Later
/// versions may append states: keep a default branch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayHealthState {
    /// Allowed, and no check has established anything about it.
    Unchecked,
    /// The relay answered the inbox check: it ended a query for this
    /// account's gift wraps (kind 1059 addressed to it) with EOSE, retried
    /// after authenticating when it asked for that. An EOSE that says the
    /// relay may withhold events until authentication (NIP-67 `auth`) still
    /// counts: the check proves the relay answered, not that it held back
    /// nothing.
    Healthy,
    /// The check could not verify the relay: it did not connect or answer
    /// in time while another relay of the same check answered, or it
    /// refused or ended the query while the account's signer is a remote
    /// or host signer that may not have answered its authentication
    /// challenge, or it refused authentication with a reply the check could
    /// not read (so a refusal cannot be told from a rate limit), or it ended
    /// the query without naming a refusal. `fault` says which. Render it as "could not verify", never as a failure.
    Suspected,
    /// The relay refused to serve this account's inbox when checked, with
    /// the account's own key answering any authentication challenge: it
    /// required authentication and refused it, required payment, or
    /// restricted or blocked the account. `fault` says which. A refusal
    /// like that does not change by asking again.
    Failing,
    /// The relay policy refuses it: this device never dials it.
    NotAllowed,
}

/// Why a relay's row is not `Unchecked` or `Healthy`. Later versions may
/// append faults: keep a default branch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayHealthFault {
    /// `NotAllowed`: on the retired-relay list.
    Retired,
    /// `NotAllowed`: not a relay URL.
    Invalid,
    /// `NotAllowed`: a host this device refuses to dial: plaintext, a
    /// private address, localhost or onion.
    Unsafe,
    /// `Failing` or `Suspected`: the relay required authentication
    /// (`auth-required:`) and did not accept the account's.
    AuthenticationRequired,
    /// `Failing` or `Suspected`: the relay required payment
    /// (`payment-required:`).
    PaymentRequired,
    /// `Failing` or `Suspected`: the relay restricted or blocked the
    /// account (`restricted:`, `blocked:`).
    Restricted,
    /// `Suspected`: no connection to the relay.
    Unreachable,
    /// `Suspected`: the relay did not answer within the check's time.
    TimedOut,
    /// `Suspected`: the relay ended the query without naming a refusal (an
    /// error or invalid-request close), or sent more than it was asked for.
    Unexplained,
}

/// A problem with the account's relay setup.
#[derive(Clone, PartialEq, Eq)]
pub struct AccountRelayWarning {
    pub kind: RelayWarningKind,
    pub severity: RelayWarningSeverity,
    /// The relays the warning is about, as row URLs.
    pub relays: Vec<String>,
    /// What would fix it, in order.
    pub actions: Vec<RelayRepairAction>,
}

impl std::fmt::Debug for AccountRelayWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountRelayWarning")
            .field("kind", &self.kind)
            .field("severity", &self.severity)
            .field("relays", &self.relays.len())
            .field("actions", &self.actions)
            .finish()
    }
}

/// The problem a warning reports. Each needs a published inbox list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayWarningKind {
    /// Critical: the published inbox list names no relay, so an invitation
    /// sent through it has nowhere to go. A sender on this same install
    /// (another local account, or this account linking a new device) resolves
    /// the route through the same fallback to the defaults and may still get
    /// through. `relays` is empty.
    InboxListEmpty,
    /// Critical: the published inbox list names relays and every one is
    /// either refused by the policy or `Failing`. This device never listens
    /// on a refused one, so an invitation sent through the list cannot reach
    /// it there; and each failing one refused to serve this account's inbox
    /// when checked (see its row's `checked_at_unix`). When the policy allows
    /// none, a sender on this same install (another local account, or this
    /// account linking a new device) resolves the route through the same
    /// fallback to the defaults and may still get through. `relays` are every
    /// entry. An `Unchecked` or `Suspected` entry never raises it.
    NoAllowedInboxRelay,
    /// Warning: the published inbox list names relays the policy refuses
    /// beside at least one it allows that is not `Failing`. This device never
    /// listens on the refused ones, so an invitation sent only to them does
    /// not reach it. `relays` are the entries not allowed.
    InboxRelaysNotAllowed,
    /// Notice: exactly one entry of the published inbox list is allowed and
    /// not `Failing`, so an invitation sent through the list reaches this
    /// device at most there. `relays` is that relay.
    SingleInboxRelay,
    /// Warning: an entry of the published inbox list is `Failing`, beside at
    /// least one allowed entry that is not: the failing relay refused to serve
    /// this account's inbox when checked (see its row's `checked_at_unix`).
    /// `relays` are the failing entries.
    InboxRelayFailing,
}

impl RelayWarningKind {
    pub fn severity(self) -> RelayWarningSeverity {
        match self {
            Self::InboxListEmpty | Self::NoAllowedInboxRelay => RelayWarningSeverity::Critical,
            Self::InboxRelaysNotAllowed | Self::InboxRelayFailing => RelayWarningSeverity::Warning,
            Self::SingleInboxRelay => RelayWarningSeverity::Notice,
        }
    }

    fn actions(self) -> Vec<RelayRepairAction> {
        match self {
            Self::InboxListEmpty | Self::SingleInboxRelay => vec![RelayRepairAction::AddInboxRelay],
            Self::NoAllowedInboxRelay => vec![
                RelayRepairAction::RemoveInboxRelay,
                RelayRepairAction::AddInboxRelay,
            ],
            Self::InboxRelaysNotAllowed | Self::InboxRelayFailing => {
                vec![RelayRepairAction::RemoveInboxRelay]
            }
        }
    }
}

/// How loudly a host presents a warning; ordered from the least severe.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RelayWarningSeverity {
    Notice,
    Warning,
    Critical,
}

/// A change to the account's relay lists that would fix a warning. The user
/// makes it; MDK never edits or republishes a list on its own. When a warning
/// lists both actions, make them one list edit: removing every entry first
/// would save an empty inbox list, which `set_account_inbox_relays` rejects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayRepairAction {
    /// Add an allowed relay to the inbox list.
    AddInboxRelay,
    /// Remove the warning's relays from the inbox list.
    RemoveInboxRelay,
}

/// The account's relay health from its held `lists`, with every relay judged
/// by `classify` (the relay plane's dial policy) and each allowed inbox
/// relay's state by its last established inbox check in `checks`, and
/// liveness left `Unknown` for the caller to fill in. Lists, policy and check
/// states decide the answer; [`AccountRelayHealth::announced`] is the part
/// whose change a host is told of.
pub(crate) fn account_relay_health(
    lists: &AccountRelayListStatus,
    classify: impl FnOnce(Vec<String>) -> Vec<RelayEndpointClassification>,
    checks: &CheckSnapshot,
) -> AccountRelayHealth {
    let mut roles: BTreeMap<String, Vec<RelayRole>> = BTreeMap::new();
    let named = [
        (RelayRole::Inbox, &lists.inbox.relays),
        (RelayRole::Write, &lists.nip65.relays),
        (RelayRole::Write, &lists.nip65.write_relays),
        (RelayRole::Read, &lists.nip65.read_relays),
    ];
    for (role, relays) in named {
        for relay in relays {
            let url = canonical_relay(relay);
            let row = roles.entry(url).or_default();
            if !row.contains(&role) {
                row.push(role);
            }
        }
    }
    // The classifier keeps the order and number of its input.
    let classified = classify(roles.keys().cloned().collect());
    let rows = roles
        .into_iter()
        .zip(classified)
        .map(|((url, roles), classification)| {
            let inbox = roles.contains(&RelayRole::Inbox);
            let check = checks.results.get(&url).filter(|_| inbox);
            let (state, fault) = match (policy_fault(classification.policy), check) {
                (Some(fault), _) => (RelayHealthState::NotAllowed, Some(fault)),
                (None, Some(check)) => (check.state, check.fault),
                (None, None) => (RelayHealthState::Unchecked, None),
            };
            RelayHealthRow {
                checked_at_unix: check
                    .filter(|_| state != RelayHealthState::NotAllowed)
                    .map(|check| check.checked_at_unix),
                checking: inbox && checks.checking.contains(&url),
                url,
                roles,
                state,
                fault,
                liveness: RelayLivenessStatus::Unknown,
            }
        })
        .collect::<Vec<_>>();

    // A cache record written before list timestamps were kept has none, but
    // its relays are still a published list.
    let inbox_list = if lists.inbox.created_at > 0 || !lists.inbox.relays.is_empty() {
        RelayListPresence::Published
    } else {
        RelayListPresence::Unknown
    };
    let inbox = rows
        .iter()
        .filter(|row| row.roles.contains(&RelayRole::Inbox))
        .collect::<Vec<_>>();
    let urls = |state: fn(RelayHealthState) -> bool| {
        inbox
            .iter()
            .filter(|row| state(row.state))
            .map(|row| row.url.clone())
            .collect::<Vec<_>>()
    };
    // Usable: allowed and not failing. Unchecked and suspected relays count,
    // so only a refusal a check established can take an entry out.
    let usable = urls(|state| {
        !matches!(
            state,
            RelayHealthState::NotAllowed | RelayHealthState::Failing
        )
    });
    let refused = urls(|state| state == RelayHealthState::NotAllowed);
    let failing = urls(|state| state == RelayHealthState::Failing);
    let mut warnings = Vec::new();
    if inbox_list == RelayListPresence::Published {
        let mut warn = |kind: RelayWarningKind, relays: Vec<String>| {
            warnings.push(AccountRelayWarning {
                kind,
                severity: kind.severity(),
                relays,
                actions: kind.actions(),
            });
        };
        if inbox.is_empty() {
            warn(RelayWarningKind::InboxListEmpty, Vec::new());
        } else if usable.is_empty() {
            warn(
                RelayWarningKind::NoAllowedInboxRelay,
                inbox.iter().map(|row| row.url.clone()).collect(),
            );
        } else {
            if !refused.is_empty() {
                warn(RelayWarningKind::InboxRelaysNotAllowed, refused);
            }
            if !failing.is_empty() {
                warn(RelayWarningKind::InboxRelayFailing, failing);
            }
            if usable.len() == 1 {
                warn(RelayWarningKind::SingleInboxRelay, usable);
            }
        }
    }
    warnings.sort_by_key(|warning| std::cmp::Reverse(warning.severity));
    AccountRelayHealth {
        inbox_list,
        falls_back_to_defaults: inbox
            .iter()
            .all(|row| row.state == RelayHealthState::NotAllowed),
        highest_severity: warnings.first().map(|warning| warning.severity),
        rows,
        warnings,
    }
}

fn policy_fault(policy: RelayEndpointPolicy) -> Option<RelayHealthFault> {
    match policy {
        RelayEndpointPolicy::Allowed => None,
        RelayEndpointPolicy::Retired => Some(RelayHealthFault::Retired),
        RelayEndpointPolicy::Invalid => Some(RelayHealthFault::Invalid),
        RelayEndpointPolicy::Unsafe => Some(RelayHealthFault::Unsafe),
    }
}

impl AccountRelayHealth {
    /// The answer a host is told changed: without liveness, when each relay
    /// was last checked or whether a check runs, so a check that confirms
    /// the answer announces nothing.
    pub(crate) fn announced(mut self) -> Self {
        for row in &mut self.rows {
            row.liveness = RelayLivenessStatus::Unknown;
            row.checked_at_unix = None;
            row.checking = false;
        }
        self
    }

    /// The allowed inbox entries, the first [`checks::MAX_CHECKED_RELAYS`]
    /// by URL: what an inbox check dials.
    pub(crate) fn checkable_inbox_relays(&self) -> BTreeSet<String> {
        self.rows
            .iter()
            .filter(|row| {
                row.roles.contains(&RelayRole::Inbox) && row.state != RelayHealthState::NotAllowed
            })
            .take(checks::MAX_CHECKED_RELAYS)
            .map(|row| row.url.clone())
            .collect()
    }
}

impl crate::MarmotApp {
    /// [`account_relay_health`] for a local account, from its cached lists
    /// under the relay plane's own dial policy and the account worker's
    /// inbox checks (`checks`, empty while no worker runs).
    pub(crate) fn account_relay_health(
        &self,
        label: &str,
        checks: &CheckSnapshot,
    ) -> Result<AccountRelayHealth, crate::AppError> {
        let lists = self.account_relay_list_status(label)?;
        Ok(account_relay_health(
            &lists,
            |urls| self.relay_plane.classify_relay_endpoints(urls),
            checks,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::checks::CheckRecord;
    use super::*;
    use transport_nostr::RelaySafetyPolicy;

    use RelayWarningKind::{
        InboxListEmpty, InboxRelayFailing, InboxRelaysNotAllowed, NoAllowedInboxRelay,
        SingleInboxRelay,
    };
    use RelayWarningSeverity::{Critical, Notice, Warning};

    fn retired() -> String {
        format!(
            "wss://{}",
            crate::retired_relay_hosts()
                .first()
                .expect("a configured retired host")
        )
    }

    /// Lists with `inbox` published, or none held when `None`, and one
    /// NIP-65 relay. A "legacy" case's inbox has no timestamp, as cache
    /// records written before timestamps were kept.
    fn lists(case: &str, inbox: Option<Vec<String>>) -> AccountRelayListStatus {
        let mut lists = AccountRelayListStatus::empty();
        lists.nip65.created_at = 10;
        lists.nip65.relays = vec!["wss://write.example".into()];
        lists.nip65.write_relays = lists.nip65.relays.clone();
        if let Some(inbox) = inbox {
            lists.inbox.created_at = if case.starts_with("legacy") { 0 } else { 10 };
            lists.inbox.relays = inbox;
        }
        lists.refresh();
        lists
    }

    fn health(lists: &AccountRelayListStatus) -> AccountRelayHealth {
        checked_health(lists, &CheckSnapshot::default())
    }

    fn checked_health(
        lists: &AccountRelayListStatus,
        checks: &CheckSnapshot,
    ) -> AccountRelayHealth {
        account_relay_health(
            lists,
            |urls| RelaySafetyPolicy::default().classify_endpoints(urls),
            checks,
        )
    }

    /// Each inbox setup raises exactly the warnings its condition names, and
    /// an inbox list MDK does not hold raises none: a wrong Critical on a
    /// healthy account that has not loaded its list yet is the worst answer.
    /// A list whose every entry is refused raises a Critical where the device
    /// used to fall back to the defaults with no warning at all.
    #[test]
    fn inbox_setups_raise_exactly_their_warnings() {
        let a = "wss://a.example".to_owned();
        let b = "wss://b.example".to_owned();
        // (case, inbox list held, presence, listening on defaults, warnings)
        type Case<'a> = (
            &'a str,
            Option<Vec<String>>,
            RelayListPresence,
            bool,
            &'a [(RelayWarningKind, RelayWarningSeverity, Vec<String>)],
        );
        let cases: [Case; 8] = [
            ("not loaded", None, RelayListPresence::Unknown, true, &[]),
            (
                "empty",
                Some(vec![]),
                RelayListPresence::Published,
                true,
                &[(InboxListEmpty, Critical, vec![])],
            ),
            (
                "single",
                Some(vec![a.clone()]),
                RelayListPresence::Published,
                false,
                &[(SingleInboxRelay, Notice, vec![a.clone()])],
            ),
            (
                "one retired among several",
                Some(vec![a.clone(), retired(), b.clone()]),
                RelayListPresence::Published,
                false,
                &[(InboxRelaysNotAllowed, Warning, vec![retired()])],
            ),
            (
                "one retired beside a single allowed",
                Some(vec![retired(), a.clone()]),
                RelayListPresence::Published,
                false,
                &[
                    (InboxRelaysNotAllowed, Warning, vec![retired()]),
                    (SingleInboxRelay, Notice, vec![a.clone()]),
                ],
            ),
            (
                "none allowed",
                Some(vec![
                    retired(),
                    "ws://plain.example".into(),
                    "not a url".into(),
                ]),
                RelayListPresence::Published,
                true,
                &[(
                    NoAllowedInboxRelay,
                    Critical,
                    vec!["not a url".into(), "ws://plain.example".into(), retired()],
                )],
            ),
            (
                "healthy",
                Some(vec![a.clone(), b.clone()]),
                RelayListPresence::Published,
                false,
                &[],
            ),
            (
                "legacy, one retired",
                Some(vec![a.clone(), retired(), b.clone()]),
                RelayListPresence::Published,
                false,
                &[(InboxRelaysNotAllowed, Warning, vec![retired()])],
            ),
        ];
        for (case, inbox, presence, on_defaults, expected) in cases {
            let health = health(&lists(case, inbox));
            let warnings = health
                .warnings
                .iter()
                .map(|warning| (warning.kind, warning.severity, warning.relays.clone()))
                .collect::<Vec<_>>();
            assert_eq!(warnings, expected, "{case}");
            assert_eq!(health.inbox_list, presence, "{case}");
            assert_eq!(health.falls_back_to_defaults, on_defaults, "{case}");
            assert_eq!(
                health.highest_severity,
                expected.first().map(|(_, severity, _)| *severity),
                "{case}"
            );
        }
    }

    /// A relay several lists name is one row with each role once, and a
    /// refused relay says why, whichever list names it.
    #[test]
    fn rows_join_roles_and_carry_the_policy_fault() {
        let mut lists = lists("rows", Some(vec!["wss://a.example/".into(), retired()]));
        lists.nip65.read_relays = vec!["wss://A.example".into(), "ws://plain.example".into()];
        let health = health(&lists);
        let rows = health
            .rows
            .iter()
            .map(|row| (row.url.as_str(), row.roles.clone(), row.state, row.fault))
            .collect::<Vec<_>>();
        let retired = retired();
        assert_eq!(
            rows,
            vec![
                (
                    "ws://plain.example",
                    vec![RelayRole::Read],
                    RelayHealthState::NotAllowed,
                    Some(RelayHealthFault::Unsafe)
                ),
                (
                    "wss://a.example",
                    vec![RelayRole::Inbox, RelayRole::Read],
                    RelayHealthState::Unchecked,
                    None
                ),
                (
                    retired.as_str(),
                    vec![RelayRole::Inbox],
                    RelayHealthState::NotAllowed,
                    Some(RelayHealthFault::Retired)
                ),
                (
                    "wss://write.example",
                    vec![RelayRole::Write],
                    RelayHealthState::Unchecked,
                    None
                ),
            ]
        );
    }

    /// What one check run establishes per relay. An answer decides at once;
    /// a refusal is `Failing` only under the account's own key, which always
    /// answers authentication; a rate limit is never a fault; and silence
    /// counts only beside a relay of the same run that answered, so a run
    /// from an offline device changes nothing.
    #[test]
    fn a_check_run_establishes_only_what_an_answer_proves() {
        use RelayHealthFault as F;
        use RelayHealthState::{Failing, Healthy, Suspected};
        use transport_nostr::DirectoryInspectionError::*;

        let run = |results: &[(&str, Result<(), transport_nostr::DirectoryInspectionError>)],
                   local_key: bool| {
            checks::established(
                results
                    .iter()
                    .map(|(relay, result)| ((*relay).to_owned(), result.clone()))
                    .collect(),
                local_key,
                7,
            )
            .into_iter()
            .map(|(relay, record)| {
                let record = record.map(|record| {
                    assert_eq!(record.checked_at_unix, 7);
                    (record.state, record.fault)
                });
                (relay, record)
            })
            .collect::<Vec<_>>()
        };
        let results = [
            ("a-served", Ok(())),
            ("b-auth", Err(AuthenticationRequired)),
            ("c-pay", Err(PaymentRequired)),
            ("d-restricted", Err(Restricted)),
            ("e-rate-limited", Err(RateLimited)),
            ("e2-auth-rate-limited", Err(AuthenticationRateLimited)),
            ("e3-auth-unread", Err(AuthenticationUnconfirmed)),
            ("e4-auth-signing", Err(AuthenticationTimedOut)),
            ("f-unexplained", Err(Unexplained)),
            ("g-closed-port", Err(Unreachable)),
            ("h-silent", Err(TimedOut)),
        ];
        let owned = |relay: &str| relay.to_owned();
        for (local_key, refused) in [(true, Failing), (false, Suspected)] {
            assert_eq!(
                run(&results, local_key),
                vec![
                    (owned("a-served"), Some((Healthy, None))),
                    (
                        owned("b-auth"),
                        Some((refused, Some(F::AuthenticationRequired)))
                    ),
                    (owned("c-pay"), Some((refused, Some(F::PaymentRequired)))),
                    (owned("d-restricted"), Some((refused, Some(F::Restricted)))),
                    (owned("e-rate-limited"), None),
                    (owned("e2-auth-rate-limited"), None),
                    (
                        owned("e3-auth-unread"),
                        Some((Suspected, Some(F::AuthenticationRequired)))
                    ),
                    (
                        owned("e4-auth-signing"),
                        Some((Suspected, Some(F::AuthenticationRequired)))
                    ),
                    (
                        owned("f-unexplained"),
                        Some((Suspected, Some(F::Unexplained)))
                    ),
                    (
                        owned("g-closed-port"),
                        Some((Suspected, Some(F::Unreachable)))
                    ),
                    (owned("h-silent"), Some((Suspected, Some(F::TimedOut)))),
                ],
                "local key: {local_key}"
            );
        }
        // A rate limit is an answer: the relay is there.
        assert_eq!(
            run(&[("a", Err(RateLimited)), ("b", Err(Unreachable))], true),
            vec![
                (owned("a"), None),
                (owned("b"), Some((Suspected, Some(F::Unreachable))))
            ]
        );
        // No relay answered: nothing is established.
        assert_eq!(
            run(&[("a", Err(Unreachable)), ("b", Err(TimedOut))], true),
            vec![(owned("a"), None), (owned("b"), None)]
        );
        assert_eq!(
            run(&[("a", Err(Unreachable))], true),
            vec![(owned("a"), None)]
        );
    }

    /// Check states raise their warnings: a failing relay beside a usable
    /// one is a Warning, and the Critical fires once every entry is refused
    /// or failing. An unchecked or suspected entry keeps the list usable, so
    /// it never makes a Critical.
    #[test]
    fn failing_inbox_relays_raise_warnings_and_unverified_ones_none() {
        use RelayHealthState::{Failing, Healthy, Suspected};
        let a = "wss://a.example".to_owned();
        let b = "wss://b.example".to_owned();
        let checks = |states: &[(&str, RelayHealthState)]| CheckSnapshot {
            results: states
                .iter()
                .map(|(url, state)| {
                    let fault = match state {
                        Failing => Some(RelayHealthFault::AuthenticationRequired),
                        Suspected => Some(RelayHealthFault::Unreachable),
                        _ => None,
                    };
                    (
                        (*url).to_owned(),
                        CheckRecord {
                            state: *state,
                            fault,
                            checked_at_unix: 9,
                        },
                    )
                })
                .collect(),
            checking: Default::default(),
        };
        type Case<'a> = (
            &'a str,
            Vec<String>,
            CheckSnapshot,
            Vec<(RelayWarningKind, RelayWarningSeverity, Vec<String>)>,
        );
        let cases: [Case; 6] = [
            (
                "one failing beside a healthy",
                vec![a.clone(), b.clone()],
                checks(&[(&a, Failing), (&b, Healthy)]),
                vec![
                    (InboxRelayFailing, Warning, vec![a.clone()]),
                    (SingleInboxRelay, Notice, vec![b.clone()]),
                ],
            ),
            (
                "one failing beside an unchecked",
                vec![a.clone(), b.clone()],
                checks(&[(&a, Failing)]),
                vec![
                    (InboxRelayFailing, Warning, vec![a.clone()]),
                    (SingleInboxRelay, Notice, vec![b.clone()]),
                ],
            ),
            (
                "every entry failing",
                vec![a.clone(), b.clone()],
                checks(&[(&a, Failing), (&b, Failing)]),
                vec![(NoAllowedInboxRelay, Critical, vec![a.clone(), b.clone()])],
            ),
            (
                "failing beside a retired relay",
                vec![a.clone(), retired()],
                checks(&[(&a, Failing)]),
                vec![(NoAllowedInboxRelay, Critical, vec![a.clone(), retired()])],
            ),
            (
                "every entry suspected",
                vec![a.clone(), b.clone()],
                checks(&[(&a, Suspected), (&b, Suspected)]),
                vec![],
            ),
            (
                "suspected beside a retired relay",
                vec![a.clone(), retired()],
                checks(&[(&a, Suspected)]),
                vec![
                    (InboxRelaysNotAllowed, Warning, vec![retired()]),
                    (SingleInboxRelay, Notice, vec![a.clone()]),
                ],
            ),
        ];
        for (case, inbox, checks, expected) in cases {
            let health = checked_health(&lists(case, Some(inbox)), &checks);
            let warnings = health
                .warnings
                .iter()
                .map(|warning| (warning.kind, warning.severity, warning.relays.clone()))
                .collect::<Vec<_>>();
            assert_eq!(warnings, expected, "{case}");
            assert!(!health.falls_back_to_defaults, "{case}");
        }
    }

    /// A check's state reaches only an allowed inbox row, which carries when
    /// it was asked; the announced answer leaves out check times and checks
    /// in progress, so a check that confirms every state announces nothing.
    #[test]
    fn check_results_reach_inbox_rows_and_confirmations_announce_nothing() {
        let a = "wss://a.example".to_owned();
        let mut lists = lists("rows", Some(vec![a.clone(), retired()]));
        lists.nip65.read_relays = vec!["wss://read.example".into()];
        let record = |checked_at_unix| CheckRecord {
            state: RelayHealthState::Healthy,
            fault: None,
            checked_at_unix,
        };
        let snapshot = |checked_at_unix, checking: &[&str]| CheckSnapshot {
            results: [&a, &retired(), &"wss://read.example".to_owned()]
                .into_iter()
                .map(|url| (url.clone(), record(checked_at_unix)))
                .collect(),
            checking: checking.iter().map(|url| (*url).to_owned()).collect(),
        };
        let first = checked_health(&lists, &snapshot(5, &[]));
        let rows = first
            .rows
            .iter()
            .map(|row| (row.url.clone(), row.state, row.checked_at_unix))
            .collect::<Vec<_>>();
        assert_eq!(
            rows,
            vec![
                (a.clone(), RelayHealthState::Healthy, Some(5)),
                (
                    "wss://read.example".into(),
                    RelayHealthState::Unchecked,
                    None
                ),
                (retired(), RelayHealthState::NotAllowed, None),
                (
                    "wss://write.example".into(),
                    RelayHealthState::Unchecked,
                    None
                ),
            ]
        );
        let again = checked_health(&lists, &snapshot(6, &[&a, "wss://read.example"]));
        let checking = again
            .rows
            .iter()
            .filter(|row| row.checking)
            .map(|row| row.url.clone())
            .collect::<Vec<_>>();
        assert_eq!(checking, vec![a.clone()]);
        assert_ne!(first, again);
        assert_eq!(first.announced(), again.announced());
    }
}
