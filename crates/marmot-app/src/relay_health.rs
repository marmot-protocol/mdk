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

use std::collections::BTreeMap;

use nostr_directory::AccountRelayListStatus;
use transport_nostr::{
    RelayEndpointClassification, RelayEndpointPolicy, RelayLivenessStatus, canonical_relay,
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
    /// Why the relay is not allowed; set exactly when `state` is `NotAllowed`.
    pub fault: Option<RelayHealthFault>,
    /// The connection state `account_relay_liveness` reports, passed through.
    pub liveness: RelayLivenessStatus,
}

impl std::fmt::Debug for RelayHealthRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayHealthRow")
            .field("url", &"<redacted>")
            .field("roles", &self.roles)
            .field("state", &self.state)
            .field("fault", &self.fault)
            .field("liveness", &self.liveness)
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

/// What MDK knows of a relay. Only `Unchecked` and `NotAllowed` are produced
/// yet; the others are reserved for checks of relays that come later.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayHealthState {
    /// Allowed, and not checked.
    Unchecked,
    /// Not produced yet.
    Healthy,
    /// Not produced yet.
    Suspected,
    /// Not produced yet.
    Failing,
    /// The relay policy refuses it: this device never dials it.
    NotAllowed,
}

/// Why a relay is not allowed, as the relay policy classifies it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayHealthFault {
    /// On the retired-relay list.
    Retired,
    /// Not a relay URL.
    Invalid,
    /// A host this device refuses to dial: plaintext, a private address,
    /// localhost or onion.
    Unsafe,
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
    /// Critical: the published inbox list names relays but the policy allows
    /// none. This device never listens on them, so an invitation sent through
    /// the list cannot reach it. A sender on this same install (another local
    /// account, or this account linking a new device) resolves the route
    /// through the same fallback to the defaults and may still get through.
    /// `relays` are the entries not allowed.
    NoAllowedInboxRelay,
    /// Warning: the published inbox list names relays the policy refuses
    /// beside at least one it allows. This device never listens on the refused
    /// ones, so an invitation sent only to them does not reach it. `relays`
    /// are the entries not allowed.
    InboxRelaysNotAllowed,
    /// Notice: exactly one entry of the published inbox list is allowed, so
    /// this device's inbox route is that one relay and an invitation sent
    /// through the list reaches it only there. `relays` is that relay.
    SingleInboxRelay,
}

impl RelayWarningKind {
    pub fn severity(self) -> RelayWarningSeverity {
        match self {
            Self::InboxListEmpty | Self::NoAllowedInboxRelay => RelayWarningSeverity::Critical,
            Self::InboxRelaysNotAllowed => RelayWarningSeverity::Warning,
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
            Self::InboxRelaysNotAllowed => vec![RelayRepairAction::RemoveInboxRelay],
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
/// by `classify` (the relay plane's dial policy) and liveness left `Unknown`
/// for the caller to fill in. Only lists and policy decide the answer, so two
/// answers from here differ exactly when a host should read it again.
pub(crate) fn account_relay_health(
    lists: &AccountRelayListStatus,
    classify: impl FnOnce(Vec<String>) -> Vec<RelayEndpointClassification>,
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
            let fault = match classification.policy {
                RelayEndpointPolicy::Allowed => None,
                RelayEndpointPolicy::Retired => Some(RelayHealthFault::Retired),
                RelayEndpointPolicy::Invalid => Some(RelayHealthFault::Invalid),
                RelayEndpointPolicy::Unsafe => Some(RelayHealthFault::Unsafe),
            };
            RelayHealthRow {
                url,
                roles,
                state: if fault.is_some() {
                    RelayHealthState::NotAllowed
                } else {
                    RelayHealthState::Unchecked
                },
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
    let (allowed, refused): (Vec<_>, Vec<_>) = rows
        .iter()
        .filter(|row| row.roles.contains(&RelayRole::Inbox))
        .partition(|row| row.fault.is_none());
    let urls = |rows: &[&RelayHealthRow]| rows.iter().map(|row| row.url.clone()).collect();
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
        match (allowed.len(), refused.is_empty()) {
            (0, true) => warn(RelayWarningKind::InboxListEmpty, Vec::new()),
            (0, false) => warn(RelayWarningKind::NoAllowedInboxRelay, urls(&refused)),
            (_, false) => warn(RelayWarningKind::InboxRelaysNotAllowed, urls(&refused)),
            (_, true) => {}
        }
        if allowed.len() == 1 {
            warn(RelayWarningKind::SingleInboxRelay, urls(&allowed));
        }
    }
    warnings.sort_by_key(|warning| std::cmp::Reverse(warning.severity));
    AccountRelayHealth {
        inbox_list,
        falls_back_to_defaults: allowed.is_empty(),
        highest_severity: warnings.first().map(|warning| warning.severity),
        rows,
        warnings,
    }
}

impl crate::MarmotApp {
    /// [`account_relay_health`] for a local account, from its cached lists
    /// under the relay plane's own dial policy.
    pub(crate) fn account_relay_health(
        &self,
        label: &str,
    ) -> Result<AccountRelayHealth, crate::AppError> {
        let lists = self.account_relay_list_status(label)?;
        Ok(account_relay_health(&lists, |urls| {
            self.relay_plane.classify_relay_endpoints(urls)
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use transport_nostr::RelaySafetyPolicy;

    use RelayWarningKind::{
        InboxListEmpty, InboxRelaysNotAllowed, NoAllowedInboxRelay, SingleInboxRelay,
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
        account_relay_health(lists, |urls| {
            RelaySafetyPolicy::default().classify_endpoints(urls)
        })
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
}
