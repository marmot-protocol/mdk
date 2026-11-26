//! Relay telemetry, relay-list, and relay-health FFI conversions.

use marmot_app::{
    AccountRelayListState, AccountRelayListStatus, MissingRelayListKind,
    RelayEndpointClassification, RelayEndpointPolicy, RelayPlaneHealth, RelayTelemetryResource,
    RelayTelemetryRuntimeConfig, RelayTelemetrySettings,
};

#[derive(Clone, Debug, uniffi::Record)]
pub struct RelayTelemetrySettingsFfi {
    pub export_enabled: bool,
    pub export_interval_seconds: u64,
}

impl From<RelayTelemetrySettings> for RelayTelemetrySettingsFfi {
    fn from(value: RelayTelemetrySettings) -> Self {
        Self {
            export_enabled: value.export_enabled,
            export_interval_seconds: value.export_interval_seconds,
        }
    }
}

impl From<RelayTelemetrySettingsFfi> for RelayTelemetrySettings {
    fn from(value: RelayTelemetrySettingsFfi) -> Self {
        Self {
            export_enabled: value.export_enabled,
            export_interval_seconds: value.export_interval_seconds,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct RelayTelemetryResourceFfi {
    pub service_version: String,
    pub service_instance_id: String,
    pub deployment_environment: String,
    pub tenant: String,
    pub os_type: String,
    pub os_version: String,
    pub device_model_identifier: Option<String>,
}

impl From<RelayTelemetryResourceFfi> for RelayTelemetryResource {
    fn from(value: RelayTelemetryResourceFfi) -> Self {
        Self {
            service_version: value.service_version,
            service_instance_id: value.service_instance_id,
            deployment_environment: value.deployment_environment,
            tenant: value.tenant,
            os_type: value.os_type,
            os_version: value.os_version,
            device_model_identifier: value.device_model_identifier,
        }
    }
}

/// Relay-telemetry runtime config supplied by the host app. The hand-written
/// `Debug` impl below redacts `authorization_bearer_token` (the OTLP push
/// credential) so a `{:?}` never prints it.
#[derive(Clone, uniffi::Record)]
pub struct RelayTelemetryRuntimeConfigFfi {
    pub otlp_endpoint: Option<String>,
    pub authorization_bearer_token: Option<String>,
    pub resource: Option<RelayTelemetryResourceFfi>,
}

impl std::fmt::Debug for RelayTelemetryRuntimeConfigFfi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayTelemetryRuntimeConfigFfi")
            .field("otlp_endpoint", &self.otlp_endpoint)
            .field(
                "authorization_bearer_token",
                &self
                    .authorization_bearer_token
                    .as_ref()
                    .map(|_| "<redacted>"),
            )
            .field("resource", &self.resource)
            .finish()
    }
}

impl From<RelayTelemetryRuntimeConfigFfi> for RelayTelemetryRuntimeConfig {
    fn from(value: RelayTelemetryRuntimeConfigFfi) -> Self {
        Self {
            otlp_endpoint: value.otlp_endpoint,
            authorization_bearer_token: value.authorization_bearer_token,
            resource: value.resource.map(Into::into),
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct RelayListFfi {
    pub kind: u64,
    pub relays: Vec<String>,
}

impl From<AccountRelayListState> for RelayListFfi {
    fn from(value: AccountRelayListState) -> Self {
        Self {
            kind: value.kind,
            relays: value.relays,
        }
    }
}

/// A relay list the account is missing, as a stable typed variant clients
/// localize without parsing strings (mdk#565).
#[derive(Clone, Copy, Debug, uniffi::Enum)]
pub enum MissingRelayListKindFfi {
    /// NIP-65 relay list — where this account publishes (outbox/write-side).
    Nip65,
    /// Marmot inbox relay list — where this account receives (inbox/read-side).
    Inbox,
}

impl From<MissingRelayListKind> for MissingRelayListKindFfi {
    fn from(value: MissingRelayListKind) -> Self {
        match value {
            MissingRelayListKind::Nip65 => Self::Nip65,
            MissingRelayListKind::Inbox => Self::Inbox,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct AccountRelayListsFfi {
    pub complete: bool,
    pub missing: Vec<MissingRelayListKindFfi>,
    pub default_relays: Vec<String>,
    pub bootstrap_relays: Vec<String>,
    pub nip65: RelayListFfi,
    pub inbox: RelayListFfi,
}

impl From<AccountRelayListStatus> for AccountRelayListsFfi {
    fn from(value: AccountRelayListStatus) -> Self {
        Self {
            complete: value.complete,
            missing: value.missing.into_iter().map(Into::into).collect(),
            default_relays: value.default_relays,
            bootstrap_relays: value.bootstrap_relays,
            nip65: value.nip65.into(),
            inbox: value.inbox.into(),
        }
    }
}

/// Stable relay-policy result for settings and remediation UI.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum RelayEndpointPolicyFfi {
    Allowed,
    Retired,
    Invalid,
    Unsafe,
}

impl From<RelayEndpointPolicy> for RelayEndpointPolicyFfi {
    fn from(value: RelayEndpointPolicy) -> Self {
        match value {
            RelayEndpointPolicy::Allowed => Self::Allowed,
            RelayEndpointPolicy::Retired => Self::Retired,
            RelayEndpointPolicy::Invalid => Self::Invalid,
            RelayEndpointPolicy::Unsafe => Self::Unsafe,
        }
    }
}

/// Policy classification for one caller-supplied relay endpoint.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct RelayEndpointClassificationFfi {
    pub endpoint: String,
    pub normalized_endpoint: Option<String>,
    pub policy: RelayEndpointPolicyFfi,
}

impl From<RelayEndpointClassification> for RelayEndpointClassificationFfi {
    fn from(value: RelayEndpointClassification) -> Self {
        Self {
            endpoint: value.endpoint,
            normalized_endpoint: value.normalized_endpoint,
            policy: value.policy.into(),
        }
    }
}

/// Stable connection states for localized relay settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum RelayStatusFfi {
    Unknown,
    Connecting,
    Connected,
    Offline,
}

impl From<marmot_app::RelayLivenessStatus> for RelayStatusFfi {
    fn from(value: marmot_app::RelayLivenessStatus) -> Self {
        match value {
            marmot_app::RelayLivenessStatus::Unknown => Self::Unknown,
            marmot_app::RelayLivenessStatus::Connecting => Self::Connecting,
            marmot_app::RelayLivenessStatus::Connected => Self::Connected,
            marmot_app::RelayLivenessStatus::Offline => Self::Offline,
        }
    }
}

/// Session-local state of one configured relay. Details can be unavailable.
#[derive(Clone, uniffi::Record)]
pub struct RelayLivenessFfi {
    pub url: String,
    pub status: RelayStatusFfi,
    pub last_attempt_unix: Option<u64>,
    pub last_error: Option<String>,
}

redact!(RelayLivenessFfi);

impl From<marmot_app::RelayLiveness> for RelayLivenessFfi {
    fn from(value: marmot_app::RelayLiveness) -> Self {
        Self {
            url: value.url,
            status: value.status.into(),
            last_attempt_unix: value.last_attempt_unix,
            last_error: value.last_error,
        }
    }
}

/// Live relay-plane connection health for the diagnostics view.
#[derive(Clone, Debug, uniffi::Record)]
pub struct RelayHealthFfi {
    pub sdk_backed: bool,
    pub total_relays: u32,
    pub initialized: u32,
    pub pending: u32,
    pub connecting: u32,
    pub connected: u32,
    pub disconnected: u32,
    pub terminated: u32,
    pub banned: u32,
    pub sleeping: u32,
    pub connection_attempts: u32,
    pub connection_successes: u32,
    pub notification_forwarder_running: bool,
    pub notification_forwarder_restarts: u64,
    pub notification_forwarder_lag_incidents: u64,
    pub notification_forwarder_lagged_notifications: u64,
    pub notification_forwarder_panics: u64,
    pub notification_forwarder_unexpected_exits: u64,
}

impl From<RelayPlaneHealth> for RelayHealthFfi {
    fn from(value: RelayPlaneHealth) -> Self {
        Self {
            sdk_backed: value.sdk_backed,
            total_relays: super::saturating_u32(value.total_relays),
            initialized: super::saturating_u32(value.initialized),
            pending: super::saturating_u32(value.pending),
            connecting: super::saturating_u32(value.connecting),
            connected: super::saturating_u32(value.connected),
            disconnected: super::saturating_u32(value.disconnected),
            terminated: super::saturating_u32(value.terminated),
            banned: super::saturating_u32(value.banned),
            sleeping: super::saturating_u32(value.sleeping),
            connection_attempts: super::saturating_u32(value.connection_attempts),
            connection_successes: super::saturating_u32(value.connection_successes),
            notification_forwarder_running: value.notification_forwarder_running,
            notification_forwarder_restarts: value.notification_forwarder_restarts,
            notification_forwarder_lag_incidents: value.notification_forwarder_lag_incidents,
            notification_forwarder_lagged_notifications: value
                .notification_forwarder_lagged_notifications,
            notification_forwarder_panics: value.notification_forwarder_panics,
            notification_forwarder_unexpected_exits: value.notification_forwarder_unexpected_exits,
        }
    }
}

/// Whether MDK holds one of the account's relay lists.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum RelayListPresenceFfi {
    /// No copy is held: not loaded yet, or none was published. MDK cannot
    /// tell which, so it raises no warning for it.
    Unknown,
    /// A published list is held, possibly an empty one.
    Published,
}

/// A list that names a relay. Later versions may add roles: keep a default
/// branch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum RelayRoleFfi {
    /// The inbox list (kind 10050), where senders send invitations.
    Inbox,
    /// A NIP-65 (kind 10002) write relay, marked write or unmarked.
    Write,
    /// A NIP-65 read relay, marked read or unmarked.
    Read,
}

/// What MDK knows of a relay. `Healthy`, `Suspected` and `Failing` come from
/// an inbox check (`check_account_relays`, or the account worker's own check
/// at its start) and describe one read of the account's inbox at the row's
/// `checked_at_unix`; they apply to inbox rows only and last while the
/// account's worker runs its current client. Later versions may add states: keep a default branch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum RelayHealthStateFfi {
    /// Allowed, and no check has established anything about it.
    Unchecked,
    /// The relay answered the inbox check: it ended a query for this
    /// account's gift wraps with EOSE, retried after authenticating when it
    /// asked for that. An EOSE saying the relay may withhold events until
    /// authentication still counts.
    Healthy,
    /// The check could not verify the relay; `fault` says why. Render it as
    /// "could not verify", never as a failure.
    Suspected,
    /// The relay refused to serve this account's inbox when checked, with the
    /// account's own key answering any authentication challenge; `fault` says
    /// how. Asking again does not change a refusal like that.
    Failing,
    /// The relay policy refuses it: this device never dials it.
    NotAllowed,
}

/// Why a row is not `Unchecked` or `Healthy`. Later versions may add faults:
/// keep a default branch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum RelayHealthFaultFfi {
    /// `NotAllowed`: on the retired-relay list.
    Retired,
    /// `NotAllowed`: not a relay URL.
    Invalid,
    /// `NotAllowed`: a host this device refuses to dial: plaintext, a private
    /// address, localhost or onion.
    Unsafe,
    /// `Failing`, or `Suspected` under a remote or host signer: the relay
    /// required authentication and did not accept the account's.
    AuthenticationRequired,
    /// `Failing`, or `Suspected` under a remote or host signer: the relay
    /// required payment.
    PaymentRequired,
    /// `Failing`, or `Suspected` under a remote or host signer: the relay
    /// restricted or blocked the account.
    Restricted,
    /// `Suspected`: no connection, while another relay of the same check
    /// answered.
    Unreachable,
    /// `Suspected`: no answer in time, while another relay of the same check
    /// answered.
    TimedOut,
    /// `Suspected`: the relay ended the query without naming a refusal, or
    /// sent more than it was asked for.
    Unexplained,
}

/// The problem a relay warning reports. Each needs a published inbox list.
/// Later versions may add kinds: keep a default branch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum RelayWarningKindFfi {
    /// Critical: the published inbox list names no relay, so an invitation
    /// sent through it has nowhere to go. A sender on this same install
    /// (another local account, or this account linking a new device) resolves
    /// the route through the same fallback to the defaults and may still get
    /// through. `relays` is empty.
    InboxListEmpty,
    /// Critical: the published inbox list names relays and each is refused
    /// by the policy or `Failing`. This device never listens on a refused
    /// one, and each failing one refused to serve this account's inbox when
    /// checked. When the policy allows none, a sender on this same install
    /// (another local account, or this account linking a new device)
    /// resolves the route through the same fallback to the defaults and may
    /// still get through. `relays` are every entry. An `Unchecked` or
    /// `Suspected` entry never raises it.
    NoAllowedInboxRelay,
    /// Warning: some entries are refused beside at least one allowed entry
    /// that is not `Failing`; an invitation sent only to the refused ones does
    /// not reach this device. `relays` are the refused entries.
    InboxRelaysNotAllowed,
    /// Notice: exactly one entry is allowed and not `Failing`, so an
    /// invitation sent through the list reaches this device at most there.
    /// `relays` is that relay.
    SingleInboxRelay,
    /// Warning: some entries are `Failing` beside at least one allowed entry
    /// that is not: each failing relay refused to serve this account's inbox
    /// when checked (see its row's `checked_at_unix`). `relays` are the
    /// failing entries.
    InboxRelayFailing,
}

/// How loudly to present a relay warning, from the least severe.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum RelayWarningSeverityFfi {
    Notice,
    Warning,
    Critical,
}

/// A change to the account's relay lists that would fix a warning; the user
/// makes it. When a warning lists both actions, make them one list edit: removing every
/// entry first would save an empty inbox list, which `set_account_inbox_relays`
/// rejects.
/// Later versions may add actions: keep a default branch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum RelayRepairActionFfi {
    /// Add an allowed relay to the inbox list.
    AddInboxRelay,
    /// Remove the warning's relays from the inbox list.
    RemoveInboxRelay,
}

/// One relay the account's inbox and NIP-65 lists name.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct RelayHealthRowFfi {
    /// Canonical URL, matching `account_relay_liveness` rows; an entry that
    /// does not parse appears as published.
    pub url: String,
    /// In the order Inbox, Write, Read.
    pub roles: Vec<RelayRoleFfi>,
    pub state: RelayHealthStateFfi,
    /// Set when `state` is `NotAllowed`, `Failing` or `Suspected`.
    pub fault: Option<RelayHealthFaultFfi>,
    /// The connection state `account_relay_liveness` reports.
    pub liveness: RelayStatusFfi,
    /// When the inbox check that decided `state` asked the relay, in Unix
    /// seconds; `None` while no check has established anything about it.
    pub checked_at_unix: Option<u64>,
    /// An inbox check of this relay is running.
    pub checking: bool,
}

redact!(RelayHealthRowFfi);

/// A problem with the account's relay setup.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct AccountRelayWarningFfi {
    pub kind: RelayWarningKindFfi,
    pub severity: RelayWarningSeverityFfi,
    /// The relays it is about, as row URLs.
    pub relays: Vec<String>,
    /// What would fix it, in order.
    pub actions: Vec<RelayRepairActionFfi>,
}

redact!(AccountRelayWarningFfi);

/// The account's relay health from its held lists, the relay policy and this
/// process's inbox checks.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct AccountRelayHealthFfi {
    /// Inbox warnings need a published inbox list; `Unknown` raises none.
    pub inbox_list: RelayListPresenceFfi,
    /// One per relay, ordered by URL.
    pub rows: Vec<RelayHealthRowFfi>,
    /// Ordered from the most severe.
    pub warnings: Vec<AccountRelayWarningFfi>,
    /// `None` without warnings.
    pub highest_severity: Option<RelayWarningSeverityFfi>,
    /// The inbox route MDK builds from the held lists is the configured
    /// defaults, because no inbox relay it holds is allowed. Also true while
    /// `inbox_list` is `Unknown`, so on its own it says nothing about
    /// invitations; the warnings do.
    pub falls_back_to_defaults: bool,
}

redact!(AccountRelayHealthFfi);

impl From<marmot_app::AccountRelayHealth> for AccountRelayHealthFfi {
    fn from(value: marmot_app::AccountRelayHealth) -> Self {
        use marmot_app::{
            RelayListPresence as Presence, RelayRepairAction as Action, RelayWarningKind as Kind,
            RelayWarningSeverity as Severity,
        };
        let severity = |severity| match severity {
            Severity::Notice => RelayWarningSeverityFfi::Notice,
            Severity::Warning => RelayWarningSeverityFfi::Warning,
            Severity::Critical => RelayWarningSeverityFfi::Critical,
        };
        Self {
            inbox_list: match value.inbox_list {
                Presence::Unknown => RelayListPresenceFfi::Unknown,
                Presence::Published => RelayListPresenceFfi::Published,
            },
            rows: value.rows.into_iter().map(Into::into).collect(),
            warnings: value
                .warnings
                .into_iter()
                .map(|warning| AccountRelayWarningFfi {
                    kind: match warning.kind {
                        Kind::InboxListEmpty => RelayWarningKindFfi::InboxListEmpty,
                        Kind::NoAllowedInboxRelay => RelayWarningKindFfi::NoAllowedInboxRelay,
                        Kind::InboxRelaysNotAllowed => RelayWarningKindFfi::InboxRelaysNotAllowed,
                        Kind::InboxRelayFailing => RelayWarningKindFfi::InboxRelayFailing,
                        Kind::SingleInboxRelay => RelayWarningKindFfi::SingleInboxRelay,
                    },
                    severity: severity(warning.severity),
                    relays: warning.relays,
                    actions: warning
                        .actions
                        .into_iter()
                        .map(|action| match action {
                            Action::AddInboxRelay => RelayRepairActionFfi::AddInboxRelay,
                            Action::RemoveInboxRelay => RelayRepairActionFfi::RemoveInboxRelay,
                        })
                        .collect(),
                })
                .collect(),
            highest_severity: value.highest_severity.map(severity),
            falls_back_to_defaults: value.falls_back_to_defaults,
        }
    }
}

impl From<marmot_app::RelayHealthRow> for RelayHealthRowFfi {
    fn from(row: marmot_app::RelayHealthRow) -> Self {
        use marmot_app::{RelayHealthFault as Fault, RelayHealthState as State, RelayRole as Role};
        Self {
            url: row.url,
            roles: row
                .roles
                .into_iter()
                .map(|role| match role {
                    Role::Inbox => RelayRoleFfi::Inbox,
                    Role::Write => RelayRoleFfi::Write,
                    Role::Read => RelayRoleFfi::Read,
                })
                .collect(),
            state: match row.state {
                State::Unchecked => RelayHealthStateFfi::Unchecked,
                State::Healthy => RelayHealthStateFfi::Healthy,
                State::Suspected => RelayHealthStateFfi::Suspected,
                State::Failing => RelayHealthStateFfi::Failing,
                State::NotAllowed => RelayHealthStateFfi::NotAllowed,
            },
            fault: row.fault.map(|fault| match fault {
                Fault::Retired => RelayHealthFaultFfi::Retired,
                Fault::Invalid => RelayHealthFaultFfi::Invalid,
                Fault::Unsafe => RelayHealthFaultFfi::Unsafe,
                Fault::AuthenticationRequired => RelayHealthFaultFfi::AuthenticationRequired,
                Fault::PaymentRequired => RelayHealthFaultFfi::PaymentRequired,
                Fault::Restricted => RelayHealthFaultFfi::Restricted,
                Fault::Unreachable => RelayHealthFaultFfi::Unreachable,
                Fault::TimedOut => RelayHealthFaultFfi::TimedOut,
                Fault::Unexplained => RelayHealthFaultFfi::Unexplained,
            }),
            liveness: row.liveness.into(),
            checked_at_unix: row.checked_at_unix,
            checking: row.checking,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every field of a relay health answer reaches the host as MDK read it,
    /// and its `Debug` shows no relay URL.
    #[test]
    fn relay_health_converts_every_field_and_debug_hides_urls() {
        use marmot_app::{
            AccountRelayHealth, AccountRelayWarning, RelayHealthFault, RelayHealthRow,
            RelayHealthState, RelayListPresence, RelayLivenessStatus, RelayRepairAction, RelayRole,
            RelayWarningKind, RelayWarningSeverity,
        };
        let health = AccountRelayHealthFfi::from(AccountRelayHealth {
            inbox_list: RelayListPresence::Published,
            rows: vec![
                RelayHealthRow {
                    url: "wss://refused.example".into(),
                    roles: vec![RelayRole::Inbox, RelayRole::Read],
                    state: RelayHealthState::NotAllowed,
                    fault: Some(RelayHealthFault::Unsafe),
                    liveness: RelayLivenessStatus::Offline,
                    checked_at_unix: None,
                    checking: false,
                },
                RelayHealthRow {
                    url: "wss://failing.example".into(),
                    roles: vec![RelayRole::Inbox],
                    state: RelayHealthState::Failing,
                    fault: Some(RelayHealthFault::AuthenticationRequired),
                    liveness: RelayLivenessStatus::Connected,
                    checked_at_unix: Some(1_700_000_000),
                    checking: true,
                },
            ],
            warnings: vec![AccountRelayWarning {
                kind: RelayWarningKind::NoAllowedInboxRelay,
                severity: RelayWarningSeverity::Critical,
                relays: vec!["wss://refused.example".into()],
                actions: vec![
                    RelayRepairAction::RemoveInboxRelay,
                    RelayRepairAction::AddInboxRelay,
                ],
            }],
            highest_severity: Some(RelayWarningSeverity::Critical),
            falls_back_to_defaults: true,
        });
        assert_eq!(
            health,
            AccountRelayHealthFfi {
                inbox_list: RelayListPresenceFfi::Published,
                rows: vec![
                    RelayHealthRowFfi {
                        url: "wss://refused.example".into(),
                        roles: vec![RelayRoleFfi::Inbox, RelayRoleFfi::Read],
                        state: RelayHealthStateFfi::NotAllowed,
                        fault: Some(RelayHealthFaultFfi::Unsafe),
                        liveness: RelayStatusFfi::Offline,
                        checked_at_unix: None,
                        checking: false,
                    },
                    RelayHealthRowFfi {
                        url: "wss://failing.example".into(),
                        roles: vec![RelayRoleFfi::Inbox],
                        state: RelayHealthStateFfi::Failing,
                        fault: Some(RelayHealthFaultFfi::AuthenticationRequired),
                        liveness: RelayStatusFfi::Connected,
                        checked_at_unix: Some(1_700_000_000),
                        checking: true,
                    },
                ],
                warnings: vec![AccountRelayWarningFfi {
                    kind: RelayWarningKindFfi::NoAllowedInboxRelay,
                    severity: RelayWarningSeverityFfi::Critical,
                    relays: vec!["wss://refused.example".into()],
                    actions: vec![
                        RelayRepairActionFfi::RemoveInboxRelay,
                        RelayRepairActionFfi::AddInboxRelay,
                    ],
                }],
                highest_severity: Some(RelayWarningSeverityFfi::Critical),
                falls_back_to_defaults: true,
            }
        );
        let rendered = format!("{health:?} {:?} {:?}", health.rows, health.warnings);
        for url in ["refused.example", "failing.example"] {
            assert!(!rendered.contains(url), "{rendered}");
        }
    }

    #[test]
    fn relay_telemetry_config_debug_redacts_bearer_token() {
        let config = RelayTelemetryRuntimeConfigFfi {
            otlp_endpoint: Some("https://otlp.example/v1/metrics".to_owned()),
            authorization_bearer_token: Some("super-secret-otlp-token".to_owned()),
            resource: None,
        };
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("super-secret-otlp-token"), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(rendered.contains("otlp.example"), "{rendered}");
    }
}
