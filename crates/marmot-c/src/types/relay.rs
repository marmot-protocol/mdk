//! C mirrors of the relay-list, relay-health, and telemetry conversions.

use marmot_uniffi::conversions::{
    AccountRelayHealthFfi, AccountRelayListsFfi, AccountRelayWarningFfi, MissingRelayListKindFfi,
    RelayEndpointClassificationFfi, RelayEndpointPolicyFfi, RelayHealthFaultFfi, RelayHealthFfi,
    RelayHealthRowFfi, RelayHealthStateFfi, RelayListFfi, RelayListPresenceFfi, RelayLivenessFfi,
    RelayRepairActionFfi, RelayRoleFfi, RelayStatusFfi, RelayTelemetryResourceFfi,
    RelayTelemetryRuntimeConfigFfi, RelayTelemetrySettingsFfi, RelayWarningKindFfi,
    RelayWarningSeverityFfi,
};

use crate::MarmotStatus;
use crate::macros::{c_enum, c_mirror};
use crate::memory::{c_bool, optional_str, required_str};

c_enum! {
    /// Observed connection state of a configured relay.
    MarmotRelayStatus from RelayStatusFfi {
        Unknown,
        Connecting,
        Connected,
        Offline,
    }
}

c_mirror! {
    /// One configured relay's observed connection state.
    MarmotRelayLiveness from RelayLivenessFfi,
    free marmot_relay_liveness_free,
    list(MarmotRelayLivenessList, marmot_relay_liveness_list_free) {
        str url,
        copy status: MarmotRelayStatus,
        opt_copy has_last_attempt_unix/last_attempt_unix: u64,
        opt_str last_error,
    }
}

c_enum! {
    /// Whether MDK holds one of the account's relay lists. `Unknown`: not
    /// loaded yet, or none was published; it raises no warning.
    MarmotRelayListPresence from RelayListPresenceFfi {
        Unknown,
        Published,
    }
}

c_enum! {
    /// A list that names a relay. Later versions may append roles: keep a
    /// default case.
    MarmotRelayRole from RelayRoleFfi {
        /// The inbox list (kind 10050), where senders send invitations.
        Inbox,
        /// A NIP-65 write relay, marked write or unmarked.
        Write,
        /// A NIP-65 read relay, marked read or unmarked.
        Read,
    }
}

c_enum! {
    /// What MDK knows of a relay. `Healthy`, `Suspected` and `Failing` come
    /// from an inbox check and describe one read of the account's inbox at
    /// the row's `checked_at_unix` (see the shared contract). Later versions
    /// may append states: keep a default case.
    MarmotRelayHealthState from RelayHealthStateFfi {
        /// Allowed, and no check has established anything about it.
        Unchecked,
        /// The relay answered the inbox check with EOSE.
        Healthy,
        /// The check could not verify the relay: render "could not verify".
        Suspected,
        /// The relay refused to serve this account's inbox when checked,
        /// with the account's own key answering any authentication.
        Failing,
        /// The relay policy refuses it: this device never dials it.
        NotAllowed,
    }
}

c_enum! {
    /// Why a row is not `Unchecked` or `Healthy`. Later versions may append
    /// faults: keep a default case.
    MarmotRelayHealthFault from RelayHealthFaultFfi {
        /// `NotAllowed`: on the retired-relay list.
        Retired,
        /// `NotAllowed`: not a relay URL.
        Invalid,
        /// `NotAllowed`: a host this device refuses to dial.
        Unsafe,
        /// `Failing` or `Suspected`: authentication required and not accepted.
        AuthenticationRequired,
        /// `Failing` or `Suspected`: payment required.
        PaymentRequired,
        /// `Failing` or `Suspected`: restricted or blocked.
        Restricted,
        /// `Suspected`: no connection while another relay answered.
        Unreachable,
        /// `Suspected`: no answer in time while another relay answered.
        TimedOut,
        /// `Suspected`: ended without naming a refusal.
        Unexplained,
    }
}

#[allow(clippy::derivable_impls)]
impl Default for MarmotRelayHealthFault {
    fn default() -> Self {
        Self::Retired
    }
}

c_enum! {
    /// The problem a relay warning reports. Later versions may append kinds:
    /// keep a default case.
    MarmotRelayWarningKind from RelayWarningKindFfi {
        /// Critical: the published inbox list names no relay, so an invitation
        /// sent through it has nowhere to go (see the shared contract for a
        /// sender on this same install).
        InboxListEmpty,
        /// Critical: every entry of the published inbox list is refused by
        /// the policy or `Failing` (see the shared contract for a sender on
        /// this same install). An `Unchecked` or `Suspected` entry never
        /// raises it.
        NoAllowedInboxRelay,
        /// Warning: some entries are refused beside at least one allowed
        /// entry that is not `Failing`.
        InboxRelaysNotAllowed,
        /// Notice: exactly one entry is allowed and not `Failing`.
        SingleInboxRelay,
        /// Warning: some entries are `Failing` beside at least one allowed
        /// entry that is not; each refused to serve this account's inbox when
        /// checked.
        InboxRelayFailing,
    }
}

c_enum! {
    /// How loudly to present a relay warning, from the least severe.
    MarmotRelayWarningSeverity from RelayWarningSeverityFfi {
        Notice,
        Warning,
        Critical,
    }
}

#[allow(clippy::derivable_impls)]
impl Default for MarmotRelayWarningSeverity {
    fn default() -> Self {
        Self::Notice
    }
}

c_enum! {
    /// A change to the account's relay lists that would fix a warning. When a
    /// warning lists both, make them one `marmot_set_account_inbox_relays`
    /// call: an empty inbox list is rejected. Later versions may append
    /// actions: keep a default case.
    MarmotRelayRepairAction from RelayRepairActionFfi {
        AddInboxRelay,
        RemoveInboxRelay,
    }
}

c_mirror! {
    /// One relay the account's inbox and NIP-65 lists name.
    MarmotRelayHealthRow from RelayHealthRowFfi {
        /// Canonical URL, matching `marmot_account_relay_liveness` rows.
        str url,
        /// In the order Inbox, Write, Read.
        vec roles/roles_len: MarmotRelayRole,
        copy state: MarmotRelayHealthState,
        /// Set when `state` is `NotAllowed`, `Failing` or `Suspected`.
        opt_copy has_fault/fault: MarmotRelayHealthFault,
        copy liveness: MarmotRelayStatus,
        /// When the inbox check that decided `state` asked the relay, in
        /// Unix seconds; absent while no check has established anything.
        opt_copy has_checked_at_unix/checked_at_unix: u64,
        /// An inbox check of this relay is running.
        copy checking: bool,
    }
}

c_mirror! {
    /// A problem with the account's relay setup.
    MarmotAccountRelayWarning from AccountRelayWarningFfi {
        copy kind: MarmotRelayWarningKind,
        copy severity: MarmotRelayWarningSeverity,
        /// The relays it is about, as row URLs.
        str_vec relays/relays_len,
        /// What would fix it, in order.
        vec actions/actions_len: MarmotRelayRepairAction,
    }
}

c_mirror! {
    /// The account's relay health from its held lists, the relay policy and
    /// this process's inbox checks. Free with
    /// `marmot_account_relay_health_free`.
    MarmotAccountRelayHealth from AccountRelayHealthFfi,
    free marmot_account_relay_health_free {
        copy inbox_list: MarmotRelayListPresence,
        /// One per relay, ordered by URL.
        vec rows/rows_len: MarmotRelayHealthRow,
        /// Ordered from the most severe.
        vec warnings/warnings_len: MarmotAccountRelayWarning,
        opt_copy has_highest_severity/highest_severity: MarmotRelayWarningSeverity,
        /// The inbox route MDK builds from the held lists is the configured
        /// defaults. Also true while `inbox_list` is `Unknown`, so on its own
        /// it says nothing about invitations; the warnings do.
        copy falls_back_to_defaults: bool,
    }
}

c_mirror! {
    /// One published relay list (`kind` is the Nostr event kind).
    MarmotRelayList from RelayListFfi {
        copy kind: u64,
        str_vec relays/relays_len,
    }
}

c_enum! {
    /// Which relay list is missing from an incomplete account relay setup.
    MarmotMissingRelayListKind from MissingRelayListKindFfi {
        /// NIP-65 relay list — where this account publishes (outbox).
        Nip65,
        /// Marmot inbox relay list — where this account receives (inbox).
        Inbox,
    }
}

c_mirror! {
    /// The account's full relay-list state.
    MarmotAccountRelayLists from AccountRelayListsFfi,
    free marmot_account_relay_lists_free {
        copy complete: bool,
        vec missing/missing_len: MarmotMissingRelayListKind,
        str_vec default_relays/default_relays_len,
        str_vec bootstrap_relays/bootstrap_relays_len,
        rec nip65: MarmotRelayList,
        rec inbox: MarmotRelayList,
    }
}

c_mirror! {
    /// Aggregate relay-pool health counters (no per-relay identities).
    MarmotRelayHealth from RelayHealthFfi,
    free marmot_relay_health_free {
        copy sdk_backed: bool,
        copy total_relays: u32,
        copy initialized: u32,
        copy pending: u32,
        copy connecting: u32,
        copy connected: u32,
        copy disconnected: u32,
        copy terminated: u32,
        copy banned: u32,
        copy sleeping: u32,
        copy connection_attempts: u32,
        copy connection_successes: u32,
        copy notification_forwarder_running: bool,
        copy notification_forwarder_restarts: u64,
        copy notification_forwarder_lag_incidents: u64,
        copy notification_forwarder_lagged_notifications: u64,
        copy notification_forwarder_panics: u64,
        copy notification_forwarder_unexpected_exits: u64,
    }
}

c_mirror! {
    /// Relay-telemetry export settings. Also a borrowed input to
    /// `marmot_set_relay_telemetry_settings`.
    MarmotRelayTelemetrySettings from RelayTelemetrySettingsFfi,
    free marmot_relay_telemetry_settings_free {
        /// Boolean as `uint8_t`: nonzero enables export.
        copy export_enabled: u8,
        copy export_interval_seconds: u64,
    }
}

impl MarmotRelayTelemetrySettings {
    pub(crate) fn to_ffi(&self) -> RelayTelemetrySettingsFfi {
        RelayTelemetrySettingsFfi {
            export_enabled: c_bool(self.export_enabled),
            export_interval_seconds: self.export_interval_seconds,
        }
    }
}

c_mirror! {
    /// OTLP resource attributes for relay-telemetry export. Borrowed input.
    MarmotRelayTelemetryResource from RelayTelemetryResourceFfi {
        str service_version,
        str service_instance_id,
        str deployment_environment,
        str tenant,
        str os_type,
        str os_version,
        opt_str device_model_identifier,
    }
}

impl MarmotRelayTelemetryResource {
    /// # Safety
    /// Every non-NULL field must be a valid NUL-terminated string.
    pub(crate) unsafe fn to_ffi(&self) -> Result<RelayTelemetryResourceFfi, MarmotStatus> {
        Ok(RelayTelemetryResourceFfi {
            service_version: unsafe { required_str(self.service_version) }?,
            service_instance_id: unsafe { required_str(self.service_instance_id) }?,
            deployment_environment: unsafe { required_str(self.deployment_environment) }?,
            tenant: unsafe { required_str(self.tenant) }?,
            os_type: unsafe { required_str(self.os_type) }?,
            os_version: unsafe { required_str(self.os_version) }?,
            device_model_identifier: unsafe { optional_str(self.device_model_identifier) }?,
        })
    }
}

c_mirror! {
    /// Runtime OTLP route config for relay telemetry. Borrowed input to
    /// `marmot_set_relay_telemetry_runtime_config`.
    MarmotRelayTelemetryRuntimeConfig from RelayTelemetryRuntimeConfigFfi {
        opt_str otlp_endpoint,
        opt_str authorization_bearer_token,
        opt_rec resource: MarmotRelayTelemetryResource,
    }
}

impl MarmotRelayTelemetryRuntimeConfig {
    /// # Safety
    /// Non-NULL strings must be valid; `resource` NULL or a valid struct.
    pub(crate) unsafe fn to_ffi(&self) -> Result<RelayTelemetryRuntimeConfigFfi, MarmotStatus> {
        let resource = if self.resource.is_null() {
            None
        } else {
            Some(unsafe { (*self.resource).to_ffi() }?)
        };
        Ok(RelayTelemetryRuntimeConfigFfi {
            otlp_endpoint: unsafe { optional_str(self.otlp_endpoint) }?,
            authorization_bearer_token: unsafe { optional_str(self.authorization_bearer_token) }?,
            resource,
        })
    }
}

c_enum! {
    /// Whether a relay endpoint may be dialed.
    MarmotRelayEndpointPolicy from RelayEndpointPolicyFfi {
        Allowed,
        /// On the centralized retired-relay denylist; never dial it.
        Retired,
        /// Not a parseable relay URL.
        Invalid,
        /// Parseable but rejected by the host-safety dial discipline.
        Unsafe,
    }
}

c_mirror! {
    /// One endpoint's dial verdict. Free the list with
    /// `marmot_relay_endpoint_classification_list_free`.
    MarmotRelayEndpointClassification from RelayEndpointClassificationFfi,
    free marmot_relay_endpoint_classification_free,
    list(MarmotRelayEndpointClassificationList, marmot_relay_endpoint_classification_list_free) {
        /// The endpoint as the caller wrote it.
        str endpoint,
        /// Canonical form, NULL when the endpoint does not parse.
        opt_str normalized_endpoint,
        copy policy: MarmotRelayEndpointPolicy,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::boxed;

    /// A relay health answer reaches C with every field, its absent fault and
    /// severity flagged, and frees deeply from its root.
    #[test]
    fn relay_health_mirrors_every_field_and_frees_deeply() {
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let before = crate::memory::audit::live_allocations();
        let health = MarmotAccountRelayHealth::from(AccountRelayHealthFfi {
            inbox_list: RelayListPresenceFfi::Published,
            rows: vec![
                RelayHealthRowFfi {
                    url: "wss://allowed.example".into(),
                    roles: vec![RelayRoleFfi::Inbox, RelayRoleFfi::Write],
                    state: RelayHealthStateFfi::Unchecked,
                    fault: None,
                    liveness: RelayStatusFfi::Connected,
                    checked_at_unix: None,
                    checking: true,
                },
                RelayHealthRowFfi {
                    url: "ws://plain.example".into(),
                    roles: vec![RelayRoleFfi::Read],
                    state: RelayHealthStateFfi::NotAllowed,
                    fault: Some(RelayHealthFaultFfi::Unsafe),
                    liveness: RelayStatusFfi::Unknown,
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
                    checking: false,
                },
            ],
            warnings: vec![AccountRelayWarningFfi {
                kind: RelayWarningKindFfi::SingleInboxRelay,
                severity: RelayWarningSeverityFfi::Notice,
                relays: vec!["wss://allowed.example".into()],
                actions: vec![RelayRepairActionFfi::AddInboxRelay],
            }],
            highest_severity: Some(RelayWarningSeverityFfi::Notice),
            falls_back_to_defaults: false,
        });
        unsafe {
            assert_eq!(health.inbox_list, MarmotRelayListPresence::Published);
            assert_eq!(health.rows_len, 3);
            let allowed = &*health.rows;
            assert_eq!(
                std::ffi::CStr::from_ptr(allowed.url).to_str().unwrap(),
                "wss://allowed.example"
            );
            assert_eq!(
                std::slice::from_raw_parts(allowed.roles, allowed.roles_len),
                [MarmotRelayRole::Inbox, MarmotRelayRole::Write]
            );
            assert_eq!(allowed.state, MarmotRelayHealthState::Unchecked);
            assert!(!allowed.has_fault);
            assert_eq!(allowed.liveness, MarmotRelayStatus::Connected);
            assert!(!allowed.has_checked_at_unix);
            assert!(allowed.checking);
            let refused = &*health.rows.add(1);
            assert_eq!(refused.state, MarmotRelayHealthState::NotAllowed);
            assert!(refused.has_fault);
            assert_eq!(refused.fault, MarmotRelayHealthFault::Unsafe);
            assert!(!refused.checking);
            let failing = &*health.rows.add(2);
            assert_eq!(failing.state, MarmotRelayHealthState::Failing);
            assert!(failing.has_fault);
            assert_eq!(
                failing.fault,
                MarmotRelayHealthFault::AuthenticationRequired
            );
            assert!(failing.has_checked_at_unix);
            assert_eq!(failing.checked_at_unix, 1_700_000_000);
            assert_eq!(health.warnings_len, 1);
            let warning = &*health.warnings;
            assert_eq!(warning.kind, MarmotRelayWarningKind::SingleInboxRelay);
            assert_eq!(warning.severity, MarmotRelayWarningSeverity::Notice);
            assert_eq!(warning.relays_len, 1);
            assert_eq!(
                std::ffi::CStr::from_ptr(*warning.relays).to_str().unwrap(),
                "wss://allowed.example"
            );
            assert_eq!(
                std::slice::from_raw_parts(warning.actions, warning.actions_len),
                [MarmotRelayRepairAction::AddInboxRelay]
            );
            assert!(health.has_highest_severity);
            assert_eq!(health.highest_severity, MarmotRelayWarningSeverity::Notice);
            assert!(!health.falls_back_to_defaults);
            marmot_account_relay_health_free(boxed(health));
        }
        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), before);
    }
}
