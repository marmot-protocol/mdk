### Added

- `Marmot::account_relay_health(account_ref)` and the `RelayHealthChanged` event, with `AccountRelayHealthFfi`,
  `RelayHealthRowFfi`, `AccountRelayWarningFfi`, `RelayListPresenceFfi`, `RelayRoleFfi`, `RelayHealthStateFfi`,
  `RelayHealthFaultFfi`, `RelayWarningKindFfi`, `RelayWarningSeverityFfi` and `RelayRepairActionFfi`. Only the
  `Unchecked` and `NotAllowed` states are produced yet; later versions add kinds, faults, actions and roles.
