### Added

- `marmot_check_account_relays`. `MarmotRelayHealthRow` gains `has_checked_at_unix`, `checked_at_unix` and `checking`
  at its end; `MarmotRelayHealthFault` and `MarmotRelayWarningKind` gain values appended after the existing ones.
  Rebuild against the matching header and library.
- `MARMOT_STATUS_RELAY_CHECK_RUNNING` (135), appended to `MarmotStatus`, for a check requested while one of the account
  runs.
