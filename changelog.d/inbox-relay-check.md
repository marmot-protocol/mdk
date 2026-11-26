### Added

- Hosts can tell a user that an inbox relay refused to serve their invitations: `check_account_relays` asks each of the
  account's inbox relays once for its gift wraps, on a connection of its own, and marks a relay `Healthy` when it
  answers, `Failing` when it gives an explicit policy refusal to the account's own key (authentication refused as
  restricted, blocked or payment-required; payment required; restricted or blocked), and `Suspected` when the check
  could not verify it. A `Warning` names a failing inbox relay beside a usable one, and the existing `Critical` also
  fires once every inbox entry is refused or failing. The account worker runs the check, once at each start for an
  account whose own key signs and on request; results belong to the running account and are never stored. A check no
  relay answered changes nothing. A request while a check runs is refused at once with the new `RelayCheckRunning`
  error (MarmotKit) or `MARMOT_STATUS_RELAY_CHECK_RUNNING` (C). In MarmotKit and C.

### Changed

- `RelayHealthChanged` also fires when an inbox check changes a relay's state, never when one confirms it.
