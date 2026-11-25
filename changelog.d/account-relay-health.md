### Added

- Hosts can tell a user that their published inbox list keeps invitations sent through it from reaching them:
  `account_relay_health` lists each relay of the account's inbox and NIP-65 lists with its roles and whether the relay
  policy allows it, and raises a `Critical` warning for a published inbox list that is empty or allows no relay
  (including the fallback to the default relays, which raised nothing before), a `Warning` for refused entries beside
  allowed ones and a `Notice` for a single allowed inbox relay, in MarmotKit and C. `RelayHealthChanged` reports changes
  that come from the relay lists only, never a relay connecting or disconnecting; connection changes come from the
  existing `subscribe_relay_liveness`. It reads only held data and never dials; an inbox list MDK does not hold yet
  raises no warning.
