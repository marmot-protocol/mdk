### Fixed

- Existing-key setup skips far-future profile and relay records, shows which relays served them, and checks the newest eligible record.
- Suggested relay repairs preserve unrecognized entries and reuse URLs from `r`-tagged inbox lists. Long NIP-65 lists can gain a missing relay role.
- A cached relay list outside the clock-skew window no longer hides an eligible list after the clock moves back.
