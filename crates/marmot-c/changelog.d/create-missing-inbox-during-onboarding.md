### Added

- `marmot_begin_onboarding_with_options` accepts `MARMOT_ONBOARDING_CREATE_MISSING_INBOX_LIST` to let existing-key sign-in publish a missing inbox list. `marmot_begin_onboarding` uses zero flags.
- `MarmotOnboardingSnapshot` ends with a nullable `created_inbox_list` record for reporting the relays onboarding set up. Rebuild consumers against the matching C header and library for the updated layout.
