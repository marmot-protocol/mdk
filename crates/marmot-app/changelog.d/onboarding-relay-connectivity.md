### Fixed

- Existing-key onboarding keeps a relay list when the same query already completed during discovery. If all declared routes time out or are unreachable, it rechecks the discovery sources before offering to edit the list (#3728).
