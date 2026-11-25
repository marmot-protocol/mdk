### Fixed

- Existing-key onboarding retries transient relay-list lookup failures once. An empty lookup with an authoritative answer can offer a relay-list edit with a warning about the failed sources.
- A relay that closes an onboarding query without sending the requested authentication challenge reports an authentication refusal after a short wait.
