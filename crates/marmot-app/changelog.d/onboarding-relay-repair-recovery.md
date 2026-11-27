### Added

- Onboarding reports `OnboardingIssue::RateLimited` when a relay answers a lookup or publication with a `rate-limited:` refusal (#3721, #3723).

### Fixed

- Preserve verified relay-list records returned before an incomplete, NIP-67, or `CLOSED` inspection end, classify persistent NIP-67 `auth` hints as `AuthenticationRequired`, classify `rate-limited:` and bare `error:` `CLOSED` reasons as transient, retry transient relay-list lookups once within `CHECK_WAIT`, and fail fast on bare `auth-required:` `CLOSED` replies without an `AUTH` challenge (#3721, #3724).
- Reuse completed kind-10002 EOSE answers on the `Relays` step without redialing declared endpoints, and prevent incomplete lookups from overwriting a newer checkpointed relay list with an older copy or `None` (#3721, #3728).
- Lossless one-click relay repair preserves invalid URLs, unknown markers, and long (>16) NIP-65 lists (marking long previews inconclusive), and copies allowed `r`-tag URLs into `relay` tags on kind-10050 inbox lists while keeping the 16-relay inbox cap (#3727).
- Preserve an unapproved relay repair proposal as `inconclusive` under a bumped revision when one source fails during approval while an authoritative source still confirms the basis is newest (#3722).
- Surface per-relay refusal findings on repair publication and initial KeyPackage publication; offer `CancelRepair` and `EditRelays` after definitive all-target repair refusals, and offer `EditRelays` to update NIP-65 write relays when initial KeyPackage publication is refused (#3723, #3747).
