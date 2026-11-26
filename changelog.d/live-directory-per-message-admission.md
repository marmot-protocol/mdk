### Breaking changes

- Added `follows_created_at: u64` to `nostr_directory::UserDirectoryRecord` and `storage_sqlite::PublicDirectoryUserRecord`, and `created_at: u64` to `nostr_directory::FetchedFollowList`, backed by schema migrations `0004_follows_created_at` (directory cache) and `0006_directory_follows_created_at` (shared storage).

### Fixed

- Switched `transport-nostr`'s live directory notification forwarder from SDK first-seen `ClientNotification::Event` to per-message `ClientNotification::Message(RelayMessage::Event)` with independent supplied-bytes verification on every copy so SDK pool deduplication cannot hide later relay copies or rebuild replays.
- Guarded `nostr-directory`'s cached KeyPackage and kind-3 contact-list ingestion against older or equal-second stale replays and existing KeyPackage deletion/replacement barriers, and cleared cached `entry.key_package` entries when live kind-5 deletions or newer malformed kind-30443 replacements fence them.
