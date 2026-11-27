### Added

- Added `NostrSdkRelayClient::from_builder_with_account_signer` in `transport-nostr-adapter` so authenticated publish and receive SDK clients share one factory path.

### Fixed

- Switched live kind-1059 inbox delivery in `transport-nostr-adapter` from SDK first-seen `ClientNotification::Event` to per-message `ClientNotification::Message(RelayMessage::Event)` with independent supplied-bytes verification, preventing SDK pool deduplication from hiding later relay copies or replays after retired attempts or queue drops.
- Shut down authenticated and anonymous publish SDK clients on eviction, replacement, account deactivation, and `MarmotRelayPlane::shutdown()`, joined in-flight delivery spill writers and loss-marker persistence tasks during plane shutdown, and switched discarded NIP-46 signer transports from `disconnect()` to `shutdown()`.
