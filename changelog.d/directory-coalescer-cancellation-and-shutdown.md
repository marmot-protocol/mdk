### Changed

- Updated `DirectoryRelayPlane` in `transport-nostr` to track coalesced directory fetches with waiter-counted cancellation and bounded `MarmotRelayPlane::shutdown()` cleanup, and removed the unused idle `Client` from `NostrSdkDirectoryRelayFetcher::standalone()`.
