### Added

- Added `FiniteRequests::shutdown` in `transport-nostr-adapter` to reject new finite requests, end active/waiting requests, and join tracked `send_msg(req)` and `CLOSE` cleanup tasks (also invoked by `NostrSdkRelayClient::shutdown`).

### Fixed

- Admitted finite requests in `transport-nostr-adapter` against a shared global queued-byte budget (64 MiB default, FIFO reservation per request with single-request exclusivity above capacity) so concurrent sweeps and directory reads cannot grow queued frame memory unboundedly.
