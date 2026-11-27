### Breaking changes

- Added explicit local queue-backpressure variants (`SliceReply::Busy`, `SecondReply::Busy`, `IdsReply::Busy`, `SweepEnd::LocalBusy`, `CompareEnd::LocalBusy`, `DirectoryInspectionError::LocalBusy`, and internal `FiniteEnd::Busy`) so local finite-request admission timeouts are never misclassified as relay `Unreachable`/`TimedOut` faults or silent record absence.

### Added

- Added `FiniteRequests::shutdown` in `transport-nostr-adapter` to reject new finite requests, retire active slots (suppressing unsent REQs and sending `CLOSE` for already-sent active requests on live clients), end active/waiting requests as `Disconnected`, and join tracked `send_msg(req)` and `CLOSE` cleanup tasks (also invoked by `NostrSdkRelayClient::shutdown`).

### Fixed

- Admitted finite requests in `transport-nostr-adapter` against a shared global queued-byte budget (192 MiB default, FIFO reservation with single-request exclusivity above capacity and sharing-group reservation so `FiniteRequests::sharing` reserves its shared budget once plus one private frame per active relay) so concurrent sweeps and directory reads bound queued frame memory without starving peer relays.
