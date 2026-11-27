### Fixed

- Replaced raw-pointer RAII cleanup guards (`PendingCommitCleanupGuard`, `NewGroupCleanupGuard`, and
  `PreparingEvolutionGuard`) with `Arc<S>` stored on `Engine<S>`, eliminating raw-pointer aliasing UB and all `unsafe`
  blocks in `cgka-engine` without changing public API signatures.
- Validated and allocated pending-publish state before committing durable staging rows across all commit-staging paths,
  ran `PendingCommitCleanupGuard`'s pending-commit and stored-proposal cleanup inside one storage transaction, and
  retained ownership of failed `SelfRemove` staging cleanups across engine retries, outbound sends, and session-open
  hydration (quarantining the group with `PendingCommitRecoveryFailed` if a storage fault persists until hydration
  retry) so failed staging leaves neither orphaned SQLite records nor wedged proposal queues.
