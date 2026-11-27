### Fixed

- Replaced raw-pointer RAII cleanup guards (`PendingCommitCleanupGuard`, `NewGroupCleanupGuard`, and
  `PreparingEvolutionGuard`) with `Arc<S>` stored on `Engine<S>`, eliminating raw-pointer aliasing UB and all `unsafe`
  blocks in `cgka-engine` without changing public API signatures.
- Validated and allocated pending-publish state before committing durable staging rows across all commit-staging paths,
  and ran `PendingCommitCleanupGuard`'s pending-commit and stored-proposal cleanup inside one storage transaction, so
  failed staging leaves no orphaned SQLite records or torn proposal state.
