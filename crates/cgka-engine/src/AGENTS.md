# AGENTS.md - crates/cgka-engine/src

Local map for engine source modules. The crate-level map in `../AGENTS.md` has the full design notes.

## Rules

- `engine.rs` owns construction and trait dispatch. Keep behavior in focused sibling modules.
- `EpochManager` is the only owner of non-stable epoch-state transitions.
- `message_processor/` is the inbound/outbound traffic junction: `mod.rs` (entry points + shared helpers + re-exports),
  `ingest.rs` (inbound peel/classify/apply path), `send.rs` (`do_send_*` outbound methods), `store.rs` (durable
  persistence / dedup / stored-message state), `application_replay.rs` (bounded background drain of retained
  canonical applications, independent of the send gate). Keep helper behavior factored across these as it grows.
- `distributed_convergence.rs` is the stored-message convergence entry point.
- `openmls_projection.rs` is the OpenMLS bytes/replay bridge for canonicalization.
- `openmls_projection/resumable.rs` owns the shared candidate-search frontier and slice continuations. Restore live
  storage before yielding; cumulative probe limits and final selection semantics span the entire search.
- `openmls_projection/candidate_replay_tests.rs` holds forked-graph fixtures, replay restoration/parity checks and
  paired measurements. It retains the `candidate_branch_peel_halt_tests` module name so existing test filters work.
  Encrypted-database process-kill checks remain in `../tests/crash_recovery_sqlite.rs`.
- `snapshot_guard.rs` owns panic-safe snapshot rollback/release for replay and peel probes.
- No Nostr types in this crate.

## Verification

```sh
cargo test -p cgka-engine
cargo test -p cgka-engine --locked --features test-policy-overrides --lib resumable_public_background_advance_retains_progress_until_complete
```
