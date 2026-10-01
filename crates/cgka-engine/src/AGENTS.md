# AGENTS.md - crates/cgka-engine/src

Source-local rules. The full module map, invariants, and design notes are in [`../AGENTS.md`](../AGENTS.md).

## Rules

- `engine.rs` owns construction and trait dispatch. Keep behavior in focused sibling modules.
- `EpochManager` is the only owner of non-stable epoch-state transitions.
- `message_processor/` is the traffic junction; keep helper behavior factored across `mod.rs`, `ingest.rs`, `send.rs`,
  `store.rs`, and `application_replay.rs` as it grows (roles in the parent module map).
- `openmls_projection/resumable.rs`: restore live storage before yielding; cumulative probe limits and final selection
  semantics span the entire search. Capture replay fingerprints only to validate or retain a continuation, after cheap
  uncontested checks.
- `openmls_projection/tests/candidate_replay.rs` keeps the `candidate_branch_peel_halt_tests` module name so existing
  test filters work. Encrypted-database process-kill checks stay in `../tests/crash_recovery_sqlite.rs`.
- `message_processor/tests/application_replay.rs` holds the opt-in encrypted negative-discovery scan measurement and a
  test-only visited-row counter; keep aggregate measurements separate from app acceptance.
- No new Nostr types. `account_identity_proof.rs` is the one tracked exception (`TODO(mdk#755)`).

## Verification

```sh
cargo test -p cgka-engine
cargo test -p cgka-engine --locked --features test-policy-overrides --lib resumable_public_background_advance_retains_progress_until_complete
```
