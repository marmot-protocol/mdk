# AGENTS.md - crates/cgka-engine/src

Local map for engine source modules. The crate-level map in `../AGENTS.md` has the full design notes.

## Rules

- `engine.rs` owns construction and trait dispatch. Keep behavior in focused sibling modules.
- `EpochManager` is the only owner of non-stable epoch-state transitions.
- `message_processor/` is the inbound/outbound traffic junction: `mod.rs` (entry points + shared helpers + re-exports),
  `ingest.rs` (inbound peel/classify/apply path), `send.rs` (`do_send_*` outbound methods), `store.rs` (durable
  persistence / dedup / stored-message state). Keep helper behavior factored across these as it grows.
- `distributed_convergence.rs` is the stored-message convergence entry point.
- `openmls_projection.rs` is the OpenMLS bytes/replay bridge for canonicalization.
- `snapshot_guard.rs` owns panic-safe snapshot rollback/release for replay and peel probes.
- No Nostr types in this crate.

## Verification

```sh
cargo test -p cgka-engine
```
