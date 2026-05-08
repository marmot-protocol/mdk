# AGENTS.md - crates/cgka-engine/src

Local map for engine source modules. The crate-level map in `../AGENTS.md`
has the full design notes.

## Rules

- `engine.rs` owns construction and trait dispatch. Keep behavior in focused
  sibling modules.
- `EpochManager` is the only owner of non-stable epoch-state transitions.
- `message_processor.rs` is the inbound/outbound traffic junction. Keep helper
  behavior factored when it grows.
- `distributed_convergence.rs` is the stored-message convergence entry point.
- `openmls_projection.rs` is the OpenMLS bytes/replay bridge for
  canonicalization.
- No Nostr types in this crate.

## Verification

```sh
cargo test -p cgka-engine
```
