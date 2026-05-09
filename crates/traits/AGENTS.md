# AGENTS.md - crates/traits

Agent-facing map for the shared trait and type crate.

## Scope

This crate owns values and traits that cross crate boundaries:

- `CgkaEngine`
- `TransportPeeler`
- `TransportAdapter`
- Marmot storage traits and `StorageProvider`
- transport envelopes and peeled messages
- group/member/message ids
- engine state and error vocabulary

It should not depend on engine internals, storage implementations, Nostr
libraries, or OpenMLS concrete engine types. OpenMLS appears only where the
storage aggregate needs the OpenMLS storage trait bound.

## Key files

| Path | Owns |
| --- | --- |
| `src/engine.rs` | Public engine trait, send/create requests, outputs, group events. |
| `src/storage.rs` | Storage trait aggregate and snapshot/rollback contract. |
| `src/engine_state.rs` | Epoch and welcome state machines. |
| `src/transport.rs` | Transport-facing message envelope types. |
| `src/transport_adapter.rs` | Account-aware adapter trait, publish targets, delivery metadata. |
| `src/ingest.rs` | Peeled-message content and ingest outcomes. |
| `tests/snapshots.rs` | JSON/debug shape checks for cross-boundary types. |

## Verification

```sh
cargo test -p cgka-traits
```

After deliberate snapshot changes:

```sh
cargo insta review
```
