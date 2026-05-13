# AGENTS.md - crates/storage-memory

Agent-facing map for the in-memory storage backend.

## Scope

`MemoryStorage` implements the full `cgka_traits::StorageProvider` aggregate for tests, simulator runs, and ephemeral
scenarios. It uses `Arc<RwLock<...>>` so clones share one backend.

## What matters

- Keep behavior aligned with `storage-sqlite` for Marmot storage traits.
- Snapshots must capture Marmot records and the OpenMLS memory map.
- Group delete must cascade messages, queued outbound intents, welcomes, capabilities, policies, snapshots, and
  group-scoped OpenMLS state.
- This backend is not persistent and should not grow production policy knobs.

## Key files

| Path | Owns |
| --- | --- |
| `src/lib.rs` | Backend implementation and tests. |
| `README.md` | Human-facing crate summary. |

## Verification

```sh
cargo test -p storage-memory
```
