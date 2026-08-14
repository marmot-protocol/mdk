# AGENTS.md - crates/cgka-session

Agent-facing map for the production-shaped account-device session crate.

## Scope

This crate wires `Engine<SqliteAccountStorage>` into an app-facing session lifecycle. It does not own a transport adapter,
account key derivation, relay sync, or UI projection.

## Rules

- Keep SQLCipher keys app-provided. Do not add key derivation or recovery here.
- Keep transport-specific code out. Inject a `TransportPeeler`.
- Surface engine effects as app events plus publishable transport work.
- Keep storage-only legacy-format promotion explicit and host-scheduled after
  readiness; do not add it to the session-open critical path or widen the
  generic engine storage API for it.
- Prefer behavior tests over internal state assertions.

## Verification

```sh
cargo test -p cgka-session
```
