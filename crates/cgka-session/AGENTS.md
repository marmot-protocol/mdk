# AGENTS.md - crates/cgka-session

Agent map for the account-device session crate. Overview and test coverage: [`README.md`](README.md). Test placement:
[`tests/AGENTS.md`](tests/AGENTS.md).

## Scope

Wires `Engine<SqliteAccountStorage>` into an app-facing session lifecycle. All code is in `src/lib.rs`
(`SessionConfig`, `AccountDeviceSession`, `SessionEffects` / `PublishWork`). Does not own a transport adapter, account
key derivation, relay sync, or UI projection.

## Rules

- Keep SQLCipher keys app-provided. Do not add key derivation or recovery here.
- Keep transport-specific code out. Inject a `TransportPeeler`; Nostr crates are dev-dependencies only.
- Surface engine effects as app events plus publishable transport work.
- `open` validates profile and convergence policy before opening storage or hydrating; keep new open-time checks
  ahead of any durable mutation.
- Keep storage-only legacy-format promotion explicit and host-scheduled after readiness; do not add it to the
  session-open critical path or widen the generic engine storage API for it.
- Prefer behavior tests over internal state assertions.

## Verification

```sh
cargo test -p cgka-session
```
