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
- `SessionConfig::with_storage` runs the session on a host-opened connection so the host can close it at a known
  instant (mdk#2323). `open` must not open a second connection in that case.
- Keep storage-only legacy-format promotion explicit and host-scheduled after readiness; do not add it to the
  session-open critical path or widen the generic engine storage API for it.
- Every `SessionError` is an engine error. A storage failure the session meets itself converts to
  `EngineError::Storage`, so hosts classify it as they do the engine's own (mdk#2602). Callers ask
  `SessionError::as_engine_error`, not the variant.
- Keep account records (KeyPackage lifecycle, group maintenance, obligations, group evolutions, durable transport
  fanouts, periodic policy) on the session's own storage handle, not behind engine forwards. A group-scoped one calls
  `Engine::check_group_live` before touching storage, so a quarantined group still fails with `UnknownGroup` and an
  unhydrated one with `GroupNotHydrated` (mdk#2602, rule 4). Writes that must commit with OpenMLS state (KeyPackage
  staging and promotion) stay engine transactions.
- Keep one audit recorder per account-device: `open` wraps the configured recorder in a `SharedRecorder`, builds the
  engine with a clone, and writes the open-time `recorder_health` row through it. Do not add audit pass-through
  methods; the runtime and the host record, rotate and finish through their own clones (mdk#2602, rule 5).
- Re-export, under its engine name, each engine item a host names alongside the session: the configuration and signer
  types, the group-authority types, the KeyPackage metadata and inventory helpers, and the application message size
  model. Hosts name these through this crate, never `cgka_engine` (mdk#2602).
- Prefer behavior tests over internal state assertions.

## Verification

```sh
cargo test -p cgka-session
```
