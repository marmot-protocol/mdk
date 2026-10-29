# AGENTS.md - crates/marmot-session

Agent map for the account-device runtime and session crate. Overview and test coverage: [`README.md`](README.md). Test
placement: [`tests/AGENTS.md`](tests/AGENTS.md).

## Scope

Owns the account-device layer between `marmot-app` and the engine. `AccountDeviceRuntime` coordinates one session with a
pluggable `TransportAdapter`: transport account activation, transport routing policy, KeyPackage publication, durable
maintenance, and publish confirmation/rollback. `AccountDeviceSession` wires `Engine<SqliteAccountStorage>` into an
app-facing session lifecycle (`SessionConfig`, `SessionEffects` / `PublishWork`).

It must not own MLS internals, transport event parsing, SQLCipher key derivation, account homes or signing-key storage
(those are `marmot-account`'s), UI projection, notifications, real relay auth, or transport-specific relay discovery.

## Layout

`src/lib.rs` is a thin facade: crate docs, `mod` declarations, and `pub use` re-exports. Every public item has a
`marmot_session::Item` path. Source is split into focused modules:

- `session.rs` — `SessionConfig`, `AccountDeviceSession`, `SessionEffects` / `PublishWork`, `SessionError`, and the
  engine items the session's API exposes, re-exported under their engine names. The module is private, and the root
  re-exports `AccountDeviceSession` and `IngestEffects` only under `test-support`.
- `error.rs` — `AccountError` and the `AccountResult` alias.
  `AccountError::as_engine_error` finds the engine error whether the runtime met it directly or through the session;
  ask it instead of matching `Engine(..)` or `Session(..)`.
- `key_package.rs` — `KeyPackagePublisher` trait, `KeyPackagePublication`, and `NoopKeyPackagePublisher`.
- `routing.rs` — `TransportRoutingPolicy` trait, `TransportRoutingError`, and `StaticTransportRouting`.
- `runtime.rs` — `AccountDeviceRuntime` plus its effect aggregates (`AccountDeviceEffects`, `AccountIngestEffects`,
  `PublishFailure`, `PendingResolution`), durable maintenance, and KeyPackage generator upgrades.
  - `runtime/slot_announcement.rs` — the slot-announcement gate (mdk#2628 3.4): while the host names a device group,
    no KeyPackage reaches this device's slot until this device's own roster entry there names it. Maintenance
    announces first.
  - `runtime/device_roster.rs` — the one roster write path (`edit_device_roster_entry`, mdk#2628 3.4, 3.6): one
    `SetDevice` commit replacing one device entry with an edit applied to the roster as read now. It sends nothing
    unless the device group is stable with nothing of this device's in flight, and sends the edit as
    `SendIntent::ReplaceDeviceEntry` naming the entry it read: the engine stages it only while the slot still holds
    that entry, so an entry is never replaced from a stale read (`DeviceEntryChanged` maps to `Busy`). Announcements,
    the tag signature key and the host's device edits all go through it; don't add another device-entry commit. Each
    announcement also writes the host's `DeviceSelfReport` (this device's client and platform) into its own entry.
  - `runtime/device_tag_key.rs` — this device's tag signature key (mdk#2628 3.1d): the host names the device group to
    tag from (`set_device_tag_group`). Maintenance, and the host before each KeyPackage publication
    (`set_device_tag_key_holding`), set this device's MLS signature key in its own roster entry when the entry lacks
    it, through `edit_device_roster_entry` like the announcement. No KeyPackage is staged, announced or published while the key is due and not
    in the merged roster, or while another device's entry carries it (the engine tags from whichever entry does), and
    a staged one that no longer advertises what this device would build is replaced. A refresh held back this way
    counts toward `key_package_refresh_overdue` like one held back by its announcement.
- `time.rs` — injectable wall clock, monotonic clock, and maintenance randomness (`SystemWallClock`,
  `SystemMonotonicClock`, `OsMaintenanceRandom`). Persist wall-clock values and sampled jitter; use monotonic time only
  for in-process windows and timeouts.

Tests: `tests/runtime.rs` plus `tests/runtime/` (frozen fanout, KeyPackage generator upgrade, component migration,
multi-device Welcome delivery), and the session's `tests/session_lifecycle.rs`, `tests/nostr_stack.rs` and
`tests/nostr_stack_chaos.rs`.

## Rules

### Session

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

### Runtime

- Keep the crate transport-generic. Nostr-specific publication belongs behind an injected boundary or in a
  transport-specific crate.
- Treat `StaticTransportRouting` as a test/simple harness implementation. A production Nostr routing policy should
  derive account inbox routes, KeyPackage publication routes, and group routes from Nostr/account state and the
  `marmot.transport.nostr.routing.v1` app component.
- Treat `KeyPackagePublisher` as provisional. The likely production direction is to move KeyPackage publication into the
  transport adapter family rather than keeping it as a separate app-core-owned publisher.
- Keep `AccountDeviceSession` as the owner of engine state.
- Keep the session private (mdk#2602). The root re-exports `AccountDeviceSession`, and any session type that only the
  session's own API hands out, only under `test-support`; a session type the runtime's public API, the facade or
  `marmot-app`'s production build names stays public. A session method the normal build never calls is deleted, unless
  tests call it through the re-export: then it keeps `#[cfg_attr(not(feature = "test-support"), allow(dead_code))]`
  on the method itself.
- Keep `AccountDeviceRuntime` the only production way to the session (mdk#2602). Hosts open it with
  `AccountDeviceRuntime::open`, which opens the session before it builds the host's transport. A session method a host
  needs becomes a runtime forward with the session's exact signature: same return type, error type and generics.
  Code a host hands the session to gets `group_authority_view()`, not the session. `session()`, `session_mut()` and
  `new` exist only under the `test-support` feature, which this crate's tests and `marmot-app` enable as a
  dev-dependency; never enable it in a normal dependency.
- Confirm pending work only after the adapter reports enough acknowledgements.
- Never let a durable maintenance record depend on an engine event alone. Engine events are in-memory, and this layer
  consumes them *after* awaiting the batch's relay publishes, so the loss window is network-wide. `GroupStateInvalidated`
  retires a `DurableGroupEvolution`, and `run_due_maintenance` re-derives that same retirement from the commit's stored
  disposition (`ConvergenceDeferred`/`EpochInvalidated`) so a lost announcement cannot strand it. Both paths go through
  `mark_evolution_superseded`; keep it the sole writer of `SupersededByConvergence`, and keep the derivation forward-only
  — nothing here un-marks a supersession on re-adoption. A supersession never revives a `Failed` obligation: that phase
  is a terminal verdict (`local_member_removed` is the live one), and re-arming it would send a `SelfUpdate` into a group
  the device has left, once per tick, uncounted by `MaintenanceRunSummary.failures`. `Complete` is deliberately not
  guarded — a withdrawn commit un-completing the obligation it satisfied is the PCS re-arm this layer owes. A pending
  leave or disband is not a terminal verdict: `run_due_maintenance` leaves the group's obligation untouched while
  either is in progress, since both can resolve with the device still a member.
- The same two reconcilers also hand a withdrawn own commit's intent back to the engine
  (`reissue_superseded_own_commit` on the event path, `reissue_superseded_own_commits_from_state` in
  `run_due_maintenance`) and return the engine's `SupersededIntentReport`s in `AccountDeviceEffects::superseded_intents`.
  Every seam that produces effects must carry them through (`extend`/`absorb`); `marmot-app` turns each report into one
  `MarmotAppEvent::GroupChangeSuperseded`, so a report dropped here is a saved change the user is never told was lost
  (mdk#1734).
- Roll back pending work when publication fails before any external exposure is possible. Once publication intent is
  durable and a relay may have accepted work, retain the journaled state and retry the exact or replaceable publication
  instead.

### Logs

- Do not log account ids, group ids, relay URLs, message ids, pubkeys, payloads, ciphertext, plaintext, or key material.
- Give every event explicit `target` and `method` fields (`docs/marmot-architecture/overview/observability.md`). Each
  target is `marmot_session::<module>`, the module that emits the event: `marmot_session::session` or
  `marmot_session::runtime` today.

## Verification

```sh
cargo test -p marmot-session
```
