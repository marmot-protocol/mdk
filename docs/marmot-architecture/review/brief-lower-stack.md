---
title: "Extraction Brief — The Lower Stack into marmot-session"
created: 2026-10-24
updated: 2026-10-24
tags: [marmot, architecture, review, extraction-brief, session, account, engine]
status: proposed
---

# Extraction Brief — The Lower Stack into `marmot-session`

Step 5 of the [core structure plan](core-structure.md#5-sequencing). It makes one layer own the engine for an
account-device and gives the rest of the stack one handle on it, without changing behaviour.

The lower stack is everything between `marmot-app` and the protocol core:
- `cgka-session` opens the engine on the account database, hydrates groups and collates the engine's effects;
- `marmot-account`'s runtime runs the publish pipeline, maintenance and KeyPackage lifecycle over a transport;
- `marmot-account`'s other half holds account identity, files and secrets;
- the engine, besides the protocol, stores account records for the layers above and owns the app's audit log.

`path:line` citations are at `b3ad5b074` (master after #2594). Production counts exclude test files and
`#[cfg(test)]` modules. A "forward" is a public function whose whole body is one call to the layer below. Following
the [review's evidence rules](README.md#evidence-rules), statements are observed in source unless marked
(hypothesis). Counts differ from [core-structure §2.3](core-structure.md#23-the-lower-stack-three-wrappers-no-narrowing),
which was measured at an earlier baseline with a different rule.

## The shape in one paragraph

A new `marmot-session` crate takes `cgka-session` and the runtime half of `marmot-account`. Its one public type is
the runtime. The runtime opens the session, and the session becomes private. `marmot-account` keeps identity, files
and secrets, which is all that the bindings, the CLI and the agent connector use. The engine stops storing account
records for the layers above and stops owning the audit log. The session reads and writes those records on the
storage handle it already holds. The audit recorder becomes one shared handle that the engine, the runtime and the app
each record into directly. The changes are made in place first, while the compiler still sees today's crates, so the
crate move at the end is mechanical.

## What the lower stack is today

| Part | Where | Production lines | What it does |
| --- | --- | ---: | --- |
| Session | `crates/cgka-session/src/lib.rs` | 1,763 | Opens the engine, hydrates groups, collates effects; 135 public functions, 85 of them forwards to the engine |
| Account runtime | `crates/marmot-account/src/{runtime,routing,key_package,time}.rs` | 6,688 | Publish-before-apply, maintenance, KeyPackage lifecycle, transport activation; 102 public functions, 31 of them forwards to the session |
| Account identity | `crates/marmot-account/src/{home,io,keyring,nip49_export,secret_store}.rs` | 2,627 | Account home layout, signing keys, secret stores |
| Engine | `crates/cgka-engine/src/` | — | 124 public inherent methods on `Engine<S>` plus the `CgkaEngine` trait |

**Three wrappers, and the top one hands out the middle one.**
- `AccountDeviceRuntime::session()` and `session_mut()` (`crates/marmot-account/src/runtime.rs:517-523`) let
  `marmot-app` skip the runtime.
- It does so 69 times in production, calling 32 session methods from 9 files:
  - 7 are audit methods, with 28 calls;
  - 2 are storage-only app concerns, the draft-commit observer and legacy message promotion, with one call each;
  - 23 are session reads and writes the runtime does not offer, with 39 calls.
- `marmot-app` also opens the session itself and passes it to `AccountDeviceRuntime::new`
  (`crates/marmot-app/src/lib.rs:4682`, `:4747`).

**`marmot-account` is two crates that share nothing.**
- The two halves share no module. The identity half uses `crate::{error, io, nip49_export, secret_store}`, and the
  runtime half uses `crate::{error, key_package, routing, time}`.
- The only shared file is `error.rs`, which holds two unrelated enums: `AccountHomeError` and `AccountError`.
- Their dependencies are disjoint too:
  - the identity half uses `nostr`, `keyring-core`, `libc`, `fs-private`, `serde_json` and `zeroize`;
  - the runtime half uses `cgka-session`, `cgka-traits`, `marmot-forensics`, `futures`, `async-trait` and `rand`.
- The bindings, the CLI and the agent connector use only the identity half: `AccountHome`, its error and summary
  types, and the secret stores.

**The engine stores account records for the layers above.**
- `crates/cgka-engine/src/maintenance.rs` has 21 public methods. 18 are one call to `MaintenanceStorage`:
  - the KeyPackage lifecycle record;
  - group maintenance state;
  - maintenance obligations;
  - group evolutions;
  - transport fanouts;
  - the periodic maintenance policy.
- Each of the 18 has exactly one caller, a forward in `cgka-session`. Neither the engine itself nor the simulator
  calls them. Engine tests reach the same records through storage, not the engine.
- Four of the 18 first check that the group is live (`ensure_group_live`, `crates/cgka-engine/src/engine.rs:2708`).
  That check enforces the quarantine contract: a quarantined or unhydrated group looks unknown on every accessor.

**The engine owns the app's audit log.**
- The engine holds the recorder as `Box<dyn ForensicRecorder>` (`engine.rs:261`).
- App audit rows travel from the app through the runtime and the session into the engine: `audit_external`,
  `audit_v5_event`, `audit_v5_enabled`, `finish_audit_v5_recording`, `audit_recorder_path`, `rotate_audit_recorder`
  and `set_recorder` (`engine.rs:2924-2999`).
- Each of these has one caller, a session forward.

**`marmot-app` imports engine types for the session's configuration and signer.**
- `FeatureRegistry`, `CanonicalizationPolicy`, `GroupAuthoritySnapshot`, `AccountIdentityProofSigner` and
  `AccountIdentityProofRequest`, three KeyPackage helpers, and `V1_SETTLEMENT_QUIESCENCE_MS`.
- That is 7 production files (`lib.rs:15-17`, `external_signer.rs:4-6`).
- `marmot-uniffi` imports the identity-proof signer the same way (`crates/marmot-uniffi/src/external_signer.rs:4-6`).

## What changes

### 1. One public layer

- The runtime opens the session from a `SessionConfig` (`AccountDeviceRuntime::open`). `marmot-app` stops naming
  `AccountDeviceSession`.
- The runtime gains a forward for each of the 23 session methods the app calls.
- `session()`, `session_mut()` and `AccountDeviceRuntime::new(session, …)` leave the production surface, and the
  session becomes a private module. Tests keep all three behind a `test-support` feature, because they drive the
  session directly to set up scenarios:
  - `marmot-account`'s runtime tests make 219 such calls to 28 session methods, `send`, `ingest` and `create_group`
    among them;
  - `marmot-app`'s tests use them too.
  Dev-dependency features do not reach normal builds, so a production use still fails `cargo build -p marmot-app`.
- The draft-commit observer and legacy message promotion are storage operations on the engine's own connection.
  `marmot-app` opens that connection and hands it to `SessionConfig::with_storage` (`lib.rs:4604-4644`).
  - It keeps a clone of the handle and calls both operations on it.
  - The clone shares the connection and the observer slot, which is an `Arc` (`crates/storage-sqlite/src/cross/outbound.rs:46-47`).
  - The observer is still installed lazily, before the first draft submission, as today.
- Session forwards that nothing calls once the runtime is the only caller are deleted. The compiler finds them.

### 2. Account records on the session's own handle

- The session already holds a clone of the engine's storage handle (`crates/cgka-session/src/lib.rs:243-247`).
  `SqliteAccountStorage` implements `MaintenanceStorage` directly (`crates/storage-sqlite/src/protocol/storage/maintenance.rs:12`).
- The 18 forwards move to the session over that handle, and the engine's 18 methods are deleted.
- The engine gains one public check, `Engine::check_group_live`, which wraps `ensure_group_live` unchanged. The four
  group-scoped accessors call it first, so quarantined and unhydrated groups still look unknown.
- The tables stay on the protocol side of the storage boundary (`crates/storage-sqlite/src/base/table_owners.rs:28-48`).
  The engine keeps writing them inside its own transactions; nothing about the transaction boundaries changes.

**What stays in the engine, and why:**
- `stage_key_package_replacement` and `promote_key_package_lifecycle`. Each writes OpenMLS KeyPackage material and the
  lifecycle record in one transaction (`maintenance.rs:47-138`).
- `own_leaf_hash`, which reads OpenMLS group state.
- The outbound-fanout accessors and pending-publication references (`engine.rs:869-962`). Core-structure §2.4
  counted them with the proxy, but they are the engine's own publish lifecycle:
  - the confirm transaction writes these records;
  - the list accessors hide quarantined and unhydrated groups;
  - the pending references read the in-memory epoch manager.

### 3. Audit ownership

- `marmot-forensics` gains a shared recorder handle.
  - It is a cloneable value that implements `ForensicRecorder` by delegating to a swappable inner recorder.
  - Swapping returns the old recorder, so dropping it flushes and closes its file at a known instant, as
    `set_recorder` does today.
- The session wraps the recorder from `SessionConfig` in this handle and gives the engine a clone at build. The
  engine's own rows are unchanged, and it never swaps the recorder.
- The runtime records through its clone. `marmot-app` keeps a clone in `AppClient` and records, swaps, rotates and
  finishes through it, never through the runtime.
- The session deletes its 8 audit forwards. The engine deletes the 7 methods listed above, plus
  `audit_recorder_health`: the session writes the open-time recorder-health row itself, with the same content.
- A side effect that step 7 can use: recording an audit row no longer needs the account worker's `&runtime`.

**Why the app's rows keep their content.**
- `audit_external` falls back to the engine's in-flight operation context (`engine.rs:2915`).
- That context is set and cleared only inside `&mut self` send and create-group calls (`engine.rs:1136`, `:1149`,
  `:1215`, `:1251`).
- An app row arrives through `&self` while no such call can be running, so it always took the explicit context or
  none. Recording it directly keeps that.

**Why the handle must be shared.** Engine rows and app rows share one writer, session and sequence: "native v5
evidence shares the recorder's source, session and sequence with engine audit rows" (`engine.rs:2948`). Two
recorders would split that sequence.

### 4. Hosts stop naming the lower stack

- `marmot-session` re-exports the engine types its configuration and signer expose.
- `marmot-app` re-exports what hosts need: `AccountError`, `SessionError` and the identity-proof signer types.
  `MaintenanceTiming` is already re-exported (`crates/marmot-app/src/lib.rs:152`).
- `marmot-app` and `marmot-uniffi` then import nothing from `cgka-engine` in production. `marmot-uniffi` drops the
  dependency.
- The `AppError::Account` and `AppError::Session` payloads (`crates/marmot-app/src/error.rs:105`, `:109`) change
  crate path only. Their `privacy_safe_kind` strings, and so every binding, are unchanged.

### 5. The crate move

```text
crates/marmot-session/           (git mv crates/cgka-session)
  src/lib.rs                     facade: the runtime, its effects, SessionConfig, errors, re-exports
  src/session.rs                 private: today's cgka-session lib.rs
  src/runtime.rs routing.rs key_package.rs time.rs   from marmot-account
  tests/                         cgka-session's tests plus marmot-account's runtime tests
crates/marmot-account/           home, io, keyring, nip49_export, secret_store, AccountHomeError
```

- `marmot-session` depends on `cgka-engine`, `cgka-traits`, `storage-sqlite` and `marmot-forensics`, plus the
  runtime's `futures`, `async-trait`, `rand`, `sha2` and `hex`.
- `marmot-account` loses every protocol dependency. Hosts that use it no longer compile the engine through it
  (hypothesis on build time; they still compile it through `marmot-app`).
- The session tests (3,135 lines) exercise `AccountDeviceSession` directly with a no-network Nostr stack. The runtime
  tests (10,188 lines) build runtimes from sessions and reach through them. Both keep working through the
  `test-support` feature from item 1, the same pattern `nostr-directory` uses.
- `marmot-app` keeps the engine connection's whole lifecycle: open, key, closer registration and close (mdk#2323).
  This brief moves none of it.

## PR sequence

Each PR is behaviour-preserving and ships alone. PRs 1–3 narrow in place, PR 4 moves, PR 5 renames.

| PR | Change | Check |
| --- | --- | --- |
| 1 | Audit ownership: the shared recorder handle; the engine, runtime and app record into clones; delete the session's 8 audit forwards and the engine's 7 audit methods | Sequence, swap and context tests (below); existing audit suites |
| 2 | Account records: move the 18 engine forwards onto the session's handle; add `Engine::check_group_live`; delete the engine's 18 methods | Quarantine table test (below); `hydration_quarantine` and `publish_lifecycle` unchanged |
| 3 | One public layer: `AccountDeviceRuntime::open`; runtime forwards for the 23 session methods the app calls; the app's own clone of the engine connection for the two storage-only calls; `session()`, `session_mut()`, `AccountDeviceRuntime::new` and the session type only under `test-support`; remove the forwards nothing calls | `cargo build -p marmot-app` without dev-dependencies; `marmot-app` and `marmot-account` suites |
| 4 | The move: `git mv crates/cgka-session crates/marmot-session`; move the runtime half and `AccountError` into it; repoint `marmot-app`, the simulator and the tests; the re-exports from item 4; CI, README and AGENTS updates | Rename-only diff (`git diff -M`); same test list per moved binary |
| 5 | Name the tracing targets after their modules: `cgka_session::session` becomes `marmot_session::session`, and `marmot_account::runtime` becomes `marmot_session::runtime`; update `docs/marmot-architecture/telemetry.md:775` and the current architecture docs that describe these crates | `tracing_audit`; a docs link check |

**CI follow-through in PR 4:**
- `scripts/classify_ci_changes.py:41-86` and `.github/workflows/wn-agent-binaries.yml:39-41` name `cgka-session`.
- The Windows lane excludes `marmot-account`'s runtime binary because it is slow (`.github/workflows/ci.yml:1229-1236`).
  After the split that binary lives in `marmot-session`, so the filter goes. The Windows lane keeps running exactly
  what it runs today: the home tests.
- The iOS keychain clippy job (`ci.yml:413`) stays on `marmot-account`.

## Proof that behaviour is unchanged

- **PR 1:**
  - One recorder sequence across sources: in a scripted send, the app's rows and the engine's rows interleave on one
    strictly increasing sequence, as they do today.
  - A swap drops the old recorder and closes its file before the call returns.
  - An app row recorded right after a send carries only its explicit context.
  - A disabled recorder still reports disabled to the engine's hot-path checks.
- **PR 2:** a table test over the four group-scoped accessors and three group states, run against PR 2's session:
  - quarantined → `UnknownGroup`;
  - unhydrated → `GroupNotHydrated`;
  - live → the stored record.
  The non-group accessors return what `MaintenanceStorage` returns. SQLite always provides that storage, so the
  engine's "maintenance storage is unavailable" error could not occur on this path.
- **PR 3:** every new runtime method is a forward of an existing session method. The app's calls change receiver, not
  arguments.
- **PR 4:** no code changes except paths. `git diff -M` shows renames, and `cargo nextest list` shows the same tests
  per moved binary before and after.
- **All PRs:** the `marmot-app`, `marmot-account` (later `marmot-session`) and `cgka-engine` suites, and
  `just simulator-smoke` for PRs 1–3, because they touch the publish and convergence paths.

## Risks

- **The quarantine contract.** Moving group-scoped accessors out of the engine could let them skip the live check.
  `check_group_live` keeps the engine as the only judge, and PR 2's table test pins all four accessors. Any later
  accessor that moves up needs the same check.
- **A recorder clone outliving shutdown.** Today the recorder closes when the engine drops. Shutdown already calls
  `finish_audit_recording` (`crates/marmot-app/src/runtime/account_worker.rs:1181`, `:1368`). PR 1 also swaps in
  `NoopRecorder` there, so the file closes at the same point even if a clone lingers.
- **Hot-path cost of the shared handle.** Each `is_enabled` and `record` call takes an uncontended read lock. Audit is
  off by default, and the engine checks the recorder's `is_enabled` or `records_v5` in three places (hypothesis: not
  measurable; check with `cgka-engine/tests/apply_history_cost.rs`).
- **`test-support` hides production misuse in test builds.** With the feature on, a production call to `session()`
  compiles in `marmot-app`'s test build. The normal build still rejects it. That is the same trade-off
  `nostr-directory` and `storage-sqlite` accepted for their test hooks.
- **Rust API breaks.** `marmot_account::{AccountDeviceRuntime, AccountError, …}` and `cgka_session::*` move. No host
  uses them; the CLI's tests and the simulator use `AccountError` and `MaintenanceTiming`, which stay reachable from
  `marmot-app`. The changelogs say so.

## Out of scope

- Merging the session and runtime structs, or removing the runtime's internal forwards to the session. With the
  session private they are internal plumbing, and removing them is a refactor with no boundary benefit.
- One routing implementation: `marmot-app`'s `AppTransportRouting` still copies `StaticTransportRouting`.
- One Welcome path: the "legacy" `DurableTransportFanout` is still the live Welcome rail.
- Moving KeyPackage publication into the transport family (`KeyPackagePublisher` is marked provisional).
- Engine policy injection and naming `openmls_projection.rs` for what it does (step 8).
- Narrowing the engine beyond the proxy and the audit sink. The simulator drives the engine directly.
- Any read-path or priority work (step 7).
- Renaming public types such as `AccountDeviceRuntime`, `AccountError` and `SessionConfig`.

## Done when

- `marmot-app` reaches the lower stack only through `marmot_session::AccountDeviceRuntime`, and production code names
  no `cgka_engine` item.
- `marmot-account` depends on no protocol crate, and `cgka-session` no longer exists.
- The engine has no account-record forwards and no audit-sink methods.
- App audit rows reach the recorder without passing through the runtime, session or engine.
- The quarantine table test and the recorder tests pass, and every suite that ran before runs with the same tests.

## Product-owner decisions (proposed)

1. **Narrow in place first, then move.** Recommended: it keeps the move PR rename-only. The alternative, moving first,
   puts real changes inside a large rename diff.
2. **The session type, `session()`/`session_mut()` and `AccountDeviceRuntime::new` are public only under
   `test-support`.** Recommended: production code sees one layer, and about 13k lines of tests keep working
   unchanged. The alternative keeps the session public for its tests, which leaves a second public layer.
3. **The outbound-fanout accessors and pending references stay in the engine.** Recommended, for the reasons in
   §2. This corrects core-structure's count of nine more proxy methods there.
4. **Hosts get the error and signer types from `marmot-app`.** Recommended: it keeps the dependency rule "hosts depend
   only on `marmot-app` and `marmot-account`" true, and lets `marmot-uniffi` drop `cgka-engine`.
5. **Type names stay through the move.** Recommended: renames are churn in every caller and change no boundary. They
   can follow later if wanted.
