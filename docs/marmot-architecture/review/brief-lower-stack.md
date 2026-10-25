---
title: "Extraction Brief — The Lower Stack into marmot-session"
created: 2026-10-24
updated: 2026-10-25
tags: [marmot, architecture, review, extraction-brief, session, account, engine]
status: proposed; product-owner decisions made 2026-10-25
---

# Extraction Brief — The Lower Stack into `marmot-session`

Step 5 of the [core structure plan](core-structure.md#5-sequencing). It makes one layer own the engine for an
account-device and gives the rest of the stack one handle on it, without changing behaviour beyond one deliberate
error-classification fix.

The lower stack is everything between `marmot-app` and the protocol core:
- `cgka-session` opens the engine on the account database, hydrates groups and collates the engine's effects;
- `marmot-account`'s runtime runs the publish pipeline, maintenance and KeyPackage lifecycle over a transport;
- `marmot-account`'s other half holds account identity, files and secrets;
- the engine, besides the protocol, stores account records for the layers above and owns the app's audit log.

Citations are at `b3ad5b074` (master after #2594). Following the [review's evidence rules](README.md#evidence-rules),
statements are observed in source unless marked (hypothesis). Counts size the work. The implementing PRs take the
full list of sites from the compiler, not from this brief.

## The shape in one paragraph

A new `marmot-session` crate takes `cgka-session` and the runtime half of `marmot-account`. Its one public type is
the runtime. The runtime opens the session, and the session becomes private. `marmot-account` keeps identity, files
and secrets, which is all that the bindings, the CLI and the agent connector use. The engine stops storing account
records for the layers above and stops owning the audit log. The session keeps those records on the storage handle
it already holds. The audit recorder becomes one shared handle that the engine, the runtime and the app each record
into. Before any of that, errors are classified by what they are rather than by the layers that carried them, so
moving a call between layers cannot change what a host sees.

## Why this version was reshaped

The first version was reviewed four times, by Codex and by Cursor. No review challenged the shape. Every finding was
a call whose behaviour a move would change. They had two causes:
- **Error shape** came up in every round:
  - a moved storage call changed how its error was wrapped, so bindings lost the typed storage outcome;
  - opening the session in the runtime would have bypassed the external-signer mapping applied where the app opens it;
  - forwards changed a method's error type, which a caller branches on.
  Each fix guarded one call. The class remained, because what a host sees depends on an error's wrapping.
- **Missed callers** came up in three rounds: a benchmark, an engine test, and places that pass the session around
  rather than call it. The brief listed sites by hand, and the compiler would have reported each one.

So this version adds PR 0, which removes the first cause. It also states rules for each PR instead of call-site
inventories.

## What is wrong today

**The top wrapper hands out the middle one.** `AccountDeviceRuntime::session()` and `session_mut()`
(`crates/marmot-account/src/runtime.rs:517-523`) let `marmot-app` skip the runtime. It does so about 70 times in
production, calling about 30 session methods. It also opens the session itself, and hands it to callbacks and helpers.
The runtime holds its own state about groups (maintenance pause, pending reconciliations, Welcome publishes in
flight), and calls that skip it skip that state.

**`marmot-account` is two crates that share nothing.** The identity half and the runtime half share no dependency
and no module except `error.rs`, which holds one unrelated enum for each. The bindings, the CLI and the agent
connector use only the identity half.

**The engine stores account records for the layers above.** `crates/cgka-engine/src/maintenance.rs` has 18 public
methods that are one call each to `MaintenanceStorage`. They cover the KeyPackage lifecycle record, group maintenance
state, obligations, group evolutions, transport fanouts and the periodic maintenance policy. Four of them check that
the group is live first (`ensure_group_live`, `crates/cgka-engine/src/engine.rs:2708`). That check enforces the
quarantine contract: a quarantined group fails as `UnknownGroup`, and an unhydrated one fails with the retryable
`GroupNotHydrated`. The layers above treat the two differently.

**The engine owns the app's audit log.** It holds the recorder. App audit rows travel from the app through the
runtime and the session into the engine, through a matching set of audit methods on each layer.

**What a host sees depends on how an error was wrapped.**
- A storage failure reaches the app in one of two forms:
  - the engine's form, `EngineError::Storage`, inside a session or account error;
  - the session's own form, `SessionError::Storage`.
- `AppError::as_engine_error` (`crates/marmot-app/src/error.rs:671-678`) finds the engine's form through either wrapper.
  It does not find the session's form.
- MarmotKit and the C ABI classify through it (`crates/marmot-uniffi/src/errors.rs:424`). So a busy, closed or full
  store is `StorageBusy`, `StorageClosed` or `StorageFull` in the engine's form, and a generic `Runtime` error in the
  session's form.
- Several app paths repeat the unwrapping by hand, each with its own list of shapes. Superseded-invite recovery, for
  example, returns the engine's form as an error but would only log the session's form.
- An external-signer rejection reaches the app as a sentinel string, because the signer hook returns `String`.
  - Transport errors check for the sentinel in their conversion to `AppError`, so every path is covered.
  - Session errors are checked at one call site, where the app opens the session (`crates/marmot-app/src/lib.rs:4682`).
- Today few session methods produce the session's form, so hosts rarely see the difference. The danger is for
  restructuring: any call moved between layers can change its wrapping, and with it what hosts see.

**Hosts name the lower stack.** `marmot-app` and `marmot-uniffi` import engine types for the session's
configuration and signer, because the session exposes them without re-exporting them.

## Rules every PR follows

1. **An error's outcome depends on what it is.** After PR 0, code may change which layer wraps an error, but never
   what the error is: a storage failure stays a storage failure of the same kind, and an engine error the same variant.
   The one deliberate exception is PR 0's own: an external-signer rejection becomes `ExternalSignerRejected` however
   it is wrapped. Production signs the identity proof only at session open, where the engine carries a rejection as a
   generic `EngineError::Other` whose text holds the sentinel (`crates/cgka-engine/src/engine.rs:560-567`).
2. **A forward keeps the forwarded method's signature**: return type, error type and generic parameters. A caller's
   code changes only its receiver.
3. **The compiler lists the sites.** Each PR removes or narrows a surface and fixes what the compiler then reports.
   Where something is handed the session rather than calling it, it gets the narrowest view that serves it.
4. **The engine is the only judge of group liveness.** Any account record that moves up and is scoped to a group
   keeps the engine's check and its exact errors.
5. **Every audit row goes to one recorder, in one sequence, and the file closes when the app says so,** not when the
   last owner happens to drop.
6. **Narrow in place, then move.** The crate move changes only paths.

## What changes

### 0. Errors classified by kind

- A session carries a storage failure one way, in the engine's form. Converting a `StorageError` into a
  `SessionError` produces `SessionError::Engine(EngineError::Storage(_))`, and the separate `Storage` variant goes.
- Code above the engine asks an error what it is through `as_engine_error` or a session-level equivalent. It never
  matches wrapper paths. The hand-written matchers in the app and the runtime switch to these helpers.
- The external-signer sentinel is recognised when any session or account error converts into `AppError`, the way it
  already is for transport errors: by the sentinel text, not by error variant. Nothing depends on the open call site.
- **This changes behaviour, on purpose:**
  - a storage failure that reaches a host in the session's form becomes typed, as the engine's form is today;
  - in the CLI it reports `engine_error` instead of `command_failed`;
  - a signer rejection inside any session or account error becomes `ExternalSignerRejected`, as a transport-path
    rejection is today. Today only the open call site maps it; on any other path it would surface as a generic engine
    error.

### 1. One public layer

- The runtime opens the session from a `SessionConfig` (`AccountDeviceRuntime::open`). `marmot-app` stops naming
  `AccountDeviceSession`.
- Each session method the app uses becomes a runtime method with the same signature. About 22 are new; the rest are
  already forwarded.
- The publication-progress observer and the conversation-window helpers are handed the session today. They get a
  read view whose one method is `with_group_authority_snapshot`, with the same generic signature and bounds.
- The draft-commit observer and legacy message promotion are storage operations on the connection `marmot-app` already
  opens for the engine. The app keeps its own clone of that handle for them.
- `session()`, `session_mut()` and `AccountDeviceRuntime::new(session, …)` leave the production surface. Tests keep
  them behind a `test-support` feature, because they drive the session directly to set up scenarios. Dev-dependency
  features do not reach normal builds, so a production use still fails to compile. `nostr-directory` uses the same
  pattern.
- The session type stays public through the move (PR 6), which changes only paths. PR 7 then makes it a private
  module that `test-support` re-exports.
- In a normal build the module is then private, so the `dead_code` lint lists candidate forwards to delete. A method
  that tests still call through the re-export stays, with the lint allowed for it in the normal build.

### 2. Account records on the session's own handle

- The session already holds a clone of the engine's storage handle, and SQLite implements `MaintenanceStorage`
  directly. The 18 forwards move onto that handle, and the engine deletes its 18 methods.
- The engine keeps liveness. One public check, `Engine::check_group_live`, wraps `ensure_group_live` unchanged.
  The four group-scoped accessors call it first.
- The tables, and the engine's transactions that write them, do not change.
- **What stays in the engine, and why:**
  - KeyPackage staging and promotion, which write OpenMLS material and the lifecycle record in one transaction;
  - the own-leaf hash, which reads OpenMLS group state;
  - the outbound-fanout accessors and pending-publication references. Core-structure §2.4 counted these as proxy
    methods, but they are the engine's own publish lifecycle: the confirm transaction writes them, the list accessors
    hide quarantined groups, and the references read the in-memory epoch manager.

### 3. Audit ownership

- `marmot-forensics` gains a shared recorder handle: a cloneable `ForensicRecorder` that delegates to a swappable
  inner recorder.
- The session wraps the configured recorder in the handle and gives the engine a clone at build. The runtime records
  through its clone. The app records, rotates and finishes through its own clone, never through the lower stack.
- The handle must be shared, because engine rows and app rows share one writer, session and sequence
  (`crates/cgka-engine/src/engine.rs:2948`). Two recorders would split the sequence.
- The file's lifetime becomes explicit.
  - Today it closes when the engine drops the last recorder.
  - With clones, one could outlive shutdown, and the next open would append to the same file with a second counter.
  - So finishing the audit log writes the stop row, then swaps in a no-op recorder, which closes the file.
- Rows keep their content.
  - The open-time recorder-health row is written by the session.
  - App rows keep the hex `group_ref` and context the engine gives them today.
  - Benchmarks install their recorder at build.
- **The engine's in-flight audit context leaks on cancellation.**
  - Send and create-group set it before awaited work and clear it after.
  - A dropped future skips the clear, so later context-less rows inherit the cancelled operation's context.
  - Whether production drops these futures mid-await is unverified (hypothesis).
  - PR 1 fixes this first with a drop guard, so recording app rows directly in PR 2 changes nothing.
- A side effect step 7 can use: recording an audit row no longer needs the account worker's runtime.

### 4. Hosts stop naming the lower stack

- This happens before the move, so the move only changes where the re-exports come from.
- The session crate re-exports the engine types its configuration and signer expose.
- `marmot-app` re-exports what hosts need: the account and session error types and the identity-proof signer types.
- `marmot-app` and `marmot-uniffi` then import nothing from `cgka-engine` in production, and `marmot-uniffi` drops the
  dependency.
- The error payloads change crate path only. Their privacy-safe kind strings, and so every binding, stay the same.

### 5. The crate move

```text
crates/marmot-session/           (git mv crates/cgka-session)
  src/lib.rs                     facade: the runtime, its effects, SessionConfig, errors, re-exports
  src/session.rs                 today's cgka-session lib.rs (private from PR 7)
  src/runtime.rs routing.rs key_package.rs time.rs   from marmot-account
  tests/                         cgka-session's tests plus marmot-account's runtime tests
crates/marmot-account/           home, io, keyring, nip49_export, secret_store, AccountHomeError
```

- `marmot-account` loses every protocol dependency.
- `marmot-app` keeps the engine connection's whole lifecycle: open, key, closer registration and close (mdk#2323).
  This brief moves none of it.
- CI scripts and workflows that name `cgka-session`, and the Windows lane's filter for the slow runtime test binary,
  follow the move. The Windows lane keeps running what it runs today.

## PR sequence

Each PR ships alone. PRs 0 and 1 change behaviour on purpose; PRs 2–8 preserve it.

| PR | Change | Check |
| --- | --- | --- |
| 0 | Errors classified by kind (item 0) | The cross-wrapping table test |
| 1 | Clear the engine's in-flight audit context with a drop guard | The cancellation test |
| 2 | Audit ownership (item 3) | The recorder tests; audit suites; the lifecycle bench builds |
| 3 | Account records (item 2) | The liveness table test; `hydration_quarantine` |
| 4 | One public layer (item 1), with the session type still public | `marmot-app` builds without `test-support`; app and account suites |
| 5 | Hosts stop naming the lower stack (item 4) | `marmot-uniffi` builds without `cgka-engine`; the PR 0 table |
| 6 | The move (item 5) | Path-only diff; the same tests per moved binary and per CI lane |
| 7 | The session becomes a private module, re-exported only under `test-support`; dead session forwards go | The compiler with and without `test-support`; the session, runtime and app suites |
| 8 | Tracing targets named after their new modules; the telemetry and architecture docs that name them | `tracing_audit`; a docs link check |

## Proof

- **PR 0:** a table test over every wrapping the lower stack can produce. Each row checks MarmotKit, the C status,
  the CLI code, the sync class and the privacy kind.
  - Each storage kind (busy, closed, full, other) and an ordinary engine variant must give the answer the engine's
    form gives today.
  - The signer sentinel must give the answer a transport-path rejection gives today: `ExternalSignerRejected` in
    MarmotKit and C, `command_failed` in the CLI, `Cancelled` sync class and the `external_signer_rejected` kind.
    It is tested in two forms: the open-time `EngineError::Other`, and the signing hook's own
    `EngineError::InvalidAccountIdentityProof`. A remap of one variant therefore fails.
  - An identity-proof failure whose text lacks the sentinel keeps the answer it gets today.
  The test then guards every later PR.
- **PR 1:** a test drops a pending send and a pending create-group, then checks that the next context-less row
  carries no operation context.
- **PR 2:**
  - app and engine rows interleave on one strictly increasing sequence;
  - a swap closes the old file before it returns;
  - after shutdown the stop row is last, and a surviving clone writes nothing;
  - the recorder-health row and app rows' `group_ref` are unchanged;
  - a disabled recorder still reads as disabled on the engine's hot path.
- **PR 3:**
  - a table over the four group-scoped accessors, the write included, against quarantined, unhydrated and live groups:
    `UnknownGroup`, `GroupNotHydrated`, or the stored result;
  - one row against a closed connection for every moved accessor, which PR 0's rule makes one shape.
- **PR 4:** rules 2 and 3. The production build is the inventory. The app's suites, the conversation-window suite
  among them, run unchanged.
- **PR 6:** the diff changes only paths: file renames, manifests, import paths, and the CI scripts and filters that
  name the crates. `cargo nextest list` shows the same tests per moved binary, and each CI lane, Windows included,
  selects the same tests as before.
- **All PRs:** the `marmot-app`, `marmot-account` (later `marmot-session`) and `cgka-engine` suites, plus
  `just simulator-smoke` for PRs 2–4, which touch the publish and convergence paths.

## Risks

- **A recorder clone outliving shutdown.** Rule 5 closes the file at the app's explicit finish. The one stop path that
  does not finish today (a failed stop) keeps today's behaviour: no stop row, and the file closes when the client drops.
- **PR 0 is visible.** The changelogs say so.
  - The few session-form storage failures that reach hosts change from generic to typed errors. Their CLI code
    changes from `command_failed` to `engine_error`.
  - A signer rejection on any path the open call site does not cover would change the other way: from a generic
    engine error (`Runtime`, `engine_error`) to `ExternalSignerRejected` (`command_failed` in the CLI).
- **Hot-path cost of the shared handle.** Each `is_enabled` and `record` call takes an uncontended read lock. Audit is
  off by default (hypothesis: not measurable; check with `cgka-engine/tests/apply_history_cost.rs`).
- **`test-support` hides production misuse in test builds.** The normal build still rejects it. `nostr-directory` and
  `storage-sqlite` accepted the same trade-off.
- **Rust API breaks.** `marmot_account::{AccountDeviceRuntime, AccountError, …}` and `cgka_session::*` move. No host
  uses them, and what the CLI's tests and the simulator use stays reachable from `marmot-app`.

## Out of scope

- Merging the session and runtime structs, or removing the runtime's internal forwards to the session. Once the
  session is private they are internal plumbing, so the crate is one layer from outside. Core-structure's target
  describes one layer that owns the engine; collapsing the two types inside it can follow if wanted.
- One routing implementation, one Welcome path, and moving KeyPackage publication into the transport family.
- Engine policy injection and naming `openmls_projection.rs` for what it does (step 8).
- Narrowing the engine beyond the proxy and the audit sink. The simulator drives the engine directly.
- Read-path or priority work (step 7).
- Renaming public types such as `AccountDeviceRuntime`, `AccountError` and `SessionConfig`.

## Done when

- `marmot-app` reaches the lower stack only through `marmot_session::AccountDeviceRuntime`, and production code names
  no `cgka_engine` item.
- `marmot-account` depends on no protocol crate, and `cgka-session` no longer exists.
- The engine has no account-record forwards and no audit-sink methods.
- App audit rows reach the recorder without passing through the runtime, session or engine.
- What a host sees for an error does not depend on its wrapping, and PR 0's table pins that.
- Every suite that ran before runs with the same tests.

## Product-owner decisions (2026-10-25)

All six were approved as recommended.

1. **Classify errors by kind first (PR 0).** It removes the class of change that four review rounds kept finding, and
   protects steps 6–8 too. Without it, each later PR would have to preserve every wrapping by hand.
2. **Narrow in place first, then move.**
   - Each narrowing PR delivers its value on its own, so the work can pause between PRs. The move (PR 6) follows the
     in-place narrowing of PRs 0–5. After it come only the step that needs one crate (PR 7) and the tracing rename
     (PR 8).
   - The cost is that the session type stays public until PR 7: it cannot become a private module while it lives in
     a different crate from the runtime.
   - Moving first could also change only paths, but it would rename the crates before any boundary improves.
3. **The session type, its accessors and `AccountDeviceRuntime::new` are public only under `test-support`.**
   - The accessors and `new` move behind the feature in PR 4.
   - The session type follows in PR 7, as a private module that the feature re-exports. Until then it stays public,
     as decision 2 explains.
   - Production sees one layer, and about 13k lines of tests keep working. Keeping the session public would leave a
     second public layer for tests.
4. **The outbound-fanout accessors and pending references stay in the engine,** for the reasons in item 2. This
   corrects core-structure's count of proxy methods.
5. **Hosts get the error and signer types from `marmot-app`.** This keeps the rule that hosts depend only on
   `marmot-app` and `marmot-account`, and lets `marmot-uniffi` drop `cgka-engine`.
6. **Type names stay through the move.** Renames are churn in every caller and change no boundary. A rename can follow
   as its own PR.
