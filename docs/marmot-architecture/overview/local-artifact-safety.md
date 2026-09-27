---
title: "Local Artifact Safety"
created: 2026-07-02
updated: 2026-09-19
tags: [marmot, overview, security, filesystem, permissions]
status: overview
---

# Local Artifact Safety

Every local file, directory, socket, or database Marmot creates must be restrictive **by construction**: the artifact
is created already at its target owner-only mode, never chmod-ed after it is reachable or holds data. This is the
local-resource twin of the network endpoint-safety policy (mdk#378; the pattern behind mdk#345, mdk#346, mdk#347,
mdk#357, mdk#367, mdk#396).

## The rules

- **No post-hoc chmod window.** Files are opened with `O_CREAT` + mode 0600 (directories: atomic 0700 `DirBuilder`).
  A `set_permissions` call after creation is only allowed belt-and-braces on top of a mode-at-create open, or to
  tighten artifacts left behind by older builds.
- **Sockets bind in staging.** Unix listeners are bound inside a fresh 0700 staging directory, chmod-ed there, and
  hard-linked onto the final path, so the socket never exists at umask-default permissions — even under a
  caller-supplied `--socket` in a directory the daemon does not own.
- **One mode parser.** `fs_private::parse_octal_mode` is the workspace's only octal permission-mode parser. Policy on
  acceptable modes (e.g. rejecting world bits on control sockets) stays with callers.
- **Databases are pre-created 0600.** The DB file is created 0600 *before* the path is handed to
  rusqlite/SQLCipher; SQLite then copies that mode onto the `-wal`/`-shm`/journal sidecars it creates. Sidecars from
  older builds are tightened on open. This applies to encrypted databases too: sidecars and the unencrypted shared
  cache have no cipher protecting them.
- **Must-precede-data PRAGMAs are applied before data.** Durability/privacy PRAGMAs that only affect subsequent
  writes (`secure_delete`, cipher settings) are applied at connection open — or, when toggled around an operation,
  set on the connection *before* `BEGIN` and restored after commit/rollback. SQLite does not guarantee zero-on-free
  for pages freed in the same transaction that toggles `secure_delete`.

## The helpers

`crates/fs-private` owns the shared implementations: `write_private`, `open_private_append`, `create_new_private`,
`ensure_private_file`, `tighten_existing_private_file`, `create_dir_all_private`, `set_private_file_mode`,
`parse_octal_mode`, `bind_unix_listener_private`, and `rename_noreplace_with_lock`.

**Coverage rule:** new code that creates a local file, socket, or database calls these helpers (or proves equivalent
restrictive-by-construction posture with an on-disk mode test) instead of re-deriving umask/chmod/PRAGMA ordering.
`crates/marmot-account/src/io.rs` (`write_file_atomically` with `FileMode::Private`) is a compliant-equivalent
implementation that predates the shared crate.

## Initializing encrypted account databases

Concurrent first opens of one database serialize salt selection, legacy rekey,
schema migration and cache publication. Waiters recheck the cache after taking
that database's lock; unrelated databases can still open in parallel. Production
root leases exclude other processes. Lock order is storage lifecycle admission,
then the per-database initialization lock, then cache publication; terminal close
waits for admitted opens before draining caches.

Salts and external-signing storage secrets are published from unique 0600 staging
files only after their contents are synced. On Android, where app SELinux domains
forbid hard links, all publishers take an exclusive `flock` on a stable 0600
`<destination>.publish.lock` sibling, check for an existing entry without following
symlinks, and rename only when absent. Competing publishers wait and adopt the
complete winner. The lock covers each destination, including storage secrets
shared by different databases, and releases on descriptor close or process exit.
Lock files remain in place; never unlink or replace them while publishers can run.
This uses Android API 26-compatible operations and adds no minimum-API requirement.
Other platforms, including iOS and macOS, retain atomic hard-link publication and
require storage roots to support same-directory hard links. Both paths refuse to
replace existing key material and expose no partially written destination. There
is no in-place-write fallback because readers could consume incomplete key material.
Generated accounts remain unavailable to attention readers and managed workers
until the setup journal reaches `LocalReady`. A failed pre-readiness resume keeps
its account files and keys while healthy accounts start. Neither journal state
nor file size proves an unreadable encrypted database empty; no automatic deletion
or salt replacement is a recovery operation.
If setup context was never persisted, startup reports an account error and
leaves the identity preparing. Retrying generated-account creation with the
host's setup request resumes that same identity and supplies the missing context;
startup cannot guess the user's relay configuration. Interrupted staging files
remain private and are never adopted or swept during another writer's publication.

## Releasing artifacts before host suspension

Creation posture is not the only thing a shared container polices. On iOS the Marmot root lives in an App Group
container shared with the Notification Service Extension, and a process suspended while holding **any** file lock
there is killed with `RUNNINGBOARD 0xdead10cc`. Two artifacts hold such a lock by design:

- every SQLite connection in WAL mode, which holds a shared lock on its `-shm` sidecar for its entire lifetime, and
- the root runtime lease (`.marmot-runtime.lock`), an advisory lock held for as long as any app/runtime handle lives.

So a host needs an operation that ends those at a known instant and can be awaited. Dropping handles is not that
operation: the databases live behind `Arc`s reachable from the engine, the OpenMLS adapter, and app projections at
once, so no host can observe or await the last clone going away, and `shutdown()` takes `&self` and therefore cannot
drop anything.

**The rules:**

- **Close, don't drop.** Every long-lived SQLite handle is built on `storage_sqlite::CloseableConnection`, which takes
  the connection out of its slot, checkpoints (`PRAGMA wal_checkpoint(TRUNCATE)`), and closes it. Surviving clones then
  fail with `StorageError::Closed` rather than panicking or keeping the file locked.
- **Closing is terminal, and nothing reopens.** `MarmotApp::close_storage` latches, and every database accessor
  refuses afterwards. A late background read that transparently reopened would re-lock the container the host was just
  told is clear — the exact failure the close exists to prevent. Hosts construct a fresh runtime on resume.
- **Terminal close precedes best-effort drain.** `MarmotAppRuntime::shutdown_and_close` closes runtime admission, every
  database, and the root lease before it gives graceful directory, account, relay, audit, and account-open cleanup a
  bounded budget. Those subsystems can await network or task progress and therefore cannot sit ahead of the lock-release
  boundary on a host suspension deadline. The terminal operation is runtime-owned and continues if its caller is
  cancelled.
- **The cut is transaction-safe, but not operation-transparent.** A statement that already owns a connection guard is
  allowed to finish; closing rolls an uncommitted SQLite transaction back, and later work receives
  `StorageError::Closed`. A higher-level operation composed of multiple transactions or an external side effect can be
  cut between its steps and must rely on durable intent/reconciliation. This is the deliberate suspension tradeoff: a
  forced process kill is at least as abrupt and also leaves the container lock held until RunningBoard terminates it.
- **Completion means completion.** The early close latch rejects new work, but `storage_is_closed` becomes true only
  after all database closes have been attempted and the root lease has been released. Repeated and concurrent terminal
  closes are safe.
- **Bail out at engine-step boundaries, not inside them.** Shutdown checks belong between whole engine operations
  (`RuntimeLifecycle::is_stopping()` in the account worker's per-group loops), where no snapshot guard is live.
  Interrupting *inside* a step can leave a `SnapshotRollbackGuard`'s window half-applied, which is worse than the kill.

`StorageError::Closed` is deliberately its own variant, and non-transient: work racing a close must be reportable as
"we shut down" rather than as a storage fault the user is shown.

## Shared-home access and corruption detection

Commands that may mutate account storage acquire the same root lease as `wnd`
and `wn-agent`. Pure account metadata listing does not open a hydrated runtime
and remains available to concurrent direct `wn` callers. When `wnd` owns the
home, CLI commands that need the runtime, including logout and foreground
stream watches, use its socket. A failed implicit socket connection does not
bypass ownership for mutations. Connector clients use `wn-agent` agent-control;
the two socket protocols are not interchangeable. Babysitter automation that
previously launched `wn` against a live `wn-agent` home must send supported
operations through agent-control instead. For administration outside that
facade, stop the owner and use a coordinated offline window before invoking
`wn`; a direct CLI mutation during live connector ownership returns
`runtime_busy`.

The lease remains root-wide, including when `--account` selects one of several
accounts. The root contains shared SQLite metadata and caches, and the app
runtime owns account workers as one unit. Two independent runtime processes
cannot safely mutate different accounts under the same home today. Use one
`wnd` owner and send commands through it, or use separate home roots for
independent processes. A per-account lease requires a separate design for
shared-root storage and runtime ownership.

Ready account workers check SQLite structure every 120 seconds without
opening a second database connection. The check has a one-second SQLite VM
budget and runs on a blocking worker. Database size and filesystem delay can
still make a check incomplete; three consecutive incomplete or overdue
intervals raise an error-level diagnostic, while a completed healthy check
clears the streak.
`corrupt` and `incomplete` are fixed, privacy-safe diagnostic categories.
This detects structural damage; it does not repair it, check every index or
foreign key, or prove MLS semantic consistency. A pending close may wait for
the connection guard held by an already-started check; I/O outside SQLite's
VM is not preemptible by the budget.

## Deliberate exception

The application root directory's mode is left as-is when it already exists: retroactively chmod-ing the root of
existing installs is a behavior change outside this policy's scope. File-level 0600 inside it is the guarantee.

## Scope

This policy covers *creation-time* posture (permissions, creation ordering, mode parsing, PRAGMA-at-open) and the
*release* posture above (closing connections and locks before host suspension). Handling
of secret contents in memory, logs, and FFI is tracked separately under the sensitive-material discipline; tracing
rules live in [`observability.md`](./observability.md).

## Current enforcement

On-disk mode tests accompany each artifact path: `fs-private` unit tests, the daemon/connector socket tests, the
`storage-sqlite` DB/sidecar mode tests, the `marmot-forensics` audit-file tests, and the `marmot-app`
device-id/key-reveal/salt/cache tests. All assert `mode & 0o777` on the real files.
