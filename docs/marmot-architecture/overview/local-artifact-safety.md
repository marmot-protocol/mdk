---
title: "Local Artifact Safety"
created: 2026-07-02
updated: 2026-10-15
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
  cache have no cipher protecting them. Use `fs_private::ensure_private_db_files`, never the general file helpers.
- **Never open a database file outside SQLite** (mdk#2351). On POSIX, closing *any* descriptor on a file releases
  every `fcntl` lock the process holds on it, and SQLite never notices (SQLite "How To Corrupt", section 2.2). An `open`/`close` of
  the database or a `-wal`/`-shm`/`-journal` sidecar while this process holds a connection to it silently drops that
  connection's SHARED lock and `-shm` read locks. Another process, such as the iOS Notification Service Extension
  sharing the App Group root, can then take the database exclusively, checkpoint or truncate the WAL, or reinitialise
  `-shm` under the live connection. So `ensure_private_db_files` creates only a *missing* main file through a
  descriptor (`O_CREAT | O_EXCL`, serialized in-process so a concurrent preparer cannot let SQLite lock the new file
  before that descriptor closes) and tightens existing files by path (`lstat` + no-follow `chmod`), never by opening
  them. Reading, copying or hashing a database file through `std::fs` while this process may hold a connection to it
  is forbidden for the same reason; go through SQLite (`VACUUM INTO`, the backup API) instead. Cross-process lock
  probes are only trustworthy because of this rule.
- **Must-precede-data PRAGMAs are applied before data.** Durability/privacy PRAGMAs that only affect subsequent
  writes (`secure_delete`, cipher settings) are applied at connection open — or, when toggled around an operation,
  set on the connection *before* `BEGIN` and restored after commit/rollback. SQLite does not guarantee zero-on-free
  for pages freed in the same transaction that toggles `secure_delete`.

## The helpers

`crates/fs-private` owns the shared implementations: `write_private`, `open_private_append`, `create_new_private`,
`ensure_private_file`, `tighten_existing_private_file`, `ensure_private_db_files` (SQLite databases only),
`create_dir_all_private`, `set_private_file_mode`, `parse_octal_mode`, `bind_unix_listener_private`, and
`rename_noreplace_with_lock`.

**Coverage rule:** new code that creates a local file, socket, or database calls these helpers (or proves equivalent
restrictive-by-construction posture with an on-disk mode test) instead of re-deriving umask/chmod/PRAGMA ordering.
`crates/marmot-account/src/io.rs` (`write_file_atomically` with `FileMode::Private` or `FileMode::Secret`) is a
compliant-equivalent implementation that predates the shared crate. Both modes rename a synced 0600 temp file over
the target, so a reader sees the whole previous file or the whole new one. Only `FileMode::Secret` (signing keys)
zeroes the replaced inode. It does so after the rename unlinks it, and `read_secret_json` re-reads when it finds its
inode unlinked. Private account state such as the setup journal is never zeroed, because readiness polls read it
while background setup rewrites it.

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

## Encrypted media files

Retained attachment bodies are moving out of the account database into one encrypted file each (mdk#2314), under
`<account>/media/<shard>/<id>` next to the database. The `media-store` crate owns the files and their lifecycle. The
account database stays the authority: each file's random key and state live in its `media_files` row, which
`storage-sqlite` serves to the crate through its catalog trait.

- **Media files take no locks.** Never use `flock`/`fcntl` on them, and never use the lock-based
  `rename_noreplace_with_lock` publish meant for key material. Each file has a unique random name and one writer, so
  creating, writing and syncing it need no lock. Writers serialize on the database row instead. This keeps media out of
  the suspension rules below: a suspended process can hold no lock on a media file.
- **Row first, then file, then commit.** A `pending` row commits before the file is exclusively created at 0600 and
  written. The file is synced once and then one transaction marks it `ready`. There is no temporary name, rename or
  directory sync, because the `pending` row already marks the file unfinished. A power loss that drops a new file's
  directory entry after the `ready` commit surfaces as a *lost* row, never as wrong bytes.
- **Plain `fsync`.** On Apple platforms media files sync with plain `fsync`, which is SQLite's own durability there,
  not Rust's `sync_all` (`F_FULLFSYNC`). Other platforms use `fsync`.
- **Delete the key, then the file.** Deleting the row under `secure_delete` is the real erase. The unlink that follows
  is best effort, and the sweep removes any file whose row is gone.
- **Terminal close covers media.** Once the account database closes, or the store's own close latch is tripped, media
  reads (including open readers), writes and sweeps fail with `Closed`. The store joins the runtime's close path; it
  never adds a second one.
- **Never on async threads.** The store's API is blocking (file I/O, hashing, AEAD). Runtime callers run it on the
  blocking pool, never inline on an account worker.
- **Hosts exclude the account directory from backups** (iCloud and Android auto-backup). Its keys are device-bound,
  so a restored database, salt or media directory would be unreadable anyway.

## Releasing artifacts before host suspension

Creation posture is not the only thing a shared container polices. On iOS the Marmot root lives in an App Group
container shared with the Notification Service Extension, and a process suspended while holding **any** file lock
there is killed with `RUNNINGBOARD 0xdead10cc`. Two artifacts hold such a lock by design:

- every SQLite connection in WAL mode, which holds a shared lock on its `-shm` sidecar for its entire lifetime, and
- the root runtime lease (`.marmot-runtime.lock`), an advisory lock held for as long as any app/runtime handle lives.

So a host needs an operation that ends those at a known instant and can be awaited. Dropping handles is not that
operation: a connection lives behind `Arc`s shared with the OpenMLS adapter and app projections, so no host can
observe or await the last clone going away, and `shutdown()` takes `&self` and therefore cannot drop anything. Nor
does any one cache hold every connection: each account has two connections to `session.sqlite`, the app's cached one
and the one its engine opens for itself.

**The rules:**

- **Close, don't drop.** Every long-lived SQLite handle is built on `storage_sqlite::CloseableConnection`, which takes
  the connection out of its slot, checkpoints (`PRAGMA wal_checkpoint(TRUNCATE)`), and closes it. Surviving clones then
  fail with `StorageError::Closed` rather than panicking or keeping the file locked.
- **Register, don't cache.** Every resource that can hold a lock in the root registers a closer with the app when it
  opens, under the same storage-open admission the close takes exclusively, so an open either registers before the
  close drains the list or refuses. `MarmotApp::close_storage` closes that list, not the handle caches. A closer
  (`storage_sqlite::DatabaseCloser`) holds only a weak reference, so an owner that drops its last handle still releases
  the lock then. This is how the close reaches each account engine's own connection while its worker is still running
  or its open is still in flight.
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
`storage-sqlite` DB/sidecar and media-store mode tests, the `marmot-forensics` audit-file tests, and the `marmot-app`
device-id/key-reveal/salt/cache tests. All assert `mode & 0o777` on the real files.

Lock retention has cross-process tests: `fs-private` holds `fcntl` read locks on a database and its sidecars, runs
`ensure_private_db_files`, and has a child process confirm every lock still blocks a writer; `storage-sqlite`
(`reopening_a_live_database_keeps_its_posix_locks`) holds a WAL account connection, opens the same database again,
and has a child process confirm it still cannot take the database exclusively.
