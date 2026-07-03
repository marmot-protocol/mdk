---
title: "Local Artifact Safety"
created: 2026-07-02
updated: 2026-07-02
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
`parse_octal_mode`, and `bind_unix_listener_private`.

**Coverage rule:** new code that creates a local file, socket, or database calls these helpers (or proves equivalent
restrictive-by-construction posture with an on-disk mode test) instead of re-deriving umask/chmod/PRAGMA ordering.
`crates/marmot-account/src/io.rs` (`write_file_atomically` with `FileMode::Private`) is a compliant-equivalent
implementation that predates the shared crate.

## Deliberate exception

The application root directory's mode is left as-is when it already exists: retroactively chmod-ing the root of
existing installs is a behavior change outside this policy's scope. File-level 0600 inside it is the guarantee.

## Scope

This policy covers *creation-time* posture (permissions, creation ordering, mode parsing, PRAGMA-at-open). Handling
of secret contents in memory, logs, and FFI is tracked separately under the sensitive-material discipline; tracing
rules live in [`observability.md`](./observability.md).

## Current enforcement

On-disk mode tests accompany each artifact path: `fs-private` unit tests, the daemon/connector socket tests, the
`storage-sqlite` DB/sidecar mode tests, the `marmot-forensics` audit-file tests, and the `marmot-app`
device-id/key-reveal/salt/cache tests. All assert `mode & 0o777` on the real files.
