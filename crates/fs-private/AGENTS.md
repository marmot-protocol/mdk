# AGENTS.md - fs-private

Restrictive-by-construction creation of local files, directories, lock files, and Unix sockets. Overview and helper
list: [`README.md`](README.md). Workspace policy: `docs/marmot-architecture/overview/local-artifact-safety.md`.

## Layout

- `src/lib.rs` — file/dir/lease/socket helpers and `parse_octal_mode`.
- `src/publication.rs` (Unix) — `rename_noreplace_with_lock`.
- `tests/publication.rs` — process-spawning publication tests, kept in their own binary so a child cannot inherit
  another unit test's advisory lock before exec.

## Rules

- Create every artifact already at its target owner-only mode (`O_CREAT` + mode, atomic 0700 `DirBuilder`, 0700
  socket staging directory + hard link). Post-create tightening is only belt-and-braces for artifacts that already
  existed.
- Never open a descriptor on an existing SQLite database or sidecar. Closing any descriptor on a file drops every
  POSIX `fcntl` lock the process holds on it, so it silently strips a live connection's locks.
  `ensure_private_db_files` opens only the main file it creates (`O_EXCL`, under its in-process mutex) and tightens
  existing files by path (`lstat` + no-follow `fchmodat`). Its cross-process lock-retention test must keep passing.
  `ensure_private_file` and `tighten_existing_private_file` open the file and are not for databases.
- Nonblocking advisory leases use private, stable lock-file descriptors; never unlink or replace a lock file while
  holders can run.
- Every writer of a `rename_noreplace_with_lock` destination must use that helper; it blocks, so callers run it where
  blocking I/O is allowed.
- `parse_octal_mode` is the workspace's only octal mode parser. No call site re-derives leading-zero stripping or radix
  handling; acceptable-mode policy stays with callers.
- Keep dependencies to `std` + `libc` so lightweight crates (e.g. `marmot-forensics`) can depend on this crate. Mode
  application is `#[cfg(unix)]`; helpers still create artifacts elsewhere.
- Keep policy out: this crate knows how to create artifacts privately, not which artifacts an application needs or
  what modes a feature should accept.

## Verification

```sh
cargo test -p fs-private
```
