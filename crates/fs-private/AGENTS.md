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
