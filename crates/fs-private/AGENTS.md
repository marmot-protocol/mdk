# AGENTS.md - fs-private

Restrictive-by-construction creation of local files, directories, and Unix sockets.

## Scope

- Own the shared "secure local artifact" helpers: files and directories are created already at their target
  owner-only mode (`O_CREAT` + mode, atomic 0700 `DirBuilder`), never chmod-ed after they are reachable; Unix
  sockets are bound inside a fresh 0700 staging directory and hard-linked into place at their final mode.
- Own the workspace's one octal permission-mode parser (`parse_octal_mode`). No call site re-derives leading-zero
  stripping or radix handling; policy on which parsed modes are acceptable stays with callers.
- Stay std-only with zero dependencies so lightweight crates (e.g. `marmot-forensics`) can depend on this crate
  without weight concerns. Mode application is `#[cfg(unix)]`; helpers still create artifacts on other platforms.
- Keep policy out: this crate knows how to create artifacts privately, not which artifacts an application needs or
  what modes a feature should accept. See `docs/marmot-architecture/overview/local-artifact-safety.md` for the
  workspace policy that mandates these helpers.

## Verification

```sh
cargo test -p fs-private
```
