# fs-private

Restrictive-by-construction helpers for local files, directories, and Unix domain sockets.

This crate owns the shared "secure local artifact" creation path: files and directories are created already at their
target owner-only mode, and Unix sockets are bound inside a fresh private staging directory and hard-linked into place.
Callers supply policy (which paths, which modes); this crate supplies the mechanics.

## What this crate does

- Creates files with `O_CREAT` at the target mode (no post-create chmod on reachable paths).
- Creates directories atomically at mode `0700` via `DirBuilder`.
- Binds Unix sockets through a private staging directory and hard-links them into the final path.
- Exposes the workspace's single octal permission-mode parser (`parse_octal_mode`).

## What it does not do

- No application policy (which artifacts to create, acceptable mode ranges).
- No dependencies beyond the Rust standard library.

See [`docs/marmot-architecture/overview/local-artifact-safety.md`](../../docs/marmot-architecture/overview/local-artifact-safety.md)
for the workspace policy that mandates these helpers.

## Run the tests

```sh
cargo test -p fs-private
```

See [`AGENTS.md`](AGENTS.md) for scope and invariants.
