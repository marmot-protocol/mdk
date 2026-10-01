# fs-private

Restrictive-by-construction helpers for local files, directories, advisory lock files, and Unix domain sockets. Use it
from any workspace crate that writes something sensitive to disk.

This crate owns the shared "secure local artifact" creation path: files and directories are created already at their
target owner-only mode, and Unix sockets are bound inside a fresh private staging directory and hard-linked into place.
Callers supply policy (which paths, which modes); this crate supplies the mechanics. The workspace policy that mandates
these helpers is
[`docs/marmot-architecture/overview/local-artifact-safety.md`](../../docs/marmot-architecture/overview/local-artifact-safety.md).

## What this crate does

- Creates files with `O_CREAT` at the target mode (no post-create chmod on reachable paths): `write_private`,
  `create_new_private`, `open_private_append`, `ensure_private_file`, `ensure_private_db_files`.
- Creates directories atomically at mode `0700` (`create_dir_all_private`), and prepares directory paths
  descriptor-relatively without following symlinks (`prepare_directory_path`).
- Acquires nonblocking, kernel-released exclusive leases on private lock files
  (`try_acquire_private_exclusive_file_lease`).
- Binds Unix sockets through a private staging directory and hard-links them into the final path
  (`bind_unix_listener_private`, `bind_unix_listener_private_tracked`, `verify_unix_socket_inode`).
- Publishes a complete staging file without replacing a concurrent publisher's destination, on platforms that forbid
  hard links such as Android (`rename_noreplace_with_lock`).
- Exposes the workspace's single octal permission-mode parser (`parse_octal_mode`).

Mode application is Unix-only; on other platforms the helpers still create the artifacts. The crate holds no
application policy (which artifacts to create, acceptable mode ranges) and depends only on `std` and `libc`.

## Run the tests

```sh
cargo test -p fs-private
```

Agent-facing scope and invariants: [`AGENTS.md`](AGENTS.md).
