# AGENTS.md - crates/media-store

The encrypted per-file media store (mdk#2314). Human overview: [`README.md`](README.md).

## Boundary

- **No SQL.** No `rusqlite`, and no dependency on `storage-sqlite`, `marmot-app`, `cgka-engine` or `cgka-traits`.
  Metadata (keys, states, lengths, digests, references) lives in the account's SQLCipher database behind a catalog
  trait that `storage-sqlite` implements. Dependency direction: `fs-private` -> `media-store` -> `storage-sqlite` ->
  `marmot-app`.
- **Never on async threads.** Every API is synchronous and blocking (file I/O, hashing, AEAD). Callers use the
  blocking pool (`spawn_blocking`), never an account worker or other async task: under UniFFI every runtime task
  shares one `async-compat` thread, so inline media work would stall every account.
- **Media files take no locks.** No `flock`/`fcntl`, and not the lock-based `fs-private` publication used for key
  material. Unique random names and one writer per file make locks unnecessary; writers serialize on the catalog row.
  See `docs/marmot-architecture/overview/local-artifact-safety.md`.
- **Privacy-safe logs only:** explicit `target` and `method` fields, aggregate counts, never ids, paths, digests,
  keys or contents (`docs/marmot-architecture/overview/observability.md`).

## Code map

| Path | Owns |
| --- | --- |
| `src/format.rs` | File format: header, header-salted HKDF payload key, 64 KiB ChaCha20-Poly1305 segments, streaming writer, offset reader. |
| `src/format_tests.rs`, `testdata/age/` | Vendored C2SP CCTV age payload vectors (0BSD/CC0) and boundary, tamper and failure tests. |

## Rules

- Keep sealing byte-identical to the age payload construction: the vectors must keep passing unchanged.
- A writer that hit an error is poisoned; never reseal or rewrite its buffer.
- Create files and directories through `fs-private` (0600/0700 at creation).

## Verification

```sh
cargo test -p media-store
cargo clippy -p media-store --all-targets -- -D warnings
```
