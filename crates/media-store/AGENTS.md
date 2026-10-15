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
| `src/format.rs` | File format: header, header-salted HKDF payload key, 64 KiB OpenSSL ChaCha20-Poly1305 segments, streaming writer (poisoned after a failure), offset reader. |
| `src/catalog.rs` | `FileId`, `Category`, `FileState`, and the two traits other crates implement: `MediaCatalog` (store-wide rows) and `PublishTarget` (one publication's one-transaction commits). |
| `src/store.rs` | `MediaStore`: intent-first publish, presence-checked reuse, `attach_existing` (reuse before a download), close-checked readers that hold their key, a small idle-limited reader cache for `read_at`, `unlink_released`, the bounded sweep, the close latch and in-flight set. `sync_file` (plain `fsync` on Apple). |
| `src/error.rs` | `MediaError`: fixed, privacy-safe messages. |
| `src/memory.rs`, `src/conformance.rs` | `catalog-conformance` feature: an in-memory catalog and the conformance suite every catalog must pass (crash table, reuse of a lost twin, release, supersession and reset during a write). |
| `src/format_tests.rs`, `src/store_tests.rs`, `testdata/age/` | Vendored C2SP CCTV age payload vectors; format tests; the in-memory conformance run and store tests (modes, close, sweep bounds, corruption). |

## Rules

- Order is the crash-safety guarantee: catalog row before file, one sync before the ready commit, abandon (row, then
  file) on failure, delete the key before the unlink. A file whose row is `pending` is never adopted.
- `PublishTarget` commits are one transaction each in the implementing catalog. Any change to their contract changes
  `conformance.rs` in the same commit, and every catalog (`storage-sqlite`, the in-memory one) must keep passing it.
- One `MediaStore` (and its clones) per account: the in-flight set that protects live publishes from the sweep is
  per instance.
- Nothing runs after close, including abandon cleanup; the next process's sweep reclaims what is left. The runtime
  closes the store through `marmot-app`'s close registry, the same one every other closeable handle uses.
- Inside a catalog transaction the only file I/O is the one `present` check (a single `stat`) for the ready twin.
  It has three outcomes: `Present` (exact expected length), `Absent` (missing or wrong length: mark lost) and an error,
  which must roll back and leave the twin's key untouched. Never turn a failed `stat` into "missing".
- A ready file that fails verification (`Corruption`) is marked lost and its cached reader dropped; `Io` and `Cipher`
  errors leave it ready, since they may be transient.
- Sweep batches charge every directory entry they visit and resume the open shard listing, so a pass lists each entry
  once however the batches split it.
- `read_at` trusts that the caller authorized the read in the catalog's domain; its reader cache only skips the key
  lookup and file open. Evict a cached reader whenever its file is released, lost or unlinked.
- Plaintext handoff leases (mdk#2314 step 4) are refused on Windows, which is not a target platform: `fs-private`
  mode bits are no-ops there, and plaintext must not depend on an inherited ACL.
- Keep sealing byte-identical to the age payload construction: the vectors must keep passing unchanged.
- A writer that hit an error is poisoned; never reseal or rewrite its buffer.
- Create files and directories through `fs-private` (0600/0700 at creation).

## Verification

```sh
cargo test -p media-store
cargo clippy -p media-store --all-targets --all-features -- -D warnings
cargo test -p storage-sqlite --lib media_catalog   # the SQLCipher catalog's conformance run
```
