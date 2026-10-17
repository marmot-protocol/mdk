# AGENTS.md - crates/media-store

The encrypted per-file media store (mdk#2314). Human overview: [`README.md`](README.md).

## Boundary

- **No SQL.** No `rusqlite`, and no dependency on `storage-sqlite`, `marmot-app`, `cgka-engine` or `cgka-traits`.
  Metadata (keys, states, lengths, digests, references) lives in the account's SQLCipher database behind a catalog
  trait that `storage-sqlite` implements. Dependency direction: `fs-private` -> `media-store` -> `storage-sqlite` ->
  `marmot-app`.
- **Never on async threads.** Every API is synchronous and blocking (file I/O, hashing, AEAD). Callers use the
  blocking pool (`spawn_blocking`), never an account worker or other async task: account workers, the relay plane and
  host calls share a few async worker threads (two to four in MarmotKit), so inline media work would stall them all.
  See the [threading model](../../docs/marmot-architecture/overview/marmot-app-runtime.md#threading-model).
- **Media files take no locks.** No `flock`/`fcntl`, and not the lock-based `fs-private` publication used for key
  material. Unique random names and one writer per file make locks unnecessary; writers serialize on the catalog row.
  See `docs/marmot-architecture/overview/local-artifact-safety.md`.
- **Privacy-safe logs only:** explicit `target` and `method` fields, aggregate counts, never ids, paths, digests,
  keys or contents (`docs/marmot-architecture/overview/observability.md`).

## Code map

| Path | Owns |
| --- | --- |
| `src/format.rs` | File format: header, header-salted HKDF payload key, 64 KiB OpenSSL ChaCha20-Poly1305 segments, streaming writer (poisoned after a failure), offset reader. |
| `src/catalog.rs` | `FileId`, `Category`, `FileState`, and the traits other crates implement: `MediaCatalog` (store-wide rows), `PublishTarget` (one publication's one-transaction commits), `CheckpointTarget` (one download checkpoint's row: current, begin, record, clear), `StageTarget` (one staged body's owner: commit, release) and `PromoteTarget` (one promotion into a message's slots). `FileState::Staged` is a complete body an owner holds before any slot references it. |
| `src/store.rs` | `MediaStore`: intent-first publish, presence-checked reuse, `attach_existing` (reuse before a download), close-checked readers that hold their key, a small idle-limited reader cache for `read_at`, `unlink_released`, staged publication (`stage`/`promote`/`release_staged`/`open_staged_reader` over a `StageTarget` and a `PromoteTarget`), `.wire` download checkpoints (`checkpoint_append`/`restore`/`clear`/`reader` over a `CheckpointTarget`, with a per-checkpoint lock; `CheckpointReader` reads a finished checkpoint in place and `finish` unlinks it once its row is gone; the private `WireFile` handle), the bounded sweep, the close latch and in-flight set. `sync_file` (plain `fsync` on Apple). |
| `src/disk.rs` | `DiskPolicy` admission (reserve plus the bytes a write needs), `DiskPolicy::download_need` (the one rule for what a download still writes; `checkpoint_needed` inverts it), `DiskPolicy::send_need` (what a send writes locally) and `free_space`. The reserve comes from the caller's config; the crate never chooses one. |
| `src/error.rs` | `MediaError`: fixed, privacy-safe messages. |
| `src/memory.rs`, `src/conformance.rs` | `catalog-conformance` feature: an in-memory catalog and the conformance suite every catalog must pass (publish crash table, reuse of a lost twin, release, supersession and reset during a write; checkpoint append/restore/clear, replacement, attempt fencing, crash tails and missing files; staged files across restarts, a crash before the staged commit, a refused commit, an ended owner, release, and promotion with a present or missing twin). |
| `src/format_tests.rs`, `src/store_tests.rs`, `testdata/age/` | Vendored C2SP CCTV age payload vectors; format tests; the in-memory conformance run and store tests (modes, close, sweep bounds, corruption). |

## Rules

- Order is the crash-safety guarantee: catalog row before file, one sync before the ready commit, abandon (row, then
  file) on failure, delete the key before the unlink. A file whose row is `pending` is never adopted.
- The store owns the checkpoint protocol; callers never touch a wire file. A `.wire` checkpoint lives exactly as long
  as its catalog row: the row commits before the file is created and is deleted before the file is unlinked. Bytes
  are appended and synced before the row records them; an append that fails, or whose record fails or is refused,
  is cut back to the recorded length before the call returns. Opening a wire file truncates it to the recorded
  length (a shorter file discards the checkpoint). Every checkpoint operation holds that checkpoint's lock (keyed by
  `CheckpointTarget::key`) from the row lookup through the file change and the record. An append is at most
  `CHECKPOINT_APPEND_MAX` bytes: that bound is the unrecorded slack callers allow when they measure free space.
- `checkpoint_reader` is the only way to read a checkpoint outside a restore. It holds the checkpoint lock only while
  it resolves the row and opens the file, never while the caller reads, so it cannot deadlock a later checkpoint
  operation on the same job. The reader's open `WireFile` keeps the file in flight; `finish` unlinks it only once its
  row is gone, deciding under the in-flight lock as the sweep does.
- The sweep unlinks any wire file `wire_partial_received` does not claim and trims an unrecorded tail back to the
  recorded length. A `WireFile` is in the in-flight set from before its first append until it drops; the sweep skips
  in-flight wire files and holds the in-flight lock from that check through any trim.
- A staged row survives restarts only while its owner holds it: `Pending` keeps meaning a write in progress, and the
  sweep reclaims any pending row no live process owns. Promotion moves `staged` to `ready` and attaches slots in one
  transaction, checking at most one ready twin; a release or an ended owner deletes the row (key) before the file.
- Every download disk check goes through `DiskPolicy::download_need`. Do not add another formula for what a download
  still writes.
- `PublishTarget`, `CheckpointTarget`, `StageTarget` and `PromoteTarget` calls are one transaction each in the implementing catalog. Any change to their contract changes
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
