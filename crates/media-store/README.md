# media-store

The encrypted per-file media store for one Marmot account. Retained attachment bodies (images, voice notes, files)
move out of the account's SQLCipher database into one encrypted file each, under `<account>/media/`
([mdk#2314](https://github.com/marmot-protocol/mdk/issues/2314)).

This crate owns the file side end to end. Each file's random key, state and slot references stay in the account
database, which this crate reaches through a catalog trait implemented by `storage-sqlite`; it never touches SQL.

## What is here

- **The file format** (`format`): a header (`mdkmedia`, version, file id) followed by the age v1 payload. The payload
  key is HKDF-SHA256 of the file's random 32-byte key salted with the header; the plaintext is sealed in 64 KiB
  ChaCha20-Poly1305 segments with counter and final-flag nonces. Segments authenticate independently, so offset reads
  decrypt only what they touch. The vendored [C2SP CCTV](https://github.com/C2SP/CCTV) age payload vectors exercise
  the same sealing code.

- **The store** (`MediaStore`): one file per body under `<account>/media/<shard>/<id>`, named by a random id.
  Publishing commits a `pending` catalog row, writes and syncs the file once, then commits it `ready` in one
  transaction with its reference. Identical content is stored once, but only reused if its file is on disk. Deleting
  the catalog row erases the key; the file is unlinked after. A bounded sweep reclaims anything a crash left behind,
  and marks a ready row whose file vanished as *lost*. Readers check the close latch on every read.
- **Download checkpoints** (`checkpoint_append`, `checkpoint_restore`, `checkpoint_clear`): a resumable download's
  ciphertext goes to an append-only `<shard>/<id>.wire` file. The store owns every step, as it does for publishing:
  the catalog's checkpoint row commits before the file exists and is deleted before the file is, each append is
  synced before the row records it, a refused or failed append is cut off at once, and operations on one checkpoint
  serialize. An append is at most `CHECKPOINT_APPEND_MAX` bytes, so a crash can leave at most that much unrecorded;
  reopening and the sweep cut it off. A finished checkpoint is read in place through `checkpoint_reader`, which keeps
  its file open (the sweep and an unlink leave it alone) until `finish` unlinks a file whose row is gone.
- **Staged publication** (`stage`, `promote`, `release_staged`, `open_staged_reader`): an outgoing body is sealed into
  a store file that stays `staged` under its owner (an outgoing upload) through the upload and across restarts, then
  becomes `ready` and attached when the message is published, reusing an identical ready file if one is on disk. An
  owner that goes away releases its staged file, key first; the sweep releases a staged row no owner holds.
- **Disk admission** (`DiskPolicy`): the caller supplies the reserve from its configuration; the crate only measures
  free space (`free_space`) and compares. `DiskPolicy::download_need` is the one rule for what a download still
  writes: the rest of its wire file and its store file, less what is already checkpointed, never less than the store
  file. `DiskPolicy::send_need` is the rule for a send: its staged file, since the upload streams.
  `DiskPolicy::migration_need` is the rule for moving a legacy database body into the store: its store file.
- **The catalog traits**: `MediaCatalog` (store-wide rows), `PublishTarget` (one publication's commit),
  `CheckpointTarget` (one download checkpoint's row), `StageTarget` (one staged body's owner) and `PromoteTarget` (one
  promotion into a published message's slots), implemented on the account database by `storage-sqlite`. The `catalog-conformance` feature exports the suite every
  implementation must pass, and an in-memory catalog.

Retained attachments use the `Retained` category and are never deleted automatically. Avatars and group images use
the `Cache` category (mdk#2314 step 9): they can always be fetched again, so the account's cache budget evicts them.
The two categories never share a file.

## Using it

The API is synchronous and blocking. Callers run it on a blocking thread pool, never inline on an async task.

```sh
cargo test -p media-store
```

The comparison against today's SQLCipher retained-attachment path is a `storage-sqlite` example:
`just bench-media-store`.
