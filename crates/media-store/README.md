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
- **The catalog traits**: `MediaCatalog` (store-wide rows) and `PublishTarget` (one publication's commit), implemented
  on the account database by `storage-sqlite`. The `catalog-conformance` feature exports the suite every
  implementation must pass, and an in-memory catalog.

Later steps of mdk#2314 add `.wire` download partials, handoff leases, free-disk admission and the evictable cache
category, and move attachments onto the store.

## Using it

The API is synchronous and blocking. Callers run it on a blocking thread pool, never inline on an async task.

```sh
cargo test -p media-store
```

The comparison against today's SQLCipher retained-attachment path is a `storage-sqlite` example:
`just bench-media-store`.
