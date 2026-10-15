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

Later steps of mdk#2314 add the file lifecycle (intent-first publish, key-first deletion, the bounded sweep),
`.wire` download partials, handoff leases, free-disk admission and the evictable cache category.

## Using it

The API is synchronous and blocking. Callers run it on a blocking thread pool, never inline on an async task.

```sh
cargo test -p media-store
```

The comparison against today's SQLCipher retained-attachment path is a `storage-sqlite` example:
`just bench-media-store`.
