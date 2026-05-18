# AGENTS.md - transport-quic-stream

Raw QUIC transport binding for transient Marmot agent text stream previews.

## Scope

- Own the QUIC endpoint setup and reliable stream framing for agent text stream preview records.
- Keep shared record semantics in `cgka-traits`; do not fork protocol constants or transcript hashing here.
- Keep durable group history, MLS start/final payload handling, account orchestration, Nostr relay transport, and UI
  presentation out of this crate.
- Treat live chunks as provisional preview data. The final MLS app payload remains authoritative.
- Keep diagnostics privacy-safe: no account ids, group ids, message ids, relay URLs, pubkeys, plaintext, ciphertext, or
  key material in tracing/logging.

## Verification

```sh
cargo test -p transport-quic-stream
```
