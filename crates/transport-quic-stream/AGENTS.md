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

## Key files

- `src/lib.rs` — crate docs, module wiring, and the public re-export facade.
- `src/protocol.rs` — ALPN/protocol identifiers, frame-size constants, and the plaintext/frame-length cap helpers.
- `src/crypto.rs` — `AgentTextStreamCrypto`, record seal/open, and the HKDF key/nonce and AAD derivations.
- `src/frame.rs` — length-prefixed wire framing: write/read a record and `frame_len` validation.
- `src/tls.rs` — server/client TLS config, ALPN pinning, and the loopback-only insecure verifier.
- `src/receive.rs` — `QuicTextStreamReceiver`, the receive loop, and received-stream DTOs (`ServerTrust` lives here).
- `src/send.rs` — `send_text_stream`, the sender DTOs, and the stream-id / UTF-8 chunk-splitting helpers.
- `src/limits.rs` — receive-side record/byte limits, the enforcing accumulator, and the limit error.
- `src/error.rs` — the crate's single `QuicTextStreamError`.
- `src/tests.rs` — cross-cutting unit and end-to-end tests.

## Verification

```sh
cargo test -p transport-quic-stream
```
