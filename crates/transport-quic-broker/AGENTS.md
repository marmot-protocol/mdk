# AGENTS.md - transport-quic-broker

Ephemeral QUIC broker for Marmot agent text stream previews.

## Scope

- Own the dumb pub/sub broker shape for live QUIC stream forwarding.
- Keep the broker memory-only: no persistence, no account database, no relay integration, and no payload logs.
- Route live records by `stream_id` plus `start_event_id`; keep shared record semantics and transcript hashing in
  `cgka-traits`.
- Keep durable group history and MLS start/final payload handling outside this crate. The broker only forwards
  provisional preview records.
- Use bounded live queues only. If a subscriber lags, dropping the subscriber is preferable to storing payloads.
- Keep diagnostics privacy-safe: no account ids, group ids, message ids, relay URLs, pubkeys, payloads, ciphertext,
  plaintext, or key material in tracing/logging.

## Verification

```sh
cargo test -p transport-quic-broker
```
