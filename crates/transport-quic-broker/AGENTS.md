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

## Layout

`src/lib.rs` is a thin facade: crate docs, `mod` declarations, and the `pub use` re-exports that keep every public item
at its `transport_quic_broker::` path. The implementation is split by concern:

| File | Owns |
| --- | --- |
| `src/protocol.rs` | public ALPN/control/limit consts plus private frame, room-TTL, and timeout tunables |
| `src/config.rs` | `QuicBrokerConfig`, `QuicBrokerTlsConfig`, and the config `Default` |
| `src/error.rs` | `QuicBrokerError` |
| `src/control.rs` | `BrokerStreamKey`, control type/envelope, and envelope encode/decode |
| `src/frame.rs` | length-prefixed control/record/byte framing, read-deadline, frame-length guard |
| `src/tls.rs` | QUIC transport/server config, PEM loaders, ALPN-pinned client endpoint, insecure verifier |
| `src/state.rs` | `BrokerState` room/backlog engine (private; rooms, queues, retention, cleanup) |
| `src/handlers.rs` | per-connection publish/subscribe stream handlers |
| `src/server.rs` | `QuicBrokerServer` bind/accept loop and cert-fingerprint helper |
| `src/client.rs` | publisher/subscriber request types, `BrokerTextPublisher`, publish/subscribe helpers |
| `src/tests.rs` | white-box unit tests reaching `pub(crate)` internals |
| `tests/control_envelope.rs` | black-box envelope/trust tests over the public API |
| `tests/broker_binary.rs` | `marmot-quic-broker` binary startup-log assertions |
| `tests/public_endpoint.rs` | `#[ignore]` live public-broker round trip |
| `src/bin/marmot-quic-broker.rs` | the broker daemon binary |

Cross-module internals are `pub(crate)`; only the items re-exported from `src/lib.rs` are `pub`.

## Verification

```sh
cargo test -p transport-quic-broker
```
