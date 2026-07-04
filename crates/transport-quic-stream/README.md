# transport-quic-stream

Raw QUIC transport binding for transient Marmot agent text stream previews.

This crate owns QUIC endpoint setup and reliable stream framing for live preview records. Shared record semantics,
transcript hashing, and protocol constants live in `cgka-traits`; durable MLS start/final payloads and account
orchestration stay in higher layers.

## What this crate does

- Sets up QUIC client/server endpoints with ALPN pinning and shared hardening defaults (connect deadline, frame caps,
  early-data policy) also consumed by `transport-quic-broker`.
- Seals and opens length-delimited preview records with HKDF-derived keys and AAD.
- Sends and receives text-stream preview chunks over ordered QUIC streams.

## What it does not do

- No Nostr relay transport, account runtime, or MLS group history.
- No broker pub/sub fan-out (see `transport-quic-broker`).
- No UI or agent control protocol (see `agent-control` / `agent-connector`).

Live preview chunks are provisional; the final MLS app payload remains authoritative.

## Run the tests

```sh
cargo test -p transport-quic-stream
```

See [`AGENTS.md`](AGENTS.md) for the module map and privacy-safe logging rules.
