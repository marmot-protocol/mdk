# transport-quic-stream

Raw QUIC transport binding for transient Marmot agent text stream previews.

This crate owns QUIC endpoint setup and reliable stream framing for live preview records. Shared record semantics,
transcript hashing, and protocol constants live in `cgka-traits`; durable MLS start/final payloads and account
orchestration stay in higher layers.

## What this crate does

- Sets up QUIC client/server endpoints with ALPN pinning and shared hardening defaults (connect deadline, frame caps,
  early-data policy) also consumed by `transport-quic-broker`. Direct clients bind the unspecified address of the
  destination family (`0.0.0.0:0` / `[::]:0`) so IPv6 and normally routed off-host destinations are reachable. That
  wildcard source bind is not authorization of the remote address: `SendTextStream` callers must supply an already
  validated and pinned `SocketAddr` plus configuration-derived trust/`server_name`. The API has no resolver or
  dev-flag context and does not infer permission from the destination IP.
- Seals and opens length-delimited preview records with HKDF-derived keys and AAD.
- Sends and receives text-stream preview chunks over ordered QUIC streams.
- Requires encrypted publishers to reserve sequences through an account-device
  durable state boundary before record writes; ambiguous state fails closed.

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
