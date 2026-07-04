# agent-stream-compose

Reusable live-preview stream composition over the QUIC broker publisher.

This crate drives a single agent text-stream preview session: connect to the memory-only broker, publish length-delimited
preview records, and report completion. Record framing and limits come from `cgka-traits`.

## What this crate does

- Exposes `run_stream_compose_session` and the `StreamComposeCommand` / `StreamComposeReport` surface.
- Reuses canonical record tags, plaintext frame caps, and progress/delta semantics from `cgka_traits::agent_text_stream`.
- Keeps transport-aware QUIC + broker wiring in one place for `wn-agent` and tests.

## What it does not do

- No account home, MLS engine, or Nostr adapter orchestration.
- No agent control socket or NDJSON protocol (see `agent-control` / `agent-connector`).
- No broker process itself (see `transport-quic-broker`).

## Run the tests

```sh
cargo test -p agent-stream-compose
```

See [`AGENTS.md`](AGENTS.md) for scope and invariants.
