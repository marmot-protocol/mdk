# agent-stream-compose

Reusable live-preview stream composition over the QUIC broker publisher, shared by `wn-agent` (`agent-connector`),
the `wn` CLI, and `marmot-app`.

This crate drives a single agent text-stream preview session: connect to the memory-only broker, publish
length-delimited preview records, track the authoritative transcript, and report completion. Record framing and limits
come from `cgka-traits`.

## What this crate does

- Exposes the session entry points and their `StreamComposeCommand` / `StreamComposeReport` surface:
  - `run_stream_compose_session` drives one broker connection.
  - `run_stream_compose_session_candidates` tries resolved broker candidates in advertised order before disabling the
    provisional transport; failover continues one sequence space.
  - `run_stream_compose_session_without_live` runs the compose/transcript lifecycle with live QUIC disabled (valid
    zero-candidate starts and unusable live routes); only provisional writes fail closed.
- Validates an optional `StreamFinishExpectation` inside the session before teardown. A mismatch returns an error and
  leaves the session running, so finish is retryable.
- On cancel, publishes a live `Abort` record when a live publisher is available (a pending broker connection gets a
  short grace period to land) so online subscribers observe the terminal cancellation. If that connection fails or
  times out, cancellation completes without a live `Abort`.
- Reuses canonical record tags, plaintext frame caps, and progress/delta semantics from
  `cgka_traits::agent_text_stream`.

## What it does not do

- No account home, MLS engine, or Nostr adapter orchestration.
- No agent control socket or NDJSON protocol (see `agent-control` / `agent-connector`).
- No broker process itself (see `transport-quic-broker`).

Live preview records are provisional; the final MLS app payload remains authoritative.

## Run the tests

```sh
cargo test -p agent-stream-compose
```

See [`AGENTS.md`](AGENTS.md) for scope and invariants.
