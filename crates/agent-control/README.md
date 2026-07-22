# agent-control

Local control-protocol DTOs and newline-delimited JSON framing for Marmot agent integrations.

This crate defines the `marmot.agent-control.v2` request/response/event types and the frame codec used over the
`wn-agent` Unix socket. Hermes and OpenClaw plugins are thin clients of this protocol.

Version 2 is intentionally incompatible with version 1. A successful `StreamBegin` returns a random 32-byte
`stream_capability` encoded as 64 lowercase hex characters. Every later append, status, progress, finalize, or cancel
request for that stream must present the capability. Treat it as an in-memory bearer secret: never persist or log it.

The envelope `id` is also the idempotency key for `StreamBegin`. Retrying the same begin request with the same `id`
returns the original stream id, start event, candidates, policy limit, and capability. Reusing that `id` with different
begin inputs is an error, and trying to begin another active stream with an occupied explicit stream id returns
`stream_id_in_use`; neither case replaces the existing session.

## What this crate does

- Owns `AgentControlEnvelope` and the typed control DTOs (bootstrap, send, subscribe, stream compose, allowlists, etc.).
- Provides newline-delimited JSON framing with a 1 MiB per-frame cap.
- Stays dependency-light: `serde` and Tokio IO only.

## What it does not do

- No engine, storage, account, or transport logic.
- No socket daemon or process lifecycle (see `agent-connector`).
- No QUIC preview composition (see `agent-stream-compose`).

## Run the tests

```sh
cargo test -p agent-control
```

See [`AGENTS.md`](AGENTS.md) for scope and invariants.
