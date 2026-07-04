# agent-control

Local control-protocol DTOs and newline-delimited JSON framing for Marmot agent integrations.

This crate defines the `marmot.agent-control.v1` request/response/event types and the frame codec used over the
`wn-agent` Unix socket. Hermes and OpenClaw plugins are thin clients of this protocol.

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
