# AGENTS.md - agent-control

Local control-protocol DTOs and newline-delimited JSON framing for Marmot agents.

## Scope

- Own the `marmot.agent-control.v1` request/response/event DTOs and the `AgentControlEnvelope` wrapper.
- Own the newline-delimited JSON frame codec (`encode_frame`/`decode_frame`/`read_frame`/`write_frame`) and the
  `MAX_AGENT_CONTROL_FRAME_BYTES` (1 MiB) frame cap.
- Keep this crate dependency-light: serde + tokio IO only, no engine, app, storage, or transport crates.

## Verification

```sh
cargo test -p agent-control
```
