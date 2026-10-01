# AGENTS.md - agent-control

Local control-protocol DTOs and newline-delimited JSON framing for Marmot agents. Protocol semantics (stream
capabilities, finalization codes, reactions, timeline reads): [`README.md`](README.md).

## Scope

- Own the `marmot.agent-control.v2` request/response/event DTOs and the `AgentControlEnvelope` wrapper.
- Own the newline-delimited JSON frame codec (`encode_frame`/`decode_frame`/`read_frame`/`write_frame`) and the
  `MAX_AGENT_CONTROL_FRAME_BYTES` (1 MiB) frame cap.
- Keep this crate dependency-light: serde + tokio IO only, no engine, app, storage, or transport crates.

## Key files

| Path | Owns |
| --- | --- |
| `src/lib.rs` | Protocol label, limits, envelope, request/response/event DTOs, frame codec, and unit tests. |
| `src/diagnostics.rs` | Identifier-free `diagnostic_status` DTOs, re-exported from `lib.rs`. |
| `../../fixtures/agent-control-v2-rich-context.json` | Shared rich-context golden, also read by the Hermes, OpenClaw, and terminal-harness tests. |

Server-side handling and wire error codes (`stream_id_in_use`, `stream_finalize_mismatch`, `stream_send_failed`) live
in `crates/agent-connector`.

## Invariants

- `v2` is stable. Do not make breaking wire changes under `v2`; add fields additively (optional, defaulted) or
  introduce a new protocol label or explicit negotiation.
- `stream_capability` is a bearer secret: never persist or log it.
- Keep additive operations (for example `stream_finish`) alongside the older ones they extend (`stream_finalize`);
  plugin clients are cohort-locked to the `wn-agent` release they ship with.
- A protocol change usually touches the connector and the plugin clients in `integrations/` too; keep them in step.

## Verification

```sh
cargo test -p agent-control
```
