# AGENTS.md - agent-connector

Local Marmot agent connector daemon; ships the `dm-agent` binary.

## Scope

- Own `serve_socket`/`AgentConnector` and the `dm-agent` Unix-socket daemon that bridges the `agent-control` protocol
  and `agent-stream-compose` previews to `MarmotApp`/`MarmotAppRuntime`.
- Own connector socket binding and permission hardening (`bind_connector_socket`, `default_socket_path`).
- Keep agent-facing wire types in `agent-control` and stream composition in `agent-stream-compose`; this crate is the
  process glue, not the protocol or composition owner.

## Verification

```sh
cargo test -p agent-connector
```
