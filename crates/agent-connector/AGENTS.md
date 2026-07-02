# AGENTS.md - agent-connector

Local Marmot agent connector daemon; ships the `dm-agent` binary.

## Scope

- Own `serve_socket`/`AgentConnector` and the `dm-agent` Unix-socket daemon that bridges the `agent-control` protocol
  and `agent-stream-compose` previews to `MarmotApp`/`MarmotAppRuntime`.
- Own `dm-agent bootstrap`, which creates or reuses a local agent account through the running control socket and prints
  phone invite details (`npub`, `nprofile`, optional terminal QR).
- Own connector socket binding and permission hardening (`bind_connector_socket`, `default_socket_path`).
- Keep agent-facing wire types in `agent-control` and stream composition in `agent-stream-compose`; this crate is the
  process glue, not the protocol or composition owner.

## Key files

The `AgentConnector` inherent impl is split across thematic sibling modules (Rust allows one inherent impl to span
several files in the same crate); methods shared across those files are `pub(crate)`.

- `src/lib.rs` — `serve_socket`, `AgentConnectorConfig`, the `AgentConnector` struct, and its core lifecycle `impl`
  (`open`, `serve_once`, `start`, agent-account readiness, `configured_relay_endpoints`). Crate-internal constants live
  here as `pub(crate)`.
- `src/connection.rs` — `AgentConnector::handle_connection`, peer authorization, the `error_response` projection, and
  the `AgentControlRequest` → handler dispatch.
- `src/account.rs` — account list/create, profile publishing, `local_account_for_account_id`, and welcomer-allowlist
  list/add/remove handlers.
- `src/messaging.rs` — final-message sends, agent activity/operation/group-system event handlers, and debug send
  recording/inject helpers.
- `src/stream.rs` — QUIC text-stream preview session lifecycle (begin/append/status/progress/finalize/cancel) and the
  idle-session sweeper.
- `src/inbound.rs` — `SubscribeInbound` drain loop and storage-backed `replay_missed_inbound` recovery after broadcast
  lag.
- `src/invite_policy.rs` — background reconciliation of pending group invites against the welcomer allowlist
  (worker spawn, reconcile, candidate enumeration, apply).
- `src/error.rs` — `ConnectorError` and its `code`/`client_message`/`privacy_safe_code` projections.
- `src/socket.rs` — socket path/bind/hardening (`default_socket_path`, `bind_connector_socket*`, stale-socket recovery).
- `src/allowlist.rs` — `AllowlistStore`/`AllowlistRecord` per-account welcomer allowlist persistence.
- `src/stream_session.rs` — `StreamSessionStore`/`ActiveStreamSession`, the persisted
  `SendIdempotencyStore` (`$MARMOT_HOME/dev/send-idempotency.json`, 1024-entry FIFO,
  versioned SHA-256 request fingerprints, crash-safe atomic writes), and the
  `DebugFinalSendStore` recorder.
- `src/media_temp.rs` — TTL sweep of decrypted inbound media temp dirs under
  `$TMPDIR/marmot-media/`.
- `src/quic.rs` — QUIC broker candidate parsing, address resolution, and trust selection.
- `src/event_projection.rs` — runtime/debug event → control event projection, the `DeliveredInboundCursor`, and the
  `InboundCatchUpDriver`.
- `src/validation.rs` — control-plane/profile/hex validation helpers and the invite-policy retry-state holders.
- `src/bootstrap.rs` — `dm-agent bootstrap` flow.
- `src/bin/dm-agent.rs` — the `dm-agent` binary entrypoint and clap CLI surface (`ServeArgs`, the `bootstrap`
  subcommand and `BootstrapArgs`, octal socket-mode parsing, and terminal-QR rendering).
- `src/tests.rs` — white-box test suite exercising the above `pub(crate)` internals.

## Verification

Before pushing connector changes, run the repo-wide pre-push gate plus this crate's tests:

```sh
just fast-ci
cargo test -p agent-connector
```

GitHub CI runs the full `just ci` workspace suite.
