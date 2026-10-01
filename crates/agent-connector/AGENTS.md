# AGENTS.md - agent-connector

Local Marmot agent connector daemon; ships the `wn-agent` binary. Operator-facing usage, invite policy, media roots,
and control-plane security model: [`README.md`](README.md).

## Scope

- Own `serve_socket`/`AgentConnector` and the `wn-agent` Unix-socket daemon that bridges the `agent-control` protocol
  and `agent-stream-compose` previews to `MarmotApp`/`MarmotAppRuntime`.
- Own `wn-agent bootstrap`, which creates or reuses a local agent account through the running control socket and prints
  phone invite details (`npub`, `nprofile`, optional terminal QR).
- Own connector socket binding and permission hardening (`bind_connector_socket`, `default_socket_path`).
- Keep agent-facing wire types in `agent-control` and stream composition in `agent-stream-compose`; this crate is the
  process glue, not the protocol or composition owner.
- Publisher routing and TLS trust use `marmot-app` host-safety validation.
  `allow_insecure_local_broker` remains an explicit dev-only opt-in.

## Invariants

- The control plane is local-only: Unix socket, no TCP listener, restrictive default modes (`0700` dir, `0600`
  socket), same effective UID unless a bearer token is configured; reject world-readable/writable socket modes. The
  token is all-or-nothing full control; do not add implied scopes without designing them.
- `stream_capability` values are bearer secrets: compare without data-dependent early exit; never log or persist them.
- Logging stays privacy-safe: no account ids, group ids, message ids, relay URLs, pubkeys, payloads, ciphertext,
  plaintext, or key material. Use explicit `target`/`method` tracing fields.
- Every invite policy fails closed without an authenticated welcomer. `--dev-allow-any-invites` requires
  `--debug-controls`.
- Outbound media reads stay confined beneath `--media-allowed-root` directory handles (no symlink following); no roots
  means media sends are disabled.
- Do not put release install commands or release URLs in `README.md`; they live in `integrations/README.md` and
  `release.md`. `README.md` is scanned by `just agent-install-docs-gate` (no `wn-agent-latest` URLs, no stale
  versioned installer URLs).
- When adding or changing a `wn-agent` flag or env var (`src/bin/wn-agent.rs`, `src/bootstrap.rs`), update the README
  "Run locally" section.

## Key files

The `AgentConnector` inherent impl is split across thematic sibling modules (Rust allows one inherent impl to span
several files in the same crate); methods shared across those files are `pub(crate)`.

- `src/lib.rs` — `serve_socket`, `AgentConnectorConfig`, the `AgentConnector` struct, and its core lifecycle `impl`
  (`open`, `serve_once`, `start`, agent-account readiness, `configured_relay_endpoints`). Crate-internal constants live
  here as `pub(crate)`.
- `src/connection.rs` — `AgentConnector::handle_connection`, peer authorization, the `error_response` projection, and
  the `AgentControlRequest` → handler dispatch.
- `src/account.rs` — account list/create, group creation, profile publishing, `local_account_for_account_id`, and welcomer-allowlist
  list/add/remove handlers.
- `src/messaging.rs` — final-message sends, agent activity/operation/group-system event handlers, and debug send
  recording/inject helpers.
- `src/stream.rs` — QUIC text-stream preview session lifecycle (begin/append/status/progress/finalize/cancel) and the
  idle-session sweeper.
- `src/inbound.rs` — `SubscribeInbound` drain loop and storage-backed `replay_missed_inbound` recovery after broadcast
  lag.
- `src/invite_policy.rs` — background reconciliation of pending group invites against the welcomer allowlist
  (worker spawn, reconcile, candidate enumeration, apply). Event- and retry-driven: `GroupJoined` events apply
  immediately, per-candidate retries wake on their own backoff, and full enumeration is an adaptive safety net
  (base `INVITE_POLICY_RECONCILE_INTERVAL`, doubling to `INVITE_POLICY_RECONCILE_MAX_INTERVAL` while passes find
  nothing) over the targeted `MarmotApp::pending_group_invites` read — never a full `app.groups()` projection
  load (mdk#1380). Enumeration failures back off on a separate failure floor so a failing store cannot spin the
  worker even with a matured retry pending.
- `src/reconcile_telemetry.rs` — privacy-safe aggregate counters for the background reconciliation loops
  (`ReconcileTelemetry` on the connector: passes, outcomes, accounts/candidate rows considered) plus the
  `ReconcileSource` label used on per-pass tracing events (mdk#1380). Current catch-up/replay state is
  exposed through `diagnostic_replay()`.
- `src/diagnostics.rs` — identifier-free `diagnostic_status` handler (account selection, KeyPackage
  aggregates, relay/replay/home observations) using no-start runtime reads.
- `src/error.rs` — `ConnectorError` and its `code`/`client_message`/`retryable`/`privacy_safe_code` projections.
- `src/socket.rs` — socket path/bind/hardening (`default_socket_path`, `bind_connector_socket*`, stale-socket recovery).
- `src/allowlist.rs` — `AllowlistStore`/`AllowlistRecord` per-account invite-policy and welcomer-allowlist persistence.
- `src/stream_session.rs` — `StreamSessionStore`/`ActiveStreamSession`, the shared runtime publisher handles, and persisted
  `SendIdempotencyStore` (`$MARMOT_HOME/dev/send-idempotency.json`, 1024-entry FIFO,
  versioned SHA-256 request fingerprints, `stream_finalize_v2:` / `stream_finish_v1:` keys for durable finalized sends,
  crash-safe atomic writes, plus bounded same-key/same-fingerprint in-flight gates whose followers
  reuse a leader's successful result or receive `send_in_progress` when the gate wait expires), and
  the `DebugFinalSendStore` recorder.
- `src/media_temp.rs` — TTL sweep of decrypted inbound media temp dirs under
  `$TMPDIR/marmot-media/`.
- `src/event_projection.rs` — runtime/debug event → control event projection, the `DeliveredInboundCursor`, and the
  `InboundCatchUpDriver`. The driver's scheduled passes are an adaptive safety net (base
  `INBOUND_CATCH_UP_BASE_INTERVAL`, doubling to `INBOUND_CATCH_UP_MAX_INTERVAL` while the runtime is quiet):
  steady-state delivery is push-driven by each account worker, so qualifying runtime activity (anything but
  `AccountError`, which a failing pass could self-emit) resets the net and wakes a backed-off pass, never faster
  than the base cadence (mdk#1380). Subscription initial catch-ups stay prompt out-of-band requests.
- `src/validation.rs` — control-plane/profile/hex validation helpers and the invite-policy retry-state holders.
- `src/bootstrap.rs` — `wn-agent bootstrap` flow, default relays/QUIC candidate, and `MARMOT_*` env resolution.
- `src/identity.rs` — `wn-agent import-identity`: owner-only, single-link, size-bounded existing Nostr identity import.
- `src/usage_diagnostics.rs` — `wn-agent usage-diagnostics` consent controls on a separate owner-only local socket,
  deliberately outside the agent-control protocol.
- `src/timeline.rs` — read-only materialized-timeline projection (`timeline_message_get`/`timeline_list`).
- `src/maintenance.rs` — agent-control maintenance status and policy handlers.
- `src/media_roots.rs` — `MediaAllowedRoots`, connector-enforced confinement for outbound plaintext media paths.
- `src/agent_created_groups.rs` — per-account activation provenance store, independent of sender authorization.
- `src/bin/wn-agent.rs` — the `wn-agent` binary entrypoint and clap CLI surface (`ServeArgs`, the `bootstrap`
  subcommand and `BootstrapArgs`, octal socket-mode parsing, and terminal-QR rendering).
- `src/tests.rs` — white-box test suite exercising the above `pub(crate)` internals.
- `src/test_support.rs` — test-only hooks and benchmark output (the file name is load-bearing for the workspace
  direct-output audit in `crates/cgka-conformance-simulator/tests/tracing_audit.rs`).
- `tests/identity_security.rs` — black-box `import-identity` prompt/file security tests (Unix only).

## Verification

Before pushing connector changes, run the repo-wide pre-push gate plus this crate's tests:

```sh
just fast-ci
cargo test -p agent-connector
cargo check -p agent-connector --bin wn-agent
```

When touching bootstrap, install, or harness-facing behavior, also run the installer dry runs and tests:

```sh
bash scripts/install-hermes-marmot.sh --dry-run
sender_hex="$(awk 'BEGIN { for (i = 0; i < 32; i++) printf "11" }')"
bash scripts/install-codex-marmot.sh --dry-run --yes --allow-welcomer "$sender_hex" --codex-bin /bin/echo
bash scripts/install-opencode-marmot.sh --dry-run --yes --allow-welcomer "$sender_hex" --opencode-bin /bin/echo
bash scripts/install-pi-marmot.sh --dry-run --yes --allow-welcomer "$sender_hex" --pi-bin /bin/echo
integrations/hermes/tests/marmot/test_dev_scripts.sh
just claude-installer-test
just codex-installer-test
just opencode-installer-test
just pi-installer-test
```

When editing `README.md`, run `just agent-install-docs-gate`. GitHub CI runs the full `just ci` workspace suite.
