# Hermes Marmot Plugin

This directory is a Hermes platform plugin for the local `dm-agent` connector.
Hermes runs the agent and tools. `dm-agent` owns the Marmot account, MLS state,
Nostr transport, final encrypted sends, and QUIC live-preview stream records.

For a real Hermes install, install it by copying or symlinking this directory to:

```sh
~/.hermes/plugins/marmot
```

The current Hermes plugin loader expects platform plugins as directories directly
under `~/.hermes/plugins/<name>/` with `plugin.yaml`, `__init__.py`, and
adapter implementation files.

## Repeatable Dev Setup

Use the repo scripts when testing the plugin without touching your normal Hermes
home. By default the root is `${TMPDIR:-/tmp}/hermes-marmot-test`; on macOS,
`$TMPDIR` usually expands to a path under `/var/folders/...`.

```sh
just hermes-dev-setup --print-env
source /tmp/hermes-marmot-test/env.sh
```

The setup script creates these paths under that root:

- `hermes-agent` for the isolated Hermes checkout.
- `hermes-home` for isolated Hermes state.
- `marmot-agent-home` for isolated `dm-agent` state.
- `hermes-home/plugins/marmot` as a symlink back to this plugin directory.
- helper scripts: `smoke-plugin.sh`, `e2e-deterministic.sh`,
  `e2e-connector.sh`, `bootstrap-agent.sh`,
  `run-dm-agent.sh`, `run-hermes-gateway.sh`, `start-dm-agent.sh`,
  `start-hermes-gateway.sh`, and `stop-dev-processes.sh`.

When Hermes is installed, the setup script also runs `hermes plugins enable
marmot` inside the isolated `HERMES_HOME`.

Useful variants:

```sh
# Create only dirs/env/plugin link/helpers; no network clone or Python install.
just hermes-dev-setup --skip-hermes-install --print-env

# Pin Hermes to a branch, tag, or commit.
just hermes-dev-setup --hermes-ref main --print-env

# Include relay and QUIC preview settings for generated helpers.
just hermes-dev-setup \
  --relay wss://relay.eu.whiteniose.chat \
  --relay wss://relay.us.whitenoise.chat \
  --quic-candidate quic://quic-broker.ipf.dev:4450 \
  --print-env

# Use a token-gated local control socket for a group-shared Hermes/dm-agent setup.
openssl rand -hex 32 > /tmp/hermes-marmot-control.token
chmod 0600 /tmp/hermes-marmot-control.token
just hermes-dev-setup --auth-token-file /tmp/hermes-marmot-control.token --socket-dir-mode 0770 --socket-mode 0660 --print-env
```

Smoke-test the plugin import against the isolated Hermes venv:

```sh
just hermes-dev-smoke
```

Run the deterministic adapter E2E:

```sh
just hermes-dev-e2e-deterministic
```

This test uses the real Hermes platform base and the real Marmot plugin, but it
uses a fake `dm-agent` socket and a fixed handler response. It does not need a
Marmot account, a running `dm-agent`, or a model.

Run the deterministic connector E2E:

```sh
just hermes-dev-e2e-connector
```

This test starts a real `dm-agent` process with debug controls enabled, injects
one inbound message through its local control socket, and verifies the fixed
Hermes response is sent back through `dm-agent`.

Run the services in foreground terminals:

```sh
source "${HERMES_MARMOT_DEV_ROOT:-${TMPDIR:-/tmp}/hermes-marmot-test}/env.sh"
"$HERMES_MARMOT_DEV_ROOT/run-dm-agent.sh"
"$HERMES_MARMOT_DEV_ROOT/run-hermes-gateway.sh"
```

Or run them in the background with logs under `/tmp/hermes-marmot-test/logs`:

```sh
source "${HERMES_MARMOT_DEV_ROOT:-${TMPDIR:-/tmp}/hermes-marmot-test}/env.sh"
"$HERMES_MARMOT_DEV_ROOT/start-dm-agent.sh"
"$HERMES_MARMOT_DEV_ROOT/start-hermes-gateway.sh"
"$HERMES_MARMOT_DEV_ROOT/stop-dev-processes.sh"
```

Delete the whole throwaway setup:

```sh
just hermes-dev-teardown --force
```

## Docker Phone Test

The repo has a Compose profile for the dedicated-computer phone test. It builds a container with `dm-agent`, Hermes,
the Marmot plugin, and `qrencode` for terminal QR output. Run these commands on the host from the Dark Matter repo root.
They start or exec into the container for you. The container uses the pilot public relays and broker:

```sh
export OPENAI_API_KEY=...
just hermes-phone-test-up
just hermes-phone-test-bootstrap
```

Use the provider secret and optional `HERMES_MODEL` or `HERMES_PROVIDER` settings that match your Hermes setup. The
Compose service passes through common provider variables when they are set in your shell.

The phone-test container patches `$HERMES_HOME/config.yaml` before starting the gateway. By default it enables Hermes
gateway streaming for the Marmot platform and keeps tool/status chatter out of durable chat history:

```sh
HERMES_MARMOT_STREAMING=1 \
HERMES_MARMOT_STREAMING_TRANSPORT=auto \
HERMES_MARMOT_TOOL_PROGRESS=off \
HERMES_MARMOT_INTERIM_MESSAGES=0 \
HERMES_MARMOT_LONG_RUNNING_NOTIFICATIONS=0 \
HERMES_MARMOT_BUSY_ACK_DETAIL=0 \
just hermes-phone-test-up
```

To compare the final-message-only path, turn streaming off:

```sh
HERMES_MARMOT_STREAMING=0 just hermes-phone-test-up
```

To deliberately test Hermes tool-progress and interim-message behavior in the phone app, opt back in:

```sh
HERMES_MARMOT_TOOL_PROGRESS=all \
HERMES_MARMOT_INTERIM_MESSAGES=1 \
HERMES_MARMOT_LONG_RUNNING_NOTIFICATIONS=1 \
just hermes-phone-test-up
```

The bootstrap command prints the agent account hex, `npub`, `nprofile`, relay hints, QUIC preview candidate, and QR
code. The QR payload is the `nprofile`; QUIC preview candidates are printed for diagnostics and are still announced by
Hermes in the first agent-stream start message. Run logs in another terminal while testing from the phone:

```sh
just hermes-phone-test-logs
```

For this manual test the container starts `dm-agent` with `MARMOT_AGENT_ALLOW_ANY=1`, so the first phone invite can land
without knowing the phone account id ahead of time. Use an explicit allowlist for a real deployment.

In the phone-test container, `MARMOT_PROFILE_NAME_ONBOARDING=1` makes the Marmot Hermes adapter ask on the first
encrypted chat message whether to publish a public Nostr profile name for the agent account. Reply with the name to
publish it as kind-0 metadata, or reply `skip` to leave the agent unnamed. Outside this container path the prompt is
opt-in; set `MARMOT_PROFILE_NAME_ONBOARDING=1` or plugin extra `profile_name_onboarding: true` to enable it.

Stop the container without deleting the agent account:

```sh
just hermes-phone-test-down
```

## Configuration

Start the connector first with the same public Nostr relay set the phone uses:

```sh
cargo run -p agent-connector --bin dm-agent -- \
  --home ~/.marmot-agent \
  --relay wss://relay.eu.whiteniose.chat \
  --relay wss://relay.us.whitenoise.chat
```

Then configure Hermes with environment variables:

```sh
export MARMOT_HOME="$HOME/.marmot-agent"
export MARMOT_ACCOUNT_ID_HEX="<agent-account-pubkey-hex>"
export MARMOT_QUIC_CANDIDATES="quic://quic-broker.ipf.dev:4450"
```

`MARMOT_AGENT_SOCKET` can override the socket path. If it is not set, the plugin
uses `$MARMOT_HOME/dev/dm-agent.sock`. If `MARMOT_ACCOUNT_ID_HEX` is omitted and
`dm-agent` has exactly one local account, the adapter selects it automatically.

The default control socket is same-UID only: parent directory `0700`, socket
`0600`, no TCP listener. If Hermes and `dm-agent` run as different local service
users, use a token file and group-readable socket modes:

```sh
install -d -m 0750 ~/.marmot-agent
openssl rand -hex 32 > ~/.marmot-agent/control.token
chmod 0600 ~/.marmot-agent/control.token

cargo run -p agent-connector --bin dm-agent -- \
  --home ~/.marmot-agent \
  --relay wss://relay.eu.whiteniose.chat \
  --relay wss://relay.us.whitenoise.chat \
  --auth-token-file ~/.marmot-agent/control.token \
  --socket-dir-mode 0770 \
  --socket-mode 0660

export MARMOT_AGENT_AUTH_TOKEN_FILE="$HOME/.marmot-agent/control.token"
```

`MARMOT_AGENT_AUTH_TOKEN` is also supported for launcher-managed secrets. Prefer
`MARMOT_AGENT_AUTH_TOKEN_FILE` for shell and service-manager setups so the token
does not appear in process environments by default.

## Behavior

- Inbound Marmot messages become Hermes `MessageEvent`s with `chat_id` set to
  the Marmot group id and `user_id` set to the sender account id.
- Normal Hermes sends call `send_final` and produce durable Marmot messages.
- Hermes progressive edits are represented as live Marmot preview streams only
  when the text is append-only. Replacement edits cancel the preview and leave
  the durable final send as the fallback.
- Status records are included in the stream transcript hash and chunk count.

Run the shim tests with:

```sh
python3 -m unittest discover -s integrations/hermes/marmot/tests
```
