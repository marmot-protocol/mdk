# WN Agent Connector

This crate ships the `wn-agent` binary: the local White Noise agent connector.

`wn-agent` is the headless Marmot process that lets an agent runtime appear as a normal Marmot member. It owns the
Marmot account home, MLS state, Nostr relay IO, invite allowlists, durable encrypted sends, and live QUIC preview
composition. Agent runtimes such as Hermes and OpenClaw stay thin: they run models and tools, then talk to
`wn-agent` through the local agent-control socket.

Hermes is the first supported adapter. OpenClaw is the second: a TypeScript channel plugin at
[`integrations/openclaw/marmot`](../../integrations/openclaw/marmot) that speaks the same agent-control protocol to this
connector. `wn-opencode` is a pure Rust harness at
[`integrations/opencode/marmot`](../../integrations/opencode/marmot) for routing allowed Marmot messages to
OpenCode.

## Names

- `agent-connector` is the Rust crate.
- `wn-agent` is the installed binary.
- "WN Agent" is the release track used for binary and adapter-install releases.

The WN Agent release tag has its own prefix, for example `wn-agent-v0.9.0`, but the numeric version is the root
workspace version from `Cargo.toml`. That keeps the agent binary, agent-control protocol, app runtime, and generated
bindings in one compatibility cohort while still letting us publish only the WN Agent artifacts when that is all that
changed.

See the root [`release.md`](../../release.md) for the full versioning and release policy.

## What This Crate Owns

This crate is process glue. It owns:

- `AgentConnector` and `serve_socket`;
- the `wn-agent` Unix-socket daemon;
- `wn-agent bootstrap`;
- local socket binding, peer checks, file modes, and optional bearer-token auth;
- allowlist-backed welcome confirmation for local agent accounts;
- final Marmot sends and QUIC live-preview composition through the app runtime.

This crate does not own the stable control DTOs or stream composition rules. Keep agent-facing wire types in
[`agent-control`](../agent-control) and stream composition behavior in [`agent-stream-compose`](../agent-stream-compose).

## Run Locally

Start the connector with the same public relay set the phone app uses:

```sh
install -d -m 0700 ~/.marmot-agent/dev/outbound-media
cargo run -p agent-connector --bin wn-agent -- \
  --home ~/.marmot-agent \
  --media-allowed-root ~/.marmot-agent/dev/outbound-media \
  --relay wss://relay.eu.whitenoise.chat \
  --relay wss://relay.us.whitenoise.chat
```

By default the control socket is:

```text
~/.marmot-agent/dev/wn-agent.sock
```

In another terminal, create or reuse the local agent account and print the phone invite details:

```sh
cargo run -p agent-connector --bin wn-agent -- bootstrap \
  --home ~/.marmot-agent \
  --qr
```

`bootstrap` prints the agent account id, `npub`, `nprofile`, relay hints, and optional terminal QR. Invite that account
from the phone app.

Check the installed or locally built version with:

```sh
wn-agent --version
```

## Invite Policy

Production connectors accept pending group invites only when the MLS-authenticated welcomer is on the configured
`--allow-welcomer` list. An empty allowlist rejects every invite.

Local development may use `--dev-allow-any-invites` together with `--debug-controls`. The connector warns when this
mode is active and accepts any authenticated welcomer, but it still rejects a welcome whose authenticated author is
missing. Do not enable either development option in production.

## Outbound Media Paths

Path-based media sends are denied unless `wn-agent` starts with one or more `--media-allowed-root PATH` options. The
connector opens each root at startup, then accepts only regular files reached beneath that directory handle without
following symlinks. Hermes and OpenClaw validate their original media source, stage a short-lived copy under
`$MARMOT_OUTBOUND_MEDIA_DIR`, send that staged path, and remove it after the connector responds.

Use a dedicated staging directory, never `/`, a home directory, or a broad application data tree. For split Unix
users, make the gateway the directory owner and give the connector's shared group read/traverse access; staged files
are created `0640`. In split-container deployments, mount the same directory read-write in the gateway and read-only
in the connector. Omitting `--media-allowed-root` deliberately leaves media sends disabled.

## Hermes Install

Versioned WN Agent builds publish the `wn-agent` binary, the Hermes Marmot plugin, and an installer script on GitHub
Releases under `wn-agent-v*` tags. The `wn-agent-latest` release contains installer scripts that are refreshed to the
newest WN Agent release. Hermes itself must already be installed.

```sh
curl -fsSL "https://github.com/marmot-protocol/mdk/releases/download/wn-agent-latest/install-hermes-marmot.sh" | bash
```

For repeatable noninteractive setup:

```sh
curl -fsSL "https://github.com/marmot-protocol/mdk/releases/download/wn-agent-latest/install-hermes-marmot.sh" | \
  bash -s -- --yes --allow-welcomer npub1...
```

Use a versioned `wn-agent-v<version>` release URL when you need a pinned install for reproducible testing.

The installer puts `wn-agent` in `~/.local/bin`, extracts the Hermes plugin to `~/.hermes/plugins/marmot`, and enables
the plugin when the `hermes` launcher is on `PATH`. It also starts a same-user connector service where supported,
bootstraps or reuses `~/.marmot-agents/hermes`, and patches only Marmot-specific Hermes config entries so existing
connectors continue to work. The default service identity is connector-specific:
`wn-agent-hermes.service` on Linux or `org.marmot.wn-agent.hermes` on macOS.

Hermes-specific setup, development helpers, and phone-test commands live in
[`integrations/hermes/marmot/README.md`](../../integrations/hermes/marmot/README.md).

## OpenClaw Install

The same WN Agent release publishes the OpenClaw Marmot channel plugin and installer:

```sh
curl -fsSL "https://github.com/marmot-protocol/mdk/releases/download/wn-agent-latest/install-openclaw-marmot.sh" | bash
```

For repeatable noninteractive setup:

```sh
curl -fsSL "https://github.com/marmot-protocol/mdk/releases/download/wn-agent-latest/install-openclaw-marmot.sh" | \
  bash -s -- --yes --allow-welcomer npub1...
```

The OpenClaw installer follows the same release flow, but uses its own default connector home and service identity:
`~/.marmot-agents/openclaw`, `wn-agent-openclaw.service` on Linux, or `org.marmot.wn-agent.openclaw` on macOS. It
installs/enables the OpenClaw plugin and updates only `channels.marmot` in OpenClaw config so existing channels
continue to work.

## OpenCode Harness Install

The same WN Agent release publishes the `wn-opencode` harness binary and installer. OpenCode itself must already be
installed.

```sh
curl -fsSL "https://github.com/marmot-protocol/mdk/releases/download/wn-agent-latest/install-opencode-marmot.sh" | bash
```

For repeatable noninteractive setup:

```sh
curl -fsSL "https://github.com/marmot-protocol/mdk/releases/download/wn-agent-latest/install-opencode-marmot.sh" | \
  bash -s -- --yes --allow-welcomer npub1...
```

The OpenCode installer creates or reuses the terminal-harness agent home at `~/.marmot-agents/harnesses`, writes a
private `wn-opencode.env`, and starts a same-user `wn-opencode` service where supported. The backing `wn-agent` service
uses `wn-agent-harnesses.service` on Linux or `org.marmot.wn-agent.harnesses` on macOS. `WN_OPENCODE_MAX_REPLY_BYTES`
defaults to 30000 bytes per Marmot reply chunk.

## Cutting A WN Agent Release

After the release commit is merged to `master`, cut a WN Agent release tag with:

```sh
just release-wn-agent 0.9.3
```

For a dry run:

```sh
just release-wn-agent-dry-run 0.9.3
```

The helper checks that:

- the requested version matches the root workspace version;
- the working tree is clean;
- `HEAD` matches `origin/master`;
- `wn-agent-v<version>` does not already exist locally or remotely.

It creates and pushes an annotated `wn-agent-v<version>` tag. Pushing that tag starts
`.github/workflows/wn-agent-binaries.yml`, which publishes the versioned binary/plugin assets and the installer script.
Pull requests, `master` pushes, and manual workflow runs build validation artifacts only; they do not publish a GitHub
Release.

## Control Plane Security

The v1 control plane is local-only:

- Unix socket only;
- default parent directory mode `0700`;
- default socket mode `0600`;
- same effective UID required;
- no TCP listener.

When the gateway and `wn-agent` run as different local service users, use a bearer token file plus group-readable socket
modes:

```sh
openssl rand -hex 32 > ~/.marmot-agent/control.token
chmod 0600 ~/.marmot-agent/control.token

cargo run -p agent-connector --bin wn-agent -- \
  --home ~/.marmot-agent \
  --auth-token-file ~/.marmot-agent/control.token \
  --socket-dir-mode 0770 \
  --socket-mode 0660 \
  --relay wss://relay.eu.whitenoise.chat \
  --relay wss://relay.us.whitenoise.chat

export MARMOT_AGENT_AUTH_TOKEN_FILE="$HOME/.marmot-agent/control.token"
```

World-readable or world-writable socket modes are rejected. Split-host gateways need a later authenticated remote control
plane; do not expose the Unix socket over TCP.

Logging must stay privacy-safe: no account ids, group ids, message ids, relay URLs, pubkeys, payloads, ciphertext,
plaintext, or key material.

## Verification

Use the narrow checks first:

```sh
cargo test -p agent-connector
cargo check -p agent-connector --bin wn-agent
bash scripts/install-hermes-marmot.sh --dry-run
bash scripts/install-opencode-marmot.sh --dry-run --yes --allow-welcomer "$(printf '11%.0s' {1..32})" --opencode-bin /bin/echo
integrations/hermes/marmot/tests/test_dev_scripts.sh
```

Before checkpointing broader release work, run the normal repo checks from the root:

```sh
just fmt-check
just check
just clippy
just test
```
