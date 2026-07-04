# WN Agent Connector

This crate ships the `wn-agent` binary: the local White Noise agent connector.

`wn-agent` is the headless Marmot process that lets an agent runtime appear as a normal Marmot member. It owns the
Marmot account home, MLS state, Nostr relay IO, invite allowlists, durable encrypted sends, and live QUIC preview
composition. Agent runtimes such as Hermes, and later OpenClaw, stay thin: they run models and tools, then talk to
`wn-agent` through the local agent-control socket.

Hermes is the first supported adapter. OpenClaw is the second: a TypeScript channel plugin at
[`integrations/openclaw/marmot`](../../integrations/openclaw/marmot) that speaks the same agent-control protocol to this
connector.

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
cargo run -p agent-connector --bin wn-agent -- \
  --home ~/.marmot-agent \
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

## Hermes Install

Versioned WN Agent builds publish the `wn-agent` binary, the Hermes Marmot plugin, and an installer script on GitHub
Releases under `wn-agent-v*` tags. Hermes itself must already be installed.

```sh
WN_AGENT_VERSION=0.9.0
curl -fsSL "https://github.com/marmot-protocol/mdk/releases/download/wn-agent-v${WN_AGENT_VERSION}/install-hermes-marmot.sh" | bash
```

To install and immediately run `wn-agent bootstrap --qr`:

```sh
WN_AGENT_VERSION=0.9.0
curl -fsSL "https://github.com/marmot-protocol/mdk/releases/download/wn-agent-v${WN_AGENT_VERSION}/install-hermes-marmot.sh" | bash -s -- --bootstrap
```

The installer puts `wn-agent` in `~/.local/bin`, extracts the Hermes plugin to `~/.hermes/plugins/marmot`, and enables
the plugin when the `hermes` launcher is on `PATH`.

Hermes-specific setup, development helpers, and phone-test commands live in
[`integrations/hermes/marmot/README.md`](../../integrations/hermes/marmot/README.md).

## Cutting A WN Agent Release

After the release commit is merged to `master`, cut a WN Agent release tag with:

```sh
just release-wn-agent 0.9.0
```

For a dry run:

```sh
just release-wn-agent-dry-run 0.9.0
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
integrations/hermes/marmot/tests/test_dev_scripts.sh
```

Before checkpointing broader release work, run the normal repo checks from the root:

```sh
just fmt-check
just check
just clippy
just test
```
