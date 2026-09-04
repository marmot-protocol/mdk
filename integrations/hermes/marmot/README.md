# Hermes Marmot Plugin

This directory is a Hermes platform plugin for the local `wn-agent` connector.
Hermes runs the agent and tools. `wn-agent` owns the Marmot account, MLS state,
Nostr transport, final encrypted sends, and QUIC live-preview stream records.

For the current guided install, runtime chooser, and steps to finish in White Noise, use the canonical
[White Noise + Agents quickstart](../../README.md#get-started-white-noise--agents).

For each activated inbound turn, the plugin asks `wn-agent` for a bounded recent
materialized chat window and supplies Hermes with durable message ids, senders,
timestamps, reply links, current reaction summaries, and
delete/invalidation state. Reply context includes both Hermes's native reply
fields and a complete structured referenced-message payload. The
model-callable `marmot_history` tool can fetch one exact message id or page older
messages using a `(recorded_at, message_id_hex)` cursor. Automatic history
lookup is best-effort and never drops the current inbound message if it fails.

The model-callable `marmot_reaction` tool and adapter hooks expose Marmot
reaction add/remove primitives to Hermes. They target an exact durable message
id or the latest inbound message and accept arbitrary non-blank, control-free
reaction content of at most 64 Unicode scalar values. Adds are idempotent;
removal can target exact content or clear all active own reactions atomically;
processing-status reaction policy remains a separate host concern.

For live previews, the plugin retries `stream_begin` with one stable v2 request
id and retains the returned stream capability in memory for subsequent append,
status, finalize, and cancel calls. The capability is a bearer secret and must
not be logged or persisted.

For a real Hermes install, install it by copying or symlinking this directory to:

```sh
~/.hermes/plugins/marmot
```

The current Hermes plugin loader expects platform plugins as directories directly
under `~/.hermes/plugins/<name>/` with `plugin.yaml`, `__init__.py`, and
adapter implementation files.

## Release Install (Hermes Already Installed)

Versioned `wn-agent` builds and the Hermes plugin are published as
[`wn-agent-v*`](https://github.com/marmot-protocol/mdk/releases) GitHub
pre-releases.

Prerequisites:

- Hermes Agent **0.19.0 or newer** installed and working locally. The installer
  validates the existing host and never installs or upgrades Hermes.
- White Noise phone app pointed at the same public relay set
- Linux x86_64, Linux arm64, macOS Apple Silicon, or macOS Intel

Verified install (the helper also forwards any installer arguments after the two URLs):

```sh
install_verified() (
  set -eu
  installer_url="$1"
  checksum_url="$2"
  shift 2
  installer_script="${installer_url##*/}"
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' 0 HUP INT TERM
  curl -fsSL "$installer_url" -o "$tmpdir/$installer_script"
  curl -fsSL "$checksum_url" -o "$tmpdir/$installer_script.sha256"
  if command -v shasum >/dev/null 2>&1; then
    (cd "$tmpdir" && shasum -a 256 -c "$installer_script.sha256")
  elif command -v sha256sum >/dev/null 2>&1; then
    (cd "$tmpdir" && sha256sum -c "$installer_script.sha256")
  else
    echo "error: need shasum or sha256sum to verify the installer" >&2
    exit 1
  fi
  bash "$tmpdir/$installer_script" "$@"
)

base_url="https://github.com/marmot-protocol/mdk/releases/download/wn-agent-v0.9.17"
install_verified "$base_url/install-hermes-marmot.sh" \
  "$base_url/install-hermes-marmot.sh.sha256"
```

In guided setup, the allowed-message-sender prompt accepts one or more `npub` or
raw hex public keys separated by commas. Leaving that prompt blank explicitly
opens Marmot messaging to every sender by writing
`MARMOT_ALLOW_ALL_USERS=true`.

For repeatable noninteractive setup, pass the allowed inviter/welcomer and allowed
message sender as either an `npub` or raw hex public key. `--allow-user` may be
repeated or given a comma-separated list to authorize multiple senders:

Run this example in the same shell where `install_verified` above was defined.

```sh
base_url="https://github.com/marmot-protocol/mdk/releases/download/wn-agent-v0.9.17"
install_verified "$base_url/install-hermes-marmot.sh" \
  "$base_url/install-hermes-marmot.sh.sha256" \
  --yes \
    --allow-welcomer npub1... \
    --allow-user npub1...,0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

Generated-identity onboarding is the default (and can be selected explicitly
with `--generate-identity`). To preserve an existing Nostr identity, place its
`nsec` or raw secret hex in a regular file owned by the current user with mode
`0600`, then use a pinned release URL:

Run this example in the same shell where `install_verified` above was defined.

```sh
base_url="https://github.com/marmot-protocol/mdk/releases/download/wn-agent-v0.9.17"
install_verified "$base_url/install-hermes-marmot.sh" \
  "$base_url/install-hermes-marmot.sh.sha256" \
  --yes \
  --existing-identity-file "$HOME/.config/example/hermes-agent.nsec" \
  --expected-npub npub1... \
  --allow-welcomer npub1... \
  --allow-user npub1...
```

The installer passes only the file path, never the secret, in process arguments.
`wn-agent` rejects symlinks, non-regular files, files owned by another user, and
files accessible by group/other users. It verifies `--expected-npub` before
starting the connector or changing Hermes configuration, imports idempotently,
then bootstraps the exact account with creation disabled. During interactive
setup, the same identity can instead be entered through a masked `/dev/tty`
prompt, which remains usable when the installer itself arrives through a pipe.
The source credential file is read-only and is not rewritten or removed.
The `--expected-npub` value must be a public `npub` or public-key hex, never an
`nsec` or raw secret key.

Hermes keeps its isolated default connector home. Reusing the same identity in
another connector home, such as OpenClaw's, requires a separate explicit import;
the installers never opt into shared home/socket state silently.

To accept Marmot messages from any sender (explicit opt-in):

Run this example in the same shell where `install_verified` above was defined.

```sh
base_url="https://github.com/marmot-protocol/mdk/releases/download/wn-agent-v0.9.17"
install_verified "$base_url/install-hermes-marmot.sh" \
  "$base_url/install-hermes-marmot.sh.sha256" \
  --yes --allow-all-users
```

Welcomer allowlist entries control which accounts may invite the Marmot agent
through `wn-agent`. Message-sender allowlist entries control which Marmot senders
Hermes accepts after gateway restart via `$HERMES_HOME/.env`
(`MARMOT_ALLOWED_USERS` and `MARMOT_ALLOW_ALL_USERS`).

Use a versioned `wn-agent-v<version>` release URL when you need a pinned install.

Use the exact release version when reporting bugs:

```sh
wn-agent --version
```

The installer puts `wn-agent` in `~/.local/bin`, extracts the plugin to
`~/.hermes/plugins/marmot`, enables the Marmot plugin, starts a same-user
`wn-agent-hermes` service where supported, bootstraps or reuses
`~/.marmot-agents/hermes`, and patches only Marmot-specific Hermes config
entries. Existing Hermes connectors such as Telegram are preserved.

Supported platforms: Linux x86_64, Linux arm64, macOS Apple Silicon, macOS Intel.
Both install scripts verify SHA256 checksums for downloaded release assets.

The installer prints restart guidance for your existing Hermes gateway. It does
not restart Hermes automatically. Restart a managed gateway with
`hermes gateway restart`.

Manual equivalent:

```sh
export MARMOT_HOME="$HOME/.marmot-agents/hermes"
export PATH="$HOME/.local/bin:$PATH"

wn-agent import-identity --json \
  --home "$MARMOT_HOME" \
  --label hermes-agent \
  --identity-file "$HOME/.config/example/hermes-agent.nsec" \
  --expected-identity npub1...

wn-agent --home "$MARMOT_HOME" \
  --socket "$MARMOT_HOME/dev/wn-agent.sock" \
  --relay wss://relay.eu.whitenoise.chat \
  --relay wss://relay.us.whitenoise.chat

wn-agent bootstrap --home "$MARMOT_HOME" --label hermes-agent \
  --no-create --account-id-hex <imported-account-hex> --qr
hermes gateway run
```

Then invite the printed agent account from the phone app.

## Repeatable Dev Setup

Use the repo scripts when testing the plugin without touching your normal Hermes
home. By default the root is `${TMPDIR:-/tmp}/hermes-marmot-test`; on macOS,
`$TMPDIR` usually expands to a path under `/var/folders/...`.

```sh
just hermes-dev-setup --print-env
source /tmp/hermes-marmot-test/env.sh
```

Development, CI, and the phone-test image default to the repo-owned
[`hermes-agent.lock`](hermes-agent.lock): Hermes `0.19.0`, release tag
`v2026.7.20`, commit `3ef6bbd201263d354fd83ec55b3c306ded2eb72a`.
Use `--hermes-ref` (or `HERMES_AGENT_REF`) only for deliberate upstream testing.
Required CI installs the same released version with `--install-pinned-wheel`;
the lock file pins both its Python package URL and SHA-256 so CI does not depend
on a cross-repository GitHub clone.

The setup script creates these paths under that root:

- `hermes-agent` for the isolated Hermes checkout.
- `hermes-home` for isolated Hermes state.
- `marmot-agent-home` for isolated `wn-agent` state.
- `hermes-home/plugins/marmot` as a symlink back to this plugin directory.
- helper scripts: `smoke-plugin.sh`, `e2e-deterministic.sh`,
  `e2e-connector.sh`, `verify-persisted-config.sh`, `bootstrap-agent.sh`,
  `run-wn-agent.sh`, `run-hermes-gateway.sh`, `start-wn-agent.sh`,
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
  --relay wss://relay.eu.whitenoise.chat \
  --relay wss://relay.us.whitenoise.chat \
  --quic-candidate quic://quic-broker.ipf.dev:4450 \
  --print-env

# Use a token-gated local control socket for a group-shared Hermes/wn-agent setup.
openssl rand -hex 32 > /tmp/hermes-marmot-control.token
chmod 0600 /tmp/hermes-marmot-control.token
just hermes-dev-setup --auth-token-file /tmp/hermes-marmot-control.token --socket-dir-mode 0770 --socket-mode 0660 --print-env
```

Smoke-test the plugin import against the isolated Hermes venv:

```sh
just hermes-dev-smoke
```

Verify Marmot loads from persisted Hermes config in a fresh Hermes subprocess
with no inherited `MARMOT_*` environment (installer/configure + fresh subprocess
probe):

```sh
just hermes-dev-setup --install-uv --print-env
source /tmp/hermes-marmot-test/env.sh
just hermes-verify-persisted-config
```

This uses the real Hermes checkout pinned by `hermes-agent.lock`, runs `configure_gateway.py` and
`hermes plugins enable marmot`, then launches a fresh Python process with all
`MARMOT_*` variables removed. The probe exercises Hermes plugin discovery,
`load_gateway_config()`, and `platform_registry.create_adapter()` only. It does
not start `hermes gateway run` or require a model provider.

Run the deterministic adapter E2E:

```sh
just hermes-dev-e2e-deterministic
```

This test uses the real Hermes platform base and the real Marmot plugin, but it
uses a fake `wn-agent` socket and a fixed handler response. It does not need a
Marmot account, a running `wn-agent`, or a model.

Run the deterministic connector E2E:

```sh
just hermes-dev-e2e-connector
```

This test starts a real `wn-agent` process with debug controls enabled, injects
one inbound message through its local control socket, and verifies the fixed
Hermes response is sent back through `wn-agent`. Its private temporary root
defaults to the current user's home directory because `wn-agent` rejects shared
`/tmp` ancestry on macOS; set `MARMOT_CONNECTOR_E2E_TMPDIR` to use another
private, user-owned parent.

Run the services in foreground terminals:

```sh
source "${HERMES_MARMOT_DEV_ROOT:-${TMPDIR:-/tmp}/hermes-marmot-test}/env.sh"
"$HERMES_MARMOT_DEV_ROOT/run-wn-agent.sh"
"$HERMES_MARMOT_DEV_ROOT/run-hermes-gateway.sh"
```

Or run them in the background with logs under `/tmp/hermes-marmot-test/logs`:

```sh
source "${HERMES_MARMOT_DEV_ROOT:-${TMPDIR:-/tmp}/hermes-marmot-test}/env.sh"
"$HERMES_MARMOT_DEV_ROOT/start-wn-agent.sh"
"$HERMES_MARMOT_DEV_ROOT/start-hermes-gateway.sh"
"$HERMES_MARMOT_DEV_ROOT/stop-dev-processes.sh"
```

Delete the whole throwaway setup:

```sh
just hermes-dev-teardown --force
```

## Docker Phone Test

The repo has a Compose profile for the dedicated-computer phone test. It builds a container with `wn-agent`, Hermes,
the Marmot plugin, and `qrencode` for terminal QR output. Run these commands on the host from the MDK repo root.
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

For this manual test the container starts `wn-agent` with `MARMOT_AGENT_DEV_ALLOW_ANY_INVITES=1` and
`MARMOT_AGENT_DEBUG_CONTROLS=1`, so the first invite from an authenticated phone can land without knowing the phone
account id ahead of time. Use an explicit allowlist and omit both development options for a real deployment.

In the phone-test container, `MARMOT_PROFILE_NAME_ONBOARDING=1` makes the Marmot Hermes adapter ask on the first
encrypted chat message whether to publish a public Nostr profile name for the agent account. Reply with the name to
publish it as kind-0 metadata, or reply `skip` to leave the agent unnamed. Outside this container path the prompt is
opt-in; set `MARMOT_PROFILE_NAME_ONBOARDING=1` or plugin extra `profile_name_onboarding: true` to enable it.

Stop the container without deleting the agent account:

```sh
just hermes-phone-test-down
```

Stop the container and delete all persisted agent/Hermes data for a fresh bootstrap:

```sh
just hermes-phone-test-reset
```

## Configuration

Start the connector first with the same public Nostr relay set the phone uses:

```sh
cargo run -p agent-connector --bin wn-agent -- \
  --home ~/.marmot-agents/hermes \
  --relay wss://relay.eu.whitenoise.chat \
  --relay wss://relay.us.whitenoise.chat
```

Bootstrap or reuse the agent account through the running connector:

```sh
wn-agent bootstrap \
  --home ~/.marmot-agents/hermes \
  --label hermes-agent \
  --relay wss://relay.eu.whitenoise.chat \
  --relay wss://relay.us.whitenoise.chat \
  --qr
```

Then configure Hermes with environment variables:

```sh
export MARMOT_HOME="$HOME/.marmot-agents/hermes"
export MARMOT_ACCOUNT_ID_HEX="<agent-account-pubkey-hex>"
export MARMOT_QUIC_CANDIDATES="quic://quic-broker.ipf.dev:4450"
```

`MARMOT_AGENT_SOCKET` can override the socket path. If it is not set, the plugin
uses `$MARMOT_HOME/dev/wn-agent.sock`. If `MARMOT_ACCOUNT_ID_HEX` is omitted and
`wn-agent` has exactly one local account, the adapter selects it automatically.

The default control socket is same-UID only: parent directory `0700`, socket
`0600`, no TCP listener. If Hermes and `wn-agent` run as different local service
users, use a token file and group-readable socket modes:

```sh
install -d -m 0750 ~/.marmot-agents/hermes
openssl rand -hex 32 > ~/.marmot-agents/hermes/control.token
chmod 0600 ~/.marmot-agents/hermes/control.token

cargo run -p agent-connector --bin wn-agent -- \
  --home ~/.marmot-agents/hermes \
  --relay wss://relay.eu.whitenoise.chat \
  --relay wss://relay.us.whitenoise.chat \
  --auth-token-file ~/.marmot-agents/hermes/control.token \
  --socket-dir-mode 0770 \
  --socket-mode 0660

export MARMOT_AGENT_AUTH_TOKEN_FILE="$HOME/.marmot-agents/hermes/control.token"
```

`MARMOT_AGENT_AUTH_TOKEN` is also supported for launcher-managed secrets. Prefer
`MARMOT_AGENT_AUTH_TOKEN_FILE` for shell and service-manager setups so the token
does not appear in process environments by default.

This is a full-control connector credential: it is not limited to the selected
Hermes account or group. Any holder can subscribe to all plaintext and operate
every account in that connector home. Do not share the connector/token with an
untrusted plugin or tenant; give that boundary its own `wn-agent` instance.

### Group activation (multi-party groups)

By default the adapter only runs an agent turn in a multi-party group when the
agent is addressed (`groupActivation=mention`). Set `MARMOT_GROUP_ACTIVATION=always`
to reply to every message. Trigger phrases come from `MARMOT_MENTION_PATTERNS`
(comma-separated) plus optional `MARMOT_AGENT_NAME`. Effective DMs (exactly two
members) always reply.

### Welcomer allowlist

On connect, `MARMOT_WELCOMER_ALLOWLIST` (or `MARMOT_DM_ALLOW_FROM`) mirrors
configured hex account ids into `wn-agent`'s welcomer allowlist so approved
inviters are accepted. Non-hex entries are ignored. When unset, the adapter
does not touch an allowlist managed directly on `wn-agent`.

### Hermes message-sender authorization

Hermes applies a separate sender gate before Marmot messages reach the agent.
The installer persists this in `$HERMES_HOME/.env`, which Hermes loads at gateway
startup:

- `MARMOT_ALLOWED_USERS` — comma-separated lowercase hex Marmot account ids
- `MARMOT_ALLOW_ALL_USERS` — explicit opt-in to accept any Marmot sender

These variables are independent from the welcomer allowlist above. A phone user
may be allowed to invite the agent without being allowed to message Hermes, and
vice versa. Restart Hermes after changing either variable.

### Media trust model

Inbound attachments are downloaded through `wn-agent`, re-staged under
`$MARMOT_HOME/dev/inbound-media` (override with `MARMOT_INBOUND_MEDIA_DIR`),
and the wn-agent temp file is removed. Outbound source paths must stay within
`MARMOT_MEDIA_LOCAL_ROOTS` (defaults to the inbound media directory). Hermes
then stages a private copy under `MARMOT_OUTBOUND_MEDIA_DIR` (defaults to
`$MARMOT_HOME/dev/outbound-media`), sends only that path, and removes it after
the connector responds. `wn-agent` must independently allow that exact staging
directory with `--media-allowed-root`; without one, path sends fail closed.

Hermes multi-image responses are sent as one ordered Marmot media message, not
as one message per image. The adapter accepts at most 10 attachments and caps
both each plaintext and the full batch to the encrypted-blob limit (512 MiB
minus authentication overhead). It validates every source before staging or
uploading any of them, applies the first non-empty caption once, and removes all
staged copies on success, error, timeout, or cancellation. Retryable control-
plane failures reuse one idempotency key; `wn-agent` binds that key to the
destination, caption, ordered attachment metadata, and plaintext hashes before
uploading, then returns the original durable message ids on a matching retry.
Reply-targeted media sends remain unsupported and fail before upload.

Large encrypted-media blobs retain the existing wire format, but every receiver
must run an MDK version with the matching 512 MiB receive bound; older receivers
still reject blobs above 64 MiB. MDK encrypts and decrypts each blob in place and
passes upload retries a shared immutable body, avoiding separate full-size
plaintext, ciphertext, and HTTP-body copies. The active blob still resides in
memory, and the connector reads the validated batch before upload, so the
aggregate 512 MiB request cap is also a deliberate peak-memory bound. This is
appropriate for release APK delivery on a suitably provisioned connector; it is
not a disk-streaming or low-memory-mobile transfer mode.

## Behavior

- Inbound Marmot messages become Hermes `MessageEvent`s with `chat_id` set to
  the Marmot group id and `user_id` set to the sender account id.
- Hermes progressive edits open at most one live preview per chat at a time. A
  newer preview cancels the previous stream for that chat.
- Explicit Hermes delivery context routes non-final commentary to durable agent
  activity (`kind: 1201`, `status: commentary`). Preview and draft frames remain
  transient; sealing the segment cancels its preview and emits one activity.
- Final answers and approvals remain durable `kind: 9` messages. Missing delivery
  context keeps this legacy final behavior for compatibility with older Hermes
  versions.
- Durable message text is exactly what Hermes hands the adapter. The adapter
  never merges, splices, or reconstructs text across sends; fragmented or
  duplicated finals must be fixed in Hermes message segmentation.
- A final or legacy plain send while a preview is open finalizes that stream as
  one tagged stream-final `kind: 9` when the final text is an append-only
  extension of the streamed text. There is no duplicate plain `send_final` for
  the same text.
- Otherwise the preview is cancelled and the final goes out verbatim as one
  plain `send_final`.
- Status records are included in the stream transcript hash and chunk count.

Run the shim tests with:

```sh
python3 -m unittest discover -s integrations/hermes/marmot/tests
```
