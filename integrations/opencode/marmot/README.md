# wn-opencode

`wn-opencode` is a dedicated Marmot harness for [OpenCode](https://opencode.ai/).
It joins Marmot groups through the local `wn-agent` connector and sends every
message from an allowed sender to `opencode run --format json`.

`wn-agent` owns the Marmot account, MLS state, Nostr transport, invite allowlist,
and durable encrypted sends. `wn-opencode` is intentionally thinner than the
Hermes and OpenClaw gateway integrations: it has no mention activation, media
handling, profile onboarding, or live previews. It is a pure harness for an
authorized operator.

## Install (OpenCode Already Installed)

Versioned `wn-agent` builds publish the `wn-agent` binary, this harness binary,
and an installer under [`wn-agent-v*`](https://github.com/marmot-protocol/mdk/releases)
GitHub pre-releases.

Prerequisites:

- OpenCode installed locally and runnable on `PATH`, or an executable path set
  with `WN_OPENCODE_BIN` / `--opencode-bin`
- White Noise phone app pointed at the same public relay set
- Linux x86_64, Linux arm64, macOS Apple Silicon, or macOS Intel

One-line install:

```sh
WN_AGENT_VERSION=0.9.2
curl -fsSL "https://github.com/marmot-protocol/mdk/releases/download/wn-agent-v${WN_AGENT_VERSION}/install-opencode-marmot.sh" | bash
```

For repeatable noninteractive setup, pass the allowed inviter and prompt sender
as either an `npub` or raw hex public key:

```sh
WN_AGENT_VERSION=0.9.2
curl -fsSL "https://github.com/marmot-protocol/mdk/releases/download/wn-agent-v${WN_AGENT_VERSION}/install-opencode-marmot.sh" | \
  bash -s -- --yes --allow-welcomer npub1...
```

The installer puts `wn-agent` and `wn-opencode` in `~/.local/bin`, starts a
same-user `wn-agent` service where supported, bootstraps or reuses
`~/.marmot-agent`, mirrors the allowlist into `wn-agent`, writes
`~/.marmot-agent/dev/wn-opencode.env`, and starts a same-user `wn-opencode`
service where supported.

Use the exact release version when reporting bugs:

```sh
wn-agent --version
wn-opencode --version
```

Manual equivalent:

```sh
export MARMOT_HOME="$HOME/.marmot-agent"
export MARMOT_AGENT_SOCKET="$MARMOT_HOME/dev/wn-agent.sock"
export WN_OPENCODE_ALLOWED_SENDERS_HEX="..."

wn-agent --home "$MARMOT_HOME" \
  --socket "$MARMOT_AGENT_SOCKET" \
  --relay wss://relay.eu.whitenoise.chat \
  --relay wss://relay.us.whitenoise.chat

wn-agent bootstrap \
  --home "$MARMOT_HOME" \
  --socket "$MARMOT_AGENT_SOCKET" \
  --allow-welcomer "$WN_OPENCODE_ALLOWED_SENDERS_HEX" \
  --qr

wn-opencode
```

Invite the printed agent account from the phone app.

## Configuration

Configure with environment variables:

| Env | Default | Meaning |
| --- | --- | --- |
| `MARMOT_HOME` | `~/.marmot-agent` | `wn-agent` data directory |
| `MARMOT_AGENT_SOCKET` | `$MARMOT_HOME/dev/wn-agent.sock` | Unix control socket |
| `MARMOT_AGENT_AUTH_TOKEN_FILE` | unset | Optional bearer-token file for group-readable socket setups |
| `MARMOT_AGENT_AUTH_TOKEN` | unset | Optional bearer token value |
| `WN_OPENCODE_ALLOWED_SENDERS_HEX` | required | Comma-separated sender account ids allowed to prompt OpenCode |
| `WN_OPENCODE_ADMIN_HEX` | unset | Legacy alias for `WN_OPENCODE_ALLOWED_SENDERS_HEX` |
| `WN_OPENCODE_ACCOUNT_ID_HEX` | first local account | Specific `wn-agent` account to use |
| `WN_OPENCODE_BIN` | `opencode` | OpenCode binary or executable path |
| `WN_OPENCODE_TIMEOUT_SECS` | `300` | Hard timeout for each OpenCode invocation |
| `WN_OPENCODE_REQUEST_TIMEOUT_SECS` | `30` | Timeout for each control-socket request |
| `WN_OPENCODE_MAX_REPLY_BYTES` | `30000` | UTF-8 byte limit for each durable Marmot reply chunk |
| `WN_OPENCODE_MAX_PENDING_PER_GROUP` | `4` | Per-group in-flight/queued prompt cap |
| `WN_OPENCODE_STATE_PATH` | `$XDG_STATE_HOME/wn-opencode/sessions.json` | Session map path |
| `WN_OPENCODE_ACTIVATION` | `always` | Only `always` is supported today |
| `RUST_LOG` | `info,wn_opencode=info` | tracing filter |

The reply limit is byte-based, not character-based. The default is 30KB, well
below Marmot's roughly 60KB message ceiling. Splitting prefers paragraph,
newline, then space boundaries and never splits a UTF-8 code point.

## Workdir Picker

On the first message in a new Marmot group, a leading `/<name>` selects
`~/<name>` as the OpenCode working directory if it is a direct child directory of
`$HOME`.

Examples:

```text
/mdk fix the failing test
/mdk
```

When the message is only the picker, `wn-opencode` stores the workdir and asks
for the next prompt.

## Security Notes

- The control socket is local Unix-domain only. Use the normal `wn-agent`
  socket mode and bearer-token options for shared local-user setups.
- The same allowlist controls invite acceptance in `wn-agent` and prompt
  execution in `wn-opencode`.
- Logs are structured and privacy-safe: no account ids, group ids, message ids,
  local paths, prompt text, OpenCode output, relay URLs, pubkeys, ciphertext, or
  key material.
- Prompt text is passed to `opencode run` as a process argument. Run this
  harness only on trusted single-user hosts or hosts with equivalent local
  process isolation.
- The session map is written through `fs-private` with owner-only file and
  directory modes.

## Development

```sh
cargo test -p wn-opencode
just opencode-dev-e2e-connector
just opencode-installer-test
cargo run -p wn-opencode
bash scripts/install-opencode-marmot.sh --dry-run --yes --allow-welcomer "$(printf '11%.0s' {1..32})" --opencode-bin /bin/echo
```

The crate is a workspace member at `integrations/opencode/marmot`.
