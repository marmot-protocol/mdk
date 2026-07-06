# wn-opencode

An adapter that bridges a Marmot group to an [opencode](https://opencode.ai/) session.

- **Every incoming message** in a Marmot group where this agent is a member is treated as a prompt.
- **Every `text` event** from opencode's `--format json` stream is posted back as a distinct Marmot message.
- **`opencode_session_id = marmot_group_id`** - no state to maintain. New group = new opencode session automatically.

Only the admin (configured by npub hex) can invite this agent to groups.

## Architecture

```
Marmot phone client
        |
        v  Nostr / Marmot
        |
   wn-agent (MDK v0.9.1+, marmot-protocol/mdk)
     - MLS + Nostr + key management + Unix socket control plane
        |
        v  marmot.agent-control.v1 (newline-JSON) over Unix socket
        |
   wn-opencode  (this crate)
     - Subscribes to InboundMessage events
     - Enforces admin allowlist
     - Spawns: opencode run --format json --session <group_id_hex> <prompt>
     - Posts each text event back as SendFinal
```

## Running

```sh
export MARMOT_HOME="$HOME/.marmot-agent"
export WN_OPENCODE_ADMIN_HEX=0046b178bfc4c65d16ac4ef61eaee105f29d9c9178281033b3c334966f0606d8

# 1. Start wn-agent (in another terminal)
wn-agent --home "$MARMOT_HOME"

# 2. Bootstrap the agent identity once
wn-agent bootstrap --home "$MARMOT_HOME" --qr

# 3. Start the adapter
cargo run --release
```

## Configuration (env vars)

| Var | Default | Meaning |
|---|---|---|
| `MARMOT_HOME` | `~/.marmot-agent` | wn-agent data directory |
| `MARMOT_AGENT_SOCKET` | `$MARMOT_HOME/dev/wn-agent.sock` | Unix socket path |
| `MARMOT_AGENT_AUTH_TOKEN_FILE` | (unset) | Optional bearer-token file for cross-user setups |
| `WN_OPENCODE_ADMIN_HEX` | required | Admin account hex (comma-separated for multiple) |
| `WN_OPENCODE_BIN` | `opencode` | Path to opencode binary |
| `WN_OPENCODE_TIMEOUT_SECS` | `300` | Hard timeout per opencode invocation |
| `WN_OPENCODE_MAX_CHUNK_CHARS` | `8000` | Split a single text event above this size |
| `RUST_LOG` | `info` | tracing filter |
