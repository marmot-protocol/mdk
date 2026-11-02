# Build Your Own wn-agent Client

This guide is for a client that is not one of the supported connectors: a notifier bot, a script, or your own agent
runtime. You run `wn-agent` as a supervised service, and your client talks to it over the local control socket with
newline-delimited `marmot.agent-control.v2` JSON. `wn-agent` owns the Marmot account, MLS state, relays and durable
encrypted sends, so your client never handles keys or ciphertext.

Every identifier below is a placeholder. Use your own values, and never paste a real secret key into a file, a command
line or a chat.

## Contents

- [Install](#install)
- [Choose an identity](#choose-an-identity)
- [Run as a service](#run-as-a-service)
- [Talk to the control socket](#talk-to-the-control-socket)
- [Create a group](#create-a-group)
- [Send a message](#send-a-message)
- [Receive messages](#receive-messages)
- [Check a full round trip](#check-a-full-round-trip)
- [Troubleshooting](#troubleshooting)

## Install

You need Linux (x86_64 or arm64) or macOS (Apple Silicon or Intel), `curl`, `tar`, `shasum` or `sha256sum`, and
`python3` for the examples. No Rust toolchain is required.

Install with the connector-only installer, `install-wn-agent.sh`, using the verified helper in the
[quickstart](README.md#wn-agent-only-your-own-client). It downloads the checksum-verified `wn-agent` from a
`wn-agent-v*` release, creates a private home, and starts a same-user service with the default White Noise relays. It
installs no harness or plugin. Releases up to 0.14.0 do not publish it; for those, the quickstart shows how to run it
from a clone of this repository.

| Setting | Default | Override |
| --- | --- | --- |
| Binary | `~/.local/bin/wn-agent` | `--system` installs to `/usr/local/bin` |
| Home (mode `0700`) | `~/.marmot-agents/standalone` | `--home PATH` |
| Socket | `<home>/dev/wn-agent.sock` | `--socket PATH` |
| Relays | `wss://relay.eu.whitenoise.chat`, `wss://relay.us.whitenoise.chat` | `--relay URL`, repeatable |
| Service | `wn-agent-standalone.service` (Linux), `org.marmot.wn-agent.standalone` (macOS) | `MARMOT_AGENT_SERVICE_NAME`, `MARMOT_AGENT_LAUNCHD_LABEL` |

Use the same relays as the people you will message. Run the installer's `--help` for every option, and `--dry-run` to
preview the plan. Check the binary with `wn-agent --version`; add `~/.local/bin` to your `PATH` if the shell cannot find
it.

## Choose an identity

The connector's identity should belong to the connector alone and not also be signed in on another client. This guide
does not cover running one identity on several devices.

Pick one of these when you install:

- **A new identity:** `--bootstrap` creates (or, on a rerun, reuses) a local account labelled `standalone-agent` and
  publishes its KeyPackage so others can add it to groups.
- **An existing identity:** `--import-identity` reads a Nostr secret key (`nsec` or hex) from a masked prompt on your
  terminal, then bootstraps that account. Add `--expected-identity npub1...` to refuse any other key. Import only a key
  that no other client uses.

Either way, the installer prints the agent's `account_id_hex`, `npub` and `nprofile`, and saves them to
`<home>/bootstrap.json` (mode `0600`). Your client passes `account_id_hex` in every request.

If you installed without either flag, rerun the installer with `--bootstrap` or `--import-identity`. To bootstrap by
hand instead, save the JSON reply where the installer would, adding any custom `--relay` values you installed with so
the printed `nprofile` matches:

```sh
home="$HOME/.marmot-agents/standalone"
(umask 077 && wn-agent bootstrap --json --home "$home" --socket "$home/dev/wn-agent.sock" \
  --label standalone-agent > "$home/bootstrap.json.tmp" && mv "$home/bootstrap.json.tmp" "$home/bootstrap.json")
```

Invites are refused by default. If people should be able to add the agent to their own groups, pass
`--allow-welcomer npub1...` (repeatable) with `--bootstrap` or `--import-identity`, or see
[invite policy](../crates/agent-connector/README.md#invite-policy). An agent that only creates its own groups needs no
allowlist.

## Run as a service

The installer writes and starts the service, passing `--home`, `--socket` and each `--relay`. Keep one `wn-agent`
process per home; a second one cannot share it.

On Linux (systemd user unit):

```sh
systemctl --user status wn-agent-standalone.service
journalctl --user -u wn-agent-standalone.service -e
systemctl --user restart wn-agent-standalone.service
```

A user unit stops when you log out unless lingering is on. For a long-running bot, enable it once:

```sh
loginctl enable-linger "$USER"
```

On macOS (LaunchAgent), logs go to `<home>/logs/wn-agent.out.log` and `<home>/logs/wn-agent.err.log`:

```sh
launchctl print "gui/$(id -u)/org.marmot.wn-agent.standalone"
launchctl kickstart -k "gui/$(id -u)/org.marmot.wn-agent.standalone"
```

With `--no-service`, the installer prints the exact `wn-agent` command to run under your own supervisor. Keep its
`--relay` options: a daemon started without relays cannot reach anyone.

Run your client as the same user. The socket is `0600` and accepts only the owner's UID. For a client under a different
user, use a bearer token file as described in
[control plane security](../crates/agent-connector/README.md#control-plane-security).

## Talk to the control socket

Each request is one JSON object on one line, at most 1 MiB, with these envelope fields:

- `marmot_agent_control`: always `"marmot.agent-control.v2"`;
- `id`: your correlation id, echoed on every reply;
- `type`: the request type, with its fields beside it;
- `auth_token`: only when the daemon runs with `--auth-token-file`.

Optional request fields may be omitted or sent as `null`. The examples below send `null` explicitly, as the bundled
connectors do.

Open a new connection for each request. `wn-agent` writes one reply line and closes the connection.
`subscribe_inbound` is the exception: it keeps the connection open and streams events. A failed request answers with
`{"type": "error", "code": "...", "message": "...", "retryable": false}`. A request that does not parse, such as one
with an unknown `type` or a missing field, currently closes the connection with no reply
([#2242](https://github.com/marmot-protocol/mdk/issues/2242)).

This standard-library helper sends the request on its stdin and prints each reply line. Save it as
`wn_agent_request.py`:

```python
#!/usr/bin/env python3
"""Send one marmot.agent-control.v2 request (JSON on stdin) to wn-agent."""
import json
import os
import socket
import sys
import uuid

PROTOCOL = "marmot.agent-control.v2"
MAX_FRAME_BYTES = 1024 * 1024


def main():
    request = json.load(sys.stdin)
    streaming = request.get("type") == "subscribe_inbound"
    envelope = {"marmot_agent_control": PROTOCOL, "id": uuid.uuid4().hex, **request}
    token_file = os.environ.get("MARMOT_AGENT_AUTH_TOKEN_FILE")
    if token_file:
        with open(token_file, encoding="utf-8") as handle:
            envelope["auth_token"] = handle.read().strip()
    replies = 0
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(None if streaming else 60)
            sock.connect(os.environ["MARMOT_AGENT_SOCKET"])
            sock.sendall(json.dumps(envelope).encode() + b"\n")
            reader = sock.makefile("rb")
            while line := reader.readline(MAX_FRAME_BYTES + 1):
                if not line.endswith(b"\n"):
                    sys.exit("error: truncated or oversized reply")
                reply = json.loads(line)
                if reply.get("id") != envelope["id"]:
                    sys.exit("error: reply id does not match the request")
                replies += 1
                print(json.dumps(reply), flush=True)
                if reply.get("type") == "error":
                    sys.exit(1)
                if not streaming:
                    return
    except socket.timeout:
        sys.exit("error: no reply within 60 seconds; the outcome is unknown")
    if replies == 0:
        sys.exit("error: wn-agent closed the connection without a reply")
    sys.exit("error: the inbound stream ended; reconnect")


if __name__ == "__main__":
    main()
```

Set the socket and account once per shell:

```sh
export MARMOT_AGENT_SOCKET="$HOME/.marmot-agents/standalone/dev/wn-agent.sock"
export MARMOT_ACCOUNT_ID_HEX="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["account_id_hex"])' \
  "$HOME/.marmot-agents/standalone/bootstrap.json")"
```

Check the connection with `account_list`. The agent account should be listed with `"local_signing": true`:

```sh
echo '{"type": "account_list"}' | python3 wn_agent_request.py
```

## Create a group

`wn-agent` has no group command yet ([#2551](https://github.com/marmot-protocol/mdk/issues/2551)), so send
`group_create`:

```sh
python3 wn_agent_request.py <<EOF
{"type": "group_create", "account_id_hex": "$MARMOT_ACCOUNT_ID_HEX", "name": "Build alerts", "members": ["npub1..."]}
EOF
```

On the wire this is one line:

```json
{"marmot_agent_control": "marmot.agent-control.v2", "id": "create-1", "type": "group_create", "account_id_hex": "<agent account id hex>", "name": "Build alerts", "members": ["npub1..."]}
```

The reply carries the new group id:

```json
{"marmot_agent_control": "marmot.agent-control.v2", "id": "create-1", "type": "group_created", "group_id_hex": "<group id hex>", "agent_created": true, "pending_welcome_count": 1}
```

- `members` takes npub or hex public keys. Each member needs a published KeyPackage, which White Noise publishes for
  every account.
- Optional fields: `description`, and `relays` to override the group's routing relays.
- `group_create` is not idempotent: a retry can create a second group. Save `group_id_hex` as soon as it arrives, and
  treat a timeout as an unknown outcome rather than retrying blindly.
- `pending_welcome_count` counts invitations not yet delivered to relays. Each member still has to accept the
  invitation in their app.

Save the id for the next steps:

```sh
export MARMOT_GROUP_ID_HEX="<group id hex>"
```

## Send a message

There is no send command yet either ([#2243](https://github.com/marmot-protocol/mdk/issues/2243)). Send `send_final`
with an `idempotency_key`, so that retrying after a timeout returns the original message ids instead of posting twice:

```sh
python3 wn_agent_request.py <<EOF
{"type": "send_final", "account_id_hex": "$MARMOT_ACCOUNT_ID_HEX", "group_id_hex": "$MARMOT_GROUP_ID_HEX", "text": "Build 42 finished", "reply_to_message_id_hex": null, "idempotency_key": "build-42-finished"}
EOF
```

```json
{"marmot_agent_control": "marmot.agent-control.v2", "id": "send-1", "type": "final_sent", "message_ids_hex": ["<message id hex>"], "maintenance_disposition": "ready"}
```

- Set `reply_to_message_id_hex` to a message id to reply to that message.
- A key names one message. Reusing a key with different text sends a new message.
- `final_sent` means `wn-agent` published the encrypted message. It does not prove a member received it; the
  [round trip](#check-a-full-round-trip) does.
- `maintenance_disposition` is `ready`, or `post_join_rotation_pending_retryable` shortly after joining a group. Both
  mean the message was sent; the second only reports key maintenance still in progress.
- A `retryable: true` error is safe to retry with the same key.

## Receive messages

Open one long-lived connection and send `subscribe_inbound`. `account_id_hex` and `group_id_hex` are optional filters;
`null` means no filter:

```sh
python3 wn_agent_request.py <<EOF
{"type": "subscribe_inbound", "account_id_hex": "$MARMOT_ACCOUNT_ID_HEX", "group_id_hex": null}
EOF
```

The first reply is `{"type": "ack", ...}`. Every later line is an event with the same `id`, for example:

```json
{"marmot_agent_control": "marmot.agent-control.v2", "id": "sub-1", "type": "inbound_message", "account_id_hex": "<agent account id hex>", "group_id_hex": "<group id hex>", "message": {"message_id_hex": "<message id hex>", "sender": {"account_id_hex": "<sender hex>", "display_name": "Example", "is_self": false}, "text": "hello", "recorded_at": 1790000000}, "mentions_self": false}
```

- The agent's own messages are not delivered back to it.
- Other event types include `message_edited`, `message_deleted`, `reaction_added`, `reaction_removed`,
  `group_state_changed` and `group_invite`. Ignore types you do not handle.
- The stream carries what arrives while you are connected. Deduplicate by `message_id_hex`, reconnect when the
  connection closes, and after a reconnect or a `resync_required` event, page `timeline_list` (`account_id_hex`,
  `group_id_hex`, optional `limit`) to fill the gap.
- The daemon accepts at most 16 subscriptions at once and answers `server_busy` beyond that.

## Check a full round trip

A running service, a bootstrap or a `final_sent` reply does not show that messages flow both ways. Check both
directions with your own White Noise account:

1. Compare the agent's full `npub`, from the installer output or `bootstrap.json`, with the account you are about to
   trust. A matching name or avatar does not verify it.
2. [Create a group](#create-a-group) with your White Noise `npub` as the member, and accept the invitation on your
   phone.
3. In a second terminal, start the [subscription](#receive-messages) and leave it running.
4. [Send](#send-a-message) a message containing a fresh word, and check that it appears in that group on your phone.
5. Reply from your phone, and check that the subscription prints an `inbound_message` with your reply text.

The setup is verified once both messages arrive. Without a phone, run a second connector as the peer: install again
with its own `--home`, `MARMOT_AGENT_SERVICE_NAME`, `MARMOT_AGENT_LAUNCHD_LABEL` and `MARMOT_AGENT_LABEL`, plus
`--bootstrap --allow-welcomer <first agent npub>`, and add its `npub` as the member.

## Troubleshooting

Start with `wn-agent doctor --home "$HOME/.marmot-agents/standalone"`. It checks the home, socket, token, relays and
accounts, and asks the running daemon about its KeyPackage and relays, without changing anything; each check ends with
a next step ([Check the setup](../crates/agent-connector/README.md#check-the-setup)). The table covers what it cannot
see:

| Symptom | Likely cause | What to do |
| --- | --- | --- |
| `wn-agent: command not found` | `~/.local/bin` is not on `PATH` | Add it, or call `~/.local/bin/wn-agent` |
| No socket, or connection refused | The service is not running | Check the service status and logs above |
| The service stops after you log out (Linux) | User units stop without lingering | `loginctl enable-linger "$USER"` |
| `startup failed` naming a permission error | A custom `--socket` directory is group- or world-accessible, or owned by another user | Use a directory you own with mode `0700`, or the default socket ([#2550](https://github.com/marmot-protocol/mdk/issues/2550)) |
| Nothing arrives, or members never see messages | The daemon runs without relays, or with relays your members do not use | Run it with `--relay` for each relay your members use; the installer's unit already does |
| The connection closes with no reply | The request did not parse | Check the protocol label, `type` and required fields, and send one line ([#2242](https://github.com/marmot-protocol/mdk/issues/2242)) |
| `error` with `retryable: true` | A temporary condition such as `server_busy` | Retry later; for sends, reuse the same `idempotency_key` |
| `group_create` fails for a member | The member has no published KeyPackage | Ask them to open White Noise once, then retry |
| Invitations to the agent are ignored | Invites are refused unless allowlisted | Rerun `bootstrap` with `--allow-welcomer`, or set an [invite policy](../crates/agent-connector/README.md#invite-policy) |
| Messages appear from the agent that your client did not send, or state goes wrong | The identity is also signed in on another client | Give the connector an identity of its own |

For the connector's flags, security model and diagnostics, see the [connector README](../crates/agent-connector/README.md).
The full request and event types are in [`agent-control`](../crates/agent-control/src/lib.rs).
