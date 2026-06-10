---
title: "Hermes Agent Production Runbook"
created: 2026-06-08
updated: 2026-06-08
tags: [marmot, architecture, agents, hermes, runbook, deployment]
status: draft-runbook
---

# Hermes Agent Production Runbook

This runbook covers the supervised deployment path for a Hermes Agent account that appears as a normal Marmot member. The
durable encrypted Marmot message is the source of truth. QUIC live previews are optional and may be disabled without
breaking final replies.

## Production Gate

This setup is ready for dogfood or a supervised production pilot when all of these are true:

- `dm-agent` runs under a dedicated service user with a persistent `MARMOT_HOME`.
- Hermes runs under its own service user and talks to `dm-agent` through the local Unix control socket.
- The control socket is either same-UID only (`0700` parent, `0600` socket) or token-gated for group sharing.
- The token file is not checked into source, is group-readable only when two service users need it, and is rotated on host
  compromise.
- At least one public Nostr relay is configured for durable Marmot traffic.
- The phone and the agent computer use the same public relay set.
- QUIC broker candidates are configured only when the broker is reachable from the phone.
- The agent account has a published KeyPackage and an invite allowlist entry for the human account that will invite it.

Do not run this as an unattended production service until the manual phone test at the end passes with real device logs.

## Components

- `dm-agent`: Rust connector. Owns Marmot account state, MLS state, relay IO, final sends, allowlists, and stream previews.
- Hermes gateway: model and tool runtime. Uses the Marmot platform plugin in `integrations/hermes/marmot`.
- Public Nostr relays: durable Marmot transport. A normal deployment does not host its own relay.
- QUIC broker: optional memory-only live-preview transport.
- Dark Matter phone app: invites the agent and verifies the chat experience from the real client side.

Current pilot values:

```sh
MARMOT_RELAYS=wss://relay.eu.whiteniose.chat,wss://relay.us.whitenoise.chat
MARMOT_QUIC_CANDIDATES=quic://quic-broker.ipf.dev:4450
```

## Control Plane Modes

Default same-user mode:

```sh
dm-agent \
  --home /var/lib/marmot-agent \
  --socket /run/marmot-agent/dm-agent.sock \
  --socket-dir-mode 0700 \
  --socket-mode 0600 \
  --relay wss://relay.eu.whiteniose.chat \
  --relay wss://relay.us.whitenoise.chat
```

Use this when Hermes and `dm-agent` run as the same Unix user. The connector also checks peer credentials on the Unix
socket.

Group-shared token mode:

```sh
sudo install -d -m 0750 -o root -g marmot-agent /etc/marmot-agent
openssl rand -hex 32 | sudo tee /etc/marmot-agent/control.token >/dev/null
sudo chown root:marmot-agent /etc/marmot-agent/control.token
sudo chmod 0640 /etc/marmot-agent/control.token

dm-agent \
  --home /var/lib/marmot-agent \
  --socket /run/marmot-agent/dm-agent.sock \
  --auth-token-file /etc/marmot-agent/control.token \
  --socket-dir-mode 0770 \
  --socket-mode 0660 \
  --relay wss://relay.eu.whiteniose.chat \
  --relay wss://relay.us.whitenoise.chat

export MARMOT_AGENT_AUTH_TOKEN_FILE=/etc/marmot-agent/control.token
```

Use this when Hermes and `dm-agent` run as separate local users in the same Unix group. World-readable or world-writable
control socket modes are rejected at startup. Remote control-plane access is out of scope for this v1 path; keep the
gateway and connector on the same host, VM, or container boundary.

## Service Manager Setup

Example units live in:

- `packaging/systemd/dm-agent.service.example`
- `packaging/systemd/hermes-gateway.service.example`
- `packaging/systemd/hermes-marmot.env.example`

Install shape:

```sh
sudo groupadd --system marmot-agent || true
sudo useradd --system --home /var/lib/marmot-agent --gid marmot-agent marmot-agent || true
sudo useradd --system --home /var/lib/hermes-agent --groups marmot-agent hermes-agent || true

sudo install -d -m 0700 -o marmot-agent -g marmot-agent /var/lib/marmot-agent
sudo install -d -m 0700 -o hermes-agent -g hermes-agent /var/lib/hermes-agent
sudo install -d -m 0770 -o marmot-agent -g marmot-agent /run/marmot-agent

sudo install -m 0640 -o root -g marmot-agent \
  packaging/systemd/hermes-marmot.env.example /etc/marmot-agent/hermes-marmot.env
sudo install -m 0644 packaging/systemd/dm-agent.service.example /etc/systemd/system/dm-agent.service
sudo install -m 0644 packaging/systemd/hermes-gateway.service.example /etc/systemd/system/hermes-gateway.service
```

Edit `/etc/marmot-agent/hermes-marmot.env` before starting services. Set the public relay URLs that the phone will also
use, optional `MARMOT_ACCOUNT_ID_HEX`, optional `MARMOT_GROUP_ID_HEX`, and optional `MARMOT_QUIC_CANDIDATES`.

Start and inspect:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now dm-agent.service
sudo systemctl enable --now hermes-gateway.service
sudo systemctl status dm-agent.service hermes-gateway.service
journalctl -u dm-agent.service -u hermes-gateway.service -f
```

Logs must stay privacy-safe: no account ids, group ids, message ids, relay URLs, pubkeys, payloads, ciphertext, plaintext,
or key material.

## Bootstrap Checklist

1. Start `dm-agent` with the same public relay set the phone uses.
2. Create or import the agent account.
3. Publish or repair the agent KeyPackage.
4. Add the phone user's account id to the agent allowlist.
5. Start Hermes with the Marmot plugin enabled.
6. Invite the agent account from the phone app.
7. Confirm the agent auto-accepts only the allowlisted invite.
8. Send a normal prompt from the phone.
9. Confirm Hermes receives the inbound message and sends a final encrypted Marmot reply.
10. If QUIC previews are enabled, confirm previews appear before the final reply and the final reply still lands.

## Dedicated Computer Phone Test

This is the shortest useful manual test for the real user shape: Hermes runs on a dedicated computer, and the phone talks to
it through normal Marmot traffic on public Nostr relays. Docker is optional isolation for the computer-side setup. It must
not change the relay model.

Use `wss://relay.eu.whiteniose.chat` and `wss://relay.us.whitenoise.chat` for this pilot so the phone and the agent
computer exercise the same public relay set. Use `quic://quic-broker.ipf.dev:4450` for live previews. If preview
debugging gets in the way, omit `--quic-candidate`; final encrypted replies still exercise the durable production path.

Use the repo Compose profile for the fastest container test. Run these commands on the host from the Dark Matter repo
root. They start or exec into the container for you:

```sh
export OPENAI_API_KEY=...
just hermes-phone-test-up
just hermes-phone-test-bootstrap
```

Use the provider secret and optional `HERMES_MODEL` or `HERMES_PROVIDER` settings that match your Hermes setup. The
Compose service passes through common provider variables when they are set in your shell.

`just hermes-phone-test-bootstrap` runs this inside the container:

```sh
docker compose exec hermes-marmot-phone-test marmot-agent-bootstrap --qr
```

The command creates or reuses the `hermes-agent` account, publishes or repairs its KeyPackage, then prints the agent
account hex, `npub`, invite URI, and terminal QR code. The container also auto-bootstraps once at startup so Hermes can
start against the selected account.

Watch logs during the phone test:

```sh
just hermes-phone-test-logs
```

The Compose phone-test profile sets `MARMOT_AGENT_ALLOW_ANY=1` so the phone can invite the agent before you know the
phone account id. For a real deployment, disable allow-any and add the phone account id to the `dm-agent` allowlist.

From the phone:

1. Point Dark Matter at the same public relay set.
2. Invite the agent account into a new chat or test group. Scan the QR code if the phone build supports the
   `marmot-agent:v1` payload; otherwise copy the printed `npub` or account hex.
3. Send a short prompt.
4. Watch `dm-agent` and Hermes logs for the inbound event and final send.
5. Confirm the phone shows the final reply.
6. If preview is enabled, confirm the preview candidate uses an address the phone can reach. Docker `127.0.0.1` and host
   loopback addresses are not reachable from the phone.

Record the exact public relay URLs, container image or base OS, `dm-agent` commit, Hermes commit, phone app build, and
whether the test used QUIC previews. Keep message contents out of the notes.

Stop the container while preserving the named volume:

```sh
just hermes-phone-test-down
```

Stop the container and delete the named volume for a fresh agent account and KeyPackage:

```sh
just hermes-phone-test-reset
```

## Rollback

Stop Hermes first, then `dm-agent`:

```sh
sudo systemctl stop hermes-gateway.service
sudo systemctl stop dm-agent.service
```

Rotate the token after a failed or suspicious run:

```sh
openssl rand -hex 32 | sudo tee /etc/marmot-agent/control.token >/dev/null
sudo chown root:marmot-agent /etc/marmot-agent/control.token
sudo chmod 0640 /etc/marmot-agent/control.token
sudo systemctl restart dm-agent.service hermes-gateway.service
```
