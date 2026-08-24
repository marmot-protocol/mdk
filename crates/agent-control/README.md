# agent-control

Local control-protocol DTOs and newline-delimited JSON framing for Marmot agent integrations.

This crate defines the `marmot.agent-control.v2` request/response/event types and the frame codec used over the
`wn-agent` Unix socket. Hermes and OpenClaw plugins are thin clients of this protocol.

The structured inbound-message, reply-context, and mutation-event schema is the
final intentionally breaking update shipped under the `v2` label while every
consumer is still released atomically from this repository. The `v2` schema is
stable after this change: any later breaking wire change must introduce a new
protocol label or explicit negotiation rather than silently changing `v2`.

Version 2 is intentionally incompatible with version 1. A successful `StreamBegin` returns a random 32-byte
`stream_capability` encoded as 64 lowercase hex characters. Every later append, status, progress, finalize, or cancel
request for that stream must present the capability. Treat it as an in-memory bearer secret: never persist or log it.

The envelope `id` is also the idempotency key for `StreamBegin`. Retrying the same begin request with the same `id`
returns the original stream id, start event, candidates, policy limit, and capability. Reusing that `id` with different
begin inputs is an error, and trying to begin another active stream with an occupied explicit stream id returns
`stream_id_in_use`; neither case replaces the existing session.

## What this crate does

- Owns `AgentControlEnvelope` and the typed control DTOs (bootstrap, send, subscribe, timeline history, invite policy, stream compose,
  allowlists, etc.).
- Provides newline-delimited JSON framing with a 1 MiB per-frame cap.
- Stays dependency-light: `serde` and Tokio IO only.

Invite-policy values serialize on the wire as `deny`, `allowlist`, `any_authenticated_direct`, and
`any_authenticated`. Deserialization also accepts the CLI spellings `any-authenticated-direct` and
`any-authenticated`.

`send_reaction` adds arbitrary non-blank, control-free reaction content of at
most 64 Unicode scalar values to a durable message. Repeating the same content
from the same account on the same target is idempotent and returns the existing
reaction id instead of publishing a duplicate.
`remove_reaction` takes the original target message id; callers do not need to
discover reaction event ids. An optional `emoji` retracts all of the calling
account's active reactions with that exact content. Omitting `emoji` retracts
all of the account's active reactions on the target in one durable delete event.

## Materialized timeline reads

`timeline_message_get` resolves one durable message id and `timeline_list` pages a
group's current materialized timeline with a stable `(recorded_at,
message_id_hex)` cursor. These are read-only views of current message state:
edits are reflected, reactions are aggregated, and deleted or invalidated
messages retain identity/attribution but never expose plaintext or attachment
metadata. Responses bound text, attachments, reactions, page size, and total
frame size.

Connectors use the same API both to attach a recent ID-bearing chat window to an
inbound turn and to expose an on-demand history tool. This is also the recovery
path after `resync_required`; clients should re-page the materialized timeline
rather than attempting to reconstruct history from the lossy event stream.

## What it does not do

- No engine, storage, account, or transport logic.
- No socket daemon or process lifecycle (see `agent-connector`).
- No QUIC preview composition (see `agent-stream-compose`).

## Run the tests

```sh
cargo test -p agent-control
```

See [`AGENTS.md`](AGENTS.md) for scope and invariants.
