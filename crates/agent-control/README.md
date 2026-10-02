# agent-control

Local control-protocol DTOs and newline-delimited JSON framing for Marmot agent integrations.

This crate defines the `marmot.agent-control.v2` request/response/event types and the frame codec used over the
`wn-agent` Unix socket. The Hermes and OpenClaw plugins (and other host integrations) are thin clients of this
protocol; `agent-connector` is the server.

## What this crate does

- Owns `AgentControlEnvelope` and the typed control DTOs (bootstrap, send, subscribe, timeline history, invite policy,
  stream compose, allowlists, identifier-free `diagnostic_status`, etc.).
- Provides newline-delimited JSON framing with a 1 MiB per-frame cap (`MAX_AGENT_CONTROL_FRAME_BYTES`).
- Stays dependency-light: `serde` and Tokio IO only.

It does not contain engine, storage, account, or transport logic, the socket daemon or process lifecycle (see
`agent-connector`), or QUIC preview composition (see `agent-stream-compose`).

## Compatibility

Version 2 is intentionally incompatible with version 1. The structured inbound-message, reply-context, and
mutation-event schema was the final intentionally breaking update shipped under the `v2` label, while every consumer
was still released atomically from this repository. The `v2` schema is now stable: any later breaking wire change must
introduce a new protocol label or explicit negotiation rather than silently changing `v2`.

`group_state_changed` includes an optional `event_id_hex`: the opaque durable occurrence id shared by live events and
storage replay. Older connectors omit it. A change kind or timestamp alone is not a safe deduplication key.

Invite-policy values serialize on the wire as `deny`, `allowlist`, `any_authenticated_direct`, and
`any_authenticated`. Deserialization also accepts the CLI spellings `any-authenticated-direct` and
`any-authenticated`.

## Stream sessions

A successful `StreamBegin` returns a random 32-byte `stream_capability` encoded as 64 lowercase hex characters. Every
later append, status, progress, finalize, or cancel request for that stream must present the capability. Treat it as an
in-memory bearer secret: never persist or log it.

The envelope `id` is also the idempotency key for `StreamBegin`. Retrying the same begin request with the same `id`
returns the original stream id, start event, candidates, policy limit, and capability. Reusing that `id` with different
begin inputs is an error, and trying to begin another active stream with an occupied explicit stream id returns
`stream_id_in_use`; neither case replaces the existing session.

### Stream finalization

`stream_finish` accepts `stream_id_hex`, `stream_capability`, `final_text`, and an optional `idempotency_key`. The
shared publisher derives the hash and chunk count from acknowledged text, status, and progress records. A text mismatch
leaves the stream active and returns the non-retryable `stream_finalize_mismatch` code; a failed durable send retains
the sealed transcript and returns the retryable `stream_send_failed` code, so clients retry the same finish request.
Successful retries with the same inputs and key return the original message ids, including after the connector
restarts. Both paths return `stream_finalized`.

The older `stream_finalize` remains supported and additionally validates the client's `transcript_hash_hex` and
`chunk_count`. New clients use `stream_finish`, an additive v2 operation. The Hermes and OpenClaw plugins call
`stream_finish` without a `stream_finalize` fallback, so they are cohort-locked to the `wn-agent` release they ship
with; an older connector answers `control_error` and the plugins degrade to a plain durable send without a live preview.

## Reactions

`send_reaction` adds arbitrary non-blank, control-free reaction content of at most 64 Unicode scalar values to a
durable message. Repeating the same content from the same account on the same target is idempotent and returns the
existing reaction id instead of publishing a duplicate.

`remove_reaction` takes the original target message id; callers do not need to discover reaction event ids. An optional
`emoji` retracts all of the calling account's active reactions with that exact content. Omitting `emoji` retracts all
of the account's active reactions on the target in one durable delete event.

## Editing a durable message

`edit_message` lets a control client update a message authored by the selected
local account. Supply `account_id_hex`, `group_id_hex`, `target_message_id_hex`,
and replacement `text`. Before publishing, `wn-agent` checks that the target is
visible, available, self-authored, and a kind-9 chat message
(`MARMOT_APP_EVENT_KIND_CHAT`). A foreign, deleted, invalidated, missing, or
non-chat target is rejected before publication with the non-retryable
`invalid_edit_target` error code; `unauthorized` remains reserved for peer
authorization failures. A successful request returns `final_sent` with the edit event id. This
lets an agent update a pinned status message without adding another chat row.

An edit has no idempotency key. If the response is lost after publication, read
the materialized target with `timeline_message_get` before deciding whether to
retry; do not blindly replay an uncertain edit.

## Materialized timeline reads

`timeline_message_get` resolves one durable message id and `timeline_list` pages a group's current materialized
timeline with a stable `(recorded_at, message_id_hex)` cursor. These are read-only views of current message state:
edits are reflected, reactions are aggregated, and deleted or invalidated messages retain identity/attribution but
never expose plaintext or attachment metadata. Responses bound text, attachments, reactions, page size, and total frame
size.

Connectors use the same API both to attach a recent ID-bearing chat window to an inbound turn and to expose an
on-demand history tool. This is also the recovery path after `resync_required`; clients should re-page the
materialized timeline rather than attempting to reconstruct history from the lossy event stream.

## Run the tests

```sh
cargo test -p agent-control
```

See [`AGENTS.md`](AGENTS.md) for scope and invariants.
