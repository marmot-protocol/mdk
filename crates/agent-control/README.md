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

To write a client of this protocol, start with [Build your own client](../../integrations/custom-client.md): framing,
group creation, sends and `subscribe_inbound`, with wire examples.

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

## Historical attachment recovery

Three additive v2 operations use MDK's native attachment pipeline:

- `attachment_get { account_id_hex, group_id_hex, message_id_hex, attachment_index }`
  inspects one current source slot locally. It does not request acquisition or start network work.
- `download_attachment` takes the same fields. It requests explicit native acquisition,
  then returns immediately with native transfer status when bytes are not retained.
  Poll with backoff; another download request joins the existing work without resetting
  retries, deadlines, cancellation, removal suppression or permission policy.
- `release_attachment { lease }` removes the private plaintext handoff and replies
  `attachment_released`. Releasing an unknown or already released lease succeeds.

Both reads reply with `attachment { attachment: ... }`. A null attachment means the
current message/source/slot is unavailable, including deletion, invalidation and expiry.
Native acquisition admission refusal also returns a null attachment, not pending work.
The zero-based index counts **all original `imeta` tags**, including rejected slots;
it is not an index into a filtered list of attachment summaries. Each call resolves
the current authenticated source again. An old response does not authorize a later read.

Identity fields are `source_message_id_hex`, `attachment_index`, `source_epoch`,
`plaintext_sha256` and `ciphertext_sha256`. These describe the authenticated reference,
not verified downloaded bytes or recipient-download proof. No locators, nonces, keys,
peer size hints or native asset handles cross the socket. Unknown epochs fail with
`attachment_epoch_unavailable`; malformed or unsupported references fail with
`attachment_rejected`. Native failed/blocked states include an actionable `failure_hint`;
this API cannot reconstruct a missing old epoch key or clear a native retry limit.

`state`, `retry_at` and advisory `locally_available` report native transfer state.
Only a successful download includes `handoff { lease, path, size_bytes }`: a private
host-local file copied by `open_attachment_handoff`, with a verified byte count.
Hash those bytes and compare with `plaintext_sha256` to verify the expected artifact;
filenames and MIME agreement are not artifact identity. A later poll may resolve a
changed source, so compare the returned source and digest too.

Release each handoff when finished, including on client errors. A release failure
with code `attachment_release_failed` is retryable. Keep the lease and retry the
same release until cleanup succeeds. Malformed leases are not retryable. Each successful
download call can create a new lease. A leased copy is a snapshot: later source
removal does not revoke an already delivered file. Copies last until release,
account removal, or stale-copy cleanup when an account worker starts in a new
process. They are not a durable cache. Undelivered replies release their leases.
Local operations have the connector's 15-second deadline; acquisition has native
budgets/deadlines and continues independently. Plaintext bytes never enter a control
frame, and existing timeline reads remain network-free and unchanged.

Older connectors do not support these new request types. Do not fall back to a saved
raw `download_media` reference for historical recovery: that does not provide these
source checks or native acquisition controls.

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

## Message edits

`edit_message` replaces the text of a chat message the calling account sent, so an agent can update one status message
in place instead of appending new ones. It publishes a kind-1009 edit; the message keeps its identity and position, and
timeline reads return the latest text. The runtime refuses, before publishing anything, any target that is missing, not
a chat message, sent by another account, deleted, or withdrawn by convergence (`invalid_edit_target`, not retryable).
Competing edits resolve by `created_at`, then the larger event id, so two edits sent in the same
second settle on the same text everywhere, though not necessarily the one sent last. Edits have no idempotency key: after an uncertain response,
read the target with `timeline_message_get` before retrying. The `final_sent` ids name the edit event, not the message:
keep passing the original message id to later `edit_message` and `timeline_message_get` calls, since an edit event id is
not an editable target and returns `invalid_edit_target`.

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
