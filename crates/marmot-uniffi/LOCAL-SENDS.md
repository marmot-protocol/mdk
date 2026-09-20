# Durable local sends and caller correlation (unreleased)

Use `send_text_with_client_token`, `reply_to_message_with_client_token`, and
`send_message_draft_with_client_token` for a host optimistic composer. They return
`LocalSendAcceptanceFfi { client_token, message_id_hex }` after a local SQLCipher
transaction records ownership and the pending timeline row. The draft variant
consumes only the selected revision in that transaction. Do not clear the composer
again when delivery completes.

## Host integration

1. Allocate an opaque token for each logical submission and insert its optimistic
   bubble immediately, before draft persistence or the send call.
2. Call the token-aware method. Acceptance means MDK owns the retained message;
   it does **not** mean relay delivery or successful MLS validation.
3. Replace the optimistic bubble when a timeline row has the exact same
   `client_token`. Both raw timeline records and prepared conversation-window
   records expose the token. Do not match by content or timestamp.
4. Follow ordinary timeline updates for delivery (`source_message_id_hex`) and
   invalidation/failure. `local_send_status` can recover the admission/attempt
   status after an interrupted call or restart. `Completed` includes a send
   summary: its disposition may still be pending or completion-unknown.

Existing send/reply/draft/upload methods remain supported with their existing
completion semantics. New token-aware methods return acceptance rather than the
old delivery summary. Pair regenerated Swift/Kotlin bindings with matching native
binaries. C hosts also need the matching regenerated header: the timeline record
layout now includes a nullable `client_token`.

## Identity and retry contract

- Tokens contain 1–128 UTF-8 bytes and are scoped to one account-device and group.
  They are opaque, local-only values, never wire tags or diagnostics.
- Repeating a text/reply/draft request with its original token returns the same
  identity. A different request using that token is rejected. Draft retry identity
  binds the original opaque revision, including after that draft was consumed.
- Two independent submissions, including identical text in the same second,
  receive distinct event IDs through independent random event entropy. The caller
  token is neither transmitted nor used to derive that entropy.
  The shared kind-9 builder applies this to legacy text/reply/media/draft sends
  and stream finals too. The wire-visible `nonce` tag is tracked by
  [protocol issue #424](https://github.com/marmot-protocol/marmot/issues/424).
- The token association survives engine handoff, restart, echo and timeline
  reprojection. Remote and legacy messages have no caller token. Deleting the
  retained source/group also removes its association: token reuse after retention
  expiry is not a permanent deduplication guarantee.
- Repeating an accepted call is a lookup, not a delivery retry. Use the existing
  `retry_group_convergence` for engine-owned pending work. A rejected attempt is
  terminal; correcting and resubmitting it requires a new token.

## Ownership and scheduling

Admission uses local storage outside the account worker's publication queue. A
ready account can admit a second message while a previous publication is awaiting
relays. Account startup can still require worker acquisition. Admission is bounded
to 256 queued submissions and 16 MiB of queued payload/request data per account.

Once admission starts, cancellation of the caller's wait does not cancel the
owned local task. The account worker drains retained submissions and continues
publication independently. Engine queue/fanout persistence atomically transfers
ownership, preventing a restart from admitting the same payload twice. Shutdown
leaves undrained work durable for a subsequent account worker.

## Media

`upload_media_with_client_token` first uploads encrypted media and, when `send` is
true, admits the resulting message with the token. It returns uploaded references
plus optional acceptance. Upload completion must precede message acceptance;
`send=false` creates no timeline row or token association. Cancellation of the wait
does not abandon the owned upload task, but process restart before admission does
not resume an upload.

Uploads are not idempotent blob operations: repeating one may generate new
encrypted references. After an unknown outcome, query `local_send_status` with the
original token before uploading again. Media references remain epoch-bound and
can be rejected if the group changes before engine acceptance. A rejected media
submission needs freshly prepared references and a new token.

## Conversation windows and draft cost

Return-to-latest can consume a coherent pre-publication checkpoint, including an
exact-query tail checkpoint captured while the window was showing history.
Revision checks still reject stale navigation; hosts should retry against their
latest received revision.

Revisioned draft saves no longer hydrate an unused return copy of attachment
plaintext. Selected-draft descriptors use a blob-free covering index. Attachment
comparison still reads existing bytes; these changes do not promise constant-time
attachment saves.
