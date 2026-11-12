# Changelog

## Unreleased

### Security

- Keep Hermes inbound attachment staging private from creation: use a `0700`
  directory and exclusively created `0600` files instead of copying source
  permissions and tightening them afterward. Tighten existing staging
  directories before copying new attachments (#2477).

### Fixed

- Preserve explicit reply targets on standalone app and Hermes media sends,
  including durable uploads and ordered batches with or without captions.
  Validate and normalize reply ids before upload or admission, keep composer
  drafts unchanged, and reject idempotency keys reused for different reply
  targets (#859).
- Update the pinned Nostr SDK fork so a manual relay reconnect dials at once
  (#3269). A connect issued right after a disconnect could find the relay
  marked disconnected by the old connection's teardown and wait out the 5 s
  retry interval, so a reconnect could miss its 5 s bound and fail with a
  reconnect observation timeout.

## 0.16.0 - 2026-11-11

### Fixed

- Run the malformed kind-445 drain test against a relay that publishes its
  filter limit, so a cold boot's catch-up proves the offline gap at once. Its
  information-less relay held the message behind the unknown-cap sweep, which
  on a loaded runner outlasted the test's wait.
- Resume v5 audit delivery of a file a receiver's `409` blocked under 0.15.0
  (#3300). 0.15.0 blocked such a file for good as partial acceptance; loading
  the cursor now clears that block as it does a 0.15.0 rejection, including a
  cursor already rewritten as version 2, resends the file's pending range, and
  retries a later `409`. Before, the file stayed blocked until age expiry
  deleted it.
- Report each relay's answer to a publish under the spelling the group or
  inbox list gave it (#3305). A relay spelled with an upper-case host or an
  explicit default port read as possibly exposed whatever it answered, so a
  group whose only relay was spelled that way never confirmed or rolled back a
  commit.
- Fetch independent directory queries up to four at a time, so KeyPackage and
  deletion reads overlap their relay waits while retaining separate event limits
  (#1813).
- Reuse notification settings, chat mutes, group records, and directory users
  across live subscription events (#1800). Track settings, mute, and group
  changes at the shared storage boundary, including engine-side forgets across
  connections. Honor timed mute expiry and skip non-notifying kinds before
  storage reads or blocking-task dispatch.
- Keep a group commit pending when a crash interrupted its send and the relay
  then refuses the retry (#2332). The interrupted send may have reached the
  relay, so a later refusal no longer rolls back a commit that members may
  have applied.
- An account that is offline or has no relays no longer repeats the full replay
  synchronization on every 15 s maintenance tick (#3238). The pass ran five
  writer transactions and woke the recovery runner each time with nothing new to
  record. It now runs once per inactive transport generation and again on
  activation.
- Quarantine a group whose read of past group state could not restore its live
  state, instead of leaving it live on that past state for the session and
  validating it as live at the next open (#3272). The group reports the new
  hydration-quarantine reason `RewindRestoreFailed`; a retry or re-join does not
  clear it, and its input is retained. The next account open tries to restore
  the live state and replays the input only if that succeeds; otherwise the
  group is quarantined again for the same reason. Opening an account now
  handles every group's interrupted rewind before ingest or a Welcome join can
  read it.
- Report each relay the host-safety rule refuses (a private or loopback
  address, a plaintext `ws://` URL, or a URL that does not parse) as never
  contacted (#3276). A commit that every other group relay refused was retried
  against it with backoff and never rolled back; it now rolls back. A Welcome
  whose recipient's inbox list includes such a relay goes to the list's other
  relays instead of failing whole. Audit records the refusal as
  `publish_attempt_failed_before_exposure`.
- Unstick a group whose deferred-peel backlog is full (#3297). Catch-up held
  the whole group behind a history event the engine could neither open nor
  store, which also held the group's live messages and the account's sync
  cursor; that event is now let go of and the rest of the group admitted. A
  quarantined group stays held. The per-group deferred-peel caps rise from
  2,048 rows and 16 MiB to 8,192 rows and 64 MiB, the account cap from 64 MiB
  to 256 MiB, and the recovery runner's account breaker from 720 to 7,200
  quanta an hour, so a first catch-up of many groups no longer pauses it.
- Keep delivering v5 audit records however many segments a device retains
  (#3300). The delivery cursor kept about 320 bytes per retained file under a 1
  MiB cap and discovery held every segment open, so at about 3,250 segments
  every pass failed before any request. Idle sealed segments are now compact
  cursor rows matched from metadata; an over-limit cursor sheds the oldest with
  a `CursorOverflow` gap. Version 1 cursors upgrade on load.
- Stop retrying v5 audit delivery silently forever (#3300). A `400`, `413` or
  `422` now halves the batch and retries the halves, and only a record the
  receiver still rejects alone is skipped, with a `ReceiverRejected` gap; `409`
  is retried instead of blocking the file for good; `401`, `403`, `404` or
  another unexpected response pauses automatic delivery until the configuration
  changes or the host runs a manual tracker update. Each attempt's outcome is
  persisted and readable.
- Record only the outcome row for a relay replay that ingest ignores as a
  duplicate or own echo (#3300). Each such message wrote about 6 KB of audit
  rows; one replay storm filled 2.4 GB of v5 segments in a week.
- Record an `ExpiredUndelivered` gap when retention deletes an audit file that
  still held undelivered data (#3300). The loss surfaced only later, as a
  generic `MissingSource` gap.
- Record a relay's size refusal in audit v5 as `relay_rejected_invalid` again
  (mdk#2334). Since 0.15.0 it was written as `unclassified`. A relay MDK did not
  send to because the event is over its known limit is recorded as
  `publish_attempt_failed_before_exposure`.
- Retire a queued group change whose commit every group relay refuses for size
  (mdk#2334). The drain rolled it back and staged it again on every pass; it is
  now dropped once and announced as `QueuedIntentRefused` with reason
  `event_too_large`.
- Stop resending an account event that is over a relay's advertised message
  limit (mdk#2334). Such a relay closed the socket, which read as a possible
  exposure, and the event was resent three times; it is no longer sent there.

## 0.15.0 - 2026-11-09

### Added

- Add host-driven automatic rejoin for eligible Unrecoverable group copies,
  with bounded retries and Rust status and explicit-retry APIs. Accepted
  recovery controls are durably retained before their inbox source is
  acknowledged. Live retries preserve the handshake; quarantined coordinators
  retain publication debt without scheduling more work.

### Security

- Verify live directory events independently at MDK's relay forwarding and
  directory ingestion boundaries before forwarding or persisting profiles,
  follow edges, relay lists, or KeyPackages (mdk#2521). Reject unsigned,
  tampered, and invalidly signed records even when a producer claims prior
  verification.
- Update the pinned Nostr SDK fork to reject tampered event content and invalid
  signatures even when the event ID is in its verification cache. This ports
  upstream nostrdevkit/nostr commits `0e08c3062186fbc6665161769037873e0a981cd5`
  and `a991ff004975deaf1ef5279969ba1c6a85f79203` (#1508).
