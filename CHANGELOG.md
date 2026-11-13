# Changelog

## Unreleased

### Breaking changes

- Return optional create/invite operation results with ordered per-account
  resolution outcomes across Rust, C, UniFFI, and CLI (#1813). Available accounts
  proceed in one MLS operation; unavailable accounts are reported individually.
  A nonempty roster with no available account creates no group or commit.
  Prepared-image retries retain the original report across restart. Stable
  agent-control v2 creation and invitation remain atomic.

### Added

- Record `read_state_publish` runtime telemetry: the count and duration of
  each new version of an account's published read state, which the account
  worker now builds at its quiescent points for reads that later move off the
  worker (mdk#3273).
- Add `durably_owned_key_packages_with_validity` to the engine, session and
  account runtime: the owned KeyPackage list with the one clock reading its
  lifetimes are judged at, the next lifetime bound ahead (a listed bundle's
  `not_after` or a not-yet-valid bundle's `not_before`), whether a stored
  bundle was skipped as undecodable, and whether a lifetime check disagreed
  with that reading. A caller may keep the list only while no write reaches
  the account database, the clock stays between that reading and the next
  bound, and the read skipped no undecodable bundle and saw no disagreement
  (mdk#3273).

### Fixed

- Fail `durably_owned_key_packages` with the storage error when proving a
  stored bundle fails to read (I/O, busy, closed), instead of returning a
  partial list that reports this device's own KeyPackages as not owned.
  Bundles whose stored value does not decode are still skipped. Storage
  backends classify OpenMLS storage errors through the new
  `StorageProvider::mls_storage_failure` (mdk#3273).

## 0.16.0 - 2026-11-12

### Security

- Keep Hermes inbound attachment staging private from creation: use a `0700`
  directory and exclusively created `0600` files instead of copying source
  permissions and tightening them afterward. Tighten existing staging
  directories before copying new attachments (#2477).
- Move OpenMLS from the `erskingardner/openmls` fork to upstream `main`, which
  carries the fixes released in OpenMLS 0.9.1 and 0.9.2. A Welcome, GroupInfo,
  Proposal or Commit with deeply nested extensions could abort the process
  (GHSA-gc79-23g3-8g52), and a rejected private message could advance its
  sender's ratchet and block that sender's later messages (GHSA-p276-g3f3-wwgh).
  Stored groups load unchanged, and members on either build interoperate.

### Fixed

- Keep a chat receiving new messages after its account's live subscriptions
  are rebuilt (#3333). A relay's end-of-stored-events reply that arrived after
  the account had accepted the new subscriptions held the group's live
  messages until the recovery runner answered it, but only a new subscription
  generation woke the runner. The chat stopped receiving messages until
  unrelated activity woke recovery, and on an idle account nothing did.
- Joining a group while stored history is still replaying no longer records
  account-wide history loss and a needless re-sync (#3342). History that the
  new subscription asks for again is now owed to it, and loss is recorded only
  if that history does not arrive.
- Re-drive a pending leave that a rival branch blocked (#3345). When a
  convergence pass applied a branch that undid a leaving admin's step-down, or
  left the account the chat's last admin, the leave was neither staged again
  nor reported blocked until unrelated traffic arrived, so sign-out could wait
  out its full 30 s leave deadline.
- Stop waking the account worker every 10 ms for a chat the account was
  removed from (#3330). When two members committed the same removal from one
  epoch, the leftover rival kept the removed chat scheduled for convergence for
  the life of the process, wasting CPU and battery.
- A delayed generated-account setup handoff at startup or in the foreground no
  longer creates a replacement account after the original is wiped or removed
  (#3290). The handoff is bound to the original account and stops if it is
  gone; sign-out and wipe wait for foreground setup before withdrawing its
  KeyPackage, and a new create leaves signed-out and unlinked accounts alone.
- Forward Swift task cancellation to MDK's cancellable subscription receives
  (#2760). MarmotKit's Swift asset now ships `nextCancellable()` for presented
  chat lists, chat-list windows, account attention, conversation windows and
  block lists; UniFFI's generated `next()` keeps waiting after its Swift task
  is cancelled. Remove a host-owned copy of these adapters when taking the new
  asset, or Swift rejects the duplicate methods.
- Write Hermes `config.yaml`, its backup, and temporary files with mode `0600`
  during gateway configuration, regardless of the process umask. Existing
  group and other access is removed (#2481).
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

### Added

- Share NIP-46 remote signer sessions across Rust, UniFFI, and C, with
  account-secret-store persistence, startup restoration, versioned permission
  approval, relay-ready pairing offers, and request-scoped cancellation (#828).
  Sign-out and wipe erase communication keys; host NIP-55 callbacks and local
  signing accounts keep their existing APIs.
  Freeing a C handle preserves the runtime-owned signer. Logout detaches the
  revoked signer after credential erasure; storage failures retain stopped,
  retryable cleanup ownership. Setup rollback restores prior callbacks and
  grant records while initial-provisioning retries retain their paired credentials.
  Native login/register adoption is runtime-owned across all bindings: caller drop
  stops waiting without cancelling admitted work. Pairing is a separate bounded,
  caller-cancellable connect call; login requires an already-verified Ready session
  and rejects other states without connecting or creating an account. Unbound pairing
  never mutates an account. Explicit session cancel/disconnect/logout interrupts
  adoption, and shutdown interrupts and settles owned work before returning.
  Adoption keeps its admission generation through binding, network waits, and
  rollback. Reconnect cannot revive retired work; rollback cannot cancel a newer generation.
  Completed accounts rebind without reopening setup; failed Native adoption restores
  prior local callbacks, records, and activation without retracting published
  KeyPackages. Legacy host login behavior and explicit sign-out cleanup are unchanged.
  Post-commit journal cleanup failures do not revoke a ready account.
  Explicit pairing can repair metadata-only interrupted credential writes.
  Local removal reports account disappearance after cancellation instead of a vault failure.
  Account deletion serializes session resume through credential erasure and removal.
  Sign-out and wipe wait for foreground setup and keep signer resume behind
  their existing account fence through credential removal.
  Unsupported relay negotiation accepts `method not found` without hiding other errors.

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
