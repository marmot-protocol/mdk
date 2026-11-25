### Added

- C and MarmotKit can durably submit tagged text, inline replies, NIP-22 thread messages with attachments, and pack
  stickers. Retrying the same accepted request with its original client token after restart returns the original ID.
- Hosts can read whether each invite reached the invited account's inbox relays: `invite_deliveries` returns one
  durable answer per group and invited account (`Waiting`, `Sending` with the latest problem, `RelayAccepted`,
  `Undeliverable` or `Cancelled`, with device and relay counts), and `InviteDeliveryChanged` reports each change, in
  MarmotKit and C (mdk#1706). `RelayAccepted` means a relay stored the Welcome, not that the recipient received it.
  Only invites sent after the upgrade are listed; an older Welcome stays in `pending_welcome_deliveries`.

### Changed

- Maintenance queues an MLS self-update as soon as it detects stale chat capabilities, instead of scheduling it up to
  five days out. The quiet period, contention jitter, and commit safety checks still apply.

### Fixed

- An invite's or new chat's Welcome that no inbox relay stores is no longer retried for weeks (mdk#3589). It has a
  delivery deadline, 7 days after it was made or its KeyPackage's expiry if sooner; after that nothing sends it, not
  the startup retry, maintenance or `redeliver_welcome`, it leaves `pending_welcome_deliveries`, and
  `invite_deliveries` reads it `Undeliverable` with what its latest attempt found. When the deadline passes while the app runs, the v5
  audit records the end as `welcome_withdrawn` with reason `expired`. A Welcome owed from before this upgrade is held to 7 days from its gift
  wrap's timestamp, so the oldest end on the first start. The startup retry no longer skips relay backoff: it asks
  only relays never asked and those whose backoff has passed. The invitee stays a member.
- Cancelling a Swift task now cancels the throwing MarmotKit call it awaits, commands and subscription receives
  alike, and releases the native references that call holds without `shutdownAndClose()` (mdk#3670). Calls whose
  work must finish, such as `shutdownAndClose()`, `removeAccount()`, `signOut()`, `signOutAndWipe()` and the `login*`
  calls, still run to completion, and the receives generated without `throws` gain throwing `nextCancellable()`
  adapters. An audit of every async export found eight whose steps could be torn by a cancel; they now keep running
  when a Kotlin or Swift caller cancels them: sign-out, sign-in, account removal, the three logins, NIP-46 signer
  removal and the audit-log switch. Overlapping audit-log switch calls end with the last stored value.
- When the app's account worker publishes a Welcome (an invite's, a new chat's, or a retry of either), the first pass
  now reaches every inbox relay of its recipient, not only the first relay that acknowledged it. Each relay is asked
  on its own. The Welcome is still marked delivered at the first acknowledgement, and the host and the account worker
  do not wait for the other relays. Their answers are recorded once all of them have answered. If the worker stops
  waiting first (at the shutdown bound, a reconnect, sign-out or unlink), nothing more is recorded: those relays stay
  owed and are retried after their backoff, and one that already stored the Welcome answers duplicate. A Welcome whose
  only acknowledgement came from a relay that accepts gift wraps but cannot serve them back no longer depends on a
  retry 30 seconds later, which a closed app never ran. `redeliver_welcome` and runtimes that publish Welcomes inline
  still stop at the first acknowledgement.
- An invite's Welcome whose recipient has no usable inbox relay no longer retries, and records a routing failure, on
  every maintenance pass while it is owed (mdk#2261, in part). Its recipient is retried 10 minutes later, then at
  doubling intervals up to 6 hours; the pacing is kept in memory, so each app start still makes one attempt. Each
  retry uses the recipient's inbox route as the account last loaded it from the local directory cache: MDK does not
  look the recipient's relay list up again, so such a Welcome still goes out only once a new list reaches the cache
  and the route table, in practice through a new invite to that person. The audit records why no route was found:
  `no_eligible_route` for an empty or unusable list, `route_resolution_failed` for no list known.
- A device linked soon after another no longer shows the account's accepted chats as invitations for up to an hour,
  where a decline turned into a leave on every device (mdk#3556). Each device broadcasts its small state to a newly
  listed device at once, and adds it to a chat only after that chat's invitation decision went out. During a relay
  outage the chat can still show as an invitation until the decision is delivered. The account database advances to
  schema 222.
