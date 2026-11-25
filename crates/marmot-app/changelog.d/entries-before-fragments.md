### Breaking changes

- Kinds 1201 and 1202 take the shape of marmot-agents D-076, and the old shape is gone (D-051): an agent item
  (kind 1201) and an answer or a control (kind 1202) are sent with `submit_custom_event` or `send_custom_event`, which
  check their shape and refuse one over `AGENT_EVENT_MAX_BYTES` (64 KiB). MDK names a turn's starting message with a
  `started_by` tag, not `e`. `send_agent_activity`, `send_agent_operation_event`, `AgentOperationEventRequest` and the
  `AppMessageIntent::AgentActivity` and `AgentOperation` variants are removed, and kinds 1201 and 1202 are no longer
  reserved app event kinds.
- `NotificationTrafficClass::AgentActivity` is removed. An agent item notifies on the standard class only while its
  latest version is a waiting approval or question, or a failed turn; other items, every kind 1202 and a chat message
  tagged `["phase", "commentary"]` do not notify. Each alerting version is delivered once, live or after the subscription
  catches up, under the key of the item's first event, so the host replaces the earlier notification; a reaction to an unreadable item previews nothing.
- A message's `NotificationUpdate::notification_key` names its chat (`message:<account>:<group>:<message id>`). Event
  ids carry no chat, so one chat's alert no longer replaces another's for the same id.
- Whether a send wakes the group's members is read from the sent event, so a send resumed after a restart wakes them
  exactly as the first attempt would: a chat message tagged `["phase", "commentary"]`, also as a reply, wakes nobody,
  and an agent item or a new version of one wakes members only while it needs a person or its turn failed.
- `TimelineUpdateTrigger::AgentActivity` becomes `AgentItem`, and `AgentOperation` is removed: a kind 1202 has no
  timeline row.
- `TimelineMessageRecord::canonical_order_key` gains the agent item `seq` before the message id.
- `AppError` gains `IncompatibleKeyPackage(Box<EngineError>)`. When a complete lookup finds only KeyPackages incompatible
  with a new direct chat's founding requirements, the start returns this variant in place of `AppError::Session`.
  Handle it in exhaustive matches. `as_engine_error` still exposes the cause (#3604).

### Added

- `submit_thread_message` and `submit_tagged_sticker` accept a client token and return before relay publication.
- `MarmotAppRuntime::invite_deliveries` and `MarmotAppEvent::InviteDeliveryChanged` (mdk#1706): one `InviteDelivery`
  per group and invited account, rolled up from the session's per-Welcome delivery records. `RelayAccepted` means a
  relay stored the Welcome, not that the recipient received it or joined.
- A later version of an agent item is a kind-1009 edit carrying the whole item with a higher `v`, sent crash-safely
  with `submit_tagged_edit_for_local_send` on the item's token. The row keeps the highest version, ignores an older
  one that arrives late, applies an edit that arrived before its item, and is not marked edited.
- `TimelineMessageRecord::agent_item` holds the parsed latest version of an agent item, and `timeline_order_seq` the
  first event's `seq`, which orders a turn's rows within one second. `AgentItem`, `AgentItemState`, `AgentRequest`
  and the agent kind constants are re-exported.
- Agent items join threads for subagents (marmot-agents D-121): a kind 1201 may carry NIP-22's `E`/`K`/`P` (root)
  and `e`/`k`/`p` (parent), and `submit_custom_event` and `send_custom_event` take its `e` only beside an `E`. An edit
  of an item still carries no `e` but its target's. A thread message answering an item in a thread names that item's
  root and the item as its parent.
- An agent item whose first event this device never gets, such as one sent before the member joined, is shown from
  its edits in its place in the timeline and its thread (marmot-agents D-124), with
  `TimelineMessageRecord::agent_item_first_event_missing` set, and an alerting edit of it alerts.
- The agent's own words in a thread under one of its items, a kind 1111 with an `E` whose `K` is 1201 and whose `P`
  is its author, neither notify nor wake members (D-122), and never count as unread or raise the @-badge. Items in a
  thread keep their own alert rule.

### Changed

- Usage diagnostics count a Welcome naming another KeyPackage of this account (`NotAddressedToThisDevice`) as
  `mdk_welcome_summary` `process` `absent`, no longer `duplicate`: a device that sees only its siblings' Welcomes cannot
  join, and counting them as copies hid it. No outcome value is added, so saved consent stays accepted.
- Relay telemetry adds `app_runtime_member_key_package_read_*` and `app_runtime_member_key_package_relay_read_*`:
  for each member a create, invite or invite recovery selects, whether its KeyPackage read heard every relay it asked,
  and how many of those relays answered. `MemberKeyPackageResolutionStats::key_package_reads` carries the same counts.
  Selection is unchanged.
- Group creation, invites and direct-chat starts always discover the members' current relay routes after
  `prewarm_group_member_key_packages`; prewarmed outboxes only add hints to the KeyPackage read, so a prewarm no longer
  makes them skip discovery. An `IncompatibleKeyPackage` verdict needs that discovery to complete, and a completed read
  that finds no deletion request for the refused KeyPackage or its slot.
- A member lookup that finds no usable KeyPackage reports `DirectoryLookupIncomplete`, not a missing or incompatible
  KeyPackage, while this device's KeyPackage journal keeps a publication of that member that the lookup did not account
  for. The README's direct-chat section states what accounts for one and how long the journal keeps it.
- A member lookup that finds no KeyPackage reports `DirectoryLookupIncomplete`, not a missing KeyPackage, while a relay
  list tied with the member's named a usable outbox that no KeyPackage read covered.
- A member lookup treats a relay that the member's relay lists name twice, or with and without a trailing root slash, as
  one relay: it reads the relay once and counts it once toward a read's limit.

### Fixed

- Removing a linked device that rewrote or cleared its own roster entry's tag signature key removes its device-group
  leaf: removal and chat cleanup also find a committed leaf by a device tag that names the slot and verifies under that
  leaf's own key. A device that moved to another device group keeps its chat leaves whatever keys its slot had, and a
  removed device's leftover chat leaf is still counted past 30 days (mdk#3679).
- An invite's Welcome past its delivery deadline (mdk#3589) is no longer sent by the startup retry and leaves
  `pending_welcome_deliveries`; `invite_deliveries` reads it `Undeliverable`. The startup retry keeps relay backoff.
- A device removed from the account can no longer change its siblings' small state (mdk#3680). It kept its last
  device-group epoch's keys for the app-message window, so until the device group moved five more epochs it could
  still send updates and broadcast requests, and a decline or read position at the highest version could not be
  undone. A device now takes a small-state update or broadcast request only from a leaf whose device tag reads, at
  the message's epoch, as a device its roster lists, and sends its own only once its leaf is tagged: a newly linked
  device's first broadcast waits for its tag commit instead of going out untagged.
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
- A newly linked device no longer waits up to an hour for its siblings' small state, showing a chat the account already
  accepted as an invitation, with an "invited you" notification, when every sibling broadcast within the last hour
  (mdk#3556). A device whose trusted roster lists a device its last broadcast was not made for broadcasts at once, and
  adds that device to a chat only once it has sent the chat's invitation decision. A send that reaches no relay holds
  the Add for a later pass instead of letting the Welcome go first. Invitation decisions now go out before other small
  state, and a winning decision read from an update older than the last broadcast is sent again. While no relay
  acknowledges the decision's page, the Add can still go first and the chat shows as an invitation until the session's
  retry delivers it.
- An admin deleting their own chat message sends an author kind 5, so every client shows it as deleted by its author
  (`DeletionSource::Author`) rather than by an admin. Kind 4891 is for another account's content only.
- A member removed from a chat, or who left it, and then added back gets a kind-1210 "member added" row naming who
  added them, the same row the adder's timeline shows.
- The README now states that chat history imported from another device, and backups, leave out group system rows
  and deleted-message placeholders, and why.
- A locally deleted chat that a newer message brings back keeps the invitation standing it had (mdk#3555): an
  unanswered invitation comes back pending with its inviter, and a sibling Add forwards it as pending, instead of
  showing a chat the user never accepted. A sibling's accept or decline that arrived while the chat was deleted is
  re-applied when it comes back. A chat deleted before this release comes back accepted, as before.
