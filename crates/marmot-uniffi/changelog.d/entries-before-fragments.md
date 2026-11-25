### Breaking changes

- `LocalSendStatusFfi` gains `RefusedNewMembers`, for a send limited to member accounts that the group gained a member
  it leaves out. `Queued` and `EngineOwned` carry the send's `message_id_hex`.
- Swift: cancelling a `Task` that awaits a throwing async call, a command or a receive, now cancels its native future
  and throws `CancellationError` (mdk#3670). Before, the call ran to completion and returned its result. A call that
  completed first still returns its result, and calls whose work must finish, such as `shutdownAndClose()`,
  `removeAccount()`, `signOut()`, `signOutAndWipe()` and the `login*` calls, still wait. The four projection `nextCancellable()` adapters now report a native error that
  completed before the cancel instead of `CancellationError`.
- `TimelineUpdateTriggerFfi::AgentActivity` becomes `AgentItem` and `AgentOperation` is removed;
  `NotificationTrafficClassFfi::AgentActivity` is removed. An agent item notifies as `Standard` only while it is a
  waiting approval or question, or a failed turn.

- `MarmotKitError` gains `IncompatibleKeyPackage`. Update exhaustive Swift `switch` and Kotlin `when` expressions to
  handle it, and regenerate bindings with the matching native library. For this error, ask the recipient to update
  their client and publish a compatible KeyPackage (#3604).

### Added

- Swift `nextCancellable()` / `nextUpdateCancellable()` adapters for the receives generated without `throws`:
  backup restore, chat list, chats, events, group state, messages, notifications, onboarding, timeline messages and
  user search subscriptions (mdk#3670).
- `TimelineMessageRecordFfi::agent_item_first_event_missing`: true for an agent item whose first event this device
  does not hold, such as one that began before the member joined; the row is built from its edits.
- `TimelineMessageRecordFfi::agent_item` (`AgentItemFfi`, `AgentItemStateFfi`): the latest version of a kind-1201
  agent item, with its type, fields JSON, `settles` and whether it alerts. A kind-1201 row without one is an
  unreadable item, such as the old shape.
- `Marmot::invite_deliveries(account_ref, group_id_hex)` and the `InviteDeliveryChanged` event (mdk#1706), with
  `InviteDeliveryFfi`, `InviteDeviceDeliveryFfi`, `InviteRelayCountsFfi`, `InviteDeliveryStateFfi`,
  `InviteDeliveryProblemFfi` and `InviteCancelReasonFfi`. `Undeliverable`, `TooLarge` and `KeyPackageRetired` are
  not produced for ordinary invites yet. Only invites sent after the upgrade are listed; an older Welcome stays in
  `pending_welcome_deliveries` and `WelcomeDeliveryPending`, which are unchanged.
- `send_custom_event_with_client_token`: durable token admission of an app-defined event, such as an answer or a
  control for an agent (kind 1202), so a retry after a restart does not send it twice.
- `submit_tagged_text`, `submit_tagged_reply`, `submit_thread_message`, and `submit_tagged_sticker` return durable
  local acceptance before relay publication.

### Changed

- A member's `MemberResolutionStatusFfi::IncompatibleKeyPackage` now requires completed relay-list discovery,
  complete KeyPackage reads and a completed read that finds no deletion request for the refused KeyPackage or its
  slot. If any is incomplete, the status is `MemberResolutionStatusFfi::Incomplete`.
- A member with no usable KeyPackage is `MemberResolutionStatusFfi::Incomplete`, not missing or incompatible, while
  this device's KeyPackage journal keeps a publication of theirs that the lookup did not account for. The API
  reference for `start_direct_conversation_with_options` states what accounts for one and how long the journal keeps
  it.
- A member with no KeyPackage is `MemberResolutionStatusFfi::Incomplete`, not missing, while a relay list tied with
  theirs named a usable outbox that no KeyPackage read covered.
- A member lookup treats a relay that the member's relay lists name twice, or with and without a trailing root slash, as
  one relay: it reads the relay once and counts it once toward a read's limit.
- Group creation, invites and direct-chat starts always discover the members' current relay routes after
  `prewarm_group_member_key_packages`; prewarmed outboxes only add hints to the KeyPackage read, so a prewarm no longer
  makes them skip discovery.

### Fixed

- An invite's Welcome that no inbox relay stores is no longer retried forever (mdk#3589). It is sent until its delivery
  deadline, 7 days after the invite or its KeyPackage's expiry if sooner, then reads `Undeliverable` in
  `invite_deliveries` with its latest attempt's problem, and leaves `pending_welcome_deliveries`. A Welcome owed from
  before this upgrade is held to 7 days from its gift wrap's timestamp. The startup retry now keeps each relay's
  backoff. The invitee stays a member.
- `sign_out`, `sign_in_account`, `remove_account`, `login`, `login_external_signer`,
  `login_recovering_incomplete_setup`, `set_audit_log_settings` and `nip46_remove` keep running when their call is
  cancelled, on Kotlin and Swift (mdk#3670). A cancel between their steps could leave a withdrawn KeyPackage slot on
  a signed-in account, a paused setup that sign-in never resumed, an account whose moderation reports were already
  purged, a half-imported account that a retry rejects as existing, a worker still using a removed signer, or running
  sessions that disagree with the stored audit-log switch. Running sessions now apply the stored audit-log switch, so
  overlapping `set_audit_log_settings` calls end with the last stored value.
- An admin's own message deletion now reports `deletionSource: Author`, and a member added back to a chat after being
  removed or leaving gets a "member added" `groupSystem` row naming who added them.
