### Breaking changes

- `MarmotLocalSendStatus::state` gains `4`: refused because the group gained a member account the send leaves out.
  The struct gains a nullable `message_id_hex` after `summary`, the send's event while MDK holds it (states 0 and 1).
  Rebuild clients with the matching header and library.
- `MarmotTimelineMessageRecord` gains a nullable `agent_item: MarmotAgentItem *` after `group_system`, and
  `agent_item_first_event_missing: bool` after it: true for an agent item whose first event this device does not
  hold, such as one that began before the member joined.
  `MarmotTimelineUpdateTrigger`'s `AgentActivity` becomes `AgentItem` and `AgentOperation` is removed, which
  renumbers the later variants; `MarmotNotificationTrafficClass` loses `AgentActivity`. Rebuild clients with the
  matching header and library.

### Added

- `MarmotAgentItem` and `MarmotAgentItemState`: the latest version of a kind-1201 agent item on its timeline row.
- `marmot_invite_deliveries` and `marmot_invite_delivery_list_free`, the `MarmotInviteDelivery` records with a
  flattened `MarmotInviteDeliveryState`, and the `MARMOT_EVENT_INVITE_DELIVERY_CHANGED` event variant (mdk#1706).
  `MarmotEvent` gains a variant: rebuild against the matching header and library.
- `marmot_send_custom_event_with_client_token`: durable token admission of a custom application event, such as an
  answer or a control for an agent (kind 1202).
- `marmot_submit_tagged_text`, `marmot_submit_tagged_reply`, `marmot_submit_thread_message`, and
  `marmot_submit_tagged_sticker` return durable local acceptance before relay publication.
- `MARMOT_STATUS_INCOMPATIBLE_KEY_PACKAGE` identifies incompatible recipient chat keys that previously returned the generic runtime status.

### Changed

- A member's `MARMOT_MEMBER_RESOLUTION_STATUS_INCOMPATIBLE_KEY_PACKAGE` now requires completed relay-list discovery,
  complete KeyPackage reads and a completed read that finds no deletion request for the refused KeyPackage or its
  slot. If any is incomplete, the status is `MARMOT_MEMBER_RESOLUTION_STATUS_INCOMPLETE`.
- A member with no usable KeyPackage is `MARMOT_MEMBER_RESOLUTION_STATUS_INCOMPLETE`, not missing or incompatible, while
  this device's KeyPackage journal keeps a publication of theirs that the lookup did not account for. The shared API
  guidance for `marmot_start_direct_chat_with_options` states what accounts for one and how long the journal keeps
  it.
- A member with no KeyPackage is `MARMOT_MEMBER_RESOLUTION_STATUS_INCOMPLETE`, not missing, while a relay list tied with
  theirs named a usable outbox that no KeyPackage read covered.
- A member lookup treats a relay that the member's relay lists name twice, or with and without a trailing root slash, as
  one relay: it reads the relay once and counts it once toward a read's limit.
- Group creation, invites and direct-chat starts always discover the members' current relay routes after
  `marmot_prewarm_group_member_key_packages`; prewarmed outboxes only add hints to the KeyPackage read, so a prewarm
  no longer makes them skip discovery.

### Fixed

- `marmot_invite_deliveries` now reports `MARMOT_INVITE_DELIVERY_STATE_KIND_UNDELIVERABLE` for an invite's Welcome
  that no relay stored by its delivery deadline, 7 days after the invite or its KeyPackage's expiry if sooner
  (mdk#3589); that Welcome is never sent again and leaves `marmot_pending_welcome_deliveries`.
