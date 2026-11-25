### Breaking changes

- `SqliteAppStorage::recovery_coverage_newest_released` takes the routes to read and returns each one's newest
  released second, from one look at the ledger. Callers that passed a `since` keep only a second at or after it.
- Account migration 0226 rebuilds `local_message_submissions` to admit state 4, a token send refused because the group
  gained a member account its member list leaves out, and indexes refused sends. It fences older binaries, which
  would send a retained member-limited send without its list. Older binaries refuse schema 226; downgrade is
  unsupported. `SqliteAppStorage::refuse_local_submission`, `invalidate_refused_local_sends_for_group` and
  `groups_with_refused_live_local_sends` are new, and retiring a queued application message refused for a new member
  settles its local send in the same transaction.
- Migration 0219 adds `message_timeline.timeline_order_seq`, rebuilds the canonical order index with it before the
  message id, and drops kind-1202 timeline rows. `TimelineMessageRecord` gains `agent_item` and
  `timeline_order_seq`, and `TimelineUpdateTrigger::AgentActivity`/`AgentOperation` become `AgentItem`.
- Account migration 0225 adds `cgka_welcome_delivery_ledger`, one record per outbound Welcome's delivery
  (mdk#1706). Older binaries refuse schema 225; downgrade is unsupported.
- Migration 0221 adds `agent_item_expired_targets`: the retention sweep records each agent item whose row it removed,
  so an edit of it that arrives later does not show it again. A sweep from before the migration is not recorded, so
  on a nightly build's database a late edit of an item removed then can still show it.
- Account migration 0223 adds the invitation standing (`pending_confirmation`, `welcomer_account_id_hex`,
  `via_welcome_message_id_hex`) to `local_group_deletion_frontiers`. Older binaries refuse schema 223; downgrade is
  unsupported.

### Added

- `recovery_unit_debts` reads many units' debts, each with its unit state, and `staged_recovery_first_seconds`
  reads the oldest staged second in many ranges, each under one connection lock.
- `renew_roster_tag_keys` updates `last_seen_at` for a slot's unexpired roster tag keys in one statement and leaves
  `seen_seq` alone (mdk#3679).
- Kind-1009 edits apply to kind-1201 agent items: the highest `v` replaces the row's content and tags, an older
  version is ignored, and the row is not marked edited. Agent items have no edit history.
- A kind-1201 agent item with an `E` tag is placed in that thread, under the parent its `e` names or else the root,
  and `reply_to_message_id_hex` is that parent unless the item names a `started_by`. An edit keeps the thread tags
  of the item's first event, whatever thread tags it carries.
- An agent item whose first event this device does not hold, such as one sent before the member joined, gets a row
  from its edits: the earliest readable edit stands in for the first event, at its place, and the highest version
  shows. `TimelineMessageRecord::agent_item_first_event_missing` says so. The first event, if it arrives, takes the
  row back to its own place. If the id turns out to name an event that is no item, such as another edit, the row
  goes, and the replies quoting it lose the quote in the same change, as `ReplyPreviewChanged`. A nightly build from
  before this change stored such edits without a row: the item shows once another event of it arrives or the chat's
  timeline is rebuilt.
- A history import reports the rows it removed, such as an item whose only edit it deleted, as `Remove` changes, so
  an open timeline drops them.
- An agent's own words in a thread under one of its agent items (a kind 1111 with `E`, `K` 1201 and `P` its sender)
  never count as unread, in the projection, its rebuild and the retention sweep.
- `delete_local_group_data` keeps the deleted row's invitation standing on the group's deletion frontier, and
  `SqliteAppStorage::local_group_deletion_invitation` returns it as `LocalGroupDeletionInvitation` (mdk#3555). A
  frontier written before schema 223, or by a delete that found no row, returns `None`.
- Account migration 0224 adds `evidence_floor_epoch` to `account_recovery_obligations` and
  `SqliteAppStorage::active_epoch_gap_evidence_floor` so active epoch-gap handoffs keep their original arrival-epoch
  floor across multi-step partial advances and restarts while parked gaps retire cleanly (and explicit unparks reset
  the floor to `stalled_epoch`). Older binaries refuse schema 224; downgrade is unsupported.

### Fixed

- A chat's `activity_sort_at` is its latest message, read position or retained floor, and falls back to
  `conversation_created_at` only when it has none. A chat a linked device or a restore stored after it began, with
  older history imported, no longer sorts at the time this device stored it (mdk#3580). Migration 0220 re-sorts the
  rows the old rule anchored at creation.
- Migration 0222 adds `small_state_broadcast_devices`: the roster devices, slot and `linked_at`, that this device's
  last small-state broadcast was made for. `begin_small_state_broadcast` takes them and `SmallStateBroadcast` returns
  them as `devices`, so `SmallStateSchedule` and `SmallStateBroadcast` are no longer `Copy` (mdk#3556).
