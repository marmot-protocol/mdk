### Breaking changes

- `RosterTagKeyStorage` gains `renew_roster_tag_keys`, which moves the sighting time of a slot's unexpired keys in one
  step and keeps their order (mdk#3679).
- `MARMOT_APP_EVENT_KIND_AGENT_ACTIVITY` and `MARMOT_APP_EVENT_KIND_AGENT_OPERATION` become
  `MARMOT_APP_EVENT_KIND_AGENT_ITEM` and `MARMOT_APP_EVENT_KIND_AGENT_REQUEST`, and the old shape's tag constants
  (`AGENT_ACTIVITY_STATUS_TAG`, `AGENT_OPERATION_*_TAG`) are removed.

### Added

- `agent_events`: the tags of kinds 1201 and 1202 (marmot-agents D-076), `AGENT_EVENT_MAX_BYTES`, and the parsers
  `AgentItem::from_tags` and `AgentRequest::from_tags` with the alert rule `AgentItem::alerts`.
  An item's `v` and `seq` are at most `i64::MAX`.
- `maintenance::WelcomeDeliveryRecord` and its `WelcomeDeliveryState`, `WelcomeDeliveryProblem`,
  `WelcomeCancelReason` and `WelcomeRelayCounts` (mdk#1706): the sender's durable record of one outbound Welcome's
  delivery.
- An agent item in a subagent's thread carries NIP-22's tags (marmot-agents D-121): `validate_agent_item_tags` takes
  one `e` beside an `E`, and `validate_agent_item_edit_tags` checks the item an edit carries, which has no `e`.
  `agent_item_thread_parent`, `agent_item_reply_target` and `is_agent_own_thread_comment` (D-122) read them.
