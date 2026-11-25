### Changed

- `wn messages send-event` accepts kinds 1201 (agent item) and 1202 (answer or control) in the marmot-agents shape,
  and refuses them in any other.
- Timeline JSON gains `agent_item_first_event_missing`, true for an agent item shown from its edits because its
  first event is not on this device.
- WN Agent refuses `send_agent_activity` and `send_agent_operation_event` with `retired_agent_event` and publishes
  nothing: MDK no longer builds the old shape of kinds 1201 and 1202.
- `wn messages timeline list` carries a kind-1201 row's parsed `agent_item` in `--json`, and shows an item MDK cannot
  read, such as the old shape, as `[unreadable agent item]` instead of its payload.
- `wn messages delete` by an admin of their own chat message sends an author kind 5 (empty content), not kind 4891,
  so it syncs as deleted by its author.

### Deprecated

- `wn messages timeline subscribe`, `wn chats subscribe-archived`, `wn groups subscribe-state` and
  `wn notifications subscribe` served the terminal UI. They still work unchanged and will be removed in a future
  release.

### Removed

- The terminal UI is gone: `wn tui` no longer exists. This is a breaking change for anyone who used it; every chat,
  group and message action it offered is a `wn` command. A home the TUI ran in may keep a `tui-media-cache/`
  directory; after an unclean exit it can hold decrypted attachments. Delete it by hand.
- `wn settings theme` is removed. It was meant for the TUI, which never read it. `wn settings show` no longer prints a
  `theme` field, and a `theme` value in an existing `settings.json` is ignored.
