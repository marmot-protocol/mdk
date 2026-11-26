### Breaking changes

- `MoveRejectedSlot` drops `tag_signature_key`: a move's carried `removed` records go into the destination with no
  key (marmot#520). Facts captured before keep reading; the stored key is ignored.

### Added

- `hold_roster_tag_keys_as_removed` sets `held_as_removed` on a slot's unexpired roster tag keys unless one already
  has it, and leaves `last_seen_at` and `seen_seq` alone (marmot#520).
