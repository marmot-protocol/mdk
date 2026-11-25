### Breaking changes

- `RosterTagKeyStorage` gains `hold_roster_tag_keys_as_removed`, which marks a slot's unexpired keys as held as
  removed, unless one already is, without moving their sighting times or order: the engine calls it for a `removed`
  record that keeps no key (marmot#520). `SendIntent::RecordRemovedSlot` now carries a record with no `tag_signature_key`.
