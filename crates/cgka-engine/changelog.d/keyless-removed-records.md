### Changed

- `SendIntent::RecordRemovedSlot` stages the lone `removed` record with no tag signature key and refuses one that
  keeps a key: its Commit removes no leaf and the roster has no entry, so nothing proves one (marmot#520).
  `SendIntent::ImportDeviceGroupRejections` refuses a carried record that keeps a key. A roster state that records a
  slot as `removed` with no key holds the keys this device keeps for the slot as removed, unless one already is, so
  the app still knows the record was held. Receivers are unchanged.
