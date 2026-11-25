### Changed

- The lone `removed` record a deciding device commits after a failed link's undo, and each `removed` record a device
  group move carries into its destination, keep no tag signature key (marmot#520). Neither Commit proves a key, so
  receivers that check `removed` records would refuse one that kept it. Devices that applied the slot's entry still
  clean up by the key they kept, and the lone record is still made once. Receivers are unchanged.
