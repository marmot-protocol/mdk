### Changed

- Linking a device now records the new device's signature key in its device-group roster entry in the Commit that adds
  it, instead of leaving the new device to write it later (marmot#521, mdk#3679). A key in an entry no longer means the
  link is made: a link counts as made once the new device's own first Commit in the device group lands. Until then the
  new device tags nothing outside the device group, and its first Commit there is a roster update writing its history
  key, or a self-update when the entry needs no change. A device refuses a device-group Welcome whose roster binds its
  entry to another key or another slot; a keyless entry from an approver that has not updated still joins. Removal,
  inactivity, sign-out, sibling chat gaps and the private KeyPackage hand-off read "made" the same way, and same-account
  sibling Adds are refused with the new `SiblingAddRefusal::LinkPending` until the sibling's link is made. Receivers
  do not enforce the new roster rules yet.
