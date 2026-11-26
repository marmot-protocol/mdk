### Changed

- Every device-group Commit is now held to the roster's key-binding rules (marmot#521, mdk#3679), whoever sends it:
  each added device gets a new entry, in that Commit, with its leaf's signature key; an entry's key never changes;
  a device's entry is removed only together with its leaf; a `removed` record keeps only the key its entry had; and no
  leaf changes its signature key. A Commit or proposal that breaks one is refused. Only new Commits are checked, so
  existing device groups keep working. One known interim gap: a late Commit that makes a device replay its last few
  device-group Commits re-checks them, so a link made before upgrading, by an Add that set no key, can lose to a rival
  branch while it is still among the last five Commits; that device then relinks. A device-group Welcome must record the joining device's key in its entry, and
  a device never writes its own key after its Add.
- Removing a linked device finds its device-group leaf by the key its entry carries and removes it with the entry.
  Removing the device that founded the device group now takes its leaf too, though OpenMLS built that leaf from a
  KeyPackage: the engine counts a founder's link as made.
  The fallback that also searched for a leaf tagged with a self-signed device tag is gone, from both removal and the
  cleanup of chat leaves (`Engine::own_account_self_signed_tags` is removed).
