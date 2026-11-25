### Changed

- The engine no longer awaits the account signer, which may be a remote NIP-46 signer (mdk#3498). Welcomes and
  recovery control are sealed and unsealed by an `InboxSealer` that `marmot-session` owns: pass one to
  `SessionConfig::new` or `SessionConfig::with_storage` (for Nostr, `NostrInboxSealer::new(signer, clock)`), and
  build `NostrMlsPeeler` without a signer. A new chat whose Welcomes cannot be sealed is still created; maintenance
  seals and sends them later. An invite whose Welcome cannot be sealed is rolled back before anything is sent.
