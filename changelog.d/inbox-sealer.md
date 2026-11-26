### Changed

- The engine no longer awaits the account signer, which may be a remote NIP-46 signer (mdk#3498). Welcomes and
  recovery control are sealed and unsealed by an `InboxSealer` that `marmot-session` owns: pass one to
  `SessionConfig::new` or `SessionConfig::with_storage` (for Nostr, `NostrInboxSealer::new(signer, clock)`), and
  build `NostrMlsPeeler` without a signer. A new chat whose Welcomes cannot be sealed is still created; maintenance
  retries each Welcome until its deadline, then marks it expired without asking the signer.
  An invite whose Welcome cannot be sealed rolls back before anything is sent. If an invite is dropped during
  sealing or preflight, maintenance rolls it back.
