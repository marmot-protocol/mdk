### Changed

- The engine no longer awaits the account signer, which may be a remote NIP-46 signer (mdk#3498). Welcomes and
  recovery control are sealed and unsealed by an `InboxSealer` that `marmot-session` owns: pass one to
  `SessionConfig::new` or `SessionConfig::with_storage` (for Nostr, `NostrInboxSealer::new(signer, clock)`), and
  build `NostrMlsPeeler` without a signer. A new chat whose Welcomes cannot be sealed is still created; maintenance
  delivers already sealed Welcomes before trying the signer for unsealed ones. It marks an unsealed Welcome expired
  at its deadline without asking the signer. Prepared invites and recovery Adds bind their sealed Welcome rows
  with the first commit fanout. If an invite is dropped during sealing or preflight, maintenance attempts to roll
  it back and retries a failed rollback.
