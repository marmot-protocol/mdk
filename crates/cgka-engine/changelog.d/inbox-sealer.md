### Breaking changes

- The engine no longer seals or unseals the account inbox (mdk#3498). Sends and creates return unsealed
  `OutboundWelcome`s; bind the sealed messages with `Engine::bind_sealed_welcomes`, together with the commit's first
  fanout write when it has one. `ingest` stops at `IngestOutcome::InboxSealed` for a Welcome addressed to this
  client; pass the unseal result to `ingest_unsealed`. To keep wire provenance across unsealing, use
  `Engine::begin_ingest_with_audit_context` and pass its continuation to `ingest_unsealed_with_audit_context`.
  `confirm_group_rejoin` takes the unsealed offer. Read it with `stored_welcome`, which takes the confirmation's
  `local_state_token` and refuses a stale one before anything is unsealed.
  `Engine::rejoin_retry` yields one eligible stored offer at a time. Unseal each offer and apply its result before
  asking for the next one.
  `Engine::transport_peeler` is removed.

### Added

- `Engine::unsealed_owed_welcomes` lists founding Welcomes a create left unsealed, for maintenance to seal (mdk#3498).
