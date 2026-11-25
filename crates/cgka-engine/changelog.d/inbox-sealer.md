### Breaking changes

- The engine no longer seals or unseals the account inbox (mdk#3498). Sends and creates return unsealed
  `OutboundWelcome`s; bind the sealed messages with `Engine::bind_sealed_welcomes`, together with the commit's first
  fanout write when it has one. `ingest` stops at `IngestOutcome::InboxSealed` for a Welcome addressed to this
  client; pass the unseal result to `ingest_unsealed` (or `ingest_unsealed_with_audit_context`).
  `confirm_group_rejoin` takes the unsealed offer. Read it with `stored_welcome`, which takes the confirmation's
  `local_state_token` and refuses a stale one before anything is unsealed.
  `retry_rejoins_after_trusted_removal` takes the unsealed `rejoin_candidates_after_trusted_removal`.
  `Engine::transport_peeler` is removed.

### Added

- `Engine::unsealed_owed_welcomes` lists founding Welcomes a create left unsealed, for maintenance to seal (mdk#3498).
