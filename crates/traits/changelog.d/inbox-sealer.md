### Breaking changes

- The account inbox leaves `TransportPeeler` for the new async `InboxSealer` (mdk#3498): `peel_welcome`,
  `wrap_welcome`, `wrap_welcome_with_metadata` and `wrap_group_recovery` are gone, and the remaining group-message
  methods are synchronous. `SendResult`'s and `AutoPublish`'s `welcomes` are unsealed `OutboundWelcome`s; a caller
  seals each and returns it as a `SealedWelcome`. `CgkaEngine::ingest` answers `IngestOutcome::InboxSealed` for a
  Welcome addressed to this client, finished by the new `ingest_unsealed`; `join_welcome` takes the unsealed
  content. `StoredMessagePayload::UnsealedWelcome` (tag 17) holds a Welcome until it is bound or, for a founding
  Welcome, its delivery deadline passes.
  `WelcomeSizeCheck::oversized_welcome` takes `OutboundWelcome`s, and `TransportAdapter::size_class_over_event_len`
  judges an event by its length.
