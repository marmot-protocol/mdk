# Changelog

## Unreleased

### Changed

- Generated accounts can copy signed kind 10002, kind 10050, and kind 0 records
  to separate public indexers after bootstrap confirmation. Relay-list and
  profile edits also schedule indexer copies after account-relay acknowledgement;
  indexer latency does not delay account readiness or edit returns. Pending
  copies are cancelled on runtime shutdown or account removal.
- Account recovery certifies a route on its operated relays only.
  `MarmotAppConfig::recovery_operated_relays` names them and defaults to
  `wss://relay.eu.whitenoise.chat` and `wss://relay.us.whitenoise.chat`. A route that lists
  none of them still certifies on all of its relays. The route's other relays are still
  compared and their events admitted, but their failures never withhold completion or
  schedule a retry. Changing the operated set rebuilds pending recovery scopes. (#2068)

- A full account delivery queue now spills deliveries into the account database instead of
  dropping them. The worker admits spilled deliveries through the ordinary ingest path,
  alternating them with live ones, and removes each row once ingest has seen it. Deliveries
  the account had already seen are not stored. A delivery still becomes queue loss when the
  router's hand-off is full (4,096 deliveries or 4 MiB), when it would exceed the durable
  spill limits (8,192 rows or 16 MiB per account), when its spill write keeps failing, when
  its row cannot be decoded, or when it is still unadmitted after 8 retries.
  `RelayPlaneHealth` reports `account_delivery_spilled` and
  `account_delivery_spill_already_seen`. (#1947)

### Fixed

- Account setup readiness, setup resume and onboarding reads no longer fail with a JSON
  parse error (`expected value at line 1 column 1`) when they race a setup-phase or
  onboarding-checkpoint update. Each atomic replacement of those owner-only files used to
  zero the previous file afterwards, so a reader that had already opened it could read
  zeros. Only local signing-key files are still zeroed, and their reader now re-reads
  instead of parsing a replaced key file.

- Preserve normalized line breaks in ingested kind:0 `about` text while still removing
  unsafe controls from every known profile string. Previously flattened cached bios stay
  until a newer event replaces them. (#1973)

- Count account-scoped relay publishes on the shared device-wide publish counters.
  `relay_publish_attempts` was previously always zero in production. Success now
  requires the acknowledgement threshold, and publishes dropped in flight (such as
  endpoints abandoned after quorum) count under the new `publish_cancellations` /
  `relay_publish_cancellations` series rather than as failures. (#1950)
- Judge epoch-backfill overflow retry backoff by the durable delay. A loaded runner
  can spend more than a second after that reservation is written, which previously
  failed a test that still required nearly the full cooldown to be remaining.

### Changed

- Restrict the account-local overflow marker writer to durable loss evidence. The account
  mutation path imports that evidence into recovery demand; runtime dispatch consolidation
  remains separate integration work. (#1946)

### Breaking changes

- Remove `RecoveryExecutorMode` and `MarmotAppConfig::recovery_executor_mode`. The
  conservative mode ran one recovery obligation per grant as a same-schema rollback
  switch. The bindings and CLI never exposed it, and recovery now has one execution
  path. Rust callers that set the field should delete it. (#2068)
- `HostPerformanceOperation` and `RuntimePerformanceOperation` gain 28 shared and
  nine Linux-specific host stages. Downstream exhaustive Rust matches must handle
  the new variants. The snapshot struct layout is unchanged; stages appear in
  `runtime_operations`.

### Added

- Route reviewed host stages through the existing runtime telemetry registry,
  including its fixed metric names and all five outcomes in snapshots and OTLP.

## 0.10.4 - 2026-09-20

### Fixed

- Keep pure explicit downloads outside automatic budgets and defer transient disk pressure before the verified-body receipt. ([#1939](https://github.com/marmot-protocol/mdk/pull/1939))

- Preserve verified publication across network revocation, refund interrupted acquisition claims, park denied demand without polling, and avoid permission locks around network polling. Native retries remain unchanged. ([#1939](https://github.com/marmot-protocol/mdk/pull/1939))

- Make locally accepted pending rows visible to conversation-window navigation before relay publication completes and
  avoid unused attachment plaintext hydration during draft saves. ([#1943](https://github.com/marmot-protocol/mdk/pull/1943))

- Apply execution-based exponential backoff to repeated epoch-backfill overflow failures. ([#1949](https://github.com/marmot-protocol/mdk/pull/1949))

### Breaking changes

- `MarmotAppConfig` adds `attachment_acquisition_mode`; full struct literals must set it or use `Default`. Handle the new terminal `AttachmentTransferState` and configuration/account `AppError` variants in exhaustive matches. `AttachmentTransferStatus` carries source MIME metadata for automatic policy observation. ([#1939](https://github.com/marmot-protocol/mdk/pull/1939))

### Added

- Add host-managed automatic attachment demand with denied startup and generation-fenced per-account media permission. Bound network retries and stop automatic reacquisition after retention failure. ([#1939](https://github.com/marmot-protocol/mdk/pull/1939))

- Add durable token-correlated local send admission and restart recovery without changing existing send-method
  completion semantics. ([#1943](https://github.com/marmot-protocol/mdk/pull/1943))
