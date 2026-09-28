# Changelog

## Unreleased

### Changed

- Generated accounts can copy signed kind 10002, kind 10050, and kind 0 records
  to separate public indexers after bootstrap confirmation. Relay-list and
  profile edits also schedule indexer copies after account-relay acknowledgement;
  indexer latency does not delay account readiness or edit returns. Pending
  copies are cancelled on runtime shutdown or account removal.
- Account recovery completes loss of unknown scope on NIP-77 comparison certificates. A
  scope certifies when every required relay finished an untruncated comparison over a
  window that covers the scope's whole goal and every difference was admitted. A queue-loss
  goal starts at the earliest wire `created_at` among the deliveries it lost. A goal with no
  known lower bound never certifies. Cold-start and incremental history compare the
  retained 30-day inventory window. An epoch gap also completes once its group's local
  epoch passes the stalled one. A relay whose compared set fills the request limit counts
  as truncated and cannot certify. (#2068)
- A recovery obligation parks once every route it still cannot certify has been compared
  three times in a row for its goal with its required relays answering, and nothing was
  admitted or certified. It then waits for new evidence or explicit repair. A comparison whose
  required relay failed or timed out does not count; one that answered but could not fetch a
  claimed event, or whose events were not durably admitted, does. New evidence, or durable
  admission on a route, starts that route's count over. (#2068)
- Every automatic recovery cause except maintenance boundaries, explicit repair and
  known-event demand compares off the account worker. The worker then admits what the
  comparison fetched a few events per turn, between commands and live input, and never
  through the live delivery queue. Automatic recovery reuses the live subscriptions
  instead of re-subscribing, so it no longer replays history the account already holds.
  The separate online epoch-gap job is removed. (#2068)
- Account recovery certifies a route on its operated relays only.
  `MarmotAppConfig::recovery_operated_relays` names them and defaults to
  `wss://relay.eu.whitenoise.chat` and `wss://relay.us.whitenoise.chat`. A route that lists
  none of them still certifies on all of the relays recovery can dial; a retired, unsafe or
  over-cap relay is never required. The route's other relays are still
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
- A live delivery now promotes the persisted transport cursor with its own checkpoint, once
  every account subscription has replayed its stored history and no loss is pending. Only a
  drain checkpoint or settled loss used to, so a restart re-downloaded everything the
  account had received live since its last drain: on the #2069 scorecard, a full pass of the
  account's history on each relay. No checkpoint passes a queued delivery that a restart
  would then no longer fetch. A delivery goes to the durable spill instead of the queue when
  it arrives while a checkpoint saves and falls below the floor that checkpoint commits, or
  when only a live promotion put it below the floor. It becomes queue loss bounded by its
  `created_at` when the spill cannot take it; `account_delivery_spilled` counts it. (#2069)

### Fixed

- Account setup readiness, setup resume and onboarding reads no longer fail with a JSON
  parse error (`expected value at line 1 column 1`) when they race a setup-phase or
  onboarding-checkpoint update. Each atomic replacement of those owner-only files used to
  zero the previous file afterwards, so a reader that had already opened it could read
  zeros. Only local signing-key files are still zeroed, and their reader now re-reads
  instead of parsing a replaced key file.

- Keep conversation-window commands usable across content-only replacements
  and report a stale window when an older visible-anchor quote names a row
  dropped by a background replacement. (#2052)

- Keep an account's delivery route open when its relay notification consumer lags. A lag
  used to close the route and send the account worker through reconnect. The reopened
  session replayed the backlog from the loss-fenced cursor, which overflowed again, so large
  accounts looped in reconnect backoff and commands failed with `transport_closed`. The
  consumer now resumes on the same receiver and the worker keeps serving commands. It
  records the loss durably, bounded below by the lowest `since` among every REQ the
  account's SDK context issued, live or closed, or unbounded when any of them had no
  `since`, and recovers it by comparison. `RelayPlaneHealth` still counts each lag in
  `notification_forwarder_lag_incidents`, `notification_forwarder_lagged_notifications`
  and `notification_forwarder_restarts`. Only an unexpected consumer exit
  (`notification_forwarder_unexpected_exits`) still closes delivery and reconnects. (#2070)

- Hand a pending loss signal to an account's next delivery route when the worker drops its
  queue with the control record still in it. The record died with the queue, but the plane
  still counted it as queued, so the loss generation could never clear and the transport
  cursor stayed fenced for the rest of the process. (#2070)

- Publish and rotate KeyPackages without a full-history resubscription. Both used to
  activate transport with no `since`, which replayed every held event on every inbox and
  group route and left a notification lag during that replay unbounded. They now reuse the
  live activation or rebuild it from the transport cursor, like reconnect. (#2070)

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
- `MarmotAppEvent` gains `HistoryNoticesChanged { account_id_hex, account_label }`, and
  `GroupRecoveryStatus` gains `history_may_be_incomplete` and `history_notice_ids` (both
  serde-defaulted). Exhaustive Rust matches and struct literals must handle them. (#2068)

### Added

- Route reviewed host stages through the existing runtime telemetry registry,
  including its fixed metric names and all five outcomes in snapshots and OTLP.
- Surface parked recovery as "history may be incomplete". `MarmotAppRuntime::history_notices`
  lists each parked occurrence as a `HistoryNotice` (opaque `notice_id`, `HistoryNoticeCause`,
  optional group, parking time); a group's own occurrences also appear in
  `GroupRecoveryStatus`. `dismiss_history_notice` runs on the account worker and durably retires
  exactly that occurrence as its own outcome, never as coverage, returning false for a stale id.
  Retiring the last pending loss obligation releases the transport-cursor fence without recording
  a recovery success, and a late observation of retired loss releases it too instead of
  re-raising it. A dismissed incremental-history notice stays dismissed: later startups still
  compare, but parking again on the same routes and required relays raises no new notice.
  `HistoryNoticesChanged` announces parking, un-parking and dismissal; a group whose own notices
  changed also gets `GroupStateUpdated`. (#2068)

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
