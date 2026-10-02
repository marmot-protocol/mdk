# Changelog

## Unreleased

### Added

- Hosts can declare a separate kind-10050 inbox relay list.
  `AccountSetupRequest::inbox_relays`, `AccountRelayListBootstrap::inbox_relays`
  (`with_inbox_relays`) and `OnboardingOptions::inbox_relays` set it for
  generated-account bootstrap, missing-list publication on import or login,
  and onboarding's recommended inbox relays. Empty keeps the previous
  behavior: `default_relays` declare both the NIP-65 and the inbox list.
  Persisted setup contexts and onboarding checkpoints without the field resume
  unchanged.
- `MarmotAppRuntime::poll_votes` pages each voter's effective poll selection
  (`PollVotePage` of `PollVote`) with the same rules as the timeline poll
  tally. (#2091)
- `MarmotAppRuntime::send_tagged_text`, `send_tagged_media`, and
  `react_with_media` add application tags (for example NIP-30 `emoji`) to a
  kind-9 chat, a media chat, or a kind-7 reaction; the reaction emits its
  attachments as `imeta`. `MediaUploadRequest::message_tags` does the same for
  a sent upload. Tags are capped at 64 rows and 16 KiB of values, and `imeta`
  rows are rejected.
- `ConversationReaction::reaction_message_id_hex` names the earliest active
  kind-7 carrying that emoji, so a NIP-30 reaction's image can be resolved.
- Account-worker startup is observable stage by stage. Six runtime
  operations, `account_startup_spawned`, `_open_queued`, `_account_state`,
  `_session_open`, `_client_restore` and `_ready_handoff`, record one span
  per stage a starting worker enters. A span stays in flight while the stage
  runs, even after its worker was aborted, and ends as a timeout if the
  ready-wait expired in that stage. An expired ready-wait now fails with
  `account worker startup timed out at <stage>`; hosts that matched the old
  message exactly should match its prefix. (#1911, #2098)

### Fixed

- v5 audit rows keep the engine's `pre_membership_event`,
  `app_payload_retention_expired`, `peel_failed_no_snapshot` and
  `quarantined_group_input_deferred` message reasons instead of writing them
  as `unclassified`. Older v5 rows with an `unclassified` reason stay
  ambiguous (#2120).
- Import and external-signer onboarding now searches the built-in public
  indexers alongside the host's discovery relays when checking an identity's
  profile, follows, and kind-10002/10050 relay lists. Previously a host that
  passed only its own messaging relays could see an existing identity's lists
  as missing and be offered (or automatically approve) a defaults-only
  replacement. A missing list is now concluded, and a repair approved, only
  when every searched relay, indexers included, answers. Indexers are dialed
  on top of the 16-relay inspection cap, so they neither displace the host's
  or the account's declared relays nor get dropped themselves. Repairs still
  publish only to the host's discovery relays and the account's declared
  relays, not to the indexers. A host-selected set from
  `set_onboarding_discovery_relays` is used as given, without indexers, so an
  unreachable indexer can be bypassed. Loopback (development) routes are
  unchanged, and the KeyPackage device check keeps its existing sources.
- A route change, such as creating or leaving a group, no longer resets
  history recovery for every route. Routes whose own window and required
  relays are unchanged keep their certificates and quiet streak; only changed
  and new routes are compared again. Before, each new DM restarted recovery
  over every route, so on accounts with many chats it rarely finished
  (#2110).
- History recovery no longer retries forever when a required relay never
  answers while another required relay answers. After six such comparisons
  for an unchanged goal and required relays, the route counts toward parking
  with the existing "history may be incomplete" notice. Offline passes and
  routes skipped or timed out by the local deadline spend no parking budget
  (#2110).
- Creating a group no longer rebuilds the whole routing table. It installs only
  the invitees' inbox routes, which the Welcome publish needs; `add_group`
  already installs the new group's routes. The rebuild took about 13 ms per
  create at 1000 chats, most of it a quadratic pass over deleted-group routes
  (#2110).
- Host catch-up (`catch_up_accounts`) and the catch-up after creating or
  changing a group no longer run a recovery job while holding the account
  worker. They drain live input and return; the worker's paced recovery job
  serves any history debt. Sends, conversation opens and new DMs no longer
  wait behind recovery, which grew with the number of chats (#2110). New
  `just bench-create-direct-message` measures DM creation latency with 300
  and 1000 existing chats.
- The post-join maintenance sweep no longer decodes every transport fanout
  once per group, which made it quadratic in the number of chats.
- Messages are no longer withdrawn as undecryptable by a convergence pass that selected
  no branch, such as the pass that settles the device's own disband. That pass never tried
  them against the group's state; they now wait for a pass that selects a branch, or for
  the engine to try them against its live state.
- A recovery comparison no longer fails when a group route, window or relay changes after
  the comparison was requested, for example when a Welcome is admitted during startup.
  Such a grant used to fail on every attempt until the next request. Each pass now compares
  the recorded incremental-history debt rather than the live routing snapshot, so it
  queries exactly the relays its settlement certifies. (#2100)

## 0.11.0 - 2026-09-29

### Changed

- A recovery scope whose route no comparison backend could compare is no longer counted as
  a quiet pass. No relay answered it, so it spends none of the three-pass parking budget and
  is recorded as unserved; incremental history still waits for a capability change.

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
- Recovery compares off the account worker. The worker then admits what the
  comparison fetched a few events per turn, between commands and live input, and never
  through the live delivery queue. Recovery reuses the live subscriptions instead of
  re-subscribing, so it no longer replays history the account already holds. The separate
  online epoch-gap job is removed. (#2068)
- The inline recovery executor is gone; every cause and caller runs the one comparison
  job. A post-join maintenance boundary installs only its own REQ and completes on that
  REQ's end of stored events. Known-event demand and routes with more than four relays are
  compared off the worker too. Explicit catch-up, `sync()` and a directly owned client's
  `next_event()` drain the live queue, then run one job in place, and no longer re-activate
  transport or re-issue live REQs once the session is active; a route change still
  refreshes them. `repair_full_history` compares every route over the retained-inventory
  window in one pass inside its 60-second budget and installs no unfloored replay, so it
  no longer fetches history older than the retained window. Full history has no lower
  bound, so the repair never reports complete. When every route's window certified it
  returns `BelowRetentionWindow` and closes its request. The owner's automatic passes over
  a pending explicit request keep each route's certified window, off the parking streak,
  and close it once every route is certified: no explicit-history debt is left
  to park into a "history may be incomplete" notice, and nothing is recorded as coverage.
  Otherwise it returns `CoverageUnproven`, `Cancelled` or `Deadline`, and the debt stays
  open for the owner's ordinary retries. The comparison gets the first 50 seconds; routes
  that finished by then are admitted in the last 10, stopping at a turn boundary if the
  budget runs out; that budget starts once the repair holds its process credit. A certified
  window wins over the clock: `Deadline` means admission ran out, or the cutoff cut a
  route and left the window uncertified. Only cancellation discards what a pass already
  fetched.
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
  every account subscription has replayed its stored history and no loss is pending. An
  account that has never persisted a cursor waits for its first drain checkpoint. Only a
  drain checkpoint or settled loss used to, so a restart re-downloaded everything the
  account had received live since its last drain: on the #2069 scorecard, a full pass of the
  account's history on each relay. No checkpoint passes a delivery that a restart would then
  no longer fetch while it is queued, or taken and not yet ingested durably. That includes
  the checkpoint a catch-up drain or startup receive runs when an older delivery fails to
  ingest after newest-first replay remembered a newer cursor, which used to persist a cursor
  a restart no longer fetched the failed delivery from. A delivery goes to the durable spill
  instead of the queue when it arrives while a checkpoint saves and falls below the floor
  that checkpoint commits, or when only a live promotion put it below the floor. It becomes
  queue loss bounded by its `created_at` when the spill cannot take it;
  `account_delivery_spilled` counts it. (#2069)

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

- Keep chat-list-window commands usable across content-only replacements, so
  paging no longer livelocks on `StaleWindow` while other chats' previews,
  badges or order keep changing. An older visible-anchor quote naming a row a
  background replacement dropped reports a stale window.

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

- Floor the post-join maintenance REQ and retained-route REQs, so a notification lag while
  one is live charges a bounded loss. The maintenance REQ used to request the group's full
  history, and a retained route was backfilled in full on every activation. Either made
  the loss unbounded, which parks as "history may be incomplete" and keeps the transport
  cursor fenced. Maintenance is now floored at the creation of the Welcome that installed
  the copy, never the local join, so a member that was offline still sees the commits
  made between that Welcome and its join. A retained route is floored at the moment the
  device saw it replaced, and from no later than the account cursor. A retained route
  stored before this release has no such moment, so the first account load after the
  upgrade records one and keeps it: earlier sessions fetched its older traffic, and the
  comparison covers the rest. Both floors sit fifteen minutes below their anchor
  (`HISTORY_FLOOR_CLOCK_SKEW_ALLOWANCE`) to absorb clock skew. The routing table now keeps
  each group's current route first. It used to sort a group's routes by id after a route
  change, so the adapter could resume a retained route from the cursor and backfill the
  current one in full. A locally deleted group no longer lists its current route twice.
  A hidden group's route replaced while it was hidden keeps a full backfill until the
  group is restored. (#2070)
- Recover end-of-stored-events (EOSE) that a relay notification lag lost. A lost EOSE left
  its subscription's replay coverage incomplete for good: the next activation
  re-subscribed instead of reusing the live one, live cursor promotion stayed off, quiet
  drains waited out their full first wait, and post-join maintenance did not observe its
  boundary. A lag still marks no EOSE complete,
  since it cannot tell a lost one from one still coming. Once the receiver has gone 30
  seconds without another lag, each REQ issued before the lag that has not reported EOSE on
  a relay is repaired there. When the SDK recorded that relay's EOSE, the lag lost only the
  notification, and the EOSE is recorded with no network traffic. Otherwise the REQ's CLOSE
  and the REQ again, unchanged and under its own id, are queued together or not at all, and
  the relay replays from the same `since` before a fresh EOSE; the relay never sees a
  repeated live id, and the SDK keeps the REQ it restores on reconnect. A relay whose
  re-issue went out is not re-issued again, but later repairs still read the SDK's record,
  so a fresh EOSE that a later lag lost still completes; one that got nothing is repaired
  again after the settle window. The notification-loss floor does not move. `NostrRelayClient` gains
  `reissue_subscription` and `subscription_eose_received`, unsupported by default, and `NostrTransportAdapter` gains
  `reissue_subscriptions_awaiting_eose`. The `nostr-sdk` fork pin moves to
  `a9c7a6423d104c603de6ea8244265ea17f0f9d89` for `Relay::batch_msg` and
  `Relay::subscription_received_eose`. (#2070)

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

- `FullHistoryRepairIncompleteReason` gains `BelowRetentionWindow`
  (`full_history_below_retention_window`): an explicit repair certified every route's
  retained window, but history below that window was never searched, and the request
  closed without leaving debt or a notice. Exhaustive Rust
  matches must handle it; bindings see only the existing error code.
- Remove `MarmotAppConfig::dev_epoch_backfill_eose_wait_ms` and
  `dev_epoch_backfill_execution_quantum_ms` with their `with_*` builders. Recovery no
  longer drains toward an end-of-stored-events budget, so neither had an effect. The
  bindings and CLI never exposed them.
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
- `AppPriorNostrRoute` gains `replaced_at` (serde-defaulted), when the device saw the route
  replaced as its group's current route. Struct literals must set it. (#2070)

### Added

- Record account recovery in the opt-in v5 audit log. The recovery owner writes
  `recovery_need_changed` when loss or demand is charged to an obligation (with its cause,
  goal bound and newly charged count), when a parked obligation's notice is shown or
  dismissed, and when a parked obligation closes; `recovery_attempt_started` and
  `recovery_attempt_finished` for every reserved attempt (obligations, endpoints, budgets,
  compared and certified routes, events retrieved, duplicate, rejected, retained and
  refused, relay counts, and a `progressed` / `quiet` / `unserved` / `deadline` /
  `cancelled` / `superseded` / `failed` outcome); and `recovery_obligation_reassessed`, its
  verdict on each obligation it settled (including an explicit request closed below the
  retained window) and whether another attempt may follow. The
  transport cursor writes `transport_cursor_advanced` for drain checkpoints, settled loss
  and retired notices, and for a live promotion only when it moves the cursor past the
  rebuild lookback, with spill and queue-loss placement counts. Each lag-lost end-of-stored-events repair
  pass writes `subscription_eose_repaired` with its relay counts (awaiting, completed without
  traffic, re-issued, re-issued earlier, failed) and whether a follow-up was scheduled. Rows carry enums, counts
  and hashed references only, and are written only when a v5 recorder is installed.

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
