# Changelog

All notable user-facing changes in the MDK compatibility cohort are tracked
here, including `wn-cli` (previously `darkmatter-cli`), WN Agent, and generated
MarmotKit bindings.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This crate uses semantic
versioning through the workspace version in the root `Cargo.toml`.

## [Unreleased]

### Added

- Experimental Linux/FreeBSD/macOS support for `fips://<npub>` Nostr delivery relay
  endpoints. Setting `WN_FIPS_SOCKET` injects the native FIPS backend while
  ordinary `ws://` and `wss://` endpoints continue to use the Nostr SDK.
- Hybrid daemon startup now preserves a distinct operational `--relay` when
  WebSocket discovery and default-account relay lists are also supplied. The
  client-only FIPS image includes `mdk-fips-tui-demo` for repeatable Linux TUI
  setup, readiness checks, and launch.
- `wn relays set ... --type inbox|nip65` atomically replaces one published
  relay list. `wn relay-stats` and the TUI relay-health screen now report
  privacy-safe FIPS backend endpoint counts for demo preflight and diagnosis.

## [0.9.14] - 2026-08-19

### Added

- The TUI adds `/search [query]` for the newest 100 matching messages, with
  highlighted matches, keyboard navigation, jumps into loaded history, and
  guidance when older history must be loaded first. Group details also scroll
  far enough to reveal relay hints for the final selected member.
  ([#1478](https://github.com/marmot-protocol/mdk/pull/1478))

- MarmotKit adds coherent group-conversation snapshots, bounded member
  KeyPackage prewarming, and account-owned profile publication. Hosts can now
  load group details and management state from one worker snapshot, prewarm a
  deduplicated invitee set without reserving packages, and publish a profile
  using the account's validated publish/bootstrap relay projection without a
  separate relay-list round trip.
  ([#1494](https://github.com/marmot-protocol/mdk/pull/1494),
  [#1495](https://github.com/marmot-protocol/mdk/pull/1495),
  [#1496](https://github.com/marmot-protocol/mdk/pull/1496))

- Group creation accepts forward-compatible options for founding message
  retention and prepared group images. Retention is installed in epoch-zero
  metadata, while bounded PNG/JPEG/GIF/WebP preprocessing and resumable image
  upload can finish before the canonical MLS mutation. Detailed creation APIs
  return the exact durable chat-list row without an extra read.
  ([#1497](https://github.com/marmot-protocol/mdk/pull/1497),
  [#1498](https://github.com/marmot-protocol/mdk/pull/1498),
  [#1500](https://github.com/marmot-protocol/mdk/pull/1500))

- Account creation exposes `Initializing`, `LocalReady`, `Publishing`,
  `NetworkReady`, and `RecoveryRequired` readiness states. A generated account
  can return once its identity, SQLCipher store, default profile, and signed
  setup KeyPackage artifact are durable locally, while restart-resumable
  network publication continues in the background.
  ([#1499](https://github.com/marmot-protocol/mdk/pull/1499))

- WN Agent adds the `wn-codex` terminal harness with per-group Codex thread
  resumption and release installers for supported Linux and macOS targets.
  Terminal harnesses also add an exact `/reset-session` command and shared
  `inherit`, `autonomous`, and explicitly acknowledged `unrestricted`
  execution profiles without mutating global backend configuration.
  ([#1501](https://github.com/marmot-protocol/mdk/pull/1501),
  [#1506](https://github.com/marmot-protocol/mdk/pull/1506),
  [#1507](https://github.com/marmot-protocol/mdk/pull/1507))

### Changed

- Account setup prioritizes its exact journaled KeyPackage before initial sync,
  publishes independent bootstrap records concurrently under one deadline, and
  records privacy-safe stage timings. The local-ready account flow reuses that
  same durable artifact instead of generating a second identity or KeyPackage.
  ([#1493](https://github.com/marmot-protocol/mdk/pull/1493),
  [#1499](https://github.com/marmot-protocol/mdk/pull/1499))

- Group creation and invitation deduplicate member references, reuse warm
  KeyPackages, batch cold relay resolution, and remove the eager app
  pending-Welcome index write from the response tail. Prepared founding images
  keep slow media upload outside the canonical create path.
  ([#1494](https://github.com/marmot-protocol/mdk/pull/1494),
  [#1498](https://github.com/marmot-protocol/mdk/pull/1498),
  [#1500](https://github.com/marmot-protocol/mdk/pull/1500))

- Sync and catch-up telemetry now exports bounded `failure_stage` and
  `error_class` dimensions across transport, subscription, relay receive, CGKA,
  persistence, and account-worker boundaries without raw errors or
  high-cardinality identifiers.
  ([#1488](https://github.com/marmot-protocol/mdk/pull/1488))

- Pi, OpenCode, and Codex terminal connectors share one bounded JSONL
  subprocess runner for deadlines, backpressure, stderr capture, session/error
  handling, cancellation, and child cleanup. OpenCode prompts are sent over
  stdin rather than appearing in spawned process arguments.
  ([#1505](https://github.com/marmot-protocol/mdk/pull/1505),
  [#1506](https://github.com/marmot-protocol/mdk/pull/1506))

### Fixed

- MarmotKit Android release artifacts now strip target JNI libraries while
  preserving the host library metadata UniFFI needs, reject residual debug or
  static-symbol sections during packaging, and retain the established ordered
  manifest contract expected by White Noise Android.
  ([#1480](https://github.com/marmot-protocol/mdk/pull/1480))

- WN Agent publication no longer fails after publishing the immutable
  versioned release when the legacy `wn-agent-latest` installer release is
  itself immutable. In that configuration the workflow leaves the stale alias
  unchanged and directs consumers to the pinned versioned installer assets.

## [0.9.13] - 2026-08-18

### Added

- MarmotKit adds bounded, local-first APIs for common host reads: keyed
  `chatListRow`, badge-ready account unread summaries, administrator ids on
  membership pages, bulk cached identity projections, and peer-keyed existing
  direct-conversation lookup. These replace repeated full chat-list, roster,
  and profile scans while preserving typed missing, malformed, and not-ready
  outcomes.
  ([#1464](https://github.com/marmot-protocol/mdk/pull/1464),
  [#1466](https://github.com/marmot-protocol/mdk/pull/1466),
  [#1468](https://github.com/marmot-protocol/mdk/pull/1468),
  [#1469](https://github.com/marmot-protocol/mdk/pull/1469),
  [#1471](https://github.com/marmot-protocol/mdk/pull/1471))

- MarmotKit release and exact-SHA snapshot workflows now package native macOS
  artifacts and Android Kotlin/JNI bindings alongside the existing Apple
  outputs, with immutable source identities, checksums, and provenance
  manifests for downstream staging.
  ([#1402](https://github.com/marmot-protocol/mdk/pull/1402),
  [#1473](https://github.com/marmot-protocol/mdk/pull/1473))

- MarmotKit exposes `appPerformanceSnapshot()`, a read-only fetch of the
  process-wide app-performance snapshot — per-phase attempt/success/failure
  counters and fixed-bucket millisecond duration histograms — so host debug
  surfaces and on-demand support dumps can read per-device timings that were
  previously available only inside the runtime, with optional OTLP export.
  Accepting
  a group invite now records its own caller-visible `group_accept_invite`
  phase alongside the existing invite, create, and roster phases, and the
  OTLP export gains the matching unlabeled `app_group_accept_invite_*`
  points. The privacy posture is unchanged: aggregate values only, with no
  account, group, relay, or payload labels.
  ([#1453](https://github.com/marmot-protocol/mdk/pull/1453))

- Sending a message now reports whether it reached the relay or is waiting in
  the group's durable queue. MarmotKit's send summary carries an explicit
  `accept_disposition` of `published` or `accepted_pending`, so a host no longer
  has to read an empty message-id list as "something went wrong" when the
  message was in fact accepted and is waiting on the group's convergence.
  ([#1426](https://github.com/marmot-protocol/mdk/pull/1426))

- A group that needs a repair before it can send again now refuses new messages
  with the typed `GroupUnrecoverableRepairRequired` error instead of opaque
  engine error text. The group id comes with it, and like `GroupSendQueueFull`
  it is deliberately not retried automatically: the group stays blocked until
  another member re-admits this device, so a host should say so rather than
  spin. Messages already queued are not discarded — they publish after the
  repair.
  ([#1426](https://github.com/marmot-protocol/mdk/pull/1426))

- `wn tui` can now search messages in the open chat with `/search [query]`
  (`messages timeline search`), the one thing the CLI could do that the TUI could
  not reach at all. Matches list newest first with sender, time, and text; `Enter`
  jumps the messages pane to the highlighted match and focuses it. Matches are
  capped at 100; a full page is reported as `100+` and asks you to refine the
  query rather than presenting a truncated count as the total. Matches older
  than the loaded history say so instead of moving the view, because the pane
  holds one contiguous run of messages and cannot represent a gap — page back with
  `g` and search again to reach them.
  ([#1478](https://github.com/marmot-protocol/mdk/pull/1478))

### Changed

- Account databases upgrade through storage migrations 47–50. Migration 47
  normalizes message metadata and introduces versioned `MDKMP` message-payload
  and `MDKS` snapshot/checkpoint codecs; existing format-1 rows remain readable
  and promote in bounded background batches after account readiness. Later
  migrations persist deferred-peel generations and add targeted pending-invite
  and direct-conversation indexes. Downgrade across migration 47 is unsupported:
  older binaries refuse the database before reading account tables, so make a
  backup before upgrading and restore that backup if downgrade is required.
  Migration 47 can temporarily require substantial disk space; allow at least
  3.25 times the existing account database size as additional free space.
  ([#1421](https://github.com/marmot-protocol/mdk/pull/1421),
  [#1433](https://github.com/marmot-protocol/mdk/pull/1433),
  [#1440](https://github.com/marmot-protocol/mdk/pull/1440),
  [#1454](https://github.com/marmot-protocol/mdk/pull/1454),
  [#1471](https://github.com/marmot-protocol/mdk/pull/1471))

- Group creation and invitation return after the durable MLS mutation instead
  of waiting for Welcome fanout; bounded background delivery retains retryable
  recovery. Invite-with-admin now applies membership and initial administrator
  policy in one commit instead of a follow-up promotion per administrator.
  ([#1457](https://github.com/marmot-protocol/mdk/pull/1457))

- Account setup publishes its initial replaceable records as one recoverable
  batch, connects directory relays concurrently, avoids redundant relay-list
  and SQLCipher work, and preserves partially exposed accounts for idempotent
  retry. One unavailable relay no longer serializes or rolls back otherwise
  acknowledged setup.
  ([#1446](https://github.com/marmot-protocol/mdk/pull/1446))

- WN Agent reconciliation is event-driven with adaptive quiet-period safety
  nets instead of two fixed five-second full-state scans. Remaining passes use
  targeted changed-state reads, reducing idle CPU and SQLite read amplification
  while retaining prompt activity and retry wakeups.
  ([#1454](https://github.com/marmot-protocol/mdk/pull/1454))

### Fixed

- Outbound operations bound foreground deferred-peel work and durably queue
  application, proposal, and commit intents when convergence cannot yet finish.
  Queued messages re-arm their drain when a convergence pass closes, and an
  in-flight regenerated intent is not published twice. This prevents accepted
  messages from remaining stranded or later failing confirmation after a
  duplicate publication.
  ([#1440](https://github.com/marmot-protocol/mdk/pull/1440),
  [#1475](https://github.com/marmot-protocol/mdk/pull/1475))

- App runtime work that can block on SQLCipher, subscription recovery, wake
  catch-up, directory reads, notifications, or media HTTP no longer stalls the
  async runtime or exclusive account worker. Lagged subscriptions rebuild from
  authoritative state, buffered wake events survive catch-up timeouts, and
  projection updates from account mutations flush promptly.
  ([#1435](https://github.com/marmot-protocol/mdk/pull/1435),
  [#1447](https://github.com/marmot-protocol/mdk/pull/1447))

- Steady-state account opens skip a duplicate SQLCipher KDF migration probe
  without weakening marker, salt, key, or recovery checks.
  ([#1442](https://github.com/marmot-protocol/mdk/pull/1442))

- Welcome joins now become durable and publish `GroupJoined` before ordinary
  relay subscriptions rebuild, with failed rebuilds retried in the background.
  Invite acceptance runs during startup hydration and returns a typed
  `AccountWorkerBusy` response when catch-up definitely prevented it from
  starting; every app-facing worker response also has an operation-class deadline whose
  `AccountWorkerResponseTimedOut` result tells hosts to refresh state before
  retrying. MarmotKit and `wn --json` preserve both distinct outcomes.
  ([#1438](https://github.com/marmot-protocol/mdk/issues/1438))

- Messages left waiting when a group is disbanded, or when this device is
  removed from it, no longer report as pending forever. The group's queue is
  gone in both cases, so those messages are now marked failed and hosts can show
  a terminal state instead of a spinner that never resolves. This also holds
  when the disband is only reconciled on the next account open.
  ([#1426](https://github.com/marmot-protocol/mdk/pull/1426))

- A message moving from pending to delivered now reaches subscribers as a
  delivery-state change rather than as new content, so a host can update a
  delivery indicator without re-reading the conversation. The same flip caused
  by an explicit convergence retry was previously recorded but never broadcast
  at all, leaving timelines and chat lists showing pending until some unrelated
  event woke them.
  ([#1426](https://github.com/marmot-protocol/mdk/pull/1426))

- `wn tui` user search no longer leaves results under a query they do not answer.
  Editing the query after results landed used to keep the old rows, their count,
  and the highlight on screen, so `f`/`x` published a follow for whoever the
  previous query had found and `c`/`a` opened a chat with them. An edit now clears
  the results, and a page still in flight for the abandoned query is dropped
  instead of landing — and taking focus mid-word with it. Moving the cursor, and
  editing that changes nothing, still keep the results.
  ([#1478](https://github.com/marmot-protocol/mdk/pull/1478))

- `wn tui` group detail can now reach its relay hints. They sit below the member
  list, so a group with more members than the pane is tall left them permanently
  off-screen; moving the selection to the last member now scrolls to the end of
  the pane and brings them into view with it.
  ([#1478](https://github.com/marmot-protocol/mdk/pull/1478))

## [0.9.12] - 2026-08-13

### Added

- WN Agent's `marmot.agent-control.v2` protocol now supports adding and
  removing durable message reactions. Hermes exposes the operations through
  its Marmot tools, and OpenClaw exposes them through
  `message(action="react")`, including current-message targeting, bounded
  reaction content, exact or all-reaction removal, and idempotent missing
  removal handling.
  ([#1399](https://github.com/marmot-protocol/mdk/pull/1399),
  [#1401](https://github.com/marmot-protocol/mdk/pull/1401))

- MarmotKit releases now publish immutable SwiftPM-compatible XCFramework
  archives, generated Swift source, checksums, and complete provenance
  manifests. Exact-master snapshot releases use source-SHA identities so
  pre-release app builds can pin bindings without replacing a versioned
  artifact.
  ([#1378](https://github.com/marmot-protocol/mdk/pull/1378))

- `wn tui` group detail now has a lowercase `a` that searches for a member to
  add, for when you do not have the pubkey to hand (`A` remains the paste-a-pubkey
  path). The search it opens is aimed at that group: `a` on a result confirms
  against it directly instead of asking which chat, `Esc` returns to the group
  detail, and a completed add reopens and reloads it.

### Changed

- Agent stream-compose append, status, and progress acknowledgements no longer
  echo the accumulated transcript on every command. This removes quadratic
  copying for long streams; `compose-append` JSON no longer contains `text`,
  while finish responses still carry and validate the complete transcript and
  the TUI tracks flushed bytes locally.
  ([#1408](https://github.com/marmot-protocol/mdk/pull/1408))

- Hot paths now avoid history-sized repeated work: outbound send gates use
  indexed message-state probes, retained convergence anchors omit unused
  message-ledger copies, Welcome joins use point lookups and filtered replay,
  MarmotKit timeline windows reconvert only changed rows, and app clients keep
  an incremental seen-event index. Existing databases remain compatible.
  ([#1405](https://github.com/marmot-protocol/mdk/pull/1405),
  [#1406](https://github.com/marmot-protocol/mdk/pull/1406),
  [#1407](https://github.com/marmot-protocol/mdk/pull/1407),
  [#1416](https://github.com/marmot-protocol/mdk/pull/1416),
  [#1417](https://github.com/marmot-protocol/mdk/pull/1417))

- Same-epoch fork resolution now uses one rule for every member: the
  committer's pairwise fast-path is removed, and a committer adjudicates a
  rival commit through the same distributed-convergence pass as an observer,
  with its own commit materialized from the commit-addressed checkpoints
  introduced in #1285. When the in-horizon recovery material (the retained
  source-epoch anchor) is missing, the group fails closed loudly — durable
  `Unrecoverable` halt plus a `GroupUnrecoverable` event — instead of
  silently keeping a possibly losing branch. A committer's rival resolution
  now waits for the convergence pass's quiescence window (~1 s); sends queue
  during it. The `ForkRecovered` group event and its MarmotKit FFI variant
  are removed (the convergence-path `CommitRolledBack` +
  `GroupStateInvalidated` pair is the rollback signal); forensic audit logs
  keep parsing the historical `fork_resolution` and `snapshot_created` rows,
  which current engines no longer emit.
  ([#1293](https://github.com/marmot-protocol/mdk/pull/1293))

- Encrypted media and Hermes/WN Agent file delivery now accept blobs up to
  512 MiB (including the 16-byte authentication tag), enabling APKs and other
  artifacts above the previous 64 MiB ceiling. Encryption/decryption is
  performed in place, Blossom fallback retries share the same immutable upload
  body, and large blob transfers have a 15-minute request budget. Receivers must
  upgrade to this compatibility cohort before downloading blobs above 64 MiB;
  the active blob remains memory-resident and one media request is bounded to
  512 MiB total.

- One publish's relay fanout now runs its per-relay attempts concurrently
  instead of one awaited relay at a time, so a slow relay no longer serially
  delays every relay after it. Fanout duration can approach the slowest
  individual attempt's budget when the transport makes concurrent progress,
  instead of the sum of per-relay budgets.
  ([#1397](https://github.com/marmot-protocol/mdk/pull/1397))

- App-runtime encrypted-media secret caching now skips the MLS group load,
  exporter-secret derivation, and database write when the current epoch's
  secret is already cached, and the cache sweep's `required` pre-check uses
  the projected group record as a positive-only fast path, re-checking the
  signed component only when the projection reports media disabled. Message
  sends and group syncs no longer pay three MLS group loads per media group
  per sweep.
  ([#1396](https://github.com/marmot-protocol/mdk/pull/1396))

### Fixed

- Outbound application messages queued during an unsettled convergence pass
  now durably arm their drain and remain visible as runnable or scheduled work,
  preventing accepted sends from being stranded while the group appears idle.
  ([#1403](https://github.com/marmot-protocol/mdk/pull/1403))

- Removed members can rejoin through a fresh Welcome without evicted-era
  snapshots aborting the past-epoch peel probe, and deliveries dropped before
  a delayed Welcome are no longer remembered as seen so relay redelivery can
  catch the new member up.
  ([#1367](https://github.com/marmot-protocol/mdk/pull/1367),
  [#1379](https://github.com/marmot-protocol/mdk/pull/1379))

- Incident replay now recognizes manifest-less NDJSON stream remnants by their
  type discriminator and fails closed instead of accepting a truncated error
  stream as an empty healthy export.
  ([#1140](https://github.com/marmot-protocol/mdk/pull/1140))

- OpenClaw Marmot inbound turns now resolve agent-scoped session stores with the
  routed agent id, and beta message sends bypass the delete-only action adapter
  so they reach durable delivery.
- Runtime catch-up now emits live events and persists transport progress for
  deliveries that completed before a later delivery fails the same relay batch.
  Direct clients receive the applied prefix with the error, and `wn sync`
  includes that prefix in its human and JSON error output. Successful and
  partial JSON output now both report projection-update and epoch-stall
  escalation counts.
- Local-only group deletion now survives account restart and historical relay
  replay. A per-group deletion frontier suppresses projection reconciliation
  until a causally newer chat message arrives, while a durable engine-to-app
  delivery outbox makes that first crossing chat recoverable after a crash and
  does not affect other locally deleted groups.
- Nostr group-sync unsubscribe draining now keeps unresolved relay teardowns
  queued until teardown is confirmed, so cancelling a sync after routing
  state commits retries pending unsubscribes and converges removal metrics
  without double-counting.
- OpenCode harness idle-timeout regression test now keeps the mock child alive
  past the idle deadline so CI load cannot race normal exit with `BackendIdle`.
- Nostr group-subscription sync now registers new routes and telemetry before
  issuing relay REQs, so immediate stored-event replay cannot be dropped as
  unroutable; failed subscriptions roll the staged state back for clean retry.
- Engine fork-detection integration tests now exercise the pinned v1
  five-commit rewind horizon in normal builds instead of overriding
  `max_rewind_commits` to one.
- Group timelines now derive their durable order from authenticated MLS source
  epochs instead of local receive time. State-change rows lead the application
  messages they authorize, pagination/live windows and read markers share that
  order, and delayed catch-up converges to the same sequence on every device.
- Runtime catch-up, key-package maintenance, and every other incremental sync
  seam now execute an armed epoch-gap full-history replay immediately instead of
  waiting for unrelated later relay traffic. Explicit full-history repair also
  consumes a pending replay without issuing the same account-wide query twice.
- Epoch-gap backfill forensic audit rows now continue past `armed` with typed
  `started`, `completed`/`failed`, and optional `deferred` lifecycle evidence
  correlated by `operation_id`, including replay seam, delivery count, transport
  activation outcome, and per-group local epoch before/after observation. In-flight
  arms minted during a replay are queued instead of being overwritten when the
  current attempt fails, and identical deferred evidence is debounced until the
  observable group-epoch state changes.
- KeyPackage NIP-09 deletions now surface privacy-safe per-relay rejection
  categories (for example `blocked` or `auth-required`) instead of repeating a
  generic `relay rejected event` summary, while successful deletions still
  clear only matching local KeyPackage publication metadata after at least one
  relay acknowledgement.
- Hermes Marmot `marmot_history` and `delete_marmot_message` tools now accept
  Hermes ToolRegistry runtime keyword arguments (`task_id`, `session_id`, and
  future dispatch metadata) instead of failing with `TypeError` during gateway
  tool calls.
- Leave-proposal persistence now commits the signed proposal, durable leave
  request, and content-dedup marker atomically, so a storage failure cannot
  strand a same-epoch leave retry without a publishable proposal.
- The Nostr SDK failed-signature regression test now observes EOSE under one
  bounded CI-safe window, avoiding sharded CI flakes without weakening
  failed-event non-emission and non-caching assertions.
- `wn tui` now scrolls the highlighted row into view on the account picker, the
  profile, group-detail, and user-search panes, and the picker popup. Past
  roughly a screenful of rows the highlight fell outside the drawn area, which
  made the selection invisible rather than merely awkward — the marker and the
  highlight are drawn inside each row.

## [0.9.11] - 2026-08-09

### Added

- Hermes Marmot delivery now batches up to 10 ordered local images into one
  encrypted-media application message instead of sending one message per image.
  The adapter pins approved source files before bounded staging, while the
  connector independently enforces the attachment-count and byte limits. Album
  sends apply the caption once, report every durable message id and attachment
  outcome, wait up to 15 minutes for terminal upload completion, and return a
  retryable timeout while cleaning staged files if the connector never finishes.
  Transport retries reuse connector-persisted idempotency so they cannot
  duplicate the album.

- WN Agent releases now include the `wn-pi` terminal-harness connector and
  installer for Linux and macOS. Pi runs in isolated JSON-mode sessions with
  bounded working-directory access, persisted conversation state, streamed
  assistant output, and the same hardened shared connector runtime now used by
  `wn-opencode`.

- Account-open startup is now stage-attributed in app telemetry: engine
  session open, stored-group hydration, the shared startup profile load, and
  the group-read-snapshot capture each get fixed-bucket duration metrics.
  New `just bench-startup` scaling benchmarks separate
  chat-projection readiness from full account-command readiness across
  0/10/100/1000 stored groups.

- Engine session open now uses two-phase hydration: a cheap seed pass reads
  only durable group records (plus a new durable transport-route table) and
  full per-group hydration — MLS load, validation, pending-commit recovery —
  runs per group, on demand from send/ingest/convergence entry points or
  eagerly via the compatibility path. Per-group hydration itself got cheaper:
  one group-record read and one message scan replace the former three record
  reads and four full message-table scans per group. Groups awaiting
  hydration report a new retryable "not hydrated yet" state instead of
  partial data.

- Runtime account opens now defer full group hydration to a background
  pipeline that runs after local readiness in chat-list recency order, so
  cold-start readiness no longer scales with stored group count. Group reads
  issued before a group hydrates wait for exactly that group; mutations and
  catch-ups keep their existing startup deferral order — `start()` returning
  therefore does NOT mean a subsequent send is unblocked: sends issued
  before the initial catch-up completes are queued and replayed in arrival
  order after it, covering any remaining hydration plus catch-up latency.
  MarmotKit surfaces a new retryable `GroupHydrationPending` error, distinct
  from `UnknownGroup`, for the remaining direct-read window.

- After a receive-error transport reconnect, the managed account worker eagerly
  drains every deferred stored group (including more than one hydration batch)
  before resuming steady-state commands, so groups are not left gated until a
  later read or send promotes them individually.

- Repeated epoch-gap backfill stalls now emit a one-time typed escalation event
  and durable forensic record with aggregate attempt and epoch information.
  Successful progress resets the escalation state so a later independent stall
  can be diagnosed separately.

- `marmot-markdown` now recognizes bare `www.example.com/path` text as web
  autolinks. The AST preserves the displayed `www.` source while exposing an
  explicit `Www` autolink kind so renderers can synthesize `https://`
  destinations without a second client-side URL parser.
  
- MarmotKit and the agent connector now acquire a nonblocking, kernel-released
  exclusive lease on their root before opening shared state. MarmotKit exposes
  typed `RuntimeBusy` contention so foreground apps can retry and notification
  extensions can return bounded fallback content instead of creating a second
  stateful writer.

- MarmotKit exposes `groupRoster`, a single lightweight membership projection
  with enriched roster rows, MLS epoch, caller self-membership or eviction
  state, lifecycle state, and a monotonic revision covering MLS epoch plus
  caller membership for cheap membership-screen change detection. Existing
  `groupDetails`, `groupMlsState`, and `groupMembers` remain available for
  compatibility.

- MarmotKit exposes `groupMemberIdsPage`, a bounded identifier-only companion
  read for chat-list consumers. A host can fetch membership for up to 100
  groups in one account-worker command instead of issuing one `groupMembers`
  or `groupRoster` command per chat. The page preserves input order, performs
  no profile enrichment, and fails as a whole when any requested group is
  unknown or quarantined
  ([#1342](https://github.com/marmot-protocol/mdk/pull/1342)).
  
- MarmotKit exposes `downloadProfileImage` for dial-safe fetching of untrusted
  kind:0 profile `picture` URLs (HTTPS-only, proxy-disabled pinned public
  resolution, bounded redirects, and streaming limits) so Android and Swift
  hosts do not maintain a separate SSRF stack for public avatars
  ([#1288](https://github.com/marmot-protocol/mdk/pull/1288)).

- Outbound messages waiting in a group's durable queue are now bounded at 256
  per group. The bound covers every reason a message waits: a group resolving a
  stalled publication, convergence input that has not settled, and messages
  queued while the account is offline. Past the bound a send is refused instead
  of queued without limit — MarmotKit reports the typed `GroupSendQueueFull`
  error, which is deliberately not retried automatically, so a host should tell
  the user the message was not accepted and offer to resend once the group is
  sending again. Nothing already queued is discarded; a slot frees only once its
  message is accepted by a relay.

- Freshly created local identities now publish an explicit empty Nostr contact
  list, giving the first follow update a safe relay-visible baseline without
  weakening anti-clobber handling for imported identities with a missing list.

- The conformance suite now includes a permanent four-participant cross-route
  recovery vector covering simultaneous privileged commits, pairwise and
  observer-side resolution, branch-depth reversal, encrypted-SQLite restart,
  exact canonical agreement, durable input dispositions, and all twelve
  directed application-decryptability probes.

### Fixed

- Group creation now performs member KeyPackage lookup and founding Welcome
  publication with bounded concurrency, includes the initial description in the
  founding MLS state, and returns once the founder projection is locally usable.
  Repairable subscription refresh and broad catch-up continue in the background,
  while privacy-safe stage histograms expose the remaining latency budget. A
  completion-bookkeeping failure for one published Welcome no longer skips the
  remaining recipients: every exposed publish is durably reconciled before the
  first error surfaces, so a restart cannot republish an already-delivered
  Welcome. Inbound membership changes now persist their app-state projection
  (including a fresh join's pending invite) before any route-refresh network
  work, closing a torn-write window where a fast-exiting process could strand
  the durable engine join without its app-state row.

- Existing-group invite commands now return after the required relay
  acknowledgement and durable local refresh instead of waiting for an
  all-account read-side catch-up. Account workers serve group projection reads
  from a fresh local snapshot while detached catch-up runs, so overlapping
  invites keep their immediate reads responsive without suppressing another
  local account's incoming Welcome. Deferred account opens now finish
  live-state projection repair after group hydration, preventing a committed
  overlapping invite from failing worker readiness as not-yet-hydrated. The
  work remains visible in the existing invite-stage telemetry
  ([#1309](https://github.com/marmot-protocol/mdk/pull/1309)).

- Account imports now journal setup progress and resume the exact persisted
  KeyPackage publication after relay failure, cancellation, or restart instead
  of minting a new stable slot. Ambiguous pre-journal state returns the typed,
  consent-gated `AccountSetupRecoveryRequired` flow; setup interruptions also
  have stable JSON recovery codes and repair hints instead of falling through
  to the generic `command_failed` bucket.

- Published NIP-65 and inbox lists containing retired relays no longer prevent
  account activation or remote KeyPackage lookup. The original lists remain
  cached and visible for settings UI, while unsafe endpoints are filtered only
  from runtime routes and configured directory relays provide operational
  fallback without rewriting or republishing the account's list.

- MarmotKit root preparation now works in physical iOS App Group and Android
  application sandboxes while retaining descriptor-relative creation and
  symlink rejection for app-controlled paths. New iOS account secrets use the
  device-only after-first-unlock Keychain policy, and legacy entries migrate
  crash-safely after the next unlocked access so notification extensions and
  background refresh can operate while the device is locked.

- Hermes and OpenClaw now bound automatically attached timeline context to the
  newest eight records and 16 KiB, dropping oldest or individually oversized
  records first. The Hermes one-line installer no longer lets an interactive
  child consume the remainder of `curl | bash`, and its guided sender allowlist
  is collected in one explicit step.

- Account projection storage types now redact encrypted group-image decryption
  and Blossom upload keys from `Debug` output, including nested group
  formatting. The TUI group diagnostics panel no longer retains or renders raw
  group component `data_hex`, so blossom image key material cannot leak through
  diagnostics `Debug` or on-screen lines.
  
- OpenMLS persistence now zeroizes temporary SQLite serialization,
  deserialization, and rollback-snapshot buffers for MLS private keys, epoch and
  message secrets, PSKs, pending group state, application-export state, and
  stored key-package handoffs on success and error paths.
  
- `wn login --nsec-stdin` and `wn account create --nsec-stdin` now keep stdin
  nsecs in a dedicated zeroizing sidecar instead of materializing them into the
  generic `Cli` command tree. Daemon execute frames and `AccountSetupRequest`
  use redacted `Debug`, avoid secret `Clone`, and wipe nsec-bearing request
  framing buffers on the final owned request payload where the implementation
  controls the buffer (`Zeroizing` encode/read paths). Transient allocator or
  `BufReader` copies are not guaranteed wiped. When the daemon app runtime is
  disabled (no `--relay`), account setup skips hosted validation and falls back
  to local `wn` execution while keeping the stdin `nsec` sidecar owned. Uppercase
  `NSEC…` argv identities are rejected at the same early gate as lowercase
  `nsec…`.

- `wn-agent serve` now exits when its control-socket path is removed or
  replaced while the listener is still bound, instead of staying alive with an
  unreachable Unix listener after the final hard link disappears.

- The runtime-start local-readiness regression test now asserts startup-before-
  subscription ordering directly while retaining a bounded hang deadline,
  avoiding false failures when unrelated startup work is delayed under loaded
  `nextest` shards.

- Same-epoch commit races now converge every member onto the same branch. A
  member that had committed from the contested epoch resolved the race through
  pairwise fork recovery and invalidated the losing commit terminally, while
  everyone else resolved it through distributed convergence, where a deeper
  valid branch can win later — so honest members could keep different lineages
  forever and silently lose every application message sent on the other side.
  The pairwise loser is now parked reconsiderable (`ConvergenceDeferred`,
  keyed by its source epoch) so a later convergence pass adopts the same
  branch everywhere, and `fork_resolution` audit rows now record the kept
  incumbent's commit digest so cross-member convergence is provable from
  forensic logs. Because OpenMLS cannot process a device's own Commit from the
  network, confirmation now atomically retains an immutable, commit-addressed
  checkpoint of the canonical MLS/Marmot state. A later reorg can restore that
  exact branch after restart, verify its epoch authenticator, and replay its
  descendants even when an epoch-keyed rollback anchor has been replaced by a
  rival branch. Checkpoints are pruned with the retained rewind horizon.
  Displacing the losing branch is also a single durable transaction now, so an
  interrupted resolution can no longer drop it without a trace.
  ([#1285](https://github.com/marmot-protocol/mdk/pull/1285))

- Locally authored messages now retain authenticated send-time branch
  provenance through stored convergence and restart, preventing an accepted
  own message from being misclassified as undecryptable merely because OpenMLS
  cannot decrypt a sender's own private-message ciphertext during replay.

- Inbound MLS commits now apply the epoch, roster, and capability projections
  atomically with the OpenMLS merge. SQLite transaction boundaries retry
  transient contention without rerunning application closures, pruning scales
  without unbounded bind lists and preserves draft-owning groups, and secure
  deletion retains a durable WAL-truncation intent until physical erasure can
  complete.

- Opaque transport objects that remain unpeelable now have a restart-safe,
  bounded 30-day local residence. Expiry releases local resources without a
  terminal protocol verdict and preserves exact-ID redelivery eligibility if
  missing history later arrives.

- Stored convergence passes whose durable base no longer matches the live tip
  are discarded and reopened at the current epoch instead of halting the group
  as unrecoverable. Eligible non-selected branches and missing-parent inputs
  remain explicitly deferred for reconsideration rather than being
  terminally invalidated.

- The full-cohort release coordinator now fetches only immutable MDK,
  WN Agent, and MarmotKit version tags, so an older local copy of the
  intentionally moving `wn-agent-latest` installer alias no longer blocks a
  release preflight with a tag-clobber error.

- `MarmotApp` now permits only one live in-memory engine session per account
  across direct clients and managed workers. Concurrent opens return the typed
  `AccountSessionBusy` error, and worker reconnect drops the failed session
  before reopening, preventing two engines over one session database from
  staging conflicting epoch work. Failed account reconcile now shuts down every
  worker it spawned before returning, including workers still opening locally,
  so a contended startup does not leave unrelated account session guards held;
  worker lifecycle transactions are serialized so a concurrent reconcile or
  teardown cannot remove workers another successful caller relied on.

- Group state changes settle promptly again when messages are queued for
  sending: a queued ordinary message no longer delays the next convergence
  pass (only an admin group-state change may briefly hold that boundary, as
  the protocol requires), and busy groups are no longer demoted to retry
  backoff while convergence is legitimately still collecting.

- Runtime chat-list and group-state subscriptions now observe group state
  changes (for example a group rename) that a member's own outbound send
  applied by folding retained convergence commits. Previously those events were
  dropped on the send path, so storage showed the new state while live
  subscribers were never notified.

### Security

- NIP-49 encrypted private-key export now zeroizes its normalized passphrase,
  scrypt-derived key, cipher-owned key copy, and plaintext decrypt buffer on
  success and error paths.

### Changed

- Generated simulator failure fixtures now preserve the complete executed
  scenario instead of substituting a diagnostic semantic reduction that may
  reproduce only the failure class. Strict virtual-time coverage also accepts
  either fixed-point quiescence or an exact no-pending-work observation after
  an explicit time advance.

- UniFFI was upgraded from 0.28.3 to 0.29.4. Generated Swift keeps the existing
  Marmot-facing declarations while gaining the generator's current
  `Sendable`/`Error` conformances; the dependency refresh also removes the
  audited `bincode`, `paste`, and `proc-macro-error2` paths and incorporates the
  `nostr` fix for RUSTSEC-2026-0219.

- The bundled SQLCipher stack now uses rusqlite 0.40.1/libsqlite3-sys 0.38.1,
  providing SQLCipher 4.14.0 and SQLite 3.51.3 with SQLite's WAL-reset
  corruption fix. Rust 1.95.0 is the minimum release that supports this
  libsqlite3-sys build; the pinned toolchain moved on to 1.97.1 below.

- The pinned Rust toolchain is now 1.97.1, and the convergence-campaign
  builder image is digest-pinned to the matching `rust:1.97.1-bookworm`.
  Rust 1.97's new `unneeded_wildcard_pattern` clippy lint required removing
  two redundant field bindings in the campaign runner's fault validation.
  ([#1305](https://github.com/marmot-protocol/mdk/pull/1305))

## [0.9.10] - 2026-07-29

### Added

- MarmotKit now exposes streaming, bounded web-of-trust user search. Results
  include typed match attribution and social distance, can include accepted
  group co-members, resolve profiles through each author's NIP-65 write relays,
  and remain in an un-promoted cache so discovering a stranger never creates a
  live directory subscription. Empty personal graphs can optionally fall back
  to configured seed accounts, reported at the explicit off-graph radius 255.
- User discovery now supplements the personal graph with up to 20 ranked
  pubkeys from Vertex's Open Ranking HTTP endpoint, bounded by a five-second
  timeout. Existing graph members are deduplicated before the remaining
  candidates are hydrated through configured relay endpoints. Hosts can
  override or disable the provider at construction time, and discovery batches
  use a dedicated stream trigger rather than reopening completed graph radii.
- MarmotKit clients can retrieve the canonical retired-relay host list and
  batch-classify arbitrary relay endpoints as `allowed`, `retired`, `invalid`,
  or `unsafe`. Classification uses the relay plane's dial-safety policy,
  preserves input order, and returns a normalized endpoint when parsing
  succeeds, allowing NIP-65 and inbox relay screens to flag entries that users
  should remove without exposing transient connection state.
- MarmotKit Markdown documents now preserve a bounded count of authored blank
  lines before blocks across document, block-quote, and list-item containers,
  including through serialization and UniFFI, so clients can render source
  spacing without reparsing message plaintext.
- WN Agent now exposes exact-message and stable cursor-paginated materialized
  timeline reads. OpenClaw and Hermes attach bounded recent history with durable
  message ids to inbound turns and provide a `marmot_history` tool for older or
  exact transcript lookup; complete referenced-message sender and text context
  is preserved, including self-authored OpenClaw reply targets.

### Changed

- Relay bootstrap and policy defaults now use Vertex and no longer use the
  retired `relay.damus.io` or `relay.nostr.band` hosts. Both retired hosts are
  rejected by the same centralized policy applied before outbound relay dials.
- `wn users search` now runs against the live bounded graph, supports opt-in
  radius-2 follows-of-follows traversal, and reports timeout or candidate-cap
  truncation as partial results rather than presenting a short list as
  complete. Daemon-hosted searches include eligible group co-members.

### Fixed

- Pending sends are retained while account transport activation is still in
  progress instead of being discarded before the relay plane becomes ready.
- Relay notification forwarding is supervised and recovered after unexpected
  receiver termination, preventing inbound delivery from silently stopping.
- Importing an identity no longer leaves an orphaned Keychain secret when
  account-home creation fails.

## [0.9.9] - 2026-07-28

### Added

- MarmotKit now supports durable, device-local chat pinning. Chat-list rows
  expose normalized pin state and position, new commands pin, unpin, and
  transactionally replace the complete pinned order, and chat-list
  subscriptions publish atomic snapshots when pin order changes.
- MDK now implements lifecycle-v1 terminal group disbanding. Current-profile
  groups can durably request and converge on an authenticated disband Commit,
  transactionally erase live MLS state, retain a terminal tombstone and local
  history, block later group activity, recover safely after restart, and expose
  lifecycle, request, support, and management state through MarmotKit.
- WN Agent inbound delivery now carries structured actor, message, media, reply,
  edit, delete, and reaction context. Durable mutation events are normalized,
  deduplicated, privacy-filtered, and delivered through the native OpenClaw and
  Hermes context surfaces; OpenCode decodes the new schema while intentionally
  ignoring ambient mutations.

### Changed

- The `marmot.agent-control.v2` inbound schema replaces the former flat message
  shape. This is the final unversioned wire break: deploy the `0.9.9` WN Agent,
  Hermes plugin, OpenClaw plugin, and OpenCode harness as one cohort. Future
  breaking changes require a new protocol label or explicit negotiation.
- Chat-list consumers must handle the new snapshot and pin-order subscription
  cases and the required pin fields. Group consumers gain terminal lifecycle
  and disband-request fields, typed disband errors, and disband commands.
- The supported integration baselines are now Hermes Agent 0.19.0 and OpenClaw
  2026.7.1. Release installers validate an existing host but never install or
  upgrade Hermes or OpenClaw.

### Fixed

- WN Agent now preserves ambient edits, deletes, and reactions that arrive
  while an agent turn is already in flight, so the bounded context is attached
  to the next triggering message instead of being lost when the current turn
  finishes.

## [0.9.8] - 2026-07-27

### Added

- MarmotKit now exposes an engine-owned, per-account disappearing-message
  retention sweep with a caller-supplied Unix-millisecond clock. The sweep
  preserves the Android background policy's current-timer gating, five-second
  skew tolerance, bounded timeline pagination, and unread-received deferral;
  returns stable per-group prune, deferral, and privacy-safe failure outcomes;
  and includes pruned media ciphertext hashes for host cache eviction.
- MarmotKit timeline records now expose the authenticated `source_epoch` plus
  the exact pinned `retention_seconds` and `retention_expires_at` decision for
  each message. Legacy rows remain distinguishable from explicitly disabled
  retention, and overflow-safe unbounded retention is not recomputed by hosts.
- MarmotKit chat-list rows now expose durable semantic conversation/activity
  timestamps, a manual-unread reminder, effective timed/indefinite MDK mute
  state, current direct/group classification, bounded latest-message attachment
  kind/count, and exact latest-message delivery state. New commands set/clear
  manual unread and read/set/clear MDK chat mute state; chat-list subscriptions
  publish these changes, including automatic finite-mute expiry. Manual unread
  remains separate from the monotonic message read marker, MDK mute remains
  separate from host notification modes such as all/mentions/nothing, and no
  wire protocol changes are involved.
- The Hermes and OpenClaw release installers can now securely import an existing
  Nostr identity from an owner-only file, optionally pin it to an expected npub,
  and bootstrap that exact account without creating a replacement identity.
  Interactive installs also provide a masked `/dev/tty` identity prompt.
- MarmotKit now exposes the durable pending leave intent, so a cold launch can
  rediscover a leave whose request has not resolved yet — including one whose
  publish failed. `ChatListRowFfi`, `AppGroupRecordFfi`, and
  `GroupManagementStateFfi` carry `leave_request_pending` plus
  `leave_requested_at_ms` (always equal to `leave_requested_at_ms != null`),
  derived at read time from the engine-owned `cgka_leave_requests` rows rather
  than a denormalized projection column, so the value cannot go stale when the
  engine clears a request without notifying the app layer. The flag is
  orthogonal to `self_membership`, which records the locally classified
  departure: `Left` is written as soon as the SelfRemove proposal publishes, so
  a pending request and `Left` routinely coexist while the group waits for a
  member to commit the removal. `GroupManagementStateFfi.can_leave` is now
  `false` while a leave is pending, and a repeat leave returns the new
  `MarmotKitError::LeaveAlreadyRequested` instead of an opaque runtime error.
  A failed leave now also publishes a group-state update, so subscribers see the
  pending flag without waiting for an unrelated refresh. `chats list --json` /
  `chat_list_row` rows gain a matching `leave_requested_at_ms` field; no other
  JSON response shapes changed.
- TUI: the daemon auto-starts at launch when it is down and the TUI holds a relay source to give it (the
  `--discovery-relays`/`--default-account-relays` passthrough flags, a global `--relay`, or `WN_RELAY`) — exactly as
  `/daemon start` would, but off the event loop, since `wn daemon start` blocks up to five seconds on its readiness
  poll. The status line shows `starting daemon...` and then the outcome, the status-bar dot flips green when the start
  lands, and the daemon-backed live subscriptions attach without any manual action. Without a relay source no start is
  attempted (it would fail requiring a relay URL): one honest status says so and the login/main flow continues degraded
  exactly as before. Deliberate divergence from the retired reference client, which killed its auto-started daemon on
  exit: the TUI never stops the daemon, because other `wn` commands share it — stop it explicitly with `/daemon stop`.
- TUI: `f`/`x` on a highlighted user-search result follow/unfollow that user directly — the same key letters as the
  Profile screen's `f`/`x`, but acting directly on the highlighted result (Profile's go through popups) instead of a
  round-trip through the Profile screen with a pasted pubkey. Both run
  `follows add`/`follows remove` on the background worker with in-flight feedback, and the outcome folds into a
  per-row `[following]` badge. Rows an account already follows are badged up front from a `follows list` snapshot (one
  local directory read per search, not a `follows check` per row). A fold whose search screen was left, whose acting
  account was switched, or whose user is no longer among the results is dropped rather than badging the wrong row; the
  results-focus hints line and the help card name the new keys.
- TUI: inbound media renders inline in the message pane. Image attachments are downloaded and decoded off the event
  loop (a worker thread runs `wn media download <group> <plaintext-hash> --output <cache path>` and the `image`
  decode, delivering the result over an `mpsc` channel drained on tick) and drawn via `ratatui-image` as cell-exact
  half-block glyphs (`▀` colored cells) on any image-capable terminal. The fidelity choice is deliberate: half-blocks
  are ordinary colored cells rather than a native pixel image (iTerm2/Kitty/Sixel), so an image is bounded strictly to
  its reserved block and can never overdraw a neighboring message or leave a terminal-side artifact behind on scroll.
  Placeholders walk `[img name]` -> `[downloading name...]` -> `[loading name...]` -> the image, or
  `[name failed: err]`, and stay `[img name]` on a terminal with no image capability. `o` opens the selected message's
  image full-size in a dismiss-on-any-key viewer, drawn with the terminal's native pixel protocol when it has one and
  the same cell-exact rendering otherwise. Decrypted media is held in memory only; the downloaded artifact is removed
  right after decode rather than cached on disk. No JSON response shapes changed (the existing `media download --json`
  `output_path` is passed via `--output`).

### Changed

- `Marmot.start()` now returns when persisted account sessions and projections
  are locally ready. Relay activation, subscriptions, directory sync, and
  initial catch-up continue asynchronously; local reads remain available while
  mutating commands are deferred and replayed in order. New privacy-safe host
  performance telemetry separates local-ready and network-ready timing.
- A leave request that already covers the current epoch is now reported as
  `EngineError::LeaveAlreadyRequested` instead of
  `EngineError::InvalidTransition`, which is documented as indicating an engine
  bug and was flattened to an opaque error at the UniFFI boundary. A user
  double-tapping Leave is routine input, and the classification is made inside
  the engine — under the same lock as the durable read and write — so concurrent
  leaves cannot race past a caller-side precheck and lose the reason. Forensic
  audit records and conformance observations for this case change from
  `invalid_transition` to `leave_already_requested`.
- TUI polish bundle: `Esc` on the main view is now spatial back (Composer → Messages → Chats, a no-op from Chats)
  after the armed-interaction clear, and never destroys a hand-typed draft. The messages-pane row highlight renders
  when that pane holds focus or while an interaction is armed — arming `/react`/`/reply`/`/delete` moves focus to the
  composer, but the target row stays lit so you can see what the action is aimed at; a flick-through preview (focus on
  the chat list with nothing armed) still shows no stray highlight. The chat sidebar shrinks to at
  most a third of the width on narrow terminals (was a fixed 36 columns). Color roles are split: cyan for
  chrome/labels/focused borders/selected markers, green reserved strictly for your own messages and the
  daemon-connection dot; the unread badge stays yellow. The login screen centers its brand/menu block as a focused
  card.
- TUI: loading and empty states are now centered and color-coded — yellow while a load is in flight
  (`loading messages...`, `searching...`, and the group-detail/profile/relay-health screen loads), dark gray when
  genuinely empty (`no chats yet`, `no messages yet`). The messages pane distinguishes its three cases: no chat loaded
  ("select a chat to start messaging"), a load in flight, and a loaded-but-empty chat.
- TUI: popups are now sized to their content in cells and centered exactly, instead of always covering 70% of the
  screen — a short confirmation is a small box, not a full panel. Confirmation bodies render yellow, the irreversible
  typed-token logout body renders red, the title shows as a cyan-bold ` Title ` on the cyan border, and the hint row is
  centered at the bottom. Every popup's key/paste modality and purpose is unchanged (styling and geometry only); the
  image viewer keeps its aspect-fit 80%×80% card.
- TUI: the hints bar now renders each key as a keycap (bold white text on a dark-gray block) followed by a dim label,
  instead of one uniform gray string. The armed-interaction hint keeps its priority over the keymap while a
  `/react`/`/reply`/`/delete` prefill is held, and boxes its `Enter`/`Esc` key references the same way. Popup hint rows
  color the bracketed `[key]` cyan with a gray description.
- TUI: the bottom status bar is now a full-width bar with a green ● / red ○ daemon-connection dot, the account display
  name styled distinctly from its shortened npub, gray `│` separators, and hide-when-zero badges — the unread count
  (yellow) only shows when nonzero instead of a permanent `0 unread`. Our last-action/error status segment is kept as a
  trailing bar segment, truncated to fit. Existing redactions (terminal-safe account label and status, no relay URLs)
  are unchanged.
- TUI: user-initiated actions no longer freeze the interface for a `wn` subprocess round-trip. Sending a message,
  replying, reacting/unreacting, deleting, opening a chat, searching users, opening group detail, and listing invites
  now run on a dedicated background worker and fold their result back into the view on the next frame, so typing,
  scrolling, and input stay responsive while the command runs. The ambient chat-list re-read that a notification for a
  non-selected chat triggers runs on that same worker (behind any queued mutations, so a re-read reflects a send that
  preceded it), so a notification burst never blocks key handling either. Each shows honest in-flight feedback
  (`sending...`, `loading chat...`, `searching...`, `loading invites...`, `loading group detail...`, and a
  `loading chat...` placeholder in the message pane) and reports the outcome when it lands. User-initiated mutations
  keep their submission order (a single worker drains a FIFO queue), optimistic send rows keep their by-id upsert
  semantics, and a result whose target the user has already moved past — an open-chat load for a chat they left, a
  search whose query changed, an invites list or a chat re-list whose account changed — is dropped instead of
  clobbering the current view. A same-chat reload merges its page by id rather than replacing, so a live subscription
  insert during the load window survives. Failures are still caught to the status line and never tear down the session.
  Genuinely modal or rare flows (login/create-identity, logout, daemon start/stop, popup submits such as
  rename/add-member/follow, profile, relay health, and stream compose) stay synchronous. No JSON response shapes
  changed.
- TUI: `j`/`k` in the chat list now live-previews the highlighted conversation while focus stays on the list
  (flick-through browsing). The preview is debounced to ~150ms of quiet after the last movement, so racing through the
  list loads only the chat you settle on rather than one load per row; a preview superseded by further movement is
  dropped, and it marks the previewed chat read the same way opening it does (it is on screen — matching the reference
  client's select-clears-unread precedent). The composer's send target follows the previewed chat (WYSIWYG), and the
  messages-pane title now names the loaded chat (terminal-safe, shortened, falling back to "Messages"), keeping the
  `[N older | M newer]` overflow annotation alongside — so the pane always shows which conversation you are reading and
  sending to, whether it was opened or previewed. `Enter` is unchanged — it opens the highlighted chat and moves focus
  to the message pane, cancelling any pending preview; opening the chat already settled in the pane is a focus move
  only (no redundant reload). No JSON response shapes changed.
- TUI: inline images are no longer pixelated, and `o` now shows the actual image on pixel-capable terminals. Inline
  previews stay cell-exact half-blocks but downscale through a proper resampling filter (Lanczos3) instead of
  `ratatui-image`'s nearest-neighbor default, so the 8-row preview reads as a legible thumbnail. On a terminal whose
  startup capability query reported a real pixel protocol, the `o` full-size viewer draws the image with that native
  protocol (inside an iTerm2 session the misdetected kitty answer is overridden to iTerm2's own inline-image
  protocol); every popup close now forces a full terminal clear and repaint so a terminal-side image can never linger
  after dismissal. Decoded images are capped to a 2100x1400 fit box at decode time — a general memory bound on every
  decode, so neither the inline preview nor any retained copy ever holds an unbounded camera-photo pixel buffer.
  Separately, viewer pixels are retained in memory only: at most four viewer copies are kept (oldest evicted first,
  worst case ~47 MB), so the decrypted download artifact is still removed right after decode and nothing is written
  back to disk. That ~47 MB bounds the viewer pool only. The inline image maps are decode-capped per image but not
  bounded in aggregate: every image scrolled past keeps one decode-capped protocol (at most ~11.8 MB) alive for the
  life of the session, so the session ceiling is ~47 MB plus that per-image cost times the images ever rendered, not
  ~47 MB flat. LRU-bounding that inline retention needs re-download support (status un-tracking plus re-entrant
  downloads) and is a deliberate follow-up, not this change. The Lanczos3 downscale runs synchronously on the render
  thread and is cached per target size, so
  scrolling never re-resizes; changing the terminal width does re-resize every visible image on that one frame, an
  accepted cost of the sharper preview. Halfblock-only terminals, and evicted images, keep the cell-exact viewer popup.
- TUI: unread badges are now runtime-backed instead of counted in the TUI. Each chat row's badge and the status
  bar's `{u} unread` total derive from the `chats list` projection (`unread_count`), so they survive a TUI restart;
  the TUI-local unread tally and its plain-`messages subscribe`-feed counting are gone (that feed now serves only
  QUIC stream previews). Chat rows gained a wn-tui-style last-message preview line (sender plus truncated text, dark
  gray; group-system rows render their summary, deleted rows a tombstone), and the chat list orders by last activity
  (`last_message.timeline_at` descending; equal-activity chats keep the `chats list` order). Opening a chat clears
  its badge immediately by calling `chats mark-read` and folding the returned projection (a failed mark-read leaves
  the badge untouched and surfaces on the status line — never zeroed locally). Live badge/preview deltas for the open
  chat ride the `messages timeline subscribe` feed's `chat_list_row`; for other chats the TUI consumes
  `notifications subscribe` and, on a NewMessage for a non-selected chat, does one debounced `chats list` re-read per
  tick (notification events deduplicated by `notification_key`), run on the background worker rather than the event
  loop. Group-invite notifications surface as a status-line notice. Background re-lists and reorders keep the
  highlighted chat selected by group id. No JSON response shapes changed.

### Security

- `wn-agent import-identity` keeps secret material out of argv, environment,
  output, and bootstrap/config artifacts; rejects symlinked, shared, or
  non-regular credential files; verifies the expected public identity before
  persistence; and makes duplicate or interrupted imports recoverable.

### Fixed

- OpenClaw inbound agent replies now travel through the registered message
  adapter and are durably routed back to the source Marmot channel with reply
  threading and idempotent retry. Inbound live previews are temporarily
  final-only so durable delivery has a single owner.
- Hermes setup now uses persisted gateway configuration for readiness, installs
  the Marmot sender-authorization policy without losing rollback metadata, and
  rejects ambiguous environment-only dry runs. Hermes and OpenClaw also detect
  existing account profiles before onboarding instead of overwriting them when
  relay lookup succeeds.
- Hermes streaming previews now recognize and remove Markdown-balancing
  backticks that Hermes appends after its streaming cursor, preserving the
  append-only preview transcript instead of misclassifying the update as a
  durable final.
- TUI chat ordering now follows the durable `activity_sort_at` anchor exposed on
  `chats list`/`subscribe`/`mark-read` rows (and timeline `chat_list_row`
  updates) instead of re-sorting by `last_message.timeline_at`, so all-pruned
  chats keep their storage position. Equal-activity rows tie-break on ascending
  `group_id`, matching storage.
- TUI: main-view keyboard accelerators now fire only on a plain keypress and ignore `Ctrl`/`Alt` chords. Previously
  `Ctrl-U` in the message pane matched the bare `u` (unreact) accelerator and published an unconfirmed reaction
  removal, and `Ctrl-Q` quit through the bare `q` accelerator. The whole accelerator family (`r`/`u`/`d`/`R`/`o`/`i`
  and `g`/`G` in the message pane, `q`/`A`/`s`/`p`/`h`/`I` and `j`/`k` list navigation elsewhere) is now guarded, while
  `Ctrl-U` stays the composer kill-line and `Ctrl-C` still quits. `Shift` is still tolerated, so the uppercase
  accelerators keep working under the kitty keyboard protocol. No JSON response shapes changed.
- TUI: logging out now reports the outcome faithfully when the follow-up account-list reload fails. Previously a reload
  failure after a successful, irreversible wipe was reported with an `error:` prefix while the removed account and its
  stale subscriptions lingered on screen. The logout is now reported as done and the status names `/refresh` to retry
  the reload; a failure of the wipe itself is still reported as an error. No JSON response shapes changed.
- TUI: a message-interaction command typed with a leading space now shows the armed-interaction hint and can be
  cleared with `Esc`, matching how it submits. `parse_slash_command` already trims the composer text, so `/react`,
  `/reply`, and `/delete` submit even with surrounding whitespace; the armed hint and the `Esc` escape hatch now trim
  the same way instead of treating a space-prefixed command as an invisible, un-clearable armed state. Plain text with
  a leading space is still a hand-typed draft and is preserved by `Esc`. No JSON response shapes changed.

## [0.9.7] - 2026-07-26

### Fixed

- Agent text-stream QUIC starts now accept zero broker candidates for durable
  final-message fallback, validate complete candidate values against the
  adopted 512-byte authority rules, preserve ordered candidate failover, and
  durably reserve encrypted publisher sequences so repeated `stream send`,
  reconnect, or daemon reuse cannot restart at sequence 1 for one start.
  Zero-candidate daemon compose returns a `streaming` payload with
  `candidate: ""` for TUI and script consumers instead of failing the start.
- KeyPackage deletion during sign-out, wipe, and explicit deletion now uses one
  scoped, account-bound relay connection set for the complete batch instead of
  cold-connecting a throwaway client for every deletion event. Relay
  acknowledgement and local-cache removal remain tracked per event.
- The Hermes plugin now maps explicitly non-final assistant commentary to
  durable kind-1201 agent activity while retaining kind-9 delivery for final
  answers and compatibility with Hermes versions that do not yet provide
  delivery metadata.

### Security

- Updated `quinn-proto` and `crossbeam-epoch` to patched releases, clearing the
  active RustSec vulnerabilities in the QUIC and OpenMLS dependency paths.
  Also removed the remaining unsoundness and yanked-package findings without
  adding audit ignores; unmaintained-only dependencies remain tracked in
  issue #1116.

## [0.9.6] - 2026-07-26

### Added

- MarmotKit now exposes account-signed public profile-image uploads to Blossom,
  with validated raster content and returned HTTPS URLs.
- MarmotKit profile metadata now includes an optional `banner` field while
  preserving the existing banner when partial updates omit it.

### Fixed

- `keys list` now reports every durably device-owned KeyPackage, including
  retained private material, and merges relay visibility without losing
  distinct relay event ids.
- MarmotKit key-package ownership now reflects durable, Welcome-usable private
  material across manual publication, automatic maintenance, and runtime
  restarts; matching relay events merge with their local record.

## [0.9.5] - 2026-07-25

### Changed

- TUI: `a` on a user-search result now picks which chat the found user is added to. It opens a group picker over the
  loaded chats list (`j`/`k` move, `Enter` picks, `Esc` closes without side effects), one row per chat in the list's
  order with the open chat preselected when one is loaded; `Enter` then opens the same confirm popup that guards the
  add (`groups add-members`), naming both the user and the chosen chat. With no chats a status notice explains and
  points at `c` (start a new chat with the found user). Previously the action targeted only the open chat and errored
  without one. No JSON response shapes changed.
- TUI: made the armed message-interaction state durable and guarded reaction content, fixing a field report where a
  user armed `/react` (via `r`), did not register the prefill, typed a whole message, and published his prose as a
  reaction. While the composer begins with `/react`, `/reply`, or `/delete`, the hints line now shows a persistent
  hint recomputed each frame from the composer text and the selected row — `reacting to <sender>: <preview> — Enter
  sends the reaction, Esc clears` — instead of a one-shot status a later event could overwrite. `Esc` clears an armed
  interaction prefill (pristine or edited) as that escape hatch, while leaving a hand-typed draft intact; `Ctrl-U` is
  the readline kill-line that clears the whole composer whatever it holds (armed prefill or hand-typed draft) and also
  clears the masked nsec-entry field, so the idle composer hint reads `Enter send  Ctrl-U clear`. `/react` accepts
  only one emoji — exactly one grapheme cluster carrying a non-ASCII scalar (real emoji, including ZWJ families, skin
  tones, flags, and keycaps), or the NIP-25 `+`/`-` sentinels — and refuses anything else (multi-word prose,
  plain-ASCII tokens, and non-Latin or accented words like `café`, `你好吗`, and `привет`) with `reactions are a single
  emoji (Enter sends the default +); Esc clears`. The `messages react` CLI command stays protocol-faithful and is
  unchanged. No JSON response shapes changed.
- TUI: `R` on the selected message replies to it. It prefills `/reply` followed by a space in the composer
  (draft-protected like the `r`
  and `d` accelerators) and names the reply target on the status line; you type the reply and `Enter` sends it. Also
  available as the `/reply <text>` slash command. The target resolves at submit against the selected row (a clear
  status-line error when nothing is selected), the send runs `messages send --group <loaded-group> --reply-to
  <selected-message-id> <text>` with `--reply-to` before the text as the guard requires, and the sent reply upserts
  optimistically without a list reload.
- TUI: added three full-view screens reached from the chat list — user search (`s` or `/users [query]`), your own
  profile (`p`), and relay health (`h`) — each a one-shot load that returns to the main view on `Esc`. User search runs
  `users search` (default radius `0..2`) over the cached follow graph; its two-region screen types the query in query
  focus (`Enter` runs it) and navigates results in results focus, where `Enter` opens a profile card (`users show`),
  `c` starts a new chat, and `a` adds the user to an existing chat (via the group picker described above) — both
  return to the main view on the affected chat on success. Profile shows your
  `profile show` fields (picture URL as literal text — no avatar fetch) and `follows list`; editing a field publishes
  only that field via `profile update --<field>`, `f` follows (`follows add`) and `x` unfollows (`follows remove`), and
  there is no nsec export. Relay health renders the redacted `relay-stats` snapshot — health summary, counters,
  delivery spread with histogram p50/p99, sync timing, and per-relay first-deliverer/timing rows keyed by an opaque
  device-local index — with no relay URLs shown (privacy decision); `r` refreshes and `j`/`k` scroll. The popup system
  gained profile-field-edit, follow-by-pubkey, new-chat-name, unfollow, and add-to-chat purposes; help and the hints
  lines cover the new screens. No JSON response shapes changed.
- TUI: added a modal popup system and a group-detail screen. One `Option<Popup>` captures every key while open
  (the screen behind it is inert), with text-entry, confirm, list-picker, and dismiss-on-any-key card variants; the
  help overlay became a card, which fixes `q` under help quitting the app. `g` on the selected chat opens a
  group-detail screen showing members (with admin and `(you)` badges), relays, and name/description loaded on entry
  from `groups members`/`groups admins`/`groups relays`/`groups show`; from it `A` adds a member (`groups
  add-members`), `x` removes one (`groups remove-members`), `P` promotes to admin (`groups promote`), `R` renames the
  group (`groups rename`), and `L` leaves (`groups leave`) — an admin is blocked from leaving with a "Cannot Leave
  Group" info card (sole-admin vs step-down message) while a non-admin gets a confirm, and `?` shows the help card.
  `I` (from the chat list or group detail) opens a pending-invites picker over `groups invites`, accepting
  (`groups accept`) or declining (`groups decline`) in place; the picker stays open across actions and closes only
  once no invites remain, and accepting from the group-detail screen returns to the main view. The group-invite
  status notice now prompts `I`. No JSON response shapes changed.
- WN Agent control clients and the connector now speak the incompatible `marmot.agent-control.v2` protocol.
  `stream_begin` returns a random per-stream bearer capability that every later stream operation must present; exact
  request-id retries return the original begin receipt, and stream-id collisions no longer replace active sessions.
- WN Agent documentation and command help now state that a configured control token replaces peer-UID authorization
  and grants the full API for every hosted account. Separate trust domains require separate connector instances.
- TUI: adopted a chat-first shell. A screen model replaces the fixed four-pane dashboard: a login/account-select
  screen (create identity, nsec login, or pick from several accounts) opens when there is no single obvious account,
  and the main view is the chat list plus the message timeline plus the composer, with the reclaimed space going to
  the chat/messages row. The 12-row status panel and 3-row header collapse into a one-line status bar
  (`{account} · daemon {on|off} · {n} chats · {u} unread · {latest status}`) and a per-focus hints line. Default
  focus is the chat list, so `j`/`k` works immediately; `Enter` opens a chat and focuses the messages pane; `A`
  reopens the account picker. Group MLS/component diagnostics move behind a new `/diagnostics` slash command that
  toggles a diagnostics panel above the composer. An explicit `--account`/`WN_ACCOUNT` selection that resolves to a
  loaded account opens the main view directly, even when several accounts exist. No JSON response shapes changed.
- TUI: the messages pane now renders the materialized message timeline (`messages timeline list` /
  `messages timeline subscribe`) with reactions, reply context, deletion tombstones, and `[img name]`/`[file name]`
  media placeholders. Scrolling uses a
  message-offset model — `j`/`k` select, `G`/`g` jump to newest/oldest, `PageUp`/`PageDown` page, and scrolling past
  the oldest loaded message pages in older history; incoming messages hold your position unless you are pinned to the
  bottom. Timestamps render in local wall-clock time. No JSON response shapes changed.
- TUI: rewrote the composer with a cursor-editing input. `Left`/`Right`/`Home`/`End` move the cursor,
  `Backspace`/`Delete` remove a character, and mid-string edits keep multi-byte characters intact. `Enter` still
  submits and there is no keyboard newline; multi-line content arrives only by paste (bracketed paste keeps its
  newlines). The composer auto-grows with its wrapped content up to 8 rows, taking the space from the messages pane.
  The login nsec-entry field reuses this input's masked mode. No JSON response shapes changed.
- TUI: unread badges are now runtime-backed instead of counted in the TUI. Each chat row's badge and the status
  bar's `{u} unread` total derive from the `chats list` projection (`unread_count`), so they survive a TUI restart;
  the TUI-local unread tally and its plain-`messages subscribe`-feed counting are gone (that feed now serves only
  QUIC stream previews). Chat rows gained a wn-tui-style last-message preview line (sender plus truncated text, dark
  gray; group-system rows render their summary, deleted rows a tombstone), and the chat list orders by last activity
  (`last_message.timeline_at` descending; equal-activity chats keep the `chats list` order). Opening a chat clears
  its badge immediately by calling `chats mark-read` and folding the returned projection (a failed mark-read leaves
  the badge untouched and surfaces on the status line — never zeroed locally). Live badge/preview deltas for the open
  chat ride the `messages timeline subscribe` feed's `chat_list_row`; for other chats the TUI consumes
  `notifications subscribe` and, on a NewMessage for a non-selected chat, does one debounced `chats list` re-read per
  tick (notification events deduplicated by `notification_key`). Group-invite notifications surface as a status-line
  notice. Background re-lists and reorders keep the highlighted chat selected by group id. No JSON response shapes
  changed.

### Added

- Durable KeyPackage and group self-update maintenance. KeyPackages now rotate under one stable kind-30443 `d` slot
  with exact signed-event retry, persisted lifetime/refresh/retry state, consumed-key retention until replacement
  acknowledgement, and no routine kind-5 deletion. New `keys maintenance-status` and `groups maintenance-status`,
  `schedule-self-update`, `maintenance-policy`, `pause-maintenance`, `resume-maintenance`, and `run-maintenance`
  commands expose the lifecycle. New groups are periodically enrolled by default; existing groups remain manual-only.
  Successful application-send JSON now includes `maintenance_disposition` without blocking sends while post-join
  rotation is pending. ([#1103](https://github.com/marmot-protocol/mdk/pull/1103))
- TUI: `/logout` removes the currently selected account. `wn logout` is destructive — it permanently erases the
  account's local data (messages, group membership, and MLS state) from this device and, for a local-signing account,
  deletes its signing key too — so the confirmation scales to the consequence. A local-signing logout is irreversible,
  so it requires typing the literal word `logout` and pressing `Enter`; an empty or mismatched entry keeps the popup
  open (so the wipe is never reachable by a stray Enter-then-Enter) and `Esc` cancels. A public-only account is
  re-addable and keeps the lighter `y`/`Enter` confirm (`n` or `Esc` cancels). The confirmation body states the
  consequences plainly, never softens the wording, tailors the irreversibility line to the account type (a public-only
  account has no key to erase), and always shows the account npub so it is unambiguous which account is destroyed. On
  confirmation the command runs, the account list reloads, and the TUI lands on a remaining account or drops back to the
  login menu when the last account is removed — never left pointing at a removed account or a stale subscription. Listed
  in the in-app help card and slash-command suggestions. No JSON response shapes changed.
- TUI: inbound media renders inline in the message pane. Image attachments are downloaded and decoded off the event
  loop (a worker thread runs `wn media download <group> <plaintext-hash> --output <cache path>` and the `image`
  decode, delivering the result over an `mpsc` channel drained on tick) and drawn via `ratatui-image` as cell-exact
  half-block glyphs (`▀` colored cells) on any image-capable terminal. The fidelity choice is deliberate: half-blocks
  are ordinary colored cells rather than a native pixel image (iTerm2/Kitty/Sixel), so an image is bounded strictly to
  its reserved block and can never overdraw a neighboring message or leave a terminal-side artifact behind on scroll.
  Placeholders walk `[img name]` -> `[downloading name...]` -> `[loading name...]` -> the image, or
  `[name failed: err]`, and stay `[img name]` on a terminal with no image capability. `o` opens the selected message's
  image full-size (same cell-exact rendering) in a dismiss-on-any-key viewer. Decrypted files cache under the TUI home
  in `tui-media-cache/`. No JSON response shapes changed (the existing `media download --json` `output_path` is passed
  via `--output`).
- TUI: message interactions on the selected message. New `/react [emoji]` (default `+`), `/unreact`, `/delete`, and
  `/retry <event-id>` slash commands call the real `messages react|unreact|delete|retry` commands; keyboard
  accelerators `r` (prefills `/react` followed by a space), `u` (removes your reaction immediately), and `d`
  (prefills `/delete`) drive
  them from the messages pane. Reaction and deletion results fold in from the timeline projection, so the list is not
  reloaded on success. `/delete` is refused for messages you did not send, and `/retry` takes an event id rather than
  acting on the selection because timeline rows carry no per-message failed-send state. No JSON response shapes
  changed.
- Markdown autolinks now carry a renderer-facing destination classification across Rust and MarmotKit surfaces. The
  original destination is preserved, while web, contact, app, public Nostr, relative, unknown, dangerous, and
  sensitive targets are distinguished for client policy.
- Explicit Markdown links and images now carry the same destination classification, including reference-style links,
  so clients can independently decide whether to navigate to or fetch an untrusted target.
- `wn tui` gained optional `--discovery-relays` and `--default-account-relays` flags (comma-separated, matching
  `wn daemon start`). They are forwarded to the `daemon start` child and to `create-identity`/`login` account setup
  so a first run with no relay configuration can supply relays without dead-ending. Flag passthrough only; no JSON
  response shapes changed.
- `wn messages send` (and the older `wn message send`) accept `--reply-to <message-id>` to send the text as a reply to
  an existing message. The reply carries the same `q`/`e` reference tags other Marmot clients produce, so recipients'
  timelines parse it into `reply_to_message_id` with a hydrated `reply_preview`. `--reply-to` is additive input only:
  the JSON response shape is unchanged, pass the group with `--group` when replying, and a reply to a not-yet-synced
  parent is still sent (its preview hydrates when the parent arrives). No new runtime API was needed; the CLI routes
  reply sends through the existing `MarmotAppRuntime::reply_to_message`. Because the trailing message text is
  hyphen-tolerant, a `--reply-to` placed *after* the text (either spelling: `--reply-to <id>` or `--reply-to=<id>`) is
  read as literal text; rather than silently sending that stray flag as part of the body, the send now fails loudly with
  error code `reply_to_after_message_text` (put `--reply-to` before the text with `--group`). Tradeoff: the guard
  rejects any message whose text contains a bare `--reply-to` or `--reply-to=<id>` token anywhere (e.g.
  `hello --reply-to friend`), so such text can no longer be sent this way.
- `chats list`, `chats list-archived`, and the `chats subscribe`/`subscribe-archived` feeds now project the runtime's
  durable per-chat state onto each chat row as additive JSON keys, so a chat list can render unread badges and a
  last-message preview without a second query. New keys: `unread_count` (number), `has_unread` (bool), `last_message`
  (`{ message_id_hex, sender, sender_display_name, plaintext, kind, timeline_at, deleted }` or `null`),
  `last_read_message_id_hex` (string or `null`), and `last_read_timeline_at` (number or `null`). The names and the
  `last_message` shape match the `chat_list_row` object already emitted on the `messages timeline subscribe` feed so
  the two feeds agree; a chat with no messages or reads yet reports empty defaults (`0`/`false`/`null`) rather than
  omitting the keys. All existing chat-row keys are unchanged.
- `chats mark-read <group-hex> [<message-id-hex>]` advances a chat's read marker and clears its unread count, giving the
  chat-list projection a CLI read path (previously unread cleared only when the account itself sent into the chat). With
  no message id it marks the newest message read (the "clear on chat open" case); with an explicit message id it marks
  read up to that message. The read marker is a forward-only high-water mark, so marking an older message leaves newer
  ones unread and re-marking never moves it backward; a chat with no messages is a no-op success. The JSON response
  carries `account_id`, `npub`, `group_id`, and the refreshed projection as the same five keys the chat rows expose
  (`unread_count`, `has_unread`, `last_message`, `last_read_message_id_hex`, `last_read_timeline_at`).
### Fixed

- `wn relays add/remove --type nip65` now round-trips the complete directional NIP-65 list instead of deleting
  read-only relays or flattening existing role markers. Relay-list JSON adds `read_relays` and `write_relays` alongside
  the existing write-target `relays` view.
- Release builds now fail app startup with a clear error when `WN_DEV_SETTLEMENT_QUIESCENCE_MS` is set instead of
  allowing it to override the protocol-pinned convergence window. Debug builds retain the override for local
  development and integration tests.
- `wnd` streaming subscription responses now have a 15-second whole-frame write deadline, including socket flush, so
  a client that stops reading cannot retain a connection permit indefinitely.
- `wnd` one-shot responses now apply the same deadline across write, flush, and socket shutdown, preventing a
  non-reading local client from pinning status, stop, or command workers.
- `wn-agent` now denies path-based media sends by default and accepts only regular, non-symlink files beneath explicit
  repeatable `--media-allowed-root` directories. Bundled Hermes and OpenClaw launchers stage short-lived copies in a
  dedicated approved directory and clean them up after each send.
- `wn-agent` replaced the ambiguous `--allow-any` invite bypass with `--dev-allow-any-invites`, requires
  `--debug-controls` alongside it, warns when the policy is active, and still rejects welcomes that lack an
  MLS-authenticated author.
- `wn-agent` now applies a 15-second whole-operation deadline to the initial unauthenticated control frame and to
  request-scoped QUIC candidate DNS lookup, preventing silent or slow peers from pinning connection permits forever.
- Every `wn-agent` control response and inbound-subscription event write now has the same 15-second whole-frame
  deadline, including socket flush, so a non-reading client cannot retain a connection permit indefinitely.
- `wnd` now caps long-lived subscriptions at 64 within its 256-connection global ceiling, preserving one-shot status,
  shutdown, and command capacity. Quota rejection is reported as the typed `server_busy` protocol error instead of an
  empty response that could be mistaken for a stopped daemon.
- `wn-agent` now caps `SubscribeInbound` streams at 16 within its 64-connection global ceiling, and both quota
  boundaries return a typed `server_busy` response so subscriptions cannot starve durable one-shot operations.
- Public Nostr relay connections now require `wss://`; `ws://` is limited to loopback development relays behind
  `WN_ALLOW_LOOPBACK_RELAYS`.
- Received-message chronology and retention now use the MLS-authenticated inner app-event timestamp instead of the
  replayable outer Nostr event timestamp. Runtime, daemon JSON, and MarmotKit surfaces expose that send time alongside
  the device-local observation time.
- WN Agent, Hermes, and OpenClaw now carry the triggering prompt message id on agent text-stream start events through
  the protocol `parent` tag, preserving the durable reply chain after timeline reloads.
- Encrypted media uploads now fail over, in order, across a default list of Blossom endpoints that accept opaque
  `application/octet-stream` ciphertext, and encrypted group-image uploads use that list's primary endpoint, replacing
  the media-only Primal default that returned HTTP 415. Blossom upload failures also retain bounded, privacy-filtered
  server rejection reasons for actionable diagnostics. Group images store no endpoint in group state, so clients
  compiled with different defaults resolve them against different endpoints until the group image is re-set on a
  current build.

### Security

- TUI: inline media no longer leaves decrypted image files in the home directory. The decrypted download artifact is
  removed immediately after it is decoded (on both the success and decode-failure paths) instead of accumulating under
  `tui-media-cache/`, and any files a prior crashed session left behind are swept from that directory at startup. The
  files had no reuse value — the viewer draws the in-memory image and a new session never reads them — so they were
  decrypted plaintext at rest, outliving message deletion, with nothing to gain by keeping them.

## [0.9.4] - 2026-07-10

### Added

- MarmotKit/UniFFI now exposes encrypted per-account composer draft storage with metadata-only list, full load, upsert,
  and delete operations. Drafts retain their text, reply target, ordered attachment bytes, and attachment presentation
  metadata in the account's SQLCipher database; attachment bytes are loaded only for the selected draft.
- MarmotKit/UniFFI now exposes the cached Nostr Kind 0 `website` field through a read-only profile accessor so app
  profile surfaces can display it without widening the writable profile record.

## [0.9.3] - 2026-07-07

### Added

- Added host-provided external signer account support for app integrations whose Nostr private key stays outside MDK.
  UniFFI can now register/login external signer accounts, account summaries expose whether signing is local or
  external, and runtime signing paths cover media upload auth, push/gift-wrap publishing, relay auth, directory
  publishing, and account identity proofs.
- UniFFI now exposes encrypted Blossom group avatars to host apps through `AppGroupRecordFfi.image_hash_hex` and
  `download_group_blossom_image`, allowing clients to detect, cache, fetch, verify, and decrypt encrypted group avatar
  images.
- Added production-shaped `wn-opencode` release packaging alongside `wn-agent`: versioned harness binaries, the
  `install-opencode-marmot.sh` installer, service setup paths, deterministic installer tests, and connector E2E
  coverage.
- Added SafeAAD app-component support advertisement so engine leaves declare support for the SafeAAD component and reject
  attempts to override it as caller-supplied group component data.

### Changed

- Account identity proofs now use a v2 canonical unpublished Nostr event signature, making account setup compatible
  with platform signers that can sign Nostr events but do not expose raw digest signing.
- WN Agent non-draft releases refresh `wn-agent-latest` installer aliases for Hermes, OpenClaw, and OpenCode while
  keeping versioned release assets pinned to their immutable `wn-agent-v<version>` release.
- Release metadata now uses standardized titles across the MDK, WN Agent, and MarmotKit tracks, and the new
  `just release-all <version>` coordinator cuts the whole cohort from one checked `origin/master` commit.

### Fixed

- Android MarmotKit binding generation now keeps the host UniFFI dylib unstripped and fails loudly if Kotlin output is
  missing, avoiding empty binding bundles when release builds set `RUSTFLAGS="-C strip=symbols"`.
- External signer account setup now discovers existing account profiles before setup and keeps account discovery
  relay-scoped.
- Push owner proof verification accepts the new event-based proof while retaining legacy verification fallback for
  already-published owner proofs.

## [0.9.2] - 2026-07-06

### Changed

- Workspace version unified at `0.9.0` across all crates (successor to MDK `0.8.0`).
- Documentation refresh: current-state inventory, missing crate READMEs, agent integration agent maps, and release
  doc alignment.
- The TUI now supports `/image <file-path> [caption]` by calling the real encrypted `wn media upload --send` path for
  the selected chat instead of rejecting image sends or inventing a plaintext placeholder.
- `wn groups invites`, `wn groups accept <group>`, and `wn groups decline <group>` now use the app runtime's
  pending-invite state and accept/decline paths instead of returning `unsupported_command`.
- `wn notifications subscribe` is now visible in help and streams daemon-backed local notification updates instead of
  returning `unsupported_command`.
- `wn keys list` now returns KeyPackage event ids and local/relay origin, and `wn keys delete` / `wn keys delete-all
  --confirm` publish real Nostr deletion events through the app runtime.
- The daemon-backed `wn stream compose-open`, `compose-append`, `compose-finish`, and `compose-cancel` commands are now
  visible in help and return a daemon-required error instead of `unsupported_command` when `wnd` is unavailable.
- `wn chats mute <group> <duration>`, `wn chats unmute <group>`, `/chat mute`, and `/chat unmute` now manage real
  per-chat local notification suppression instead of hiding or rejecting that surface.
- `wn sync` is visible in top-level help as the CLI diagnostic/repair catch-up path. The TUI still rejects `/sync`
  because live updates come from daemon subscriptions.
- `export-nsec`, relay type validation, and confirmation-gated destructive commands now return specific JSON error
  codes instead of sharing a generic unsupported-command shape.
- `wn-agent` stream finalization now accepts idempotency keys, and the OpenClaw/Hermes adapters retry
  `stream_finalize` with stable per-stream keys so a post-write timeout does not duplicate the durable final.
- Hermes dev setup now mirrors OpenClaw by passing custom QUIC preview candidates through the generated
  `bootstrap-agent.sh` helper and syntax-checking every generated helper script in its contract test.
- WN Agent release assets now include Hermes and OpenClaw one-line installers that perform guided full setup for
  `wn-agent`, gateway plugin config, and same-user service startup while preserving existing gateway connectors/channels.
- The Hermes and OpenClaw installers now use connector-specific default homes, service names, and bootstrap labels so
  default installs create separate Marmot/Nostr agent identities on the same machine.
- WN Agent release assets now include the `wn-opencode` Marmot harness and `install-opencode-marmot.sh`, providing a
  service-backed setup path for machines that already have OpenCode installed.
- The OpenCode installer uses the terminal-harness agent home (`~/.marmot-agents/harnesses`) and connector-specific
  `wn-agent` service identity by default, leaving room for future terminal harness backends to share that agent.
- Non-draft WN Agent releases now refresh a `wn-agent-latest` installer-only release so curl setup commands can default
  to the latest connector/harness installers while versioned releases remain available for pinned installs.

### Security

- Every outbound relay connection now passes through one host-safety chokepoint: relay endpoints whose literal host is
  loopback, RFC1918/private, link-local (including `169.254.169.254`), CGNAT, multicast, or IPv6 ULA are rejected before
  a socket is opened, so a poisoned routing record or relay-list event can no longer steer the relay pool at internal
  services (SSRF). Local relays (e.g. an in-process `MockRelay` or a dev `nostr-rs-relay`) are reachable only when
  `WN_ALLOW_LOOPBACK_RELAYS=1` is set, mirroring `WN_ALLOW_LOOPBACK_BLOB_ENDPOINTS`; production installs leave it unset.
- The `wn-agent` connector no longer connects to an agent-supplied `quic://` broker candidate that resolves to a
  non-public address, and no longer derives no-cert-verification (`insecure_local`) trust from a candidate that merely
  resolves to loopback. Loopback brokers are reachable, without certificate verification, only when `wn-agent serve` is
  started with the new `--insecure-local-broker` dev flag and the candidate host is a literal loopback (SSRF + trust
  downgrade hardening).
- The `wnd` daemon control socket (and the `wn-agent` connector socket) is now created owner-only (0600)
  atomically — bound inside a private 0700 staging directory and linked into place — instead of being chmod-ed
  after `bind`, removing the brief window where the socket was reachable at umask-default permissions (for
  example under a caller-supplied `--socket` in a pre-existing shared directory).
- Daemon auto-watch of inbound agent stream starts (kind:1200) no longer derives no-cert-verification
  (`insecure_local`) trust from the sender-controlled `quic://` candidate, and QUIC candidate resolution now rejects
  sender-provided candidates that resolve to loopback, RFC1918/private, link-local (including `169.254.169.254`),
  multicast, unspecified, broadcast, IPv6 unique-local (ULA), or IPv6 unicast link-local endpoints. Local endpoints are
  only reachable when the local user explicitly passes `--insecure-local` (SSRF + trust downgrade hardening).
- The direct and broker QUIC preview transports now share one hardening profile: the `marmot-quic-broker` no longer
  enables replayable TLS 0-RTT early data (an off-path attacker could replay captured publish control frames to
  create/feed rooms); every preview dial (`wn stream send/watch`, broker publish/subscribe) is bounded by a 15 s
  connect timeout and a client-side idle/keepalive transport config; `wn stream receive` bounds its wait for a sender
  to dial (300 s) and the TLS handshake; broker control frames are capped at 256 bytes pre-auth (previously a peer
  could demand a ~66 KB allocation per stream before validation); and broker frame reads apply one deadline across the
  whole frame, so a peer dribbling one byte per timeout window can no longer stretch pre-auth reads.
- Group creation now enforces the same admin-policy invariants every commit already enforces. A group can no longer be
  created listing an admin who is not one of the initial members (a "phantom" admin that would silently gain admin
  rights the moment a matching member joined, with no admin-grant event anyone observes), and admin identities are
  validated as real secp256k1 keys rather than accepted on length alone. The engine-owned profile and admin-policy
  components are also non-negotiable: an invitee whose KeyPackage omits them is rejected up front instead of the group
  being created with an empty admin set that permanently freezes all membership changes. Welcome-join applies the same
  admin-leaf check before accepting a group.
- A single group member can no longer permanently disable another member's ability to send by broadcasting one crafted
  far-future-epoch message. The convergence send-gate now bounds the future side of the horizon the same way it already
  bounds the past: a buffered convergence input more than `max_rewind_commits` epochs ahead of the group tip (which can
  never chain from the tip) no longer counts as unresolved work, and a convergence row that fails to decode/project now
  fails open instead of closed. Previously such an input left the group reporting "unsettled" forever, so every outbound
  send was queued and never drained, with no recovery short of manual database surgery.

### Fixed

- `wnd` now buffers daemon request frames before scanning for the newline delimiter, avoiding one async `read()` call per
  byte for large `Execute` requests while preserving the existing 1 MiB request cap and stalled-client timeout.
- A legitimate long agent preview (more than 4096 records or 1 MiB of cumulative deltas) is no longer silently
  terminated mid-stream by the QUIC broker: the broker's publish path previously enforced the subscriber-sized receive
  defaults on the publisher and closed the room when they tripped. Forward-role limits now come from broker
  configuration (see the new `--publish-max-records` / `--publish-max-frame-bytes` flags) with defaults far above
  the receive defaults; subscribers still enforce their own receive limits. The byte bound counts record frame bytes
  as forwarded on the wire (ciphertext, including the per-record AEAD tag, for encrypted previews) since the broker
  never decrypts.
- A single non-UTF-8 frame on a text-bearing preview record no longer tears down the whole received preview (direct
  receive and broker subscribe): the frame renders as replacement characters and the stream continues. Transcript
  hashing covers the raw bytes, so sender/receiver transcript verification is unaffected.
- A subscriber joining a broker room with a large retained backlog no longer copies the backlog while holding the
  broker-wide lock (records are now reference-shared), so one subscribe cannot head-of-line-block publish/forward
  across every other room.
- A group copy that realized your own removal no longer stays self-quarantined when the removing commit later loses
  branch selection: the convergence apply clears the removed marker whenever the selected canonical branch records your
  membership, so `message send` works again on that group instead of failing `invalid_transition` ("local group copy is
  marked removed"). The removal's system rows are withdrawn through the existing invalidation event; rejoining via a new
  Welcome is only required while the removal remains canonical.

### Changed

- `marmot-quic-broker` gained `--publish-max-records` (default 65536) and `--publish-max-frame-bytes` (default
  64 MiB) flags bounding what the broker forwards per publish stream (frame bytes counted as carried on the wire);
  both appear in the startup output. The broker's
  publish path also now applies the same generous 120 s quiet-gap deadline to record reads that the direct path and
  the subscriber loop already used, so an alive-but-wedged publisher (kept alive by QUIC keepalives) can no longer pin
  a room indefinitely; agents quiet for under two minutes between records are unaffected.

- **Breaking:** retired the experimental "darkmatter" naming. The crate is now `wn-cli` and installs the `wn` CLI and
  `wnd` daemon; the connector daemon is `wn-agent`. Env vars moved from `DM_*` to `WN_*` (`WN_ACCOUNT`, `WN_RELAY`,
  `WN_SOCKET`, `WN_SECRET_STORE`, `WN_HOME`, `WN_KEYCHAIN_SERVICE`, `WN_ALLOW_LOOPBACK_BLOB_ENDPOINTS`,
  `WN_DEV_SETTLEMENT_QUIESCENCE_MS`), the default data directory moved from `darkmatter` to `whitenoise` (dev fallback
  `.whitenoise`), the default keychain service is `com.marmot.whitenoise`, daemon sockets are `wnd.sock` /
  `wn-agent.sock`, the profile deep-link scheme is `marmot://`, release tags follow `wn-agent-v*`, and the Homebrew
  formula is `marmot-protocol/tap/wn`. There is no automatic compatibility fallback: stop any still-running legacy
  daemon **before** the first `wnd` start (`dm daemon stop` with the old binary, or kill the pid recorded in the old
  data directory's `dev/dmd.pid`) — the renamed socket/pid files make an old `dmd` invisible to `wn daemon status`.
  Then move the data directory (for example
  `mv ~/Library/Application\ Support/darkmatter ~/Library/Application\ Support/whitenoise`), update `DM_*` env vars in
  shell profiles and service units, and reinstall from the new formula. If the data directory is not moved, `wn` starts
  with an empty account list rather than a targeted error. Keychain entries stored under the old
  `com.marmot.darkmatter` service can still be read manually by setting `WN_KEYCHAIN_SERVICE=com.marmot.darkmatter`, or
  re-import the account to write them under the new service.

- `message send` (and every other group send) on a group whose local copy records your own removal now fails with the
  deterministic JSON error code `invalid_transition` ("local group copy is marked removed (self-evicted)") instead of an
  opaque `engine_error`, matching the engine's realized self-eviction semantics (#376).

## [0.2.0] - 2026-06-21

### Added

- Added the `dm-agent` local connector daemon with `serve` and `bootstrap --qr`, bridging Marmot encrypted groups to
  agent gateways through the `marmot.agent-control.v1` Unix-socket NDJSON protocol.
- Added the Hermes Marmot platform plugin (`integrations/hermes/marmot`) and `install-hermes-marmot.sh` for downloading
  versioned `dm-agent` binaries plus the plugin from `dm-agent-v*` GitHub Releases.
- Added the OpenClaw Marmot channel plugin (`integrations/openclaw/marmot`) and `install-openclaw-marmot.sh` for the
  same release cohort; supports durable sends, live QUIC preview streaming, inbound media, reactions, deletes, ambient
  messages, and NIP-27 mention routing through OpenClaw agent tools.
- Added a versioned DM Agent release track (`dm-agent-v<version>`) publishing `dm-agent` for linux-x86_64,
  linux-aarch64, darwin-aarch64, and darwin-x86_64, Hermes and OpenClaw plugin bundles, and pinned installer scripts.
- UniFFI: added `reveal_nsec` to export the selected account private key as `nsec1` bech32 for in-app key backup.
- UniFFI: added NIP-49 encrypted private-key export for password-wrapped backup.
- UniFFI: added per-account `unread_count` without loading a full app session.
- UniFFI: added `retry_group_convergence` for non-duplicating group repair resends.
- Added app-side per-group recovery for hydration-quarantined groups.
- Added engine `sign_out_and_wipe` for full local and remote account teardown, and non-destructive `sign_out` with
  optional relay KeyPackage cleanup.
- Added rich reaction notifications scoped to the reacted-to message author.

- Added `--data-dir` to `dm daemon start` (an alias for `--home`), completing `wnd`/`dmd` setup-flag parity
  alongside the existing `--logs-dir`, `--discovery-relays`, and `--default-account-relays`. The resolved home is
  forwarded to the spawned `dmd` child as before; `--home` still takes precedence when both are given.

- Added `dm groups set-avatar-url <group> --url <https-url> [--dim WxH] [--thumbhash <hex>]` (and `--clear`) to set,
  update, and clear the group URL avatar (`marmot.group.avatar-url.v1`) over the existing app runtime path; a parallel
  legacy `dm group set-avatar-url` form is also available. `dm groups show` / `dm chats show` now surface the
  `avatar_url` component in both human and `--json` output, and an invalid (non-HTTPS / disallowed-host) URL returns
  the stable `invalid_group_avatar_url` JSON error. `set-avatar-url` now requires exactly one of `--url` / `--clear`
  (`--dim` / `--thumbhash` only accompany `--url`), and an explicit empty `--url ""` is rejected as
  `invalid_group_avatar_url` rather than silently clearing the avatar. Human `show` output also surfaces
  `avatar_dim` / `avatar_thumbhash` render hints when present.

- The TUI now renders kind-1210 group system rows as friendly lines (e.g. "alice added bob", "bob left",
  "alice renamed the group") instead of raw JSON. These durable rows are synthesized locally from authenticated group
  state changes (member added/removed/left, admin granted/revoked, group renamed, avatar changed) and appear inline in
  message and timeline history.

- Added `dm relay-stats`, which prints the device-local relay performance telemetry (aggregate lifecycle counters,
  cross-relay arrival spread, per-relay first-deliverer and first-event/EOSE timing, and redacted relay health). The
  command runs against the live `dmd` runtime when a daemon socket exists. Output is aggregate-only and uses opaque
  device-local relay indices — never relay URLs.
- Added Whitenoise-shaped identity and plural command entrypoints: `dm create-identity`, `dm login`, `dm whoami`,
  `dm accounts`, and `dm groups`.
- Added the remaining Whitenoise-shaped top-level command names (`debug`, `logout`, `export-nsec`, `media`,
  `follows`, `profile`, `relays`, `settings`, `users`, `notifications`, and `reset`) with real local behavior where
  the app runtime supports it and explicit `unsupported_command` errors where lower-layer behavior does not exist yet.
- Added `dm chats subscribe`, `dm chats subscribe-archived`, and `dm groups subscribe-state`, which stream typed
  daemon responses for chat rows and group state.
- Added `dm messages search` and `dm messages search-all` over local projected message history.
- Added Whitenoise-shaped cursor flags for `dm messages list`: `--before`, `--before-message-id`, `--after`, and
  `--after-message-id`.
- Added real `dm groups leave` support over the Marmot SelfRemove path, including app-runtime SelfRemove capability
  advertisement.
- Added real `dm groups promote`, `dm groups demote`, and `dm groups self-demote` support over the Marmot admin-policy
  app component.
- Added typed app-message payloads for `dm messages react`, `dm messages unreact`, `dm messages delete`, and
  `dm messages retry` group-convergence retries. Message projections and `messages subscribe` now expose typed
  `app_message` metadata for reactions, deletions, and media references.
- Added `dm media list <group>`, which lists typed media references already projected from group message history.
- Added `dm media upload` and `dm media download` over `encrypted-media-v1` media and Blossom, using
  `https://blossom.primal.net` as the default upload server.
- Added `dm messages subscribe <group>`, a daemon-backed newline-delimited stream that emits typed `message`,
  `agent_stream_start`, `agent_stream_final`, `agent_stream_delta`, and `stream_preview` updates, including live
  brokered QUIC text chunks from runtime-owned stream watch state.
- Added `dm stream watch --background`, which starts a brokered QUIC stream watch through `dmd` and reports
  runtime-managed running/completed/failed preview state through `dm daemon status --json`.
- Added redacted relay-plane health to `dm daemon status --json`.
- Added `dmd --default-account-relays`, matching `wnd` setup flags and applying daemon account-relay defaults to
  daemon-forwarded account creation.
- Added TUI `/stream` slash commands for starting, watching, finishing, verifying, and inspecting brokered agent text
  stream previews from the selected chat.
- Added a TUI status panel below the composer with the latest status line, selected-chat MLS epoch/group/member state,
  and raw app-component data from `dm groups show --json`.
- Added `dm stream start`, `dm stream finish`, and `dm stream verify` for anchoring agent text
  stream starts/finals through normal encrypted Marmot messages and checking QUIC transcript hashes.
- Added `dm stream watch` and `dm stream send --broker` for brokered QUIC preview streams anchored by the
  durable start message.
- Added `dm stream receive` and `dm stream send` for provisional raw QUIC agent text stream previews.
- Added `dm keys rotate` as an explicit repair command that force-mints and publishes a fresh replacement KeyPackage.
- Added TUI unread badges for chats that receive messages while another chat is selected.
- Added a TUI slash-command suggestion popup that opens on `/` and filters as the composer input narrows.
- Added a scrollable TUI messages panel: Tab to the Messages focus and use Up/Down or `j`/`k` to scroll, plus
  PageUp/PageDown and Home/End from any focus. New messages stay pinned to the bottom unless you have scrolled up.

### Fixed

- CLI and daemon command JSON builders now return the existing `invalid_public_key` error instead of panicking if a
  stored account id cannot be converted to `npub`.

- `dm --help`, `dm <subcommand> --help`, and `dm --version` now print to stdout instead of stderr (exit code 0 was
  already correct). Previously every clap parse result — including the help/version display "errors" that carry exit
  code 0 — was routed to stderr, leaving stdout empty and breaking shell piping and scripts (e.g. `dm --help | less`).
  With `--json`, help/version are now reported as `{"ok": true, "result": {"help"|"version": "..."}}` rather than being
  wrapped as an error object; genuine usage errors still go to stderr (and `ok: false` in JSON mode). Routing is gated
  on clap's exit code, not just the error kind: a missing required subcommand (e.g. `dm messages` with no subcommand)
  renders help text but exits nonzero, so it stays a usage error on stderr / `ok: false` instead of being reported as
  successful help output.
- The distributed-convergence canonicalization apply path now persists its multi-write merge atomically. The
  `merge_staged_commit` replay, Marmot group-record refresh, and message-disposition writes that run when a stored
  out-of-order commit is replayed are wrapped in a single SQLite transaction, closing the residual torn-write window
  left after #157/#421 (which only covered the live state-transition paths). A crash mid-merge now rolls back to the
  prior consistent epoch instead of stranding torn group state and an orphaned apply snapshot.
- OpenMLS group state transitions are now persisted atomically. The multi-write commit-merge path (engine state,
  pending-commit cleanup, and OpenMLS value-store updates) is wrapped in a single SQLite transaction, so a crash or
  interruption mid-merge can no longer leave torn group state on disk; the device either advances to the new epoch
  fully or rolls back to the prior consistent state on next load.
- `dmd` now moves peer authorization and request-frame reads onto per-connection tasks immediately after accept, so a
  client that writes a partial frame and stalls can only stall itself; other clients can still reach Ping, Status, and
  Shutdown without waiting for the stalled request timeout.
- `dmd` now handles daemon-forwarded Execute and subscription setup work on spawned connection tasks instead of awaiting
  worker-mutating requests in the single accept loop. `dm daemon status` and `dm daemon stop` remain responsive while a
  long Execute owns daemon worker state; status falls back to a best-effort worker snapshot when that state is busy.
- `dm stream receive`, unanchored `dm stream send`, and foreground `dm stream watch` now stay client-hosted when a
  daemon socket is configured, and direct daemon Execute requests for those long-running stream commands return
  `daemon_forbidden` instead of blocking `dmd`'s accept loop.
- `dm logout` now stays client-hosted when `dmd` is only auto-discovered from the default socket, so signing out works
  while the daemon is running; explicitly socket-targeted logout requests still fail instead of mutating account state
  inside `dmd`.
- Auto-discovered daemon command forwarding now falls back to local execution only when the client cannot connect to
  `dmd`. If the daemon accepts a command but closes or returns malformed/no output before responding, `dm --json` now
  reports `daemon_state_unknown` instead of silently re-running the command locally.
- `dm messages list` now validates its pagination cursor flags instead of silently mishandling them. Previously,
  `--before-message-id`/`--after-message-id` were ignored unless the matching `--before`/`--after` timestamp was also
  supplied, and any lone cursor flag combined with `--limit` returned the oldest N messages instead of the newest.
  Supplying a message-id cursor without its timestamp (or vice versa), or combining `--before*` with `--after*`, now
  returns a clear error (`message_pagination_cursor_mismatch` / `message_pagination_conflicting_cursors`), matching the
  `dm messages timeline list` behavior.
- Fixed TUI live message subscription gating so highlighted-chat navigation cannot append another chat's incoming
  messages into the loaded conversation or count the visible chat as unread.
- The TUI composer now accepts a leading `?` instead of swallowing it to toggle help. Previously, typing or pasting a
  message that started with `?` into an empty composer toggled the help panel and dropped the character, making it
  impossible to compose such messages. The `?` help shortcut now applies only when the composer is not focused; the
  `/help` and `/?` slash spellings remain available.
- The TUI no longer exits the whole session when an error occurs while a stream composer is active. Failures from
  finishing or cancelling a stream (daemon gone, broker/QUIC error, relay publish rejection) are now caught into the
  status line — mirroring the non-streaming Enter path — so the composer stays open and the user can retry Enter/Esc.
- TUI stream compose now pins the live preview to the group the stream was opened on instead of the
  currently-selected chat. Previously, if a background subscription tick shifted the chat selection while streaming
  (e.g. the streamed-into chat was archived or removed by another member/device), each keystroke upserted the streamed
  text under the wrong group and finishing/cancelling left a permanent ghost "streaming" row under the original group.
- `dm profile update` no longer wipes the rest of your published Nostr profile. It previously published a fresh kind-0
  metadata event built only from the flags you passed, so e.g. `dm profile update --picture URL` erased
  name/display_name/about/nip05/lud16, and `dm profile update` with no flags published an empty profile that wiped
  everything. It now fetches your current published profile from the selected relay, overlays only the provided
  fields, and publishes the merged result. A no-flags invocation is rejected with `empty_profile_update`, and when the
  selected relay holds no current profile event the command refuses with `profile_update_inconclusive` (retry with a
  `--relay` that has your current profile) instead of clobbering it.
- `dmd` no longer exits when a single client connection is abrupt, empty, oversized, malformed, or stalled.
  Per-connection read failures (a client that closes before sending, a mid-write interrupt, a request over the 1 MiB
  cap, or invalid JSON) are now reported to that client and skipped like authorization failures, instead of propagating
  out of the accept loop and killing the daemon (which left a stale socket and pid file). The accept loop also bounds
  how long it waits for a client to send its request frame, so a same-UID client that connects but never sends data can
  no longer wedge the loop and starve other clients. `dm` rejects oversized requests client-side before sending — even
  on the default implicit daemon socket — so e.g. `dm messages send` with a body over the limit fails locally with a
  clear size-limit error instead of silently falling back to local execution or reaching the daemon.
- dm-agent: hardened group-system id deduplication and `send_final` idempotency keys.
- marmot-app: retry distributed convergence after admin promote.
- Engine: tightened MLS proposal ordering and member departure handling.
- agent-connector: replay lagged ambient inbound events after subscription reconnect.
- marmot-account: keep exposed group evolution commits instead of rolling them back after publish.
- Hermes Marmot adapter: select the local-signing account, clamp stream chunks to the policy cap, per-conversation inbound
  concurrency, `send_final` idempotency with bounded retry, rename dead `stream_tool` client method to
  `stream_progress`, and align transcript seed lengths with QUIC varint framing.
- OpenClaw Marmot plugin: filter QUIC candidates to `quic://`, accept singular `MARMOT_QUIC_CANDIDATE`, guard concurrent
  live-preview `ensureBegun`, allowlist outbound media paths, preserve debounced inbound media and signals, cancel
  in-flight live preview begins, and cache per-group `is_direct` with fail-closed lookup errors.
- OpenClaw/Hermes connector parity: mentions via NIP-27 `p` tags, media upload/download, deletes, and ambient inbound
  routing aligned across both adapters.
- marmot-account: confirm relay-accepted auto-publishes instead of rolling back on publish shortfall.
- marmot-app: schedule group convergence retries correctly; serve account-worker reads after hydration, not after catch-up.
- storage-sqlite: retry `SQLITE_BUSY` and classify transient lock contention.
- transport-nostr-adapter: normalization-safe relay URL routing matches.
- CLI: strip invisible and terminal format-spoofing control characters from safe terminal output.
- App messages now attach Nostr expiration metadata where the group retention policy requires it.
- marmot-app: fail over encrypted-media uploads across Blossom endpoints.
- marmot-account: tolerate corrupt account records; reject Windows drive-relative account labels.
- UniFFI: normalize group-id hex in `messages()` and `subscribe_messages()`; bound message subscription snapshots.
- storage-sqlite: exclude invalidated tombstones from unread counts and chat-list previews; group-scope
  `invalidate_app_event_by_message_id`; disambiguate `epoch_key_pairs_id` key encoding.
- marmot-account: prune orphaned KeyPackage bundles on publish failure.
- Shared host-safety classifiers for URL validation across app components.
- Blossom media download redirect validation.
- Engine: quarantine bad groups during hydration; lone uncommitted proposals no longer block outbound app payloads.
- storage-sqlite: recover from corrupt proposal-queue ref-list blobs and undeserializable `QueuedProposal` entries;
  incrementally project new timeline events and prune timeline projections.
- traits: accept query strings on encrypted-media endpoint URLs.
- marmot-app: keep confirmed-but-partial group projections on publish shortfall; avoid rollback after exposed create
  welcome.
- cgka-engine: prune fork recovery snapshots.
- CLI: exponential backoff on failed stream append retries.
- Engine: cache member-validation marker to skip O(groups × members) reverify on open.

### Security

- Redacted TUI `/login` `nsec` composer input when users type leading whitespace, repeated whitespace, or tabs before
  submitting the import.
- Hardened `dmd` IPC by making daemon-owned socket directories `0700`, daemon sockets `0600`, requiring same-UID
  peers, bounding request size, and refusing `reset`/`logout` execution through the daemon socket.
- Encrypted-media uploads and downloads no longer act on loopback-HTTP blob endpoints (e.g. `http://127.0.0.1:PORT`)
  unless `DM_ALLOW_LOOPBACK_BLOB_ENDPOINTS=1` is set for local development. Such endpoints stay valid group state, but
  a production install treats them as unusable instead of issuing requests at the local host on behalf of a remote
  group admin.

### Changed

- Aligned the experimental `dm stream` QUIC preview transport with the merged spec (pre-interop breaking change):
  broker connections now negotiate ALPN `marmot.quic_broker.v1` and send a binary broker control envelope instead of
  JSON, the plaintext frame cap is 65519 bytes, transcript hashes use QUIC varint length prefixes, receivers silently
  discard replayed records at or below their seq high-water mark, and brokers serve replay backlog only within a
  configurable `--replay-ttl-secs` window (default 0, cap 300). Old and new `dm`/broker builds do not interoperate.

- Removed the kind `10051` KeyPackage relay list. KeyPackage kind `30443` events now publish to, and are fetched from,
  the account's kind `10002` NIP-65 relays. The `key_package` relay type is no longer accepted by `dm relays`, account
  relay-list status no longer reports a `key_package` list, and account bootstrap only requires the NIP-65 and inbox
  relay lists.
- Added plural `dm messages` command spelling for the message send/list/subscribe surface, matching the daemon-hosted
  runtime subscription model. The older singular `dm message` spelling still works during the transition.
- `dm messages subscribe` can now omit the group argument to stream live updates across all local groups for the
  selected account.
- `dm create-identity` and `dm login --nsec-stdin` now publish the initial local KeyPackage automatically after
  relay-list setup, so the normal invite path does not require a separate `keys publish` repair step.
- `dm keys publish` now republishes the cached initial KeyPackage instead of minting a replacement package during
  normal repair/setup flows.
- Message projections now order history by recorded transport time before local receipt/insertion order, so synced
  stream anchors/finals no longer jump ahead of older chat text merely because they arrived first during catch-up.
- Account list, `whoami`, sync, and message-list JSON now include cached Nostr profile display names where available,
  and the TUI uses those names in account chrome and received-message authors before falling back to npubs.
- `dm groups show --json` now includes selected-group MLS state, and group JSON includes the Nostr routing app
  component alongside the other group components.
- The TUI now tails daemon-backed `messages subscribe` updates for the selected chat, so incoming messages and QUIC
  stream-preview deltas can render without timer-driven message-list refreshes.
- The TUI now tails daemon-backed `chats subscribe` updates for the selected account, so newly processed invites appear
  in the chat list without switching accounts.
- The TUI status panel now tails daemon-backed `groups subscribe-state` updates for the selected chat, so MLS epoch and
  app-component diagnostics refresh after live group evolution events.
- Removed the daemon runtime maintenance timer and the TUI's periodic daemon/account/chat/message refresh paths; runtime
  state now advances from startup, explicit CLI/TUI intents, and subscription events.
- TUI stream compose typing now batches append calls instead of blocking the interface on a daemon round-trip for every
  character.
- TUI stream compose now keeps a daemon-side transcript and treats live QUIC publishing as best-effort, so finishing a
  stream still publishes the full durable final message when the broker is slow or unreachable.
- The TUI uses higher-contrast neutral account labels and green focus accents instead of the low-contrast cyan account
  treatment; daemon controls stay focused on start, status, and stop.
- TUI slash commands now accept quoted multi-word names for `/chat new`, so group names with spaces no longer consume
  the first word after the space as a member pubkey.
- TUI stream compose now defaults to the production QUIC broker candidate at `quic://quic-broker.ipf.dev:4450`, and
  daemon auto-watch paths only request insecure local trust for loopback broker candidates.
- Typed app-message payloads are validated before publish/projection; malformed reaction, media, delete, or retry
  envelopes are rejected instead of being treated as valid typed app messages.
- `dm login` and `dm account create` now reject positional `nsec` values; private-key imports must use
  `--nsec-stdin`, and the TUI pipes `/login <nsec>` to the child `dm` process over stdin instead of argv.
- `dmd` now keeps long-lived per-account relay subscriptions for real WebSocket relays instead of rebuilding
  subscriptions through periodic rebuild loops.
- `dm daemon status --json` now reports `last_runtime_activity` instead of `last_sync`, matching the runtime-owned
  subscription model.
- Nostr SDK relay connect and publish calls are now bounded by timeouts so first-run account setup fails with JSON
  instead of hanging indefinitely when a local relay does not ACK publishes.
- `dm create-identity` and `dm login --nsec-stdin` publish the required NIP-65 and inbox relay lists, plus the initial
  KeyPackage event, for new local signing identities from daemon account-relay defaults when relay-list flags are
  omitted; `dm login --nsec-stdin --relay <url>` remains the command-local import fallback.
- Newly created local identities now publish matching Nostr `name` and `display_name` values using two-word pseudonyms
  instead of account-id-derived Marmot labels.
- Imported `nsec` accounts now require `--publish-missing-relay-lists` before publishing missing required relay
  lists discovered from bootstrap relays.
- Removed the file-backed local transport and Marmot Lab crate; local tests now use Nostr SDK mock relays and
  product flows require relay-backed setup.
- Moved the CLI crate source directory from `crates/dm` to `crates/cli`. The Cargo package remains
  `darkmatter-cli`, and the installed binaries remain `dm` and `dmd`.

## [0.1.0] - 2026-05-17

Initial release of the `dm` command-line app, the `dmd` background daemon, and the Ratatui TUI.

### Added

- `dm` account commands for creating local signing accounts, adding public-only accounts, listing local
  accounts, inspecting account status, and checking relay-list readiness.
- `dm keys` commands for publishing the selected account's KeyPackage and fetching another account's latest
  KeyPackage from bootstrap relays.
- `dm group`, `dm chats`, `dm message`, and `dm sync` commands for creating encrypted groups, managing members,
  sending/listing messages, archiving chat projections, and processing relay events for a local account.
- Stable `--json` response envelopes for scripts, daemon forwarding, and TUI integration.
- `dmd` daemon support for socket-backed command execution, pid/log files, daemon status reporting, background
  sync, and app-level Nostr user-directory warming.
- `dm tui`, a terminal interface over the real CLI/daemon command surface with account selection, chat
  navigation, message sending, slash commands, daemon controls, account onboarding, and member management.
- Local installation docs for `cargo install --path crates/cli --locked --bins`.
- Homebrew release checklist and namespaced tap packaging path for `marmot-protocol/tap/darkmatter`.

[Unreleased]: https://github.com/marmot-protocol/mdk/compare/v0.9.14...HEAD
[0.9.14]: https://github.com/marmot-protocol/mdk/compare/v0.9.13...v0.9.14
[0.9.13]: https://github.com/marmot-protocol/mdk/compare/v0.9.12...v0.9.13
[0.9.12]: https://github.com/marmot-protocol/mdk/compare/v0.9.11...v0.9.12
[0.9.11]: https://github.com/marmot-protocol/mdk/compare/v0.9.10...v0.9.11
[0.9.10]: https://github.com/marmot-protocol/mdk/compare/v0.9.9...v0.9.10
[0.9.9]: https://github.com/marmot-protocol/mdk/compare/v0.9.8...v0.9.9
[0.9.8]: https://github.com/marmot-protocol/mdk/compare/v0.9.7...v0.9.8
[0.9.7]: https://github.com/marmot-protocol/mdk/compare/v0.9.6...v0.9.7
[0.9.6]: https://github.com/marmot-protocol/mdk/compare/v0.9.5...v0.9.6
[0.9.5]: https://github.com/marmot-protocol/mdk/compare/v0.9.4...v0.9.5
[0.9.4]: https://github.com/marmot-protocol/mdk/compare/v0.9.3...v0.9.4
[0.9.3]: https://github.com/marmot-protocol/mdk/releases/tag/v0.9.3
[0.2.0]: https://github.com/marmot-protocol/mdk/releases/tag/v0.2.0
[0.1.0]: https://github.com/marmot-protocol/mdk/releases/tag/v0.1.0
