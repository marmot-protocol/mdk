# AGENTS.md - crates/transport-nostr-adapter

Agent-facing map for the Nostr transport adapter crate. Read [`README.md`](README.md) for the human overview,
recovery-session contract, and reconciliation budgets.

## Scope

This crate implements the shared `TransportAdapter` boundary for Nostr-shaped traffic:

- account inbox activation,
- group subscription sync,
- stale group subscription cleanup,
- relay-event to account-scoped delivery routing,
- publish target validation and endpoint-level publish reports.

It does not own MLS peeling, CGKA convergence, storage, account key custody, or real relay socket policy by default. The
optional `sdk` feature provides `NostrSdkRelayClient` through the `NostrRelayClient` boundary and relies on `nostr-sdk`
for reconnect/backoff and relay status mechanics.

## Key files

| Path | Owns |
| --- | --- |
| `src/lib.rs` | Adapter implementation, relay-client boundary, routing state, lifecycle metrics. |
| `src/acquisition.rs` | Owned bounded acquisition and receiver-scoped loss evidence types. |
| `src/publish_accounting.rs` | Shared logical publish counters and the cancellation guard used by direct and account publish paths. |
| `src/key_package.rs` | Marmot kind `30443` KeyPackage event building/publishing (`NostrKeyPackagePublication`, `NostrKeyPackagePublisher`). |
| `src/pairing.rs` | Device-pairing messages as rumors gift-wrapped to the account's own key. Built only with `unreleased-device-pairing` and in this crate's tests. |
| `src/relay_list.rs` | NIP-65 kind `10002` and Marmot inbox kind `10050` relay-list event building. |
| `src/sweep/` | Time-sliced resumable history sweep (#2660 phase 3): engine over `SweepRelay`, caller-owned sink and cursor store; `sdk.rs` is the SDK-backed relay, `hint_tap.rs` reads NIP-67 `more` off the wire for it and counts each live REQ's reply frames. Called by `marmot-app`'s recovery runner `quantum.rs`, which owns account history debt by default since PR 5g. |
| `src/compare/` | NIP-77 comparison of one (route, relay, range) against the caller's held ids (#2660 phase 4): windows under the relay's set limit, differences fetched by id oldest first, each window certified once every id the relay holds there is fetched or held. Called by the same recovery runner's `compare.rs`; its `host.rs` builds `SdkSweepRelay` from the account's existing pool. |
| `src/replay_fence.rs` | Fences on a group's live frames (#2660 phase 4): arming at a counted EOSE, the owner's `ReplayFencePlan` answers, partial release, owner-completed holds, and buffered live frames, held or waiting for admission, moving to the coverage a fresh activation installs. Enabled by the recovery runner from PR 5g. |
| `src/sdk_client.rs` | Optional `nostr-sdk` relay client implementation and SDK planning tests. |
| `src/telemetry.rs` | Relay delivery telemetry: cross-relay arrival spread (phase 1) and subscription sync timing / initial-sync gate (phase 2); local-time, aggregate, privacy-safe. |
| `tests/inbound_routing.rs` | Public behavior tests for group delivery, welcome delivery, group sync, and publish. |
| `tests/acquisition_contract.rs` | Request validation and optional-boundary shape tests. |
| `tests/publish_accounting.rs` | Direct-adapter publish admission, classification, and cancellation tests, with or without `sdk`. |
| `tests/selective_history_acquisition_tests.rs` | `sdk`-gated bounded history acquisition and reconciliation-cursor tests. |
| `tests/time_sliced_sweep.rs` | `sdk`-gated sweep over the wire through `limit_relay.rs`: 500 clamp including raw500/validated499 with1,200valid events (#2885), NIP-77 saturated second, an inconclusive second (a listed id withheld, a malformed NEG-MSG, or repeated id-fetch events that cut a one-id reply; retried and never saturated), resume, rate-limited CLOSED, NIP-67 hints (the proxy's wok mode): `more` splits, `finish` changes nothing; replies cut mid-stream (the proxy's stall) report every byte read, a comparison's fetch included. |
| `tests/relay_limit_subscriptions.rs` | `sdk`-gated subscription behavior against `tests/support/limit_relay.rs`, a proxy enforcing strfry 1.1.3's per-connection limits (REQ and NEG caps, filter shape, 500 limit clamp). |

## Invariants

- Keep Nostr event DTO conversion delegated to `transport-nostr-peeler`.
- Keep `TransportDeliverySource` metadata diagnostic only; do not feed it into consensus decisions.
- Preserve account-scoped deliveries even when group subscriptions share relay endpoints.
- Keep account-inbox and group subscription ids scoped to the activation attempt that issued them
  (`SubscriptionAttempt`). A relay reports end-of-stored-events by subscription id and nothing else, so a shared id
  would let a superseded attempt's in-flight EOSE satisfy the replay-coverage gate the next activation just reset. Ids
  stay derived from account/group/endpoint state plus the attempt, never from `since`, which is not recorded with the
  routes and so could not be reconstructed at eviction time.
- Keep the attempt ordinal in `AdapterState::activation_attempt_high_water` and never clear it — not on
  `deactivate_account`, not on the failed-activation rollback. Both drop the account's routes without closing the relay
  sockets the superseded attempt's REQs still stream on, so an ordinal recovered from the routes would re-issue ids that
  are still live. `AccountRoutes.attempt` holds only the live copy that `account_subscription_ids` reconstructs from.
- Keep `activate_account`'s opening `unsubscribe_account` unconditional. Attempt-scoped ids removed the relay-side
  REQ-replace backstop, and a rolled-back activation can leave `accounts` empty while the relay client still holds this
  account's subscriptions; an orphaned REQ double-delivers because routing is content-keyed.
- Never leave a REQ live that `account_subscriptions` does not track (#2262):
  - Track a REQ's id before handing it to nostr-sdk, and untrack it only once its CLOSE went out. A failed subscribe
    registered nothing of its own and closes nothing: a late or repeated subscribe may name an id another live REQ
    still holds. `unsubscribe_account` untracks per id as it closes, so a caller dropped mid-sweep leaves the
    rest tracked.
  - Never abort subscribe tasks. `subscribe_all` drains its siblings after an error and detaches them when dropped.
    Every lifecycle operation takes `lock_subscriptions`, which waits for those stragglers to register before any
    sweep.
  - That wait is bounded so a hung relay client cannot wedge the adapter. When it gives up, it retires the barrier;
    a task that finishes after its barrier was retired closes the REQ it just registered, unless the current routes
    want that id. It releases its barrier guard, then holds the lifecycle lock across that check and the CLOSE, so
    neither can interleave with an activation mid-sweep or a retry re-registering the id.
  - A failed or cancelled group sync closes the REQs its batch installed once its subscribe tasks settle, except ids
    the committed routes still want (`close_abandoned_sync_batch`). Its guard holds the lifecycle lock throughout.
- Never fail a subscription, activation or group sync because a relay is unreachable (#1951). nostr-sdk refuses a
  REQ outright on a relay that failed more than one connect attempt, and its reconnect re-sends only the REQs it
  registered:
  - `subscribe_planned` records such a relay's REQ (id and original filter) in `OwedSubscriptions`. The relay's
    frontier monitor re-sends it on the relay's next `Connected`, after emitting that connection's replay boundary,
    and after a lag cutover; `subscribe_planned` re-sends at once when the relay connected before the entry existed.
  - Only a refusal no reconnect cures counts against a plan (`relay_owes`: relay gone, banned, terminated or shut
    down, unable to read, or already holding the id). A plan fails only when no relay registered or owes its REQ.
  - Owed ids stay in `account_subscriptions`. `unsubscribe` and each id of `unsubscribe_account` forget the id under
    the re-send lock before its CLOSE, and a re-send holds that lock across its check and registration, so a closed
    REQ never comes back. A new CLOSE path must forget first too.
  - Owing adds no replay-coverage state: an owed relay stays `RelayReplay::Awaiting` like one that queued the REQ
    while disconnected, and restarts at its connection boundary.
  - `NostrSubscribeReport` carries aggregate owed and refused relay counts into the `activations_*` and
    `group_syncs_*` metrics. Clients that do not override `subscribe_reporting` report every success as full.
- Never count a replay a relay may have clamped as coverage (#2263):
  - `observe_relay_event` takes an authenticated event id and counts each relay's stored events per activation,
    sync or maintenance REQ until that relay's EOSE, without materializing a DTO. Consumers must pass a relay's
    copies in order with its EOSE, and report unconvertible stored events through
    `observe_unconvertible_relay_event` instead of dropping them.
  - A relay that sent `RELAY_REPLAY_PAGE_LIMIT` or more ends `RelayReplay::Delegated`, not complete-query `Eose`: its
    received input can be admitted under the owner's fence, while the coverage gate stays incomplete. Raw live counts
    survive; the account's recovery runner owes and proves the missing range. The adapter fetches no history of its
    own for any reply.
- Keep each endpoint's `ReplayLiveCount` to its own physical EOSE in one source generation (the endpoint serial), for
  the coverage ledger's live boundary (#2660). Its `requested_at` must be no later
  than when the relay ran the query: the endpoint's stamp taken before its REQ is issued, raised for a REQ the SDK
  re-sent on reconnecting to that connection's `connected_at`. The monitor reads that stamp only when the SDK's
  success count shows it belongs to a connection the monitor saw (`connection_stamp`); never stamp a count later
  than that. The relay leaving `Connected` (`NostrSdkNotification::Disconnected`, which a client shutdown sends for
  every connection still open before it aborts the monitors) or a relay `CLOSED` ends the count as
  `ReplayEndedCount`, only if its boundary was admitted, and an EOSE still in flight for that serial installs none
  (`ReplayEndpoint::stopped`). A `CLOSED` the SDK keeps to send again (AUTH, a rate limit) ends the count without
  stopping the serial: the restored REQ's EOSE counts only its own reply (after the serial's first EOSE, through
  `ReplayEndpoint::recount`). A count's `live_from`, where its provisional tail may start, is `requested_at` only
  when the adapter issued the REQ in that serial; for a REQ the SDK sent (a reconnect, a kept `CLOSED`) it is the
  second the adapter recorded its EOSE (`ReplayEndpoint::sent_again`), because the SDK reports `Connected` before it
  counts the connection and records its time, so that stamp can be the previous connection's or missing. A reconnect
  without a reported disconnect and receiver loss drop it. Never carry a count
  into the next serial.
- A live count streams (`ReplayEndpointView::streaming`, which alone may hold a provisional tail) only while the relay
  client reports, when asked, the connection its serial started on (`NostrRelayClient::relay_connection`): the one
  it reported when the adapter issued the REQ, or when the adapter saw the boundary that restarted it
  (`ReplayEndpoint::connection`). Never infer streaming from notifications alone: a shutdown, a removed account
  context or a reconnect the adapter has not seen yet must read as not streaming at once. The SDK client names a
  connection by its relay monitor and the SDK's attempt count, read on both sides of a `Connected` status read
  (`current_connection`): the SDK marks `Connecting`, counts the attempt, then marks `Connected` before it counts the
  success, so only that sandwich errs toward none under every interleaving. A multi-account root answers from the
  account's own context; a removed or shut-down context, or a shut-down frontier, names none. Streaming names a
  connection, not a REQ: it can stay true until the adapter processes notifications already queued for that relay
  (a `CLOSED` on a connection that stays open, or a boundary handled after the next connection opened, which records
  that newer connection). That delay is the accepted limit; anything it does not bound is a bug.
- Stage each group's complete replay range before timestamp/id-ordered release. Keep
  live arrivals behind the draining batch. Every replacement REQ establishes its own current-peer boundary,
  including equivalent or narrower repacks; never inherit another REQ's ready floor. In-deadline peers fence
  payload release until EOSE or their finite lease settles. Verified raw SDK group copies feed admission;
  deduplicated `Event` copies must not bypass
  it, and retired REQs must never admit late copies. SDK seen-state is not account admission.
- Admission belongs to each REQ/relay/transport-route, never a sticky group-wide failure flag. Share
  ciphertext bodies with separate source claims; retiring or failing one source must not discard a healthy
  source's older history. Waiting starts again at an unfinished source's first connection boundary. Each
  active route gets one `REPLAY_WAIT_LIMIT` waiting allowance when service starts; peer waits and draining do not
  spend it. Arrivals and repeated loss never extend active leases. Empty expired
  streams become dormant; a first or newer connection can reopen waiting. Late history without that restart is
  explicit loss, never a raw-EOSE certificate. Discarded history retains its own floor. Fresh requests do not
  inherit failure.
- Transport consumers use `NostrSdkRelayClient::notifications`, the ordered per-relay SDK frontier, and
  `dispatch_sdk_replay`. Carry connection and receiver-loss boundaries with the payloads; never poll SDK
  state to infer their generation. Authentication alone must not advance a connection epoch. Reader epochs are
  process-monotonic and survive queued frontend work. Receiver loss abandons the source's open streams without
  starting IO: they end incomplete, their discarded bodies retain a loss floor, and the recovery runner alone
  refetches the window. Real SDK/frontend gaps enter the existing plane loss fence. Empty waiting never fabricates
  discarded-input evidence. Only recorded transport REQ payloads enter the frontier; acquisition replies stay with their
  collectors.
- `NostrSdkRelayClient::relay_connections` publishes each monitored relay's latest connection generation from the
  same `Connected` branch that opens its replay boundary, so it never moves on AUTH alone. It is a wake signal for
  the recovery runner, which diffs generations; it carries no replay boundary, and nothing may order payloads by it.
- Bound pending replay by `REPLAY_BUFFER_MAX_ITEMS` and `REPLAY_BUFFER_MAX_BYTES`, with one additional
  draining batch; include inbox and ready-delivery backpressure. A per-account supervisor owns draining tasks;
  atomically install ready-channel placements under the admission lock, without a cancellation gap.
  Notification-worker cancellation must not orphan accepted work. Account retirement cancels it and retains
  unresolved loss. Keep released live-copy dedup bounded by the item allowance; historical refetch bypasses it.
  Discard a source's partial interrupted or lost history instead of releasing its newer suffix, and retain its
  floor as loss until `take_replay_status` imports it. Later live input must not stay permanently
  stalled. Silence or a terminal refusal alone must not stall a completed peer or turn incomplete coverage
  into a certificate.
  An empty wait must not mint loss; only actually discarded ciphertext retains a loss floor. Interrupted
  multi-tag history discards the affected source's whole MLS-group unit, never releases its newer suffix.
- Keep admission and all-relay EOSE separate. `take_replay_status` holds a read guard through a synchronous
  cursor seal; import its loss before another await, then drop it. Notify only wakes the router; it never
  consumes evidence. `ack_replay_delivery` follows actual pinned queue/spill placement or recorded loss, never
  merely adapter enqueue.
- A fence (`src/replay_fence.rs`) holds one group's live frames from its point on, never the account: held frames count
  neither in `admission_pending` nor against request placement or stream admission, and every release path
  (`GroupReplay::release`, native ingress, both `stage_delivery` fast paths) lets out only what lies below the point.
  Nothing arms until `enable_replay_fencing`. Then a live EOSE whose count is non-empty holds the REQ's
  groups from its `since` until a `fence_replay` plan whose ticket saw that count as admitted answers it. An arming
  belongs to its own count: `ReplayEndpoint::count_id` moves whenever a live count is installed or ends, and only an
  arming whose count is still current can be admitted or kept unanswered, so a count that ends or is replaced (an empty
  recount) before admission drops its arming. Full replies are fenced too, without counting as complete coverage.
  Holds have no request deadline: the owner advances or releases them as durable backlog admission permits; no
  expired timer authorizes newer input. Unanswered armings
  still retire with their unadmitted count. A plan older than the
  last applied is ignored, and a fence nothing holds ends at once. A fresh activation (`record_account_replay_start`)
  moves the buffered live frames native ingress does not own into the new coverage: those fences hold stay held from
  the same point under the old plan ticket, and those still waiting for admission wait there. Only frames for groups
  its REQs no longer route, or past the buffer bounds, become replay loss. A fence holds only what is still in the replay
  buffer: never call back a frame already handed off (a queued or borrowed native batch, a draining hand-off); it goes
  on as late input, as at expiry, and the range stays owed. A hand-off that rejoins the buffer keeps its placement pin
  until its next hand-off; while a fence holds it there, that pin is exempt (`held_pins`), but a pin on a copy still out
  never is. Held frames stay under the replay buffer bounds, so overflow is loss. `placed()`
  stays strict; only the recorder's `placed_apart_from_fences` passes held frames, and `fence_held_since` caps the
  plane's cursor seal at the oldest held frame its restart floor does not cover. With fencing off, every changed
  predicate reduces to its old form.
- Record each REQ's filter `since` and the routes it selects (`NostrSubscription::delivery_routes`) in its SDK
  account context before the REQ goes out, find it by subscription id when the REQ closes, and keep a closed
  REQ's floors for the rest of the context's life: routing is content-keyed, and a closed REQ's buffered or
  in-flight notifications have no deadline, so they can still be lost in a lag. Do not add a time-based expiry.
  Read `notification_loss_bounds` at the lag; an unfloored REQ or missing evidence is `Unbounded`, never "no
  loss". Per-route floors are known only while every REQ the context ever issued had a floor and known routes,
  within `MAX_DELIVERY_LOSS_ROUTES`; otherwise the lag is loss on every route from the floor.
- Expose allocation-free guarded source views and a coalescing change watch. Membership, query windows and
  ordered epochs change a process-monotonic generation; ACK progress does not. Generation identity
  must survive activation replacement. The adapter starts no recovery IO of its own, and there is no adapter
  or plane quiet-period retry controller. Keep live REQs and the SDK registry unchanged, never poll SDK EOSE
  to certify admission, and never revive terminal refusals with private fetches. Native admission is neither
  exhaustive coverage nor loss acknowledgment; the account owner alone persists/qualifies it.

- Hand every relay `CLOSED` on a live REQ to `handle_relay_closed` in `dispatch_sdk_notification`, the one dispatch
  both notification consumers share (the relay plane's in `transport-nostr`, and this crate's test forwarder); change
  `CLOSED` handling there, never in a consumer loop. Classify each message on its own with `sdk_subscription_refusal` /
  `NostrSdkRelayClient::subscription_refusal`, which mirrors how
  nostr-sdk settles that REQ (kept for `rate-limited:`, and for `auth-required:` with an authenticator); never read
  the SDK registry when the queued notification is handled, since a later re-send may have changed it. An unknown
  authenticator keeps `auth-required:` pending. The forwarder test pins the table against the SDK registry. Treat a
  staged group-sync REQ as live. A dropped refusal before EOSE settles that relay's replay coverage but never
  completes it. Keep original-query `AccountSubscriptionEose` separate from `AccountSubscriptionInput`: delegated
  full replies end current input, so activation reuse, announce readiness and drain waits use the latter. Neither its `complete`
  nor `settled` qualifies history or promotes a cursor. Native placement and the plane's loss barrier still guard
  readiness; cursor qualification keeps its independent guarded seal. Repack floor selection still requires
  original-query completion: current-input readiness must not discard an unresolved original floor. Ending a drain early on settled input must
  leave its checkpoint exactly as the drain's timeout would. EOSE is final; a later `CLOSED` does not undo it. Ignore closes for ids that are not live
  (superseded attempts, one-shot fetches). Keep only the reason's category, never its text, in state, logs,
  telemetry and the audit queue.
- Keep the time-sliced sweep (`src/sweep/`) a mechanism: it covers what one call can of one (route, relay, range)
  and reports it; it never picks routes, relays or retries. Cover a slice only on proof (a reply below the NIP-11 cap
  counting every EVENT the relay sent, below a full reply from a relay with no published cap, or one second's NIP-77
  id set; NIP-67 `more` always splits). Count proofs hold only for kinds everyone may read: strfry spends its cap on events it
  withholds; do not sweep a restricted-read kind without another proof. Admit before saving the cursor,
  and never count a refusal, rate limit or unreachable relay as an empty page. `SdkSweepRelay` gives every NIP-77
  comparison and ids REQ an explicit `limit`, and a comparison that fills it proves nothing. `SdkSweepRelay` dials nothing: its endpoint must already be in the client's pool.
- Never drop a request its relay can end itself (mdk#2719). Both drivers run each request through `ask_until_cut`: on
  its deadline or cancellation it calls the relay's `interrupt`, and when that returns `true` awaits the request for
  up to `INTERRUPT_GRACE` before dropping it, and never uses its reply. `SdkSweepRelay` cancels its acquisition
  through the SDK's `AcquisitionCanceller` (dropping the handle would discard the report), so the partial reply still
  meters its `received_event_bytes`, and once interrupted it starts no further request, a second's next id chunk
  included. Its NIP-77 exchanges carry ids, not events, and are dropped.
- Keep the comparison driver (`src/compare/`) a mechanism like the sweep. A window certifies only when the relay's
  set for it stayed under `COMPARE_SET_LIMIT` and every id the relay holds there was fetched or already held; a
  withheld id, a filled set or a cut leaves its window unproven, and a window that cannot shrink below one second
  ends `SaturatedWindow`. Certify oldest first, so a cut proves the prefix below the oldest unfetched difference.
  A relay without NIP-77 or a refused comparison proves nothing and ends the call; never read it as an empty set.
- No NIP-67 hint proves a slice; only counting does. `more` splits, and `finish` is never read: hints reach the sweep
  only off the wire, where a misread `finish` would skip history while a misread `more` only costs requests. Do not
  add a hint-based `SliceProof` until nostr-sdk surfaces hints itself.
- `SdkSweepRelay` reads `more` through the client's wire tap (`src/sweep/hint_tap.rs`), which
  `NostrSdkRelayClient::from_builder` installs around the builder's transport. A slice registers its filter before its
  REQ goes out, binds to the next REQ to that relay carrying exactly that one filter, and takes that id's first EOSE.
  A hint the tap can't pin on one REQ reads as none, and the slice is left to counting. That covers two watches with
  one filter, a second one-filter REQ carrying the filter while the watch is live (a stale or unrelated REQ looks the
  same as the sweep's), a REQ re-using the bound id, and an EOSE too long to be real. The tap reads the relay's frames
  as the SDK does: text frames only, the verb decoded as JSON decodes it, and an EOSE identified by nostr's own
  `RelayMessage` parser, which alone decides that a frame ends the REQ. It runs before the SDK's size check, so it
  parses only EOSEs of at most 1 KiB, outside its lock. It never alters, delays or drops a frame, and keeps no event,
  id or payload past the watch.
- The same tap counts, per REQ, the EVENT frames its relay sends before that REQ's EOSE, valid or not, on the
  connection the REQ went out on (`ReplyCounts`). `dispatch_sdk_notification` asks
  `NostrRelayClient::reply_sent_nothing` once as it dispatches each EOSE, and each ask answers only the oldest EOSE
  for the id not yet asked about, true only if that is also the newest (the SDK may have re-sent the id and had it
  answered before the dispatch); every EOSE frame is counted, even with no count open. The live count keeps the answer as
  `ReplayLiveCount::sent_nothing` only when the SDK counted nothing either; `marmot-app` lets only that empty count
  prove its window. Err toward unknown: a frame the tap cannot tie to one REQ while counts are open (an unreadable EVENT
  id, an oversized EOSE, a binary frame) spoils every open count on its connection; a REQ re-sent on the same
  connection while the relay may still answer the earlier one (open, spoiled, or closed by the client) starts unknown;
  past 1,024 REQs per relay the oldest count goes. Wrappers of a tapped client delegate `reply_sent_nothing`.
- Keep real relay clients behind `NostrRelayClient`. A client that is not the SDK's hands its relays' messages to
  the plane through `relay_notification_source` (`sdk` feature): one stream of `NostrSdkNotification`s, each
  event's signature already verified and each relay's frames in order, which the plane dispatches through
  `dispatch_sdk_replay` like the SDK's. The default, `None`, means its relays send the plane nothing.
- Both SDK consumers enter through `dispatch_sdk_replay`; `dispatch_sdk_notification` is its private payload handler.
  Observe and admit a raw group copy from one validated/decoded transport message, outside the state write lock.
  The directory-only Client stream stays separate from transport replay generations.
- Keep the `nostr-sdk` dependency behind the `sdk` feature.
- Relay endpoints are host-safety filtered before any connect at the `RelaySafetyPolicy` chokepoint in `transport-nostr`
  (`crates/transport-nostr/src/safety.rs`); relay hosts that are non-public IP literals are rejected, and literal
  loopback hosts are rejected too unless the dev loopback flag is set (the flag admits loopback only —
  private/link-local/CGNAT literals stay rejected). A new relay-connect path must go through that chokepoint, not around
  it. See `docs/marmot-architecture/overview/dial-safety.md`.
- Keep per-relay telemetry keyed by the opaque `RelayIndex`. `resolve_relay_labels` (gated behind a
  `RelayExportConsent` token) is the only path that turns an index back into a relay URL, and exists solely for the
  opt-in export boundary. Do not add another reverse mapping or resolve indices outside that boundary.
- Do not log relay URLs, account ids, group ids, message ids, subscription ids, pubkeys, plaintext, ciphertext, or
  payload-derived values.
- Use tracing `target` plus `method` fields so crate/module/method are visible while diagnostic data stays
  aggregate-only.
- Floor history REQs where the caller anchors them: a recovery maintenance session at the `since` it is installed
  with, and a retained route at its `TransportGroupSubscription::retained_since`, never later than the activation's
  `since`. A route with a retained floor is retained wherever it sits; among floorless routes the first per group is
  the current one and a later distinct one is retained and backfilled in full. Re-add a live retained route only when
  its floor widens (`AccountRoutes::group_since`): the repack then issues it at the wider floor.
- Send group routes as batched REQs, never one REQ per route (#2266): `NostrSubscription::GroupBatch` carries up to
  `GROUP_BATCH_ROUTES` routes that share normalized endpoints and `since` as one `#h` filter, so an account stays far
  under a relay's per-connection REQ limit and recovery's one-shot fetches find room. That holds while the routes'
  batches, counted per relay-set and floor family, stay well under the limit: a repack briefly holds both the old and
  new batches of the families it changes, so one relay's co-floored routes near 4,900 can reach strfry's 200 during
  it. `AccountRoutes::batches` always carries exactly `AccountRoutes::groups`, after a partial commit too. Activation
  packs every route (`pack_group_batches`) and numbers batches from 0. A group sync that changes the route set repacks
  only the families it touches, each in full (`plan_family_repacks`): one a route leaves (removed, or re-added to
  widen its floor) or joins, and one whose routes, issued again, would land in a family the sync issues. Every other
  family's live REQs stay as they are, so one relay set's churn never re-sends another's. A repacked route keeps the
  floor it was issued at, or starts at the sync's floor when the activation's replay coverage is complete; completed
  coverage alone repacks nothing. Families that share a route or a family key form one `FamilyRepack`, which commits
  once all of its batches went out (`commit_group_sync`). A repack whose batch failed keeps its families' live
  batches, routes (a route it removed among them) and coverage, closes the REQs its batches installed, and is tried
  again by the next sync, which `AccountRoutes::retry_repacks` keeps from returning early as unchanged; the sync
  commits the rest and then returns the error. The new batches enter replay
  coverage before their REQs go out (`stage_replay_batches`, as activation does, so an early EOSE or stored page
  counts), go out before the replaced ones close, and the replaced ones leave coverage on commit
  (`retire_replay_batches`); a failed or cancelled repack retires only its own uncommitted batches. A sync's
  batches replay like an activation's. Never append batches or leave a removed route in a live filter: that
  fragments batches back to the REQ limit, and a removed route's events still reach the relay client, which then
  suppresses the re-added route's replay of them. Batch numbers come from `AccountRoutes::next_batch`, which staging
  spends whether or not a repack commits, so no id is reused within an attempt. Coverage, refusals, lag repair and
  `account_subscription_ids` are per batch; a full batch reply delegates every route it carries to the recovery
  runner. Use canonical group order across REQs. A batch counts only once every route's history completes. Post-join maintenance
  and one-shot fetches stay per route.
- Recovery maintenance ids include the owner's durable attempt serial. A duplicate install joins only a live session;
  after failure, cancellation, removal or account reactivation, require a strictly greater serial for that account/group.
  Never clear `maintenance_attempt_high_water` while the adapter lives: CLOSE and route removal cannot recall late EOSE.
  Only recovery installs use the scoped client API; preserve the legacy maintenance subscribe/cleanup path.
- Keep `pairing` behind `unreleased-device-pairing` (and `cfg(test)`). The explicit default-off `dev-device-groups`
  CLI capability forwards it with production timing; ordinary releases do not enable it. A pairing reader accepts only rumors the account authored; that proves the
  account, never a device.
- Use Marmot kind `30443` for KeyPackages; never substitute deprecated NIP-104 key package kinds. There is no dedicated
  KeyPackage relay list; KeyPackages go to the NIP-65 kind `10002` relays.

## Verification

History driver tests own admission, saved cursors, budgets and certification. Keep real SDK wire tests for request
limits, byte-cut splitting, hint binding and interruption reports; a model reply does not prove those boundaries.
Script only replies supported producers can deliver: optional SDK filter verification is off by default, but its
acquisition set already deduplicates identical events. A proxy's outbound FIFO marker does not prove the SDK processed
inbound bytes, so it cannot replace the third-chunk cancellation test's receipt premise.

Keep the native ingress public-registration and local-publication tests at the adapter boundary; the app's real-MLS
local-publication journey separately owns plaintext and durable message preservation. Pausing an in-process fixture's
Tokio clock must preserve its production replay leases and bounds. The signature/delivery proofs at the 32k replay
bound run in nextest's `adapter-replay-bounds` group; do not reduce those bounds to cut their CPU cost.

```sh
cargo test -p transport-nostr-adapter
cargo test -p transport-nostr-adapter --features sdk
```

Run the ignored unchanged-subscription latency diagnostic manually, outside the ordinary suite:

```sh
cargo test -p transport-nostr-adapter --locked --test inbound_routing unchanged_sync_latency -- --ignored --exact --nocapture
```
