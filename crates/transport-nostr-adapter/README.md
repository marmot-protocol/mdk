# transport-nostr-adapter

Concrete Nostr transport adapter for Marmot CGKA transport messages. It implements `cgka_traits::TransportAdapter`
for Nostr-shaped relay traffic: account-aware routing, subscriptions, and publishing. The default core is relay-client
agnostic; the optional `sdk` feature adds a `nostr-sdk` backed `NostrSdkRelayClient`.

## What this crate does

- Activates account inbox subscriptions and group subscriptions, refreshes group subscriptions for an active account,
  and removes stale group subscriptions when an active account's group set changes. Group routes go out batched, up
  to `GROUP_BATCH_ROUTES` (50) per REQ, so a 1,000-group account holds about 21 REQs per relay.
- Converts relay-delivered `NostrTransportEvent` values into account-scoped `TransportDelivery` values.
- Routes kind `445` group messages by endpoint + transport group id.
- Routes signed kind `1059` giftwraps through the account-inbox plane.
- Publishes already-wrapped `TransportMessage`s to target endpoints and returns endpoint-level publish reports.
- Builds and publishes Marmot kind `30443` KeyPackage events through the same relay-client boundary when supplied with
  the MIP-00 metadata.
- Builds NIP-65 kind `10002` and Marmot inbox kind `10050` account relay-list events. KeyPackages are published to the
  NIP-65 relays; there is no dedicated KeyPackage relay list.
- Exposes adapter-local lifecycle metrics for diagnostics.
- With the `sdk` feature, plans `nostr-sdk` filters/subscription ids, signs unsigned group events with the configured
  SDK signer, publishes to specific relays, forwards SDK notifications into adapter deliveries, and exposes a redacted
  aggregate relay-health snapshot.

## What this crate does not do

- No MLS peeling; that remains in `transport-nostr-peeler`.
- No CGKA convergence; that remains in `cgka-engine`.
- No account key custody. The `sdk` client uses the signer already configured on the supplied `nostr-sdk::Client`.
- No duplicate reconnect/backoff loop. The optional `nostr-sdk` client relies on SDK `RelayOptions` for reconnect, retry
  interval adjustment, jitter, relay sleep/ban/terminate behavior, and connection stats.
- No full production relay-plane orchestration. Relay auth, relay scoring, full KeyPackage metadata derivation, and
  per-platform lifecycle wiring still need hardening. Runtime-level endpoint safety, bounded subscription replay, group
  fanout, and redacted aggregate relay health live in `marmot-app`'s relay plane.

## Boundary shape

Inbound:

```text
relay client -> NostrRelayEvent -> NostrTransportAdapter -> TransportDelivery
```

Outbound:

```text
TransportPublishRequest -> NostrTransportAdapter -> NostrRelayClient
```

`NostrRelayClient` is intentionally small so tests can use an in-memory client and production can use
`NostrSdkRelayClient` behind the `sdk` feature.

Public DTO ingress verifies the event signature and id/content binding before delivery, including reconciliation
and acquired replay pages. SDK notifications carry event ids authenticated by the pinned SDK. Its verification
cache is keyed by id, so later copies may contain altered bytes: a buffered copy reuses only the held body's
trusted routing and timestamp, while an uncached copy must match the authenticated event hash before replay
accounting. Admission also enforces the exact Marmot tag shape. Group peeling checks payload identity and
routing without repeating Schnorr verification.

`observe_relay_event` accepts an authenticated event id, endpoint, subscription id and timestamp. It records
every relay's timing and stored-page slot without building or serializing an ingest DTO. While a replay body
is buffered, additional relay copies reuse its trusted routing and timestamp metadata and add independent
source claims. Released live duplicates also skip conversion. A historical refetch whose body is no longer
held is admitted again through the original REQ gates rather than suppressed by SDK seen-state.

The SDK client retains idle WRITE-only publication connections for up to 60 seconds.
History acquisition on the same client adds READ capability to a retained connection
before issuing its request. The promoted connection keeps WRITE capability and is no
longer eligible for idle publication eviction; request subscriptions still close when
the acquisition finishes or is cancelled. Both publication paths preserve typed SDK
acknowledgements, including the distinction between affirmative and duplicate ACKs.

Subscription-created connections close when their last subscription ends. An active
publication keeps a shared connection open until its lease ends. Externally supplied
connections and connections promoted for history acquisition keep their existing
pool lifetime. Subscription-owned connections do not consume the idle WRITE-only
publication allowance, either while subscribed or while awaiting removal. Missing
subscription connections do not prevent other idle sockets from expiring.

Replacement activation passes its planned subscriptions to
`unsubscribe_account(account_id, replacements)` before closing old REQs. Their
ownership keeps unchanged sockets and connection epochs alive; final teardown
passes an empty slice. Pending replacements remain reachable by account cleanup
if setup is cancelled. Removed sockets also lose their notification monitors and
frontier entries; re-adding a relay receives a fresh process-monotonic connection
epoch. Notification-reader startup shares the relay lifecycle lock with eviction,
so a stale pool snapshot cannot reattach a removed monitor.

The app-runtime layer projects group subscriptions and group-message publish targets from
`marmot.transport.nostr.routing.v1` and applies relay endpoint parsing/deduplication before subscription or publish.
KeyPackage publish targets come from the user's kind `10002` NIP-65 relay list, and directory/profile discovery is
coalesced in the shared runtime relay plane. Kind `30443` is the Marmot KeyPackage event kind, not a deprecated NIP-104
key package kind.

## Privacy-safe diagnostics

Adapter diagnostics are aggregate-only: counts, status buckets, method names, and success/failure totals. They never
include relay URLs, account ids, group ids, message ids, subscription ids, pubkeys, plaintext, ciphertext, or
payload-derived values. Tracing uses explicit `target` and `method` fields such as
`transport_nostr_adapter::adapter` / `publish`.

`NostrTransportAdapter::publish_event_with_client` wraps the complete publication future.
Direct and account-adapter sends share these counters. Endpoint fanout and authentication retries
remain one logical attempt; dropping an in-flight publication records one cancellation.
Account, endpoint-safety, and envelope validation stay outside this accounting boundary.

## Ordered subscription replay

Initial activation, group-subscription sync, and recovery maintenance stage group deliveries through stored
replay and any backward pages, then release each group's batch in `(created_at, event id)` order. Live
arrivals during release queue behind that batch. Each REQ/relay/route owns its historical claims and admission
state. A shared ciphertext body is retained once per destination group; failure or retirement removes only
that source's claims. A fulfilled predecessor keeps its held range during handoff. Paging runs per route from
the outset, finishes all routes of one MLS group together, and waits for its history to leave the pool before
paging the next group. Groups use a common ordering across overlapping REQs.

An initial replay gets a 30-second waiting interval, reconciled with its first observed connection boundary.
Clamped routes each get a 30-second paging allowance when their service starts, reusing
`REPLAY_PAGE_LIMITS.max_duration`; queueing, peer-release waits and delivery draining do not spend it.
Arriving events and repeated loss do not extend an active lease. An empty expired group stream becomes dormant; a
first or newer connection can reopen waiting. Late history without that restart is discarded with its original
loss floor, not certified by wire EOSE. Lost partial history also stays incomplete. A silent or terminally
refused peer cannot freeze available history indefinitely. Fresh requests have fresh ownership. This does not
establish ordering across unavailable relay history. Every replacement REQ establishes its own boundary, even
for an equivalent or narrower repack. Each valid waiting peer fences group payload release until EOSE or its
finite lease settles; another peer's EOSE is not permission to release ciphertext early. Group delivery uses verified raw SDK
copies, so SDK duplicate suppression cannot consume the only copy of ciphertext discarded by a cancelled
attempt. Retired subscription copies cannot bypass admission.

An empty waiting endpoint or cancelled empty acquisition does not create notification loss. Discarded
ciphertext retains its original floor. Late inbox copies remain countable so a clamped replay still triggers
backward paging.

Transport receivers use each relay's ordered SDK notifications, including connection and receiver-loss
boundaries. Every queued payload carries reader/connection epochs. A warm reconnect resets admission before
the SDK restores the same REQ IDs; old queued EOSE cannot satisfy the new generation. Authentication alone
does not change the connection epoch or restart an active capture. Receiver loss fences the source until the
account recovery owner grants a full-window capture. Forced paging is not a physical
EOSE: late stored copies remain historical until their stream ends. Only transport-owned REQ payloads enter
this frontier; acquisition replies stay with their request-local collectors. Direct SDK subscribers and the
directory client keep their independent Client streams.

`AccountRecoveryOwner` persists unresolved original windows as a `SubscriptionReplay` goal. Borrowed
`ReplayAdmissionStatus` source views describe issued requests and current-epoch admission without allocating.
Source membership, query windows and ordered epochs change its generation; page progress and ACKs do not.
The generation remains distinct across account activation replacement.

The app registers `ReplayIngress` before activation, including durable group spill rows as retained input.
Every group frame then uses this lane, including local publication fanout, post-EOSE and untracked live tails; none enters the ordinary
delivery queue. Each complete group range moves into a `ReplayBatch`, bypassing live-queue/spill alternation. The owner
borrows the oldest frame through ordinary ingest and acknowledges it afterwards. Cancellation before ACK
returns that frame and its suffix without copying ciphertext. A leased group holds its newer arrivals;
other ready groups take turns. Retained spill input joins remote pages before any of that range decrypts,
even when the current relay no longer holds those local copies.
New source metadata, a restart or distinct historical input revokes an unstarted loan: `delivery()` returns `None`, and dropping the
batch returns its suffix for merging after the new range completes. `take_batch(Some(group))` distinguishes
that pending boundary from empty input. Same-account repacks preserve held live bodies. Ingest that already
committed still ACKs its frame: revoking a loan cannot undo durable MLS progress. Spill settlement must succeed
before its corresponding native ACK.
Local fanout neither records relay history nor settles an outstanding source boundary. Inbox and legacy-only
adapter consumers retain their ordinary delivery path.

Only the owner's frozen `ReplayCapturePlan` starts recovery IO. It binds the account, source generation,
issued REQ and endpoint, and retains the existing process recovery credit through accepted IO cleanup.
Explicit captures refetch the original window, not a recent tail or an existing truncated continuation.
Taking over capture in the same wire epoch preserves held ciphertext. Mechanical continuation of a physically
clamped native reply remains automatic. Live REQs and the SDK registry stay unchanged; a private fetch cannot
restore a terminally refused REQ. SDK EOSE flags cannot bypass queued history.

A per-account supervisor owns queued capture tickets, paging and delivery draining independently of
notification workers. Ticket installation and ready-channel placement commit synchronously under the admission
lock. Cancelling a notification worker cannot strand a queued capture or an accepted delivery. Dropping an
owner capture cancels its IO without releasing its credit before cleanup. The account owner alone decides
retry, completion and retirement; the adapter and relay plane have no quiet-period recovery scheduler.
Account retirement cancels accepted work and reports only ciphertext actually discarded.

Each account's pending ciphertext, including retained supplements, leased native batches, inbox and
ready-delivery backpressure, is bounded by
`REPLAY_BUFFER_MAX_ITEMS` (32,000 copies, the 500-event page limit times 64 pages) and
`REPLAY_BUFFER_MAX_BYTES` (32 MiB of payload). Native leases stay charged until ACK. One serialized legacy
delivery-channel draining batch can retain another batch's allowance concurrently. Each native ACK frees
its frame's allowance for subsequent input. A separate 32,000-ID released-event window suppresses repeated
live copies, not historical refetches.
Delivery metadata, router-placement pins and the SDK notification queue are outside the payload cap; it does
not bound RSS or wire bytes. Interrupted pages get one fresh request at the same boundary within the page
bound. Overflow, failed paging, a saturated second, deadline expiry and cancellation discard the affected
owner's partial history and report its floor when ciphertext was discarded; they never certify it or release
its newest partial page. Failure of one transport tag discards the source's whole affected MLS-group unit,
not a newer suffix from another tag of that group. Healthy peer claims and independent groups survive.

`dispatch_sdk_replay` is the SDK entry point; its private payload dispatcher cannot bypass generation checks.
`take_replay_status` transfers retained loss to the consumer's existing recovery fence and holds a read guard
through its synchronous cursor seal. Drop the status before awaiting again. `replay_loss_notified` wakes the
router without consuming evidence. Loss survives replacement until imported. Buffered and releasing ciphertext
holds the cursor, but a dead relay alone does not: all-relay EOSE is a separate certificate. The router calls
`ack_replay_delivery` only after installing its queue/spill pin or recording loss, closing the
adapter-to-router gap. The account owner persists limited native admission only after pending bytes and
nondurable spill handoffs are clear, including every native batch ACK. A source whose range is already
queued to the owner needs no additional acquisition while those bytes drain. Limited native admission never
certifies exhaustive history or acknowledges queue/notification loss. Its cached permission must match the
guarded source generation at cursor seal.
A pending owner observation does not authorize the cursor, but already-acquired bytes need no new IO.
The owner drops borrowed source observations before SQLite writes and rechecks their generation at seal.
Unservable original windows park visibly without capture credit or loss charges; terminal group retirement
removes only obsolete native scope debt. Durable native ACKs can advance the cursor through the existing live
promotion path once current sources drain. Save failures keep the target pending; replayed durable receipts
can restore it after reopen without duplicate plaintext notifications.

Timestamp sorting leaves the existing 100-generation sender-ratchet tolerance unchanged: more than 100
messages from one sender in the same second can still exceed it because event-id order is not
sender-generation order; backdated events can also disagree with sender generations. Trusted cursor floors
retain their configured rewind. With no durable cursor, the app
requests full retained history instead of substituting the recent live tail, including when the relay refuses
NIP-77. Recovery maintenance also pages from its Welcome-anchored floor. Cursor checkpoints retain their
previous floor while replay is staged, leased to the owner or not yet placed by the delivery router.
An unfloored plane query, including one caused by an untrusted future cursor or explicit full-history policy,
stays unfloored; the app does not replace it with a recent-tail fallback.
Ordinary comparison acquisition is unchanged.

## Recovery maintenance sessions

`install_group_maintenance_recovery_subscription` accepts the account recovery owner's durable attempt serial and
a history floor, and returns an opaque wire id. The app floors the session at the Welcome that installed the joined
copy, less a clock-skew allowance, so a notification lag while it is live stays bounded; `None` requests the
group's full history. A replacement session must use a fresh serial, including after cancellation or reopen.
Reusing a serial joins only a live session without resetting its EOSE. After failure, cancellation or removal, the adapter
requires a strictly greater serial for that account/group, even across account activation. Its lifetime high-water map
retains one scalar per account/group that used this API. Remove the session with
`remove_group_maintenance_recovery_subscription` and its returned id. Failed or cancelled teardown retains retry intent.

`subscription_endpoint_eose` reports EOSE only for the caller-supplied endpoint in that subscription's captured
membership (`None` means unknown subscription or endpoint). EOSE can satisfy a maintenance first-boundary prerequisite;
it does not establish exhaustive historical coverage or durable admission.

Injected `NostrRelayClient` implementations opt in with `supports_scoped_subscriptions` and implement both
`subscribe_scoped` and `unsubscribe_scoped` using the exact supplied wire id. `NostrSdkRelayClient` supports this. The
default (`false`) rejects recovery sessions before staging routes or teardown work. Existing `GroupMaintenance` values
and legacy installation/removal APIs retain their shape and ids.

## Reconciliation progress ownership

`NostrSdkRelayClient::reconcile_subscription` requires a `NostrReconciliationProgress` store for
that account and route. Hosts serialize reconciliation per route and preserve its cursor across
subscription rebuilds. The first ID of each exact-ID request is checkpointed before the request,
including when the caller later cancels; after the response the cursor moves through the IDs that
returned. An ID left unattempted by the pass budget does not move the cursor.
A failed progress read or write stops replay; it must not silently restart at a refused prefix.
Empty remote sets preserve the cursor: failed relay comparisons can also produce an empty set, and
the next nonempty set wraps around the saved position.

MarmotApp stores the cursor in its encrypted account database alongside existing route inventory
(migration 0061). Route retirement deletes it, and a late replay cannot recreate deleted route
state. There is no shared cross-route cursor cache, so activity on other routes cannot evict an
active route's progress. State adds at most one 32-byte cursor to each existing route row.

MarmotApp stages SDK progress in memory and saves a route's cursor after every owned comparison
event has completed its ordinary ingest attempt. Capacity refusals still permit rotation, but
remain outside inventory and cannot certify coverage. Failed network requests and interrupted
admission preserve the pre-pass cursor.

Selected-only comparison plans are validated but not reused. The next grant rebuilds its operational
plan from existing coverage debt. Ignoring a legacy plan leaves messages, replay cursors, coverage
evidence, retry cost and capability blocks intact. A new comparison request clears the prior
operational plan; a duplicate request key leaves the current plan intact.

Pass budgets:

- The NIP-77 remote-only selection holds at most 512 IDs from a 16,384-ID reconciliation set.
- The first NIP-77 reply gets up to five seconds. A pass uses the earlier of its caller's absolute
  cutoff and a twenty-second SDK allowance. MarmotApp runs up to four routes concurrently under
  its account-wide cutoff, keeping time for partial-result handoff and epoch-gap window fetches.
- Each pass sends at most 16 request-local exact-ID acquisitions within that deadline and the
  aggregate 256-item / 1-MiB-serialized-event allowance. The first request names one ID; later ones name up to 64
  consecutive IDs the same endpoints claimed, sized to the byte room left at the largest event the pass has seen,
  because a relay streams every event a request names before the byte limit can stop it. Until an event has
  returned, batches start at one ID and double. When a budget cuts a request short, its first unreturned ID leads
  the next pass; when no relay answers, the pass stops after advancing through what returned, at least one ID.
- One event up to 5 MiB can occupy an otherwise empty pass, matching the pinned SDK's default normalized-message
  ceiling; larger events remain incomplete. Full-event SDK cache hits share this rule with fetched events.
- The first exact-ID request may temporarily retain up to 5 MiB per endpoint before deduplication, and the SDK can
  observe one rejected boundary event beyond its byte limit. The largest endpoint's received count/bytes
  conservatively charges each network request. Relays can return different events from one batch, so the
  distinct events a pass returns are held to the same allowance; one that does not fit leads the next pass.
- These are returned-result and SDK-received budgets, not complete wire or memory ceilings.

Each exact-ID request goes only to the endpoints whose comparison claimed that ID, and
each endpoint's comparison has its own deadline. Once one endpoint has compared, the others get
until half of what was left of the pass, so a relay that answers once and then stalls cannot use
up the time to fetch what the others claimed. Fast endpoint failures leave that endpoint
incomplete while healthy IDs continue within the same pass budgets; a silent endpoint can still
consume most of the remaining deadline for the IDs it claimed. A byte/item/deadline exit
retains partial events but leaves incomplete every endpoint whose claimed IDs the pass did not
return. An endpoint that claimed nothing left behind still succeeds, and
`NostrReconciliationSummary::failed_endpoints` names the ones that failed, so a caller can
certify a subset of a route's relays. `incomplete_endpoints` names the failed ones that still
answered: they finished the comparison and served their exact-ID requests, but this pass did
not return every ID they claimed. The rest timed out, errored or truncated.
`endpoint_failures` gives each failed endpoint one `NostrReconciliationFailure`: the first stage that
failed it, such as a NEG-ERR (with its reason's machine-readable prefix, never the text), no first
reply, the pass deadline, or an endpoint outside the account's pool. A failure in a later window or
boundary probe is classified the same way. An incomplete endpoint is `Withheld` only when it reached
EOSE on an exact-ID fetch without an ID it claimed; one this pass's own budget or ordering left
unasked or cut short is `PassLimit`.

Wrapper clones of one SDK pool share eight comparison permits per canonical relay. Initial comparisons,
window searches and boundary probes take the same permits; waiting spends the caller's existing deadline.
`SDK_RECONCILIATION_WINDOW_PROBES` sets both this per-relay permit limit and the window-search probe count.
Different endpoints and independently built account pools have independent permits. This bounds active SDK
sync futures, not the lifetime of remote sessions: cancellation queues the SDK's asynchronous cleanup task
but does not confirm that NEG-CLOSE has reached the socket before a permit is reused.

strfry answers a NEG-OPEN past its per-connection session cap with a session-less NOTICE (`ERROR: too
many concurrent NEG requests`) that nostr-sdk ignores, so the comparison waits out its first-reply
timeout. The client watches the relay while the NEG-OPEN is pending and reports that timeout as
`NegCapNotice`. It keeps no per-relay rejection state between passes; the caller paces retries.

A group route's gap is fetched from its oldest end. MLS applies commits in order, so fetching IDs in ID order,
which is effectively random in time, could let commits carry a member's epoch more than the retained-epoch window
past older messages still missing, which can then never be read (mdk#2086).

- **Window.** When the gap holds more than one pass (256 IDs, or fewer when the route's events are large enough that
  256 would exceed 1 MiB), the pass finds the oldest window `[since, bound]` that fits with dry-run comparisons: up to
  six rounds of eight concurrent probes within half of what is left of the deadline. A first search starts at the
  recent end, where a catch-up gap sits, at distances shrinking by powers of two; later rounds spread evenly within
  the bracket. A probe counts as fitting only when every relay asked answered it: a relay that missed it may hold
  older history the others lack.
- **Unfinished searches.** A pass whose search did not find such a window fetches nothing and the next pass resumes
  its bracket, because fetching a window larger than a pass would return part of it in ID order. It fetches anyway
  when the bracket can no longer shrink or the previous pass already waited: the narrowest window a complete probe
  measured, or else the whole gap, with delivery still held to a time prefix. A pass whose probes no relay answered
  fetches nothing.
- **Time prefix.** A window the byte budget or deadline cuts short returns only events older than every one it left
  for the next pass, found with one more probe round up to the returned events' timestamps; timestamps are whole
  seconds, so a second split by the budget is held together. When no probe gets a complete answer the boundary is
  unknown and the pass holds everything. Events held back are fetched again. Every ID of the window not returned
  holds delivery back, including ones a request timed out on, except an event every claimant answered without or one
  over the single-object ceiling. Ordered passes reserve part of the deadline for that probe round.
- **No order, no delivery.** A route that cannot prove an order (a relay that answers comparisons but never the
  probes, or one second holding more than a pass) returns nothing and stays quiet. Its events stay fetchable, and
  recovery parks it with its "history may be incomplete" notice if that persists, rather than admit newer commits
  ahead of older messages. Such a pass sets `NostrReconciliationSummary::order_unproven`; the relay plane counts it,
  and opt-in telemetry exports the device-wide total as `relay_reconciliation_order_unproven_passes`.
- **Memory.** The client remembers, per route and in memory only, the last bound that fit, how far past it to look
  next, an unfinished bracket, and the route's average event size, so a backlog being worked through usually needs
  one round. It also sets aside IDs a pass returned that the account has not admitted since, and IDs every claimant
  answered without (not ones this pass's own allowance dropped), or that can never fit the single-object ceiling:
  they yield to history not tried yet and are
  retried with leftover room. A route keeps as many as its relays' comparisons can name together, up to 65,536;
  beyond that it cannot keep an order and stays quiet. Past 65,536 across routes the least recently used route's
  memory is dropped, and it sets its IDs aside again. Losing this memory costs at most extra narrowing or a refetch.

A window is fetched in the cursor's rotation and returned in time order. The rotation's first ID leads, and the rest
are grouped by claiming relays so requests batch fully. A budget cut leaves the cursor just before the ID it deferred,
so that ID is the next pass's first request with the single-object allowance, whichever relays claim it. Selection never changes the summary's endpoint results: a relay that claimed an ID this pass left unfetched stays incomplete. The
account inbox route keeps ID-order selection. The extra dry-run comparisons are control traffic: about 200 KiB to
fetch an eight-event, 2.6-MB gap against 1,100 retained events in the adapter fixture.

Replay position is advisory, separate from admitted event inventory. A cancelled fetch retains its
pre-I/O cursor advance. A completed byte-limit rejection of an otherwise eligible network ID
restores the preceding cursor when earlier results consumed this pass's allowance, so the ID leads
the next pass even if that earlier result stays unadmitted. Repeated route URLs are counted once
after parsing, preserving one acquisition obligation per distinct relay. Refused and over-ceiling
events recur on wrap; only durable app ingestion removes an event from the missing set.

## Raw page evidence

Bounded acquisition reports `raw_received_items` and `oldest_raw_created_at` before SDK cache,
duplicate and event filtering. A short validated event list does not establish a short relay page.
Epoch-gap paging uses the raw evidence to descend, and a completed oldest page for admission;
neither the evidence nor end of stored events certifies durable history coverage.
The byte allowance counts validated serialized event JSON, not rejected wire bytes or process memory.

## Run tests

```sh
cargo test -p transport-nostr-adapter
cargo test -p transport-nostr-adapter --features sdk
```

See [`AGENTS.md`](AGENTS.md) for the file map, routing invariants, and telemetry rules.
