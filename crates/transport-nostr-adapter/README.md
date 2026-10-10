# transport-nostr-adapter

Concrete Nostr transport adapter for Marmot CGKA transport messages. It implements `cgka_traits::TransportAdapter`
for Nostr-shaped relay traffic: account-aware routing, subscriptions, and publishing. The default core is relay-client
agnostic; the optional `sdk` feature adds a `nostr-sdk` backed `NostrSdkRelayClient`.

## What this crate does

- Activates account inbox subscriptions and group subscriptions, refreshes group subscriptions for an active account,
  and removes stale group subscriptions when an active account's group set changes.
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

The SDK client retains idle WRITE-only publication connections for up to 60 seconds.
History acquisition on the same client adds READ capability to a retained connection
before issuing its request. The promoted connection keeps WRITE capability and is no
longer eligible for idle publication eviction; request subscriptions still close when
the acquisition finishes or is cancelled. Both publication paths preserve typed SDK
acknowledgements, including the distinction between affirmative and duplicate ACKs.

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

Pass budgets:

- The NIP-77 remote-only selection holds at most 512 IDs from a 16,384-ID reconciliation set.
- Each pass sends at most 16 request-local exact-ID acquisitions within the two-second comparison deadline and the
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
each endpoint's comparison has its own deadline. Fast endpoint failures leave that endpoint
incomplete while healthy IDs continue within the same pass budgets; a silent endpoint can still
consume most of the two-second deadline for the IDs it claimed. A byte/item/deadline exit
retains partial events but leaves incomplete every endpoint whose claimed IDs the pass did not
return. An endpoint that claimed nothing left behind still succeeds, and
`NostrReconciliationSummary::failed_endpoints` names the ones that failed, so a caller can
certify a subset of a route's relays. `incomplete_endpoints` names the failed ones that still
answered: they finished the comparison and served their exact-ID requests, but this pass did
not return every ID they claimed. The rest timed out, errored or truncated.

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
  its bracket, because fetching a window larger than a pass would return part of it in ID order. It fetches the
  narrowest window anyway when the bracket can no longer shrink or the previous pass already waited, and falls back
  to ID-order selection when no relay answers. At most one pass in a row returns nothing this way.
- **Time prefix.** A window the byte budget or deadline cuts short returns only events no newer than any it left for
  the next pass, found with one more probe round just before the returned events' timestamps; events sharing a second
  with one left behind may still be returned. Events held back are fetched again. IDs it tried and may never get
  (over the single-object ceiling, withheld by every claimant, or claimed only by a relay that did not answer) do not
  hold delivery back. Ordered passes reserve part of the deadline for that probe round.
- **Memory.** The client remembers, per route and in memory only, the last bound that fit, how far past it to look
  next, an unfinished bracket, and the route's average event size, so a backlog being worked through usually needs
  one round. It also sets aside IDs a pass returned that the account has not admitted since, and IDs every claimant
  answered without: they yield to history not tried yet and are retried with leftover room. Once 1,024 IDs are set
  aside the route uses ID-order selection, which cannot stall behind them. Losing this memory costs at most extra
  narrowing or a refetch.

A window is fetched in the cursor's rotation, grouped by claiming relays so requests batch fully, and returned in time
order. Selection never changes the summary: a relay that claimed an ID this pass left unfetched stays incomplete. The
account inbox route keeps ID-order selection. The extra dry-run comparisons are control traffic: about 200 KiB to
fetch an eight-event, 2.6-MB gap against 1,100 retained events in the adapter fixture.

Replay position is advisory, separate from admitted event inventory. A cancelled fetch retains its
pre-I/O cursor advance. A completed byte-limit rejection of an otherwise eligible network ID
restores the preceding cursor when earlier results consumed this pass's allowance, so the ID leads
the next pass even if that earlier result stays unadmitted. Repeated route URLs are counted once
after parsing, preserving one acquisition obligation per distinct relay. Refused and over-ceiling
events recur on wrap; only durable app ingestion removes an event from the missing set.

## Run tests

```sh
cargo test -p transport-nostr-adapter
cargo test -p transport-nostr-adapter --features sdk
```

See [`AGENTS.md`](AGENTS.md) for the file map, routing invariants, and telemetry rules.
