---
title: "Review Pass 1 — E: Transport Plane"
created: 2026-10-15
updated: 2026-10-15
tags: [marmot, architecture, review, pass-1, transport, nostr, large-groups]
status: draft for discussion
---

# Review Pass 1 — E: Transport Plane

System E of the [review](README.md): the Nostr transport. It covers the relay plane, the adapter and the peeler, how
events are published and subscribed, and whether the design holds at the [scale targets](README.md#scale-targets),
especially groups of thousands. Baseline `ceb8b24c9`. Sizes were measured with the real `NostrMlsPeeler`. "(inferred)"
marks claims reasoned from code but not traced at runtime.

## Summary

- **Welcomes are the first thing to break as groups grow.** Every Welcome carries the full ratchet tree, about
  358 bytes per member, and NIP-59 wrapping triples it. A one-invitee Welcome passes the 64 KiB default of public
  strfry relays at about 56 members, and the White Noise relays' 2 MiB limit at about 1,917. A group of thousands
  cannot be joined by Welcome today, even on our own relays.
- **From about 81 members, Welcomes need NIP-44's extended length format.** NIP-44 v2 uses a 6-byte length prefix for
  plaintexts of 65,536 bytes or more. The pinned rust-nostr fork implements it, but libraries that implement only the
  older 2-byte format cannot handle these Welcomes. Whether other Marmot implementations support it is unverified.
- **Commits are not the near-term problem on our relays.** They grow about 109 bytes per member in the worst case, so
  they stay under 2 MiB until about 19,000 members. On 64 KiB public relays they would fail from about 586 members, but
  group traffic uses only the White Noise relays today.
- **Nothing knows an event is too big.** There is no size check before publishing, and NIP-11 is never read. A
  "too large" rejection looks like any other `invalid:` rejection. If every relay rejects the frame by closing the
  socket instead, the pending commit retries hourly forever and the group can no longer commit (inferred).
- **Relays with different limits can split a group silently.** A relay that definitively rejects a commit is treated
  as "not owed", so the undelivered-commit gate lifts while members who read only that relay lose the epoch.
- **Per-group readiness, as Pass 1 B proposes, can be built mostly from parts that exist,** but none of them is
  exposed per group, and a batch repack resets every group's catch-up state.
- **The `TransportAdapter` trait is the right boundary for publish and receive,** and everything else bypasses it:
  coverage, cursors, loss, maintenance REQs and comparisons all go through the concrete relay-plane type.

## 1. Relay limits in practice

| Relays | Software | Event limit | WebSocket frame | Subscriptions per connection | Notes |
| --- | --- | --- | --- | --- | --- |
| `relay.us/eu.whitenoise.chat` (every group relay today) | strfry | 2 MiB | 4 MiB | 200 | 1–3 filters per REQ, 16 kinds per filter, 3 tag constraints per filter, 500 results per filter; timestamps up to 15 minutes in the future and 1,095 days old; no NIP-42 auth (operator-supplied) |
| `relay.damus.io`, `relay.primal.net` | strfry | not advertised | 1,000,000 B | 200 / 20 | NIP-11 |
| `relay.snort.social`, `nostr.wine` | memlay, nostr.wine | not advertised | 512 KiB | 300 / 50 | NIP-11 |
| `nos.lol`, `offchain.pub` | strfry | not advertised (default 64 KiB) | 128 KiB | 20 | NIP-11 |
| Default strfry configuration | strfry | 64 KiB of normalized JSON (`events.maxEventSize`) | 128 KiB (`maxWebsocketPayloadSize`) | 200 | [`strfry.conf`](https://github.com/hoytech/strfry/blob/master/strfry.conf) |

NIP-11 documents were fetched on 2026-10-15. strfry advertises its WebSocket frame size as `max_message_length` but
does not advertise its event-size limit, so NIP-11 overstates what a strfry relay accepts. Group events go to the White
Noise relays. Welcomes go to each recipient's own inbox relays (kind 10050), which may be public relays.

## 2. Event sizes against group size

These are the bytes of the published event JSON, which is what relays limit. Each pair is event bytes / MLS bytes
before Nostr wrapping. Measured in a `cgka-session` integration test using the real peeler, on an Apple M4 Max.

| Members N | Add 1 commit | Add 50 commit | Welcome, 1 invitee | Welcome, 50 invitees | Self-update | Chat message |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 2 | 2,008 / 1,165 | 32,832 / 24,284 | 7,333 / 1,841 | 76,965 / 27,111 | 1,336 / 661 | 988 / 399 |
| 50 | 7,444 / 5,242 | 38,132 / 28,259 | 55,121 / 19,305 | 131,585 / 44,363 | 6,816 / 4,772 | 988 / 399 |
| 100 | 12,956 / 9,377 | 43,648 / 32,394 | 109,741 / 37,273 | 218,965 / 62,331 | 12,332 / 8,907 | 988 / 399 |
| 500 | 56,788 / 42,251 | 87,480 / 65,268 | 524,801 / 180,609 | 612,181 / 205,667 | 56,164 / 41,781 | 988 / 399 |
| 1,000 | 111,504 / 83,288 | 142,196 / 106,305 | 1,049,089 / 359,677 | 1,049,089 / 384,735 | 110,880 / 82,818 | 988 / 399 |
| 2,000 | 220,888 / 165,325 | 251,576 / 188,342 | 2,097,665 / 717,745 | 2,097,665 / 742,803 | 220,260 / 164,855 | 988 / 399 |

The group size at which each event first exceeds a limit:

| Event | 64 KiB | 128 KiB | 512 KiB | 1 MiB | 2 MiB |
| --- | ---: | ---: | ---: | ---: | ---: |
| Welcome, 1 invitee | 56 | 116 | 476 | 956 | 1,917 |
| Welcome, 50 invitees | already at N = 2 | 46 | 406 | 886 | 1,847 |
| Self-update or remove commit | 586 | 1,185 | about 4,780 | about 9,570 | about 19,150 |
| Add commit, 50 invitees | 300 | 899 | about 4,490 | about 9,280 | about 18,870 |
| Chat message, group-data commit | never | never | never | never | never |

Values above N = 2,000 are linear extrapolations. Welcome crossings come from an exact model of the NIP-44 padding,
which reproduces all 25 measured Welcomes.

Where the bytes come from:

- **Welcome.** MLS Welcome bytes are about 965 + 358·N + 511·k for k invitees. The 358 bytes per member are one leaf of
  the ratchet tree, sent because both create and join set `use_ratchet_tree_extension(true)`
  (`crates/cgka-engine/src/group_lifecycle.rs:415`, `crates/cgka-engine/src/wire_format.rs:82`). About 150 bytes of each
  leaf is Marmot's app-data extension, including a 104-byte account-identity proof. NIP-59 then base64-encodes it three
  times (rumor content, seal, gift wrap) and pads twice, for about 2.92×.
- **Commit.** About 109 bytes per member. In a tree where only the admin has committed, parent nodes are blank, so an
  update path encrypts to about N recipients. As members commit, the tree fills and this moves toward O(log N). Each
  added member also inlines a 626-byte KeyPackage.
- **Invite traffic.** Every invitee receives a full copy of a Welcome that grows with N. Inviting 50 people into a group
  of 1,000 publishes about 52 MB per relay.

**NIP-44 length format.** NIP-44 v2 encodes plaintexts of 65,536 bytes or more with a 6-byte length prefix (two zero
bytes and a `u32`), up to 2³²−1 bytes. The pinned fork
([`erskingardner/rust-nostr@a9c7a64`](https://github.com/erskingardner/rust-nostr/tree/a9c7a6423d104c603de6ea8244265ea17f0f9d89))
implements this (`nostr/src/nips/nip44/v2.rs:26-29`, `:98-110` in the fork). Older implementations cap plaintext just
below 64 KiB: upstream `nostr` 0.44.8 could not wrap a 64-member Welcome at all
([#1638](https://github.com/marmot-protocol/mdk/issues/1638)). A gift wrap's plaintext needs the extended format from
about 81 members for one invitee, 69 for ten, and 11 for fifty. Clients whose NIP-44 library predates the extended
format cannot decrypt those Welcomes.

## 3. When an event is too big

There is no size check before publishing, and no constant for the maximum outbound event size
(`crates/marmot-app/src/relay_plane/mod.rs:4069-4141`). NIP-11 is read only by a test harness. A relay's answer is
classified like this (`crates/transport-nostr-adapter/src/sdk_client.rs:4625-4678`):

| Relay behaviour | Classification | Fanout status |
| --- | --- | --- |
| `OK false "invalid: …"`, including "too large" | Rejected by the relay, category `Invalid` | `Failed` (terminal) |
| `OK false "error: …"` or no prefix | Possibly exposed | Outstanding, retried |
| Socket closed or frame refused, or a timeout | Possibly exposed | Outstanding, retried |

Each relay call also resends the event up to three times, even after a terminal rejection (`sdk_client.rs:51-56`,
`:3092-3138`).

What that means for each artifact (`crates/marmot-account/src/runtime.rs:4632-4979`):

| Artifact | Every relay answers `invalid:` | Some relays accept | No relay accepts, and some may have received it |
| --- | --- | --- | --- |
| Commit | Rolled back. The host gets an untyped `AppError::Publish`. A retry produces the same size and fails again. | Confirmed. The rejecting relays count as "not owed" (`runtime.rs:2880-2918`), so the undelivered-commit gate does not fire. | Never rolled back: rollback needs no possible exposure (`runtime.rs:4970-4979`). The commit is retried from 30 s backing off to hourly, with no attempt cap (`runtime.rs:84-85`). Until then the group cannot commit, and sends queue up to 256 intents (inferred). |
| Welcome | No terminal state; each target is retried with backoff (`runtime.rs:5817-5856`, `:5964-5978`). A delivery failure is shown to the host. The invitee is in the tree but never joins. | Delivered | Same as the first column |
| Application message | Recorded as failed, with a generic reason | Delivered | Retried with backoff. It blocks the group's later fanouts during resume (`runtime.rs:3387-3396`). |

## 4. Subscriptions at scale

- **Shape.** Group routes are packed by endpoint set and `since`, 50 per REQ: one filter, `kinds: [445]`, one `#h` tag
  key with up to 50 values, and no `limit` (`crates/transport-nostr-adapter/src/lib.rs:132-140`, `:3921-3967`;
  `sdk_client.rs:2716-2738`). The inbox is one REQ for `kinds: [1059]`, `#p: [self]`. That fits the White Noise limits,
  provided "3 tag constraints" means three tag keys and not three values. The CI harness assumes keys
  (`crates/transport-nostr-adapter/tests/relay_limit_subscriptions.rs:205-227`).
- **Count.** 100 groups on one relay family need 3 REQs per connection, and 1,000 need 21. Groups on different relay
  sets, or with different floors, fragment the batches, in the worst case to one REQ per group, which a 20-subscription
  public relay refuses after about 19 groups.
- **Repacks.** Any route change closes and reissues every batch with new subscription ids (`lib.rs:228-234`,
  `:3236-3252`). Joining or leaving one group therefore replays and resets EOSE for every group on the account
  (inferred).
- **Paging.** A replay that hits the 500-result cap pages backwards, up to 64 pages per route
  (`lib.rs:117-130`, `:2092-2310`). That covers about 32,000 events per route per activation; beyond that, catch-up is
  incomplete and recovery owns it.

## 5. Per-group catch-up evidence

Pass 1 B needs per-group "transport caught up" evidence. Today EOSE is tracked per REQ per relay, completed only after
paging, and exported only as account-wide counts (`lib.rs:565-600`, `:1473-1482`). The options:

| Option | Exists today | Limits |
| --- | --- | --- |
| A batch's EOSE counts for every group in it | Most pieces: per-route subscription ids and EOSE accessors (`lib.rs:1429-1500`), used only in tests | Means "caught up since the account floor". Every repack resets it. |
| Per-group `since` cursors | Only an in-memory issued floor per route | Batches need one shared floor, so per-group floors fragment them; it also needs durable cursors |
| Per-group NIP-77 comparison | Yes (`relay_plane/mod.rs:3547-3600`) | Bounded fetches per pass; only 2 recovery credits per process; relays without negentropy are unsupported. A backlog over many groups would not clear within minutes (inferred). |
| A separate per-group REQ for catch-up | Yes, but only after joining a group (`client/mod.rs:1589-1760`; `marmot-account/src/runtime.rs:1470-1515`) | One subscription per catching-up group. Fine under 200; would need throttling under 20. It already has the durable phase machine that readiness needs. |

Suggested combination:

- per-route batch EOSE plus paging completion as the baseline evidence, with batches that keep their membership across
  repacks;
- a per-group catch-up REQ for the foreground tier and for groups with gap evidence;
- NIP-77 comparison as the proof for background groups, with more than two credits.

## 6. Large invites

- **Welcome fanout.** Eight Welcomes in flight, each with a 20 s ceiling (`runtime.rs:63`, `:286-307`;
  `sdk_client.rs:64`). Inviting 1,000 people takes about 125 waves, from about 2 minutes on healthy relays to about
  40 minutes in the worst case. All of it runs on the worker, which serves only snapshot reads meanwhile (inferred).
- **KeyPackage discovery.** Three hops: relay list, inbox list, KeyPackages. Authors are chunked 32 per filter, with 4
  concurrent fetches, 3 s per fetch, and one shared 50 s deadline, all on the worker
  (`crates/marmot-app/src/directory/member_key_packages.rs:31-42`, `:509-518`). The invite is all or nothing: one member
  still undecided at the deadline fails it. With diverse outbox relays, 1,000 members need far more than 50 s
  (inferred).
- **Partial failure.** The commit is confirmed before Welcomes go out, so invitees whose Welcome fails stay in the tree
  as members who never joined.

## 7. The transport boundary

`cgka_traits::TransportAdapter` has five methods: activate, sync groups, deactivate, publish and receive
(`crates/traits/src/transport_adapter.rs:1170-1200`). `AccountDeviceRuntime` is generic over it, but `AppRuntime`
fixes it to the relay-plane adapter (`crates/marmot-app/src/lib.rs:474-478`). `AppClient` calls about 30 inherent
methods on the concrete type for delivery intake and receipts, cursor sealing, loss and overflow, coverage, post-join
maintenance REQs, recovery comparisons, telemetry and the directory.

The trait is right for publish and receive, which is all `marmot-account` needs. What readiness and recovery need
(coverage evidence, cursors, loss, comparisons) has no transport-neutral surface. That is why the app reaches past
the trait.

The [transport-agnosticism](../overview/transport-agnosticism.md) leaks all remain at this baseline:
- the directory has no seam;
- the peeler is fixed in the app, and `notifications.rs` builds a second gift wrap;
- the endpoint grammar is written three times, and `TransportEndpoint` is still a bare string;
- `nostr::Keys` appears in the SQLCipher key code, and the engine still depends on `nostr` (mdk#755);
- there is no blob-store trait;
- client construction is concrete.

Dial safety uses one shared classifier with several enforcement points. One of them, Open Ranking directory search
(`crates/marmot-app/src/directory/open_ranking.rs:196-225`), is missing from the chokepoint table in
[`dial-safety.md`](../overview/dial-safety.md).

## 8. Time windows

No code knows the White Noise relays' 1,095-day or 15-minute timestamp windows (inferred).

- Exact-event retries and Welcome redelivery older than 1,095 days would be refused with `invalid:` and fail
  silently.
- A device whose clock runs more than 15 minutes fast has every publish refused, because the outer `created_at` is
  bound to the inner event time (`crates/transport-nostr-peeler/src/peeler.rs:168-176`). Its commits roll back and its
  messages fail, with untyped errors.
- If relays ever prune history, nothing records a relay-side horizon.

## 9. Recommendations

**Large groups.** These are protocol-level and belong in the Marmot spec, backed by the numbers in §2.

1. **Take the ratchet tree out of the Welcome.** Every Welcome carries the full tree (§2), so its size grows with the
   group and every invitee receives a full copy. MLS allows a Welcome without the tree when the joiner gets it another
   way. This is a wire-format change, so the design belongs in the Marmot spec; [#2336](https://github.com/marmot-protocol/mdk/issues/2336)
   tracks the proposal. With the tree delivered once per invitation, each Welcome would grow with the number of
   invitees instead of the group size. This is the change that makes groups of thousands joinable.
2. **Confirm that every Marmot implementation supports NIP-44's extended length format.** Welcomes for groups above
   about 81 members depend on it. Recommendation 1 would keep Welcome plaintexts small enough not to need it.
3. **Invite in batches sized to fit relay limits,** since each added member costs about 626 bytes in the commit.
4. **Keep the tree filled.** Members' self-updates, including the existing post-join self-update, keep commit paths
   near O(log N) instead of O(N).

**Too-large handling.** These are local fixes.

5. Add a size category, make it terminal and not retried, and return a typed error to the host.
6. Check the size before publishing, against configured relay limits. Treat unknown relays as 64 KiB.
7. Give a commit that no relay may have received a terminal path. For example, after a bound, look the event up by id
   on the relays, and roll back if none has it.
8. Treat a relay that definitively rejects a commit as a delivery problem for that relay's readers, not "not owed".
9. Give Welcome rejections a terminal state.
10. Resolve KeyPackages partially (invite who resolved, report the rest), and run discovery and Welcome fanout off the
    worker (Pass 1 B step 3).

**Readiness and the boundary.**

11. Expose per-route coverage (EOSE plus paging), and keep batch membership stable across repacks.
12. Add a transport-neutral coverage surface next to `TransportAdapter`, instead of reaching into the concrete
    relay-plane type.
13. Add Open Ranking to the dial-safety chokepoint table.

## 10. Possible defects found in this pass

All five are filed. [#2336](https://github.com/marmot-protocol/mdk/issues/2336) tracks the large-group work, including
the protocol change in recommendation 1 and the existing [#1638](https://github.com/marmot-protocol/mdk/issues/1638).

| # | Candidate | Status |
| --- | --- | --- |
| E-1 ([#2332](https://github.com/marmot-protocol/mdk/issues/2332)) | A commit that every relay may have received, but none acknowledged, stays pending and retries hourly forever, blocking further commits | Observed in code (rollback condition and uncapped backoff); end-to-end effect inferred |
| E-2 ([#2333](https://github.com/marmot-protocol/mdk/issues/2333)) | A relay that definitively rejects a commit is "not owed", so members who read only that relay lose the epoch with no warning | Observed |
| E-3 ([#2334](https://github.com/marmot-protocol/mdk/issues/2334)) | No pre-publish size check, no NIP-11 use, and "too large" indistinguishable from other rejections; untyped host errors | Observed |
| E-4 ([#2335](https://github.com/marmot-protocol/mdk/issues/2335)) | Welcomes for groups larger than about 81 members need NIP-44's extended length format, which older NIP-44 libraries lack | Observed. Corrected on 2026-10-15: the extended format is part of NIP-44 v2, not a fork extension |
| E-5 ([#2336](https://github.com/marmot-protocol/mdk/issues/2336)) | Groups larger than about 1,900 cannot be joined by Welcome even on the White Noise relays | Measured |

## 11. Questions for the product owner

1. Does "3 tag constraints per filter" on the White Noise relays mean three tag keys or three values? Batches send 50
   `#h` values under one key; if it means values, every batch REQ would be refused.
2. Do White Noise users' inbox relay lists (kind 10050) default to the White Noise relays? If so, Welcomes inherit the
   2 MiB limit for most users today.
3. Do other Marmot implementations, such as Marmot-TS, support NIP-44's extended length format?
4. Do the White Noise relays prune old events? The 1,095-day window is a write-time limit, but catch-up assumes relays
   keep history.
