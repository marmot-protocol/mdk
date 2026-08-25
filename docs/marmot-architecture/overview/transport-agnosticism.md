---
title: "Transport Agnosticism — Where the Wiring Stops and How to Finish It"
created: 2026-08-23
updated: 2026-08-23
tags: [marmot, overview, transport, nostr, architecture, working-note]
status: working-note
---

# Transport Agnosticism — Where the Wiring Stops and How to Finish It

The target architecture says transport is pluggable: `CgkaEngine` emits opaque messages,
`TransportPeeler` owns envelopes, `TransportAdapter` owns carriers
([`nostr-role.md`](./nostr-role.md), [`target-architecture.md`](./target-architecture.md)).
The engine side of that boundary genuinely holds. Everything between the engine and the outside
world — the app layer in `marmot-app` — does not yet hold, and two recent pieces of evidence show
exactly where it breaks:

1. **The FIPS relay-transport spike** (`codex/fips-relay-transport-spike`). Swapping the socket
   layer took days because `NostrRelayClient` is already a trait. Anything above the socket —
   envelope selection, KeyPackage discovery, endpoint validation — required edits across three
   crates' worth of Nostr-shaped assumptions, and the spike ultimately kept a WebSocket relay for
   discovery ("relay lists and KeyPackage discovery" stayed on an ephemeral local Wok relay).
2. **Three open PRs from @lopatin96** that each poke a separate hole rather than use a seam,
   because no seam exists at the app boundary:

| PR | What it wants | Which gap it exposes |
| --- | --- | --- |
| [#1513](https://github.com/marmot-protocol/mdk/pull/1513) | Supply the nostr-sdk client (and thus its websocket transport) from outside | The app boundary has no transport seam at all; only the deep, crate-private relay-client trait does |
| [#1521](https://github.com/marmot-protocol/mdk/pull/1521) | Invite KeyPackages the caller already holds | KeyPackage *discovery* is hard-bound to account-name resolution over relays; an embedder with its own directory has no way to hand packages in |
| [#1514](https://github.com/marmot-protocol/mdk/pull/1514) | Permit one named loopback blob origin | Host-safety policy assumes the deployment shape "public DNS endpoints, loopback = tests only"; an app running its own local services doesn't fit the grammar |

Each PR's review history shows the cost of piecemeal seams: #1513 accumulated traffic-splitting
defects (stale publish-client cache, `client()` ignoring the injected plane, clone-then-replace
shutting down sibling planes), and #1521 drifted from established invite-path invariants (Welcome
delivery drive, `accept_disposition` gating). These are all instances of one unenforceable-today
invariant:

> **One-account-one-carrier:** every byte an account sends or receives — group messages, welcomes,
> publishes, discovery reads, blob fetches — goes over the same supplied transport posture.

Optional knobs deep inside `marmot-app` cannot enforce that invariant locally. A small number of
explicit seams can.

---

## Locked decisions

These are settled and bound the design below.

1. **Identity stays Nostr.** Participants are npubs. Not negotiable (Layer 1).
2. **The inner application message stays an unsigned Nostr event.** Fixed on every carrier.
   Authentication comes from MLS membership, never from an outer signature (Layer 2).
3. **Discovery stays Nostr semantically — but not necessarily over `wss://`.** We build on Nostr's
   network effects; we are not making a generic CGKA stack for any network. However, the *carrier*
   used to reach Nostr data (relays, directories, profiles, KeyPackage documents) may itself vary:
   a QUIC-by-pubkey overlay carrying Nostr wire formats is still "Nostr discovery." So the
   directory seam keeps Nostr event vocabulary and swaps only how bytes reach it.
4. **Group traffic rides any carrier.** Kind-445-style outer wrapping is a transport concern;
   other transports wrap differently.
5. **Blob storage is swappable.** Blossom is the default implementation, not the interface.

---

## Inventory: where Nostr actually lives today

Grounded survey of the leak sites, by category.

### Already clean

- **Engine → transport.** The engine emits `TransportMessage` values with opaque payloads;
  `crates/cgka-engine`'s one nostr dependency is a self-flagged TODO (`account_identity_proof.rs`,
  mdk#755).
- **Adapter contract.** `cgka_traits::TransportAdapter` (`crates/traits/src/transport_adapter.rs`)
  covers activation, group sync, publish fanout with durable `OutboundFanout`, delivery, and
  endpoint receipts. It is signer-free and Nostr-free. `TransportEndpoint` exists and its docs
  already anticipate mesh peer ids.
- **Envelope split reserved.** `TransportGroupSubscription` carries both `group_id` and
  `transport_group_id` so the MIP-01 transport-data split lands cleanly.
- **Capability negotiation** (`crates/traits/src/capabilities.rs`) enumerates
  `TransportKind::Nostr` today and was designed for more than one kind.
- **Host-safety classifier primitives**
  (`crates/traits/src/app_components/host_safety.rs`) are transport-neutral; it is their callers
  that are URL-shaped.

### Leaking

**L1. Directory plane has no seam.** KeyPackage resolution, relay lists, contact lists, and
profiles in `marmot-app` speak concrete `NostrTransportEvent` over `NostrRelayClient` /
`NostrSdkDirectoryRelayFetcher`:

- `marmot-app/src/directory/member_key_packages.rs` (`resolve_member_key_packages*`),
- `marmot-app/src/relay_plane/directory.rs` — `DirectoryRelayFetcher` is `pub(crate)`;
  the only impl is `NostrSdkDirectoryRelayFetcher`,
- `marmot-app/src/key_package_records.rs` — record validation consumes
  `NostrTransportEvent` directly,
- `marmot-app/src/lib.rs` (`relays_from_relay_list_event`, NIP-65 parsing).

This is why #1521 needs to exist and why the FIPS spike could not move discovery off WebSockets.

**L2. Envelope/peeler choice is concretely instantiated in the app.**
`NostrMlsPeeler` is constructed directly in `marmot-app/src/lib.rs`; gift-wrap construction is
duplicated outside the peeler in `notifications.rs::build_notification_gift_wrap`
(`EventBuilder::gift_wrap` called directly). The `TransportPeeler` trait
(`crates/traits/src/peeler.rs`) exists, but nothing lets a host supply a different wrapper.

**L3. Endpoint grammar triplicated.** Three independent validators encode "what a relay address
looks like," all ws/wss-and-DNS shaped:

- `crates/traits/src/app_components/routing.rs::validate_nostr_relay_url` (signed routing
  component),
- `crates/transport-nostr-peeler/src/peeler.rs::validate_welcome_relays` (attacker-controlled
  welcome `relays` tag, issue #392),
- `marmot-app/src/relay_plane/safety.rs` (`evaluate_relay_url` / `reject_unsafe_relay_host`,
  the dial chokepoint).

There is no endpoint value type owned by the traits layer; each layer re-parses strings. The FIPS
spike had to teach all three a new scheme. Note this is *not* an argument for weakening any of the
three checks — welcome-relay validation and dial safety stay exactly as strict — it is an argument
for sharing one parsed representation so a new scheme is added once, deliberately, with its own
host-safety rules.

**L4. Identity types leak inward.** `nostr::Keys` is the account secret shape throughout
`marmot-app` (including storage-facing code in `sqlcipher.rs`); `nostr_sdk::PublicKey` parses
account ids; `nostr_group_id_hex` naming reaches storage DTOs. Identity being npubs is fine;
nostr-sdk *types* being the app's lingua franca is what blocks carrier swaps at compile time.

**L5. Blob store is a concrete function pile.** `media/blossom.rs`
(`upload_blossom_blob*`, fetch path in `media/mod.rs::download_encrypted_media`,
`fetch_encrypted_media_blob`) with SSRF gates welded to Blossom URL validation
(`media/host_safety.rs::validate_blossom_fetch_url` plus resolved-address pinning). There is no
`BlobStore` seam, which is why #1514 reaches into two gates with a process-global allowlist.

**L6. Client construction is private and duplicated.** Two sites build nostr-sdk clients
(`MarmotRelayPlane::from_sdk`, `relay_client_for_account_id`), neither reachable from outside —
the direct cause of #1513 — and the per-account client cache interacts badly with late
configuration (review finding on #1513).

---

## The five seams

Each seam is a trait owned by the right crate, with a default implementation that reproduces
today's behavior exactly. Nothing changes for callers that supply none of them.

### S1. Directory seam (new — biggest gap)

A trait covering the four directory operations the app performs:

```text
KeyPackageDocument lookup/publication   (today: key-package events via DirectoryRelayFetcher)
Relay-list resolution                   (today: NIP-65 events)
Profile/contact resolution              (today: kind-0 / kind-3 events)
Welcome inbox addressing                (today: source event id from a relay read)
```

Shape follows locked decision 3: **inputs and outputs keep Nostr vocabulary** (npub ids, hex
event ids, NIP-shaped JSON payloads), while the *carrier* is injected. Concretely: promote a
public form of `DirectoryRelayFetcher` into `cgka-traits` (or a new small crate), parameterized by
`TransportEndpoint` instead of `RelayUrl`, with `NostrSdkDirectoryRelayFetcher` as the default
impl. An embedder then implements "fetch this Nostr document from my overlay" without touching
any validation logic, and #1521's caller-held packages become the degenerate case: a directory
that answers from the embedder's own index.

What stays fixed: record validation (`key_package_records.rs`), dedup-by-account semantics, and
the requirement that Welcomes address by source event id.

### S2. Peeler/envelope injection (mostly done, finish it)

`MarmotAppRuntime` already takes a boxed `TransportPeeler`. Remaining work:

- Route all wrap/unwrap through the supplied peeler; remove the direct
  `EventBuilder::gift_wrap` call in `notifications.rs` behind either the peeler or a
  peeler-adjacent notifier seam so notification gift-wraps follow whatever wrapper the runtime
  uses.
- Make the default (`NostrMlsPeeler`) explicit at the composition root instead of constructed at
  use sites (`lib.rs:3353`, tests).

### S3. Endpoint type owned by traits

Introduce one canonical parsed endpoint representation in `cgka-traits` (generalizing
`TransportEndpoint`), with per-scheme classification contributed by each transport — including
scheme-specific host-safety rules (a QUIC-by-pubkey endpoint names a node, not a DNS host, and
gets its own classifier arm rather than a bypass). Refactor the three validators (L3) to consume
it. Rules per validator do not change on day one; only the shared parsing does. New schemes then
land as one deliberate change in traits + one chokepoint arm each in the peeler validator and
dial-safety chokepoint, instead of three scattered grammar edits.

### S4. Blob store seam

Extract `BlobStore` (`put` / `get` / descriptor validation) into traits-adjacent surface with
Blossom as default impl. Host-safety policy becomes configuration the host supplies to the store
(per-endpoint permits, dev-loopback flags), replacing #1514's process-global `OnceLock` — which
its own author flagged as a compromise. The SSRF discipline (validate scheme, validate resolved
address, pin) moves behind the seam once and applies to whatever store implements it.

### S5. Composition-root wiring in `marmot-app`

Replace L6's two private constructors plus optional-knob builders with one explicit host-supplied
bundle installed before any account work:

```text
TransportBundle {
    adapter:        Arc<dyn TransportAdapter>,      // S2 consumer; default = Nostr adapter
    directory:      Arc<dyn Directory>,             // S1; default = Nostr SDK fetcher
    blob_store:     Arc<dyn BlobStore>,             // S4; default = Blossom
    account_client_factory / equivalent             // folded here, not a separate knob
}
```

Fail-closed rule: **an app uses either the full default bundle or a fully supplied one.**
Partially-supplied configurations are constructor errors, not fallbacks — that single rule would
have prevented every traffic-split defect found in #1513 review (stale cache, `client()` ignoring
the plane, clone divergence). Supplied components are owned by the host: replacement after startup
is rejected rather than wound-down implicitly.

Type hygiene rides along: public APIs and DTOs take hex/opaque ids; npub↔type conversion happens
only inside the Nostr default implementations (L4).

---

## Sequencing

Ordered so each step ships independently useful and no step requires a protocol change.

1. **S5 first, minimal:** fail-closed bundle + constructor-time injection of the pieces that
   already have traits (`TransportAdapter`, `TransportPeeler`). This alone resolves most of
   #1513 and establishes the invariant enforcement point. Deprecate the builder knobs as they
   fold in.
2. **S1:** public directory trait + default Nostr impl; rewire member-key-package resolution and
   relay-list handling onto it. Land #1521 rebased onto it (its multi-device test remains the
   proof; the API becomes "packages from your directory," with account-name resolution as the
   built-in directory).
3. **S3:** endpoint type consolidation. Pure refactor, big de-risking payoff for every later
   carrier.
4. **S4:** blob store seam; re-do #1514 as config-on-the-store.
5. **S2 cleanup:** notification gift-wrap routing, peeler-at-composition-root.
6. **Second-adapter proof:** repeat the FIPS-native exercise against the finished seams. Exit
   criterion: group delivery + welcomes run end-to-end with zero WebSocket endpoints configured,
   discovery carried over the alternate carrier using unchanged Nostr document formats, and the
   diff touches only the new seams plus one host-safety chokepoint arm.

PR disposition under this plan: **#1513** collapses into S5 (hold or land-short with the
understanding that the builder knobs are transitional). **#1521** stands on its multi-device
merits — the protocol already describes multiple leaves per account — and gets reframed as the
first consumer of S1. **#1514** waits for S4 unless needed sooner, in which case land it as-is
behind a documented "transitional" note.

## Invariants the seams must preserve

- One-account-one-carrier (enforced structurally by S5's fail-closed bundle).
- Layer 2 inner-event format untouched on all carriers (peeler seam swaps wrappers only).
- Welcome-relay validation (#392) and dial-safety discipline (`dial-safety.md`) stay strict per
  scheme; a new scheme adds rules, never bypasses them.
- Privacy-safe telemetry/observability contracts apply to every adapter impl by construction
  (`relay_plane/telemetry.rs` patterns; aggregate-only, no endpoints/pubkeys in logs).
- Multi-step state-change discipline (`multi-step-state-changes.md`) applies to the bundle
  install itself: validate-before-mutate, no partial bundles observable.
- `crates/traits` stays free of nostr-sdk dependencies; Nostr specifics live in default impls
  only.

## See also

- [`nostr-role.md`](./nostr-role.md) — three-layer model this note implements.
- [`nostr-account-transport.md`](./nostr-account-transport.md) — directory/bootstrap/routing
  boundaries this note consolidates.
- [`dial-safety.md`](./dial-safety.md) — per-transport chokepoint discipline S3 must respect.
- [`target-architecture.md`](./target-architecture.md) — the four-component target these seams
  complete.
