---
title: "Review — Core Crate Structure"
created: 2026-10-15
updated: 2026-10-15
tags: [marmot, architecture, review, structure, crates]
status: draft for discussion
---

# Review — Core Crate Structure

This page asks one question of the core crates (`traits`, `cgka-engine`, `cgka-session`, `marmot-account`,
`storage-sqlite`, `marmot-app` and the Nostr transport): is each one shaped for what it is supposed to do? It ranks
the biggest gaps between what each crate is documented to be and what it contains, and it proposes a target crate map
with a sequence for getting there. Baseline `ab1de296f`.

Line counts are production code. They exclude test files and inline `#[cfg(test)]` blocks, so they are lower than
Pass 0's figures. Counts that split mixed files by function are approximate, to about ±15%. "(inferred)" marks
judgements not traced end to end.

## Summary

1. **`marmot-app` is a product monolith in a runtime's clothing.** Its documented job is "the runtime boundary for
   client applications". Only about 23% of its 107k production lines are runtime orchestration. About 57% are product
   features, and about 20% are infrastructure and observability code (audit logs, telemetry, analytics) that belongs
   lower in the stack or in a crate of its own.
2. **The real per-account core is an undocumented god object.** `AppClient` has 58 fields and 449 methods, 299 of them
   taking `&mut self`. The docs call it "a lower-level compatibility surface", and they describe a
   `MarmotAccountSession` and `SharedServices` that don't exist. The public runtime mostly forwards calls: 179 of its
   250 public methods are thin delegations, and a feature crosses four hand-written layers.
3. **`storage-sqlite` is the app's whole data model with a protocol store inside it.** Protocol persistence is 16% of
   its production code. It exposes 389 public app methods next to 119 storage-trait methods, 84% of them used by
   `marmot-app`, and its protocol code behaves differently depending on app tables.
4. **The lower stack has three identical wrappers and no layer narrows the surface.** The account runtime makes 34
   pass-throughs and hands out the session directly. The session makes 119 more. The engine exposes 153 methods,
   about 38 of which are a storage proxy for account records plus the app's audit sink.
5. **The protocol/app boundary is crossed inside single transactions in both directions.** That, not the contracts,
   decides where code lives. Account-runtime state machines sit in `traits` because the engine's transactions write
   them. Drafts are consumed inside the engine's outbound transaction, and the engine's outbox is acknowledged inside
   the app's.
6. **`marmot-account` is two crates in one.** Account identity and files are used by the bindings, the CLI and the
   agent connector. The account-device publish runtime is used only by `marmot-app`. The two share no state.
7. **Nostr knowledge sits in the wrong layers in both directions.** It is below the transport in the engine, `traits`,
   the account crate and storage, and above it in `marmot-app`'s relay plane.

The proposed direction (§4): about eight focused crates around a slimmer engine and a smaller `marmot-app`. Start with
the seams that are already nearly separate: the media store (in progress, #2314), the relay plane and the directory.

## 1. Each crate's intended role against its contents

| Crate | Documented role | Production lines | What it actually holds |
| --- | --- | ---: | --- |
| `traits` | Shared engine, storage and transport contracts | 10,136 | The contracts (about 5.5k), plus about 2.6k of app-level types: polls, reporting, app-event UI strings, media and avatar components, agent streams, host safety. Also account-runtime state machines: the `OutboundFanout` transitions and maintenance records. |
| `cgka-engine` | The CGKA engine: MLS, convergence, capability rules | 37,203 | Protocol core and convergence: about 11.2k, including `openmls_projection.rs`, which is really the replay and apply engine. Also about 30 storage pass-throughs for account records, the app's audit recorder, and product policy (see §2.4). |
| `cgka-session` | One encrypted account-device session | 1,687 | About 700 lines of real work (open, hydrate, effect collation) and 119 pass-throughs. Its API leaks engine types, so callers import the engine anyway. |
| `marmot-account` | Account and session coordinator: publish-before-apply, transport activation | 9,400 | Account identity and files (2.7k), the publish pipeline, a second "legacy" fanout that is the live Welcome path, maintenance, KeyPackage scheduling and a routing implementation the app duplicates |
| `storage-sqlite` | SQLCipher implementation of `StorageProvider` and OpenMLS storage | 43,707 | Protocol 16%, app projections 33%, attachments and avatars 17%, recovery and transport bookkeeping 12%, product state 11%, infrastructure 7%, shared DB 2% |
| `marmot-app` | Multi-account runtime, shared services, relay plane, projections, app events | 107,048 | See §2.1 |
| `transport-nostr-*` | Nostr envelopes and the relay adapter | about 19k (non-test files) | Well scoped, but the relay plane that drives them lives in `marmot-app` |

## 2. The mismatches, in detail

### 2.1 `marmot-app`: a product monolith

| Category | Domains | Share |
| --- | --- | ---: |
| Runtime orchestration, the stated role | Runtime and lifecycle, `AppClient` core, sync, ingest and cursor, relay plane, group command plumbing | about 23% |
| Product features | Directory and search (11.9%), media (9.4%), onboarding (7.8%), messaging and timeline (6.9%), history recovery (6.4%), group management, chat list and presentation windows, notifications, drafts, agent streams, moderation | about 57% |
| Infrastructure and observability | Audit, telemetry and analytics (12.2%, the largest single domain), SQLCipher key derivation, the root lease, dial-safety helpers, `marmot-account` trait implementations, the KeyPackage lifecycle, row-to-DTO mapping | about 20% |

The crate grew from 41k lines on 2026-07-15 to 229k lines, tests included, three months later. That is about 21
lines added for every line removed.

**Four objects, unclear owners.**
- `MarmotApp` (32 fields, 355 methods across 16 files) is a service locator: every other layer holds a clone of it.
- `AppClient` (58 fields, 449 methods) is where nearly every feature lives. The worker owns it.
- `MarmotAppRuntime` (6 fields, 313 methods) is the API the hosts use (`marmot-uniffi` calls 234 of its methods). It
  mostly forwards to `AccountManager` (16 fields, 7 of them onboarding state).
- An `AccountWorkerCommand` enum with 89 variants joins them.

One reaction, for example, goes `MarmotAppRuntime::react_to_message`, then `AccountManager::send_app_event`, then
`AccountWorkerCommand::SendAppEvent`, then `AppClient::send_app_event`, then a 376-line function. The same state is
held in more than one object: `relay_plane` in four, and analytics, the audit tracker configuration and the directory
sync handle in two each.

**Cross-cutting hooks.** About 550 references to audit, performance and analytics hooks sit outside the observability
modules. Forty `_unobserved` functions exist only to pair each public operation with an instrumented wrapper. The
101-variant `AppError` and 47 crate-root re-exports tie every module to the root.

**Seams that already exist in state but not in code.**
- The relay plane depends on almost nothing else in the crate: 10% of its lines are methods on the hub objects.
- The directory makes no account-storage calls and has its own databases, yet it is written as 67 methods on
  `MarmotApp`.

Sync and history recovery are one subsystem split across two files: they share about 10 `AppClient` fields, and sync
references 48 recovery symbols.

### 2.2 `storage-sqlite`: two stores in one type

- **The callers are the app.** One concrete type, `SqliteAccountStorage`, carries 389 public app methods and 119
  storage-trait methods. About 84% of the public methods are used by `marmot-app`, and about 62 have no production
  caller outside the crate. 236 of its 251 re-exports are app DTOs.
- **It breaks a stated rule.** The root `AGENTS.md` says to keep transport-specific code out of storage crates. This
  crate holds NIP-77 reconciliation, relay-plane spill, NIP-51 block lists, the NIP-59 moderation outbox, Nostr route
  rows and Blossom upload secrets.
- **The protocol implementation depends on app state.** Message release checks whether an `account_state` row exists.
  The engine's local-forget path wipes about 20 app tables. The outbound path consumes drafts and local submissions,
  and fires an observer registered through `cgka-session`.
- **The schema is jointly owned.** Twelve of 110 migrations touch both protocol and app tables. Thirteen live triggers
  touch protocol tables: twelve rewrite `chat_list_rows` when engine leave and disband tables change, and one guards
  `cgka_groups` inserts. About 42 more cross between app domains. One of those resets the new media catalog whenever a
  presentation table's `store_epoch` changes (`migrations/0110_media_files.rs:51`). That is what #2314 specifies for a
  store reset, but it ties the media store's lifecycle to a projection table.
- **The engine's cache pays for app writes.** Every app-connection commit changes `PRAGMA data_version`, which
  invalidates the engine's cached MLS groups (`connection.rs:1387-1404`; the cost is unmeasured).

History agrees with the split. Of 164 recent commits to the crate, 69% touched no protocol module and only 15%
touched protocol and app code together.

The couplings a split has to carry, all with file:line in the source inventory:
1. The outbox is acknowledged in the app's transaction.
2. Drafts and local submissions are consumed in the engine's transaction.
3. Message release writes app recovery tables.
4. Group and route deletion clear reconciliation rows.
5. Local forget and local delete span both sides.
6. Foreign keys cascade from app tables to `cgka_groups`.
7. The engine-table triggers above update the chat list.
8. App reads join engine tables.
9. The app writes the engine's authority outbox.
10. App writes invalidate the engine's MLS cache.
11. Both sides share one migration ledger.

Several bridges already half exist: the at-least-once outbox, the released-receipt journal, the secure-delete intents
and the replay fingerprint.

### 2.3 The lower stack: three wrappers, no narrowing

A query from the app can cross the account runtime (34 pass-throughs), then the session (119), then the engine.
`session()` and `session_mut()` on the account runtime let the app skip a layer
(`crates/marmot-account/src/runtime.rs:517-523`).

The session's public API exposes `FeatureRegistry`, `CanonicalizationPolicy`, `AccountIdentityProofSigner` and
`GroupAuthoritySnapshot` without re-exporting them. That alone explains most of `marmot-app`'s direct imports of
`cgka_engine`. The session's concrete SQLite type also ends the engine's `S: StorageProvider` genericity, and nothing
above benefits from that genericity.

App concerns tunnel down through the session: the draft-commit observer and the promotion of legacy message rows.

### 2.4 The engine: protocol core plus three other jobs

- **A storage proxy for account records.** The account runtime has no store handle of its own, so the engine forwards
  storage calls for it: 21 in `maintenance.rs` and 9 for fanouts and pending references.
- **The app's audit sink.** Eight methods, plus ownership of the recorder's file path and rotation. App audit records
  travel from the app through the runtime and the session into the engine.
- **Product policy.** Several rules belong to product layers, not the protocol:
  - a chat with an `imeta` tag triggers media-secret export (`crates/cgka-engine/src/app_payload.rs:41-48`);
  - an app moderation rule decides which message kinds need source authority;
  - the join transaction creates a 24-hour post-join maintenance obligation with a relay-EOSE deadline;
  - the engine decodes `NostrRoutingV1` to derive transport routes.
- **The protocol core itself is sound.** Convergence and canonicalization are about 11.2k of the 37.2k lines, with
  the matching tests, simulator and formal model. The name `openmls_projection.rs` hides that it is the replay and
  apply engine.

### 2.5 The unit of work decides placement

Because the confirm transaction writes the `OutboundFanout` record, its 668-line state machine lives in `traits`, the
shared contract crate. For the same reason, maintenance obligations live there with an EOSE deadline field. Drafts
are consumed inside the engine's outbound transaction, and the engine's outbox is acknowledged inside the app's
checkpoint transaction.

The real architectural rule today is "whatever one transaction must cover lives in the same crate", and the
protocol/app line is drawn around that, not around responsibilities.

### 2.6 `marmot-account`: two crates

- **Who uses what.** The bindings, the CLI, the agent connector and the simulator use only `AccountHome`, its error
  and summary types, and the secret stores. Only `marmot-app` uses `AccountDeviceRuntime`. The two halves share no
  state and have different dependencies: `nostr` and the keyring on one side, the session and `traits` on the other.
- **Overlap with the app.**
  - **Routing:** the app's `AppTransportRouting` copies `StaticTransportRouting`.
  - **KeyPackages:** the account owns scheduling and state, while the app owns the Nostr event format and publishes
    outside `TransportAdapter`.
  - **Welcomes:** the "legacy" `DurableTransportFanout` is still the live publication path, next to two app-side
    mechanisms.

### 2.7 `traits`: contracts mixed with app types

About 26% of the crate is app-level: polls, reporting, the UI strings in `app_event`, the encrypted-media, avatar and
Blossom components, agent text streams, and host safety. Nostr specifics such as `NostrRoutingV1` and EOSE fields
sit in a crate meant to be transport-neutral. The `CgkaEngine` trait has no generic consumer, so it is a compile-time
witness, not the contract the layers above use.

### 2.8 Nostr in the wrong layers

- **Below the transport:**
  - the account identity proof in the engine (mdk#755);
  - `NostrRoutingV1` decoding in the engine;
  - EOSE in `traits` and in the account runtime;
  - Nostr replaceable-event floors in `AccountHome`;
  - NIP-77, NIP-51 and NIP-59 bookkeeping in storage.
- **Above the transport:** the relay plane, and with it the KeyPackage event format, in `marmot-app`.

### 2.9 Generic SDK or White Noise's app core

MDK is meant to serve any client building a Marmot app, not only White Noise. Most of the stack is generic, but some
White Noise deployment choices are compiled in:
- the recovery-operated relays are White Noise's (`crates/marmot-app/src/config.rs:18-21`);
- directory search defaults to Open Ranking (`config.rs:13-15`);
- product analytics is written directly against Aptabase (`crates/marmot-app/src/product_analytics/delivery.rs`).

Telemetry and audit delivery already use OTLP, a standard format, and take their endpoints from build-time
configuration (`config.rs:8-12`), so they are generic enough today. Only audit recording has a trait
(`ForensicRecorder` in `marmot-forensics`).

Decision for `marmot-observability`: move the code as it is first. The one seam to get right in that move is the
recording interface `marmot-app` reports through, because that is what any client sees. Exporter traits, such as a
pluggable analytics provider, can come later, if and when another client needs them.

## 3. What stays as it is

- The engine's convergence core, its explicit `EpochState`, and the verification around it (engine tests, conformance
  simulator, Tamarin model).
- The transport trait for publish and receive ([Pass 1 E](e-transport.md#7-the-transport-boundary)).
- One SQLCipher database per account-device identity, and the root lease.
- The bindings' dependence on one runtime API.

## 4. Proposed target structure

```text
Hosts:        marmot-uniffi   marmot-c   cli   agent-connector
                    │  (runtime API + account home only)
Runtime:      marmot-app ── composition root; per-account product core
                    │       (messaging, groups, projections and windows, sync + recovery,
                    │        onboarding coordinator, notifications), split by role per Pass 1 B
App services: directory   media-store + media transfer   app store   marmot-observability
                    │
Account:      marmot-device-runtime (session + publish pipeline + maintenance +
                    │                KeyPackage lifecycle + single routing + one Welcome rail)
              marmot-account (identity, files, secrets)          transport-nostr (adapter + relay plane
                    │                                             + routing, EOSE/coverage, KeyPackage format)
Protocol:     cgka-engine (protocol core; policy injected)   protocol store (StorageProvider + OpenMLS)
                    │
Foundation:   cgka-traits (contracts only)   marmot-components (app component and payload types)
              fs-private   marmot-forensics (schema)
```

| Target crate | Takes from | Main change |
| --- | --- | --- |
| `cgka-traits` | itself | Keeps the engine, storage, transport and capability contracts and the protocol component codec, about 7.5k lines. App types move to `marmot-components`; Nostr routing and EOSE move to `transport-nostr`. |
| `marmot-components` (new) | `traits` | App component and payload types: media, avatar, polls, reporting, agent-stream descriptors. It sits below the engine, because the engine validates components. |
| `cgka-engine` | itself | Protocol core only. Product rules (media-secret export, moderation authority, routing decode) come in through a small policy interface. The account-record storage proxy and audit-recorder ownership move up. `openmls_projection` gets a name that says what it does. |
| Protocol store | `storage-sqlite` | `StorageProvider` and OpenMLS storage. The app tables move out, and the cross-domain writes become explicit hooks or journals. |
| App store | `storage-sqlite` | Projections, product state and the recovery ledger. Transport-specific bookkeeping moves to `transport-nostr` or the directory. |
| `marmot-device-runtime` (new) | `cgka-session`, `marmot-account` runtime | One layer that owns the engine and its own account-record store handle: publish pipeline, maintenance, KeyPackage lifecycle, one routing implementation, one Welcome path. It re-exports the config types callers need. |
| `marmot-account` | itself | Identity, files, secret stores: what the bindings, CLI and agent already use. |
| `transport-nostr` | `transport-nostr-adapter`, `marmot-app` `relay_plane/` | Adapter plus relay plane, routing derivation, coverage evidence (EOSE and paging), and the KeyPackage event format. This is where Pass 1 E's size handling and coverage surface belong. |
| `directory` (new) | `marmot-app` `directory/`, relay-plane directory code, previews | Discovery, profiles, KeyPackage lookup and search, with the databases it already owns. |
| `media-store` and media transfer | #2314; `marmot-app` `media/` | The encrypted file store (in progress), plus Blossom transfer, crypto and resume. |
| `marmot-observability` (new) | `marmot-app` `relay_telemetry_export`, `product_analytics`, `audit_otlp_sender`, audit upload, `collector_host_safety` | The code that ships diagnostics off the device: relay telemetry over OTLP, Aptabase product analytics, audit-log upload and OTLP delivery, and the collector dial-safety checks. The recording points stay in `marmot-app` and report through one observer interface, replacing the 40 `_unobserved` pairs over time. Decided 2026-10-15: move it as it is first, and generalize later (§2.9). |
| `marmot-app` | itself | Composition root and per-account product core, organized by role (writer lane, read path, I/O lanes; [Pass 1 B](b-runtime-concurrency.md)). `AppClient` stops being a public type; only `wn sync` uses it today. |

**Dependency rules for the target:**
- Dependencies point downward only.
- App services never depend on `marmot-app`.
- Hosts depend only on `marmot-app` and `marmot-account`.
- No storage crate contains transport code.
- Nothing below `transport-nostr` knows Nostr relay semantics. Nostr identity is the documented exception.

## 5. Sequencing

Each step can ship on its own, and later steps depend on the in-flight fixes landing first.

| Step | Change | Why this order | Size |
| --- | --- | --- | --- |
| 1 | `media-store` crate (#2314) | In progress, and the template for the rest | — |
| 2 | Relay plane into `transport-nostr` | The most separable seam; gives Pass 1 E's fixes a home | about 5.5k lines move |
| 3 | Directory crate | Already owns its state; makes no account-storage calls | about 11–13k |
| 4 | `storage-sqlite` internal boundaries: `protocol/`, `app/` and an explicit `cross/` module listing the 11 couplings | Makes the split reviewable before any crate moves; no behaviour change | Moves only |
| 5 | Lower stack: merge the session into `marmot-device-runtime`, split off `marmot-account`, move the engine's storage proxy and audit ownership up, re-export config types | After #2338 and #2323 land, since both touch this code | Touches about 10 `marmot-app` files and `marmot-account` |
| 6 | `marmot-observability` for the exporters, plus an observer interface | Removes the largest `marmot-app` domain | about 7–8k |
| 7 | Inside `marmot-app`: break up `AppClient` along Pass 1 B's roles; make sync and recovery one owned subsystem; take onboarding out of `AccountManager`; remove duplicated state | Depends on the runtime work (multi-thread runtime session) | Large |
| 8 | Split `storage-sqlite` into protocol, app and base crates; move app types into `marmot-components`; inject engine policy | Last, because they need steps 4 and 5 | Large |

Steps 1, 2, 3 and 6 alone would move about a third of `marmot-app`'s production code into focused crates (inferred).

## 6. Questions for the product owner

1. Is about eight new or reshaped crates acceptable, or should some of the target crates stay as modules?
2. In the long run, should the protocol and app stores share one database file (option a) or use two (option b)? Two
   files give real isolation and remove the engine-cache invalidation and WAL contention, but every coupling in §2.2
   then needs a journal or intent.
3. Can `AppClient` stop being public? Only `wn sync` and integration tests use it.
4. Do the names `marmot-device-runtime`, `marmot-components` and `transport-nostr` work for you? (`marmot-observability`
   is agreed.)
5. Should White Noise's deployment defaults (operated relays, directory search provider, analytics provider) move out
   of the SDK into configuration that hosts pass in (§2.9)?

## Doc drift found in this pass

These architecture docs describe structure the code doesn't have:
- [`app-core-boundary.md`](../overview/app-core-boundary.md) calls `AppClient` a compatibility surface;
- [`marmot-app-runtime.md`](../overview/marmot-app-runtime.md) describes `MarmotAccountSession` and `SharedServices`;
- `storage-sqlite`'s crate docs describe a protocol store;
- `DurableTransportFanout` is labelled legacy but is the live Welcome path.

They should be corrected when the target structure is agreed.
