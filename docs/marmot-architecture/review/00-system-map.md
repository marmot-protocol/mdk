---
title: "Review Pass 0 — System Map"
created: 2026-10-15
updated: 2026-10-15
tags: [marmot, architecture, review, system-map]
status: draft
---

# Review Pass 0 — System Map

This pass describes what exists. It does not judge it; Pass 1 does that. Each section summarizes one detailed map page
and lists the observations that page raised for Pass 1 to test. Source references are pinned to the review baseline,
commit `9c95ff2bf` on `master`.

| Page | What it maps |
| --- | --- |
| This page | Crate layering, dependency edges, change coupling, cross-cutting observations |
| [`map-authority.md`](map-authority.md) | Every durable store, who writes it, and what is authoritative versus derived |
| [`map-concurrency.md`](map-concurrency.md) | Host entry points, tasks, the account worker, channels and locks |
| [`map-engine-contract.md`](map-engine-contract.md) | Engine state, the per-group state machine, and the API the layers above use |
| [`map-journeys.md`](map-journeys.md) | Six end-to-end journeys traced hop by hop |
| [`map-platforms.md`](map-platforms.md) | Build matrix, platform-specific code, lifecycle and resource assumptions |

## 1. Layering

### Intended layering

The architecture docs ([`target-architecture.md`](../overview/target-architecture.md),
[`marmot-app-runtime.md`](../overview/marmot-app-runtime.md)) describe a strict stack. Each layer depends only on the
one below it, and transport is reached through traits:

```text
host app ─► binding ─► marmot-app ─► marmot-account ─► cgka-session ─► cgka-engine ─► StorageProvider (trait)
                           │                │                                │
                           │                └──► TransportAdapter (trait)    └──► TransportPeeler (trait)
                           └──► relay plane (implements TransportAdapter for the Nostr carrier)
```

### Actual crate sizes

Rust lines under each crate's `src/`, excluding test files kept there (`tests.rs`, `tests/`, `*_tests.rs`,
`test_support`). Inline `#[cfg(test)]` modules are still counted, so these numbers are upper bounds.

| Layer | Crate | `src/` lines |
| --- | --- | ---: |
| Bindings and hosts | `marmot-uniffi` | 25,367 |
| | `marmot-c` | 20,096 |
| | `cli` (`wn`, `wnd`, TUI) | 32,374 |
| | `agent-connector` (`wn-agent`) | 11,964 |
| App runtime | `marmot-app` | 138,786 |
| Account | `marmot-account` | 9,715 |
| Session | `cgka-session` | 1,687 |
| Engine | `cgka-engine` | 41,522 |
| Storage | `storage-sqlite` | 62,867 |
| Transport | `transport-nostr-adapter` | 16,701 |
| | `transport-nostr-peeler` | 2,458 |
| | `transport-quic-stream`, `transport-quic-broker` | 4,152 |
| Agent streams | `agent-control`, `agent-stream-compose` | 3,386 |
| Foundation | `traits` (`cgka-traits`) | 11,840 |
| | `marmot-forensics` | 8,169 |
| | `marmot-markdown` | 6,147 |
| | `fs-private` | 2,095 |

`marmot-app` is 35% of the reviewed source (399k lines): 3.3 times the engine and 2.2 times storage. Its largest
parts are `runtime/` (38k lines), `client/` (35k), 34k lines of top-level modules (`lib.rs` alone is 8k),
`directory/` (11k), `relay_plane/` (7k) and `media/` (7k). The crate also contains notifications, moderation
reports, onboarding, history recovery, audit logging, telemetry, product analytics, public event previews, chat and
conversation presentation, drafts and user blocks.

### Dependency edges that skip a layer

`cargo metadata` shows these normal (non-dev) edges that bypass the intended stack:

| From | To | What crosses |
| --- | --- | --- |
| `marmot-app` | `storage-sqlite` | 52 non-test files import `storage_sqlite::` directly. Projections, attachments, drafts and recovery state are read and written without going through the session or account layers. |
| `marmot-app` | `cgka-engine` | 10 non-test files import `cgka_engine::` directly. |
| `marmot-app` | `cgka-session` | 10 non-test files, beside the `marmot-account` path. |
| `marmot-uniffi` | `cgka-engine`, `marmot-account`, `transport-nostr-peeler` | Account identity proofs and signer types (`crates/marmot-uniffi/src/external_signer.rs:4`), secret-store and account types. |
| `marmot-c` | `marmot-uniffi` | The C ABI is built on top of the UniFFI crate, not beside it. |
| `marmot-c` | `transport-nostr-adapter` | The process network proxy (`crates/marmot-c/src/nip46.rs:25`). |
| `cgka-session` | `storage-sqlite` | The session is concrete over `Engine<SqliteAccountStorage>` (`crates/cgka-session/src/lib.rs:194`), so the engine's `S: StorageProvider` genericity stops one layer up. |
| `cgka-engine` | `marmot-forensics` | The engine emits forensic audit records directly (`epoch_manager.rs`, `distributed_convergence.rs`, `group_lifecycle.rs`). |

In practice, `storage-sqlite` serves as `marmot-app`'s data layer as well as the engine's persistence backend. It
defines the `Stored*` row types for app projections, and `marmot-app/src/conversions.rs` maps them to app DTOs.

### Public surface sizes

These are approximate regex counts of non-test declarations. They indicate how much surface each layer mirrors by hand:

| Crate | Public functions | Public types |
| --- | ---: | ---: |
| `marmot-app` | about 806 `pub fn` | about 316 `pub struct`/`pub enum` |
| `marmot-uniffi` | about 352 `pub fn` | about 341 UniFFI records, enums and objects |
| `marmot-c` | 211 `extern "C"` functions | (C structs mirror UniFFI types) |

## 2. Change coupling

Git history shows which systems change together, a direct measure of how well the boundaries hold. Method:
non-merge commits on `master` from 2026-07-15 to the baseline, counting only non-test files under `crates/`. Each
path maps to a Pass 1 system (A to H, see the [review README](README.md#plan)). Reproduce with
`python3 -I docs/marmot-architecture/review/change_coupling.py . 2026-07-15 9c95ff2bf`.

- 790 commits; 638 touched non-test source in reviewed crates.
- 260 of those (41%) touched one system, 378 (59%) touched two or more, and 103 touched four or more.

Most frequent pairs:

| Pair | Commits touching both | Share |
| --- | ---: | ---: |
| B app runtime + G surfaces | 217 | 55% of B's 397 |
| B app runtime + C storage | 126 | 75% of C's 169 |
| C storage + G surfaces | 96 | 57% of C's 169 |
| A engine + B app runtime | 86 | 47% of A's 182 |
| B app runtime + E transport | 81 | 81% of E's 100 |
| B app runtime + D session/account | 73 | 86% of D's 85 |
| B app runtime + H sidecars | 69 | 85% of H's 81 |

Three readings to test in Pass 1:

- **Storage is not independent of the app.** Three quarters of storage changes also change the app runtime, which
  fits `storage-sqlite` carrying app projections.
- **Every app feature is plumbed by hand through the surfaces.** Over half of app-runtime changes also touch
  bindings or the CLI, which fits three hand-maintained public surfaces (UniFFI, C ABI, CLI) that mirror
  `marmot-app`.
- **Almost nothing below the app changes alone.** Transport, session/account and sidecar changes nearly always
  touch `marmot-app` too. Either the lower crates' contracts are still moving, or their real owner is the app
  runtime.

## 3. What the detailed maps found

One paragraph per page; each page has its own observation list.

- **[Authority](map-authority.md).** Each account has one SQLCipher database holding both the protocol authority and
  every product projection, including up to 2 GiB of attachment bytes with no eviction. The engine and the app each
  hold their own connection to it, write each other's tables, and are joined by a durable outbox
  (`pending_application_events`) plus 131 triggers. Several stores grow without reclamation, and the CLI runs
  without the root lease.
- **[Concurrency](map-concurrency.md).** One worker task per account owns the whole stack and serves an 89-variant
  command enum. MLS crypto, synchronous SQLCipher and relay-publish awaits run inline on it. Under UniFFI, every task
  in the runtime shares one `async-compat` thread, so on iOS, Android and macOS all accounts and the relay plane are
  serialized on a single OS thread. C and CLI hosts get multi-thread runtimes.
- **[Engine contract](map-engine-contract.md).** `EpochState` is explicit, but the effective per-group lifecycle
  spans at least eight facets. Only 2 of 17 engine events are durable. Six outbound durability rails coexist. The
  scheduling hint for convergence passes through five in-memory copies. The API is 153 engine methods behind 119
  near one-to-one session pass-throughs, and the `CgkaEngine` trait is not what the layers above use.
- **[Journeys](map-journeys.md).** A send crosses about 17 hops and 9 layers with about 20 type conversions, and it
  holds the worker for up to 20 s per relay. Inbound messages are deduplicated in at least six places. Every live
  checkpoint marks the chat list stale, and the next chat-list read then rebuilds every row. Cold start pays about
  five PBKDF2 runs per account. Recovery and attachment ownership is each spread across five or more components.
- **[Platforms](map-platforms.md).** Windows has no host-facing binding build. Mobile builds compile and link in CI
  but run no tests. Real platform secret stores never run in CI. The notification-extension path spends most of
  its time before its bounded wait starts.

## 4. Cross-cutting themes for Pass 1

These recur across several maps. They are hypotheses to test, not conclusions.

1. **The account worker is both the center of the system and its bottleneck.** Engine, storage, publish, projections,
   media scheduling, recovery and maintenance all run through one actor per account, and under UniFFI all actors
   share one thread. Most head-of-line and latency findings trace back here.
2. **One database, two owners.** Protocol state and product state share a file, two connections, an outbox,
   cross-writes and triggers. Bulk bytes share the protocol database's mutex, WAL and `secure_delete`.
3. **Mechanisms multiply by addition.** Six outbound durability rails, three Welcome publication paths, five copies of
   the pending-convergence set, six dedup layers, incremental history tracked twice, and two chat-list writers per
   send. Each looks like a fix added next to the previous mechanism rather than replacing it.
4. **Hidden O(history) costs on hot paths.** Each canonical convergence apply copies the group's whole message
   ledger. Each live checkpoint triggers a full chat-list rebuild on the next read. Full hydration reads every
   message row of a group. Recovery selection runs on every delivery. The first is now measured
   ([#2326](https://github.com/marmot-protocol/mdk/issues/2326)): at 50,000 messages, each apply writes and deletes a
   28.5 MB snapshot, and the applying pass takes 0.47 s with old history and 1.35 s with recent history, on an M4 Max.
   The others are not yet measured.
5. **The lifecycle contract does not fit mobile well.** Suspension means terminal close and a full rebuild. A cold
   start is expensive. Startup serializes behind a process-wide mutex. `shutdown_and_close` leaves the engine's
   connection to the graceful phase.
6. **Many invariants exist only in prose.** "Single writer" comments that the code contradicts, `AGENTS.md` rules that
   compensate for missing structure, and architecture docs that have drifted from the code: the index's
   current-vs-target table, the `marmot-app-runtime.md` scheduling description, the publish-before-apply steps in
   `target-architecture.md`, and `attachment-acquisition.md`.

## 5. Possible defects found during Pass 0

The review does not fix anything, but these look like bugs rather than design questions. D1 and D2 are filed;
the others still need confirming.

| # | Candidate | Evidence | Confidence |
| --- | --- | --- | --- |
| D1 ([#2323](https://github.com/marmot-protocol/mdk/issues/2323)) | `shutdown_and_close` can return, or release the root lease, while the engine's `session.sqlite` connection is still open | [Journey 4, observation 1](map-journeys.md#journey-4-startup-and-shutdown); the suspension tests never start a worker | Observed in code; impact not reproduced |
| D2 ([#2324](https://github.com/marmot-protocol/mdk/issues/2324)) | QUIC broker dials with platform trust fail on Android, because `rustls-platform-verifier` is never initialized | [Platforms, observation 2](map-platforms.md#observations-for-pass-1) | Observed in code and dependency source; not run on a device |
| D3 | Swift and Kotlin hosts run every runtime task on one thread | [Platform map §3](map-platforms.md#3-async-runtime-per-host); [concurrency observation 1](map-concurrency.md#observations-for-pass-1). In the field, iOS and Android show UI stalls; macOS, on the same binding with a faster CPU, shows fewer, mostly loading delays when opening a group. The Linux desktop app on the multi-thread C ABI is not yet compared. | Observed in code and dependency source; consistent with field symptoms; needs a thread trace on a device |
| D4 | Every live checkpoint causes a full chat-list rebuild on the next read | [Journey 2, observation 2](map-journeys.md#journey-2-receive-and-converge) | Observed; cost unmeasured, intent unclear |
| D5 | The NAT64 prefix is rejected, so IPv4-only HTTP and QUIC hosts may be unreachable on IPv6-only networks | [Platforms, observation 7](map-platforms.md#observations-for-pass-1) | Inferred |
| D6 ([#2326](https://github.com/marmot-protocol/mdk/issues/2326), [#2330](https://github.com/marmot-protocol/mdk/issues/2330)) | Every canonical convergence apply copies the group's whole message ledger, and every pass rescans all messages in the rewind horizon | [Authority, observation 9](map-authority.md#observations-for-pass-1); benchmark in the issue | Observed and measured |
| E-1 to E-5 ([#2332](https://github.com/marmot-protocol/mdk/issues/2332)–[#2336](https://github.com/marmot-protocol/mdk/issues/2336)) | Transport: a commit that may have reached a relay retries forever, rejecting relays are "not owed", no size checks, large Welcomes that need NIP-44's extended length format, and groups over about 1,900 members cannot be joined | [Pass 1 E §10](e-transport.md#10-possible-defects-found-in-this-pass) | Observed and measured |

## 6. Seams the map suggests

Structural splits, including breaking up `marmot-app`, are in scope (see the [review README](README.md)). The map
shows where seams already exist in practice. These are candidates for Pass 1 to evaluate, not recommendations.

- **Relay plane** (`relay_plane/`, about 7k lines). It already owns its own tasks, queues, spill and loss evidence,
  and it implements the transport trait the engine stack uses.
- **Content acquisition** (`media/`, attachment runtime, and the attachment and avatar stores). It has its own state
  machine, budgets, permits and byte stores, and today its bytes live in the protocol database.
  [#2314](https://github.com/marmot-protocol/mdk/issues/2314) is moving them into an encrypted per-file store; its
  step 0 format code (PR [#2320](https://github.com/marmot-protocol/mdk/pull/2320)) started in
  `storage-sqlite/src/media_store/`. It is now agreed to become its own `media-store` crate
  ([proposal](https://github.com/marmot-protocol/mdk/issues/2314#issuecomment-6189159429)): a mechanism crate with no
  SQL, a catalog trait implemented by `storage-sqlite`, the crash-safety orchestration inside the crate, all calls on
  the blocking pool, and one shared close registry. It is the first split out of the app and storage monolith and a
  possible template for the other seams listed here.
- **History recovery.** It has a durable obligation machine, a credit pool and a network job, but its ownership is
  spread across the relay plane, `AppClient`, the worker and storage.
- **Directory and discovery** (`directory/`, about 11k lines). It has its own databases, already outside
  `session.sqlite`.
- **Projections and presentation** (timeline, chat list, conversation and presentation windows). They are derived
  from the engine outbox but live in the protocol database and are maintained partly by triggers.
- **Sidecars** (audit, telemetry, analytics). They touch the runtime in 85% of their commits.

## 7. Proposed Pass 1 order

1. **B, app runtime concurrency** first. Drafted: [`b-runtime-concurrency.md`](b-runtime-concurrency.md). Themes 1 and 5 and candidates D1 and D3 depend on it, and the single-thread
   question should be settled with a device trace before anything else is redesigned.
2. **C, storage, and A, the engine**, in parallel. Themes 2, 3 and 4 run through both.
3. **D, publish-before-apply**, once A and C have described the rails and the outbox.
4. **E, transport** (drafted: [`e-transport.md`](e-transport.md)); **F, content acquisition; G, surfaces; H, sidecars.** These are mostly about where the seams in §6
   should fall.

Measurements to collect early, because several themes depend on numbers:

- a thread-name trace of a MarmotKit build under load;
- cold-start time per account split into KDF, migrations and hydration;
- chat-list rebuild cost against chat count;
- convergence-apply snapshot cost against group history length (done: [#2326](https://github.com/marmot-protocol/mdk/issues/2326));
- worker command latency while a convergence pass or a catch-up runs.
