# Outgoing-message latency investigation

## Scope and provenance

The baseline below records the diagnostic investigation. The subsequently authorized
implementation is described in **Implementation follow-up**. The opt-in harness lives in
`src/tests/conversation_cold_open/send_latency.rs` and reuses the existing encrypted
account, scripted relay, and retained-history fixture.

## Implementation follow-up

The working branch now includes return-to-latest checkpoint support, persisted
local caller correlation, an additive durable-admission queue ahead of worker
publication, and revisioned-draft hydration/descriptor-read optimizations. Binding
contracts and host migration guidance live in
[`LOCAL-SENDS.md`](../marmot-uniffi/LOCAL-SENDS.md).

The follow-up navigation race measurement delivered pending rows before relay
release in all ten trials (including all five navigation-first trials). A separate
regression exercises history-to-latest and stale-revision retries during a held
publication. Local-admission regressions cover exact token reuse/conflicts,
distinct identical sends, token-free wire payloads, admission behind blocked
publication, and startup draining. Storage coverage checks atomic engine handoff
rollback; binding coverage checks prepared-window cache invalidation and token
deep-free ownership.

Quiet follow-up draft measurements (same disk-backed fixture/toolchain/profile;
30 samples per size):

| Attachment bytes | Save p50 before → after | Save p95 before → after | Selected-read p50 before → after |
| --- | --- | --- | --- |
| 0 | 0.652 → 0.673 ms | 1.238 → 1.340 ms | after: 0.020 ms |
| 4 MiB | 36.779 → 15.013 ms | 47.953 → 16.253 ms | 8.648 → 0.028 ms |
| 16 MiB | 142.442 → 54.846 ms | 162.961 → 56.336 ms | 34.513 → 0.029 ms |

The first follow-up ran alongside binding compilation and had substantial 16-MiB
tail outliers; the isolated draft rerun above removes that known interference.
Logs: `/tmp/opencode/mdk-send-latency-after.log` and
`/tmp/opencode/mdk-draft-latency-after-quiet.log`. These remain workstation
measurements, not iPhone performance claims. Attachment equality comparison still
hydrates existing bytes and remains size-dependent.

Follow-up verification passed: `just fast-ci` (including binding-documentation and
C command-parity gates), 101 selected local-state/send/binding tests across the
four touched runtime/storage/binding crates, 46 conversation-window tests, 19
storage draft tests, five app draft-lifecycle regressions, and all five opt-in
measurement scenarios. The final six-test submission subset was rerun after the
background-read interruption and completion-transaction changes. C headers were
regenerated, and token deep-free tests ran with `alloc-audit`. Host/device artifact
smoke tests and iPhone measurements are not part of this Linux validation.

Final logs: `/tmp/opencode/mdk-send-fast-ci-final.log`,
`/tmp/opencode/mdk-local-send-final-tests.log`,
`/tmp/opencode/mdk-window-regressions.log`, and
`/tmp/opencode/mdk-draft-regressions-after.log`.

- Investigated MDK base: `f669d808` (master, September 20, 2026).
- iOS source previously inspected: `3db71627df7e28bb24ee4feba05994a74caba04c`.
- That iOS revision pins MarmotKit 0.10.2, MDK
  `7dba6fc83eb054c6d703da182300a8e0f140eefc`.
- Draft app methods, revisioned draft storage, send-client implementation, and
  conversation-window implementation are unchanged between the pinned release
  and the investigated base. The command-file additions are unrelated diagnostic
  APIs. This is source comparison, not a benchmark of both complete releases.

## Reproduction

Use a disk-backed directory for temporary databases. On the investigation host,
the default `/tmp` is tmpfs, which would hide durable-write costs. Build artifacts
may live on tmpfs; account databases should not.

```sh
mkdir -p target/latency-fixtures
TMPDIR="$PWD/target/latency-fixtures" \
RUST_MIN_STACK=33554432 \
CARGO_PROFILE_TEST_DEBUG=0 \
CARGO_PROFILE_TEST_OPT_LEVEL=1 \
CARGO_INCREMENTAL=0 \
cargo test -p marmot-app send_latency -- --ignored --nocapture --test-threads=1
```

These are diagnostic distributions, not timing thresholds for CI. All fixtures
are synthetic and the relay is in-process; no real network or user data is used.
Output contains only fixed phase labels, fixture sizes/counts, and durations.

### Measurements

- `measure_draft_save_latency`: 30 revision-checked caption saves and selected
  reads each for text-only, 4 MiB, and 16 MiB attachment drafts. Attachment content
  stays unchanged within each size. The first save includes attachment insertion
  or replacement; subsequent samples update the caption. App-layer input cloning
  is included, Swift/UniFFI conversion is not. Existing storage timing observers
  distinguish connection wait, write begin, and transactions; these nested samples
  overlap and must not be summed as disjoint phases.
- `measure_draft_save_under_transaction_contention`: another thread owns the
  account-storage transaction before the save starts, then releases it after an
  intentional 500 ms hold. This demonstrates sensitivity to contention, not that
  production transactions normally take 500 ms.
- `measure_pending_window_latency`: an established, authority-ready latest window
  receives ten draft sends with relay publication blocked, at zero and 2,000
  retained messages. Submission-to-window includes worker admission and projection,
  but excludes draft saving, startup, FFI, and host layout. The relay is released
  only after observation or the watchdog. Response timing includes that artificial
  barrier and is not a normal network-delivery benchmark.
- `measure_send_queued_behind_blocked_publish`: a first send holds the worker in
  publication. A synchronous draft read/save runs during that hold; a second draft
  send is polled for 500 ms. The test checks that the second send has not created
  its own pending projection before the first publication is released. Queue
  timing separates the first send's startup wait from the second send's wait.
- `measure_latest_command_racing_send`: the same established window receives both
  a return-to-latest command and a draft send. Both executor enqueue orderings are
  exercised. Stale-window rejection is counted separately from accepted navigation
  commands, and missing pending updates within the 500 ms relay hold are counted.
  The test does not implement the host's stale-revision retry loop.

## Interpretation boundaries

The harness measures Rust on Linux, not an iPhone. It does not reproduce Swift
task scheduling, optimistic-row suppression, draft autosave orchestration,
attachment uploads, real relay latency, or a full incoming catch-up workload.
The large-history fixture has one group and synthetic retained messages; it is
not a multi-account or large-roster benchmark.

A fast idle draft save cannot rule out storage contention on a device. A fast
pending projection for the first send cannot rule out a second send waiting
behind publication. A stable local message identity and durable acceptance are
separate from the eventual send response and from host rendering.

## Recorded results (September 20, 2026)

Final run: Linux x86-64, Intel Core i9-10850K, Rust 1.97.1, optimized test
profile (`opt-level=1`, debug assertions enabled), serial tests, encrypted
databases on `/dev/sda2`, default WAL/FULL storage settings. The final run followed
completion of the other Cargo jobs. These are single-run diagnostic samples,
not a controlled hardware benchmark or an iOS latency prediction.

| Operation | Samples | p50 (ms) | p95 (ms) | Max (ms) |
| --- | ---: | ---: | ---: | ---: |
| Text draft save | 30 | 0.652 | 1.238 | 2.149 |
| Text selected-draft read | 30 | 0.020 | 0.021 | 0.024 |
| Draft save, unchanged 4 MiB attachment | 30 | 36.779 | 47.953 | 155.937 |
| Selected-draft read, 4 MiB attachment | 30 | 8.648 | 8.800 | 42.369 |
| Draft save, unchanged 16 MiB attachment | 30 | 142.442 | 162.961 | 336.528 |
| Selected-draft read, 16 MiB attachment | 30 | 34.513 | 34.928 | 35.578 |
| Submit to pending window, no retained history | 10 | 33.011 | 41.474 | 41.474 |
| Submit to pending window, 2,000 retained messages | 10 | 34.332 | 39.572 | 39.572 |

The attachment-save rows include the initial insertion/replacement sample as
described above. With only ten samples, the reported p95 is the maximum.
Storage timing observers reported effectively zero connection wait in the
uncontended draft cases. Millisecond runtime histograms truncate sub-millisecond
samples; zero sums do not mean that no work occurred.

### Main finding: navigation can defeat the pre-publication fast path

All five trials that enqueued return-to-latest before Send accepted the navigation
command and failed to deliver a pending row within the deliberate 500 ms relay
hold. After releasing publication, navigation completed with the sent message in
its snapshot. All five reversed-order trials rejected navigation as stale and
delivered the pending row before release, in 34–38 ms. This is not evidence that
stale rejection is a fix; real hosts retry stale commands, which this harness
does not emulate.

The ordering matches the inspected iOS send path: it enqueues follow-latest
immediately before handing off the outgoing message.

The source-level mechanism is in `src/runtime/conversation_window.rs`:

1. The window actor handles an explicit command by calling `reader.read` with
   `allow_checkpoint = command.is_none()`, so commands pass `false`.
2. `Reader::capture_live` consequently neither takes the pending send capture nor
   listens for its notification. It enqueues `CaptureConversation` on the account
   worker and awaits the reply.
3. The send occupying that worker can already have written and published its local
   capture, then be awaiting relay publication.
4. The window actor is awaiting its command read, so it cannot deliver the pending
   capture through the ordinary invalidation path in the meantime.

This establishes a concrete route for relay latency to become bubble latency
despite the ordinary pending-window path being independent of publication.
It does not establish that this was the exact incident on the user's device.

### Worker serialization and storage contention are separate

- With a deliberately held account transaction, the draft save took **506.651 ms**.
- While the worker was instead blocked in relay publication, draft read plus save
  took **2.574 ms**: that local API is not inherently queued behind publication.
- A second send behind that blocked publication did not produce a second local
  projection during the 500 ms hold. Its queue wait was **530 ms**, and its complete
  response took **563.459 ms** including the injected hold.
- The first send in that scenario also had a **758 ms** queue wait after account
  reconciliation/startup. This is distinct from the authority-ready warm-window
  scenario, whose ten sends had a zero-millisecond aggregate queue wait. Startup
  is not included in the warm-window numbers.

### Attachment drafts have a separate size-dependent cost

Even caption-only saves reuse an API taking all attachment plaintext. Storage
loads existing attachment bytes to compare them, then reloads the hydrated saved
draft, although the revisioned caller ultimately returns selected metadata.
These are concrete sources of avoidable work to investigate.

The descriptor-only selected read also scales with attachment size in this run.
The query selects metadata columns following `plaintext` in the attachment row;
inspect SQLCipher/SQLite overflow-page access and storage layout before assuming
that excluding plaintext from the result makes that read constant-cost. The
harness measures this scaling but does not prove its low-level cause.

## Recommended next changes, in priority order

1. **Fix the latest-command/pending-capture interaction.** Preserve query,
   generation, authority, and revision coherence, but prevent an accepted
   follow-latest operation from blocking local-send visibility behind transport.
   Evaluate a same-query fast path or a command-compatible coherent capture rather
   than indiscriminately enabling stale checkpoints for all navigation commands.
   Promote the reproduced ordering to a deterministic regression test with a
   blocked relay; include stale retries and history-to-latest navigation.
2. **Coordinate with iOS.** Avoid unnecessary follow-latest commands when already
   following latest, and keep immediate host-owned visual acknowledgment separate
   from projection availability. Exact reconciliation still needs a stable identity.
3. **Optimize attachment-draft operations.** Investigate metadata-only updates and
   eliminating hydrated return values from the revisioned save path. Verify that
   revision conflicts, attachment ordering, and newer edits retain their semantics.
4. **Treat early durable acceptance as a separate API/scheduling design.** It is
   useful for correlation and repeated sends, but returning earlier alone will not
   remove a worker queue blocked behind another operation. Preserve durable outbox
   ownership and mutation ordering rather than acknowledging an in-memory enqueue.
5. **Profile real catch-up contention on device if delays remain.** The controlled
   transaction experiment demonstrates the dependency; it does not identify a
   production lock holder. Do not weaken durability or shorten busy timeouts based
   on that experiment.

## Validation and artifacts

- Five opt-in measurement scenarios passed on Rust 1.97.1.
- Five existing `draft_lifecycle` tests passed.
- Existing `live_window_observes_pending_send_while_relay_publish_is_blocked`
  regression passed (direct, draft, and definitive-failure cases).
- `cargo clippy -p marmot-app --tests -- -D warnings` passed.
- Workspace formatting and `git diff --check` passed.

The host's default Rust 1.97.1 installation was incomplete. A complete pinned
toolchain was installed under `/tmp/opencode/mdk-latency-rustup`; repository
toolchain files were not changed. An earlier exploratory run used 1.96.1 and is
not the source of the final table. Compilation used a 32 MiB Rust thread stack
after the smaller-stack exploratory compiler crashed.

Final local output: `/tmp/opencode/mdk-send-latency-final.log`.
Draft regression output: `/tmp/opencode/mdk-draft-regressions.log`.
Clippy output: `/tmp/opencode/mdk-send-latency-clippy.log`.
The harness and this report are retained on the investigation branch; temporary
logs and build artifacts are not tracked.

## Original iOS correlation requirements

The iOS agent requests an opaque caller-supplied `client_token` on text, reply,
draft, and upload-and-send commands, echoed as
`TimelineMessageRecordFfi.client_token: Option<String>`. The original proposal below
is retained as design rationale. The implemented additive API and its explicit
idempotency/retention limits are documented in
[`LOCAL-SENDS.md`](../marmot-uniffi/LOCAL-SENDS.md).

The request addresses a distinct race from window latency: MDK's first own-row
projection may precede the send response that supplies its authoritative message
ID. Fingerprint matching cannot be exact if content differs, and identical sends
must not be matched by text alone.

Original recommended contract:

- The host creates a token before inserting its optimistic row. MDK treats it as
  opaque local correlation metadata and echoes it unchanged, without normalization.
- Persist the token-to-message association in the encrypted account-device store
  atomically with the first local projection. The first row delivered through
  either timeline updates or prepared conversation windows must already contain it.
  Adding it only when the send response completes does not close the race.
- Preserve the association across publication, relay echoes, convergence retries,
  runtime restart, and projection rebuild. Store it with durable local source
  metadata, not only in the disposable materialized timeline or an in-memory map.
- Never place the token in inner-event tags/content, transport wrappers, telemetry,
  debug output, or error strings. Received events cannot supply a local token.
  A message from another device using the same sender identity also has no token
  unless this installation has its own corresponding persisted submission.
- Scope matching to the account and conversation. Specify token size bounds and
  reuse/conflict behavior; do not silently rebind a token to another message.
- Transport retry of an accepted message retains its binding. A new host send
  attempt and an idempotent retry are different operations; the presence of a
  correlation token alone must not imply a new idempotency guarantee.
- For `upload_media(send=true)`, carry the token through asynchronous HTTP upload
  completion into the eventual message projection. Preparation-only uploads have
  no timeline row; the later `send_message_draft` supplies the token for that send.
- Keep existing no-token callers working, for example through additive token-aware
  command variants. A new optional argument is still a source/ABI change unless
  compatibility is explicitly provided. Regenerate and validate matching bindings.

The original identity edge case was: the legacy inner-event builder hashes sender, second-level
timestamp, kind, tags, and content without a per-submission nonce. Two identical
messages within one second can therefore share an event ID; the existing
`retry_group_convergence` binding documentation already calls this out. A single
optional token on that one row cannot represent two independent optimistic sends.
Do not overwrite the first token or put the caller's token on the wire to solve
this. Define collision behavior or an independent event-uniqueness mechanism as
part of the implementation and its tests. The token-aware path now uses independent
random event entropy and rejects token rebinding; legacy APIs retain their existing semantics.

Required coverage includes projection-before-response, normalized/staged content
mismatch, identical back-to-back messages, token conflicts, upload-and-send versus
prepare-only upload, draft conflict before acceptance, definitive failure and
unknown completion, restart/reprojection, relay echo, and received-message token
absence. Validate both raw timeline and prepared conversation-window DTOs.

Likely implementation boundaries are `marmot-uniffi/src/commands/{message,
conversation_window,media}.rs`, the corresponding runtime commands and worker
completion paths, the common local send projection in `marmot-app/src/client`,
and durable storage plus timeline decoding in `storage-sqlite`. The FFI record
addition by itself is insufficient.
