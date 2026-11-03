# AGENTS.md - crates/marmot-session/tests

Session integration tests exercise the `AccountDeviceSession` boundary, which the `test-support` feature re-exports
(this crate enables it for its own tests as a dev-dependency). Keep helper code in `support/` and do not reach into
engine, storage, adapter, or peeler internals. File coverage is summarized in
[`../README.md#tests`](../README.md#tests).

## Runtime tests

`runtime.rs` drives `AccountDeviceRuntime` over a real session and a scripted transport; the files under `runtime/` are
pulled into that one binary with `include!`. They set up scenarios through the session accessors that the
`test-support` feature exposes, which this crate enables for its own tests as a dev-dependency.

## Nostr stack harness

`support/nostr_stack.rs` is a no-network harness: the real `NostrTransportAdapter` and `NostrMlsPeeler` with relay
sockets replaced by an in-memory `NostrRelayClient`. Use it for production-shaped session/adapter/peeler behavior:
publish ack/fail lifecycle, inbox and group subscription routing, NIP-59 Welcome delivery, kind `445` group delivery,
and duplicate, dropped, or reordered relay deliveries.

`nostr_stack/chaos.rs` is the seeded chaos module in the `nostr_stack` integration binary and imports its `support`
module. Keep reports reproducible by seed and write artifacts under `target/`, never into the repo. Lifecycle chaos
stays at the adapter/session boundary: assert routed `IngestOutcome`s and emitted `GroupEvent`s, not internal engine
state. Preserve all six delivery scripts and their default convergence settings when moving them. The separate
`duplicate_group_relay_delivery_is_idempotent_at_session_boundary` case uses an explicit zero quiescence window and
keeps that distinct contract.

Never connect to real relays from these tests.

## Fixtures

`support/storage_fixture.rs` opts runnable runtime and lifecycle fixtures into storage's existing test-process
relaxation, then delegates to `tempfile::tempdir`. Those binaries route this module directly with `#[path]`. The Nostr
harness opts in at the start of `NostrStackHarness::new`. Keep original keys, option arguments, private directories,
encrypted files, independent handles and every open/drop/reopen and assertion. The opt-in skips allocator enablement
and uses `synchronous=NORMAL`; it does not establish production `FULL` or power-loss guarantees.

Keep the ignored `send_skips_slow_relay` body and its native `tempfile::tempdir` path unchanged. Required nextest runs
isolate each test; a fresh process selecting only that diagnostic retains dependent storage defaults. A mixed run
passing `--include-ignored` to the Rust test harness shares settings with relaxed cases and cannot guarantee those defaults.
Do not use test-name sniffing, resets or startup hooks to conceal that limit. Production-setting and physical-crash
proof owners keep their own default storage paths.

`../fixtures/session-promotion-v1.bin` backs the promotion-facade regression; see
[`../fixtures/README.md`](../fixtures/README.md) before regenerating or replacing it.

## Verification

```sh
cargo test -p marmot-session
```
