# cgka-session

Production-shaped account-device wrapper around `Engine<SqliteAccountStorage>`. This is where app integration starts to
become concrete: one `AccountDeviceSession` per Marmot account-device identity, returning app events plus publishable
transport work from each lifecycle method.

## Opening a session

`SessionConfig::new(database_path, database_key, identity, peeler)` takes the SQLCipher database path and key, the
local identity, and a `TransportPeeler`. `AccountDeviceSession::open` also requires an account identity-proof signer
(`SessionConfig::account_identity_proof_signer`). Optional builder methods set the feature registry, supported
app-component set, protocol profile, storage options, convergence policy, forensic recorder, and maintenance clock/RNG
sources.

Open fails closed before touching storage if the convergence policy is unacceptable or a legacy protocol profile is
requested without `legacy_compatibility_profile()`. It then opens encrypted storage, builds the engine, retires (for
the current profile) non-current local KeyPackages, and hydrates stored groups. By default hydration is eager: every
group is fully hydrated (or quarantined) before `open` returns. `defer_group_hydration()` runs only the cheap seed
pass; groups are listed but return `GroupNotHydrated` until the host calls `hydrate_next_groups` /
`ensure_group_hydrated` or a send or ingest promotes them on demand. Embedders without a background pipeline should keep
the default.

## What this crate does

- Opens one encrypted SQLite database for one Marmot account-device identity.
- Builds `Engine<SqliteAccountStorage>` with an injected `TransportPeeler`.
- Surfaces `GroupEvent`s and publishable transport work as `SessionEffects`.
- Preserves the publish-before-apply contract: callers confirm or fail pending group operations after transport
  publish, including auto-publish work created while ingesting inbound messages.
- Exposes convergence advancement (`advance_convergence`, `advance_convergence_inputs`) so queued outbound work can be
  regenerated from canonical state.
- Exposes durable maintenance, KeyPackage-lifecycle, group-evolution, and transport-fanout records for the account
  layer above it.
- Provides compact `group_authority` reads and `with_group_authority_snapshot` for composing host-owned persisted
  reads with current engine facts on this session's store. The callback is synchronous and read-only; unhydrated groups
  return `GroupNotHydrated`. It does not serve a frozen startup snapshot or start relay work.
- Provides `canonical_group_membership` for device-scoped reconciliation: authenticated leaf indexes and account
  identities, plus whether this device's own leaf is active. Pending roster projections do not replace those facts.
- Offers `promote_legacy_message_rows` for host-scheduled, bounded promotion of legacy stored rows after readiness.

It does **not** do account key derivation, recovery, or key rotation; relay sync, network publish, or transport
adaptation; or UI projection and application databases. Those live above this crate (see
[`marmot-account`](../marmot-account/) and [`marmot-app`](../marmot-app/)).

## Tests

```sh
cargo test -p cgka-session
```

- `tests/session_lifecycle.rs` — encrypted open/create/confirm/close/reopen, Welcome and app-message ingest,
  auto-publish and SelfRemove re-proposal work, convergence releasing queued outbound work, disband requests, compact authority
  capture, KeyPackage cutover on open, and the legacy-row promotion facade (using
  [`fixtures/session-promotion-v1.bin`](fixtures/README.md)).
- `tests/nostr_stack.rs` — the production-shaped non-relay stack: SQLCipher storage, the real `NostrMlsPeeler`, and
  `NostrTransportAdapter` over an in-memory relay client. Covers inbox and group subscription routing, NIP-59 Welcome
  and kind `445` group delivery, routing-component-driven `h` tags and publish targets (the transport id is not the MLS
  group id), publish ack/insufficient-ack/error resolution, duplicate and out-of-order delivery, and invite evolution
  with commit and Welcome outputs.
- `tests/nostr_stack_chaos.rs` — seeded no-network delivery-chaos scripts against the same stack, including invite
  lifecycle chaos (wrong-route drops, Welcome replay, shared commit fanout, Welcome/commit ordering). Reports go to
  `target/session-stack-chaos/`.

Test placement rules: [`tests/AGENTS.md`](tests/AGENTS.md).
