# AGENTS.md - crates/marmot-app

App runtime bridge for the first real Marmot app surfaces.

## Scope

- Own the app-facing runtime that ties `AccountHome`, SQLCipher session storage, Nostr peeling, and Nostr transport
  adapter support together.
- Keep runtime orchestration, managed account workers, subscriptions, and live agent stream watches in the `src/runtime/`
  module instead of regrowing `src/lib.rs`. The module splits along these seams: `mod.rs` (the `MarmotAppRuntime`
  orchestration core — construction/start/shutdown, shared services, lifecycle, module wiring and re-exports),
  `account_worker.rs` (the per-account worker: command enum, worker loop, reconnect backoff, runtime-event publishers),
  `subscriptions.rs` (the `Runtime*Subscription` handles and the materialized-timeline window), `commands.rs` (the
  `AccountManager` command-RPC wrappers that send a worker command and await its oneshot reply), `agent_stream_watch.rs`
  (agent-text-stream discovery and the brokered-QUIC watch machinery), `audit_tracker.rs` (the forensic audit-log
  tracker upload worker), and `event_routing.rs` (pure `MarmotAppEvent` classification/routing helpers). Keep `mod.rs`
  re-exporting the moved public types so `crate::runtime::Item` and the `marmot_app::...` paths stay stable.
- Keep app-client commands and query methods in the `src/client/` module; the crate root should construct clients but
  not absorb their behavior again. The `AppClient` inherent impl is split across the module along these seams: `mod.rs`
  (the `AppClient` struct plus the broadly-shared command/query API — key-package, group lifecycle, message/media/agent
  send commands, and the lifecycle helpers and encrypted-media helpers they share), `sync.rs` (transport sync: `sync`,
  `next_event`, `sync_sdk_relay`, `ingest_delivery`, `sync_runtime_groups`, the relay-echo/transport-cursor helpers, and
  the cursor unit tests), `projection.rs` (timeline/group projection accessors, the `*_for_group` component reads, the
  kind-1210 group-system row synthesis, and the local-send projection helpers), `push.rs` (push-token registration and
  notification-trigger publishing), `retention.rs` (the engine-owned retention sweep policy, bounded timeline scan,
  per-group outcome orchestration, and classifier tests), and `audit.rs` (audit-context construction, the local/observed
  `human_action` recorders, and the `ObservedHumanActionAudit` descriptor). Private items referenced across these files
  are widened to `pub(crate)`; `pub` items keep stable `marmot_app::...` paths via the crate-root re-export.
  Steady-state sync passes must not rescan full retained state (no full `MlsGroup::load` sweeps, no full
  account-projection loads; cheap per-group probes are acceptable): the encrypted-media epoch-secret warm pass
  skips authoritative (`MlsGroup::load`) component re-checks at an unchanged group epoch
  (`encrypted_media_not_required_epochs`, mdk#1380), and the sync checkpoint skips its second
  `refresh_group_routes` when the drained prefix carried zero deliveries and clean routes.
- Keep app-defined custom events on the `AppMessageIntent::Custom` path in `src/messages/intents.rs`: kind, tags, and
  content pass through verbatim, and kinds MDK owns (`is_reserved_app_event_kind`: chat, reaction, edit, delete,
  agent, group system, push token) are rejected with `AppError::InvalidAppMessagePayload` so apps cannot forge
  protocol-owned events. Custom kinds project as standalone timeline rows under
  `TimelineUpdateTrigger::CustomEvent` (never folding onto a target message like reactions/deletes) and are queryable
  by kind through `AppMessageQuery::kinds`.
- Keep group DTOs, component projections, and group event projection helpers in `src/groups.rs`.
- Keep encrypted-media DTOs, exporter labels, and Blossom upload/download helpers in the `src/media/` module
  (`blossom.rs`, `crypto.rs`, `group_image.rs`, `host_safety.rs`).
- Keep the mechanical `storage_sqlite` `Stored*` <-> app-DTO mapper free functions (account state, groups, components,
  messages, app events, push registrations, telemetry/audit settings) in `src/conversions.rs`. They hold no `MarmotApp`
  state.
- Keep the forensic audit-log feature in `src/audit_log.rs`: the `AuditLog*` DTOs, salted-hash identity derivation,
  the upload client, the per-account upload checkpoint (`audit-upload-checkpoint.json`), and the `MarmotApp` methods for
  audit settings, recorder open/build, file enumeration, path validation/resolution/removal, and HTTP upload. Audit-log
  unit tests live in its own `#[cfg(test)] mod tests`.
- Keep audit uploads incremental (mdk#1181). An audit file whose size and mtime still match its checkpoint entry is
  never re-read or re-posted; only the growing active file re-transfers, bounded by the recorder's segment threshold.
  Do not add a trigger path that bypasses the size-1 coalescing queue in `runtime/audit_tracker.rs`, and do not let one
  oversized or failing file block the files behind it. Retention/deletion of sealed segments is mdk#1014, not this
  contract.
- Keep the upload checkpoint's cost proportional to the account's *live* audit files, not to its history. `retain_present`
  prunes entries for files that are gone, so the sidecar is O(live `audit-*.jsonl` files) — but nothing deletes sealed
  segments (mdk#1014), so that bound grows with cumulative audit volume, and each tracker run stats every file and
  rewrites the whole sidecar. Do not add a per-upload or per-line entry, and do not treat the sidecar as durable state:
  losing it costs one repeat transfer per file and nothing else.
- A file above `AUDIT_LOG_UPLOAD_MAX_BYTES` has no app-level transfer path. `post_audit_log_file` enforces the same
  ceiling, so the tracker's skip is the whole story: the file stays on disk for manual handling. Do not document an
  escape hatch that does not exist, and do not widen the ceiling to invent one.
- Keep SQLCipher key derivation, per-database salt persistence, legacy-key migration/recovery, and the in-process
  v2-open probe-verdict cache (mdk#1439) in `src/sqlcipher.rs`. The verdict cache is advisory only: a durable
  migration marker or a missing verdict always re-runs the recovery probe, so the mdk#568 crash windows keep their
  self-heal. Key presentation and the passphrase KDF work factor follow the decision record in
  `docs/marmot-architecture/storage-format-v2.md`.
- Keep the user-directory domain in the `src/directory/` module instead of regrowing `src/lib.rs`. It splits along these
  seams: `records.rs` (the public `UserDirectory*`/`UserProfileMetadata`/`DirectoryKeyPackage` DTOs surfaced to
  `marmot-uniffi`/`cli`, plus the stateless record helpers — cached <-> shared record conversion, recency selection,
  Nostr profile/follow-list parsing, search-match ranking, and `profile_content_json` — which hold no `MarmotApp`
  state), `methods.rs` (the split `impl MarmotApp` block: relay-list/profile/key-package/follow-list fetches, the
  public `directory_*`/`*_user_directory` API, directory-cache lifecycle, and in-memory directory-record hydration),
  `cache.rs` (the per-account SQLCipher directory cache), and `sync.rs` (the directory-subscription sync worker and
  plan). `mod.rs` re-exports the DTOs so the `marmot_app::...` paths stay stable; private items referenced across these
  files (and from `tests.rs`/sibling test modules) are widened to `pub(crate)`, never narrowed.
- Keep stateless account relay-list and KeyPackage parsing/validation (relay-list status, KeyPackage tag/metadata
  validation, fresh-vs-cached reconciliation, record merge, publish-endpoint selection) in
  `src/key_package_records.rs`. They hold no `MarmotApp` state.
- Keep the crate root focused on app construction, shared state, storage/projector wiring, account relay-list helpers,
  the shared directory-record selection primitives (`DirectoryFreshness`, `DirectorySelection`, `sort_directory_records`)
  reused by `key_package_records.rs`, and public re-exports.
- Keep CLI/TUI presentation out of this crate.
- Keep the Nostr user directory app-facing and pubkey-keyed. It may cache local-account links, profile metadata, follow
  lists, relay lists, and KeyPackages. Web-of-trust search may traverse the live follow graph, but traversal is bounded
  by construction: a capped search radius, a per-radius candidate cap, a per-radius fetch timeout, batched
  author-scoped fetches, and a per-search lifecycle — traversal runs only while a search
  subscription is live and stops as soon as its consumer drops. There is no background or open-ended crawl.
- Keep web-of-trust search results un-promoted. Strangers discovered by search are never written to `directory_users`
  and must never reach `directory_sync_plan` or live per-author subscriptions (mdk#418); cache them only in the
  un-promoted `directory_search_graph_users` tier, which directory sync never reads.
- Keep runtime directory subscriptions chunked and privacy-safe. Subscription identifiers must not embed raw pubkeys.
- Treat Marmot kind `30443` KeyPackages as cached last-resort packages. Normal publish should reuse the cached valid
  package and stable replaceable d-tag; expired or policy-invalid packages rotate to a fresh package ref.
- Incoming welcomes may auto-join MLS state, but app projections must preserve local confirmation state. Pending invites
  should stay visible until accepted, and decline should leave the group before archiving the local projection.
- Keep protocol engine behavior in `cgka-engine` and session ownership in `cgka-session`.
- Keep Nostr group routing sourced from `marmot.transport.nostr.routing.v1` component bytes; relay filtering may affect
  connections, but must not rewrite signed routing state. Relay endpoints pass through the `RelaySafetyPolicy`
  host-safety chokepoint (`src/relay_plane/safety.rs`), and agent-stream broker candidates through
  `src/runtime/agent_stream_watch.rs`, before any connect; both follow the one dial discipline in
  `docs/marmot-architecture/overview/dial-safety.md` (validate + pin, trust from config, loopback only under an explicit
  dev flag). Do not add an outbound relay/broker path that bypasses them.
- Keep `MarmotAppRuntime::shutdown_and_close` the one terminal teardown for hosts whose process can be suspended: it
  closes admission, closes every SQLite database and releases the root runtime lease first, then gives graceful worker
  cleanup a bounded budget. The terminal operation must outlive cancellation of its caller. `shutdown` alone does not
  release file locks. Closing is terminal — do not add a path that transparently reopens a database afterwards, and
  put shutdown checks at engine-step boundaries (never inside a step, where a snapshot guard may be live). See
  `docs/marmot-architecture/overview/local-artifact-safety.md`.
- Keep legacy message-format promotion after account readiness and bounded to
  one small transaction per steady-state maintenance tick. Log aggregate
  progress only, retry transient contention, and halt durable decode failures
  without disabling legacy reads.
- Keep local test relay code in tests; production app runtime should talk to Nostr relay URLs through the adapter.
- Do not print or log account ids, group ids, relay URLs, message ids, pubkeys, payloads, ciphertext, plaintext, or key
  material.
- Keep the relay-telemetry export path in the `src/relay_plane/` module (rollup in `relay_plane/telemetry.rs`) and
  `relay_telemetry_export.rs` (exporter, including the `MarmotRelayPlane::telemetry_exporter` constructor). It is
  opt-in and off by default: `MarmotRelayPlane::telemetry_exporter` is the single construction gate, relay-identity
  resolution requires it, and export points carry only a `relay` label. Keep the OTLP wire encoding and HTTP push behind
  the `otlp-export` feature; keep the privacy-critical mapping (`build_export_batch`) and the opt-in gate in the default
  build. See `docs/marmot-architecture/relay-observability.md`.

## Verification

```sh
cargo test -p marmot-app
# Opt-in OTLP exporter wire encoding and push (heavy deps behind a feature):
cargo test -p marmot-app --features otlp-export
```
