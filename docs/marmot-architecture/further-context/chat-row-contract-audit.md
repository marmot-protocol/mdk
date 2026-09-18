---
title: "Chat-row contract audit and release validation"
created: 2026-09-19
updated: 2026-09-19
status: audit
---

# Chat-row contract audit and release validation

Audited source: `dc7ddf752f33e921f265f3ac6394ca4d9f630f41` (merged
[#1917](https://github.com/marmot-protocol/mdk/pull/1917)), against the agreed
[#1742](https://github.com/marmot-protocol/mdk/issues/1742) screen contract.
This records current behavior and scoped follow-ups; it does not add an API or
establish adoption of a released artifact by either flagship client.

**The bounded chat list is usable, but the original complete-row contract is not
finished.** Draft preview replacement is missing. Delivery and lifecycle data
already reach native callers; replacing their persistence is unnecessary.

## Field and update audit

| Agreed behavior | Current source/native output | Finding |
| --- | --- | --- |
| Selected title, avatar and fallback | `PresentedChatRow` / `PresentedChatRowFfi` / `MarmotPresentedChatRow` contain selected `presentation`, the base `row`, and `avatar_asset`. | Implemented. Keep the selected presentation and durable avatar access. |
| Draft replaces preview, including attachment summary | None of those rows or the base `ChatListRow` has a draft field. `message_drafts` is a separate account-wide summary query; the revisioned selected draft serves conversation opening. | **Missing in the list contract.** Separate composer persistence does not provide a prepared list preview. |
| Draft changes update an open list | Draft mutations and durable acceptance emit draft invalidations. The conversation window consumes them; `open_chat_list_window` and `open_presented_chat_list` do not. | **Missing update dependency**, even if a host manually fetches draft summaries. |
| Clear only the submitted draft on durable acceptance | `send_message_draft` uses revision-bound submission; acceptance and conditional clear share the storage transaction. Newer edits survive, failed admission preserves the draft. Legacy sends retain host-owned clearing. | Implemented for the revisioned send path. Reuse it; list work must not invent another send/clear authority. |
| Latest message attachment/system/sender data | `ChatListMessagePreview` carries attachment kind/count, sender display name, typed group-system data, deletion provenance and message kind. UniFFI adds parsed content tokens; C mirrors it. | Implemented for message previews, not draft attachments. Identity/attachment enrichment still occurs at the app read boundary. |
| Delivery state | Native `last_message.delivery_state` mirrors NotApplicable/Pending/Delivered/Failed. Storage selects Failed for `local_publish_failed`, Delivered for an outgoing source-backed row, Pending for an outgoing row without a source, and NotApplicable for incoming content. | Present. **Delivered is not a recipient receipt/read acknowledgement.** It describes local source/publication state. No transport-ack-to-recipient inference is justified. |
| Invitation and empty preview | `pending_confirmation` is independent of optional `last_message`. There is no selected preview union with an Invitation placeholder. | Sufficient facts exist, but the host still chooses the empty-invite preview. The agreed typed selected-preview contract remains incomplete. |
| Membership, leaving and disband | Native rows preserve `self_membership`, `lifecycle_state`, `disbanding`, `disband_request`, and leave timestamp; the binding also supplies `leave_request_pending`. | Present. Keep unresolved leave intent distinct from classified membership. |
| Chats/Unread/Archived/Left membership | Indexed storage scope gives Left precedence over archive and includes queued departure. Chats excludes Archived/Left; invites stay in Chats but not Unread. Runtime returns bounded replacement windows. | Implemented; no new lifecycle projection is needed. |
| Available row actions | No row capability/action record exists. Group-management and conversation-screen contracts expose separate permissions. | The broad original row contract is incomplete here too. Reuse shared authority logic when defining list actions; displayed capability never authorizes a command. |

Sources:
[base row and delivery derivation](../../../crates/storage-sqlite/src/chat_list.rs),
[selected row](../../../crates/storage-sqlite/src/chat_presentation.rs),
[bounded storage views](../../../crates/storage-sqlite/src/chat_list/pages.rs),
[bounded live list](../../../crates/marmot-app/src/runtime/chat_list_window.rs),
[legacy selected subscription](../../../crates/marmot-app/src/runtime/presented_chat_list.rs),
[draft invalidation](../../../crates/marmot-app/src/drafts.rs),
[revisioned draft storage](../../../crates/storage-sqlite/src/message_drafts/revisioned.rs),
[UniFFI base fields](../../../crates/marmot-uniffi/src/conversions/chat_list.rs),
[UniFFI selected fields](../../../crates/marmot-uniffi/src/conversions/presentation.rs),
[C base fields](../../../crates/marmot-c/src/types/chat_list.rs), and
[C selected fields](../../../crates/marmot-c/src/types/presentation.rs).

## Next implementation scope

1. **Complete selected list previews.** Add a typed selection for draft (bounded
   text/attachment metadata), message, invitation and empty state. Reuse the
   existing single-draft tables and revisioned acceptance path. Read only drafts
   for returned rows in the same coherent window snapshot; do not call the
   account-wide draft list or load attachment BLOBs per screen refresh. Subscribe
   before the initial read and reconcile save/delete/accepted-send changes,
   including lag recovery. Keep draft activity, unread counters, list membership,
   stable anchors and pin order unchanged. Define empty/whitespace/reply-only
   draft selection explicitly before implementation. Preserve lower-level rows.
2. **Define row actions narrowly.** Inventory actual list gestures in iOS/Android,
   reuse the existing membership/management rules, and expose only the necessary
   typed availability. Do not obtain an entire conversation or hydrate an engine
   just to render list actions. Mutations still check current authority.
3. **Document delivery at the native boundary.** Preserve existing discriminants
   and compatibility; explain the source-backed meaning of Delivered in generated
   API documentation. Any rename or true recipient-receipt feature needs a
   separately reviewed contract, not a release-time enum substitution. Reuse
   [#1695](https://github.com/marmot-protocol/mdk/issues/1695) for durable
   queued/retrying/acknowledgement-unknown diagnostics and
   [#1291](https://github.com/marmot-protocol/mdk/issues/1291) for peer-receipt
   reconciliation of stale local failures. Both issues remain open; this audit
   verifies the four-state row mapping, not those issues' complete causal paths.

Acceptance for the preview slice includes text-only and attachment-only drafts,
clear/failure/newer-edit races, restart/offline reads, concurrent subscription
changes, and query-work bounds independent of account-wide draft count and BLOB
size. Test Rust, generated Swift/Kotlin, and C field ownership. This is a concrete
C3 follow-up. Multiple saved drafts remain separate in
[#1520](https://github.com/marmot-protocol/mdk/issues/1520); list preview work
uses the existing single selected draft. The existing C4/C5/C7/C8 implementations
remain the foundation for this work.

## Release validation boundary

C8 implementation is complete through #1917: bounded automatic acquisition is on
for eligible accepted conversations, with native progress, cancellation,
retry/remove/download-again and policy controls. Pending invitations still defer
automatic attachment acquisition; avatars may download before acceptance.
Defaults remain 2 GiB/account, 256 MiB free-disk reserve plus write headroom,
one automatic transfer and a 64 MiB automatic ciphertext cap. Keep acquired bytes
until source deletion/expiry or explicit local removal; do not evict to make room.

The release includes migration 86. Preserve the normal migration/downgrade gate;
downgrading the database is unsupported. The release owner chooses the version
and publishes a synchronized cohort using [release.md](../../../release.md).
This audit does not change versions or start publication.

### Local evidence

Rust sources are the audited master revision; the C scripts include the fix below.
All checks use Rust 1.97.1 on Apple Silicon with Xcode 27.0.

| Check | Result |
| --- | --- |
| Chat-list filter across storage/app/UniFFI/C (`alloc-audit`) | 185 passed; two existing operational benchmarks ignored. Covers list partitioning, leave/disband, invitation attention, delivery mapping, restart and native field conversion. |
| Revisioned/legacy draft storage filter | 19 passed, including acceptance/clear atomicity, newer-edit protection and encrypted reopen. |
| Storage migration filter | 90 passed; three ignored entries are two subprocess helpers exercised by parent crash tests and the large upgrade benchmark. Migration 86 rollback/reapply, old-format upgrade, downgrade refusal and encrypted reopen passed. |
| Optimized C shared/static smoke, after script fix | Passed; valgrind unavailable on this host. |
| C bundle staging and checked-in header copy | Passed. |
| Generated Swift/Kotlin projection fixtures against release host library | Both passed; includes compilation of the attachment control surface and DTO round trips. |
| `just fast-ci` | Passed, including default/export feature checks and clippy, binding parity, privacy/install gates and five convergence-policy tests. |
| Shell syntax, relative documentation links, `git diff --check` | Passed. |

Commands for the Rust regression checks:

```sh
cargo test -p storage-sqlite -p marmot-app -p marmot-uniffi -p marmot-c \
  --features marmot-c/alloc-audit chat_list --lib
cargo test -p storage-sqlite -p marmot-app -p marmot-uniffi message_draft --lib
cargo test -p storage-sqlite migrations:: --lib
```

The native host probe uses `marmotkit-release-profile.env` and
`cargo build --release -p marmot-uniffi --features cli --locked`, then runs the
existing `chat-projections-smoke.sh` generation/fixture commands against
`target/release` instead of `target/debug`. These are the default-feature host
fixtures, not the OTLP-enabled device bundles. Full workspace tests and formal
proofs remain the normal CI/release gates; no physical device benchmark or full
XCFramework/JNI packaging was run by this audit.

### Optimized macOS C failure and correction

Before the change, `crates/marmot-c/c-smoke.sh` builds successfully, but Xcode
27.0 (build 27A266a), Rust 1.97.1 / LLVM 22.1.6 rejects the generated shared
library at the C consumer link: `mis-aligned LINKEDIT string pool`, offset
`0x03C21E14`. `otool` confirms `LC_SYMTAB.stroff = 63053332` (4 modulo 8).
The separately linked optimized static C consumer passes on this host.

A controlled final-crate rebuild with `-C strip=none` changes `stroff` to
63120632 (8-byte aligned); the shared consumer then links and runs successfully.
The C bundle and smoke scripts now explicitly set
`CARGO_PROFILE_RELEASE_STRIP=none` on Darwin, matching MarmotKit's existing
Apple policy. Optimization stays enabled. This does not change Linux packaging,
ABI layouts, the compiler version or system linker, and does not patch binaries.
See the related upstream debug-stripping reports
[rust-lang/rust#157750](https://github.com/rust-lang/rust/issues/157750) and
[llvm/llvm-project#203678](https://github.com/llvm/llvm-project/issues/203678).

The local C static link reports SDK deployment-target mismatch warnings in native
dependencies; a smoke pass on this host is not minimum-supported-macOS evidence.
Published Marmot C currently targets **Linux x86_64**. Apple MarmotKit packages
**static XCFramework slices** and already uses a pinned `strip=none` release
profile. Host binding-generation checks are useful preflight, but do not
replace target-specific packaging and consuming-app validation.

### After release

Record exact source SHA, tag, manifest, checksums and matching generated/native
inputs adopted by each client. Verify cold unread/latest opening, paging anchors,
profiles/reactions/drafts, restart/offline behavior, invitation acceptance,
attachment controls and account switching. Measure storage, FFI conversion and UI
layout separately, including long-message bursts and large-video local chunk
assembly. Keep useful host caches until replacement behavior is demonstrated.
Host smoke results do not replace XCFramework/JNI packaging, consuming-app
archives, privacy resource gates or physical-device measurements.
