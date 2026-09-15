---
title: "Shared conversation presentation"
created: 2026-09-15
updated: 2026-09-15
status: implementation
---

# Shared conversation presentation

C5 M3 ([#1838](https://github.com/marmot-protocol/mdk/issues/1838)) adds shared Rust header/capability
selection and a window-scoped identity dictionary. It is a presentation sidecar to the retained timeline,
not another stored transcript. M4 attaches it to the combined live window; M5 adds the native screen contract.

## Sources and ownership

| Field | Source and behavior |
| --- | --- |
| Title/avatar, peer, member count | Existing keyed `ChatPresentationInput` and shared title/avatar selector. Custom group names win; encrypted group images precede URL images. No new selection cache. |
| Lifecycle and capabilities | `ConversationHeaderState` carries scalar worker inputs: epoch, membership, self role/admin count, pending confirmation/leave, lifecycle/disbanding gates and support-blocker presence. No roster in the selector or output. |
| Visible identities | Cached directory records in bounded pages, keyed by canonical account id, including former members. Names are sanitized; missing profiles get stable pseudonyms and avatar placeholders. Header and identity avatars share the existing store-scoped cache-key framing. |
| System actors/subjects | Existing system parser, only after one bounded storage join verifies supplied/stored synthesized direction, absent inner source id, origin commit attribution and matching visible content/source epoch. Member-authored kind-1210 JSON and legacy rows without attribution do not become trusted transitions. |
| Reactions and mentions | Existing timeline aggregate and Markdown/NIP-27 parser. Explicit limited reference collections, separate total reaction counts, and explicit omission/truncation indicators. |

`ConversationAuthority` owns the self and per-member management selection previously in UniFFI. The existing
native management conversion delegates to it. Pending, departed, leaving, disbanding and unrecoverable conversations
suppress ordinary actions even if the retained roster still contains the local account. Pending invitations use
accept/decline commands; retained history remains readable. Observed admin roles require current membership; pending confirmation only gates display actions. Display
capabilities never replace command validation: leave/removal preflight checks actual membership, role and target
constraints, then the runtime validates lifecycle policy.

M3 does not implement the full `group()` read optimization assigned in #1793. Its input contract is compact:
M4 must capture the scalar authority state with its other account fields, without obtaining a roster for this screen.
The existing full-roster management screen continues to use its separate query.

## Bounds and rendering

A presentation accepts at most 200 timeline rows. Per row it exposes a sender, reply author, at most eight main-body
and eight reply mentions, two authenticated system references, and up to eight reaction kinds with two reactor
previews each, ordered by count then emoji as in the existing native projection. Reaction totals count all aggregate entries, including omitted kinds. The dictionary includes every
explicit reference, plus the header peer: at most 7,201 identities. Cache queries use the existing 100-identity pages.
Each identity name is at most 256 UTF-8 bytes. Avatar URLs reuse the existing bounded safety validator.

Only explicit returned references request profile-resolved rendering. Other content remains literal or uses its
stable raw-identity fallback; truncation never instructs a client to issue additional profile lookups. Expanded
reaction/member screens use the existing narrow APIs. The shared mention parser scans its existing 65,519-byte
prefix; a longer body reports truncation. Up to 256 raw tags are examined for additional `p` references;
exceeding that scan budget also reports truncation.

The **presentation sidecar** has a conservative 64 MiB serialized upper bound derived from its field and collection
limits, including worst-case JSON escaping in tests. The production refresh path does not encode the sidecar to
measure its size. Encrypted avatar media types are capped at the protocol limit of 128 bytes. This is an output bound, not a total source-read or process-memory guarantee: M1's timeline
page can already contain large message bodies/reaction aggregates, and selected directory records may contain other
cached metadata. M3 does not copy that raw content, media bytes, full profiles, or full reactor lists into its output.
The eventual M4/M5 composed payload must account separately for timeline/draft bytes; this ceiling does not bound them.

## Consistency, refresh and erasure

Storage captures a `ConversationPresentationPage` that owns the immutable timeline page and its provenance evidence
without duplicating the transcript. It checks all eligible rows in one bounded query under one storage lock. This
capture can run inside the caller-owned account transaction; directory enrichment happens after releasing it.
The builder checks both captured/current account-store identity, row group ids, membership-input agreement and row count. The caller owns
capture of account fields: M4 must read header inputs, timeline and system provenance under its account snapshot,
then reconcile invalidations that arrived during construction. The directory remains a separate store; no global
atomic snapshot is claimed. This method alone is not a live subscription or an atomic screen-open API.

`depends_on_profile` checks all dictionary keys, including historical authors and the selected peer. Reuse the
existing profile-commit wakeups to rebuild when a visible dependency changes; broadcast lag requires full refresh.
M4 owns subscribe-before-read, refresh retries, account reset/close and store replacement. No second background
worker or durable identity cache is introduced. Dropping the window drops its sidecar; account erasure retains its
existing owners and must close M4 handles. Errors do not start network repair or downloads.

Tests cover inactive permission gates, admin transitions, historical/reply/mention identity completeness, profile-only
commit invalidation, selected title/avatar precedence, scoped provenance, bounded ancillary references, UTF-8/JSON
byte limits and store/group mismatch. These are contract checks, not device latency measurements.
