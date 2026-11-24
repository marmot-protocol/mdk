# Changelog

## Unreleased

### Breaking changes

- `RosterTagKeyStorage` gains `renew_roster_tag_keys`, which moves the sighting time of a slot's unexpired keys in one
  step and keeps their order (mdk#3679).
- `MARMOT_APP_EVENT_KIND_AGENT_ACTIVITY` and `MARMOT_APP_EVENT_KIND_AGENT_OPERATION` become
  `MARMOT_APP_EVENT_KIND_AGENT_ITEM` and `MARMOT_APP_EVENT_KIND_AGENT_REQUEST`, and the old shape's tag constants
  (`AGENT_ACTIVITY_STATUS_TAG`, `AGENT_OPERATION_*_TAG`) are removed.

### Added

- `agent_events`: the tags of kinds 1201 and 1202 (marmot-agents D-076), `AGENT_EVENT_MAX_BYTES`, and the parsers
  `AgentItem::from_tags` and `AgentRequest::from_tags` with the alert rule `AgentItem::alerts`.
  An item's `v` and `seq` are at most `i64::MAX`.
- An agent item in a subagent's thread carries NIP-22's tags (marmot-agents D-121): `validate_agent_item_tags` takes
  one `e` beside an `E`, and `validate_agent_item_edit_tags` checks the item an edit carries, which has no `e`.
  `agent_item_thread_parent`, `agent_item_reply_target` and `is_agent_own_thread_comment` (D-122) read them.

## 0.19.0 - 2026-11-22

### Breaking changes

- The agent text stream over QUIC is retired. `agent_text_stream` keeps only what groups that require the `0x8006`
  component need: `AgentTextStreamQuicPolicyV1`, `AgentTextStreamPolicyError`, the role bits, the role features and
  capabilities, `AGENT_TEXT_STREAM_QUIC_ROLES`, `required_role_capabilities`, `AGENT_TEXT_STREAM_COMPONENT_STATE_LEN`
  and the three component-state caps. Gone: `AgentTextStreamRecordV1`, `AgentTextStreamRecordError`,
  `AgentTextStreamKeyContextV1`, `AgentTextStreamTranscriptV1`, `AGENT_TEXT_STREAM_EXPORTER_CACHE_KEY` and the record,
  key-context, transcript, stream-id, AEAD and ciphertext constants, and the `STREAM_*_TAG` tag names. Kind 1200
  (`MARMOT_APP_EVENT_KIND_AGENT_STREAM_START`) stays reserved.

### Added

- `threads` holds the NIP-22 thread-message profile: `NIP22_COMMENT_KIND`, `is_nip22_comment` (now also true for a
  kind 1111 with a lowercase `e` and no numeric `k`, the form White Noise Linux sent before 2026-11-17),
  `thread_message_parent`, `thread_root_tag` and `is_chat_message` (kind 9 or a thread message).

## 0.18.0 - 2026-11-20

### Breaking changes

- `SendIntent::AddOwnAccountDevices` and `GroupEvent::GroupJoined` gain `forwarded: ForwardedInvitation`, what the
  adding device's copy says about its invitation (mdk#3546). Both default when deserialized; struct literals need
  the field.
- `EngineError::SiblingAddUnsettled` refuses a same-account Add that forwards its copy's invitation instead of
  queueing it while the chat is unsettled (mdk#3546); exhaustive matches need the variant.

- `OutboundIntentStorage` gains `put_change_not_delivered`, `changes_not_delivered` and
  `delete_change_not_delivered` for `ChangeNotDelivered` records (mdk#2332); custom storage must implement them.

### Added

- `StoredMessagePayload::OutboundWelcome` and `StagedInviteWelcome` keep the transport event id of the KeyPackage
  the Welcome answers (`key_package_event_id`, `with_key_package_event_id`, `welcome_key_package_event_id`). A Welcome
  that names one is stored as the new variant 14 (outbound) or 15 (staged); one that does not keeps its old variant,
  byte for byte. An older build cannot decode the new variants; `storage-sqlite` migration 0216 makes it refuse
  such a database.
- `TransportAdapter::event_size_class` measures an event as the transport sends it, for the sender's audit. It
  defaults to `None`.
- `MessageStorage::release_message_for_replay_without_stall_evidence` releases a row the engine judged not to be
  evidence of missing history, such as traffic that may predate this copy's Welcome (mdk#3536). It defaults to
  `release_message_for_replay`; a backend that turns releases into an epoch-gap backfill must not raise one from it as
  stall evidence, only where that backfill is all that re-owes the message.
- `TransportEndpointFailure::is_endpoint_prohibited` tells an adapter's refusal of the endpoint itself, unsent and not
  for size, such as the Nostr relay plane's host-safety refusal (mdk#3305).
  `EventSizeClass::from_rejected_targets` leaves such targets out of its proof: the rest must all refuse the event for
  size, and at least one must remain.
- `OutboundFanout::record_stuck` keeps when the session first read a pending commit back past the read-back bound,
  and `stuck_at_ms` reads it (mdk#3460); the session audits the commit stuck once by it. A fanout stored before the
  field reads `None`.
- `OutboundFanout::pending_final_answers` lists each target of a pending commit whose latest answer was final,
  whatever its status, with the causes `refused_targets` gives (mdk#2332). A relay that may hold an earlier copy and
  refused a later attempt is listed, and stays a target that may hold the event.
- `ChangeNotDelivered` and `ChangeOrigin` (`Direct`, or `QueuedIntent` with its id) describe a group change given up
  after its call returned (mdk#2332), and `GroupEvent::GroupChangeNotDelivered` announces a direct one.
  `OutboundFanout::set_host_change` names the host's change a pending fanout carries, once, and `host_change_kind`
  reads it; a fanout stored before the field reads `None`.
- `OutboundFanout::acknowledge_target` records that an endpoint served a pending commit's exact event, by a read or
  by the account's own echo (`FanoutAcknowledgement`), and ends its target `Accepted` from any other status, its
  exposure bit kept (mdk#2332). `validate_successor_of` admits that edge only with the acknowledgement recorded, on a
  pending commit. `target_index_of` finds a target by any spelling of its URL, and `is_frozen_event` tells the
  fanout's own event by its staged or published id. `takes_acknowledgement` tells whether a target would take one,
  for a host deciding whether a relay's copy of the event is worth ingesting.
- `TransportAdapter::read_back` asks endpoints, now, for a frozen message's exact event, one `TransportReadBack` per
  endpoint: `Found`, `NotFound` (the endpoint ended the read without it) or `NoAnswer` (mdk#2332). Only `Found` says
  anything about the event. The default answers `NoAnswer` everywhere. `OutboundFanout::first_attempt_at_ms` is when
  the first attempt on any target started, written once and kept by `validate_successor_of`; a stored fanout without
  it reads `created_at_ms` once any target was attempted. `target_may_hold_event` tells a target whose relay may hold
  the event.
- `FanoutTargetStatus::Abandoned` ends a target nothing was ever sent to when its pending commit is given up and rolled
  back (mdk#2332). `OutboundFanout::abandon_unsent_targets` sets it on every outstanding target, refusing unless the
  commit is pending, no target accepted it and none may hold it; `validate_successor_of` admits the edge only with MLS
  `Pending → RolledBack` and only from a stored row no target may hold. `reachability_read_at_ms` and
  `record_reachability_read` keep when the device last read the commit to learn whether it is online.
  `possible_exposure` and `target_may_hold_event` now read a row stored before the exposure bit by its stored status, as
  `RetryableUnavailable` with a failure that does not prove nothing was sent, or as a `Failed` with no stored failure
  (the first frozen-fanout writer's shape for every publish error), so such a row counts as exposed.
- `OutboundFanout::set_queued_intent` names, before the fanout is first stored, the queued intent a pending commit, an
  application message or a proposal was drained from, and `queued_intent_id` reads it (mdk#2332).
  `validate_successor_of` keeps it unchanged; a row stored without it reads as naming none.

## 0.17.0 - 2026-11-15

### Breaking changes

- `GroupStorage::put_group` is replaced by `put_group_with_roster(group, committed)` and
  `put_group_keeping_roster(group)` (mdk#3273). A record write that merges, clears or re-derives committed membership
  passes the group's committed members and writes them in the same transaction; staging and every other record write
  keep the stored roster. `StorageProvider` now also requires `CommittedRosterStorage`: each group's committed roster
  (`CommittedMembers`, its distinct member account ids) at a `RosterRevision` no earlier roster of the account-device
  held, so a group forgotten or deleted and joined again never reuses one.
- `TransportPeeler::peel_group_message` takes `&PreparedGroupMessage<'_>` instead of `&TransportMessage` (#2492,
  #3406). Move context-independent validation and decoding into the new `prepare_group_message`, whose default
  borrows the raw payload; a wrapping peeler delegates preparation to the peeler that decrypts.
- `TransportEndpointFailure` gains `pre_send` (#2332, #3396): true only when no frame can have left (a dial
  refusal, a DNS failure, a socket that never opened, or the adapter refused the event). A relay's `rate-limited:`
  or `auth-required:` answer is never pre-send, so the target counts as possibly exposed. Struct literals set it.

### Added

- `maintenance::CommitRefusal`, `CommitRefusalCause` and `transport_adapter::RefusedTarget` record the group
  relays that refused a confirmed own commit for good (mdk#2333, #3426).
- `StorageProvider::has_atomic_group_savepoints` says whether `with_group_savepoint` is a real savepoint, which writes
  no snapshot and leaves none of its unit's writes after a crash (mdk#3278). It defaults to `false`, matching the
  snapshot fallback, so existing providers build unchanged; a provider that overrides `with_group_savepoint` with a
  savepoint overrides this too.
- `StorageProvider::past_peel_context_generation` lets a backend opt into caching historical peel contexts across
  live ingest (#3406). The default `None` keeps uncached recovery; opting in requires complete mutation tracking,
  exclusive writer transactions and atomic group savepoints.
- `TransportAdapter::commit_size_refusals` and `publish_commit` let an adapter refuse a commit over its size floor at
  a relay of unknown limit before sending (#2332, #3396). The defaults refuse nothing and publish as `publish` does.
- `StorageProvider::mls_storage_failure` separates a failed OpenMLS storage read from a stored value that did not
  decode (mdk#3273). The default treats every error as a failure, so no failed read is skipped.

### Changed

- Pin an independently calculated NIP-01 digest for empty tags and content, including lowercase hex output (mdk#3383).

## 0.16.0 - 2026-11-12

### Breaking changes

- `GroupHydrationQuarantineReason` adds `RewindRestoreFailed` (mdk#3272): a read of past group state rewound the live
  group onto a retained anchor and could not restore it, in this session or when the account opened. Neither a retry
  nor a re-join clears it, and the next open tries to restore the live state. Exhaustive matches must add it.
- `EngineError::EventTooLarge { artifact, size_class }` refuses a change whose event fits none of the relays its
  publish would reach (mdk#2334): a group create whose founding Welcome fails the `WelcomeSizeCheck`, or a queued
  intent the drain retires. Exhaustive matches add it.
- `GroupEvent::QueuedIntentRefused` adds `artifact: Option<OversizedArtifact>` and
  `size_class: Option<EventSizeClass>` (mdk#2334). Both are set only with `reason` `event_too_large`: the event that
  fits none of its relays' known size limits, or that every relay refused for size, and its size class. Struct
  patterns add them or `..`. Serialized events without the fields still deserialize, and events without a size
  refusal serialize as before.

### Added

- `StorageProvider::list_snapshots_with_prefixes` lists every group's snapshots whose names start with given prefixes
  in one read (mdk#3272). Engine construction uses it to find interrupted rewinds. It defaults to listing each stored
  group's snapshots, so existing providers build unchanged.
- `OversizedArtifact` (commit, Welcome, application message or other) moves here from marmot-session, which re-exports
  it (mdk#2334).
- `WelcomeSizeCheck` judges a founding create's Welcomes before the engine writes anything (mdk#2334): the size
  class of the first that fits none of the endpoints its publish would reach.
- `TransportEndpointFailure::over_known_limit` is an adapter's refusal to send an event over an endpoint's known limit
  (mdk#2334): `NotExposed` with the `TooLarge` category, the event's size class and the fixed reason
  `TransportEndpointFailure::OVER_KNOWN_LIMIT_REASON`. `TooLarge` now also covers this refusal, and
  `EventSizeClass::from_rejected_targets` counts it, alone or mixed with endpoints' own size refusals.
- `TransportAdapter::size_class_over_known_limits` returns a message's size class when `publish` would refuse it,
  unsent, on every endpoint it would send to, because it is over each one's known limit; it sends nothing (mdk#2334).
  It defaults to `None`, so existing adapters build unchanged.

### Changed

- `OutboundFanout::possible_exposure` also answers `true` for a target that is `Attempting`, and
  `OutboundFanout::mark_attempt_started` on a target already `Attempting` (an attempt a crash or an unwound pass left
  without a recorded result) records its possible exposure (mdk#2332). A definite refusal of the retry no longer ends
  the target `Failed`, so a pending commit that may have reached the relay is not rolled back.

## 0.15.0 - 2026-11-09

Third-party `StorageProvider`, `CgkaEngine` and `TransportPeeler` implementations must add the required methods below.
Nothing in `cgka-traits` is `#[non_exhaustive]`, so exhaustive matches and struct literals must also add the new
variants and fields.

### Breaking changes

- `StorageProvider` requires two new supertraits: `AccountDeviceHistoryKeyStorage`
  (`put_account_device_history_key_if_absent`, `account_device_history_key`; mdk#2741) and `DeviceGroupWelcomeStorage`
  (put, get, list and delete of an expected device-group Welcome; `accept_device_group_welcome` has a default;
  mdk#2704, mdk#2948). Third-party backends must implement both.

- `StorageProvider::pending_ref_high_water` is required, with no default (mdk#2683): a monotonic account-device bound
  over every persisted pending-send reference, raised atomically with those artifacts and never lowered. An unknown
  legacy bound returns an error, not zero.

- `GroupStorage` now requires `invitation_admission` and `put_invitation_admission` for native transactional
  admission metadata (mdk#2914, mdk#2628 D96). `cgka_traits::group::InvitationAdmission` binds the original
  generation to founding origin or its exact successful local Welcome output; no transport id is used as the shared
  generation seed.

- `CapabilityStorage::save_member_capabilities` and `member_capabilities` are removed (mdk#2645); the engine reads
  member capabilities from each current leaf.

- `OpenMlsContentFilter` gains `CommitsAndProposalsBetween { from, through }` (mdk#2711).

- `CgkaEngine` requires `group_recovery_source`, `epoch_pin`, `own_signature_key`, `expect_device_group_welcome` and
  `withdraw_device_group_welcome` (mdk#2683, mdk#2819, mdk#2704). `TransportPeeler` requires `wrap_group_recovery`
  (mdk#2685).

- `SendIntent::AppMessage::expected_epoch` is now `Option<EpochPin>` (epoch plus authenticator digest), not
  `Option<EpochId>` (mdk#2819); read it with `CgkaEngine::epoch_pin`.

- `SendIntent` gains `StepDownAndLeave { group_id }` and `SendResult` gains `LeaveRequested { request }` (mdk#3014):
  an admin's Leave that records the leave request first and leaves the step-down and SelfRemove to the engine.
  Exhaustive matches need them. A `StepDownAndLeave` made behind an earlier queued intent is queued like any other
  intent; no schema or wire change.

- `SendIntent` also gains `RecoverMembers`, `AddOwnAccountDevices`, `RemoveOwnAccountDevices`, `LinkDevice`,
  `UnlinkDevice`, `RecordRemovedSlot`, `ImportDeviceGroupRejections`, `MarkDeviceGroupMoved`, `ReplaceDeviceEntry`,
  `ReplaceAccountEntry` and `EnableAccountDevices`. `GroupEvent` gains `QueuedIntentRefused` (mdk#2707), and
  `GroupEvolutionSemantic` gains `RecoverMembers`.

- `LeaveRequest` gains `blocked: Option<LeaveBlockReason>` (`#[serde(default)]`; one reason, `LastActiveAdmin`), and
  `EngineError` gains `LeaveNotBlocked { group_id }` (kind `leave_not_blocked`) for a Cancel asked of a leave that is
  not blocked (mdk#3014). Struct literals and exhaustive matches need them. Stored requests without the field read as
  not blocked; no schema change.

- `EngineError` also gains `AccountDevicesActivationRefused`, `NoDataAppComponent`, `LinkDeviceUnsettled`,
  `DeviceEntryChanged`, `AccountEntryChanged`, `AccountEntryUnsettled`, `UnexpectedDeviceGroupWelcome`,
  `GroupRecoveryUnsettled`, `GroupRecoverySourceMismatch`, `WelcomeNotAddressedToThisDevice`, `SiblingWelcomeHeld`
  and `SiblingWelcomePredatesForget`; `is_transient` is also true for `GroupRecoveryUnsettled`.

- `IngestOutcome` and `PeeledContent` gain `GroupRecovery { recovery }` (mdk#2685). `InputRejectionCategory` gains
  `NotAddressedToThisDevice`, and `PeeledContent::Welcome` gains `key_package_event_id` (mdk#2633).

- Add `TooLarge` endpoint rejection, coarse `EventSizeClass`, and optional size evidence on endpoint and aggregate
  publish failures (mdk#2993). Rust struct literals and exhaustive matches must adopt the new fields/case. Old
  retained JSON remains readable with unknown evidence; older readers may reject newly written rejection variants. No
  schema or wire change.

- Struct literals must add `Group.self_removed_sibling_slots`, `Group.device_roster_departures`,
  `GroupMaintenanceState.post_join_history`, `KeyPackageLifecycleState.unusable_artifact_replaced_by` and
  `slot_withdrawn_at`, `RetainedKeyPackagePrivateMaterial.authored_event_id` and `awaiting_confirmed_replacement`,
  `DurableConvergencePass.retry`, `AccountDeviceSignerBinding.account_identity_proof`, `AutoPublish.welcomes` and
  `GroupEvent::MessageReceived.sender_leaf_index`. All read as absent or empty from older stored JSON.

- `StoredMessagePayload::OutboundWelcome` is now a struct variant `{ message, origin_commit_id, key_package_ref,
  deliver_until }`; `StagedInviteWelcome` gains `key_package_ref` and `deliver_until`, and the new
  `StagedSiblingWelcome` and `OutboundSiblingWelcome` variants carry sibling Welcomes. `outbound_welcome` and
  `staged_invite_welcome` take the new fields and `into_message` returns `Option`. Payloads written with the new
  binary tags (6–13) are unreadable by 0.14 readers.

- `MULTI_DEVICE_JOIN_AUTHORIZATION_COMPONENT_ID` (0x800a) is removed and no longer protocol-owned; the registry
  withdrew it (mdk#2632). `CONSUMED_KEY_PACKAGE_RETENTION_SECS` is renamed `KEY_PACKAGE_REPLACEMENT_GRACE_SECS` (same
  value) (mdk#2643).

### Added

- New types: `EpochPin` (mdk#2819), `EventSizeClass` (mdk#2993), `InvitationAdmission` (mdk#2914), `LeaveBlockReason`
  (mdk#3014), and `PublicationObservation`, the sender's immutable local time of a carrier's first actual accepted
  publication (D100).

- `SiblingAddRefusal` says why a same-account Add of one sibling to a chat would be refused now (mdk#2856), including
  `AlreadyPresent` for selected-tree sibling presence, which another KeyPackage cannot resolve. It serves experimental
  device groups; no stored or wire encoding.

### Changed

- Retained, unconsumed KeyPackage private material is deleted 24 hours after its replacement's publication is
  confirmed (`KEY_PACKAGE_REPLACEMENT_GRACE_SECS`), or when it expires if sooner (mdk#2643).

- A Commit refused on replay only because its committer is not an admin is reported as an invalid Commit carrying
  `AuthorizationFailed`, and its audit `Rejection` record is written (mdk#2647). Persisted state, dedup and branch
  selection are unchanged.
