# Changelog

## Unreleased

## 0.16.0 - 2026-11-11

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
