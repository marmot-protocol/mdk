### Breaking changes

- `Engine::own_account_leaves_tagged_by` returns each leaf's signature key with the slot its tag read as.
- `Engine::queue_app_message_with_audit_context` takes the intent's `only_to_members`.

### Added

- `Engine::own_account_self_signed_tags` reads, for this account's other leaves, a device tag that verifies under
  that leaf's own signature key, with the slot it names (mdk#3679).
- An application message sent with `only_to_members` is encrypted only into an epoch whose member accounts it all
  lists, checked at encryption for direct sends and queued ones alike; otherwise it fails with
  `AppMessageNewMembers`, or, queued, is retired through `retire_refused_queued_outbound_intent` and announced as
  `QueuedIntentRefused`.
- `Engine::deferred_stall_evidence_since` returns deferred stall evidence for rows whose arrival epoch falls in
  `min_epoch..=group.epoch`, for active epoch-gap handoffs across partial advances.
- `Engine::stored_outbound_welcome_status`, an outbound Welcome's status read from its stored rows without the
  live-group gate, for the sender's invite delivery view (mdk#1706).

### Changed

- `SendIntent::UnlinkDevice` may keep the removed leaf's signature key in the slot's `removed` record once that leaf
  has committed since its Add, and refuses any `removed` record while the removed leaf is still its link's KeyPackage
  leaf (mdk#3679). Receivers are unchanged.
- An invite's and a founding create's Welcome record `deliver_until`: 7 days after
  staging, or the KeyPackage's `not_after` if sooner, and `outbound_welcome_status` reports them
  `Settled(Expired)` from then on (mdk#3589). A device link's deadline is unchanged. `sent_welcome_deliver_until` and
  the status hold a Welcome stored without a deadline to its transport timestamp plus the window.
- Budget-expired deferred-peel evictions delete the deferred row from `cgka_messages` directly instead of calling
  `release_message_for_replay`, so storage hosts are no longer notified via the release journal for budget-expired
  rows, avoiding false epoch-gap arms, `seen_events` retirement, and relay bounce-backs.

### Fixed

- Re-deferring an unopenable `PeelDeferred` row across an epoch sweep preserves its original arrival epoch instead of
  restamping it to the tip epoch.
- Deferred-peel sweeps at the retry-budget or residence-budget cutoff attempt a newly arrived peel context once before
  deleting the row, so a commit that unlocks the row on the cutoff sweep decrypts instead of being discarded.
