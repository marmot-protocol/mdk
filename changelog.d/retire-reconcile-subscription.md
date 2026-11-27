### Breaking changes

- Removed the retired pre-#2660 `NostrSdkRelayClient::reconcile_subscription`, `NostrTransportAdapter::record_reconciliation`, and `NostrReconciliation*` types from `transport-nostr-adapter` (along with the doc-hidden `reconcile_inbox_history` / `reconcile_group_history` wrappers on `transport-nostr`). Account history recovery uses `sweep::run_sweep` and `compare::run_comparison` over `SdkSweepRelay`.

### Fixed

- Bounded active dry-run NIP-77 comparisons in `transport-nostr-adapter` (`sync_watching_neg_cap_detailed`) by the caller's `deadline`, so a relay sending non-converging `NEG-MSG` frames that continually reset `idle_timeout` cannot hold a per-relay NEG permit indefinitely.
