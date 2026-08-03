# Convergence mutation matrix

All mutants are simulator-only alternate rules over minimal deterministic
witnesses. `tests/mutation_adequacy.rs` requires every row to change the adopted
observation and keeps this table exactly aligned with the executable catalog.

| Mutation id | Changed rule | Primary killing layer | Production-shaped sentinel |
| --- | --- | --- | --- |
| `selector_comparison_order` | Raw depth precedes effective depth | Independent reference differential | Tamarin policy corpus and `generated_policy_cases_match_selector` |
| `witness_sender_epoch_deduplication` | Repeated messages count as distinct senders | Independent reference differential | Witness scoring properties and same-sender duplicate campaigns |
| `app_witness_admission_removal` | Valid app witnesses are ignored | Witness enabled/disabled A/B | Milestone 3 witness-policy campaign and `witness_mode_is_a_first_class_input_not_a_policy_rewrite` |
| `cutoff_boundary_admission` | Exact rewind boundary is excluded | Reference/canonicalizer boundary | Retained-anchor and rollback-horizon canonicalization tests |
| `frozen_member_persistence` | Crash discards the frozen candidate set | TLC plus Stateright lifecycle | Durable convergence-phase kill matrix |
| `scheduler_deadline_rearm` | New input after settlement does not re-arm | Quiescence and scheduler model | Virtual-time re-arm and deferred-input scheduler regressions |
| `output_invalidation` | Losing-branch projected output survives | Canonicalization/application oracle | Losing-app invalidation and exact projection checks |
| `publication_acknowledgement` | Accepted publication remains pending | Scenario pending-work oracle | Lost/duplicate acknowledgement and no-pending-work checks |
| `retained_history_expiration_boundary` | Exact retention boundary expires early | Reference/canonicalizer boundary | Past-epoch, proposal-expiry, and retained-relay boundary tests |
