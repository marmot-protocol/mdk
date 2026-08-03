# Convergence protocol decisions

Verified against the adopted Marmot protocol at commit
`4ad4ae21479c3f3fa9950c6fc4556a76941a62e1` (marmot#410).

1. Marmot v1 gives one bounded preparation opportunity to an already-queued,
   admin-authorized local intent after a pass settles and before queued inbound
   input alone starts another pass. It makes no administrative-progress
   guarantee while valid selection-relevant input, including self-updates,
   continues without bound.
2. The active policy is the implicit mandatory convergence-v1 baseline. There
   is deliberately no group field or negotiable local override for the current
   values. Adding a component now would create migration and mixed-policy states
   without enabling a supported policy choice.
3. A future change to selection, eligibility, retention, witness scoring,
   admissible input, or bounded-pass lifecycle semantics requires a new required
   app component and capability. Clients may not infer it from software version.
4. Engine resource, app scheduler, and input-acquisition constants are not
   protocol policy. They may change locally only when resource exhaustion stays
   fail-closed/retryable and the same closed retained input reaches the same
   settled canonical result. A constant that cannot satisfy this
   non-interference rule must be reclassified and versioned as protocol policy.

The machine-readable classification is `policy_contract::CONSTANT_DECISIONS`.
`tests/protocol_decision_gate.rs` pins all v1 values, covers every constant-ledger
ID exactly once, and varies pass partition, wake delay, and temporary resource
failure over one closed input set.
