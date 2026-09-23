# #1946: bounded incremental comparison versus parked history debt

Decision proposal only. No implementation or schema change is authorized by this document.

## Evidence and conflict

The frozen combined run at `3fcb823652b3bfe4f294423dc452994c16443c18` ran all 2,868 affected-crate tests: 2,865 passed and three failed. The frozen-cursor failure is separate and has a contained compatibility fix. The two `since_floor` tests still fail in isolation after restoring the legacy bounded inventory comparison inside the owner executor.

`cold_restart_reconciles_backlog_below_since_floor` requires a late relay object below a saved subscription floor to be recovered automatically after cold restart, without a separately detected epoch gap. Its third boot checks durable inventory prevents another payload download. `stalled_epoch_backfill_still_arms_after_route_reconciliation` additionally requires the ordinary below-floor reconciliation and the independently detected epoch gap to coexist.

The present owner parks unprovable incremental history in `NeedsDeepRepair`. Its durable scope can retain the original no-cursor/unbounded goal. An unchanged cold restart neither resets retry cost nor rearms that parked obligation. Those rules deliberately prevent a reopen-driven full-history loop, but they also suppress the older bounded routine reconciliation path. Merely restoring its executor call does not authorize it.

## Recommended contract amendment

Preserve bounded automatic incremental reconciliation, with these explicit limits:

1. Keep one authorization owner, one durable reservation sequence, and the existing account-wide retry deadline/ordinal. Cold restart may queue a bounded incremental comparison opportunity; it cannot bypass, reset, or shorten cooldown.
2. Represent the operational comparison opportunity separately from the existing unresolved coverage obligation. Use a stable, account-local durable pending record, not one row per boot or attempt. It is part of the same recovery ledger and has no independent dispatcher or retry clock.
3. Its immutable grant uses the current live subscription floor and the existing capped local inventory/window and route budget. It may run the existing blocking comparison executor. It must not reopen an unfloored history subscription merely because old coverage debt remains unresolved.
4. Finishing that bounded operation means only that the queued comparison opportunity was serviced. Unknown, partial, unsupported, or failed results cannot satisfy the independent history-coverage predicate. Persist any unresolved range/endpoint obligation in the existing history record before retiring the operational request. Repeated requests coalesce; do not silently replace an unresolved coverage goal.
5. Known unsupported capability stays quiescent until a permitted capability/policy change. An ordinary timer tick cannot manufacture a new opportunity. A cold-open request may queue a bounded comparison even when older unprovable history remains parked; this is the deliberate change to the currently approved blanket reopen rule.
6. No SDK upgrade, new connection allocation, async acquisition service, worker scheduler, remote paging, new public API, or relaxed loss acknowledgment belongs to this correction.

## Concrete implementation boundary

- `storage-sqlite/src/account_recovery*` and the integration migration: one stable pending opportunity plus atomic coalescing/reservation/retirement, preserving separate coverage debt and the shared retry state. Final column/record shape must be checked against current schema before editing; no migration renumbering in published dependencies.
- `marmot-app/src/client/recovery.rs`: join the cold-open opportunity, select it under the same owner/cooldown, freeze bounded acquisition intent separately from coverage completion goals.
- `marmot-app/src/client/sync.rs`: run the existing bounded comparison only from that grant; record truthful results and retain unresolved debt.
- `runtime/account_worker.rs`: use the existing due-owner tick to service a deferred opportunity. No second timer or dispatcher.

## Acceptance criteria

- The two existing below-floor journeys recover the same events and retain their exact no-redownload, cursor, and epoch-gap guarantees. Their timing setup must respect owner cooldown rather than assume every cold boot immediately activates recovery.
- A rapid sequence of reopens queues at most one opportunity, preserves the exact retry sequence/cap, and cannot produce extra unfloored activations.
- Unknown coverage remains pending across successful bounded comparisons and reopen; cancellation or a persistence failure cannot lose the opportunity or coverage debt.
- Unsupported capability does not become a repeated comparison loop through reopen.
- Frozen wake collection remains floored and does not spend a recovery reservation. Explicit full-history repair remains an independently requested supported API through the same owner.
- Normal and conservative modes share this durable record, pacing and completion contract.

## Smaller alternative, with an API behavior change

Keep the current quiescence rule and require an explicit caller-requested catch-up to investigate below-floor arrivals once automatic history has parked. Document that cold restart alone no longer restores those events. Rewrite the two regressions only after that changed delivery guarantee is explicitly accepted; retain their admission, no-redownload, cursor and independent-epoch checks around the explicit request.

The recommendation is to preserve automatic bounded recovery. The alternative is smaller but changes an existing delivery behavior, so it is not being applied merely to make tests pass.
