---
name: blast-radius
description: >-
  Assess what an MDK change could break beyond its edited code. Use for
  "what could this break", downstream impact, compatibility or migration
  risk, and focused impact analysis before implementation or review. Trace
  affected contracts through engine/session state, persistence and restart,
  transport, public APIs, bindings, and feature configurations; identify the
  assumptions that make the change safe and check them with existing evidence.
  Distinguish reproduced failures, code-supported findings, and unresolved
  risks. Independent review belongs to review-local; delivery to land-change.
---

# Assess an MDK change's blast radius

Identify material effects beyond the diff, the contracts they depend on, and
the evidence needed to decide whether the change is safe. A caller inventory
is a starting point, not an impact assessment.

## Bound the assessment

Use the change, files, PR, or proposal the user named. For an existing branch
without a narrower scope, identify its merge base with the intended target
branch (`master` by default) and include relevant staged, unstaged, and
untracked changes. Record the base/head and working-tree scope. Do not treat
an unavailable or stale target ref as current without checking it. A proposal
needs an explicit before/after contract; it does not need an invented patch.

Read the root and nearest `AGENTS.md` for affected owners. Inspect the actual
implementation and relevant caller expectations, not just the PR description.
Use history when the reason for a guard or compatibility path affects the
assessment. Do not weaken a documented invariant to make the proposal safe.

Keep the assessment non-mutating for product code and external state unless
the user also authorized implementation. Existing focused checks and isolated
scratch probes may produce local evidence; they do not authorize fixes,
migrations of user data, or public posting. Preserve any stricter reviewer
restrictions: a `review-local` seat reports a proposed executable check to the
author rather than writing a probe or building in its protected checkout.

## Follow the changed contract

State what changes observably, including errors, defaults, side effects,
ordering, ownership, and persistence. Follow both direct consumers and the
indirect readers that symbol searches miss: stored rows, serialized fields,
events/subscriptions, callbacks, background workers, and another language
reading the same bytes. Check the dependency version and local patch that MDK
actually uses when a library contract is decisive.

Use the relevant boundaries below; do not run an exhaustive workspace audit
for a small local change. An unrelated boundary needs no speculative risk.

| Boundary | MDK-specific questions and owning guidance |
| --- | --- |
| Ownership and projections | Is the change to authoritative protocol state, durable user intent, or derived display/cache state? Can a projection be stale, rebuilt, or absent? Keep shared rules in MDK and inspect host/binding consumers. Start with [the app-core boundary](../../../docs/marmot-architecture/overview/app-core-boundary.md). |
| Persistence and restart | Which writers, readers, migrations, rollback paths, and open-time reconciliation use the affected state? What happens to existing rows or a crash between writes? Keep account-device isolation and distinguish durable from volatile state. Follow [SQLite storage boundaries](../../../docs/marmot-architecture/further-context/app-sqlite-storage-boundaries.md) and the nearest storage `AGENTS.md`. |
| Asynchronous operations and publication | Which awaits, cancellations, retries, or competing workers can observe partial progress? What was accepted externally, what remains pending, and what may be retried without redoing completed work? Follow [multi-step state changes](../../../docs/marmot-architecture/overview/multi-step-state-changes.md). |
| Transport and untrusted input | Check duplicate/reordered/partial delivery, history completeness, reconnects, admission and authorization, and endpoint policy as relevant. Preserve the transport-independent engine and examine actual dial chokepoints and documented residuals in [dial safety](../../../docs/marmot-architecture/overview/dial-safety.md). |
| APIs, wire data, and bindings | Follow public types, errors, defaults, serialized/storage representations, C/UniFFI conversions, CLI JSON, daemon messages, and integration callers. Public consumers may live outside this checkout; report that coverage limit. Keep opaque variable-length MLS `GroupId` bytes distinct from 32-byte Nostr routing handles. See the [root owner map](../../../AGENTS.md). |
| Build and runtime configuration | Which feature combinations, platforms, release artifacts, or production/test timing defaults change reachability? Check changed public items and feature-gated dependents. A development override or installed binary is not evidence for every supported production build. Use the root verification rules and affected crate guidance. |
| Privacy and local artifacts | Could a new error, diagnostic, export, or lifecycle path expose identifiers or secrets, change permissions, or keep database locks through suspension? Follow [observability](../../../docs/marmot-architecture/overview/observability.md) and [local artifact safety](../../../docs/marmot-architecture/overview/local-artifact-safety.md). |
| Verification assumptions | Do models, reference oracles, vectors, generated cases, or exact-name test filters still cover the changed contract? A renamed route, new writer, or changed atomic boundary can invalidate existing evidence without making the old checks fail. Consult the affected simulator/formal owners through the root map. |

Name affected consumers by their role and cite the actual source locations.
For each material risk, describe the reachable trigger, changed behavior, and
user or system consequence. State exposure conditions and uncertainty instead
of inventing probability percentages. Missing external consumer access is an
unknown, not proof that no consumer exists.

## Check the decisive assumptions

Find the facts on which safety depends, such as "the retry retains the exact
published event" or "this row is derived and startup rebuilds it before use."
Do not force the assessment into one assumption when independent contracts
are at risk. Prioritize the facts whose failure changes the conclusion.

For each, establish the strongest useful evidence within the task's budget:

- Read the actual implementation and specification, and trace the failure
  path through reachable inputs, ordering, and state. A type signature alone
  may not establish a runtime or persistence guarantee.
- Reuse an existing focused check when it exercises the disputed production
  path. Use [verify-mdk](../verify-mdk/SKILL.md) for runtime selection,
  readiness, fidelity, evidence retention, and cleanup. Prefer a saved input
  or existing owner-level regression to a new duplicate test.
- Use [formal-verification](../formal-verification/SKILL.md) when the decisive
  question needs a model or proof. Keep bounds, fairness, and the connection
  to implementation explicit; a model pass does not clear every caller.
- If a new probe is useful, keep it isolated and run the actual operation,
  not a restatement of the algorithm. Use [test-audit](../test-audit/SKILL.md)
  for changes to tests or test support. Do not modify production code solely
  to make the assessment runnable.

Keep execution scoped. Follow root/crate requirements when code changes
require broader gates, but do not launch workspace builds, broad campaigns,
benchmarks, or platform suites merely because many consumers were found.
When a check cannot run, retain the reasoning and name the missing evidence.

Classify findings by evidence, separately from severity:

- **Reproduced:** a recorded execution at an identified revision/configuration
  demonstrates the failure. Give the command/input, actual result, expected
  result, and relevant artifacts.
- **Code-supported:** a concrete reachable path or a direct contract
  contradiction establishes the problem from source/specification. Cite the
  premises and trace. State that it was not reproduced; lack of a practical
  reproducer does not invalidate a sound correctness or security finding.
- **Unresolved:** a material risk depends on a fact not established yet.
  Name that fact and the cheapest way to settle it. Do not report a hypothesis
  as a confirmed defect.

A passing check clears only the failure it can observe under its actual
conditions. A no-match search, compile success, timeout, skipped test, or
unexercised fault does not clear a behavioral risk. Preserve known
counterexamples until evidence actually resolves them.

## Hand back a bounded conclusion

Lead with the behavioral change and whether the assessed scope is safe,
needs changes, or remains inconclusive. Then give:

- Affected contracts/consumers and decisive assumptions, with citations.
- Findings, each with severity, evidence class, trigger, consequence, and
  suggested remedy. Keep code-supported defects actionable.
- Risks checked and cleared, with the evidence and its limits; unresolved
  gaps remain separate.
- The smallest remaining validation or design change needed before relying
  on the result, including checks not run and external consumers not examined.

Scale the report to the change; omit empty sections and raw tool dumps.
Do not fix unrelated problems or present this assessment as independent
approval. [review-local](../review-local/SKILL.md) owns independent reviews,
and [land-change](../land-change/SKILL.md) owns the delivery gates and queue.

Adapted from PStack's
[blast-radius](https://github.com/cursor/plugins/blob/bb68f2365eceafa0cb2d253112f675acf5f144cc/pstack/skills/blast-radius/SKILL.md).
The upstream copyright and permission notice are retained in [LICENSE](LICENSE).
