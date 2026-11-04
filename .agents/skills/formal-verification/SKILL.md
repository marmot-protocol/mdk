---
name: formal-verification
description: >-
  Establish and audit formal guarantees for MDK's protocol safety, convergence,
  crash recovery, and eventual progress. Use when asked to prove an invariant,
  model-check a race or crash/restart sequence, find gaps in formal coverage,
  check whether a model still matches changed Rust, or choose a verification
  tool or language. Extend MDK's Tamarin, TLA+/TLC, and Stateright work where
  suitable; evaluate current alternatives when they can establish a missing
  guarantee. Connect each claim to production code, state its bounds and
  assumptions, and demonstrate that its check detects a relevant defect.
  Ordinary test authoring and test-suite cleanup belong to test-audit.
---

# Formal verification for MDK

Start with the claim MDK needs to justify. Choose the method after locating
the implementation and existing evidence. Extending a suitable existing model
is preferable to maintaining another description of the same behavior; a new
tool earns its place by answering a question the existing tools cannot answer
well enough.

## Ground the claim

Read the root and nearest `AGENTS.md` for the affected code and verification
files. Use [MDK evidence](references/mdk-evidence.md) to locate relevant models,
implementation bridges, and known limitations; follow its owning sources
instead of treating the map as proof coverage.

State the property and the harm its violation would cause. Distinguish:

- **Safety:** a forbidden outcome never occurs, such as application output
  becoming accepted on a losing branch.
- **Liveness:** an outcome eventually occurs under stated assumptions, such
  as a pending administrative change making progress after input closes.
- **Implementation correctness:** the Rust operation satisfies a specification
  over the inputs and executions the verifier actually covers.

For a named problem, stay on that problem. When asked to find a verification
gap, rank candidates by harm, difficulty of reaching the failure with existing
checks, and cost of maintaining useful evidence. Read existing proof and test
coverage before calling a candidate a gap. Missing a tool is not itself a gap.

## Select the method

Read [Tool selection](references/tool-selection.md) when choosing or revisiting
a method. Confirm current capabilities in official documentation and probe
compatibility with the relevant MDK code before committing to a new verifier.
Retain existing pinned tools unless changing them is part of the task.

Choose the cheapest method that establishes the needed claim. Generated tests,
fuzzing, mutation checks, and dynamic analysis can be the right answer; label
their evidence accurately. A copied Rust algorithm in another language is a
separate model, even if it resembles the implementation exactly.

## Define the verification contract

Keep durable scope and correspondence notes beside the owning model or
harness, extending its existing documentation. Do not create a second global
inventory. Record enough for an agent unfamiliar with the work to determine:

- The property, protocol source or implementation contract, and excluded
  behavior. Protocol changes belong in `marmot-protocol/marmot`.
- Covered Rust files, symbols, state writers, and entry points. Map modeled
  actions to implementation steps, including transaction boundaries, awaits,
  cancellation, publication acknowledgement, and durable versus volatile state.
  An action is atomic only to the extent the implementation guarantees it.
- Input domains and bounds: participants, candidates, messages, integers,
  failures, retries, schedules, loop unwinding, and exploration limits as
  relevant. State whether completion is exhaustive within that scope or relies
  on an inductive argument.
- Assumptions and trusted components: authenticated/dependency-closed input,
  policy agreement, clocks, fairness, input closure, storage/crypto contracts,
  stubs, axioms, unchecked specifications, and solver/tool behavior as relevant.
  Identify where implementation evidence supports each material assumption;
  an unsupported assumption remains a stated limitation.
- Exact commands, pinned tool/compiler/solver versions, target and features,
  expected positive and negative outcomes, run budget, and evidence location.
- The source revision reviewed for correspondence, plus the patch identity
  when checking uncommitted changes. A prior green run is evidence for that
  revision, not a claim about later edits.

Reuse MDK names so grep connects the property, model, Rust test, and vector.
For new code-level harnesses, run the real production operation where the
tool supports it. Apply `test-audit` when adding or changing tests or test
support; do not expose engine internals or add a second algorithm just to make
a verifier accept the code.

## Check the claim and the implementation bridge

Run the relevant existing checks before changing verification. When checking
drift, compare covered code against the recorded correspondence revision;
follow moves, new writers, changed dependencies, and relevant configuration.
A formatting-only diff and a new await between two writes have different
effects on the model. If no reliable revision exists, establish a baseline
from the current code and label historical correspondence unknown.

Build or update the verification from the code and intended contract. Do not
weaken a property, strengthen assumptions, remove actions, or reduce bounds to
hide a failing result. An intentional contract change needs supporting
evidence and an explicit account of the old and new guarantees.

Check reachability and sensitivity for each new or materially changed claim:

- Show that its preconditions and interesting actions can occur. An
  unreachable antecedent or contradictory harness assumptions can make a
  universal assertion pass vacuously.
- Introduce the relevant defect in an isolated scratch checkout and show
  the intended check fail for the intended reason, then restore the baseline.
  Distinguish a model mutation, a simulator semantic mutant, and a mutation of
  production Rust. Each establishes sensitivity only for the thing it changes.
- For an abstract model, separately exercise the implementation bridge with
  shared cases, a production differential, or a replay of the relevant actions.
  If the bridge cannot be checked, report that limitation. A model pass alone
  does not establish that Rust implements the model, and shared cases alone
  do not establish full refinement.

For a counterexample, translate the steps into MDK operations and check their
feasibility against the implementation. Use existing Scenario IR, stable
action ids, and the cheapest capable production harness where applicable.
Preserve the cycle and fairness assumptions of a liveness counterexample; a
finite replay can demonstrate a prefix, not prove infinite-run starvation.
Distinguish a product defect, protocol ambiguity, modeling error, unsupported
tool behavior, and unresolved correspondence. Do not repair product code as a
side effect of a verification-only request.

Inspect individual property results, not only exit status. A timeout,
incomplete exploration, insufficient unwind bound, unsupported operation, or
omitted property is not a pass. An expected negative control passes its gate
only when it fails for the named property rather than setup or tool failure.

## Integrate and report

Use the owning `AGENTS.md` verification commands. Keep local scope targeted;
do not run broad campaigns or workspace suites just because a formal skill
is active. Retain evidence in a fresh scratch location with the checked
revision, commands, configuration, results, and counterexamples. Apply MDK's
private-artifact rules to traces containing real identities, payloads, or key
material; commit only suitable synthetic fixtures.

Update the owning proof inventory and implementation links in the same change.
For an added verifier, supply a reproducible targeted command and a justified
CI lane or documented manual cadence; do not leave an unrun harness presented
as established assurance. Keep experimental probes explicitly experimental.
Use `land-change` when asked to land the work.

Report the property and user impact, chosen method and rationale, exact scope
and assumptions, result per property, sensitivity evidence, implementation
correspondence, and remaining gaps. Separate abstract-model verification,
code-level verification, and test/dynamic evidence. State what this work adds
over the evidence MDK already had. Never summarize a bounded or conditional
result as "MDK is formally verified."

Adapted from PStack's formal-verification creation and maintenance skills at
[revision bb68f236](https://github.com/cursor/plugins/tree/bb68f2365eceafa0cb2d253112f675acf5f144cc/pstack/skills).
The upstream copyright and permission notice are retained in [PSTACK_LICENSE.md](../PSTACK_LICENSE.md).
