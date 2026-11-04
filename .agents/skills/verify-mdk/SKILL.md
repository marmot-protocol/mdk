---
name: verify-mdk
description: >-
  Run and assess MDK runtime verification through existing engine, public app,
  process, CLI/daemon, and binding harnesses. Use when asked to verify behavior
  end to end, reproduce a runtime failure, choose an acceptance journey, check
  offline or restart recovery, or assess whether a run's evidence supports a
  claim. Select the cheapest execution boundary that exposes the required
  behavior, check build and runtime readiness, retain reproducible evidence,
  and verify cleanup. Test authoring belongs to test-audit; formal guarantees
  belong to formal-verification; delivery belongs to land-change.
---

# Verify MDK runtime behavior

Turn the requested behavior into observable acceptance conditions, select an
existing execution path, and report what the actual run establishes. Read the
root and nearest `AGENTS.md` for the selected harness. Use the
[routing reference](references/runtime-routes.md) for concrete starting points,
readiness checks, commands, evidence, and cleanup.

## Frame and route

State the expected behavior before running it. Name the operation, initial
state, stimulus, expected effects, and any persistence or recovery boundary.
For a bug, preserve the failing input and conditions so the same reproduction
can check a fix. Set a run budget suited to the claim and the repository's
local verification limits.

Choose the cheapest boundary that can expose every required effect:

- Engine and storage owners for exact MLS state, dispositions, transactions,
  or deterministic delivery. Use file-backed storage for reopen, encryption,
  locking, or crash-survival claims.
- Public app-runtime journeys for session behavior, public projections,
  messaging, membership, and recovery through the normal app stack.
- Actual CLI/daemon or language/ABI calls when command parsing, forwarding,
  output, bindings, or host behavior is the claim.
- Process, container, or VM execution when its additional failure or isolation
  boundary matters. Do not widen execution merely to make a run sound stronger.

Check adapter capabilities before executing a scenario. An app projection
cannot establish hidden engine-private state. An orderly close/reopen is not
an abrupt kill; an action-boundary kill is not a crash inside a transaction.
A local relay does not establish a public operator's limits or behavior.

Reuse maintained coverage inventories and saved inputs. Add a missing check
at its existing owner through `test-audit` when the task authorizes it;
otherwise report the gap. Keep feature details with their owners rather than
copying a second feature map into this skill.

## Prepare an isolated, identifiable run

Record the checkout, source revision and any relevant dirty patch, build
profile, features, timing policy, selected tests or scenario, and command.
Identify the binaries actually executed. Durable acceptance evidence follows
the campaign manual's clean-build/provenance requirements; exploratory dirty
runs stay labeled as such.

Use synthetic disposable accounts, private per-identity roots, run-owned
sockets/ports, and a fresh private evidence directory. Never drive the user's
active accounts or adopt an unrelated daemon or relay. Keep evidence outside
the participant roots that teardown removes.

Before driving, confirm the selected test exists and will execute, matching
helper binaries are available, and required runtime/relay readiness checks
succeed. Keep dependent helpers in the same profile and feature mode. Freeze
matching executables for shared build targets or longer runs; a later build
must not replace a helper mid-run. Use the existing harness readiness and
protocol checks rather than adding product-only verification commands.

After a surprising failure, check readiness again. If the instance or state
cannot be trusted, stop that attempt and relaunch in fresh isolation. Preserve
its evidence before retrying; a later pass does not erase the earlier failure.
Bound retries by a specific corrected cause, not a desire for a green result.

## Drive and inspect

Exercise the real operation at the selected boundary. Do not use internal
setters, fabricated acknowledgements, or a test-only shortcut to supply the
effect being asserted. Existing substitutes for external services are useful
only for the contracts they actually exercise; state their limits.

Observe the action and its consequences. Depending on the claim, check exact
payload multiplicity, membership and permissions, public state, continued
communication, pending-work disposition, or what survives reopening. A send
returning success does not by itself establish recipient delivery.

For a fault or race, inspect stimulus evidence: an outage must cut a live
connection, a crash must kill the intended process, and a claimed ordering
must actually occur. Concurrent submission alone does not prove competing MLS
commits. An unexercised stimulus is not a successful fault test.

Inspect semantic results and expected failures as well as exit status. A
diagnostic can pass because it captured a failed scenario. Registration,
preflight, a skipped test, an exhausted budget, or a repair request returning
success does not establish the requested outcome. Keep strict oracles; do not
remove assertions, enable weak-oracle mode, or increase retries to make a
verification pass.

## Clean up and preserve evidence

Run the selected harness's close/shutdown path after success and failure.
Release database handles and reap run-owned children before removing their
roots. Check cleanup errors and surviving owned processes by their recorded
identity; do not kill by process name or clean another agent's artifacts.

Confirm reports, inputs, transcripts, and provenance still exist after
teardown. Retain only the data needed for the claim. Real account state and
checkpoint-bearing replay capsules may contain keys: keep them owner-only,
uncommitted, and out of public reports. Follow MDK logging/privacy rules;
private evidence does not authorize sensitive production logging.

## Report and maintain

Report each acceptance condition as verified, failed, or not established, with
the executed boundary/build, command, evidence path, and material limitations.
Separate product failures, harness errors, environmental refusals, unexercised
stimuli, and incomplete coverage. If the outcome cannot yet be classified,
keep that uncertainty explicit. Include cleanup failures in the result.

Running this skill does not replace the root/crate gates or the landing smoke.
Use `land-change` when delivering a change and `formal-verification` when the
question requires a model or proof rather than runtime observations.

When a documented route drifts, confirm the actual behavior before correcting
the owning map or harness. Treat a broken product contract as a product gap,
not permission to rewrite its acceptance condition. A new or materially
changed recipe must be followed through one real execution, evidence review,
and teardown; mark unexecuted recipes as unvalidated.

Adapted from PStack's
[create-verification-skill](https://github.com/cursor/plugins/blob/bb68f2365eceafa0cb2d253112f675acf5f144cc/pstack/skills/create-verification-skill/SKILL.md).
The upstream copyright and permission notice are retained in [LICENSE](LICENSE).
