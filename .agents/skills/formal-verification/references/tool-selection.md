# Select a verification method

The starting points below were checked against official sources on 2026-11-04.
They are not an allowlist or a permanent ranking. Recheck official manuals,
supported Rust/compiler versions, soundness caveats, release status, and
platform/dependency compatibility when choosing a new tool or relying on a
new capability. Record sources and dates with the selection rationale.

## Start with the missing guarantee

| Needed evidence | Starting point | MDK-specific decision |
| --- | --- | --- |
| Symbolic protocol/convergence safety | Existing Tamarin model | Extend its scope where appropriate; keep authentication assumptions separate from claims about actual cryptographic code. |
| Adversarial authentication, epoch/key binding, or compromise recovery | Evaluate a dedicated security-protocol model, starting with Tamarin | The current convergence model assumes important admitted-input facts. Identify the attacker and the missing security property before modeling additional protocol behavior. |
| Computational cryptographic security under primitive assumptions | Evaluate a computational prover such as CryptoVerif only when the claim needs it | A different proof obligation from symbolic protocol safety; neither approach automatically verifies OpenMLS or MDK's shipped Rust. Protocol security assumptions belong with the canonical Marmot specification. |
| Temporal progress with fairness, crashes, and eventual input closure | Existing TLA+/TLC lifecycle model | Preserve the fair/unfair distinction and durable/volatile state. Do not replace temporal checking with a finite successful execution. |
| Executable bounded state exploration and trace projection | Existing Rust/Stateright mirror | Preserve action identity and the mapping into Scenario IR. A Rust model is not the production runtime merely because both are Rust. |
| Assertions over real Rust inputs, arithmetic, indexing, or a small sequential operation | Evaluate Kani | Probe the actual production call graph and supported types. Explicitly state domains, unwind checks, contracts, stubs, and trusted assumptions. |
| Inductive functional or ownership guarantees worth maintained specifications and proof code | Evaluate Verus or another suitable code verifier | Determine whether it can verify the shipped operation or requires a separately maintained rewrite. Account for specifications and trusted boundaries. |
| Local interleavings and memory-ordering behavior | Evaluate Loom or another concurrency checker | Identify what scheduling and synchronization the checker actually controls. Keep the production algorithm; a copied toy race model cannot close its implementation claim. |
| Undefined behavior in Rust ownership/pointer paths | Evaluate Miri as complementary dynamic analysis | Focus on reachable Rust paths and valid caller contracts; unsupported native dependencies can block the intended target. Do not label a clean run a universal proof. |
| Larger symbolic exploration of an existing TLA+ specification | Evaluate Apalache if TLC's cost blocks a named claim | Compare the same property and configurations; account for bounded executions and supported temporal semantics before substituting tools. |
| Arbitrary-size mathematical theorem beyond tractable finite exploration | Evaluate an inductive proof in a suitable verifier or proof assistant, such as Lean or Rocq | Justify the theorem, axioms, maintenance cost, and link to Rust. A proved restatement without an implementation bridge may add less than a focused production check. |
| Parsing, wire bytes, persistence, integration, or a concrete regression already testable cheaply | Existing Rust tests, properties, fuzzing, or replay | Use `test-audit` and real production boundaries. These can be sufficient without adding a formal language. |

When none fits, research the specific missing capability. Compare the closest
existing MDK method with a concrete alternative; do not survey every language
or install a new suite simply to populate this table.

## Compatibility and trust checks

Before integration, run a small probe against the actual intended function or
model. Record the compiler, verifier, solver, target, features, unsupported
operations, explored domain, runtime, and what the probe genuinely checked.
Respect MDK's pinned build inputs. Use isolated tooling for an experiment;
do not move the workspace toolchain or introduce broad production seams just
to obtain a green prototype.

Assess all of these when they affect the claim:

- **Code identity.** Does the verifier execute/check production code, a
  verification build with equivalent operations, or a separately restated
  algorithm? What changes under `cfg`, replacement types, stubs, or contracts?
- **Exploration.** Which inputs and schedules are quantified over? Did the
  run complete that exploration? Keep unwind assertions and coverage checks;
  insufficient unwinding is not an accepted bound on a larger claimed domain.
- **Trusted facts.** What is assumed rather than proved, including external
  specifications, foreign functions, cryptography, storage semantics, and
  unchecked proof escapes? Does the real caller establish preconditions?
- **Maintenance.** Can the same check run on the supported development and CI
  platforms at a useful cost? Who owns drift detection and tool upgrades?

## Current caveats that change the choice

- **Kani:** current feature documentation excludes concurrency and `await`;
  it warns that concurrent code is compiled as sequential code. Such a run
  cannot establish an MDK scheduler/race claim. Kani also has experimental
  function/loop-contract techniques, so do not permanently characterize it
  as bounded-only. Validate the chosen mode and its proof obligations.
  Sources: [feature support](https://model-checking.github.io/kani/rust-feature-support.html),
  [loop unwinding](https://model-checking.github.io/kani/tutorial-loop-unwinding.html),
  [loop contracts](https://model-checking.github.io/kani/reference/experimental/loop-contracts.html).
- **Verus:** it verifies a supported subset of Rust and is actively evolving.
  Check whether MDK's real code and dependencies fit before proposing an
  adoption or claiming code-level coverage.
  Source: [official repository](https://github.com/verus-lang/verus).
- **Loom:** concurrency-sensitive operations must use its instrumented
  replacements. Uninstrumented synchronization is invisible to its schedule
  exploration; ordinary Tokio integration tests do not become exhaustively
  checked by placing them inside a Loom closure. Review its memory-model
  limitations and the production/instrumented correspondence.
  Source: [official crate documentation](https://docs.rs/loom/latest/loom/).
- **Miri:** executed paths can reveal undefined behavior, but a clean run does
  not cover every input or execution. Foreign/native operations have support
  limits. The deterministic environment is unsuitable for generating real
  cryptographic keys; use synthetic disposable data.
  Source: [official README](https://github.com/rust-lang/miri).
- **Apalache:** its documented starting model uses finite parameters/data and
  bounded-length executions. Do not infer that replacing TLC preserves MDK's
  existing fairness and infinite-run liveness argument.
  Source: [official introduction](https://apalache-mc.org/docs/apalache/index.html).
- **Security-protocol proofs:** Tamarin can reason about an unbounded number
  of role instances when the model and proof support it; MDK's bounded
  initializers are a choice of model scope, not a universal limit of Tamarin.
  CryptoVerif works in a computational model with explicit primitive
  assumptions. Distinguish these guarantees before choosing another language.
  Sources: [Tamarin manual](https://tamarin-prover.com/manual/master/book/001_introduction.html),
  [CryptoVerif](https://bblanche.gitlabpages.inria.fr/CryptoVerif/).

Refresh these caveats when they matter to the target; keep the reasoning
durable and capability claims dated. Adding a tool is justified by new
evidence for a named property, not by the age of this list.
