---
title: "Distributed Convergence Campaigns"
created: 2026-08-04
updated: 2026-08-15
tags: [marmot, convergence, testing, containers, virtual-machines]
---

# Distributed Convergence Campaigns

The `convergence-campaign-runner` crate extends the canonical conformance scenario boundary across operating-system
processes and isolated hosts. It does not define a second scenario language or convergence oracle. A campaign pins the
exact selected input bytes by SHA-256, assigns each scenario participant to a build, and selects an execution backend.
The input may be raw canonical Scenario IR or a saved generated-input envelope. Generated inputs additionally pin the
digest of the canonical IR inside the envelope, so changing generator provenance or expectations cannot obscure which
executable history reached the adapter.
The child nodes continue to report through the same versioned process protocol and exact-state oracle used by the
process adapter.

## Backend boundary

Containers are the default distributed backend. They cover process isolation, retained-relay restart, participant
restart, participant-to-relay network partition/heal, latency, jitter, bandwidth, loss, disk pressure, database contention, and
participant-specific images for mixed-build runs. Commands are constructed as argv arrays; manifests cannot inject
shell fragments. Because container participants communicate through the relay rather than directly to one another,
participant-to-participant partition selectors are rejected instead of recording a vacuous fault; use the VM backend
when direct peer-network isolation is part of the scenario.

Each container invocation acquires a unique runtime resource token. Network and relay names combine the operator
namespace with that token; setup failure and cleanup therefore cannot address a concurrent campaign's resources even
when both manifests select the same namespace. Participant process names retain their separate process-run token.

The image's test relay and loopback proxy live in the campaign-runner crate. A container manifest must record
`allow_cleartext_isolated_relay: true` as explicit operator approval before the runner enables the cleartext test hop.
The proxy binds only to loopback and has no configurable upstream: it can dial only the fixed
`marmot-campaign-relay` alias that the runner assigns to the relay on the isolated OCI network. It resolves and pins
that authorized alias and rejects public, loopback, or otherwise non-private addresses. This is a recorded local test
exception, not an approved production dial path.

VMs are an explicit escalation, not a parallel implementation. The MDK runner validates and normalizes the campaign,
then invokes an external driver using a versioned manifest and artifact-directory contract. A VM manifest is rejected
unless the campaign requests behavior that the container backend cannot faithfully provide, currently block-device
latency. Driver capability declarations make the reason for escalation reviewable. Provisioning belongs in the
dedicated multi-VM harness rather than this repository.

Before either backend starts, the runner resolves the selected input through the simulator-owned parser. Container
orchestration consumes that value in memory; manifest-declared host crashes deterministically lower into process crash
and restart steps, and the process report records a distinct digest for the post-lowering IR it compiles. VM runs write
the selected canonical IR privately to `canonical-scenario.json`. The VM `{scenario}` placeholder names that file, so
external drivers never need a second generated-envelope parser and cannot accidentally execute envelope metadata as
Scenario IR.

VM driver lifecycle contract v1 contains two argv-only invocations on the same driver: the campaign action and an
idempotent cancellation/cleanup action. The runner executes cleanup after success, failure, or campaign timeout under
its own nonzero timeout, records its receipt, and fails closed if cleanup does not complete. The external driver owns
termination of descendants and cleanup of infrastructure created through local or remote APIs; killing the immediate
driver child is not considered sufficient cleanup. Cleanup argv must contain `{manifest}`, which resolves to the
normalized manifest so the driver targets the exact versioned ownership record rather than global infrastructure.

## Reproducibility and artifacts

Every manifest contains:

- a stable campaign id and schema version;
- the selected scenario/envelope path and exact source digest;
- the resolved canonical Scenario IR digest when a generated envelope is selected;
- the complete participant/build/image assignment;
- the backend and its declared capabilities;
- faults attached to named Scenario IR barriers; and
- an operator-selected private output directory.

`validate` checks the manifest, participant-to-scenario binding, digest, fault parameters, and backend suitability.
It also rejects a heal without a matching active partition and a duplicate partition that has not first been healed.
`plan` emits the exact normalized command plan without running it. `run` first writes the normalized manifest with
owner-only permissions; VM runs also write the selected `canonical-scenario.json`. It then writes the process report and
distributed run receipt. The normalized manifest always records the selected canonical digest. Container cleanup is
attempted on both success and failure and cleanup failures remain visible in the receipt.

External container faults run immediately before the named barrier. Host crash faults are different: the runner lowers
them into scenario-owned process crash and restart actions immediately after the named barrier, so evidence describes
the lifecycle transition at the same deterministic schedule position on every run.

Synthetic campaign manifests and reports must not contain production account ids, group ids, pubkeys, relay URLs,
message content, ciphertext, plaintext, or key material. Incident-derived inputs remain local sensitive artifacts and
must not be committed.

## Operator workflow

Build the current Linux campaign image from the repository root:

```sh
docker build -f Dockerfile.convergence-campaign -t marmot-conformance:local .
```

The campaign image pins both base-image indexes and the Debian package snapshot. Update the digest, dated tag, and
snapshot timestamp together during an explicit dependency refresh. The resulting image also stores the resolved
runtime package set at `/usr/local/share/campaign-runtime-packages.txt`. Its builder tag must match the channel in
`rust-toolchain.toml`, which is copied into the build context and enforced by the ordinary CI toolchain gate.
Participant containers run as the invoking
non-root host identity so their private bind-mounted run roots remain writable; only short-lived network fault
injectors explicitly select UID 0 together with their narrowly scoped `NET_ADMIN` capability.

Container manifests require `NAME@sha256:DIGEST` references for the relay, default participant, and mixed-build
overrides. A local developer using an image such as `marmot-conformance:local` must deliberately set
`allow_mutable_image_references: true`; evidence from that run therefore cannot be mistaken for a digest-pinned run.
Every container manifest must also deliberately set `allow_cleartext_isolated_relay: true`; omission fails validation,
and the normalized manifest preserves that approval in the evidence bundle.

Keep local or incident-derived manifests under `campaign-local/` and run artifacts under `campaign-output/` (or the
already ignored incident directories). These paths are excluded from the Docker build context, and the campaign
Dockerfile copies only workspace build inputs into the builder stage.

Then validate, inspect, and run a pinned manifest:

```sh
cargo run -p convergence-campaign-runner --bin cgka-distributed-campaign -- validate campaign.yaml
cargo run -p convergence-campaign-runner --bin cgka-distributed-campaign -- plan campaign.yaml
cargo run -p convergence-campaign-runner --bin cgka-distributed-campaign -- run campaign.yaml
```

The real-container tests are intentionally ignored in ordinary local and PR runs because they require a Linux
container daemon and a prebuilt image. Run them explicitly with:

```sh
CGKA_CONVERGENCE_IMAGE=marmot-conformance:local \
  cargo test -p convergence-campaign-runner --test container_runtime -- --ignored
```

The named four-party checkpoint can retain its exact distributed evidence outside the test's temporary directory:

```sh
CGKA_CONVERGENCE_IMAGE=marmot-conformance:local \
CGKA_DISTRIBUTED_ARTIFACTS_DIR="$PWD/target/cgka-distributed-container-evidence" \
  cargo test -p convergence-campaign-runner --test container_runtime \
    four_party_cross_route_recovery_containers_match_unified_route -- --ignored --exact
```

The default CI lane validates command construction and the process boundary without requiring Docker. Scheduled lanes
run selected real-container tests when the runner environment advertises that capability. The four-party checkpoint
uses the same `cross-route-app-runtime-recovery/v1` builder, canonical IR digest, and strict public process-report
oracle as the isolated-process checkpoint, then uploads its owner-only evidence directory even after failure. It is
public protocol/application projection evidence; exact MLS state, durable convergence-input dispositions, and active
decryptability remain owned by the engine-capable control.

The retained-relay visibility seam is not a network administration API. The runner bind-mounts an owner-only,
run-scoped control directory into the repository-owned relay. Relay admission records contain only publication class
and an opaque token derived with an ephemeral secret; raw Nostr event ids, payloads, ciphertext, and key material are
not persisted. The directory lives under the runner's temporary resource lease and is removed with that lease rather
than uploaded as campaign evidence.

## Execution lanes and budgets

Reviewed lane manifests live under `crates/convergence-campaign-runner/lanes`. They are compiled into the runner with
`include_str!` and parsed by `CampaignLaneConfigV1::builtin`, so the reviewed JSON is the only policy source rather
than a second copy of the same constants in Rust.
The four lanes are:

- pull request: the ordinary mandatory formal/model/vector checks without Docker;
- nightly: file-backed, crash, retained-relay, mutation, process, policy-sweep, and selected-container coverage;
- weekly/manual: the nightly coverage plus a larger generated batch and the full current container test target; and
- release hardening: the weekly work plus an operator-supplied distributed manifest with at least two participant
  build ids and, for containers, at least two effective participant images.

The source revision must already have passed the mandatory PR formal gate; scheduled workflows do not repeat the same
state-independent proof. The failure-corpus lifecycle validation recipe is a dependency of every lane in this slice;
it validates indexing, classification, reduction, and promotion mechanics but does not execute an incident corpus.
Accordingly, `incident_corpus` is false until a lane has a real, reviewed incident-derived input set and runner.

Every lane defines maximum wall time, CPU time, peak RSS, disk use, artifact bytes, artifact retention, flake retries,
and flake rate. `cgka-distributed-campaign check-budget` consumes an observed-usage JSON document and exits nonzero if
any limit is exceeded. It also rejects zero executed cases, observations below the lane minimum, and flaky-case counts
larger than executed-case counts. The nightly, weekly/manual, and release-hardening workflows wrap each lane command
with `observe-step`, aggregate the private step records with `collect-observation`, then invoke `check-budget` even
after an earlier failure. A failed wrapped command writes its step record before returning nonzero, so failure evidence
is retained rather than replaced by a generic red workflow.

On the scheduled Linux runner, each step records elapsed wall time, `wait4` user/system CPU, peak RSS, exit or signal,
and a filesystem-block-write lower bound. Executed cases come from Nextest's experimental structured suite summaries;
retry counts come from its retry-status records. The aggregate sums sequential step wall/CPU time and case/retry
counts, takes the maximum per-step RSS, and measures final regular-file bytes below the declared working and retained
artifact roots without following symlinks. These are deliberately bounded observations: setup/tool installation,
GitHub upload time, peak transient Docker disk use, non-Nextest case notions, and the collector's own metadata bytes are
not included; process usage also excludes work performed outside the command's child tree, such as the Docker daemon.
Non-Unix observations lack required CPU/RSS fields and therefore cannot satisfy scheduled collection.
The retained raw observation and budget decision live under `target/cgka-nightly-lane-evidence` or
`target/cgka-hardening-lane-evidence` beside the per-step records.

The scheduled workflows pin Nextest `0.9.104` because case and retry accounting depends on its structured suite and
retry-status formats. Missing artifact roots contribute zero bytes so an early lane failure can still retain its
aggregate; the disk root remains mandatory. A release manifest's `output_dir` must not equal or nest under the retained
weekly, adversarial, or distributed-container roots, because overlapping roots would double-count bytes and are
rejected.

GitHub-hosted jobs have a six-hour execution ceiling. The weekly/manual wall budget is five hours and release
hardening is five and a half hours, leaving the same job time to collect, evaluate, and upload failure evidence. A
hardening workload that needs a longer reviewed budget must move to a runner whose execution ceiling can preserve
equivalent evidence headroom; raising `timeout-minutes` above the hosted-runner limit does not do so.

`minimum_executed_cases` is therefore only a liveness floor: it prevents empty evidence, but does not prove that every
declared capability ran. Capability-specific evidence remains required before a lane can support an assurance claim.

The version-1 evidence-bundle type requires a scoped assurance claim, covered decision routes, models, adapters,
mutation results, tested workload/constant boundaries, unresolved counterexamples, residual assumptions, untested
surfaces, a passing same-lane budget evaluation, and at least one digest-pinned artifact. `check-evidence` recomputes
the evaluation from the recorded observation and reviewed lane policy instead of trusting producer-supplied result
fields. It rejects incomplete bundles, parent-traversing artifact paths, missing files, and SHA-256 mismatches by
resolving artifacts relative to the bundle's directory. Valid bundles are written with owner-only permissions.

## Failure corpus lifecycle

Generated simulator failures already write a portable capsule, a minimized Scenario IR reproducer, and—when enabled—a
sensitive byte-replay capsule. Distributed execution now also appends a message-free record to a private version-1
corpus whenever a run fails. Simulator capsules and process-node capsules can be indexed with their pinned scenario;
the corpus groups them by semantic fingerprint, counts recurrence across adapters/build matrices, retains seeds and
capsule paths, and records the best time-to-diagnosis plus digest-pinned promoted-vector provenance.

Every entry has exactly one reviewable classification: product defect, protocol ambiguity, environment failure, or
expected resource refusal. Environment failures are recognized conservatively. Resource and protocol failures remain
product defects until an operator explicitly establishes that a refusal was expected or that the protocol is
ambiguous; the tooling does not turn an unexpected failure into an expected outcome automatically.

Scenario minimization first removes semantic dependency units—partition/heal, offline/reconnect, crash/restart,
storage-fault/clear, and withhold/release pairs—then removes independent transport noise while requiring the same
semantic failure identity. Non-layer-specific VM, container, process, and app-runtime failures emit a candidate for the
next smaller adapter. The candidate carries the minimized canonical scenario and failure identity, so the smaller
adapter must reproduce the same failure before the layer is removed from the diagnosis.

Only validated synthetic-shareable capsules with portable expectations may be promoted into fixed vector candidates.
The promotion command writes the candidate before recording its path, SHA-256 digest, and source-capsule path/digest
in the corpus. The diagnosis command cannot assert promotion. Sensitive capsules remain local and are never eligible.

## What this evidence means

A passing distributed campaign establishes the declared scenario, build matrix, fault schedule, adapter capabilities,
and observations actually requested by that scenario. It does not prove arbitrary networks, kernels, storage devices,
or unbounded executions correct. Evidence bundles must retain those boundaries and list untested surfaces explicitly.
