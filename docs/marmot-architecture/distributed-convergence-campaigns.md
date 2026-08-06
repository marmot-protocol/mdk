---
title: "Distributed Convergence Campaigns"
created: 2026-08-04
updated: 2026-08-06
tags: [marmot, convergence, testing, containers, virtual-machines]
---

# Distributed Convergence Campaigns

The `convergence-campaign-runner` crate extends the canonical conformance scenario boundary across operating-system
processes and isolated hosts. It does not define a second scenario language or convergence oracle. A campaign pins the
exact Scenario IR bytes by SHA-256, assigns each scenario participant to a build, and selects an execution backend.
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

VM driver lifecycle contract v1 contains two argv-only invocations on the same driver: the campaign action and an
idempotent cancellation/cleanup action. The runner executes cleanup after success, failure, or campaign timeout under
its own nonzero timeout, records its receipt, and fails closed if cleanup does not complete. The external driver owns
termination of descendants and cleanup of infrastructure created through local or remote APIs; killing the immediate
driver child is not considered sufficient cleanup. Cleanup argv must contain `{manifest}`, which resolves to the
normalized manifest so the driver targets the exact versioned ownership record rather than global infrastructure.

## Reproducibility and artifacts

Every manifest contains:

- a stable campaign id and schema version;
- the canonical scenario path and digest;
- the complete participant/build/image assignment;
- the backend and its declared capabilities;
- faults attached to named Scenario IR barriers; and
- an operator-selected private output directory.

`validate` checks the manifest, participant-to-scenario binding, digest, fault parameters, and backend suitability.
It also rejects a heal without a matching active partition and a duplicate partition that has not first been healed.
`plan` emits the exact normalized command plan without running it. `run` first writes the normalized manifest with
owner-only permissions, then writes the process report and distributed run receipt. Container cleanup is attempted on
both success and failure and cleanup failures remain visible in the receipt.

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

The default CI lane validates command construction and the process boundary without requiring Docker. Scheduled lanes
may opt into the real-container tests when the runner environment advertises that capability.

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
state-independent proof. Incident-corpus coverage is deliberately false in these manifests until the failure-corpus
slice lands.

Every lane defines maximum wall time, CPU time, peak RSS, disk use, artifact bytes, artifact retention, flake retries,
and flake rate. `cgka-distributed-campaign check-budget` consumes an observed-usage JSON document and exits nonzero if
any limit is exceeded. It also rejects zero executed cases, observations below the lane minimum, and flaky-case counts
larger than executed-case counts. The scheduled workflows do not yet emit this aggregate observation or invoke
`check-budget`; these limits are machine-checkable reviewed policy, not yet a green-workflow attestation.
`minimum_executed_cases` is therefore only a liveness floor: it prevents empty evidence, but does not prove that every
declared capability ran. Capability-specific evidence remains required before a lane can support an assurance claim.

The version-1 evidence-bundle type requires a scoped assurance claim, covered decision routes, models, adapters,
mutation results, tested workload/constant boundaries, unresolved counterexamples, residual assumptions, untested
surfaces, a passing same-lane budget evaluation, and at least one digest-pinned artifact. `check-evidence` recomputes
the evaluation from the recorded observation and reviewed lane policy instead of trusting producer-supplied result
fields. It rejects incomplete bundles, parent-traversing artifact paths, missing files, and SHA-256 mismatches by
resolving artifacts relative to the bundle's directory. Valid bundles are written with owner-only permissions.

## What this evidence means

A passing distributed campaign establishes the declared scenario, build matrix, fault schedule, adapter capabilities,
and observations actually requested by that scenario. It does not prove arbitrary networks, kernels, storage devices,
or unbounded executions correct. Evidence bundles must retain those boundaries and list untested surfaces explicitly.
