---
title: "Distributed Convergence Campaigns"
created: 2026-08-04
updated: 2026-08-04
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
restart, network partition/heal, latency, jitter, bandwidth, loss, disk pressure, database contention, and
participant-specific images for mixed-build runs. Commands are constructed as argv arrays; manifests cannot inject
shell fragments.

VMs are an explicit escalation, not a parallel implementation. The MDK runner validates and normalizes the campaign,
then invokes an external driver using a versioned manifest and artifact-directory contract. A VM manifest is rejected
unless the campaign requests behavior that the container backend cannot faithfully provide, currently block-device
latency. Driver capability declarations make the reason for escalation reviewable. Provisioning belongs in the
dedicated multi-VM harness rather than this repository.

## Reproducibility and artifacts

Every manifest contains:

- a stable campaign id and schema version;
- the canonical scenario path and digest;
- the complete participant/build/image assignment;
- the backend and its declared capabilities;
- faults attached to named Scenario IR barriers; and
- an operator-selected private output directory.

`validate` checks the manifest, participant-to-scenario binding, digest, fault parameters, and backend suitability.
`plan` emits the exact normalized command plan without running it. `run` first writes the normalized manifest with
owner-only permissions, then writes the process report and distributed run receipt. Container cleanup is attempted on
both success and failure and cleanup failures remain visible in the receipt.

Synthetic campaign manifests and reports must not contain production account ids, group ids, pubkeys, relay URLs,
message content, ciphertext, plaintext, or key material. Incident-derived inputs remain local sensitive artifacts and
must not be committed.

## Operator workflow

Build the current Linux campaign image from the repository root:

```sh
docker build -f Dockerfile.convergence-campaign -t marmot-conformance:local .
```

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

Reviewed lane manifests live under `crates/convergence-campaign-runner/lanes`. The Rust policy test requires those
files to equal the built-in policy exactly, so a budget or coverage change cannot arrive as an unreviewed JSON edit.
The four lanes are:

- pull request: strict formal checks, fixed vectors, and bounded engine/reference/relay coverage without Docker;
- nightly: expanded seeds, file-backed storage, crash and retained-relay matrices, targeted mutations, process runs,
  selected containers, and the incident corpus;
- weekly/manual: process/container soak plus full targeted mutations, resource sweeps, constant sweeps, and mixed-build
  support; and
- release hardening: the largest reviewed bounds, mixed-version execution, and incident-derived regressions.

Every lane defines maximum wall time, CPU time, peak RSS, disk use, artifact bytes, artifact retention, flake retries,
and flake rate. `cgka-distributed-campaign check-budget` consumes an observed-usage JSON document and exits nonzero if
any limit is exceeded. A flake is therefore evidence, not permission to turn a failing assertion green silently.

The version-1 evidence-bundle type requires a scoped assurance claim, covered decision routes, models, adapters,
mutation results, tested workload/constant boundaries, unresolved counterexamples, residual assumptions, untested
surfaces, a passing same-lane budget evaluation, and digest-pinned artifacts. `check-evidence` rejects incomplete
bundles; valid bundles are written with owner-only permissions.

## What this evidence means

A passing distributed campaign establishes the declared scenario, build matrix, fault schedule, adapter capabilities,
and observed exact-state/decryptability checks. It does not prove arbitrary networks, kernels, storage devices, or
unbounded executions correct. Evidence bundles must retain those boundaries and list untested surfaces explicitly.
