---
title: "Distributed Convergence Campaigns"
created: 2026-08-04
updated: 2026-08-05
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

The campaign image pins both base-image indexes and the Debian package snapshot. Update the digest, dated tag, and
snapshot timestamp together during an explicit dependency refresh. The resulting image also stores the resolved
runtime package set at `/usr/local/share/campaign-runtime-packages.txt`. Participant containers run as the invoking
non-root host identity so their private bind-mounted run roots remain writable; only short-lived network fault
injectors explicitly select UID 0 together with their narrowly scoped `NET_ADMIN` capability.

Container manifests require `NAME@sha256:DIGEST` references for the relay, default participant, and mixed-build
overrides. A local developer using an image such as `marmot-conformance:local` must deliberately set
`allow_mutable_image_references: true`; evidence from that run therefore cannot be mistaken for a digest-pinned run.

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

## What this evidence means

A passing distributed campaign establishes the declared scenario, build matrix, fault schedule, adapter capabilities,
and observations actually requested by that scenario. It does not prove arbitrary networks, kernels, storage devices,
or unbounded executions correct. Evidence bundles must retain those boundaries and list untested surfaces explicitly.
