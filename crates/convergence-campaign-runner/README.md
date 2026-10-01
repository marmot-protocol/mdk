# convergence-campaign-runner

Operating-system-level convergence campaigns for Marmot: OCI containers, network namespaces and faults, process and
host restarts, disk pressure, mixed participant builds, and delegation to external VM drivers. Use it when a convergence
question needs real sockets, separate participant images, or host isolation that the in-process
[`cgka-conformance-simulator`](../cgka-conformance-simulator/) cannot represent.

The simulator defines canonical scenarios, the black-box node protocol, and the oracle; this crate only runs them in a
wider environment. For when *not* to use containers or VMs, read
[`RUNNING_CAMPAIGNS.md`](../cgka-conformance-simulator/RUNNING_CAMPAIGNS.md); for large seed/case matrices and
promotion rules, read [`SCALING_CAMPAIGNS.md`](../cgka-conformance-simulator/SCALING_CAMPAIGNS.md). The full operator
contract, backend boundary, and artifact posture are in
[`docs/marmot-architecture/distributed-convergence-campaigns.md`](../../docs/marmot-architecture/distributed-convergence-campaigns.md).

## Binaries

- `cgka-distributed-campaign` — the campaign CLI (below).
- `cgka-conformance-node` — participant process inside campaign containers.
- `cgka-conformance-relay` — campaign-only relay plus loopback proxy. These use real sockets, so they live here rather
  than in the deterministic simulator.

## Running a campaign

A versioned YAML or JSON manifest selects either a container backend (`docker` or `podman`) for ordinary distributed
runs, or an external VM driver when a campaign needs kernel, block-device, filesystem, or stronger host-isolation
behavior that containers cannot represent faithfully.

```sh
docker build -f Dockerfile.convergence-campaign -t marmot-conformance:local .

cargo run -p convergence-campaign-runner --bin cgka-distributed-campaign -- validate campaign.yaml
cargo run -p convergence-campaign-runner --bin cgka-distributed-campaign -- plan campaign.yaml
cargo run -p convergence-campaign-runner --bin cgka-distributed-campaign -- doctor campaign.yaml
cargo run -p convergence-campaign-runner --bin cgka-distributed-campaign -- run campaign.yaml
```

`validate` checks the manifest and pinned scenario bytes without side effects (`--require-mixed-builds` demands at
least two participant builds). `plan` prints the normalized argv execution plan, `doctor` checks that the container
runtime or VM driver is executable, and only `run` performs external mutation. Container manifests require
`NAME@sha256:DIGEST` image references unless they deliberately set `allow_mutable_image_references: true`, which
marks the evidence as not digest-pinned.

### Scenario inputs

The scenario path may contain raw canonical Scenario IR or a `GeneratedScenarioInputV1` saved by the simulator report
runner. Generated inputs pin both their exact envelope digest and their resolved canonical-IR digest. Container runs
resolve the selected IR in memory and record the digest of the post-lowering IR they execute; manifest-declared host
crashes add deterministic process lifecycle steps. VM runs write the selected IR privately as
`canonical-scenario.json`, so external drivers do not need to understand the generator envelope.

## Safety posture

- Commands are always built as argv arrays. Manifests never contain shell fragments, credentials, key material,
  plaintext application payloads, or public relay endpoints. Campaign artifacts are written with owner-only modes.
- A container manifest must record `allow_cleartext_isolated_relay: true` before the runner enables the cleartext test
  hop to its relay. The proxy binds loopback and can dial only the fixed `marmot-campaign-relay` alias the runner
  assigns to its relay on the isolated OCI network; it resolves and pins that alias and rejects addresses outside an
  RFC 1918 or IPv6 unique-local network. This exception is never a general-purpose or production relay dial path.
- Every container invocation acquires a unique resource lease. Relay and network names include that unguessable run
  component, so setup failure and cleanup can never target a concurrent campaign that chose the same operator
  namespace.
- The relay's reversible visibility control uses an owner-only ephemeral directory and opaque run-local event tokens;
  campaign evidence retains no Nostr event ids.

### VM drivers

VM drivers implement lifecycle contract v1: the manifest supplies ordinary run argv plus separate idempotent cleanup
argv and a cleanup timeout. The runner invokes cleanup after success, failure, or timeout and records both its command
receipt and any cleanup failure. Cleanup argv must include `{manifest}` so the driver receives the normalized,
versioned ownership record for the exact run.

## Execution lanes and resource budgets

Scheduled lanes use the same binary to collect and enforce resource evidence against reviewed policies in
[`lanes/`](lanes/). Lanes are `pull_request`, `nightly`, `weekly_manual`, and `release_hardening`.

- `lane <lane>` prints or privately writes a lane's reviewed policy.
- `observe-step --name <name> --output <step.json> -- <argv...>` runs one trusted workflow command, preserves its
  ordinary output, and writes a private step record.
- `collect-observation` combines step records with final artifact and working-directory sizes into
  `observed-usage.v1.json`.
- `check-budget <lane> <observation>` fails when observed usage exceeds the lane's budget.

The nightly workflow retains these files under `target/cgka-nightly-lane-evidence`; weekly/manual and
release-hardening runs use `target/cgka-hardening-lane-evidence`. Release manifests must keep `output_dir` disjoint from
the retained weekly, adversarial, and distributed-container artifact roots; nested roots are rejected to prevent
double-counting.

## Release hardening evidence

Release hardening takes an exact lowercase 40-character ancestor commit rather than an operator-authored mutable image
tag. The workflow builds the current and ancestor campaign images from their exact source trees, resolves both to local
`sha256:<image-id>` references, and uses `materialize-release-campaign` to write the shared four-party cross-route
scenario plus its mixed-build manifest.

`assemble-release-evidence` then joins the reviewed claim under [`release-claims/`](release-claims/) to the completed
normalized manifest, successful command receipt, strict public process oracle, lane observation, budget evaluation, and
required step records. It copies privacy-safe inputs into one owner-only bundle tree and writes a validation record
containing only the canonical scenario and raw process-report digests, not their payload-bearing bytes.
`check-evidence` then verifies every bundled SHA-256 digest. A bundle is evidence for its exact source and baseline
revisions only; it is not a universal convergence claim. `just convergence-release-hardening-lane <manifest>` runs the
whole lane.

## Failure corpus

Failed distributed executions append a privacy-safe entry to the private `failure-corpus.v1.json` in the campaign
output directory:

- `index-capsule` and `index-node-capsule` add simulator or process-node failures.
- `classify-failure` applies the reviewed four-way disposition.
- `diagnose-failure` records time-to-diagnosis.
- `promote-capsule` creates a fixed vector candidate from validated synthetic-shareable evidence and records its
  capsule/vector digests in the corpus. Promotion cannot be asserted through the diagnosis command.

## Real-container tests

The default test run validates command construction and the process boundary without Docker. The real-container tests
are ignored because they need a Linux container daemon and the prebuilt image:

```sh
CGKA_CONVERGENCE_IMAGE=marmot-conformance:local \
  cargo test -p convergence-campaign-runner --test container_runtime -- --ignored
```

The scheduled real-container lane runs both the network-shaping smoke and the shared four-party cross-route
checkpoint. Set `CGKA_DISTRIBUTED_ARTIFACTS_DIR` to an absolute path to retain the checkpoint's exact scenario,
normalized manifest, process report, distributed receipt, and any failure-corpus entry; without it, the test uses an
automatically deleted temporary directory:

```sh
CGKA_CONVERGENCE_IMAGE=marmot-conformance:local \
CGKA_DISTRIBUTED_ARTIFACTS_DIR="$PWD/target/cgka-distributed-container-evidence" \
  cargo test -p convergence-campaign-runner --test container_runtime \
    four_party_cross_route_recovery_containers_match_unified_route -- --ignored --exact
```
