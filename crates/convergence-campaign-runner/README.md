# Distributed convergence campaign runner

This crate owns operating-system-level convergence campaigns. It deliberately
lives outside `cgka-conformance-simulator`: the simulator defines canonical
scenarios and black-box node behavior, while this runner owns containers,
network namespaces, host/process restarts, disk pressure, mixed images, and VM
delegation.

The durable entrypoint is `cgka-distributed-campaign`. A versioned YAML or JSON
manifest selects either:

- a container backend (`docker` or `podman`) for ordinary distributed runs;
- an external VM driver when a campaign requires kernel, block-device,
  filesystem, or stronger host-isolation behavior that containers cannot
represent faithfully.

For the end-to-end operator workflow, including when *not* to use containers or VMs, read
[`../cgka-conformance-simulator/RUNNING_CAMPAIGNS.md`](../cgka-conformance-simulator/RUNNING_CAMPAIGNS.md). For
large seed/case matrices, promotion rules, and family design, read
[`../cgka-conformance-simulator/SCALING_CAMPAIGNS.md`](../cgka-conformance-simulator/SCALING_CAMPAIGNS.md).

The selected scenario path may contain raw canonical Scenario IR or a
`GeneratedScenarioInputV1` saved by the simulator report runner. Generated
inputs pin both their exact envelope digest and their resolved canonical-IR
digest. Container runs resolve the selected IR in memory and record the digest
of the post-lowering IR they execute; manifest-declared host crashes add
deterministic process lifecycle steps. VM runs write the selected IR privately
as `canonical-scenario.json`, so external drivers do not need to understand the
generator envelope.

Commands are always built as argv arrays. Manifests do not contain shell
fragments, credentials, key material, plaintext application payloads, or
public relay endpoints. Campaign artifacts are written with owner-only modes.

The campaign image's relay and loopback proxy executables are owned by this
crate, not the deterministic simulator. A container manifest must record
`allow_cleartext_isolated_relay: true` before the runner enables this cleartext
test hop. The proxy binds loopback and can dial only the fixed
`marmot-campaign-relay` alias that the runner assigns to its relay on the
isolated OCI network; it resolves and pins that authorized alias and rejects
addresses outside an RFC 1918 or IPv6 unique-local network. This exception is
never a general-purpose or production relay dial path.

Every container invocation acquires a unique resource lease. Relay and network
names include that unguessable run component, so setup failure and cleanup can
never target a concurrent campaign that chose the same operator namespace.

VM drivers implement lifecycle contract v1: the manifest supplies ordinary run
argv plus separate idempotent cleanup argv and a cleanup timeout. The runner
invokes cleanup after success, failure, or timeout and records both its command
receipt and any cleanup failure. Cleanup argv must include `{manifest}` so the
driver receives the normalized, versioned ownership record for the exact run.

Use `cgka-distributed-campaign validate <manifest>`, then `plan` to inspect the
normalized execution plan before `run` performs any external mutation.

Scheduled execution lanes use the same binary to collect and enforce resource
evidence. `observe-step --name <name> --output <step.json> -- <argv...>` runs one
trusted workflow command, preserves its ordinary output, and writes a private
step record. `collect-observation` combines those records with final
artifact and working-directory sizes into `observed-usage.v1.json`, and
`check-budget <lane>` evaluates it against the compiled reviewed policy. The
nightly workflow retains these files under
`target/cgka-nightly-lane-evidence`; weekly/manual and release-hardening runs
use `target/cgka-hardening-lane-evidence`.
Release manifests must keep `output_dir` disjoint from the retained weekly,
adversarial, and distributed-container artifact roots; nested roots are rejected
to prevent double-counting.

Release hardening takes an exact lowercase 40-character ancestor commit rather
than an operator-authored mutable image tag. The workflow builds the current and
ancestor campaign images from their exact source trees, resolves both to local
`sha256:<image-id>` references, and uses `materialize-release-campaign` to write
the shared four-party cross-route scenario plus its mixed-build manifest.
`assemble-release-evidence` then joins the reviewed claim under
`release-claims/` to the completed normalized manifest, successful command
receipt, strict public process oracle, lane observation, budget evaluation, and
required step records. It copies privacy-safe inputs into one owner-only bundle
tree and writes a validation record containing only the canonical scenario and
raw process-report digests—not their payload-bearing bytes. `check-evidence`
then verifies every bundled SHA-256 digest. A generated bundle is evidence for
its exact source and baseline revisions only; it is not a universal
convergence claim.

Failed distributed executions append a privacy-safe entry to the private
`failure-corpus.v1.json` in the campaign output directory. `index-capsule` and
`index-node-capsule` add simulator or process failures, `classify-failure`
applies the reviewed four-way disposition, `diagnose-failure` records
time-to-diagnosis, and `promote-capsule` creates a fixed vector candidate from
validated synthetic-shareable evidence and records its capsule/vector digests
in the corpus. Promotion cannot be asserted through the diagnosis command.

The scheduled real-container lane runs both the network-shaping smoke and the shared four-party cross-route
checkpoint. Set `CGKA_DISTRIBUTED_ARTIFACTS_DIR` to an absolute path to retain the latter's exact scenario, normalized
manifest, process report, distributed receipt, and any failure-corpus entry; without it, the
ignored local test uses an automatically deleted temporary directory. The relay's reversible visibility control uses
an owner-only ephemeral directory and opaque run-local event tokens; it retains no Nostr event ids in campaign
evidence.

The operator contract, backend boundary, artifact posture, and real-container
verification commands live in
[`docs/marmot-architecture/distributed-convergence-campaigns.md`](../../docs/marmot-architecture/distributed-convergence-campaigns.md).
