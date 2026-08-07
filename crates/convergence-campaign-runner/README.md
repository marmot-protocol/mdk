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

The selected scenario path may contain raw canonical Scenario IR or a
`GeneratedScenarioInputV1` saved by the simulator report runner. Generated
inputs pin both their exact envelope digest and their resolved canonical-IR
digest. The runner writes the resolved IR privately as `canonical-scenario.json`;
container nodes and external VM drivers therefore execute the same scenario
without needing to understand the generator envelope.

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

Failed distributed executions append a privacy-safe entry to the private
`failure-corpus.v1.json` in the campaign output directory. `index-capsule` and
`index-node-capsule` add simulator or process failures, `classify-failure`
applies the reviewed four-way disposition, `diagnose-failure` records
time-to-diagnosis, and `promote-capsule` creates a fixed vector candidate from
validated synthetic-shareable evidence and records its capsule/vector digests
in the corpus. Promotion cannot be asserted through the diagnosis command.

The operator contract, backend boundary, artifact posture, and real-container
verification commands live in
[`docs/marmot-architecture/distributed-convergence-campaigns.md`](../../docs/marmot-architecture/distributed-convergence-campaigns.md).
