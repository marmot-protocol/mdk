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

Commands are always built as argv arrays. Manifests do not contain shell
fragments, credentials, key material, plaintext application payloads, or
public relay endpoints. Campaign artifacts are written with owner-only modes.

Use `cgka-distributed-campaign validate <manifest>`, then `plan` to inspect the
normalized execution plan before `run` performs any external mutation.

Virtual-machine manifests set a nonzero `timeout_seconds` for the complete
external-driver invocation. Container database-contention durations are
positive whole seconds, and every generated node command receives an explicit
relay-proxy listen address in addition to the upstream relay address.

Failed distributed executions append a privacy-safe entry to the private
`failure-corpus.v1.json` in the campaign output directory. `index-capsule` and
`index-node-capsule` add simulator or process failures, `classify-failure`
applies the reviewed four-way disposition, `diagnose-failure` records
time-to-diagnosis and vector promotion, and `promote-capsule` creates a fixed
vector candidate from synthetic shareable evidence.

The operator contract, backend boundary, artifact posture, and real-container
verification commands live in
[`docs/marmot-architecture/distributed-convergence-campaigns.md`](../../docs/marmot-architecture/distributed-convergence-campaigns.md).
