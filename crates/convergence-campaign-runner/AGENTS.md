# AGENTS.md — convergence-campaign-runner

Read [`README.md`](README.md) for the operator overview and
[`../../docs/marmot-architecture/distributed-convergence-campaigns.md`](../../docs/marmot-architecture/distributed-convergence-campaigns.md)
for the durable evidence contract. Also read
[`../cgka-conformance-simulator/RUNNING_CAMPAIGNS.md`](../cgka-conformance-simulator/RUNNING_CAMPAIGNS.md) before
running a wider adapter and [`../cgka-conformance-simulator/SCALING_CAMPAIGNS.md`](../cgka-conformance-simulator/SCALING_CAMPAIGNS.md)
before designing a large matrix.

## Agent operating workflow

1. Confirm that the scenario already passes the smallest subject capable of its oracle. Containers and VMs add
   environment evidence; they do not repair an invalid scenario or oracle.
2. Resolve and verify the exact scenario/generated-input bytes, source revision, participant images, adapter
   capabilities, and output root. Preserve selected and executed IR digests.
3. Run `validate`, `plan`, and `doctor` before `run`. Inspect argv, image assignment, namespace/resource token, faults,
   cleanup, deadlines, and artifact paths. Manifests never contain shell fragments.
4. Use containers for sockets, network namespaces, real transport lifecycle, participant image separation, and
   supported network/disk faults. Use the external VM backend only for a named kernel, filesystem, block-device,
   reboot, or stronger host-isolation hypothesis.
5. Keep broad seed discovery in the simulator's isolated worker runner. Promote only representative saved inputs,
   failures, slow/resource boundaries, and mixed-build cases to this crate.
6. On any setup, mutation, timeout, or cleanup failure, retain every receipt and fail closed. Never manually delete
   namespace-only resources belonging to a potentially concurrent campaign.
7. Treat public process/container projection as public evidence only. Pair it with an exact engine-capable control for
   cryptographic state, input dispositions, pending work, or active decryptability claims.
8. Record exact revisions/image digests and keep evidence owner-only. Never use public relays, real identifiers,
   payloads, credentials, ciphertext, plaintext, or key material.

## Scope

This crate owns operating-system-level convergence campaigns: OCI containers,
network namespaces and fault injection, process/host restart, disk pressure,
mixed participant images, artifact receipts, and delegation to an external VM
driver. It consumes canonical scenarios and the versioned JSONL node protocol
from `cgka-conformance-simulator`; it must not define a second scenario language
or convergence oracle.

The campaign-only relay and loopback proxy binaries live here because they use
real sockets. Keep real network behavior out of the deterministic simulator
crate. The cleartext proxy is permitted only when the versioned manifest
records explicit operator approval for the runner-created isolated container
network. It must remain loopback-bound on the participant side and dial only
the runner-owned relay alias, resolving and pinning a private address while
rejecting public or loopback addresses.

## Invariants

- Construct every external command as an argv array. Never accept shell
  fragments from manifests.
- Include the runner-generated resource token in every container network and
  relay name; cleanup must never target namespace-only shared names.
- Apply fault mutations transactionally: on failure, attempt every applicable
  rollback, retain every receipt, and fail closed when compensation is
  incomplete.
- Accept only exact success for required mutations. Use absence-tolerant exit
  codes only for idempotent cleanup, then verify the postcondition.
- Do not claim a fault that cannot affect the selected backend. Reject
  participant-to-participant container partitions and VM-only storage faults at
  validation time.
- Keep participant processes non-root. Grant `NET_ADMIN` only to short-lived
  fault-injector containers.
- Keep manifests and shareable evidence free of account ids, group ids,
  pubkeys, relay URLs, payloads, ciphertext, plaintext, credentials, and key
  material. Create artifacts through `fs-private`.
- VM lifecycle contract v1 always runs its idempotent cleanup command under an
  independent timeout after success, failure, or timeout and records the
  result. Never treat killing only the immediate driver process as cleanup.

## Verification

```sh
cargo test -p convergence-campaign-runner --locked
cargo clippy -p convergence-campaign-runner --all-targets --locked -- -D warnings
```

The ignored real-container test additionally requires a prebuilt Linux image
and a Docker or Podman daemon; see the crate README for the exact command.
