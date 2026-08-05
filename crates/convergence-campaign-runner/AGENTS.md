# AGENTS.md — convergence-campaign-runner

Read [`README.md`](README.md) for the operator overview and
[`../../docs/marmot-architecture/distributed-convergence-campaigns.md`](../../docs/marmot-architecture/distributed-convergence-campaigns.md)
for the durable evidence contract.

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

## Verification

```sh
cargo test -p convergence-campaign-runner --locked
cargo clippy -p convergence-campaign-runner --all-targets --locked -- -D warnings
```

The ignored real-container test additionally requires a prebuilt Linux image
and a Docker or Podman daemon; see the crate README for the exact command.
