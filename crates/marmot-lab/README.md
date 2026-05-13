# marmot-lab

Local end-to-end lab for exercising Marmot with two restartable clients.

The lab uses:

- real `AccountDeviceSession` instances backed by SQLCipher SQLite;
- the real Nostr MLS peeler;
- the real Nostr transport adapter;
- either a deterministic file relay under `--home <path>/relay`, or an actual `nostr-relay-builder::MockRelay` reached
  through `nostr-sdk`.

It is meant for fast local protocol work, not production app code.

## Quick Smoke

```sh
cargo run -p marmot-lab -- --home /tmp/marmot-lab smoke
```

Run the same flow through an in-process SDK mock relay:

```sh
cargo run -p marmot-lab -- mock-smoke
```

That creates Alice and Bob, has Bob publish a KeyPackage, has Alice create a group, syncs Bob's welcome, sends one app
message, and syncs Bob's received message.

Exercise the same path with both clients closed and reopened before the app message send:

```sh
cargo run -p marmot-lab -- mock-restart-smoke
```

## Three-Terminal SDK Mock Relay Lab

Terminal 1:

```sh
cargo run -p marmot-lab -- relay
```

Copy the printed `ws://127.0.0.1:<port>` URL.

Terminal 2:

```sh
cargo run -p marmot-lab -- --home /tmp/marmot-lab --relay ws://127.0.0.1:<port> client bob
```

Then inside Bob's client:

```text
bob> kp
bob> tail
```

Terminal 3:

```sh
cargo run -p marmot-lab -- --home /tmp/marmot-lab --relay ws://127.0.0.1:<port> client alice
```

Then inside Alice's client:

```text
alice> create test bob
alice> send <group-hex> hello from alice
```

Bob's terminal should print the join and the received message.

## Two-Terminal File Relay Lab

The file relay is still useful when you want deterministic JSON artifacts and no live relay process:

```sh
cargo run -p marmot-lab -- --home /tmp/marmot-lab client bob
cargo run -p marmot-lab -- --home /tmp/marmot-lab client alice
```

Use the same in-client commands shown above.

## Important Caveat

Client sessions now persist their OpenMLS signing identity through the same SQLCipher-backed account-device store as
group state, so restart/reopen should not change MLS signatures. Resolve pending publish work before intentionally
exiting a client; resumable pending-publish recovery is still a separate engine/session feature.

One-shot commands are useful for `init`, `status`, and smoke checks. The interactive `client` command is the path to use
for real end-to-end testing.
