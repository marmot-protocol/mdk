# Native FIPS demo and relay benchmark

This directory contains the Linux demo environment for MDK's hybrid Nostr
relay adapter. Nostr discovery and account metadata continue to use WebSocket;
Welcomes and kind-445 group traffic can use the same Wok relay through its
native FIPS endpoint.

The benchmark is deliberately application-level. It sends ordinary encrypted
Marmot group messages through `wn`, waits for an echo from a second MDK client,
and measures the round trip with the initiator's monotonic clock. It does not
claim to measure raw UDP, WebSocket, FIPS, Wok, or MLS processing in isolation.

## Demo relay

- WebSocket: `wss://relay.fips.whitenoise.chat`
- Native FIPS: `fips://npub1pq5w2qtanuqfu6xctrqvz6jz5adwa0qyr3wvkfw2xy6yv7fneytq49daxg`
- FIPS peer UDP: `62.238.50.254:2121` or `[2a01:4f9:c015:b7a::1]:2121`
- Wok's logical FIPS port: `7777`

The `fips://` endpoint intentionally has no path or port. A FIPS node first
peers with the relay node over UDP 2121; MDK then opens the logical Wok service
at port 7777 through the local FIPS API. Public TCP port 7777 is not involved.
NIP-42 is disabled on both relay front ends for this spike.

## Reproducible checks

Run the read-only remote interoperability check:

```sh
just fips-native-remote
```

It performs a Nostr query to EOSE over both the public WebSocket connection and
the native FIPS connection. It does not publish an event.

Run the complete disposable Docker demo:

```sh
just fips-native-mdk-e2e
```

This creates two accounts using local WebSocket discovery, publishes FIPS-only
inbox lists, creates and accepts a group, exchanges messages in both directions,
checks aggregate FIPS readiness, and exercises a small benchmark round trip.
The small in-container timing is a harness check, not benchmark evidence.

Build the client-only Linux demo image with:

```sh
docker build -f testing/fips-native/Dockerfile.client -t mdk-fips-client .
```

This image contains `wn`, `wnd`, the TUI, FIPS client daemon/tools, the
read-only relay smoke check, and the benchmark harness. It does not contain or
run Wok; the relay remains on the remote relay host.

For a persistent demo client, copy `demo-client-fips.yaml` into a writable,
private directory and mount that directory at `/etc/fips`. On first start FIPS
generates `fips.key` and `fips.pub` beside the configuration; do not use the
deterministic identity in `remote-client-fips.yaml` outside disposable tests.

Run the fast benchmark-tool checks with:

```sh
just fips-benchmark-check
```

## Two-host benchmark setup

Use two Linux MDK clients, such as the demo TUI/CLI image on a VM and a Linux
container on macOS. Record the exact MDK commit or image digest used on each
host. Keep both systems synchronized with NTP if collecting the optional
approximate one-way timing; the primary round-trip metric does not require
synchronized clocks.

Configure each FIPS node with the relay peer in
`remote-client-fips.yaml`, start FIPS, and confirm the peer is present:

```sh
fipsctl --socket /run/fips/control.sock show peers
```

Use a different account pair and group for each transport lane:

- WebSocket lane: both accounts advertise only the WebSocket relay for inbox
  delivery; the group therefore freezes a WebSocket route.
- FIPS lane: publish account discovery and KeyPackages through WebSocket, then
  atomically replace each account's inbox set with the single `fips://`
  endpoint before the inviter fetches the invitee's KeyPackage and creates the
  group.

Separate groups avoid replaceable-event timestamp races and prevent one lane's
relay update from changing the other lane while measurements are running.
All discovery, profile, relay-list, and KeyPackage operations remain on the
WebSocket control plane.

For a FIPS-lane account, stop its daemon before changing the inbox list, wait at
least one second after login or the previous kind-10050 publication, and run:

```sh
WN_FIPS_SOCKET=/run/fips/api.sock \
  wn --home "$WN_HOME" --account "$ACCOUNT_NPUB" --json \
  --relay wss://relay.fips.whitenoise.chat \
  relays set \
  fips://npub1pq5w2qtanuqfu6xctrqvz6jz5adwa0qyr3wvkfw2xy6yv7fneytq49daxg \
  --type inbox
```

Start `wnd` with the WebSocket relay as its discovery/default-account relay,
the FIPS endpoint as an operational relay for the FIPS lane, and
`WN_FIPS_SOCKET=/run/fips/api.sock`. Before creating or sending, require this
predicate from `wn relay-stats`:

```text
.result.fips.enabled == true
.result.fips.connected_endpoints > 0
.result.fips.reconnecting_endpoints == 0
```

The inviter must fetch the invitee through the WebSocket bootstrap relay after
the invitee's final inbox publication, then create the group. Confirm
`wn groups relays GROUP_ID` reports exactly the intended lane endpoint on both
members after the invite is accepted.

## Running a measurement

The Docker image installs the harness as `mdk-relay-benchmark`; from a source
checkout use `python3 testing/fips-native/benchmark.py`. The commands below use
the installed name. Account, group, home, and socket values are needed locally
to drive `wn`, but they are never written to benchmark output.

Choose a synthetic run identifier that does not contain account, group, relay,
or user information. Start the responder first on host B:

```sh
mdk-relay-benchmark responder \
  --home "$WN_HOME" --socket "$WN_SOCKET" \
  --account "$ACCOUNT_NPUB" --group "$GROUP_ID" \
  --run-id run-001-fips-a-to-b --transport fips \
  --client-label linux-b --relay-label demo-wok \
  --build-id "$MDK_BUILD_ID" \
  --output fips-a-to-b-responder.jsonl \
  --expected 55
```

Then run the initiator on host A with the same run id:

```sh
mdk-relay-benchmark initiator \
  --home "$WN_HOME" --socket "$WN_SOCKET" \
  --account "$ACCOUNT_NPUB" --group "$GROUP_ID" \
  --run-id run-001-fips-a-to-b --transport fips \
  --client-label linux-a --relay-label demo-wok \
  --build-id "$MDK_BUILD_ID" \
  --output fips-a-to-b-initiator.jsonl \
  --warmups 5 --samples 50 --payload-bytes 512
```

Repeat with the roles reversed, then repeat both directions on the dedicated
WebSocket group with `--transport websocket`. Do not run the two lanes
concurrently. Use identical warmup, sample, and payload settings and avoid
other traffic on the clients during each run.

Combine one or more initiator files from each lane:

```sh
mdk-relay-benchmark summarize \
  --websocket websocket-a-to-b-initiator.jsonl \
  --websocket websocket-b-to-a-initiator.jsonl \
  --fips fips-a-to-b-initiator.jsonl \
  --fips fips-b-to-a-initiator.jsonl \
  --output comparison.jsonl
```

Retain the raw redacted JSONL, comparison output, MDK build ids, image digests,
host regions, run order, payload size, and sample count. A useful report shows
failure counts plus p50, p95, and p99 rather than only a mean.

## Interpretation limits

- `round_trip_ms` is the preferred result: initiator send through responder
  receive/echo and back to initiator receive, measured on one monotonic clock.
- `publish_ack_ms` is how long that invocation of `wn messages send` took to
  receive relay publication acknowledgement; it is not remote delivery time.
- `approx_sender_to_responder_ms` is diagnostic only and depends on synchronized
  wall clocks.
- Process startup, local daemon IPC, MLS processing, relay work, and the
  responder's `wn` invocation are included equally in both transport lanes.
- Internet path and VM/container placement can dominate the result. These runs
  are directionally useful demo evidence, not a protocol microbenchmark or a
  general latency claim.
- Successful smoke tests establish current interoperability. They do not yet
  establish durable store-and-forward behavior, native macOS support, or
  production readiness.
