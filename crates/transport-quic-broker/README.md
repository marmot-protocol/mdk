# transport-quic-broker

`transport-quic-broker` is a minimal, memory-only QUIC pub/sub broker for Marmot agent text stream previews. It ships
the `marmot-quic-broker` daemon and the client helpers apps use to publish to and subscribe through it.

It does not store stream payloads, maintain accounts, talk to Nostr relays, or decide final message authority. Clients
anchor a stream through normal encrypted Marmot messages, then use this broker only for transient preview chunks. The
final MLS app-message payload remains authoritative.

## Protocol Shape

- Broker connections negotiate ALPN `marmot.quic_broker.v1`.
- Publishers open a QUIC unidirectional stream, send one binary broker control envelope frame, then send agent text
  stream record frames.
- Subscribers open a QUIC bidirectional stream, send one binary broker control envelope frame, then receive matching
  record frames from the broker. The broker rejects a publish envelope on a bidirectional stream and a subscribe
  envelope on a unidirectional stream.
- Rooms are keyed by `stream_id + start_event_id` (raw bytes in the control envelope).
- Subscriber queues are bounded and live-only.
- Each backlog or live record write to a subscriber is bounded by the 120-second application quiet-gap deadline. A
  stalled, flow-controlled write resets that subscriber stream and unsubscribes it so its handler and per-connection
  stream permit can be reused. Transport keepalives do not extend this deadline; they only keep the QUIC connection
  alive. Quiet gaps while waiting for the next record are unaffected, and a healthy connection stays up after one
  subscriber is evicted. Connection admission and the connection permit of a still-open multiplexed connection are
  unchanged.
- Replay backlog is gated by `--replay-ttl-secs` (default `0`: no retained replay, matching the first-profile
  `replay_ttl_secs` default; hard cap 300s). With a nonzero replay window, backlog entries are timestamped on append
  and purged once they age out; finished rooms keep their remaining backlog for at most 60 seconds.

## Run

```sh
cargo run -p transport-quic-broker --bin marmot-quic-broker -- --bind 127.0.0.1:4450
```

The broker prints its listen address and the SHA-256 fingerprint of its certificate. Without PEM files it generates a
self-signed certificate for `localhost`, which is suitable for local development only.

| Flag | Default | Purpose |
| --- | --- | --- |
| `--bind <ADDR>` | `0.0.0.0:4450` | UDP listen address. |
| `--cert-pem <PATH> --key-pem <PATH>` | generated self-signed | Stable TLS certificate and key (must be passed together). |
| `--per-subscriber-queue <n>` | `32` | Bounded live queue depth per subscriber. |
| `--max-backlog <n>` | `1024` | Replay backlog depth. |
| `--replay-ttl-secs <n>` | `0` | Replay window; hard cap 300. |
| `--publish-max-records <n>` | `65536` | Max records forwarded per publish stream. |
| `--publish-max-frame-bytes <n>` | 64 MiB | Max cumulative record frame bytes forwarded per publish stream. |
| `--json` | off | Emit structured startup/status logs. |

The publish bounds are forward-role abuse limits counted on the wire (ciphertext for encrypted previews); subscribers
still enforce their own receive limits.

Docker and VM deployment notes live in [`../../docs/quic-broker-deployment.md`](../../docs/quic-broker-deployment.md).
