# transport-quic-broker

`transport-quic-broker` is a minimal, memory-only QUIC pub/sub broker for Marmot agent text stream previews.

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
- Replay backlog is gated by `--replay-ttl-secs` (default `0`: no retained replay, matching the first-profile
  `replay_ttl_secs` default; hard cap 300s). With a nonzero replay window, backlog entries are timestamped on append
  and purged once they age out; finished rooms keep their remaining backlog for at most 60 seconds.

## Run

```sh
cargo run -p transport-quic-broker --bin marmot-quic-broker -- --bind 127.0.0.1:4450
```

For local development the broker prints the SHA-256 fingerprint of its generated self-signed certificate. A stable
certificate can be supplied with `--cert-pem <path> --key-pem <path>`.

Other operator flags: `--per-subscriber-queue <n>` and `--max-backlog <n>` tune the bounded live queue and replay
backlog depths, `--replay-ttl-secs <n>` sets the replay window (default `0`, hard cap 300), and `--json` emits
structured startup/status logs.

Docker and VM deployment notes live in [`../../docs/quic-broker-deployment.md`](../../docs/quic-broker-deployment.md).
