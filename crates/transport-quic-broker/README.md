# transport-quic-broker

`transport-quic-broker` is a minimal, memory-only QUIC pub/sub broker for Marmot agent text stream previews.

It does not store stream payloads, maintain accounts, talk to Nostr relays, or decide final message authority. Clients
anchor a stream through normal encrypted Marmot messages, then use this broker only for transient preview chunks. The
final MLS app-message payload remains authoritative.

## Protocol Shape

- Publishers open a QUIC unidirectional stream, send one broker control frame, then send agent text stream record
  frames.
- Subscribers open a QUIC bidirectional stream, send one broker control frame, then receive matching record frames from
  the broker.
- Rooms are keyed by `stream_id + start_event_id`.
- Subscriber queues are bounded and live-only.
- Finished rooms retain bounded backlog for 60 seconds so late subscribers can still replay the completed preview.

## Run

```sh
cargo run -p transport-quic-broker --bin marmot-quic-broker -- --bind 127.0.0.1:4450
```

For local development the broker prints the SHA-256 fingerprint of its generated self-signed certificate. A stable
certificate can be supplied with `--cert-pem <path> --key-pem <path>`.

Docker and VM deployment notes live in [`../../docs/quic-broker-deployment.md`](../../docs/quic-broker-deployment.md).
