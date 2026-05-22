# QUIC Broker Deployment

`marmot-quic-broker` is the memory-only sidecar used by brokered agent text stream previews. It forwards live QUIC
records keyed by `stream_id + start_event_id`; it does not store payloads, maintain accounts, talk to relays, or decide
final message authority.

## Local Docker Compose

The root `docker-compose.yml` starts the local relay stack and a local QUIC broker:

```sh
docker compose up -d
docker compose ps
```

The broker listens on UDP `127.0.0.1:4450` and uses a generated self-signed certificate. Local CLI probes should use
`--insecure-local`:

```sh
dm --account <alice> stream start <group-hex> \
  --stream-id <stream-hex> --quic-candidate quic://127.0.0.1:4450
dm --account <bob> stream watch <group-hex> --stream-id <stream-hex> --insecure-local
dm --account <bob> stream watch <group-hex> --stream-id <stream-hex> --insecure-local --background
dm stream send --broker --connect 127.0.0.1:4450 --insecure-local \
  --stream-id <stream-hex> --start-event-id <start-message-id-hex> "hello over brokered quic"
```

Use the foreground watch for one-off transport probes. With `dmd` running, `--background` hands the watch to the daemon
so `messages subscribe` receives `agent_stream_delta` and `stream_preview` updates in the normal typed message stream.

Stop the stack with:

```sh
docker compose down -v
```

## GHCR Image

`.github/workflows/quic-broker-image.yml` builds the broker container for pull requests that touch the broker image path.
On `master` pushes it also publishes:

- `ghcr.io/<owner>/<repo>/marmot-quic-broker:sha-<short-sha>`
- `ghcr.io/<owner>/<repo>/marmot-quic-broker:latest`

The image exposes UDP `4450` and runs:

```sh
marmot-quic-broker --bind 0.0.0.0:4450
```

## VM Run

For a real VM, provision a certificate whose DNS name matches the broker candidate host, open UDP `4450`, then run:

```sh
docker run --rm \
  -p 4450:4450/udp \
  -v /etc/letsencrypt/live/broker.example.com:/run/certs:ro \
  ghcr.io/<owner>/<repo>/marmot-quic-broker:latest \
  --bind 0.0.0.0:4450 \
  --cert-pem /run/certs/fullchain.pem \
  --key-pem /run/certs/privkey.pem
```

Clients should announce the reachable candidate in the durable MLS start payload:

```sh
dm --account <alice> stream start <group-hex> \
  --stream-id <stream-hex> --quic-candidate quic://broker.example.com:4450
```

When the certificate chains to normal platform roots and the candidate host matches the certificate, clients can use the
default platform verifier. `--insecure-local` is only for loopback development.

## Production Broker

The shared production broker candidate is:

```sh
quic://quic-broker.ipf.dev:4450
```

It uses a certificate for `quic-broker.ipf.dev`, so clients should use normal platform trust and must not pass
`--insecure-local`.
