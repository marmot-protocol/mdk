# QUIC Broker Deployment

`marmot-quic-broker` is the memory-only sidecar used by brokered agent text stream previews. It forwards live QUIC
records keyed by `stream_id + start_event_id`; it does not store payloads, maintain accounts, talk to relays, or decide
final message authority.

Broker replay retention is an operator-side bound. The broker does not read MLS group state and cannot independently
enforce `agent-text-stream-quic-v1.replay_ttl_secs`; configure broker replay TTLs no greater than the policy for the
groups served. Clients still treat broker replay as provisional preview data until the final MLS message transcript hash
verifies the stream.

## Local Docker Compose

The root `docker-compose.yml` starts the local relay stack and a local QUIC broker:

```sh
docker compose up -d
docker compose ps
```

The broker listens on UDP `127.0.0.1:4450` and uses a generated self-signed certificate. Local CLI probes should use
`--insecure-local`:

```sh
wn --account <alice> stream start <group-hex> \
  --stream-id <stream-hex> --quic-candidate quic://127.0.0.1:4450
wn --account <bob> stream watch <group-hex> --stream-id <stream-hex> --insecure-local
wn --account <bob> stream watch <group-hex> --stream-id <stream-hex> --insecure-local --background
wn stream send --broker --connect 127.0.0.1:4450 --insecure-local \
  --stream-id <stream-hex> --start-event-id <start-message-id-hex> "hello over brokered quic"
```

Use the foreground watch for one-off transport probes. With `wnd` running, `--background` hands the watch to the daemon
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

Manual `workflow_dispatch` runs publish only the `sha-<short-sha>` tag unless they run on `master`.

The image exposes UDP `4450` and runs:

```sh
marmot-quic-broker --bind 0.0.0.0:4450
```

Operator limits beyond the defaults: `--per-subscriber-queue`, `--max-backlog`, `--replay-ttl-secs`, and the
forward-role publish bounds `--publish-max-records` (default 65536) and `--publish-max-frame-bytes` (default 64 MiB).
The publish bounds cap what the broker forwards per publish stream, counted as carried on the wire (ciphertext for
encrypted previews, plaintext otherwise) since the broker never decrypts; subscribers still enforce their own
(receive-side, decrypted-plaintext) limits.

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
wn --account <alice> stream start <group-hex> \
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

### How production runs

The production host runs the broker binary natively under systemd, not the container:

- `marmot-quic-broker.service` runs as user `quic` with
  `/usr/local/bin/marmot-quic-broker --bind [::]:4450 --cert-pem /etc/quic/cert.pem --key-pem /etc/quic/key.pem --json`.
- certbot renews the `quic-broker.ipf.dev` certificate. Its deploy hook,
  `/etc/letsencrypt/renewal-hooks/deploy/quic-broker`, installs `fullchain.pem` and `privkey.pem` into `/etc/quic`
  readable by group `quic`, then restarts the unit.
- The binary has no `--version`. Record the image tag and binary SHA-256 when you deploy. The startup JSON line in
  `journalctl -u marmot-quic-broker` shows the certificate fingerprint and the active limits.

### Redeploying production

Deploy the binary from a `master` image tag so the build matches CI. The image is amd64-only and its binary needs
glibc 2.36 or newer. Extract the binary on any machine with Docker:

```sh
tag=sha-<12-char-commit>
docker create --platform linux/amd64 --name broker-extract \
  ghcr.io/marmot-protocol/mdk/marmot-quic-broker:$tag
docker cp broker-extract:/usr/local/bin/marmot-quic-broker ./marmot-quic-broker
docker rm broker-extract
shasum -a 256 marmot-quic-broker
```

Copy it to the host. As root, stage it and prove it loads the production certificate and negotiates the ALPN on
loopback before you replace the running binary:

```sh
install -o root -g root -m 0755 marmot-quic-broker /usr/local/bin/marmot-quic-broker.new
runuser -u quic -- /usr/local/bin/marmot-quic-broker.new --bind 127.0.0.1:14451 \
  --cert-pem /etc/quic/cert.pem --key-pem /etc/quic/key.pem --json &
openssl s_client -quic -alpn marmot.quic_broker.v1 -connect 127.0.0.1:14451 \
  -servername quic-broker.ipf.dev -verify_hostname quic-broker.ipf.dev -verify_return_error -brief </dev/null
kill %1
```

Then keep the running binary for rollback, swap, and restart:

```sh
cd /usr/local/bin
cp -p marmot-quic-broker "marmot-quic-broker.$(date -u +%Y%m%d)"
mv marmot-quic-broker.new marmot-quic-broker
systemctl restart marmot-quic-broker
journalctl -u marmot-quic-broker -n 3 --no-pager
```

To roll back, move the dated copy back over `marmot-quic-broker` and restart the unit. Finish with the checks below.

### Checking the deployed broker

Clients require the ALPN `marmot.quic_broker.v1`, and so does every broker build since mdk#320. A broker built before
that sets no ALPN: rustls then closes the handshake with `no_application_protocol` (TLS alert 120, shown as
`peer doesn't support any known protocol`), so every current client fails. The alert arrives before the server sends
its certificate, so it can also hide certificate problems. Check the ALPN after every deploy. OpenSSL 3.2 or newer can
make the QUIC handshake without a Rust build:

```sh
openssl s_client -quic -alpn marmot.quic_broker.v1 \
  -connect quic-broker.ipf.dev:4450 -servername quic-broker.ipf.dev \
  -verify_hostname quic-broker.ipf.dev -verify_return_error -brief </dev/null
```

A current broker prints `CONNECTION ESTABLISHED`, `Protocol version: QUICv1`, and `Verification: OK`. A broker
without the ALPN prints `quic_do_handshake:protocol is shutdown`. Add `-4` or `-6` to check each address family.
macOS `/usr/bin/openssl` is LibreSSL and has no `-quic`; use Homebrew `openssl@3`. OpenSSL requires an ALPN for QUIC,
so it cannot reproduce a client that offers none.

The end-to-end check publishes and subscribes through the production broker with platform trust. It tries each
resolved address until one round-trips:

```sh
cargo test -p transport-quic-broker --test public_endpoint -- --ignored
```
