# Native FIPS relay transport

`transport-fips-native` implements MDK's semantic `FipsRelayApi` boundary on
Linux, FreeBSD, and macOS. It connects to a local FIPS daemon over its Unix socket,
opens one supervised WFP1 flow per `fips://<npub>` relay endpoint, and carries
normal Nostr client/relay JSON messages without HTTP or WebSocket framing.

The endpoint deliberately contains no path or port. This experimental slice
uses FIPS service port `7777`; the local API socket is supplied by the host
through `NativeFipsRelayConfig`.

Run the portable tests with:

```sh
cargo test -p transport-fips-native
```

Run the Linux-native Wok interoperability lab with Docker:

```sh
just fips-native-e2e
```

Run the read-only external interoperability probe against the configured demo
relay with:

```sh
just fips-native-remote
```

The external probe requires ordinary outbound UDP access. It verifies the
FIPS peer connection and a Nostr `REQ`/`EOSE` round trip without publishing an
event.

Set `FIPS_REMOTE_SMOKE_MODE=--publish` to additionally publish one disposable
signed kind-445 event and require both its `OK true` receipt and subscription
echo.

Set `FIPS_REMOTE_SMOKE_MODE=--inbox` to perform the same focused round trip
with a signed kind-1059 event addressed to a disposable recipient. This
isolates the Welcome carrier's relay subscription and fanout path from MLS
processing.

Run the full two-account MDK CLI scenario with:

```sh
just fips-native-mdk-e2e
```

That test uses an ephemeral local WebSocket Wok relay for relay lists and
KeyPackage discovery, then publishes FIPS-only account inbox lists, creates an
MLS group whose routing component contains only the external FIPS relay,
accepts the Welcome, and verifies application messages in both directions.
