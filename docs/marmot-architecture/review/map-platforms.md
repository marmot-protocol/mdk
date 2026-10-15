---
title: "Review Map — Platforms"
created: 2026-10-15
updated: 2026-10-15
tags: [marmot, architecture, review, system-map, platforms]
status: draft
---

# Review Map — Platforms

Part of [Pass 0](00-system-map.md). Baseline `9c95ff2bf`. The same Rust core ships to iOS, Android, macOS, Linux and
Windows. This page records how each platform is built, tested and hosted today, and where platform behaviour reaches
into the architecture. It is descriptive. Observations at the end are inputs to every Pass 1 system. "(inferred)"
marks a claim reasoned from code but not traced; "(dep)" cites a crate in the cargo registry.

## 1. Platform matrix

| Platform | Host | Binding | Built | Run in CI |
| --- | --- | --- | --- | --- |
| iOS (arm64 device and simulator) | White Noise iOS plus a Notification Service Extension | MarmotKit Swift over UniFFI, static XCFramework (`crates/marmot-uniffi/xcframework.sh:10-13`) | On `marmotkit-v*` tags, master, weekly, or PRs labelled `ci:apple` (`.github/workflows/bindings.yaml`, `bindings-profile.yml:3-35`) | Build and link of a consumer only (`crates/marmot-uniffi/validate-swift-package.sh:96-117`); a label-gated clippy of `marmot-account` for iOS (`.github/workflows/ci.yml:339-374`) |
| Android (4 ABIs, API 26) | White Noise Android | MarmotKit Kotlin over UniFFI, JNI `libmarmot_uniffi.so` (`crates/marmot-uniffi/kotlin-bindings.sh:65-66`) | PRs touching `marmot-uniffi` or Cargo files; release tags (`bindings-profile.yml:201-218`) | ELF and 16 KB page-alignment checks only (`release.md:658-664`) |
| macOS (arm64) | White Noise macOS | MarmotKit Swift over UniFFI, one `macos-arm64` slice (`crates/marmot-uniffi/DISTRIBUTION.md:122-123`). The C ABI has local smoke evidence only on Darwin (`crates/marmot-c/README.md:475-476`). | Apple lanes as for iOS; `wn-agent` darwin builds | No Rust tests run on macOS. SwiftPM consumer build; `wn-agent --help`. |
| Linux (x86_64) | `wn`/`wnd`/TUI, `wn-agent`, and the Linux desktop app over the C ABI | C ABI `libmarmot_c` plus `marmot.h`; native binaries | Every PR (`ci.yml`); `marmotc-v*` publishes Linux x86_64 only (`.github/workflows/c-bindings.yml:93`) | The full test matrix, CLI and relay end-to-end tests, conformance, C smoke tests (`ci.yml:290-336`, `:428-792`) |
| Linux (aarch64) | `wn-agent` and harnesses | Binaries | `wn-agent-binaries.yml:121` | `--help` only |
| Windows (x86_64 MSVC) | None documented ([`app-core-boundary.md`](../overview/app-core-boundary.md) lists Android, iOS, macOS and the CLI) | Neither the CLI nor the C ABI is built or packaged (`crates/marmot-c/c-bindings.sh:19`, `:47-49` handle Linux and Darwin only) | `windows-port.yml`: path-filtered, not a required check (`.github/workflows/windows-port.yml:4-25`) | Tests for `fs-private`, `marmot-account`, `marmot-forensics` and `marmot-app`'s root lease only (`windows-port.yml:62-69`) |
| wasm32 | Browser-capable library boundary | `cgka-traits`, `cgka-engine`, `transport-nostr-peeler` | Required check (`ci.yml:212-254`) | Build only |

Windows is not a target. There are no Windows bindings and none are planned. The Linux desktop app may
cross-compile to Windows, but that is untested and not represented in this workspace's CI.

## 2. Platform-specific code

| Crate | What differs by platform |
| --- | --- |
| `fs-private` | Owner-only creation with `O_NOFOLLOW` and 0600/0700 on Unix; **no-op off Unix** (`crates/fs-private/src/lib.rs:826-838`, `:911-955`). Root lease: `flock` on Unix, `LockFileEx` on Windows (`:53-152`). Apple and Android path-walk anchoring (`:366-612`). Unix-socket helpers are Unix-only (`:992-1107`). |
| `marmot-account` | Keyring backend per OS (`crates/marmot-account/src/keyring.rs:80-147`). iOS keychain service suffix and migration (`keyring.rs:8-47`). Windows rename-aside file replacement, documented as non-atomic (`crates/marmot-account/src/io.rs:274-305`). Unix-only link-count checks and directory fsync. |
| `marmot-app` | Root lease, "unsupported" off Unix and Windows (`crates/marmot-app/src/root_runtime_lease.rs:26-88`). Android salt publication by lock and rename instead of hard links (`crates/marmot-app/src/sqlcipher.rs:443-453`). Unix-only inode check on media sources. |
| `storage-sqlite` | Android warning that SQLCipher `mlock` is best effort (`crates/storage-sqlite/src/connection.rs:46-65`). |
| `cgka-engine` | `wasm32` deadline clock (`crates/cgka-engine/src/deadline.rs:6-51`). |
| `cli` | The `daemon` module is ungated but uses Unix sockets and `peer_cred` (`crates/cli/src/daemon/mod.rs:23`, `:174`), so the crate is Unix-only in practice (inferred). |
| `agent-connector` | Ungated `std::os::unix` control socket and media roots (`crates/agent-connector/src/socket.rs:1-8`). |

## 3. Async runtime per host

The same core is scheduled differently depending on the binding:

| Host | Runtime |
| --- | --- |
| Swift and Kotlin (UniFFI) | Exports use `async_runtime = "tokio"` (`crates/marmot-uniffi/src/lib.rs:247`). UniFFI wraps each future in `async_compat::Compat` (dep `uniffi_macros-0.29.4/src/export/scaffolding.rs:281-283`). With no Tokio runtime current on the foreign thread, Compat falls back to one global `new_current_thread()` runtime driven by a single `async-compat/tokio-1` thread (dep `async-compat-0.2.5/src/lib.rs:456-469`). `marmot-uniffi` builds no runtime of its own. So every `tokio::spawn` (account workers, relay plane, timers) runs on that one thread (inferred). |
| C ABI | One `new_multi_thread()` runtime per client (`crates/marmot-c/src/lib.rs:521-524`). |
| `wn`, `wnd`, `wn-agent` | `#[tokio::main]`, multi-threaded. |

Work offloaded with `spawn_blocking` (the first account open, media AEAD for file transfers, external-signer callbacks)
runs on Tokio's blocking pool either way.

## 4. Lifecycle

- **Root lease.** Every UniFFI constructor and `wn-agent` takes a nonblocking exclusive lease on
  `<root>/.marmot-runtime.lock` and fails with `RuntimeBusy` when it is held (`crates/marmot-app/src/lib.rs:1794-1817`).
  The kernel releases it on process exit. `wn` and `wnd` use the unleased constructor (`crates/cli/src/lib.rs:1306`).
- **Suspension.** iOS kills a suspended process that holds a file lock in a shared App Group container (`0xdead10cc`;
  [`local-artifact-safety.md`](../overview/local-artifact-safety.md)). The contract is to await `shutdownAndClose()`
  before suspension and to build a fresh runtime on resume. `shutdown()` alone keeps the databases and the lease.
  There is no enter-background or enter-foreground API (`crates/marmot-uniffi/README.md:117-140`).
- **Push wake.** Hosts call `collect_notifications_after_wake(max_wait_ms, source)` for a bounded catch-up
  (`crates/marmot-app/src/runtime/mod.rs:1845-1937`). The `source` argument is unused (`:1848`). An iOS Notification
  Service Extension constructs with `CursorPersistence::Frozen`, one `Marmot` per push
  (`crates/marmot-uniffi/src/lib.rs:333-343`), which also disables automatic attachment acquisition and analytics.
- **Network change.** The only hook is `notify_connectivity_restored`, which interrupts retry backoff
  (`crates/marmot-uniffi/src/commands/notification.rs:50-56`). There is no path-change signal and no QUIC rebind. The
  nostr-sdk reconnect interval is pinned to 5 s (`crates/transport-nostr-adapter/src/sdk_client.rs:43-47`).

## 5. Secrets

| Platform | Default store |
| --- | --- |
| iOS | Keychain, `AfterFirstUnlockThisDeviceOnly`, no access group (`crates/marmot-account/src/keyring.rs:8-70`) |
| macOS | Keychain (`keyring.rs:86-92`) |
| Android | Android Keystore over JNI, after `MarmotAndroid.initialize(context)` (`keyring.rs:124-127`) |
| Windows | Windows credential store (`keyring.rs:102-105`) |
| Linux | D-Bus Secret Service (`keyring.rs:107-122`) |

Hosts can also supply a store (UniFFI `SecretStore`, C `MarmotSecretStore`). `AccountHome::open` defaults to a
plaintext 0600 file store, which `wn-agent` uses. External signers are UniFFI callbacks; NIP-46 is C-only. SQLCipher
keys are derived from the account secret plus a salt file.

## 6. Native dependencies

- SQLCipher through `rusqlite` with vendored OpenSSL, plus a direct vendored `openssl` for media AES, compiled for every
  target (`Cargo.toml:99`, `:122`).
- TLS: `rustls` with `ring`. Websockets and HTTP use bundled webpki roots; QUIC uses `rustls-platform-verifier` (OS
  trust) (`crates/transport-quic-stream/src/tls.rs:65-73`).
- MLS crypto is pure Rust (`openmls_rust_crypto`). Together with OpenSSL and `ring`, the build carries three crypto
  stacks.
- JNI is required by the Android keyring and by `rustls-platform-verifier`.

## Observations for Pass 1

1. **Swift and Kotlin hosts may run the whole runtime on one thread.** See §3. Every account worker does SQLCipher and
   MLS work inline on its task, so on iOS, Android and macOS one account's convergence pass or hydration batch could
   stall every other account and the relay plane. C and CLI hosts get a multi-threaded runtime, so the same core
   behaves differently by binding, and nothing documents this. Field symptoms fit: iOS and Android show UI stalls,
   while macOS, on the same binding with a faster CPU, shows fewer. The Linux desktop app, on the multi-thread C ABI,
   has not been compared. Pass 1 system B should confirm this with a thread-name trace on a device build.
2. **QUIC previews on Android may fail certificate verification** (filed as
   [#2324](https://github.com/marmot-protocol/mdk/issues/2324)). Broker dials default to platform trust when no
   certificate is pinned (`crates/marmot-app/src/runtime/agent_stream_watch.rs:611-622`). On Android,
   `rustls-platform-verifier` verifies through a JNI context that must be initialized first, and panics otherwise
   (dep `rustls-platform-verifier-0.6.2/src/android.rs:90-94`, `src/verification/android.rs:107`). Nothing in the
   repository initializes it, and the Android bundle does not ship its Kotlin component (`release.md:649-655`). Not yet
   confirmed on a device.
3. **Windows is not a target, and the partial support shows it.** No host-facing binding is built for Windows, `wn-cli` and `agent-connector` are
   Unix-only by construction, restrictive file creation is a no-op (contradicting `local-artifact-safety.md`), and
   account-file replacement is non-atomic.
4. **Mobile runtimes and platform secret stores never run in CI.** Keyring tests use a mock (`keyring.rs:81-84`), the
   Apple and Android lanes build without running anything, and no Rust tests run on macOS.
5. **The notification-extension budget sits mostly outside `max_wait`.** Construction, `start()`, the PBKDF2 opens
   (256k iterations each, `crates/marmot-app/src/sqlcipher.rs:9-18`) and hydration happen before the bounded
   catch-up, and worker readiness may wait up to 45 s (`crates/marmot-app/src/lib.rs:412`). A Notification Service
   Extension gets about 30 s and a small memory limit (inferred risk).
6. **`shutdown_and_close` keeps running after the lease is released.** After closing storage it spends up to 2 s
   flushing analytics and up to 5 s on graceful drain (`crates/marmot-app/src/runtime/mod.rs:6159-6172`). Combined with
   the engine connection that `close_storage` does not close (see the
   [journey map](map-journeys.md#journey-4-startup-and-shutdown)), the "nothing holds a lock when this returns"
   contract depends on that graceful drain finishing.
7. **IPv6-only networks may be refused (inferred).** The shared host-safety classifier rejects addresses outside
   `2000::/3`, and a test asserts that the NAT64 prefix `64:ff9b::/96` is rejected
   (`crates/traits/src/app_components/host_safety.rs:89-127`;
   `crates/marmot-app/src/collector_host_safety/tests.rs:63`).
   DNS64-synthesized addresses for IPv4-only Blossom, broker or collector hosts would then fail. App Review tests on
   IPv6-only networks.
8. **Trust anchors are inconsistent.** Relays and HTTP use bundled roots while QUIC uses OS trust, so user- or
   MDM-installed CAs apply on one path only.
9. **Configuration comes from process environment.** SOCKS5 and loopback flags are read from environment variables once
   per process (`crates/marmot-app/README.md:93-108`), which mobile hosts cannot easily set.
10. **Root exclusivity is not universal.** Because the CLI is unleased, a desktop app, `wn`/`wnd` and `wn-agent` sharing
    one root are not mutually excluded. On Android, a second `Marmot` in the same process gets `RuntimeBusy`, because
    `flock` is per open file description, so WorkManager must reuse the one handle (inferred).
11. **Restored devices.** Keys are `ThisDeviceOnly`, but the databases and salt files can be backed up, so a restored
    device may hold databases it cannot open. There is no backup guidance.
