# marmot-uniffi

UniFFI bindings for the Marmot app runtime.

The Rust API in `src/` is the source of truth for both generated Swift and generated Kotlin. Platform scripts only
package that shared surface:

- `./crates/marmot-uniffi/xcframework.sh` builds `output/MarmotKit.xcframework` plus `output/MarmotKit.swift` for iOS.
- `./crates/marmot-uniffi/xcframework-macos.sh` builds `output/macos/MarmotKit.xcframework` plus
  `output/macos/MarmotKit.swift` for macOS on Apple Silicon (`aarch64-apple-darwin`). Its output directory is separate
  from the iOS one so building both in one workspace cannot clobber either artifact.
- `./crates/marmot-uniffi/kotlin-bindings.sh` builds `output/android/kotlin/.../marmot_uniffi.kt` plus Android
  `jniLibs` shared libraries.

The generated Swift file is platform-independent: `output/MarmotKit.swift` and `output/macos/MarmotKit.swift` are the
same UniFFI surface, and releases publish it once.

See [`DISTRIBUTION.md`](DISTRIBUTION.md) for immutable Apple and Android artifacts, exact release and snapshot URLs,
checksums, provenance, and generated-source synchronization rules.

The Kotlin binding is generated from the same release host library metadata as Swift, so it exposes the same `Marmot`
object, subscription objects, records, enums, and error variants.

## Exclusive Root Ownership

Every `Marmot` constructor acquires a nonblocking exclusive lease on
`.marmot-runtime.lock` in `rootPath`. The lease prevents the foreground app and
an independently launched notification service extension from hydrating and
writing the same Marmot state at the same time. The lock is owned by an open
file descriptor, so the kernel releases it if iOS terminates the process; the
lock file itself is stable and must not be deleted.

When another process or runtime owns the root, construction throws the typed
Swift error `MarmotKitError.RuntimeBusy`. An NSE should take its bounded
fallback path, while a foreground app can retry after the current owner exits.
Calling `shutdown()` stops runtime work but intentionally does not release the
lease while the `Marmot` object or one of its runtime handles is still alive.
Release the final object reference before constructing a replacement.

## Service Endpoint Defaults

`marmotkit-endpoints.env` sets the public build-time defaults consumed by Marmot's compiled endpoint config:

- `MARMOT_AUDIT_LOG_TRACKER_ENDPOINT`
- `MARMOT_RELAY_TELEMETRY_OTLP_ENDPOINT`

These are route URLs only. Host apps still supply audit and telemetry bearer tokens at runtime. Set either environment
variable before invoking a build script to override the default for staging or local testing.

Public profile-image uploads default to `https://blossom.primal.net`. Rust
hosts can override or disable that third-party service with
`MarmotServiceEndpoints::profile_image_blob_endpoint`; FFI callers can continue
to pass an explicit Blossom server to `uploadProfileImage`.

## Kotlin / Android

Prerequisites:

```sh
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
# macOS Android Studio default:
export ANDROID_NDK_HOME="$HOME/Library/Android/sdk/ndk/<version>"
# Linux / common CI default:
# export ANDROID_NDK_HOME="$HOME/Android/Sdk/ndk/<version>"
```

CI jobs can also set `ANDROID_SDK_ROOT` or `ANDROID_HOME`; the build script will discover the newest NDK under
`$ANDROID_SDK_ROOT/ndk` or `$ANDROID_HOME/ndk` when `ANDROID_NDK_HOME` is not set.

Build all Android ABIs:

```sh
./crates/marmot-uniffi/kotlin-bindings.sh
```

The script keeps the host library's UniFFI metadata intact while stripping
debug and static symbol sections from each packaged Android JNI library.

To build a subset:

```sh
ANDROID_ABIS="arm64-v8a x86_64" ./crates/marmot-uniffi/kotlin-bindings.sh
```

Generated Kotlin uses package `dev.ipf.marmotkit`, loads `libmarmot_uniffi.so`, and requires the normal
UniFFI Kotlin runtime dependencies used by the generated file: JNA, Kotlin coroutines, and AndroidX annotations.

### Android initialization (required before the first `Marmot(...)`)

`Marmot(...)` constructs the Android-native keyring store, which talks to the Android Keystore over JNI and needs the
`ndk-context` initialized with the application `Context` first. The build copies two hand-written helpers
(`kotlin-support/`) next to the generated binding:

- `dev.ipf.marmotkit.MarmotAndroid` — the call consumers use.
- `io.crates.keyring.Keyring` — the JNI shim the `android-native-keyring-store` crate requires (statically linked into
  `libmarmot_uniffi.so`, so its symbol is exported from that library).

Android consumers MUST call `MarmotAndroid.initialize(this)` from `Application.onCreate` before constructing `Marmot`,
otherwise the first constructor crashes with `android context was not initialized`:

```kotlin
class MarmotApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        MarmotAndroid.initialize(this)
    }
}
```

iOS does not need this — `apple-native-keyring-store` uses Keychain APIs that do not require a `JavaVM`. If the host
framework already initialized `ndk-context`, do not call `initialize` again.

The output directories are ignored because generated bindings and packaged native libraries are derived artifacts.
Regenerate them from this crate before vendoring into an app repository.

See [`AGENTS.md`](AGENTS.md) for scope, invariants, and verification commands.

## Interactive account onboarding

Imported identities can use the durable preflight API instead of `login`:

1. Call `begin_onboarding(nsec, options)` or
   `begin_external_signer_onboarding(public_key, signer, options)`. Supply the
   same `default_relays` as new-account creation and a separate set of trusted
   `discovery_relays`. These methods return a persisted account and snapshot
   before fetching or publishing Nostr records.
2. Display the snapshot steps in their returned order (profile, follows, general
   relays, inbox relays, single-device notice, KeyPackage). Use step identities,
   not enum discriminants, as positions. Subscribe with `subscribe_onboarding`, read its initial
   `snapshot`, and drive `next` concurrently with `run_onboarding`.
3. Localize the typed status, findings, and actions. A healthy account advances
   automatically until the single-device acknowledgment. `NeedsInput` offers a repair or, for profile/follows, an
   explicit `continue_onboarding_without`. Empty follow lists are valid.
4. `propose_onboarding_recommended_relays`, `propose_onboarding_relays`,
   `propose_onboarding_profile`, and `propose_onboarding_follows` only prepare
   a proposal. Profile fields left unset preserve their current values; an
   explicit empty string clears a field. Display the proposed edits, then pass the returned
   snapshot revision to `approve_onboarding_repair`. For an inbox proposal use
   `read_relays` and an empty `write_relays`. `cancel_onboarding_repair` dismisses
   a proposal until approval has been recorded.
5. `retry_onboarding_step` retries a failure; `set_onboarding_discovery_relays`
   retries with explicitly chosen discovery sources without publishing them.
   After process restart, read `onboarding_snapshot`, register the external
   signer again if applicable, and run/resume or retry the indicated step.
6. Enter the normal app only when `snapshot.ready` is true. Normal worker
   commands reject unfinished onboarding; the workflow alone can publish its
   initial KeyPackage. `account_setup_readiness` stays `Initializing` until the
   interactive workflow is complete.

The `SingleDevice` step always pauses before initial KeyPackage publication.
Display a general notice that White Noise does not yet support synchronized
multi-device use and recommends one device. The snapshot's `single_device_notice`
adds evidence with `OtherInstallationPossible`, `NoneFound`, or `Unknown` discovery.
When another installation is possible, explain that invitations may reach only
one installation and conversations will not automatically appear on both.
Reinstallation or cleared local state can produce the same evidence; do not
claim to have identified a physical device or a particular app.

Offer **Cancel** and **Continue anyway**. `CancelOnboarding` means leave the
onboarding view without acknowledging; the account remains persisted and gated.
It does not call sign-out, delete packages, or remove an account. For Continue
anyway, call `acknowledge_onboarding_single_device(account_ref, snapshot.revision)`.
MDK rejects a stale revision, persists the acknowledgment, and resumes setup.
The acknowledgment survives publication failure, cancellation, and restart.
An explicit retry of `SingleDevice`, or a new sign-in after signing out a completed
account, requires a new acknowledgment. Ordinary setup retries preserve it.

Detection reads verified kind-30443 records through the validated relay routes
without starting an account worker. It compares the newest record per slot with
the local stable slot and durably owned private packages, including retained
rotation material. `other_packages` includes original publication and expiration
timestamps. No short recency cutoff excludes an otherwise usable package:
republication retains the original event timestamp, so it is not last-active time.
No public device identifier is introduced, and continuing never deletes another
installation's packages.

`discovery_complete` describes only the bounded queries to the selected sources;
it is false for failed, malformed, future-dated, or potentially truncated results.
Positive evidence can accompany incomplete discovery. `Unknown` means discovery
was inconclusive; `NoneFound` means none were found on those sources. Neither is
an assurance that multi-device use is safe. Both still require the general notice.
Completed pre-notice checkpoints remain ready; incomplete checkpoints acquire
the notice before KeyPackage publication when upgraded.

Snapshots are complete states, not deltas. A slow subscriber may miss
intermediate states but receives the latest persisted state. Cancellation can
leave a step `Checking`; `run_onboarding` resumes it. Once a repair is approved,
a retry resumes that repair before other checks. It cannot be cancelled as if
nothing had been published: a relay may already have accepted it. Signed bytes
are retained before the first send and replayed unchanged on retry.

Discovery reads require a completed relay query. Failed/partial empty discovery
is distinct from absence and never offers automatic replacement. Fresh signed
records remain available for inspection even when their contents are malformed;
a newer malformed record does not silently fall back to an older valid one.
Repairs re-fetch the source before signing and reject a changed record. Nostr
has no conditional replace operation, so simultaneous edits after this check
remain subject to its normal replaceable-event ordering.

Relay checks include syntax, local safety/retirement policy, read/write roles,
and bounded queries through the relevant routes. Inbox queries filter for the
account's recipient tag and use an isolated account-bound signer. They retain no
inbox payloads. Read permission and KeyPackage publication are checked separately;
these checks do not guarantee future availability or every relay's acceptance of
future third-party inbox messages. Incomplete workflows recheck reachability
older than five minutes. Completed onboarding is retained and reruns when a
signed-out account enters the identity-only flow again.

The existing `login` and generated-account APIs remain compatible. Apps must
adopt the new identity-only APIs and screen to enable this experience. Legacy
accounts without an onboarding checkpoint are not retroactively blocked. C
consumers have equivalent methods and subscriptions; external-signer entry
points retain the C API's existing callback-vtable limitation.
