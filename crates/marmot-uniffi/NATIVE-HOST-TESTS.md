# Run native-host tests without a platform keychain

Run the generated Swift binding against a local relay and synthetic accounts:

```bash
bash crates/marmot-uniffi/native-host-smoke.sh
```

Run from the repository root on macOS or Linux with the repository's Rust toolchain, Swift with SwiftPM/XCTest, and the native build dependencies described in [building local bindings](README.md#building-local-bindings). This is a source-checkout test, not an XCFramework or Android release-artifact validator.

The existing `ios-account-clippy` job in [CI](../../.github/workflows/ci.yml) runs this XCTest on macOS alongside the Swift subscription-cancellation smoke.

The script builds the debug native library, binding generator, and relay example with `--features cli`, without test-policy timing overrides. It generates Swift from that library and stages a temporary SwiftPM package: `MarmotKit` contains `marmot_uniffi.swift`, the `marmot_uniffiFFI` system-library target contains the generated header and module map renamed to `module.modulemap`, and the test target imports `MarmotKit` and XCTest. Native link flags and the library search environment point at the matching debug library. Generated files stay out of the checkout.

[`examples/native-host-relay.rs`](examples/native-host-relay.rs) uses the existing `nostr_relay_builder::MockRelay`, binds a local WebSocket endpoint, and launches the supplied test command with `MDK_SMOKE_RELAY_URL` set to that endpoint. It waits for the child, shuts down the relay, and propagates failures. No public relay or production credential is needed. Initial dependency downloads can still require network access.

## Use the checked Swift test

[`tests/native_host_smoke.swift`](tests/native_host_smoke.swift) is the runnable recipe, including the store, configuration, bounded waits, assertions, and teardown. Keep host adaptations based on that source rather than copying an independent lifecycle example. [`tests/runtime_threads.rs`](tests/runtime_threads.rs) is the existing Rust fixture for the same MockRelay/injected-store approach and separately checks runtime thread ownership and file closure; it does not execute generated Swift.

The Swift test follows this sequence:

1. Create a unique task-owned directory under the host-provided temporary directory, using its canonical path and private directory permissions. Give Alice and Bob separate roots and separate in-memory stores.
2. Construct each runtime with `Marmot.newWithConfiguration`, `relayUrls: [relay]`, and `MarmotOptions(relayPolicy: .allowLoopback, secretStore: store, deployment: marmotDeploymentNeutral())`. The neutral deployment avoids deployment-provided public services. Loopback access is an explicit development opt-in, not a production default.
3. Start both runtimes and generate synthetic identities with `createIdentityWithProfile(defaultRelays: [relay], bootstrapRelays: [relay], inboxRelays: [relay])`. Set every runtime default, account default, bootstrap, and inbox relay list explicitly. An empty bootstrap list is not an offline switch.
4. Wait for `accountSetupReadiness(accountRef:) == .networkReady` for both accounts. `.localReady` means durable local setup, not completed relay-list and initial KeyPackage publication. Fail on `.recoveryRequired`. `start().totalRelays` describes the relay-pool snapshot at startup; it is not an account-setup barrier, and a zero count before account creation does not establish failure.
5. Create the group, wait until Bob's chat list contains that exact group, and accept the invite. After sending text, wait until Bob's stored messages contain the expected decrypted plaintext and Alice's sender identity. A returned group ID or successful send alone does not establish Welcome or message delivery. The checked source uses 30-second stage deadlines and a 180-second watchdog for a stuck native call.
6. Await Alice's `shutdownAndClose()` before opening the same root with the same retained store. Check the account identity and send another message through the reopened runtime, then observe delivery at Bob. Close every runtime before deleting its root, including on failure.

### Keep secret storage alive with its root

The test's `MemorySecretStore` keeps plaintext secret-key hex only in memory. It protects every callback with `NSLock`; `@unchecked Sendable` alone would not make the dictionary safe. Callbacks may run concurrently on native worker threads and must not wait for the UI thread. The callback boundary passes plaintext keys in both directions; it provides no encryption or OS credential protection.

Retain the store for the whole test, including same-root reopening. The encrypted account files and the signing keys are separate state. The same root plus the retained store preserves usable keys; a fresh empty store requires a fresh test root. Opening persisted files with an empty replacement store does not recover the account's credentials. Do not use real imported identities or production account directories in this recipe.

### Keep the host filesystem and keychain boundaries separate

Derive test roots from a host-authorized directory URL, then create a unique owned child. In an Apple app, use the appropriate sandbox or App Group container supplied by platform APIs. Canonicalization is for the host-authorized path, not permission to accept arbitrary raw paths or resolve untrusted symlinks into trusted storage.

The Apple constructor path depends on the existing [`fs-private` directory preparation](../fs-private/src/lib.rs): it opens a complete authorized path, or its deepest complete existing ancestor, with `O_NOFOLLOW_ANY`, then creates descendants relative to that descriptor. It avoids separately opening sandbox-managed ancestors while retaining no-symlink and traversal checks. This filesystem prerequisite applies even when a secret store is injected; replacing the store cannot repair a filesystem authorization failure. Do not bypass path checks to make a test pass.

Platform-keychain integration is a separate test boundary. A host using the platform store still needs appropriate signing, entitlements, and keychain access configuration for its platform and deployment. An injected test store neither grants those permissions nor demonstrates that platform-keychain access works. Keep such integration tests in a suitably configured app/test host.

## Configure an Android host test

Use the matching generated Kotlin and native library. Android must call `MarmotAndroid.initialize(context)` before constructing `Marmot`, including when a test injects its own store. See [Kotlin / Android](README.md#kotlin--android) for packaging and JNI setup. The local relay must be reachable from the Android test process; emulator loopback is not the development machine's loopback. `MDK_SMOKE_RELAY_URL` is supplied to the desktop child process, not automatically to a device.

This test-only store implements the generated callback signatures. The methods synchronize on one monitor, key credentials by account ID, and retain the label for lookup:

```kotlin
import dev.ipf.marmotkit.*

private class MemorySecretStore : SecretStore {
    private data class Credential(val label: String, val secret: String)
    private val credentials = mutableMapOf<String, Credential>()

    @Synchronized
    override fun hasSecretForLabel(label: String): Boolean =
        credentials.values.any { it.label == label }

    @Synchronized
    override fun hasSecretForAccountId(accountIdHex: String): Boolean =
        credentials.containsKey(accountIdHex)

    @Synchronized
    override fun writeSecret(label: String, accountIdHex: String, secretKeyHex: String) {
        credentials[accountIdHex] = Credential(label, secretKeyHex)
    }

    @Synchronized
    override fun loadSecret(label: String, accountIdHex: String): String {
        val credential = credentials[accountIdHex]
        if (credential == null || credential.label != label) {
            throw MarmotKitException.SecretNotFound("Synthetic test credential missing")
        }
        return credential.secret
    }

    @Synchronized
    override fun removeSecret(label: String, accountIdHex: String) {
        credentials.remove(accountIdHex)
    }
}
```

In an Android test's suspending setup, use this configuration. `context` is the Android test host's authorized context, `root` is a unique test-owned directory beneath its private storage, and `relay` is the reachable MockRelay WebSocket URL:

```kotlin
MarmotAndroid.initialize(context)
val store = MemorySecretStore()
val kit = Marmot.newWithConfiguration(
    rootPath = root.canonicalPath,
    relayUrls = listOf(relay),
    options = MarmotOptions(
        relayPolicy = RelayPolicyFfi.ALLOW_LOOPBACK,
        secretStore = store,
        deployment = marmotDeploymentNeutral(),
    ),
)
kit.start()
val identity = kit.createIdentityWithProfile(
    defaultRelays = listOf(relay),
    bootstrapRelays = listOf(relay),
    inboxRelays = listOf(relay),
)
```

Apply the Swift test's readiness, recipient-delivery, bounded-wait, and teardown sequence to the Android assertions. Kotlin uses `accountSetupReadiness(accountRef)` and `AccountSetupReadinessFfi.NETWORK_READY`; retain `store` across reopening and await `shutdownAndClose()` before constructing another runtime on `root`. Put shutdown in test teardown or `finally`, before deleting the directory. The Kotlin snippets describe configuration and callbacks; the shell command above runs the checked Swift XCTest, not an Android instrumentation suite.
