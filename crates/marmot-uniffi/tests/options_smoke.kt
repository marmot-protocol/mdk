package dev.ipf.marmotkit

import java.nio.file.Files

private class OptionsStore : SecretStore {
    override fun hasSecretForLabel(label: String): Boolean = label == "probe"
    override fun hasSecretForAccountId(accountIdHex: String): Boolean = false
    override fun writeSecret(label: String, accountIdHex: String, secretKeyHex: String) {}
    override fun loadSecret(label: String, accountIdHex: String): String = "callback-probe"
    override fun removeSecret(label: String, accountIdHex: String) {}
}

fun main() {
    val findings = listOf(
        OnboardingFindingFfi(OnboardingIssueFfi.TIMED_OUT, "wss://example.com",
            OnboardingFindingContextFfi.RECORD_DISCOVERY, OnboardingCheckPurposeFfi.RECORD_LOOKUP,
            OnboardingCheckOutcomeFfi.UNKNOWN, OnboardingRelayCapabilityFfi.NONE,
            listOf(OnboardingActionFfi.RETRY), 7uL),
        OnboardingFindingFfi(OnboardingIssueFfi.TIMED_OUT, "wss://example.com",
            OnboardingFindingContextFfi.DECLARED_ROUTE, OnboardingCheckPurposeFfi.DIRECTORY_QUERY,
            OnboardingCheckOutcomeFfi.UNKNOWN, OnboardingRelayCapabilityFfi.WRITE,
            listOf(OnboardingActionFfi.RETRY), 7uL),
        OnboardingFindingFfi(OnboardingIssueFfi.INSPECTION_COMPLETED, "wss://read.example.com",
            OnboardingFindingContextFfi.DECLARED_ROUTE, OnboardingCheckPurposeFfi.DIRECTORY_QUERY,
            OnboardingCheckOutcomeFfi.SUCCESS, OnboardingRelayCapabilityFfi.READ,
            emptyList(), 7uL),
    )
    for (finding in findings) {
        val diagnostic = FfiConverterTypeOnboardingFindingFfi.lift(FfiConverterTypeOnboardingFindingFfi.lower(finding))
        check(diagnostic == finding)
    }
    // The deployment is the one required field.
    val defaults = MarmotOptions(deployment = marmotDeploymentNeutral())
    check(defaults.relayPolicy == null && defaults.cursorPersistence == null)
    check(defaults.clientName == null && defaults.secretStore == null)
    check(defaults.deployment.keychainService == "org.marmot-protocol.mdk")
    val options = MarmotOptions(
        relayPolicy = RelayPolicyFfi.ALLOW_LOOPBACK_RELAYS_AND_BLOBS,
        cursorPersistence = CursorPersistenceFfi.FROZEN,
        clientName = "whitenoise",
        deployment = marmotDeploymentWhiteNoise(),
    )
    val copy = FfiConverterTypeMarmotOptions.lift(FfiConverterTypeMarmotOptions.lower(options))
    check(copy.relayPolicy == options.relayPolicy && copy.cursorPersistence == options.cursorPersistence)
    check(copy.clientName == "whitenoise")
    check(copy.deployment.keychainService == "com.marmot.whitenoise")
    // Foreign callbacks are lowered into Rust by the constructor, not locally lifted.
    copy.secretStore = OptionsStore()
    val root = Files.createTempDirectory("marmot-options-").toFile()
    try {
        Marmot.newWithConfiguration(root.path, listOf("ws://127.0.0.1:1"), copy).use { kit ->
            check(kit.listAccounts().isEmpty())
        }
    } finally {
        root.deleteRecursively()
    }
    println("Kotlin onboarding diagnostics, runtime options and host-store construction passed")
}
