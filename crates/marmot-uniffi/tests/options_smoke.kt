package dev.ipf.marmotkit

import java.nio.file.Files
import kotlinx.coroutines.runBlocking

private class OptionsStore : SecretStore {
    override fun hasSecretForLabel(label: String): Boolean = label == "probe"
    override fun hasSecretForAccountId(accountIdHex: String): Boolean = false
    override fun writeSecret(label: String, accountIdHex: String, secretKeyHex: String) {}
    override fun loadSecret(label: String, accountIdHex: String): String = "callback-probe"
    override fun removeSecret(label: String, accountIdHex: String) {}
}

fun main(args: Array<String>) = runBlocking {
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
            kit.nip46New("{\"relays\":[\"ws://127.0.0.1:1\"],\"name\":\"Kotlin permissions\"}").use { session ->
                check(session.status().state == Nip46StateFfi.PERMISSION_APPROVAL)
                try {
                    session.uri()
                    error("unapproved session exposed a pairing URI")
                } catch (error: Nip46ErrorFfi.PermissionApprovalRequired) {
                }
                val reviewed = session.reviewPermissions()
                session.approvePermissions(reviewed.version, reviewed.grants)
                check(session.uri().startsWith("nostrconnect://"))
                try {
                    session.cancelRequest("stale")
                    error("stale request cancellation succeeded")
                } catch (error: Nip46ErrorFfi.RequestNotFound) {
                }
                session.disconnect()
                check(session.status().state == Nip46StateFfi.DISCONNECTED)
                session.cancel()
                check(session.status().state == Nip46StateFfi.CANCELLED)
            }
            val experimentalRoot = root.resolve("experimental")
            if (args.contains("--dev-device-groups")) {
                Marmot.newWithExperimentalDeviceGroups(experimentalRoot.path,
                    listOf("ws://127.0.0.1:1"), copy).use { experimental ->
                    check(experimental.listAccounts().isEmpty())
                }
            } else {
                try {
                    Marmot.newWithExperimentalDeviceGroups(experimentalRoot.path, emptyList(), copy).close()
                    error("default native library accepted experimental construction")
                } catch (error: MarmotKitException.Runtime) {
                    check(error.details == "experimental_device_groups_unavailable")
                    check(!experimentalRoot.exists())
                }
            }
        }
    } finally {
        root.deleteRecursively()
    }
    println("Kotlin onboarding diagnostics, runtime options and host-store construction passed")
}
