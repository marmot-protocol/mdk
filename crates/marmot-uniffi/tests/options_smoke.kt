package dev.ipf.marmotkit

import java.nio.file.Files
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.runBlocking

private class OptionsStore : SecretStore {
    private data class Credential(val label: String, val key: String)

    private val secrets = ConcurrentHashMap<String, Credential>()

    override fun hasSecretForLabel(label: String): Boolean =
        label == "probe" || secrets.values.any { it.label == label }

    override fun hasSecretForAccountId(accountIdHex: String): Boolean = secrets.containsKey(accountIdHex)

    override fun writeSecret(label: String, accountIdHex: String, secretKeyHex: String) {
        secrets[accountIdHex] = Credential(label, secretKeyHex)
    }

    override fun loadSecret(label: String, accountIdHex: String): String =
        secrets[accountIdHex]?.takeIf { it.label == label }?.key
            ?: throw MarmotKitException.SecretNotFound("Missing smoke credential")

    override fun removeSecret(label: String, accountIdHex: String) {
        secrets.remove(accountIdHex)
    }
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
            // The kept experimental alias still opens.
            val experimentalRoot = root.resolve("experimental")
            Marmot.newWithExperimentalDeviceGroups(experimentalRoot.path,
                listOf("ws://127.0.0.1:1"), copy).use { experimental ->
                check(experimental.listAccounts().isEmpty())
            }

            val relay = "ws://127.0.0.1:1"
            kit.start()
            val account = kit.createIdentityWithProfile(listOf(relay), listOf(relay)).account
            val groupOptions = CreateGroupOptionsFfi(
                description = null, initialImage = null, disappearingMessageSecs = 0uL,
            )
            val creation = kit.createGroupWithOptions(account.label, "Founding admins smoke", emptyList(), groupOptions)
            val group = checkNotNull(creation.groupIdHex)
            val creator = kit.groupDetails(account.label, group).members.single()
            check(creator.isSelf && creator.isAdmin)

            val invalidOptions = groupOptions.copy(
                initialAdmins = listOf("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
            )
            try {
                kit.createGroupWithOptions(account.label, "Invalid admin smoke", emptyList(), invalidOptions)
                error("native group creation accepted a nonmember admin")
            } catch (error: MarmotKitException.Runtime) {
                check(error.details == "initial admins must be founding members")
            }
            kit.shutdownAndClose()
        }
    } finally {
        root.deleteRecursively()
    }
    println("Kotlin onboarding diagnostics, runtime options and host-store construction passed")
}
