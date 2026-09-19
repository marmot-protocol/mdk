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
    val defaults = MarmotOptions()
    check(defaults.relayPolicy == null && defaults.cursorPersistence == null)
    check(defaults.clientName == null && defaults.secretStore == null)
    val options = MarmotOptions(
        relayPolicy = RelayPolicyFfi.ALLOW_LOOPBACK_RELAYS_AND_BLOBS,
        cursorPersistence = CursorPersistenceFfi.FROZEN,
        clientName = "whitenoise",
    )
    val copy = FfiConverterTypeMarmotOptions.lift(FfiConverterTypeMarmotOptions.lower(options))
    check(copy.relayPolicy == options.relayPolicy && copy.cursorPersistence == options.cursorPersistence)
    check(copy.clientName == "whitenoise")
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
    println("Kotlin runtime options defaults and host-store construction passed")
}
