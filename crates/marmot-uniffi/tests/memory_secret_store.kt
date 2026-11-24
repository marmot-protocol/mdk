package dev.ipf.marmotkit

// Test-only plaintext memory vault. Retain this instance across root reopening.
internal class MemorySecretStore : SecretStore {
    private data class Receipt(
        val record: SecretCredential,
        var secret: String?,
        val origin: SecretOrigin,
        var release: SecretReleaseMode? = null,
    )

    private val namespace = java.util.UUID.randomUUID().toString()
    private val receipts = mutableListOf<Receipt>()

    override fun cleanupNamespace(): String = namespace

    private fun sameSlot(a: SecretCredential, b: SecretCredential): Boolean =
        a.kind == b.kind && a.accountIdHex == b.accountIdHex &&
            (a.kind == SecretCredentialKind.SIGNING || a.homeId == b.homeId)

    private fun conflict(): Nothing =
        throw MarmotKitException.Runtime("In-memory credential ownership conflict")

    private fun missing(): Nothing =
        throw MarmotKitException.SecretNotFound("In-memory credential missing")

    @Synchronized
    override fun hasSecretForLabel(label: String): Boolean =
        receipts.any { it.record.kind == SecretCredentialKind.SIGNING &&
            it.record.label == label && it.secret != null }

    @Synchronized
    override fun hasSecretForAccountId(accountIdHex: String): Boolean =
        receipts.any { it.record.kind == SecretCredentialKind.SIGNING &&
            it.record.accountIdHex == accountIdHex && it.secret != null }

    @Synchronized
    override fun acquireSecret(record: SecretCredential, mode: SecretClaimMode,
        proposedHex: String?): AcquiredSecret {
        val prior = receipts.find { it.record.ownerId == record.ownerId }
        if (prior != null) {
            if (prior.record != record || prior.release != null) { conflict() }
            val secret = prior.secret ?: missing()
            if (proposedHex != null && proposedHex != secret) { conflict() }
            return AcquiredSecret(secret, prior.origin)
        }
        val source = receipts.find { sameSlot(it.record, record) && it.secret != null }
        if (mode == SecretClaimMode.CREATE_ONLY && (source != null || proposedHex == null)) { conflict() }
        if ((mode == SecretClaimMode.ADOPT_ONLY || mode == SecretClaimMode.MIGRATE_LEGACY) && source == null) { missing() }
        val secret = source?.secret ?: proposedHex ?: missing()
        if (proposedHex != null && proposedHex != secret) { conflict() }
        if (secret.length != 64 || !secret.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) { conflict() }
        val origin = if (source == null) { SecretOrigin.CREATED } else { SecretOrigin.EXISTING }
        receipts.add(Receipt(record, secret, origin))
        for (entry in receipts) {
            if (sameSlot(entry.record, record) && entry.release == SecretReleaseMode.PRESERVE) {
                entry.secret = null
            }
        }
        return AcquiredSecret(secret, origin)
    }

    @Synchronized
    override fun loadSecret(record: SecretCredential): String =
        receipts.find { it.record == record && it.release == null }?.secret ?: missing()

    @Synchronized
    override fun releaseSecret(record: SecretCredential, mode: SecretReleaseMode): SecretReleaseOutcome {
        val prior = receipts.find { it.record.ownerId == record.ownerId }
        if (prior != null) {
            if (prior.record != record) { conflict() }
            if (prior.release == null) {
                prior.release = mode
                if (mode == SecretReleaseMode.DELETE_IF_UNOWNED) { prior.secret = null }
            }
        } else {
            receipts.add(Receipt(record, null, SecretOrigin.EXISTING, mode))
        }
        return SecretReleaseOutcome.RELEASED
    }

    @Synchronized
    override fun reconcileCleanup() {
        for (entry in receipts) {
            if (entry.release == SecretReleaseMode.DELETE_IF_UNOWNED) { entry.secret = null }
        }
    }
}
