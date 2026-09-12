package dev.ipf.marmotkit

fun main() {
    val parsed = MediaAttachmentResultFfi.Parsed(
        reference = MediaAttachmentReferenceFfi(
            locators = listOf(MediaLocatorFfi("blossom-v1", "https://media.example/aa.bin")),
            ciphertextSha256 = "11".repeat(32),
            plaintextSha256 = "22".repeat(32),
            nonceHex = "33".repeat(12),
            fileName = "diagram.png",
            mediaType = "image/png",
            version = EncryptedMediaVersionFfi.V1,
            sourceEpoch = 7u,
            dim = null,
            thumbhash = null,
        ),
    )
    val rejected = MediaAttachmentResultFfi.Rejected(
        diagnostic = MediaDiagnosticFfi(
            stage = MediaErrorStageFfi.METADATA,
            code = MediaErrorCodeFfi.MISSING_FIELD,
            field = MediaErrorFieldFfi.NONCE,
            message = "media attachment is missing nonce",
        ),
    )
    val indexed = MediaAttachmentProjectionFfi(1u, parsed)
    val container = MediaAttachmentProjectionFfi(null, rejected)

    val parsedCopy = FfiConverterTypeMediaAttachmentResultFfi.lift(
        FfiConverterTypeMediaAttachmentResultFfi.lower(parsed),
    )
    val rejectedCopy = FfiConverterTypeMediaAttachmentResultFfi.lift(
        FfiConverterTypeMediaAttachmentResultFfi.lower(rejected),
    )
    val indexedCopy = FfiConverterTypeMediaAttachmentProjectionFfi.lift(
        FfiConverterTypeMediaAttachmentProjectionFfi.lower(indexed),
    )
    val containerCopy = FfiConverterTypeMediaAttachmentProjectionFfi.lift(
        FfiConverterTypeMediaAttachmentProjectionFfi.lower(container),
    )
    check(parsedCopy == parsed)
    check(rejectedCopy == rejected)
    check(indexedCopy == indexed)
    check(containerCopy.attachmentIndex == null)

    for (code in MediaErrorCodeFfi.values()) {
        val diagnostic = MediaDiagnosticFfi(
            stage = MediaErrorStageFfi.FETCH,
            code = code,
            field = MediaErrorFieldFfi.LOCATOR,
            message = "library owned",
        )
        val copy = FfiConverterTypeMediaDiagnosticFfi.lift(
            FfiConverterTypeMediaDiagnosticFfi.lower(diagnostic),
        )
        check(copy == diagnostic)
    }

    try {
        parseMediaImetaTag(MessageTagFfi(listOf("imeta", "v encrypted-media-v1")), 1u)
        error("incomplete imeta must reject")
    } catch (error: MarmotKitError.MediaAttachment) {
        check(error.diagnostic.code == MediaErrorCodeFfi.MISSING_FIELD)
    }

    println("Kotlin media diagnostic DTO round trip passed")
}
