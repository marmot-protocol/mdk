import Foundation

@main
struct MediaDiagnosticsSmoke {
    static func main() throws {
        let parsed = MediaAttachmentResultFfi.parsed(
            reference: MediaAttachmentReferenceFfi(
                locators: [
                    MediaLocatorFfi(kind: "blossom-v1", value: "https://media.example/aa.bin")
                ],
                ciphertextSha256: String(repeating: "11", count: 32),
                plaintextSha256: String(repeating: "22", count: 32),
                nonceHex: String(repeating: "33", count: 12),
                fileName: "diagram.png",
                mediaType: "image/png",
                version: .v1,
                sourceEpoch: 7,
                dim: nil,
                thumbhash: nil
            )
        )
        let rejected = MediaAttachmentResultFfi.rejected(
            diagnostic: MediaDiagnosticFfi(
                stage: .metadata,
                code: .missingField,
                field: .nonce,
                message: "media attachment is missing nonce"
            )
        )
        let indexed = MediaAttachmentProjectionFfi(attachmentIndex: 1, result: parsed)
        let container = MediaAttachmentProjectionFfi(attachmentIndex: nil, result: rejected)

        let parsedCopy = try FfiConverterTypeMediaAttachmentResultFfi.lift(
            FfiConverterTypeMediaAttachmentResultFfi.lower(parsed)
        )
        let rejectedCopy = try FfiConverterTypeMediaAttachmentResultFfi.lift(
            FfiConverterTypeMediaAttachmentResultFfi.lower(rejected)
        )
        let indexedCopy = try FfiConverterTypeMediaAttachmentProjectionFfi.lift(
            FfiConverterTypeMediaAttachmentProjectionFfi.lower(indexed)
        )
        let containerCopy = try FfiConverterTypeMediaAttachmentProjectionFfi.lift(
            FfiConverterTypeMediaAttachmentProjectionFfi.lower(container)
        )
        precondition(parsedCopy == parsed)
        precondition(rejectedCopy == rejected)
        precondition(indexedCopy == indexed)
        precondition(containerCopy.attachmentIndex == nil)

        for code in [
            MediaErrorCodeFfi.invalidStructure,
            .missingField,
            .duplicateField,
            .malformedField,
            .unsupportedVersion,
            .unsupportedFormat,
            .profileMismatch,
            .destinationPolicy,
            .noSupportedLocator,
            .downloadFailed,
            .decryptionFailed,
            .integrityMismatch,
        ] {
            let diagnostic = MediaDiagnosticFfi(
                stage: .fetch,
                code: code,
                field: .locator,
                message: "library owned"
            )
            let copy = try FfiConverterTypeMediaDiagnosticFfi.lift(
                FfiConverterTypeMediaDiagnosticFfi.lower(diagnostic)
            )
            precondition(copy == diagnostic)
        }

        do {
            _ = try parseMediaImetaTag(
                tag: MessageTagFfi(values: ["imeta", "v encrypted-media-v1"]),
                sourceEpoch: 1
            )
            preconditionFailure("incomplete imeta must reject")
        } catch MarmotKitError.MediaAttachment(let diagnostic) {
            precondition(diagnostic.code == .missingField)
        }

        print("Swift media diagnostic DTO round trip passed")
    }
}
