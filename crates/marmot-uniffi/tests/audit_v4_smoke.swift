import Foundation

@main
struct AuditV4Smoke {
    static func main() throws {
        // V3 generated bindings expect this checksum and must reject this library.
        precondition(uniffi_marmot_uniffi_checksum_method_marmot_set_audit_log_tracker_config() != 61397)
        for model: String? in ["iPhone17,3", nil] {
            let source = AuditLogUploadSourceV4Ffi(
                hardwareModel: model, platform: "ios", appVersion: "test"
            )
            let copy = try FfiConverterTypeAuditLogUploadSourceV4Ffi.lift(
                FfiConverterTypeAuditLogUploadSourceV4Ffi.lower(source)
            )
            precondition(copy == source)
        }
        print("Swift audit v4 metadata round trip passed")
    }
}
