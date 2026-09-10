import Foundation

@main
struct AuditV4Smoke {
    static func main() throws {
        // UniFFI 0.29.4 generated V3 bindings at MDK c1289eed expect 61397 for
        // set_audit_log_tracker_config. They must reject this library rather
        // than silently treating their deviceLabel bytes as hardwareModel.
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
