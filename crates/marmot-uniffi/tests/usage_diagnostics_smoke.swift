import Foundation
@main
struct UsageSmoke {
    static func main() throws {
        let receipt = UsageDiagnosticsSettingsFfi(decision: .granted, policyRevision: "usage-diagnostics-v1", registryRevision: "mdk-product-v1", updatedAtMs: 123, previouslyEnabled: true)
        let copy = try FfiConverterTypeUsageDiagnosticsSettingsFfi.lift(FfiConverterTypeUsageDiagnosticsSettingsFfi.lower(receipt))
        precondition(copy == receipt)
        let metadata = ProductAnalyticsMetadataFfi(appVersion: "1.0", osFamily: "ios", osMajorVersion: "26", deviceClass: "phone", hostSurface: "native", environment: "staging", isDebug: true)
        let result = try FfiConverterTypeProductAnalyticsMetadataFfi.lift(FfiConverterTypeProductAnalyticsMetadataFfi.lower(metadata))
        precondition(result == metadata)
        let activity = try FfiConverterTypeProductAnalyticsActivityFfi.lift(FfiConverterTypeProductAnalyticsActivityFfi.lower(.foregroundNotification))
        precondition(activity == .foregroundNotification)
        let status = UsageDiagnosticsStatusFfi(consent: .granted, telemetry: .ready, productAnalytics: .unconfigured, queuedEvents: 12, droppedEvents: 23, acceptedBatches: 34, failedBatches: 45)
        let statusCopy = try FfiConverterTypeUsageDiagnosticsStatusFfi.lift(FfiConverterTypeUsageDiagnosticsStatusFfi.lower(status))
        precondition(statusCopy == status)
        print("Swift usage/diagnostics record round trips passed")
    }
}
