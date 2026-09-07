package dev.ipf.marmotkit
fun main() {
    val receipt = UsageDiagnosticsSettingsFfi(UsageDiagnosticsDecisionFfi.GRANTED, "policy", "registry", 123, true)
    check(FfiConverterTypeUsageDiagnosticsSettingsFfi.lift(FfiConverterTypeUsageDiagnosticsSettingsFfi.lower(receipt)) == receipt)
    val metadata = ProductAnalyticsMetadataFfi("1.0", "android", "16", "phone", "native", "staging", true)
    check(FfiConverterTypeProductAnalyticsMetadataFfi.lift(FfiConverterTypeProductAnalyticsMetadataFfi.lower(metadata)) == metadata)
    val status = UsageDiagnosticsStatusFfi(UsageDiagnosticsDecisionFfi.GRANTED, DiagnosticsExporterStatusFfi.READY, DiagnosticsExporterStatusFfi.UNCONFIGURED, 12uL, 23uL, 34uL, 45uL)
    check(FfiConverterTypeUsageDiagnosticsStatusFfi.lift(FfiConverterTypeUsageDiagnosticsStatusFfi.lower(status)) == status)
    println("Kotlin usage/diagnostics record round trips passed")
}
