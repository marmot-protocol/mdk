package dev.ipf.marmotkit

fun main() {
    for (model in listOf("Pixel 9a", null)) {
        val source = AuditLogUploadSourceV4Ffi(
            hardwareModel = model, platform = "android", appVersion = "test",
        )
        val copy = FfiConverterTypeAuditLogUploadSourceV4Ffi.lift(
            FfiConverterTypeAuditLogUploadSourceV4Ffi.lower(source)
        )
        check(copy == source)
    }
    println("Kotlin audit v4 metadata round trip passed")
}
