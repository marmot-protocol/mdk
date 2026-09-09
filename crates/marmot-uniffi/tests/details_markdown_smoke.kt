package dev.ipf.marmotkit

fun main() {
    val block = MarkdownBlockFfi.Details(
        summary = listOf(MarkdownInlineFfi.Text("More")),
        open = false,
        body = listOf(MarkdownBlockFfi.Paragraph(listOf(MarkdownInlineFfi.Text("body")))),
        blankLinesBefore = listOf(1.toUByte()),
    )
    val copy = FfiConverterTypeMarkdownBlockFfi.lift(FfiConverterTypeMarkdownBlockFfi.lower(block))
    check(copy == block)
    println("Kotlin Markdown Details DTO round trip passed")
}
