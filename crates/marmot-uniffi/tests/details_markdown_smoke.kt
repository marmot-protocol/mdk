package dev.ipf.marmotkit

fun main() {
    val block = MarkdownBlockFfi.Details(
        summary = listOf(MarkdownInlineFfi.Text("More")),
        open = false,
        body = listOf(MarkdownBlockFfi.Paragraph(listOf(MarkdownInlineFfi.Text("body")))),
        blankLinesBefore = byteArrayOf(1),
    )
    val copy = FfiConverterTypeMarkdownBlockFfi.lift(FfiConverterTypeMarkdownBlockFfi.lower(block))
    check(copy is MarkdownBlockFfi.Details)
    check(copy.summary == block.summary && copy.open == block.open && copy.body == block.body)
    check(copy.blankLinesBefore.contentEquals(block.blankLinesBefore))
    println("Kotlin Markdown Details DTO round trip passed")
}
