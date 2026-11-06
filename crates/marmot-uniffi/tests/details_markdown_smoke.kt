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
    val authoredLabel = "bücher.de"
    val destination = "https://xn--bcher-kva.de"
    val paragraph = MarkdownBlockFfi.Paragraph(listOf(
        MarkdownInlineFfi.Link(
            dest = destination,
            title = null,
            children = listOf(MarkdownInlineFfi.Text(authoredLabel)),
            classification = MarkdownLinkDestinationKindFfi.WEB,
        ),
        MarkdownInlineFfi.Text(" README.md archive.zip report.pdf"),
    ))
    val paragraphCopy = FfiConverterTypeMarkdownBlockFfi.lift(
        FfiConverterTypeMarkdownBlockFfi.lower(paragraph)
    )
    check(paragraphCopy is MarkdownBlockFfi.Paragraph)
    val link = paragraphCopy.inlines[0]
    check(link is MarkdownInlineFfi.Link)
    check(link.dest == destination && link.classification == MarkdownLinkDestinationKindFfi.WEB)
    check(link.children == listOf(MarkdownInlineFfi.Text(authoredLabel)))
    check(paragraphCopy.inlines.size == 2)
    check(paragraphCopy.inlines[1] == MarkdownInlineFfi.Text(" README.md archive.zip report.pdf"))
    println("Kotlin Markdown Details and inferred-domain DTO round trips passed")
}
