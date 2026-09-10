import Foundation

@main
struct DetailsMarkdownSmoke {
    static func main() throws {
        let block = MarkdownBlockFfi.details(
            summary: [MarkdownInlineFfi.text(content: "More")],
            open: false,
            body: [MarkdownBlockFfi.paragraph(inlines: [MarkdownInlineFfi.text(content: "body")])],
            blankLinesBefore: Data([1])
        )
        let copy = try FfiConverterTypeMarkdownBlockFfi.lift(FfiConverterTypeMarkdownBlockFfi.lower(block))
        precondition(copy == block)
        print("Swift Markdown Details DTO round trip passed")
    }
}
