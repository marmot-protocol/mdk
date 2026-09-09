//! Reviewer-required disclosure regressions (fallback, multiline, bounds).

use marmot_markdown::{Block, Inline, parse};

mod common;
use common::{code, paragraph, t};

fn texts(doc: &marmot_markdown::Document) -> String {
    fn walk_blocks(blocks: &[Block], out: &mut String) {
        for block in blocks {
            match block {
                Block::Paragraph { inlines } | Block::Heading { inlines, .. } => {
                    walk_inlines(inlines, out);
                }
                Block::BlockQuote { blocks, .. } => walk_blocks(blocks, out),
                Block::List { items, .. } => {
                    for item in items {
                        walk_blocks(&item.blocks, out);
                    }
                }
                Block::Details { summary, body, .. } => {
                    walk_inlines(summary, out);
                    walk_blocks(body, out);
                }
                Block::CodeBlock { content, .. } | Block::MathBlock { content } => {
                    out.push_str(content);
                }
                Block::Table { header, rows, .. } => {
                    for cell in header.iter().chain(rows.iter().flatten()) {
                        walk_inlines(&cell.inlines, out);
                    }
                }
                Block::ThematicBreak => {}
            }
            out.push('\n');
        }
    }
    fn walk_inlines(inlines: &[Inline], out: &mut String) {
        for inline in inlines {
            match inline {
                Inline::Text(s) | Inline::Code(s) => out.push_str(s),
                Inline::Emph(c) | Inline::Strong(c) | Inline::Strikethrough(c) => {
                    walk_inlines(c, out);
                }
                Inline::Link { children, .. } => walk_inlines(children, out),
                Inline::SoftBreak | Inline::HardBreak => out.push('\n'),
                Inline::Image { alt, .. } => walk_inlines(alt, out),
                Inline::Autolink { url, .. } => out.push_str(url),
                Inline::Math(s) => out.push_str(s),
                Inline::NostrMention(entity) | Inline::NostrUri(entity) => {
                    out.push_str(&entity.bech32);
                }
            }
        }
    }
    let mut out = String::new();
    walk_blocks(&doc.blocks, &mut out);
    out
}

fn has_details(doc: &marmot_markdown::Document) -> bool {
    fn walk(blocks: &[Block]) -> bool {
        blocks.iter().any(|block| match block {
            Block::Details { .. } => true,
            Block::BlockQuote { blocks, .. } => walk(blocks),
            Block::List { items, .. } => items.iter().any(|item| walk(&item.blocks)),
            _ => false,
        })
    }
    walk(&doc.blocks)
}

#[test]
fn eof_fallback_preserves_completed_summary() {
    let doc = parse("<details>\n<summary>KEEP_THIS_SUMMARY</summary>\nbody");
    assert!(!has_details(&doc));
    assert_eq!(doc.blocks[0], paragraph("<details>"));
    assert!(
        texts(&doc).contains("KEEP_THIS_SUMMARY"),
        "completed summary must survive EOF fallback: {doc:?}"
    );
    assert!(texts(&doc).contains("<summary>"));
    assert!(texts(&doc).contains("</summary>"));
    assert_eq!(doc.blocks.last(), Some(&paragraph("body")));
}

#[test]
fn container_loss_preserves_completed_summary() {
    let doc = parse("> <details>\n> <summary>KEEP **THIS**</summary>\n> body\n</details>\n# After");
    assert!(!has_details(&doc));
    let Block::BlockQuote { blocks, .. } = &doc.blocks[0] else {
        panic!("quote");
    };
    assert!(
        texts(&doc).contains("KEEP"),
        "quoted fallback must keep the completed summary: {doc:?}"
    );
    assert!(
        blocks.iter().any(|block| match block {
            Block::Paragraph { inlines } => inlines.iter().any(|inline| matches!(
                inline,
                Inline::Text(s) if s.contains("<summary>")
            )),
            _ => false,
        }),
        "summary delimiters must remain literal: {blocks:?}"
    );
    assert!(blocks.iter().any(|block| {
        match block {
            Block::Paragraph { inlines } => inlines
                .iter()
                .any(|inline| matches!(inline, Inline::Strong(_))),
            _ => false,
        }
    }));
    assert_eq!(doc.blocks.last(), Some(&common::heading(1, "After")));
}

#[test]
fn scan_refusal_preserves_completed_summary() {
    let header = "<details>\n<summary>KEEP_THIS_SUMMARY</summary>\n";
    let pad = 65_536_usize.saturating_sub(header.len());
    let md = format!("{header}{}</details>\n# After", "y".repeat(pad));
    let doc = parse(&md);
    assert!(!has_details(&doc), "closer past the window must not commit");
    assert!(
        texts(&doc).contains("KEEP_THIS_SUMMARY"),
        "scan-refused fallback must keep the completed summary"
    );
    assert!(texts(&doc).contains("<summary>"));
    assert_eq!(doc.blocks.last(), Some(&common::heading(1, "After")));
}

#[test]
fn summary_accepts_three_consecutive_lines() {
    let (_, summary, body, _) = {
        let doc = parse("<details>\n<summary>\nMore **information**\n</summary>\nbody\n</details>");
        match &doc.blocks[0] {
            Block::Details { summary, body, .. } => (true, summary.clone(), body.clone(), ()),
            other => panic!("expected Details, got {other:?}"),
        }
    };
    assert!(
        summary
            .iter()
            .any(|inline| matches!(inline, Inline::Strong(_)))
    );
    assert!(
        texts(&marmot_markdown::Document {
            blocks: vec![Block::Paragraph {
                inlines: summary.clone()
            }],
            blank_lines_before: vec![0],
        })
        .contains("More")
    );
    assert_eq!(body, vec![paragraph("body")]);
}

#[test]
fn summary_code_spans_can_cross_a_line() {
    let doc =
        parse("<details>\n<summary>use `literal\n</summary>` here</summary>\nbody\n</details>");
    let Block::Details { summary, .. } = &doc.blocks[0] else {
        panic!("expected Details, got {doc:?}");
    };
    assert_eq!(
        summary,
        &[t("use "), code("literal </summary>"), t(" here"),]
    );
}

#[test]
fn indented_code_before_summary_prevents_extraction() {
    let doc =
        parse("<details>\n    code\n<summary>ordinary later text</summary>\nbody\n</details>");
    let Block::Details { summary, body, .. } = &doc.blocks[0] else {
        panic!("expected Details, got {doc:?}");
    };
    assert!(
        summary.is_empty(),
        "later summary must not be promoted: {summary:?}"
    );
    assert!(
        body.iter().any(|block| match block {
            Block::CodeBlock { content, .. } => content.contains("code"),
            _ => false,
        }),
        "indented code must start the body: {body:?}"
    );
    assert!(
        body.iter().any(|block| match block {
            Block::Paragraph { inlines } => inlines.iter().any(|inline| matches!(
                inline,
                Inline::Text(s) if s.contains("<summary>ordinary later text</summary>")
            )),
            _ => false,
        }),
        "later summary stays literal body text: {body:?}"
    );
}

#[test]
fn fallback_preserves_summary_mention_and_gaps() {
    let npub = format!("npub1{}", "q".repeat(52));
    let doc = parse(&format!(
        "<details>\n<summary>see @{npub} **now**</summary>\n\nbody\n"
    ));
    assert!(!has_details(&doc));
    assert_eq!(doc.blank_lines_before[0], 0);
    assert!(
        texts(&doc).contains(&npub),
        "summary mention must survive fallback: {doc:?}"
    );
    assert!(texts(&doc).contains("now"));
    assert_eq!(doc.blocks.last(), Some(&paragraph("body")));
}

#[test]
fn summary_crossing_scan_boundary_stays_literal() {
    let header = "<details>\n<summary>";
    let pad = 65_536_usize.saturating_sub(header.len()) + 8;
    let md = format!(
        "{header}{}KEEP</summary>\nbody\n</details>",
        "z".repeat(pad)
    );
    let doc = parse(&md);
    assert!(!has_details(&doc));
    assert!(texts(&doc).contains("KEEP"));
    assert!(texts(&doc).contains("<summary>"));
    assert!(texts(&doc).contains("body"));
}

#[test]
fn blank_interrupted_summary_falls_back() {
    let doc = parse("<details>\n<summary>\n\nMore\n</summary>\nbody\n</details>");
    assert!(!has_details(&doc));
    assert!(texts(&doc).contains("<summary>"));
    assert!(texts(&doc).contains("More"));
}

#[test]
fn indented_code_then_summary_in_quote() {
    let doc = parse("> <details>\n>     code\n>\n> <summary>later</summary>\n> body\n> </details>");
    let Block::BlockQuote { blocks, .. } = &doc.blocks[0] else {
        panic!("quote");
    };
    let Block::Details { summary, body, .. } = &blocks[0] else {
        panic!("details in quote: {blocks:?}");
    };
    assert!(summary.is_empty());
    assert!(
        body.iter()
            .any(|block| matches!(block, Block::CodeBlock { .. }))
    );
    assert!(body.iter().any(|block| match block {
        Block::Paragraph { inlines } => inlines.iter().any(|inline| matches!(
            inline,
            Inline::Text(s) if s.contains("<summary>later</summary>")
        )),
        _ => false,
    }));
}
