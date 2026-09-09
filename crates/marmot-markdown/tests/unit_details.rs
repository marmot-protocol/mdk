//! Structured `<details>` / `<summary>` block recognition.

use marmot_markdown::{Block, Inline, parse};

mod common;
use common::{em, paragraph, strong, t};

fn details_only(md: &str) -> (bool, Vec<Inline>, Vec<Block>, Vec<u8>) {
    let doc = parse(md);
    assert_eq!(
        doc.blocks.len(),
        1,
        "expected a single top-level block: {doc:?}"
    );
    match &doc.blocks[0] {
        Block::Details {
            summary,
            open,
            body,
            blank_lines_before,
        } => (
            *open,
            summary.clone(),
            body.clone(),
            blank_lines_before.clone(),
        ),
        other => panic!("expected Details, got {other:?}"),
    }
}

fn no_delimiter_text(inlines: &[Inline]) -> bool {
    !inlines.iter().any(|inline| match inline {
        Inline::Text(s) => {
            s.to_ascii_lowercase().contains("<details")
                || s.to_ascii_lowercase().contains("</details")
                || s.to_ascii_lowercase().contains("<summary")
                || s.to_ascii_lowercase().contains("</summary")
        }
        Inline::Emph(c) | Inline::Strong(c) | Inline::Strikethrough(c) => !no_delimiter_text(c),
        Inline::Link { children, .. } => !no_delimiter_text(children),
        _ => false,
    })
}

#[test]
fn issue_input_without_blank_lines() {
    let md = "<details>\n<summary>Tap to expand</summary>\nHidden body **bold**\n</details>";
    let (open, summary, body, gaps) = details_only(md);
    assert!(!open);
    assert_eq!(summary, vec![t("Tap to expand")]);
    assert_eq!(body.len(), 1);
    assert_eq!(gaps, vec![0]);
    let Block::Paragraph { inlines } = &body[0] else {
        panic!("expected body paragraph");
    };
    assert_eq!(inlines[0], t("Hidden body "));
    assert!(matches!(inlines[1], Inline::Strong(_)));
    assert!(no_delimiter_text(inlines));
    assert!(no_delimiter_text(&summary));
}

#[test]
fn issue_input_with_blank_lines() {
    let md = "<details>\n<summary>Sum</summary>\n\nBody para\n\n</details>";
    let (open, summary, body, gaps) = details_only(md);
    assert!(!open);
    assert_eq!(summary, vec![t("Sum")]);
    assert_eq!(body, vec![paragraph("Body para")]);
    assert_eq!(gaps, vec![1]);
}

#[test]
fn open_attribute_and_case() {
    let (open, ..) = details_only("<DETAILS OPEN>\n<body>\n</DETAILS>");
    assert!(open);
    let (open, ..) = details_only("<details open=\"false\">\nbody\n</details>");
    assert!(open);
    let (open, ..) = details_only("<details opened>\nbody\n</details>");
    assert!(!open);
    let (open, ..) = details_only("<details data-open=\"1\" title=\"open\">\nbody\n</details>");
    assert!(!open);
}

#[test]
fn ignored_quoted_gt_and_false_prefixes() {
    let (open, summary, body, _) =
        details_only("<details title=\"a>b\" foo='open'>\n<summary>Hi</summary>\nX\n</details>");
    assert!(!open);
    assert_eq!(summary, vec![t("Hi")]);
    assert_eq!(body, vec![paragraph("X")]);
}

#[test]
fn empty_and_missing_summary() {
    let (_, summary, body, _) = details_only("<details>\n<summary></summary>\nbody\n</details>");
    assert!(summary.is_empty());
    assert_eq!(body, vec![paragraph("body")]);
    let (_, summary, body, _) = details_only("<details>\n\nbody\n</details>");
    assert!(summary.is_empty());
    assert_eq!(body, vec![paragraph("body")]);
    let (_, summary, body, gaps) = details_only("<details>\n</details>");
    assert!(summary.is_empty());
    assert!(body.is_empty());
    assert!(gaps.is_empty());
}

#[test]
fn multiline_summary() {
    let (_, summary, body, _) =
        details_only("<details>\n<summary>More\ninfo</summary>\nbody\n</details>");
    assert_eq!(summary, vec![t("More"), Inline::SoftBreak, t("info")]);
    assert_eq!(body, vec![paragraph("body")]);
}

#[test]
fn formatted_and_nostr_summary() {
    let body = "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
    let md = format!("<details>\n<summary>See *{body}* @npub1{body}</summary>\ninside\n</details>");
    let (_, summary, ..) = details_only(&md);
    assert!(matches!(summary[0], Inline::Text(_)));
    assert!(summary.iter().any(|i| matches!(i, Inline::Emph(_))));
    assert!(summary.iter().any(|i| matches!(i, Inline::NostrMention(_))));
}

#[test]
fn later_summary_is_body_text() {
    let (_, summary, body, _) =
        details_only("<details>\n<summary>First</summary>\n<summary>Later</summary>\n</details>");
    assert_eq!(summary, vec![t("First")]);
    assert_eq!(body, vec![paragraph("<summary>Later</summary>")]);
}

#[test]
fn nested_and_adjacent() {
    let doc = parse(
        "<details>\n<summary>Outer</summary>\n<details>\n<summary>Inner</summary>\nin\n</details>\n</details>\n\n<details>\nnext\n</details>",
    );
    assert_eq!(doc.blocks.len(), 2);
    let Block::Details { body, .. } = &doc.blocks[0] else {
        panic!("outer");
    };
    assert!(matches!(body[0], Block::Details { .. }));
    assert!(matches!(doc.blocks[1], Block::Details { .. }));
}

#[test]
fn quoted_and_list_nesting() {
    let doc = parse(
        "> <details>\n> <summary>Q</summary>\n> quoted\n> </details>\n\n- <details>\n  listed\n  </details>",
    );
    assert_eq!(doc.blocks.len(), 2);
    let Block::BlockQuote { blocks, .. } = &doc.blocks[0] else {
        panic!("quote");
    };
    assert!(matches!(blocks[0], Block::Details { .. }));
    let Block::List { items, .. } = &doc.blocks[1] else {
        panic!("list");
    };
    assert!(matches!(items[0].blocks[0], Block::Details { .. }));
}

#[test]
fn body_holds_blocks_and_code() {
    let md = "<details>\n<summary>S</summary>\n\n# Head\n\n- item\n\n```\n</details>\n```\n\nstill\n</details>";
    let (_, _, body, _) = details_only(md);
    assert!(matches!(body[0], Block::Heading { .. }));
    assert!(matches!(body[1], Block::List { .. }));
    assert!(matches!(body[2], Block::CodeBlock { .. }));
    assert_eq!(body[3], paragraph("still"));
}

#[test]
fn compact_inline_stays_literal() {
    let doc = parse("<details><summary>x</summary>y</details>");
    assert_eq!(
        doc.blocks,
        vec![paragraph("<details><summary>x</summary>y</details>")]
    );
}

#[test]
fn escaped_and_entity_and_code_stay_literal() {
    let doc = parse("\\<details>\n");
    assert!(!matches!(doc.blocks[0], Block::Details { .. }));
    let doc = parse("&lt;details&gt;\nsummary\n&lt;/details&gt;");
    assert!(
        !doc.blocks
            .iter()
            .any(|b| matches!(b, Block::Details { .. }))
    );
    let doc = parse("`<details>`\n");
    let Block::Paragraph { inlines } = &doc.blocks[0] else {
        panic!("para");
    };
    assert!(matches!(inlines[0], Inline::Code(_)));
}

#[test]
fn unmatched_and_malformed_fallback() {
    let doc = parse("<details>\nhello\n");
    assert_eq!(doc.blocks[0], paragraph("<details>"));
    assert_eq!(doc.blocks[1], paragraph("hello"));
    let doc = parse("<details>\nhello\n</details foo>");
    assert!(
        !doc.blocks
            .iter()
            .any(|b| matches!(b, Block::Details { .. }))
    );
    let doc = parse("<detailsx>\nhello\n</details>");
    assert!(!matches!(doc.blocks[0], Block::Details { .. }));
    let doc = parse("<details>\n<summary\nhello\n</details>");
    assert!(
        !doc.blocks
            .iter()
            .any(|b| matches!(b, Block::Details { .. }))
    );
}

#[test]
fn closer_outside_quote_does_not_steal() {
    let doc = parse("> <details>\n> hello\n</details>");
    let Block::BlockQuote { blocks, .. } = &doc.blocks[0] else {
        panic!("quote");
    };
    assert!(!blocks.iter().any(|b| matches!(b, Block::Details { .. })));
    assert_eq!(doc.blocks[1], paragraph("</details>"));
}

#[test]
fn sibling_after_fallback_is_preserved() {
    let doc = parse("<details>\nhello\n\n# After");
    assert_eq!(doc.blocks.last(), Some(&common::heading(1, "After")));
}

#[test]
fn source_gaps_after_summary_and_not_after_close() {
    let doc = parse("before\n\n<details>\n<summary>S</summary>\n\ninner\n\n</details>\n\nafter");
    assert_eq!(doc.blank_lines_before, vec![0, 1, 1]);
    let Block::Details {
        blank_lines_before, ..
    } = &doc.blocks[1]
    else {
        panic!("details");
    };
    assert_eq!(blank_lines_before, &vec![1]);
}

#[test]
fn shared_and_forward_references() {
    let doc = parse("[lab]: /url\n\n<details>\n<summary>[lab]</summary>\nsee [lab]\n</details>");
    let Block::Details { summary, body, .. } = &doc.blocks[0] else {
        panic!("details");
    };
    let (summary, body) = (summary.clone(), body.clone());
    assert!(matches!(
        summary[0],
        Inline::Link { ref dest, .. } if dest == "/url"
    ));
    let Block::Paragraph { inlines } = &body[0] else {
        panic!("body");
    };
    assert!(matches!(
        inlines[1],
        Inline::Link { ref dest, .. } if dest == "/url"
    ));
}

#[test]
fn crlf_and_unicode_summary() {
    let md = "<details>\r\n<summary>café 🦫</summary>\r\nbody\r\n</details>\r\n";
    let (_, summary, body, _) = details_only(md);
    assert_eq!(summary, vec![t("café 🦫")]);
    assert_eq!(body, vec![paragraph("body")]);
}

#[test]
fn scan_and_tag_caps() {
    let over_tag = format!("<details class='{}'>", "x".repeat(4096));
    let md = format!("{over_tag}\nbody\n</details>");
    let doc = parse(&md);
    assert!(!matches!(doc.blocks[0], Block::Details { .. }));

    let mut inside = "pre\n".to_string();
    inside.push_str("<details>\nbody\n</details>");
    let doc = parse(&inside);
    assert!(
        doc.blocks
            .iter()
            .any(|b| matches!(b, Block::Details { .. })),
        "opener inside the 65536-byte window should match"
    );

    let mut outside = "x".repeat(65536);
    outside.push_str("\n<details>\nbody\n</details>");
    let doc = parse(&outside);
    assert!(
        !doc.blocks
            .iter()
            .any(|b| matches!(b, Block::Details { .. })),
        "opener after the recognition window must stay literal"
    );
}

#[test]
fn code_span_protects_summary_close() {
    let (_, summary, ..) =
        details_only("<details>\n<summary>use `</summary>` here</summary>\nbody\n</details>");
    assert_eq!(
        summary,
        vec![t("use "), common::code("</summary>"), t(" here")]
    );
}

#[test]
fn strong_in_body() {
    let (_, _, body, _) = details_only("<details>\nHidden body **bold**\n</details>");
    let Block::Paragraph { inlines } = &body[0] else {
        panic!("para");
    };
    assert!(inlines.iter().any(|i| matches!(i, Inline::Strong(_))));
    let _ = (em(vec![]), strong(vec![]));
}
