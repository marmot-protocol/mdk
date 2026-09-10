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
fn fallback_restores_markdown_heading() {
    let doc = parse("<details>\n<summary>one\n# heading\n\nbody\n</details>");
    assert!(!has_details(&doc));
    assert_eq!(doc.blocks[0], paragraph("<details>"));
    assert!(
        doc.blocks
            .iter()
            .any(|block| matches!(block, Block::Heading { level: 1, .. })),
        "fallback must restore heading structure: {doc:?}"
    );
    assert_eq!(doc.blocks.last(), Some(&paragraph("</details>")));
    assert!(texts(&doc).contains("one"));
    assert!(texts(&doc).contains("heading"));
    assert!(texts(&doc).contains("body"));
}

#[test]
fn fallback_retains_blank_before_summary() {
    let doc = parse("<details>\n\n<summary>sum</summary>\n\nbody");
    assert!(!has_details(&doc));
    assert_eq!(
        doc.blank_lines_before,
        vec![0, 1, 1],
        "gap before a completed summary must survive fallback: {doc:?}"
    );
    assert_eq!(doc.blocks[0], paragraph("<details>"));
    assert!(texts(&doc).contains("sum"));
    assert_eq!(doc.blocks.last(), Some(&paragraph("body")));
}

#[test]
fn fallback_multiline_keeps_lists_code_refs_and_siblings() {
    let doc = parse(
        "<details>\n<summary>one\n- item\n\n    code\n\n[lab]: /url\n\nsee [lab]\n# After\n</details>\n\nsibling",
    );
    assert!(!has_details(&doc));
    assert!(
        doc.blocks
            .iter()
            .any(|block| matches!(block, Block::List { .. })),
        "list structure must survive fallback: {doc:?}"
    );
    assert!(
        doc.blocks
            .iter()
            .any(|block| matches!(block, Block::CodeBlock { .. })),
        "indented code must survive fallback: {doc:?}"
    );
    assert!(
        doc.blocks
            .iter()
            .any(|block| matches!(block, Block::Heading { .. })),
        "following heading must survive: {doc:?}"
    );
    assert_eq!(doc.blocks.last(), Some(&paragraph("sibling")));
}

#[test]
fn fallback_blank_before_summary_on_container_loss_and_scan_refusal() {
    let listed = parse("- <details>\n\n  <summary>sum</summary>\n  body\n# After");
    assert!(!has_details(&listed));
    let Block::List { items, .. } = &listed.blocks[0] else {
        panic!("list: {listed:?}");
    };
    assert!(
        items[0].blank_lines_before.get(1) == Some(&1),
        "container-loss fallback must keep the blank before summary: {listed:?}"
    );
    assert_eq!(listed.blocks.last(), Some(&common::heading(1, "After")));

    let header = "<details>\n\n<summary>sum</summary>\n";
    let pad = 65_536_usize.saturating_sub(header.len());
    let md = format!("{header}{}</details>", "y".repeat(pad));
    let doc = parse(&md);
    assert!(!has_details(&doc));
    assert_eq!(doc.blank_lines_before[0], 0);
    assert!(
        doc.blank_lines_before.get(1) == Some(&1),
        "scan-refused fallback must keep the blank before summary: {doc:?}"
    );
}

#[test]
fn summary_code_protects_details_delimiter() {
    let doc = parse("<details>\n<summary>`one\n</details>\ntwo`\n</summary>\nbody\n</details>");
    let Block::Details { summary, body, .. } = &doc.blocks[0] else {
        panic!("expected Details, got {doc:?}");
    };
    assert!(
        summary
            .iter()
            .any(|inline| matches!(inline, Inline::Code(s) if s.contains("</details>"))),
        "code span must protect the details delimiter: {summary:?}"
    );
    assert_eq!(body, &vec![paragraph("body")]);
}

#[test]
fn code_span_can_protect_earlier_line_summary_closer() {
    let doc = parse("<details>\n<summary>`one\n</summary>\ntwo`</summary>\nbody\n</details>");
    let Block::Details { summary, .. } = &doc.blocks[0] else {
        panic!("expected Details, got {doc:?}");
    };
    assert_eq!(
        summary,
        &[code("one </summary> two")],
        "later matching ticks must protect the earlier closer: {summary:?}"
    );
}

#[test]
fn summary_retains_hard_break() {
    let doc = parse("<details>\n<summary>one  \ntwo</summary>\nbody\n</details>");
    let Block::Details { summary, .. } = &doc.blocks[0] else {
        panic!("expected Details, got {doc:?}");
    };
    assert!(
        summary
            .iter()
            .any(|inline| matches!(inline, Inline::HardBreak)),
        "two trailing spaces must remain a hard break: {summary:?}"
    );
}

#[test]
fn summary_code_span_protects_delimiter_only_interior_lines() {
    let doc = parse(
        "<details>\n<summary>`one\n</summary>\n</details>\ntwo`\n</summary>\nbody\n</details>",
    );
    let Block::Details { summary, body, .. } = &doc.blocks[0] else {
        panic!("expected Details, got {doc:?}");
    };
    assert!(
        summary.iter().any(|inline| matches!(
            inline,
            Inline::Code(s) if s.contains("</summary>") && s.contains("</details>")
        )),
        "delimiter-only interior lines must stay inside the code span: {summary:?}"
    );
    assert_eq!(body, &vec![paragraph("body")]);
    assert_eq!(doc.blocks.len(), 1);

    let crlf = parse(
        "<details>\r\n<summary>`one\r\n</summary>\r\n</details>\r\ntwo`\r\n</summary>\r\nbody\r\n</details>\r\n",
    );
    let Block::Details { summary, body, .. } = &crlf.blocks[0] else {
        panic!("expected CRLF Details, got {crlf:?}");
    };
    assert!(
        summary.iter().any(|inline| matches!(
            inline,
            Inline::Code(s) if s.contains("</summary>") && s.contains("</details>")
        )),
        "CRLF delimiter-only lines must stay inside the code span: {summary:?}"
    );
    assert_eq!(body, &vec![paragraph("body")]);
}

#[test]
fn summary_code_span_can_span_three_lines_and_crlf() {
    let doc = parse("<details>\n<summary>`one\n</summary>\ntwo`</summary>\nbody\n</details>");
    let Block::Details { summary, .. } = &doc.blocks[0] else {
        panic!("expected Details, got {doc:?}");
    };
    assert!(
        summary
            .iter()
            .any(|inline| matches!(inline, Inline::Code(_)))
    );

    let crlf = parse(
        "<details>\r\n<summary>`one\r\n</summary>\r\ntwo`</summary>\r\nbody\r\n</details>\r\n",
    );
    let Block::Details { summary, .. } = &crlf.blocks[0] else {
        panic!("expected CRLF Details, got {crlf:?}");
    };
    assert!(
        summary
            .iter()
            .any(|inline| matches!(inline, Inline::Code(_)))
    );
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

#[test]
fn failed_summary_replays_ordinary_block_semantics() {
    for summary in [
        "<summary>\nTitle\n---",
        "<summary>\nTitle\n===",
        "<summary>\n~~~rust\n# literal heading\n~~~",
        "<summary>\n$$\nx + y\n$$",
        "<summary>\n- first\n- second",
        "<summary>\n> first\n> second",
        "<summary>\nheader | value\n--- | ---\na | b",
    ] {
        let expected = parse(summary);
        for ending in ["", "\n\n# After", "\n</details>\n# After"] {
            let doc = parse(&format!("<details>\n{summary}{ending}"));
            assert_eq!(doc.blocks[0], paragraph("<details>"));
            assert_eq!(
                &doc.blocks[1..1 + expected.blocks.len()],
                expected.blocks.as_slice(),
                "fallback changed ordinary Markdown: {summary:?}, ending={ending:?}: {doc:?}"
            );
            if !ending.is_empty() {
                assert_eq!(doc.blocks.last(), Some(&common::heading(1, "After")));
            }
        }
    }
}

#[test]
fn failed_summary_replay_respects_remaining_container_depth() {
    let prefix = "> ".repeat(90);
    let held = format!("<summary>\n{}content", "> ".repeat(200));
    let input = held
        .lines()
        .map(|line| format!("{prefix}{line}\n"))
        .collect::<String>();
    let doc = parse(&format!("{prefix}<details>\n{input}"));
    let mut blocks = doc.blocks.as_slice();
    let mut depth = 0;
    loop {
        let quote = blocks.iter().find_map(|block| match block {
            Block::BlockQuote { blocks, .. } => Some(blocks.as_slice()),
            _ => None,
        });
        let Some(children) = quote else { break };
        depth += 1;
        assert!(depth <= 96, "fallback exceeded container depth: {depth}");
        blocks = children;
    }
    assert!(texts(&doc).contains("content"));
}

#[test]
fn many_line_open_summary_release_probe_compares_to_control() {
    use std::time::Instant;
    let n = 32_749usize;
    let mut hostile = String::from("<details>\n<summary>\n");
    for _ in 0..n {
        hostile.push_str("x\n");
    }
    let mut control = String::from("<details>\n");
    for _ in 0..n {
        control.push_str("x\n");
    }
    let _ = parse(&hostile);
    let _ = parse(&control);
    let started = Instant::now();
    let _ = parse(&hostile);
    let hostile_us = started.elapsed().as_micros();
    let started = Instant::now();
    let _ = parse(&control);
    let control_us = started.elapsed().as_micros();
    eprintln!(
        "many-line open-summary probe bytes={} hostile_us={} control_us={} ratio={:.2}",
        hostile.len(),
        hostile_us,
        control_us,
        hostile_us as f64 / control_us.max(1) as f64
    );
    assert!(
        hostile_us < 5_000_000,
        "hostile many-line summary must stay well under the previous multi-second stall, us={hostile_us}"
    );
}
