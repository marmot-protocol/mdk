// Markdown-recognizer baseline over the shared identity-reference corpus.
//
// The corpus (crates/marmot-app/tests/support/identity_reference_vectors.rs)
// records, per row, the HRP the markdown recognizer is expected to produce
// (`md_hrp`, None when the reference produces no nostr entity). This test
// pins that baseline: the markdown recognizer is shape-only, so rows like
// `damaged_npub_checksum` are recognized even though resolution rejects
// them, while bare event/address literals produce no entity at all.

include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../marmot-app/tests/support/identity_reference_vectors.rs"
));

use marmot_markdown::{Block, Inline, NostrHrp, parse};

fn expected_hrp(name: &str) -> NostrHrp {
    match name {
        "npub" => NostrHrp::Npub,
        "note" => NostrHrp::Note,
        "nevent" => NostrHrp::Nevent,
        "nprofile" => NostrHrp::Nprofile,
        "naddr" => NostrHrp::Naddr,
        other => panic!("unknown md_hrp name {other}"),
    }
}

fn collect_inline_hrps(inline: &Inline, hrps: &mut Vec<NostrHrp>) {
    match inline {
        Inline::NostrMention(entity) | Inline::NostrUri(entity) => hrps.push(entity.hrp),
        Inline::Emph(children) | Inline::Strong(children) | Inline::Strikethrough(children) => {
            for child in children {
                collect_inline_hrps(child, hrps);
            }
        }
        Inline::Link { children, .. } => {
            for child in children {
                collect_inline_hrps(child, hrps);
            }
        }
        Inline::Image { alt, .. } => {
            for child in alt {
                collect_inline_hrps(child, hrps);
            }
        }
        _ => {}
    }
}

fn collect_block_hrps(block: &Block, hrps: &mut Vec<NostrHrp>) {
    match block {
        Block::Paragraph { inlines, .. } | Block::Heading { inlines, .. } => {
            for inline in inlines {
                collect_inline_hrps(inline, hrps);
            }
        }
        Block::BlockQuote { blocks, .. } | Block::Details { body: blocks, .. } => {
            for child in blocks {
                collect_block_hrps(child, hrps);
            }
        }
        Block::List { items, .. } => {
            for item in items {
                for child in &item.blocks {
                    collect_block_hrps(child, hrps);
                }
            }
        }
        Block::Table { header, rows, .. } => {
            for cell in header.iter().chain(rows.iter().flatten()) {
                for inline in &cell.inlines {
                    collect_inline_hrps(inline, hrps);
                }
            }
        }
        Block::ThematicBreak | Block::CodeBlock { .. } | Block::MathBlock { .. } => {}
    }
}

#[test]
fn markdown_recognition_matches_shared_corpus_baseline() {
    for case in cases() {
        let document = parse(&case.reference);
        let mut hrps = Vec::new();
        for block in &document.blocks {
            collect_block_hrps(block, &mut hrps);
        }
        match case.md_hrp {
            Some(expected) => {
                assert_eq!(hrps, vec![expected_hrp(expected)], "case {}", case.name);
            }
            None => assert!(
                hrps.is_empty(),
                "case {} unexpectedly recognized as {hrps:?}",
                case.name
            ),
        }
    }
}
