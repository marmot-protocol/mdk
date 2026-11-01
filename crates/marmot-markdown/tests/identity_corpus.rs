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
        "nrelay" => NostrHrp::Nrelay,
        other => panic!("unknown md_hrp name {other}"),
    }
}

// Every corpus input is a single line, so each document holds at most one
// top-level paragraph and the recognizer's inline findings are all in its
// inlines — a single flat_map over those suffices.
fn collect_top_level_hrps(block: &Block, hrps: &mut Vec<NostrHrp>) {
    let Block::Paragraph { inlines, .. } = block else {
        return;
    };
    hrps.extend(inlines.iter().filter_map(|inline| match inline {
        Inline::NostrMention(entity) | Inline::NostrUri(entity) => Some(entity.hrp),
        _ => None,
    }));
}

#[test]
fn markdown_recognition_matches_shared_corpus_baseline() {
    for case in cases() {
        let document = parse(&case.reference);
        let mut hrps = Vec::new();
        for block in &document.blocks {
            collect_top_level_hrps(block, &mut hrps);
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
