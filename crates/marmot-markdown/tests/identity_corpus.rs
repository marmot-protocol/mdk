// Markdown-recognizer baseline over the shared identity-reference corpus.
//
// The corpus (crates/marmot-app/tests/support/identity_reference_vectors.rs)
// records, per row, the HRP the markdown recognizer is expected to produce
// (`md_hrp`, None when the reference produces no nostr entity). This test
// pins that baseline: bare event/address references require a valid checksum,
// while npub mentions and nostr: URIs remain shape-only. For example,
// `damaged_npub_checksum` is recognized even though resolution rejects it.

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
// top-level paragraph — but entities can nest inside emphasized spans,
// links and image alt text, so the walk recurses through container
// inlines rather than trusting the top level alone. (`Inline::Code` holds
// a plain `String`, so a code span can never contain an entity.)
fn collect_top_level_hrps(block: &Block, hrps: &mut Vec<NostrHrp>) {
    let Block::Paragraph { inlines, .. } = block else {
        return;
    };
    collect_inlined_hrps(inlines, hrps);
}

fn collect_inlined_hrps(inlines: &[Inline], hrps: &mut Vec<NostrHrp>) {
    for inline in inlines {
        match inline {
            Inline::NostrMention(entity) | Inline::NostrUri(entity) => {
                hrps.push(entity.hrp);
            }
            Inline::Emph(nested) | Inline::Strong(nested) | Inline::Strikethrough(nested) => {
                collect_inlined_hrps(nested, hrps)
            }
            Inline::Link { children, .. } => collect_inlined_hrps(children, hrps),
            Inline::Image { alt, .. } => collect_inlined_hrps(alt, hrps),
            _ => {}
        }
    }
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

// No corpus row nests an entity inside a container inline, so the
// recursion above has no baseline coverage. These cases pin it: an entity
// nested in emphasis, strong, strikethrough, a link's children or an
// image's alt text is still recognized.
#[test]
fn nested_entities_are_recognized_too() {
    let entity = format!("nostr:{NPUB}");
    let cases = [
        ("emphasis", format!("*{entity}*")),
        ("strong", format!("**{entity}**")),
        ("strikethrough", format!("~~{entity}~~")),
        (
            "link children",
            format!("[{entity}](https://example.invalid/x.png)"),
        ),
        (
            "image alt text",
            format!("![{entity}](https://example.invalid/x.png)"),
        ),
    ];
    for (name, markdown) in cases {
        let document = parse(&markdown);
        let mut hrps = Vec::new();
        for block in &document.blocks {
            collect_top_level_hrps(block, &mut hrps);
        }
        assert_eq!(
            hrps,
            vec![NostrHrp::Npub],
            "entity nested in {name} must still be recognized"
        );
    }
}
