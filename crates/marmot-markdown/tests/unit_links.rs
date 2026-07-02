use std::time::{Duration, Instant};

use marmot_markdown::{Block, Inline, parse};

mod common;
use common::{parse_blocks, parse_inlines, t};

fn link(dest: &str, title: Option<&str>, children: Vec<Inline>) -> Inline {
    Inline::Link {
        dest: dest.to_string(),
        title: title.map(|t| t.to_string()),
        children,
    }
}
fn image(dest: &str, title: Option<&str>, alt: Vec<Inline>) -> Inline {
    Inline::Image {
        dest: dest.to_string(),
        title: title.map(|t| t.to_string()),
        alt,
    }
}

fn count_links(inlines: &[Inline]) -> usize {
    inlines
        .iter()
        .map(|inline| match inline {
            Inline::Link { children, .. } => 1 + count_links(children),
            Inline::Image { alt, .. } => count_links(alt),
            Inline::Emph(children) | Inline::Strong(children) | Inline::Strikethrough(children) => {
                count_links(children)
            }
            _ => 0,
        })
        .sum()
}

fn count_images(inlines: &[Inline]) -> usize {
    inlines
        .iter()
        .map(|inline| match inline {
            Inline::Image { alt, .. } => 1 + count_images(alt),
            Inline::Link { children, .. } => count_images(children),
            Inline::Emph(children) | Inline::Strong(children) | Inline::Strikethrough(children) => {
                count_images(children)
            }
            _ => 0,
        })
        .sum()
}

fn count_links_in_blocks(blocks: &[Block]) -> usize {
    blocks
        .iter()
        .map(|block| match block {
            Block::Paragraph { inlines } | Block::Heading { inlines, .. } => count_links(inlines),
            _ => 0,
        })
        .sum()
}

fn parse_inlines_within(input: &str, max_elapsed: Duration) -> Vec<Inline> {
    let started = Instant::now();
    let parsed = parse_inlines(input);
    let elapsed = started.elapsed();
    assert!(
        elapsed <= max_elapsed,
        "markdown inline parse exceeded {:?} budget for {} bytes: {:?}",
        max_elapsed,
        input.len(),
        elapsed
    );
    parsed
}

fn parse_blocks_within(input: &str, max_elapsed: Duration) -> Vec<Block> {
    let started = Instant::now();
    let blocks = parse(input).blocks;
    let elapsed = started.elapsed();
    assert!(
        elapsed <= max_elapsed,
        "markdown block parse exceeded {:?} budget for {} bytes: {:?}",
        max_elapsed,
        input.len(),
        elapsed
    );
    blocks
}

/// Mirrors the crate-internal `MAX_OPEN_BRACKET_DELIMITERS` /
/// `MAX_INLINE_NESTING_DEPTH` constants. They are intentionally not public API,
/// but the boundary behavior is security-relevant for darkmatter#654.
const BRACKET_DELIM_CAP: usize = 96;

// ----- Inline links ---------------------------------------------------

#[test]
fn inline_link_simple() {
    assert_eq!(
        parse_inlines("[foo](/url)"),
        vec![link("/url", None, vec![t("foo")])]
    );
}

#[test]
fn inline_link_with_title() {
    assert_eq!(
        parse_inlines("[foo](/url \"t\")"),
        vec![link("/url", Some("t"), vec![t("foo")])]
    );
}

#[test]
fn inline_link_bracketed_dest() {
    assert_eq!(
        parse_inlines("[foo](<https://x>)"),
        vec![link("https://x", None, vec![t("foo")])]
    );
}

#[test]
fn inline_link_empty_dest() {
    assert_eq!(
        parse_inlines("[foo]()"),
        vec![link("", None, vec![t("foo")])]
    );
}

#[test]
fn inline_link_with_text_around() {
    assert_eq!(
        parse_inlines("see [foo](/u) ok"),
        vec![t("see "), link("/u", None, vec![t("foo")]), t(" ok")]
    );
}

#[test]
fn inline_link_coalesces_literal_child_runs() {
    assert_eq!(
        parse_inlines("[a [b] c](/url)"),
        vec![link("/url", None, vec![t("a [b] c")])]
    );
}

#[test]
fn inline_link_with_emphasis_in_text() {
    // Emphasis inside link text IS processed.
    assert_eq!(
        parse_inlines("[*foo*](/u)"),
        vec![link("/u", None, vec![Inline::Emph(vec![t("foo")])])]
    );
}

#[test]
fn many_emphasis_delimiters_interleaved_with_links_stay_bounded() {
    // Regression for darkmatter#686: each link used to rescan the full
    // delimiter stack just to deactivate earlier `[` openers, so unrelated
    // accumulated `*` delimiters made `*[a](b)` repeated in one paragraph
    // quadratic. The wall-clock budget is deliberately generous for CI, but a
    // reintroduced quadratic at this size fails instead of silently burning CPU.
    let links = 80_000;
    let input = "*[a](b)".repeat(links);
    let parsed = parse_inlines_within(&input, Duration::from_secs(5));

    assert_eq!(count_links(&parsed), links);
    assert!(matches!(parsed.first(), Some(Inline::Emph(_))));
}

#[test]
fn many_emphasis_delimiters_interleaved_with_unmatched_close_brackets_stay_bounded() {
    // Regression for darkmatter#710, fixed in #712: every `*` pushes an
    // emphasis delimiter, and every following unmatched `]` used to rescan the
    // full mixed delimiter stack looking for a bracket/image opener that was
    // never present. Keep the hostile single-paragraph `*]` shape under an
    // explicit wall-clock budget so the test fails on quadratic behavior, not
    // just on structural changes. The budget is calibrated for the default
    // debug CI profile; optimized test profiles may leave extra headroom.
    let pairs = 80_000;
    let input = "*]".repeat(pairs);
    let parsed = parse_inlines_within(&input, Duration::from_secs(5));

    assert!(
        parsed.len() >= pairs / 2,
        "expected linear retained output for hostile `*]` shape: {} inlines for {pairs} pairs",
        parsed.len()
    );
    assert!(matches!(parsed.first(), Some(Inline::Emph(_))));
}

#[test]
fn many_emphasis_delimiters_with_emphasis_inside_links_stay_bounded() {
    // The per-link emphasis pass must only process the current link-text
    // suffix. Rebuilding all previous output for each `[*a*](b)` link made the
    // same outer `*` accumulator quadratic with a much larger constant.
    let links = 20_000;
    let input = "*[*a*](b)".repeat(links);
    let parsed = parse_inlines_within(&input, Duration::from_secs(5));

    assert_eq!(count_links(&parsed), links);
    assert!(matches!(parsed.first(), Some(Inline::Emph(_))));
}

#[test]
fn nested_link_opener_chains_with_emphasis_stay_bounded() {
    // Pin the bracket-chain deactivation path: closing the innermost link must
    // deactivate earlier link openers without scanning unrelated `*` delimiters.
    let links = 8_000;
    let input = "*[a[b[c[d](e)](f)](g)](h)".repeat(links);
    let parsed = parse_inlines_within(&input, Duration::from_secs(5));

    assert_eq!(count_links(&parsed), links);
}

#[test]
fn reference_link_variants_with_emphasis_stay_bounded() {
    // Full, collapsed, and shortcut reference links all call absorb_link after
    // resolving labels; keep each branch covered by the hostile shape.
    let links = 8_000;
    for unit in ["*[id][id]", "*[id][]", "*[id]"] {
        let input = format!("{}\n\n[id]: /url", unit.repeat(links));
        let blocks = parse_blocks_within(&input, Duration::from_secs(5));

        assert_eq!(count_links_in_blocks(&blocks), links, "unit={unit}");
    }
}

#[test]
fn images_interleaved_with_emphasis_stay_bounded() {
    // Images keep earlier link openers active, but still exercise the per-link
    // process_emphasis call with an empty active window above stack_bottom.
    let images = 80_000;
    let input = "*![a](b)".repeat(images);
    let parsed = parse_inlines_within(&input, Duration::from_secs(5));

    assert_eq!(count_images(&parsed), images);
}

#[test]
fn inline_link_with_code_span_in_text() {
    assert_eq!(
        parse_inlines("[`code`](/u)"),
        vec![link("/u", None, vec![Inline::Code("code".into())])]
    );
}

#[test]
fn unmatched_bracket_falls_through() {
    assert_eq!(parse_inlines("[foo"), vec![t("[foo")]);
}

#[test]
fn unmatched_close_bracket_is_text() {
    assert_eq!(parse_inlines("foo]"), vec![t("foo]")]);
}

#[test]
fn many_unmatched_link_brackets_stay_literal_without_quadratic_work() {
    // Regression for darkmatter#654: `"[" * N + "]" * N` used to keep every
    // `[` on the delimiter stack and then spend quadratic time scanning and
    // shifting that stack on the closing `]` run. The parser now caps the open
    // bracket stack and advances one opener per unmatched close.
    let n = 100_000;
    let input = format!("{}{}", "[".repeat(n), "]".repeat(n));
    assert_eq!(parse_inlines(&input), vec![t(&input)]);
}

#[test]
fn many_unmatched_image_brackets_stay_literal_without_quadratic_work() {
    let n = 50_000;
    let input = format!("{}{}", "![".repeat(n), "]".repeat(n));
    assert_eq!(parse_inlines(&input), vec![t(&input)]);
}

#[test]
fn excess_open_brackets_pair_with_latest_kept_opener() {
    // Once the opener cap is reached, later `[` bytes remain literal text.
    // A subsequent valid close therefore pairs with the latest kept opener,
    // not the latest literal `[`. Pin this pathological-but-intentional split
    // so future changes do not accidentally uncap the delimiter stack.
    let input = format!("{}text](url)", "[".repeat(BRACKET_DELIM_CAP + 1));
    assert_eq!(
        parse_inlines(&input),
        vec![
            t(&"[".repeat(BRACKET_DELIM_CAP - 1)),
            link("url", None, vec![t("[text")]),
        ]
    );
}

#[test]
fn no_matching_paren_falls_through() {
    // `[foo](/url` — never closes; no link, all literal.
    assert_eq!(parse_inlines("[foo](/url"), vec![t("[foo](/url")]);
}

// ----- Images ---------------------------------------------------------

#[test]
fn image_simple() {
    assert_eq!(
        parse_inlines("![alt](/img.png)"),
        vec![image("/img.png", None, vec![t("alt")])]
    );
}

#[test]
fn image_with_title() {
    assert_eq!(
        parse_inlines("![alt](/img.png \"caption\")"),
        vec![image("/img.png", Some("caption"), vec![t("alt")])]
    );
}

#[test]
fn image_in_text() {
    assert_eq!(
        parse_inlines("see ![alt](/img) ok"),
        vec![t("see "), image("/img", None, vec![t("alt")]), t(" ok")]
    );
}

// ----- Reference links (full / collapsed / shortcut) ----------------

#[test]
fn full_ref_link() {
    let input = "[foo][bar]\n\n[bar]: /url \"t\"";
    assert_eq!(
        parse_blocks(input),
        vec![Block::Paragraph {
            inlines: vec![link("/url", Some("t"), vec![t("foo")])]
        }]
    );
}

#[test]
fn collapsed_ref_link() {
    let input = "[foo][]\n\n[foo]: /url";
    assert_eq!(
        parse_blocks(input),
        vec![Block::Paragraph {
            inlines: vec![link("/url", None, vec![t("foo")])]
        }]
    );
}

#[test]
fn shortcut_ref_link() {
    let input = "[foo]\n\n[foo]: /url";
    assert_eq!(
        parse_blocks(input),
        vec![Block::Paragraph {
            inlines: vec![link("/url", None, vec![t("foo")])]
        }]
    );
}

#[test]
fn ref_link_case_insensitive() {
    let input = "[Foo]\n\n[foo]: /url";
    assert_eq!(
        parse_blocks(input),
        vec![Block::Paragraph {
            inlines: vec![link("/url", None, vec![t("Foo")])]
        }]
    );
}

#[test]
fn missing_ref_falls_through_to_text() {
    let input = "[foo][bar]";
    let blocks = parse(input).blocks;
    assert_eq!(
        blocks,
        vec![Block::Paragraph {
            inlines: vec![t("[foo][bar]")]
        }]
    );
}

// ----- Non-ASCII UTF-8 in links --------------------------------------

#[test]
fn inline_link_non_ascii_dest_bare() {
    assert_eq!(
        parse_inlines("[foo](/日本語🦫)"),
        vec![link("/日本語🦫", None, vec![t("foo")])]
    );
}

#[test]
fn inline_link_non_ascii_dest_bracketed() {
    assert_eq!(
        parse_inlines("[foo](</日本語🦫>)"),
        vec![link("/日本語🦫", None, vec![t("foo")])]
    );
}

#[test]
fn inline_link_non_ascii_title() {
    assert_eq!(
        parse_inlines("[foo](/u \"日本語🦫\")"),
        vec![link("/u", Some("日本語🦫"), vec![t("foo")])]
    );
}

#[test]
fn shortcut_ref_link_non_ascii_label() {
    let input = "[日本語🦫]\n\n[日本語🦫]: /url";
    assert_eq!(
        parse_blocks(input),
        vec![Block::Paragraph {
            inlines: vec![link("/url", None, vec![t("日本語🦫")])]
        }]
    );
}

// ----- Nested-link prevention ----------------------------------------

#[test]
fn no_nested_links() {
    // `[a [b](/u1) c](/u2)` — the inner `[b](/u1)` link absorbs and
    // deactivates the outer `[`, so the outer text becomes literal.
    let input = "[a [b](/u1) c](/u2)";
    let parsed = parse_inlines(input);
    // Expect: literal "[a ", inner link, literal " c](/u2)"
    assert_eq!(
        parsed,
        vec![t("[a "), link("/u1", None, vec![t("b")]), t(" c](/u2)"),]
    );
}

// ----- Image alt with nested link ------------------------------------

#[test]
fn image_alt_can_contain_link_text() {
    // Inside an image, links DO render (per spec); the outer image
    // wraps everything.
    assert_eq!(
        parse_inlines("![see [a](/u)](/img)"),
        vec![image(
            "/img",
            None,
            vec![t("see "), link("/u", None, vec![t("a")])]
        )]
    );
}
