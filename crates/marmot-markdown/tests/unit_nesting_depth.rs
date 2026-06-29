//! Regression tests for darkmatter#208 — unbounded inline emphasis nesting
//! depth crashed the recipient via a stack-overflow abort.
//!
//! The block parser caps container nesting at `MAX_CONTAINER_DEPTH`, but inline
//! emphasis / strong / strikethrough nesting was unbounded. Input of the shape
//! `'*' * N + 'a' + '*' * N` builds a chain of nested Strong/Emph nodes of
//! depth ~N/2, which then overflowed the thread stack inside `parse()` itself
//! (recursive `coalesce_text_runs`), the derived serde (de)serialization, and
//! the `marmot-uniffi` `From` conversions — a fatal, uncatchable abort that
//! any group member could trigger on others with one message.
//!
//! The fix caps inline nesting depth at parse time, leaving excess delimiters
//! as literal text. These tests pin that behavior: a process abort would crash
//! the test binary (SIGABRT), so simply returning from `parse()` is the pass
//! condition for the pathological inputs.

use marmot_markdown::{Block, Inline, parse};

/// Maximum inline nesting depth the parser is allowed to emit. Mirrors the
/// crate-internal `MAX_INLINE_NESTING_DEPTH`; kept as a local constant because
/// the parser's value is not part of the public API.
const DEPTH_CEILING: usize = 96;

/// Iteratively measure the deepest inline nesting in a document. Recursive
/// measurement would itself risk overflowing on a hostile tree, so this uses
/// an explicit stack.
fn max_inline_depth(doc: &marmot_markdown::Document) -> usize {
    let mut max = 0usize;
    // (slice, index, depth-of-this-slice)
    let mut block_stack: Vec<(&[Block], usize)> = vec![(doc.blocks.as_slice(), 0)];
    let mut inline_stack: Vec<(&[Inline], usize, usize)> = Vec::new();

    // Drain all blocks, seeding inline walks from each leaf's inlines.
    while let Some(&mut (blocks, ref mut bi)) = block_stack.last_mut() {
        if *bi >= blocks.len() {
            block_stack.pop();
            continue;
        }
        let block = &blocks[*bi];
        *bi += 1;
        match block {
            Block::Paragraph { inlines } | Block::Heading { inlines, .. } => {
                inline_stack.push((inlines.as_slice(), 0, 1));
                walk_inlines(&mut inline_stack, &mut max);
            }
            Block::BlockQuote { blocks } => block_stack.push((blocks.as_slice(), 0)),
            Block::List { items, .. } => {
                for item in items {
                    block_stack.push((item.blocks.as_slice(), 0));
                }
            }
            Block::Table { header, rows, .. } => {
                for cell in header {
                    inline_stack.push((cell.inlines.as_slice(), 0, 1));
                    walk_inlines(&mut inline_stack, &mut max);
                }
                for row in rows {
                    for cell in row {
                        inline_stack.push((cell.inlines.as_slice(), 0, 1));
                        walk_inlines(&mut inline_stack, &mut max);
                    }
                }
            }
            _ => {}
        }
    }
    max
}

fn walk_inlines(stack: &mut Vec<(&[Inline], usize, usize)>, max: &mut usize) {
    while let Some(&mut (slice, ref mut idx, depth)) = stack.last_mut() {
        if *idx >= slice.len() {
            stack.pop();
            continue;
        }
        let item = &slice[*idx];
        *idx += 1;
        *max = (*max).max(depth);
        let children = match item {
            Inline::Emph(c) | Inline::Strong(c) | Inline::Strikethrough(c) => Some(c.as_slice()),
            Inline::Link { children, .. } => Some(children.as_slice()),
            Inline::Image { alt, .. } => Some(alt.as_slice()),
            _ => None,
        };
        if let Some(children) = children {
            stack.push((children, 0, depth + 1));
        }
    }
}

fn nested_stars(n: usize) -> String {
    let mut s = String::with_capacity(2 * n + 1);
    s.push_str(&"*".repeat(n));
    s.push('a');
    s.push_str(&"*".repeat(n));
    s
}

/// `"![" * n + "a" + "](x)" * n` — the nested-image attack shape from the
/// adversarial review of darkmatter#208. Each `](x)` closes one image and
/// wraps the prior content as its alt text, building image nesting of depth
/// ~n+1 unless capped.
fn nested_images(n: usize) -> String {
    let mut s = String::with_capacity(6 * n + 1);
    s.push_str(&"![".repeat(n));
    s.push('a');
    s.push_str(&"](x)".repeat(n));
    s
}

#[test]
fn deeply_nested_emphasis_does_not_overflow_parse() {
    // Pre-fix: aborts with "stack overflow" at this size on a 2 MiB stack.
    let doc = parse(&nested_stars(100_000));
    // Reaching here means parse() did not abort. Depth must be bounded.
    assert!(
        max_inline_depth(&doc) <= DEPTH_CEILING,
        "inline depth exceeded the cap"
    );
}

#[test]
fn deeply_nested_emphasis_serializes_without_overflow() {
    // Pre-fix: serde_json *serialization* aborts at N≈48000 on a 2 MiB stack
    // (a fatal, uncatchable SIGABRT). The fix bounds tree depth so serialize
    // always completes. Reaching the assert means no abort occurred.
    let doc = parse(&nested_stars(48_000));
    let json = serde_json::to_string(&doc).expect("serialize");
    assert!(!json.is_empty());

    // Deserialization of a max-depth tree is *catchably* rejected by
    // serde_json's own recursion limit (128 JSON levels) — never a crash. The
    // pre-existing block-container cap (MAX_CONTAINER_DEPTH = 96) has the exact
    // same property, so this is established, accepted behavior: the security
    // contract is "no abort", not "round-trips at max depth". Accept either a
    // successful parse or a graceful recursion-limit error.
    match serde_json::from_str::<marmot_markdown::Document>(&json) {
        Ok(back) => assert!(max_inline_depth(&back) <= DEPTH_CEILING),
        Err(e) => assert!(
            e.to_string().contains("recursion limit"),
            "unexpected deserialize error: {e}"
        ),
    }
}

#[test]
fn deeply_nested_strikethrough_does_not_overflow() {
    let n = 100_000;
    let mut s = String::with_capacity(2 * n + 1);
    s.push_str(&"~".repeat(n));
    s.push('a');
    s.push_str(&"~".repeat(n));
    let doc = parse(&s);
    assert!(max_inline_depth(&doc) <= DEPTH_CEILING);
}

#[test]
fn deeply_nested_images_do_not_overflow_parse() {
    // Adversarial review of darkmatter#208: the emphasis-only cap left the
    // link/image wrapping path (`absorb_link`) unguarded, so `"![" * N + "a"
    // + "](x)" * N` still built image nesting of depth ~N and aborted in
    // parse()/serde/uniffi. Run on a deliberately small (1 MiB) stack so an
    // unbounded tree reliably overflows — matching the original attack model
    // (recipient threads with modest stacks). Reaching the assert means no
    // abort; depth must be bounded by the cap.
    let handle = std::thread::Builder::new()
        .stack_size(1024 * 1024)
        .spawn(|| {
            let doc = parse(&nested_images(48_000));
            let depth = max_inline_depth(&doc);
            assert!(
                depth <= DEPTH_CEILING,
                "image nesting depth {depth} exceeded the cap"
            );
            // Serialization walks the same tree and previously aborted too.
            let json = serde_json::to_string(&doc).expect("serialize");
            assert!(!json.is_empty());
        })
        .expect("spawn");
    handle
        .join()
        .expect("nested-image parse panicked or aborted");
}

#[test]
fn excess_image_delimiters_stay_literal_not_dropped() {
    // When wrapping would exceed the cap, the closing `]` is left as literal
    // text rather than silently dropping content. The single `a` must always
    // survive, and excess `]`/`[` characters must remain as literal text.
    let n = 4_000;
    let doc = parse(&nested_images(n));
    let mut letters = 0usize;
    let mut brackets = 0usize;
    // Iterative leaf walk over every recursive inline container.
    let mut stack: Vec<&Inline> = Vec::new();
    for block in &doc.blocks {
        if let Block::Paragraph { inlines } = block {
            stack.extend(inlines.iter());
        }
    }
    while let Some(item) = stack.pop() {
        match item {
            Inline::Text(s) => {
                letters += s.bytes().filter(|&b| b == b'a').count();
                brackets += s.bytes().filter(|&b| b == b']' || b == b'[').count();
            }
            Inline::Emph(c) | Inline::Strong(c) | Inline::Strikethrough(c) => {
                stack.extend(c.iter());
            }
            Inline::Link { children, .. } => stack.extend(children.iter()),
            Inline::Image { alt, .. } => stack.extend(alt.iter()),
            _ => {}
        }
    }
    assert_eq!(letters, 1, "the single literal letter must survive");
    assert!(
        brackets > 0,
        "excess bracket delimiters must remain as literal text"
    );
}

#[test]
fn shallow_image_nesting_still_parses_normally() {
    // A modestly nested image (well under the cap) must still wrap as an
    // Image with the inner image as its alt content.
    let doc = parse("![![a](inner)](outer)");
    let Block::Paragraph { inlines } = &doc.blocks[0] else {
        panic!("expected paragraph");
    };
    let Inline::Image { alt, dest, .. } = &inlines[0] else {
        panic!("expected outer image, got {:?}", inlines[0]);
    };
    assert_eq!(dest, "outer");
    assert!(
        matches!(alt.as_slice(), [Inline::Image { .. }]),
        "outer image alt should contain the inner image"
    );
}

#[test]
fn image_nesting_can_reach_depth_ceiling_without_off_by_one() {
    // Link/image delimiter tracking is capped to the same value as emitted
    // inline nesting. A cap one lower would reject the legitimate max-depth
    // image tree; a cap one higher would keep useless openers that can never
    // produce a deeper display tree.
    let doc = parse(&nested_images(DEPTH_CEILING - 1));
    assert_eq!(max_inline_depth(&doc), DEPTH_CEILING);
}

#[test]
fn excess_emphasis_delimiters_stay_literal_not_dropped() {
    // The cap leaves un-paired delimiter runs as literal text rather than
    // silently discarding content. Concatenating all Text leaves must recover
    // every `*` and the `a`.
    let n = 100_000;
    let doc = parse(&nested_stars(n));
    let mut stars = 0usize;
    let mut letters = 0usize;
    // Iterative leaf walk.
    let mut stack: Vec<&Inline> = Vec::new();
    for block in &doc.blocks {
        if let Block::Paragraph { inlines } = block {
            stack.extend(inlines.iter());
        }
    }
    while let Some(item) = stack.pop() {
        match item {
            Inline::Text(s) => {
                stars += s.bytes().filter(|&b| b == b'*').count();
                letters += s.bytes().filter(|&b| b == b'a').count();
            }
            Inline::Emph(c) | Inline::Strong(c) | Inline::Strikethrough(c) => {
                stack.extend(c.iter());
            }
            _ => {}
        }
    }
    // Each successful pairing consumes delimiter chars from the literal text
    // but re-homes them as structure; the `a` is always preserved. The total
    // `*` retained as literal text is whatever the depth cap left unpaired.
    assert_eq!(letters, 1, "the single literal letter must survive");
    assert!(stars > 0, "excess delimiters must remain as literal text");
}

// ----- Ordinary nesting is unaffected by the cap -------------------------

#[test]
fn shallow_nesting_still_parses_normally() {
    // `***foo***` → Em(Strong(foo)); well under the cap, must be untouched.
    let doc = parse("***foo***");
    let Block::Paragraph { inlines } = &doc.blocks[0] else {
        panic!("expected paragraph");
    };
    assert_eq!(
        inlines,
        &vec![Inline::Emph(vec![Inline::Strong(vec![Inline::Text(
            "foo".to_string()
        )])])]
    );
}

#[test]
fn nesting_just_under_cap_is_preserved() {
    // Build genuine alternating nesting a few levels deep and confirm the
    // structure is retained (cap only bites at MAX_INLINE_NESTING_DEPTH).
    let depth = 10;
    let mut s = String::new();
    for _ in 0..depth {
        s.push('*');
    }
    s.push('a');
    for _ in 0..depth {
        s.push('*');
    }
    let doc = parse(&s);
    let d = max_inline_depth(&doc);
    assert!(d >= 2, "modest nesting should still produce nested nodes");
    assert!(d <= DEPTH_CEILING);
}
