//! `marmot-markdown` — a hand-written, near-zero-dependency CommonMark parser
//! that emits an abstract syntax tree.
//!
//! ## Goals
//!
//! 1. **Simplicity.** Straight-line parsing, no clever abstractions, no
//!    speculative generality.
//! 2. **Near-zero dependencies.** The only library dependency is `serde`
//!    for AST (de)serialization.
//! 3. **First-class nostr.** Two extra inline node types —
//!    [`Inline::NostrMention`] for bare `@npub1…` handles, and
//!    [`Inline::NostrUri`] for explicit `nostr:<hrp>1…` references —
//!    parsed inline alongside links and emphasis.
//!
//! ## Architecture
//!
//! Two passes that are never fused:
//!
//! - **Pass 1 — block structure** ([`block`]): walks the input line by
//!   line, maintaining a stack of open containers (blockquote, list,
//!   list item) and at most one open leaf (paragraph, code, math, or
//!   table). Link-reference definitions are harvested at paragraph
//!   close.
//! - **Pass 2 — inline tokenization** ([`inline`]): walks the block tree
//!   and replaces each leaf's raw text with a `Vec<Inline>`. Emphasis,
//!   strikethrough, and links go through the spec's delimiter-stack +
//!   `process_emphasis` algorithm.
//!
//! ## HTML is not parsed
//!
//! Unlike CommonMark proper, this parser **does not** recognize general HTML
//! blocks or raw HTML inlines. Tag-like sequences (`<div>`, `<!-- ... -->`,
//! etc.) are passed through as literal text and HTML-escaped at render
//! time. Only autolinks — `<scheme:body>` and `<email@host>` — get
//! structured treatment, plus a bounded [`Block::Details`] extension for
//! structural `<details>` / `<summary>` lines (see the crate README).
//!
//! ## Untrusted destinations
//!
//! Link, image, and autolink destinations are preserved and classified with
//! [`LinkDestinationKind`]. Classification is descriptive, not permission to
//! navigate or fetch. Renderers must inspect it before binding a destination
//! to a WebView, OS opener, deep-link handler, or image loader. Dangerous and
//! sensitive destinations should remain inert by default; recognized families
//! still require the client's normal navigation, privacy, and network policy.
//!
//! ## Example
//!
//! ```
//! use marmot_markdown::{Block, Inline, parse};
//!
//! let doc = parse("# Hi *there*");
//! assert!(matches!(
//!     doc.blocks.as_slice(),
//!     [Block::Heading { level: 1, .. }]
//! ));
//! ```
//!
//! All AST types implement `Serialize` and `Deserialize` unconditionally.

pub mod ast;
mod block;
mod destination;
mod details;
mod entity;
mod inline;
mod nostr;
mod scanner;

/// Maximum nested block-container depth emitted by the parser.
pub const MAX_CONTAINER_DEPTH: usize = block::MAX_CONTAINER_DEPTH;

/// Maximum blank-line source gap retained before a block.
pub const MAX_SOURCE_BLANK_LINES: u8 = block::MAX_SOURCE_BLANK_LINES;

pub use ast::{
    Alignment, AutolinkKind, Block, CodeBlockKind, Document, Inline, LinkDestinationKind, ListItem,
    ListKind, NostrEntity, NostrHrp, TableCell,
};
pub use destination::classify_link_destination;

/// Parse a CommonMark document (with this crate's nostr and GFM extensions)
/// into a [`Document`].
///
/// Recognized extensions on top of CommonMark 0.31:
///
/// - GFM tables (`| h | k |\n| - | - |\n| 1 | 2 |`).
/// - GFM strikethrough (`~~foo~~`).
/// - GFM task-list items (`- [ ]`, `- [x]`).
/// - Bare URLs (GFM-style extended autolinks) for the schemes `http://`,
///   `https://`, `mailto:`, `tel:`, `marmot://`, `whitenoise://`, and
///   `whitenoise-staging://`, plus bare `www.` host/path forms. `www.`
///   autolinks preserve their source text; renderers synthesize an `https://`
///   launch destination. Recognized at word boundaries; trailing punctuation
///   (`.,;:!?*_~` and unbalanced `)`) is excluded from the matched URL. Opaque
///   app-scheme forms like `marmot:foo` and `whitenoise:foo` (no `//`) stay
///   literal.
/// - Math: inline `$…$` and block `$$ … $$` (content is opaque — recognized
///   but never parsed as LaTeX).
/// - Bounded `<details>` / `<summary>` disclosure blocks. The opener and
///   closer each occupy their own logical line after quote/list prefixes and
///   at most three columns of local indent. Compact one-line HTML stays
///   literal. Recognition is limited to a 65536-byte original-source prefix
///   and a 4096-byte structural tag cap. Missing or empty summaries yield an
///   empty `summary` list; clients may localize a fallback label. Failed
///   candidates remain ordinary Markdown with their tags literal.
/// - Nostr bare mentions (`@npub1…`) and URIs (`nostr:<hrp>1…`) for the
///   whitelisted HRPs `npub`, `note`, `nevent`, `nprofile`, `naddr`,
///   `nrelay`. `nsec` is deliberately rejected from the ergonomic
///   [`Inline::NostrMention`] / [`Inline::NostrUri`] entity forms. Bare
///   `nostr:` URIs whose body isn't valid bech32 stay as literal text (they are
///   *not* downgraded to a generic bare-URL autolink). When private-key text is
///   deliberately used as an explicit destination or angle-bracket autolink,
///   it is preserved with [`LinkDestinationKind::Sensitive`] so the client can
///   display it without making it actionable.
///
/// Bech32 strings are validated for *shape* only (no checksum).
pub fn parse(input: &str) -> Document {
    let (blocks, blank_lines_before, refs) = block::parse_blocks(input);
    inline::parse_inlines(blocks, blank_lines_before, &refs)
}

#[cfg(test)]
mod details_work_tests {
    use super::*;
    use crate::details::Work;

    #[test]
    fn many_failed_openers_stay_linear() {
        let mut md = String::new();
        for _ in 0..200 {
            md.push_str("<details>\n");
        }
        md.push_str("tail\n");
        let doc = parse(&md);
        assert!(
            !doc.blocks
                .iter()
                .any(|b| matches!(b, Block::Details { .. }))
        );
        let work = Work::get();
        assert!(
            work < 200 * 64,
            "failed openers must not rescan quadratically, work={work}"
        );
    }

    #[test]
    fn unmatched_backtick_first_line_stays_linear() {
        use crate::details::MAX_DETAILS_SCAN_BYTES;
        let mut prev = 0usize;
        for n in [4_000usize, 8_000, 16_000, 32_000] {
            Work::reset();
            let md = format!("<details>\n{}\n</details>", "`".repeat(n));
            let _ = parse(&md);
            let work = Work::get();
            assert!(
                work <= n * 16 + 4_096,
                "backtick close-search must stay linear, n={n} work={work}"
            );
            if prev > 0 {
                assert!(
                    work <= prev.saturating_mul(3),
                    "work must not jump quadratically, n={n} prev={prev} work={work}"
                );
            }
            prev = work;
        }
        Work::reset();
        let near_cap = 65_519.min(MAX_DETAILS_SCAN_BYTES.saturating_sub(16));
        let md = format!("<details>\n{}\n</details>", "`".repeat(near_cap));
        let _ = parse(&md);
        let work = Work::get();
        assert!(
            work <= near_cap * 16 + 4_096,
            "FFI-cap backtick line must stay linear, work={work}"
        );
    }

    #[test]
    fn summary_opener_plus_backticks_stays_linear() {
        let mut prev = 0usize;
        for n in [4_000usize, 8_000, 16_000, 32_000] {
            Work::reset();
            let md = format!("<details>\n<summary>{}\n</details>", "`".repeat(n));
            let _ = parse(&md);
            let work = Work::get();
            assert!(
                work <= n * 16 + 4_096,
                "summary+backtick search must stay linear, n={n} work={work}"
            );
            if prev > 0 {
                assert!(
                    work <= prev.saturating_mul(3),
                    "work must not jump quadratically, n={n} prev={prev} work={work}"
                );
            }
            prev = work;
        }
    }

    #[test]
    fn unequal_backtick_runs_stay_linear() {
        Work::reset();
        let mut md = String::from("<details>\n<summary>");
        for len in 1..=64 {
            md.push_str(&"`".repeat(len));
            md.push('x');
        }
        md.push_str("\n</details>");
        let _ = parse(&md);
        let work = Work::get();
        assert!(
            work < 64 * 64 * 8,
            "unequal run lengths must not rescan suffixes, work={work}"
        );
    }

    #[test]
    fn multiline_scanner_actual_work_is_linear() {
        let mut prev = 0usize;
        for n in [1_000usize, 2_000, 4_000, 8_000] {
            Work::reset();
            let mut md = String::from("<details>\n<summary>\n");
            for _ in 0..n {
                md.push_str("x\n");
            }
            md.push_str("</details>");
            let _ = parse(&md);
            let work = Work::get();
            let bytes = md.len();
            assert!(
                work <= bytes * 16 + 4_096,
                "multiline continuation must stay linear, n={n} bytes={bytes} work={work}"
            );
            if prev > 0 {
                assert!(
                    work <= prev.saturating_mul(3),
                    "work must not jump quadratically, n={n} prev={prev} work={work}"
                );
            }
            prev = work;
        }
        Work::reset();
        let near_cap = 32_000usize;
        let mut md = String::from("<details>\n<summary>\n");
        for _ in 0..near_cap {
            md.push_str("x\n");
        }
        let bytes = md.len();
        let _ = parse(&md);
        let work = Work::get();
        assert!(
            work <= bytes * 16 + 4_096,
            "many-line open summary near the FFI cap must stay linear, bytes={bytes} work={work}"
        );
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

    #[test]
    fn bounded_summary_never_copies_unbounded_suffix() {
        Work::reset();
        let huge = format!("<summary>{}", "z".repeat(1_000_000));
        let classified = crate::details::parse_summary_line_bounded(&huge, 16);
        assert!(matches!(
            classified,
            crate::details::SummaryLine::OpenOnly { .. }
        ));
        let work = Work::get();
        assert!(
            work < 8_192,
            "a 16-byte budget must not copy a 1MB suffix, work={work}"
        );
    }
}
