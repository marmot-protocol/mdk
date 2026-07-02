//! Pass 2: inline tokenization.
//!
//! Walks the block tree and replaces each leaf block's single raw
//! `Inline::Text` with a tokenized `Vec<Inline>`. Phase 5 covers text,
//! backslash escapes, code spans, inline math, entity references, and
//! hard/soft line breaks. Emphasis, links, autolinks, raw HTML, and nostr
//! nodes are added in later phases.

use std::collections::HashMap;

use crate::ast::{
    AutolinkKind, Block, Document, Inline, ListItem, NostrEntity, NostrHrp, TableCell,
};
use crate::block::LinkRef;
use crate::entity;
use crate::nostr;
use crate::scanner;

/// ASCII bytes that have a dedicated arm in `tokenize`'s dispatch match.
/// Keep in sync with the explicit match arms — used as the exit condition
/// for the plain-byte fast-scan in the `_` wildcard arm.
///
/// `d`, `h`, `m`, `t`, `w` are tripwires for bare-URL schemes (`darkmatter://`,
/// `http(s)://`, `mailto:`, `tel:`, `whitenoise:`); the bulk-scan rescue below keeps the
/// fast path for the overwhelmingly common case of ordinary prose containing
/// those letters.
const INLINE_SPECIAL: [bool; 128] = {
    let mut t = [false; 128];
    let chars = b"\\`$&[!*_~]<@ndhmtw\n";
    let mut k = 0;
    while k < chars.len() {
        t[chars[k] as usize] = true;
        k += 1;
    }
    t
};

/// Maximum inline emphasis / strong / strikethrough (and link/image) nesting
/// depth the tokenizer will build. The analogue of [`crate::MAX_CONTAINER_DEPTH`]
/// for inline content. Delimiter runs that would nest past this depth are left
/// as literal text.
///
/// This bounds the recursion depth of every consumer that walks the inline
/// tree — the derived `serde` (de)serialization, the `marmot-uniffi` `From`
/// conversions, and `coalesce_text_runs` — so that hostile input cannot drive
/// any of them into a stack-overflow abort (a fatal, uncatchable crash). See
/// darkmatter#208.
pub(crate) const MAX_INLINE_NESTING_DEPTH: usize = 96;

/// Maximum number of simultaneously-open link/image bracket delimiters kept on
/// the delimiter stack. Excess openers remain literal text. This mirrors the
/// emitted inline nesting cap: a deeper bracket stack cannot produce valid
/// display nesting, and keeping it unbounded lets hostile input spend quadratic
/// time repeatedly searching/dropping unmatched openers (darkmatter#654).
const MAX_OPEN_BRACKET_DELIMITERS: usize = MAX_INLINE_NESTING_DEPTH;

/// Returns `true` if any inline in `items` is nested at least `cap` levels
/// deep, counting the items in `items` themselves as level 1.
///
/// Iterative, explicit-stack walk that prunes as soon as the cap is reached,
/// so it is cheap (`O(cap)`) on the hostile single-chain input and — unlike a
/// recursive walk — cannot itself overflow the stack.
fn nesting_depth_at_least(items: &[Inline], cap: usize) -> bool {
    if cap == 0 {
        return true;
    }
    if cap == 1 {
        return !items.is_empty();
    }
    // Each frame: (slice, next index into slice, depth of this slice's items).
    let mut stack: Vec<(&[Inline], usize, usize)> = vec![(items, 0, 1)];
    while let Some(&mut (slice, ref mut idx, depth)) = stack.last_mut() {
        if *idx >= slice.len() {
            stack.pop();
            continue;
        }
        let item = &slice[*idx];
        *idx += 1;
        let children = inline_children(item);
        if let Some(children) = children {
            if depth + 1 >= cap {
                return true;
            }
            stack.push((children, 0, depth + 1));
        }
    }
    false
}

fn inline_children(item: &Inline) -> Option<&[Inline]> {
    match item {
        Inline::Emph(c) | Inline::Strong(c) | Inline::Strikethrough(c) => Some(c.as_slice()),
        Inline::Link { children, .. } => Some(children.as_slice()),
        Inline::Image { alt, .. } => Some(alt.as_slice()),
        _ => None,
    }
}

pub(crate) fn parse_inlines(blocks: Vec<Block>, refs: &HashMap<String, LinkRef>) -> Document {
    Document {
        blocks: walk_blocks(blocks, refs),
    }
}

fn walk_blocks(blocks: Vec<Block>, refs: &HashMap<String, LinkRef>) -> Vec<Block> {
    blocks.into_iter().map(|b| walk(b, refs)).collect()
}

// `refs` is threaded through here so Phase 8 (links) can resolve reference
// labels; emphasis (Phase 9) etc. don't use it.
fn walk(block: Block, refs: &HashMap<String, LinkRef>) -> Block {
    match block {
        Block::Paragraph { inlines } => Block::Paragraph {
            inlines: tokenize(&extract_raw(inlines), refs),
        },
        Block::Heading { level, inlines } => Block::Heading {
            level,
            inlines: tokenize(&extract_raw(inlines), refs),
        },
        Block::BlockQuote { blocks } => Block::BlockQuote {
            blocks: walk_blocks(blocks, refs),
        },
        Block::List { kind, tight, items } => Block::List {
            kind,
            tight,
            items: items
                .into_iter()
                .map(|item| ListItem {
                    blocks: walk_blocks(item.blocks, refs),
                    checked: item.checked,
                })
                .collect(),
        },
        Block::Table {
            alignments,
            header,
            rows,
        } => Block::Table {
            alignments,
            header: header
                .into_iter()
                .map(|cell| TableCell {
                    inlines: tokenize(&extract_raw(cell.inlines), refs),
                })
                .collect(),
            rows: rows
                .into_iter()
                .map(|row| {
                    row.into_iter()
                        .map(|cell| TableCell {
                            inlines: tokenize(&extract_raw(cell.inlines), refs),
                        })
                        .collect()
                })
                .collect(),
        },
        // Code blocks, HTML blocks, math blocks, thematic breaks don't
        // tokenize here.
        b => b,
    }
}

fn extract_raw(inlines: Vec<Inline>) -> String {
    match inlines.into_iter().next() {
        Some(Inline::Text(s)) => s,
        _ => String::new(),
    }
}

#[derive(Debug, Clone, Copy)]
struct BracketDelim {
    /// `b'['` link opener, `b'!'` image opener, `b'*'`/`b'_'`/`b'~'`
    /// emphasis-or-strikethrough run.
    kind: u8,
    /// Index in `out` of the Text node holding this delimiter's
    /// characters. For brackets: a placeholder Text("[" / "!["). For
    /// runs: a Text containing the run's chars.
    out_pos: usize,
    /// Index in `bytes` of the leading character (for brackets, the `[`).
    input_pos: usize,
    /// True while the delimiter can still participate in matching.
    active: bool,
    /// For runs: original run length (frozen for rule-of-three).
    orig_len: usize,
    /// For runs: remaining length.
    len: usize,
    /// For runs: can this run open / close emphasis?
    can_open: bool,
    can_close: bool,
    /// Previous active link/image bracket delimiter at the time this delimiter
    /// was pushed. Maintained only for `[` / `![` delimiters so bracket closing
    /// and link-opener deactivation can walk bracket delimiters directly instead
    /// of rescanning the full mixed delimiter vector on every `]` or link wrap.
    prev_bracket: Option<usize>,
}

impl BracketDelim {
    fn bracket(kind: u8, out_pos: usize, input_pos: usize, prev_bracket: Option<usize>) -> Self {
        Self {
            kind,
            out_pos,
            input_pos,
            active: true,
            orig_len: 0,
            len: 0,
            can_open: false,
            can_close: false,
            prev_bracket,
        }
    }
}

/// Tokenize the raw paragraph/heading text. First-match-wins.
pub(crate) fn tokenize(raw: &str, refs: &HashMap<String, LinkRef>) -> Vec<Inline> {
    let bytes = raw.as_bytes();
    let mut out: Vec<Inline> = Vec::new();
    // Entity decoding only ever shrinks bytes (e.g. `&amp;` → `&`), so
    // `raw.len()` is a safe upper bound. Pre-sizing avoids the doubling
    // reallocation chain (4→8→16→…) as the first text run accumulates.
    let mut buf = String::with_capacity(raw.len());
    let mut delims: Vec<BracketDelim> = Vec::new();
    let mut last_bracket_delim: Option<usize> = None;
    let mut open_bracket_delims = 0usize;
    let mut i = 0;
    let mut inline_math_closer_exhausted = false;

    // Try a "consume an Inline or fall back to a literal byte" recognizer.
    // Used for the recognizers whose only failure mode is "didn't match —
    // treat the lead byte as text". Keeps the dispatch table readable.
    macro_rules! try_or_literal {
        ($lit:literal, $try:expr, $wrap:expr) => {
            match $try {
                Some((v, end)) => {
                    flush_text(&mut out, &mut buf, &delims);
                    out.push($wrap(v));
                    i = end;
                }
                None => {
                    buf.push($lit);
                    i += 1;
                }
            }
        };
    }

    while i < bytes.len() {
        let c = bytes[i];
        match c {
            b'\\' => {
                if i + 1 < bytes.len() {
                    let next = bytes[i + 1];
                    if next == b'\n' {
                        flush_text(&mut out, &mut buf, &delims);
                        out.push(Inline::HardBreak);
                        i += 2;
                        // Skip leading whitespace on next line (paragraph
                        // continuations should already have it stripped,
                        // but be defensive).
                        while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
                            i += 1;
                        }
                        continue;
                    }
                    if scanner::is_ascii_punct(next) {
                        buf.push(next as char);
                        i += 2;
                        continue;
                    }
                }
                buf.push('\\');
                i += 1;
            }
            b'`' => {
                if let Some((content, end)) = try_code_span(bytes, i) {
                    flush_text(&mut out, &mut buf, &delims);
                    out.push(Inline::Code(content));
                    i = end;
                } else {
                    let end = skip_backtick_run(bytes, i);
                    buf.push_str(std::str::from_utf8(&bytes[i..end]).unwrap_or(""));
                    i = end;
                }
            }
            b'$' if inline_math_closer_exhausted => {
                buf.push('$');
                i += 1;
            }
            b'$' => match try_inline_math(bytes, i) {
                InlineMathScan::Matched { content, end } => {
                    flush_text(&mut out, &mut buf, &delims);
                    out.push(Inline::Math(content));
                    i = end;
                }
                InlineMathScan::NoMatch => {
                    buf.push('$');
                    i += 1;
                }
                InlineMathScan::NoCloserInSuffix => {
                    inline_math_closer_exhausted = true;
                    buf.push('$');
                    i += 1;
                }
            },
            b'&' => match entity::decode(bytes, i) {
                Some((decoded, end)) => {
                    // Entities decode straight into the text buffer (no
                    // flush) so adjacent literal bytes stay coalesced.
                    buf.push_str(&decoded);
                    i = end;
                }
                None => {
                    buf.push('&');
                    i += 1;
                }
            },
            b'[' => {
                if open_bracket_delims < MAX_OPEN_BRACKET_DELIMITERS {
                    flush_text(&mut out, &mut buf, &delims);
                    let out_pos = out.len();
                    out.push(Inline::Text("[".to_string()));
                    let delim_idx = delims.len();
                    delims.push(BracketDelim::bracket(b'[', out_pos, i, last_bracket_delim));
                    last_bracket_delim = Some(delim_idx);
                    open_bracket_delims += 1;
                } else {
                    buf.push('[');
                }
                i += 1;
            }
            b'!' if bytes.get(i + 1) == Some(&b'[') => {
                if open_bracket_delims < MAX_OPEN_BRACKET_DELIMITERS {
                    flush_text(&mut out, &mut buf, &delims);
                    let out_pos = out.len();
                    out.push(Inline::Text("![".to_string()));
                    let delim_idx = delims.len();
                    delims.push(BracketDelim::bracket(
                        b'!',
                        out_pos,
                        i + 1,
                        last_bracket_delim,
                    ));
                    last_bracket_delim = Some(delim_idx);
                    open_bracket_delims += 1;
                } else {
                    buf.push_str("![");
                }
                i += 2;
            }
            b'*' | b'_' | b'~' => {
                flush_text(&mut out, &mut buf, &delims);
                let (run_len, can_open, can_close) = classify_delim_run(bytes, i, c);
                let out_pos = out.len();
                out.push(Inline::Text(
                    std::str::from_utf8(&bytes[i..i + run_len])
                        .unwrap()
                        .to_string(),
                ));
                delims.push(BracketDelim {
                    kind: c,
                    out_pos,
                    input_pos: i,
                    active: true,
                    orig_len: run_len,
                    len: run_len,
                    can_open,
                    can_close,
                    prev_bracket: None,
                });
                i += run_len;
            }
            b']' => {
                flush_text(&mut out, &mut buf, &delims);
                if let Some(end) = try_close_bracket(
                    bytes,
                    i,
                    &mut out,
                    &mut delims,
                    &mut last_bracket_delim,
                    &mut open_bracket_delims,
                    refs,
                ) {
                    i = end;
                } else {
                    buf.push(']');
                    i += 1;
                }
            }
            b'<' => {
                if let Some((url, end)) = try_uri_autolink(bytes, i) {
                    flush_text(&mut out, &mut buf, &delims);
                    out.push(Inline::Autolink {
                        url,
                        kind: AutolinkKind::Uri,
                    });
                    i = end;
                } else if let Some((url, end)) = try_email_autolink(bytes, i) {
                    flush_text(&mut out, &mut buf, &delims);
                    out.push(Inline::Autolink {
                        url,
                        kind: AutolinkKind::Email,
                    });
                    i = end;
                } else {
                    // Unrecognized `<` — emit as literal text. HTML is NOT
                    // parsed; tag-like sequences pass through unchanged.
                    buf.push('<');
                    i += 1;
                }
            }
            b'@' => try_or_literal!('@', try_nostr_mention(bytes, i), Inline::NostrMention),
            b'n' => {
                if let Some((entity, end)) = try_nostr_uri(bytes, i) {
                    flush_text(&mut out, &mut buf, &delims);
                    out.push(Inline::NostrUri(entity));
                    i = end;
                } else if let Some((entity, end)) = try_nostr_bare_mention(bytes, i) {
                    flush_text(&mut out, &mut buf, &delims);
                    out.push(Inline::NostrMention(entity));
                    i = end;
                } else {
                    buf.push('n');
                    i += 1;
                }
            }
            b'd' | b'h' | b'm' | b't' | b'w' => {
                if let Some((url, end)) = try_bare_url(bytes, i) {
                    flush_text(&mut out, &mut buf, &delims);
                    out.push(Inline::Autolink {
                        url,
                        kind: AutolinkKind::Uri,
                    });
                    i = end;
                } else {
                    buf.push(c as char);
                    i += 1;
                }
            }
            b'\n' => {
                let trailing = trailing_space_count(&buf);
                let hard = trailing >= 2;
                // Strip any trailing spaces/tabs from the buffer (they're
                // either the hard-break signal or just paragraph-internal
                // trailing whitespace, neither of which we want in the
                // emitted text).
                while buf.ends_with(' ') || buf.ends_with('\t') {
                    buf.pop();
                }
                flush_text(&mut out, &mut buf, &delims);
                if hard {
                    out.push(Inline::HardBreak);
                } else {
                    out.push(Inline::SoftBreak);
                }
                i += 1;
                // Skip leading whitespace on the next line (paragraph
                // continuations should already have it stripped).
                while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
                    i += 1;
                }
            }
            _ => {
                // Fast path: c is ASCII and not in any special arm above
                // (otherwise the match would have caught it). Bulk-scan
                // forward over the run of contiguous ASCII non-special bytes
                // and append them in one push_str, instead of paying
                // per-byte from_utf8 + push_str + dispatch overhead.
                if c < 0x80 {
                    let start = i;
                    i += 1;
                    while i < bytes.len() {
                        let cc = bytes[i];
                        if cc >= 0x80 {
                            break;
                        }
                        if INLINE_SPECIAL[cc as usize] {
                            // `n` is in INLINE_SPECIAL only as a tripwire for
                            // the `nostr:` URI scheme and bare `npub1…`
                            // mentions; the vast majority of `n` bytes in
                            // prose aren't either. Replicate the cheap
                            // discriminator here so those bytes stay in the
                            // bulk run instead of bouncing out to dispatch
                            // and back.
                            if cc == b'n'
                                && bytes.get(i + 1..i + 6) != Some(b"ostr:")
                                && bytes.get(i + 1..i + 5) != Some(b"pub1")
                            {
                                i += 1;
                                continue;
                            }
                            // Same rescue for `h`/`m`/`t`/`w` — they're
                            // tripwires for bare-URL schemes and most occur
                            // mid-word in prose.
                            if matches!(cc, b'd' | b'h' | b'm' | b't' | b'w')
                                && !looks_like_bare_url_start(bytes, i)
                            {
                                i += 1;
                                continue;
                            }
                            break;
                        }
                        i += 1;
                    }
                    buf.push_str(std::str::from_utf8(&bytes[start..i]).unwrap());
                } else {
                    let len = utf8_char_len(c);
                    let end = (i + len).min(bytes.len());
                    buf.push_str(std::str::from_utf8(&bytes[i..end]).unwrap_or(""));
                    i = end;
                }
            }
        }
    }
    flush_text(&mut out, &mut buf, &delims);
    // Pair emphasis / strong / strikethrough delim runs at the top level.
    process_emphasis(&mut out, &mut delims, 0);
    // Any remaining unclosed bracket openers are orphans — their `[` /
    // `![` placeholder Text nodes stay literal, but they no longer block
    // coalescing.
    coalesce_text_runs(&mut out);
    out
}

fn coalesce_text_runs(items: &mut Vec<Inline>) {
    for item in items.iter_mut() {
        match item {
            Inline::Emph(children) | Inline::Strong(children) | Inline::Strikethrough(children) => {
                coalesce_text_runs(children)
            }
            Inline::Link { children, .. } => coalesce_text_runs(children),
            Inline::Image { alt, .. } => coalesce_text_runs(alt),
            _ => {}
        }
    }
    // O(n) in-place compaction: `Vec::remove(i+1)` shifts the tail on every
    // merge, so the prior loop was O(n × m) for m adjacent-Text merges (which
    // emphasis pairing produces in bulk after dropping placeholder Texts).
    // `dedup_by` walks the slice once with a read/write cursor; the closure's
    // two `&mut Inline` come from distinct slice positions, so extracting two
    // disjoint `&mut String` and folding `later` into `earlier` is sound.
    items.dedup_by(|later, earlier| {
        let Inline::Text(later_s) = later else {
            return false;
        };
        let Inline::Text(earlier_s) = earlier else {
            return false;
        };
        earlier_s.push_str(later_s);
        true
    });
}

/// Flush the text buffer into `out`. Coalesces with the previous Text node
/// **unless** that node is the placeholder for the most recent open bracket
/// delimiter — in that case we push a fresh Text so absorb_link can later
/// drain the link's children separately from the placeholder.
fn flush_text(out: &mut Vec<Inline>, buf: &mut String, delims: &[BracketDelim]) {
    if buf.is_empty() {
        return;
    }
    let last_idx = out.len().wrapping_sub(1);
    let blocked = delims
        .last()
        .is_some_and(|d| d.active && d.out_pos == last_idx);
    if !blocked && let Some(Inline::Text(prev)) = out.last_mut() {
        prev.push_str(buf);
        buf.clear();
        return;
    }
    // `mem::take` would reset `buf` to capacity 0, forcing the next text run
    // to grow from scratch. Preserve the existing capacity so a paragraph
    // with N inline delimiters costs ~1 alloc total instead of ~N growth
    // chains.
    let cap = buf.capacity();
    out.push(Inline::Text(std::mem::replace(
        buf,
        String::with_capacity(cap),
    )));
}

fn trailing_space_count(buf: &str) -> usize {
    buf.bytes().rev().take_while(|&b| b == b' ').count()
}

/// Try to consume a code span starting at byte `i` (pointing at `` ` ``).
/// Returns the (normalized content, end-index-just-past-closing-run).
fn try_code_span(bytes: &[u8], i: usize) -> Option<(String, usize)> {
    let mut j = i;
    while j < bytes.len() && bytes[j] == b'`' {
        j += 1;
    }
    let run_len = j - i;
    let mut k = j;
    while k < bytes.len() {
        if bytes[k] == b'`' {
            let mut m = k;
            while m < bytes.len() && bytes[m] == b'`' {
                m += 1;
            }
            if m - k == run_len {
                let content = normalize_code_span(&bytes[j..k]);
                return Some((content, m));
            }
            k = m;
        } else {
            k += 1;
        }
    }
    None
}

fn skip_backtick_run(bytes: &[u8], i: usize) -> usize {
    let mut end = i;
    while end < bytes.len() && bytes[end] == b'`' {
        end += 1;
    }
    end
}

fn normalize_code_span(b: &[u8]) -> String {
    // 1. Replace newlines with single spaces. `scanner::lines` already
    //    normalized `\r\n` / bare `\r` to `\n` before the block pass, so
    //    only `\n` can appear here.
    let mut s = String::with_capacity(b.len());
    let mut prev_was_nl = false;
    let src = std::str::from_utf8(b).unwrap_or("");
    for c in src.chars() {
        if c == '\n' {
            if !prev_was_nl {
                s.push(' ');
            }
            prev_was_nl = true;
        } else {
            s.push(c);
            prev_was_nl = false;
        }
    }
    // 2. If the result begins AND ends with a space (and isn't all spaces),
    //    strip one space from each end.
    if s.len() >= 2 && s.starts_with(' ') && s.ends_with(' ') && s.bytes().any(|b| b != b' ') {
        s = s[1..s.len() - 1].to_string();
    }
    s
}

/// Try to consume a single-`$` inline math span. Boundary rule: opening `$`
/// must not be followed by whitespace; closing `$` must not be preceded by
/// whitespace.
fn try_inline_math(bytes: &[u8], i: usize) -> InlineMathScan {
    debug_assert_eq!(bytes[i], b'$');
    // Reject `$$` (block math) and dollar runs of 2+.
    if bytes.get(i + 1) == Some(&b'$') {
        return InlineMathScan::NoMatch;
    }
    let Some(next) = bytes.get(i + 1).copied() else {
        return InlineMathScan::NoMatch;
    };
    if next == b' ' || next == b'\t' || next == b'\n' {
        return InlineMathScan::NoMatch;
    }
    // Scan for a closing `$` not preceded by whitespace, not preceded by
    // backslash escape. If this valid-looking opener reaches EOF without a
    // close, no later opener in the same suffix can succeed either: the close
    // predicate depends only on the candidate `$`, not on the opener. Tell the
    // tokenizer to stop rescanning that suffix so hostile `$x ` repeats stay
    // linear instead of O(number_of_$ × input_len).
    let mut k = i + 1;
    while k < bytes.len() {
        let c = bytes[k];
        if c == b'\\' && k + 1 < bytes.len() {
            // Escape inside math is opaque, but we still need to skip an
            // escaped `$` for boundary scanning.
            k += 2;
            continue;
        }
        if c == b'$' {
            // Check it isn't `$$`.
            if bytes.get(k + 1) == Some(&b'$') {
                k += 2;
                continue;
            }
            let prev = bytes[k - 1];
            if prev == b' ' || prev == b'\t' || prev == b'\n' {
                // Not a valid close; keep searching.
                k += 1;
                continue;
            }
            let Some(content) = std::str::from_utf8(&bytes[i + 1..k])
                .ok()
                .map(str::to_string)
            else {
                return InlineMathScan::NoMatch;
            };
            return InlineMathScan::Matched {
                content,
                end: k + 1,
            };
        }
        k += 1;
    }
    InlineMathScan::NoCloserInSuffix
}

enum InlineMathScan {
    Matched { content: String, end: usize },
    NoMatch,
    NoCloserInSuffix,
}

// ---------------------------------------------------------------------------
// Links + images (delimiter-stack closer)
// ---------------------------------------------------------------------------

fn is_bracket_delim_kind(kind: u8) -> bool {
    kind == b'[' || kind == b'!'
}

fn previous_active_bracket_delim(
    delims: &[BracketDelim],
    mut cursor: Option<usize>,
) -> Option<usize> {
    while let Some(idx) = cursor {
        let delim = delims.get(idx)?;
        if delim.active && is_bracket_delim_kind(delim.kind) {
            return Some(idx);
        }
        cursor = delim.prev_bracket;
    }
    None
}

fn active_bracket_delim_count(delims: &[BracketDelim], mut cursor: Option<usize>) -> usize {
    let mut count = 0;
    while let Some(idx) = previous_active_bracket_delim(delims, cursor) {
        count += 1;
        cursor = delims[idx].prev_bracket;
    }
    count
}

fn refresh_active_bracket_state(
    delims: &[BracketDelim],
    last_bracket_delim: &mut Option<usize>,
    open_bracket_delims: &mut usize,
) {
    *last_bracket_delim = previous_active_bracket_delim(delims, *last_bracket_delim);
    *open_bracket_delims = active_bracket_delim_count(delims, *last_bracket_delim);
}

fn deactivate_bracket_delim(
    delims: &mut [BracketDelim],
    opener_idx: usize,
    last_bracket_delim: &mut Option<usize>,
    open_bracket_delims: &mut usize,
) {
    if let Some(opener) = delims.get_mut(opener_idx)
        && opener.active
        && is_bracket_delim_kind(opener.kind)
    {
        opener.active = false;
    }
    refresh_active_bracket_state(delims, last_bracket_delim, open_bracket_delims);
}

/// Handle a `]` byte at position `i`. Returns the byte index past the close
/// on success, or `None` if the `]` should be emitted as literal text.
fn try_close_bracket(
    bytes: &[u8],
    i: usize,
    out: &mut Vec<Inline>,
    delims: &mut Vec<BracketDelim>,
    last_bracket_delim: &mut Option<usize>,
    open_bracket_delims: &mut usize,
    refs: &HashMap<String, LinkRef>,
) -> Option<usize> {
    // Find the most recent active opener (`[` or `![`) through the bracket-only
    // chain. This is the bracket analogue of the emphasis openers-bottom
    // optimization: every unmatched `]` consumes at most one opener instead of
    // rescanning/removing from the full mixed delimiter vector.
    let opener_idx = previous_active_bracket_delim(delims, *last_bracket_delim)?;
    *last_bracket_delim = Some(opener_idx);
    let opener = delims[opener_idx];

    // 1. Inline link: `](dest "title")`
    if bytes.get(i + 1) == Some(&b'(')
        && let Some((dest, title, end)) = parse_inline_link_suffix(bytes, i + 1)
    {
        if absorb_link(
            out,
            delims,
            opener_idx,
            dest,
            title,
            last_bracket_delim,
            open_bracket_delims,
        ) {
            return Some(end);
        }
        // Wrapping refused (depth cap): make this opener literal and emit the
        // close bracket as text so future `]` bytes advance to earlier openers.
        deactivate_bracket_delim(delims, opener_idx, last_bracket_delim, open_bracket_delims);
        return None;
    }

    // 2. Full reference link: `][label]`
    if bytes.get(i + 1) == Some(&b'[')
        && let Some((label_raw, end)) = parse_ref_label(bytes, i + 1)
    {
        if !label_raw.trim().is_empty()
            && let Some(def) = refs.get(&crate::block::normalize_label(&label_raw))
        {
            let (dest, title) = (def.dest.clone(), def.title.clone());
            if absorb_link(
                out,
                delims,
                opener_idx,
                dest,
                title,
                last_bracket_delim,
                open_bracket_delims,
            ) {
                return Some(end);
            }
            deactivate_bracket_delim(delims, opener_idx, last_bracket_delim, open_bracket_delims);
            return None;
        }
        // Empty `[]` after `]` — collapsed reference: use the link text as
        // the label.
        if label_raw.is_empty() {
            let label = label_text(bytes, opener.input_pos + 1, i);
            if let Some(def) = refs.get(&crate::block::normalize_label(&label)) {
                let (dest, title) = (def.dest.clone(), def.title.clone());
                if absorb_link(
                    out,
                    delims,
                    opener_idx,
                    dest,
                    title,
                    last_bracket_delim,
                    open_bracket_delims,
                ) {
                    return Some(end);
                }
                deactivate_bracket_delim(
                    delims,
                    opener_idx,
                    last_bracket_delim,
                    open_bracket_delims,
                );
                return None;
            }
        }
    }

    // 3. Shortcut reference: just `]`. Use the link text as label.
    let label = label_text(bytes, opener.input_pos + 1, i);
    if !label.is_empty()
        && let Some(def) = refs.get(&crate::block::normalize_label(&label))
    {
        let (dest, title) = (def.dest.clone(), def.title.clone());
        if absorb_link(
            out,
            delims,
            opener_idx,
            dest,
            title,
            last_bracket_delim,
            open_bracket_delims,
        ) {
            return Some(i + 1);
        }
        deactivate_bracket_delim(delims, opener_idx, last_bracket_delim, open_bracket_delims);
        return None;
    }

    // No match — make the opener literal and emit literal `]`.
    deactivate_bracket_delim(delims, opener_idx, last_bracket_delim, open_bracket_delims);
    None
}

/// Parse `(dest "title")` starting at the `(`.
fn parse_inline_link_suffix(b: &[u8], i: usize) -> Option<(String, Option<String>, usize)> {
    debug_assert_eq!(b.get(i), Some(&b'('));
    let mut j = i + 1;
    j = scanner::skip_ws_and_one_newline(b, j);
    let (dest, j2) = crate::block::parse_link_destination(b, j).unwrap_or((String::new(), j));
    j = j2;
    j = scanner::skip_ws_and_one_newline(b, j);
    // Optional title.
    let mut title = None;
    if let Some(&c) = b.get(j)
        && matches!(c, b'"' | b'\'' | b'(')
        && let Some((t, ne)) = crate::block::parse_link_title(b, j)
    {
        title = Some(t);
        j = ne;
        j = scanner::skip_ws_and_one_newline(b, j);
    }
    if b.get(j) != Some(&b')') {
        return None;
    }
    Some((dest, title, j + 1))
}

/// Parse `[label]` starting at `[`. Returns (raw label, end-after-`]`).
fn parse_ref_label(b: &[u8], i: usize) -> Option<(String, usize)> {
    debug_assert_eq!(b.get(i), Some(&b'['));
    let mut j = i + 1;
    let start = j;
    while j < b.len() && b[j] != b']' {
        if b[j] == b'\\' && j + 1 < b.len() {
            j += 2;
            continue;
        }
        if b[j] == b'[' {
            return None;
        }
        j += 1;
        if j - start > 999 {
            return None;
        }
    }
    if b.get(j) != Some(&b']') {
        return None;
    }
    let label = std::str::from_utf8(&b[start..j]).ok()?.to_string();
    Some((label, j + 1))
}

/// Best-effort label text for shortcut/collapsed reference resolution: the
/// raw bytes between `[` and `]` from the source. Backslash-escaped `]`
/// inside is allowed.
fn label_text(b: &[u8], start: usize, end: usize) -> String {
    let mut out = String::new();
    let src = std::str::from_utf8(&b[start..end]).unwrap_or("");
    let mut chars = src.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\'
            && let Some(&next) = chars.peek()
        {
            out.push(next);
            chars.next();
            continue;
        }
        out.push(c);
    }
    out
}

/// Replace the placeholder + intermediate inlines with a single Link/Image
/// inline; deactivate earlier `[` openers (no nested links).
///
/// Returns `true` if the link/image was wrapped, `false` if wrapping was
/// refused because it would push the inline tree past
/// [`MAX_INLINE_NESTING_DEPTH`] (darkmatter#208). On refusal `out`/`delims`
/// are left untouched so the caller can fall back to literal-text handling
/// of the closing `]` after deactivating the refused opener.
fn absorb_link(
    out: &mut Vec<Inline>,
    delims: &mut Vec<BracketDelim>,
    opener_idx: usize,
    dest: String,
    title: Option<String>,
    last_bracket_delim: &mut Option<usize>,
    open_bracket_delims: &mut usize,
) -> bool {
    // First, pair any emphasis runs strictly inside the link before
    // wrapping — emphasis inside link text DOES get processed (per spec).
    process_emphasis(out, delims, opener_idx + 1);
    refresh_active_bracket_state(delims, last_bracket_delim, open_bracket_delims);
    let opener = delims[opener_idx];
    let prev_bracket = opener.prev_bracket;

    // Depth guard (darkmatter#208). Wrapping the children in a Link/Image node
    // produces a node one level deeper than its deepest child, exactly like
    // emphasis pairing. Without this bound, input shaped as
    // `"![" * N + "a" + "](x)" * N` builds image nesting of depth ~N and later
    // overflows the stack in coalesce_text_runs, serde, and the uniffi
    // conversions — a fatal, uncatchable abort. If wrapping would exceed the
    // cap, refuse it and leave the delimiters as literal text. The probe is the
    // same iterative, early-pruning O(cap) walk used by process_emphasis, so it
    // neither overflows nor costs anything on ordinary input.
    if nesting_depth_at_least(&out[opener.out_pos + 1..], MAX_INLINE_NESTING_DEPTH) {
        return false;
    }

    let kind_is_image = opener.kind == b'!';
    // Children = items after the placeholder.
    let children: Vec<Inline> = out.drain(opener.out_pos + 1..).collect();
    // Drop the placeholder Text("[" / "![").
    out.pop();
    if kind_is_image {
        out.push(Inline::Image {
            dest,
            title,
            alt: children,
        });
    } else {
        out.push(Inline::Link {
            dest,
            title,
            children,
        });
    }
    // Pop all delimiters from opener_idx onward (any inner unclosed openers
    // are now part of the link's children). The bracket-only cursor/count are
    // refreshed from the surviving chain below, so this is a truncate rather
    // than repeated `Vec::remove` shifting. For links, prevent nested links by
    // deactivating earlier `[` openers through the same bracket chain; this is
    // proportional to active bracket openers, not unrelated emphasis delimiters.
    delims.truncate(opener_idx);
    if !kind_is_image {
        let mut cursor = previous_active_bracket_delim(delims, prev_bracket);
        while let Some(idx) = cursor {
            let prev = delims[idx].prev_bracket;
            if delims[idx].kind == b'[' {
                delims[idx].active = false;
            }
            cursor = previous_active_bracket_delim(delims, prev);
        }
    }
    *last_bracket_delim = previous_active_bracket_delim(delims, prev_bracket);
    *open_bracket_delims = active_bracket_delim_count(delims, *last_bracket_delim);
    true
}

// ---------------------------------------------------------------------------
// Autolinks + raw HTML
// ---------------------------------------------------------------------------

/// Schemes recognized as bare (unbracketed) URLs.
///
/// **Order matters:** `whitenoise-staging://` must come before `whitenoise://`
/// because the `find(..)` lookup is first-match-wins, and the latter is a
/// strict prefix of the former. With them in the wrong order
/// `whitenoise-staging://x` would parse as `whitenoise:` + literal
/// `-staging://x`.
const BARE_URL_SCHEMES: &[&[u8]] = &[
    b"https://",
    b"http://",
    b"mailto:",
    b"tel:",
    b"darkmatter://",
    b"whitenoise-staging://",
    b"whitenoise://",
];

/// True if the bytes starting at `i` begin with one of the recognized bare-URL
/// scheme prefixes. Used by the bulk-scan tripwire to keep ordinary text
/// (every `d`/`h`/`m`/`t`/`w` byte in prose) on the fast path.
fn looks_like_bare_url_start(bytes: &[u8], i: usize) -> bool {
    BARE_URL_SCHEMES
        .iter()
        .any(|s| bytes.get(i..i + s.len()) == Some(s))
}

/// Try to consume a bare URL (no surrounding `<>`) starting at `i`. Matches
/// `https://`, `http://`, `mailto:`, `tel:`, or an app deep-link authority form
/// followed by a non-empty run of non-whitespace, non-`<` bytes. Trailing
/// punctuation is stripped per the GFM extended-autolink rules (`.,;:!?*_~`
/// always; `)` only when it would unbalance the URL body).
fn try_bare_url(bytes: &[u8], i: usize) -> Option<(String, usize)> {
    let prev = if i == 0 { None } else { Some(bytes[i - 1]) };
    if !nostr::left_boundary_ok(prev) {
        return None;
    }
    // If the previous byte is `<`, the angle-bracket autolink form was tried
    // and rejected (e.g. body contained a space). Per existing convention,
    // the whole `<…>` token stays literal — don't rescue part of it as a
    // bare URL.
    if prev == Some(b'<') {
        return None;
    }
    let scheme = BARE_URL_SCHEMES
        .iter()
        .find(|s| bytes.get(i..i + s.len()) == Some(**s))?;
    let body_start = i + scheme.len();
    let mut j = body_start;
    while j < bytes.len() {
        let c = bytes[j];
        if c == b' '
            || c == b'\t'
            || c == b'\n'
            || c == b'\r'
            || c == b'<'
            || c == b'>'
            || c < 0x20
            || c == 0x7f
        {
            break;
        }
        j += 1;
    }
    if j == body_start {
        return None;
    }
    j = trim_trailing_punct(bytes, body_start, j);
    if j == body_start {
        return None;
    }
    let url = std::str::from_utf8(&bytes[i..j]).ok()?.to_string();
    Some((url, j))
}

/// Trim trailing punctuation from a bare-URL body per GFM:
/// - Always strip `.`, `,`, `;`, `:`, `!`, `?`, `*`, `_`, `~`.
/// - Strip `)` only when the body has more `)` than `(` (so balanced parens
///   inside the URL — e.g. Wikipedia disambiguation links — are kept).
fn trim_trailing_punct(bytes: &[u8], start: usize, mut end: usize) -> usize {
    let mut opens = 0usize;
    let mut closes = 0usize;
    for &b in &bytes[start..end] {
        match b {
            b'(' => opens += 1,
            b')' => closes += 1,
            _ => {}
        }
    }
    while end > start {
        let c = bytes[end - 1];
        match c {
            b'.' | b',' | b';' | b':' | b'!' | b'?' | b'*' | b'_' | b'~' => end -= 1,
            b')' if closes > opens => {
                end -= 1;
                closes -= 1;
            }
            b')' => return end,
            _ => return end,
        }
    }
    end
}

/// `<scheme:body>` — scheme is `[A-Za-z][A-Za-z0-9+.-]{1,31}`, body has no
/// `<`, `>`, control chars, or whitespace. Returns the URL (without the
/// surrounding `<>`).
fn try_uri_autolink(bytes: &[u8], i: usize) -> Option<(String, usize)> {
    debug_assert_eq!(bytes[i], b'<');
    let mut j = i + 1;
    if j >= bytes.len() || !bytes[j].is_ascii_alphabetic() {
        return None;
    }
    let scheme_start = j;
    j += 1;
    while j < bytes.len()
        && (bytes[j].is_ascii_alphanumeric()
            || bytes[j] == b'+'
            || bytes[j] == b'.'
            || bytes[j] == b'-')
        && (j - scheme_start) < 32
    {
        j += 1;
    }
    let scheme_len = j - scheme_start;
    if !(2..=32).contains(&scheme_len) {
        return None;
    }
    if bytes.get(j) != Some(&b':') {
        return None;
    }
    j += 1;
    while j < bytes.len() {
        let c = bytes[j];
        if c == b'>' {
            break;
        }
        if c == b'<' || c == b' ' || c == b'\t' || c == b'\n' || c < 0x20 || c == 0x7f {
            return None;
        }
        j += 1;
    }
    if bytes.get(j) != Some(&b'>') {
        return None;
    }
    let url = std::str::from_utf8(&bytes[scheme_start..j])
        .ok()?
        .to_string();
    Some((url, j + 1))
}

/// `<email@host>` per CommonMark §6.4.
fn try_email_autolink(bytes: &[u8], i: usize) -> Option<(String, usize)> {
    debug_assert_eq!(bytes[i], b'<');
    let mut j = i + 1;
    let local_start = j;
    while j < bytes.len() && is_email_local_char(bytes[j]) {
        j += 1;
    }
    if j == local_start {
        return None;
    }
    if bytes.get(j) != Some(&b'@') {
        return None;
    }
    j += 1;
    // host: label ('.' label)*; label is alnum + optional internal hyphens,
    // 1..=63 chars.
    loop {
        let label_start = j;
        if j >= bytes.len() || !bytes[j].is_ascii_alphanumeric() {
            return None;
        }
        j += 1;
        while j < bytes.len()
            && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'-')
            && (j - label_start) < 63
        {
            j += 1;
        }
        // Last char must not be `-`.
        if bytes[j - 1] == b'-' {
            return None;
        }
        if bytes.get(j) == Some(&b'.') {
            j += 1;
            continue;
        }
        break;
    }
    if bytes.get(j) != Some(&b'>') {
        return None;
    }
    let url = std::str::from_utf8(&bytes[local_start..j])
        .ok()?
        .to_string();
    Some((url, j + 1))
}

fn is_email_local_char(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'.' | b'!'
                | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'/'
                | b'='
                | b'?'
                | b'^'
                | b'_'
                | b'`'
                | b'{'
                | b'|'
                | b'}'
                | b'~'
                | b'-'
        )
}

/// Try to consume an `@npub1…` bare-mention starting at byte `i` (which
/// must point at `@`). Returns the parsed entity and the byte index just
/// past the bech32. Bare-mention only accepts `npub`; other HRPs require
/// the explicit `nostr:` prefix.
fn try_nostr_mention(bytes: &[u8], i: usize) -> Option<(NostrEntity, usize)> {
    debug_assert_eq!(bytes[i], b'@');
    let prev = if i == 0 { None } else { Some(bytes[i - 1]) };
    if !nostr::left_boundary_ok(prev) {
        return None;
    }
    let (hrp, end) = nostr::classify_bech32(bytes, i + 1)?;
    if hrp != NostrHrp::Npub {
        return None;
    }
    let bech32 = std::str::from_utf8(&bytes[i + 1..end]).ok()?.to_string();
    Some((NostrEntity { hrp, bech32 }, end))
}

/// Try to consume a bare `npub1…` mention starting at byte `i` (which must
/// point at `n`). Same shape rules as `try_nostr_mention` but without the
/// `@` prefix. Restricted to the `npub` HRP — other HRPs require the
/// explicit `@` or `nostr:` prefix to avoid false-positive matches on
/// running text that happens to start with `note1…` / `nevent1…`.
fn try_nostr_bare_mention(bytes: &[u8], i: usize) -> Option<(NostrEntity, usize)> {
    debug_assert_eq!(bytes[i], b'n');
    let prev = if i == 0 { None } else { Some(bytes[i - 1]) };
    if !nostr::left_boundary_ok(prev) {
        return None;
    }
    // Don't let the bare form rescue a prefix that already declined: if the
    // previous byte is `@`, or this starts immediately after `nostr:`, then
    // the longer form was tried and rejected, so the trailing bech32 must
    // stay literal too.
    if prev == Some(b'@') || (i >= 6 && bytes.get(i - 6..i) == Some(b"nostr:")) {
        return None;
    }
    let (hrp, end) = nostr::classify_bech32(bytes, i)?;
    if hrp != NostrHrp::Npub {
        return None;
    }
    let bech32 = std::str::from_utf8(&bytes[i..end]).ok()?.to_string();
    Some((NostrEntity { hrp, bech32 }, end))
}

/// Try to consume a `nostr:<hrp>1…` URI starting at byte `i` (which must
/// point at `n`). Returns the parsed entity and the byte index just past
/// the bech32.
fn try_nostr_uri(bytes: &[u8], i: usize) -> Option<(NostrEntity, usize)> {
    debug_assert_eq!(bytes[i], b'n');
    if bytes.get(i + 1..i + 6) != Some(b"ostr:") {
        return None;
    }
    let prev = if i == 0 { None } else { Some(bytes[i - 1]) };
    if !nostr::left_boundary_ok(prev) {
        return None;
    }
    let (hrp, end) = nostr::classify_bech32(bytes, i + 6)?;
    let bech32 = std::str::from_utf8(&bytes[i + 6..end]).ok()?.to_string();
    Some((NostrEntity { hrp, bech32 }, end))
}

// ---------------------------------------------------------------------------
// Emphasis / strong / strikethrough — the spec's process_emphasis algorithm.
// ---------------------------------------------------------------------------

fn classify_delim_run(bytes: &[u8], i: usize, ch: u8) -> (usize, bool, bool) {
    let mut j = i;
    while j < bytes.len() && bytes[j] == ch {
        j += 1;
    }
    let len = j - i;
    let prev = if i == 0 { None } else { Some(bytes[i - 1]) };
    let next = bytes.get(j).copied();
    let prev_is_ws = prev.is_none_or(is_ascii_ws_for_flank);
    let next_is_ws = next.is_none_or(is_ascii_ws_for_flank);
    let prev_is_punct = prev.is_some_and(scanner::is_ascii_punct);
    let next_is_punct = next.is_some_and(scanner::is_ascii_punct);
    let left_flanking = !next_is_ws && (!next_is_punct || prev_is_ws || prev_is_punct);
    let right_flanking = !prev_is_ws && (!prev_is_punct || next_is_ws || next_is_punct);
    let (can_open, can_close) = match ch {
        b'_' => (
            left_flanking && (!right_flanking || prev_is_punct),
            right_flanking && (!left_flanking || next_is_punct),
        ),
        // `*` and `~`: flanking is enough.
        _ => (left_flanking, right_flanking),
    };
    (len, can_open, can_close)
}

fn is_ascii_ws_for_flank(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0B | 0x0C)
}

/// Walk the delimiter stack and pair up `*` / `_` / `~` runs, replacing the
/// matched portion with `Emph` / `Strong` / `Strikethrough` inlines.
fn process_emphasis(out: &mut Vec<Inline>, delims: &mut [BracketDelim], stack_bottom: usize) {
    if out.is_empty() || stack_bottom >= delims.len() {
        return;
    }

    // Find the active delimiter window before allocating the link scratch.
    // Per-link emphasis calls often have no active delimiter above
    // `stack_bottom`; returning before `DelimLinks::new` keeps those empty
    // windows allocation-free.
    let mut first = None;
    let mut arena_start = usize::MAX;
    for (idx, delim) in delims.iter().enumerate().skip(stack_bottom) {
        if !delim.active {
            continue;
        }
        if first.is_none() {
            first = Some(idx);
        }
        arena_start = arena_start.min(delim.out_pos);
    }
    let Some(first) = first else {
        return;
    };

    // Stable delimiter links for the active slice. We keep `delims` itself in
    // source order so existing indices remain usable for links/images outside
    // this processing window.
    let mut links = DelimLinks::new(stack_bottom, delims.len());
    let mut last = None;
    for (idx, delim) in delims.iter().enumerate().skip(stack_bottom) {
        if !delim.active {
            continue;
        }
        links.set_prev(idx, last);
        if let Some(p) = last {
            links.set_next(p, Some(idx));
        }
        last = Some(idx);
    }

    // The CommonMark delimiter algorithm removes delimiter nodes and wraps
    // inline ranges in its inner loop. Doing that with Vec::remove/drain/insert
    // shifts the tail on every match, so an input like `*a* *a* ...` spends
    // quadratic time moving both `out` and `delims`. Convert only the active
    // output suffix for this delimiter window to a tiny intrusive list:
    // delimiter `out_pos` values become stable node ids, removals are pointer
    // rewrites, and we only compact back to Vec once at the end. For per-link
    // emphasis processing, this avoids rebuilding all previously parsed output
    // for every link in a hostile paragraph.
    for d in delims.iter_mut().skip(stack_bottom).filter(|d| d.active) {
        d.out_pos -= arena_start;
    }
    let mut arena = InlineArena::from_items(out.split_off(arena_start));

    // For each (delim_char, can_open, mod3) we track an "openers_bottom"
    // index — earlier than this we won't search for an opener again.
    use std::collections::HashMap;
    let mut openers_bottom: HashMap<(u8, bool, usize), usize> = HashMap::new();

    let mut closer_cursor = Some(first);
    while let Some(closer_idx) = closer_cursor {
        let closer = delims[closer_idx];
        if !is_run(closer.kind) || !closer.can_close || !closer.active {
            closer_cursor = links.next(closer_idx);
            continue;
        }
        let key = (closer.kind, closer.can_open, closer.orig_len % 3);
        let bottom = *openers_bottom.get(&key).unwrap_or(&stack_bottom);

        // Walk back to find a compatible opener.
        let mut opener_pos: Option<usize> = None;
        let mut k_cursor = links.prev(closer_idx);
        while let Some(k) = k_cursor {
            if k < bottom {
                break;
            }
            let opener = &delims[k];
            // Brackets terminate the search. Inactive brackets are not linked
            // into this pass, matching the previous "continue if inactive"
            // behavior.
            if opener.kind == b'[' || opener.kind == b'!' {
                break;
            }
            if !is_run(opener.kind) || !opener.active || opener.kind != closer.kind {
                k_cursor = links.prev(k);
                continue;
            }
            if !opener.can_open {
                k_cursor = links.prev(k);
                continue;
            }
            // Strikethrough only pairs runs of length ≥ 2 on both sides.
            if opener.kind == b'~' && (opener.len < 2 || closer.len < 2) {
                k_cursor = links.prev(k);
                continue;
            }
            // Rule of three (`*` and `_`; not `~` per the plan).
            if opener.kind != b'~' {
                let both_can = opener.can_close || closer.can_open;
                let sum_is_mod3 = (opener.orig_len + closer.orig_len).is_multiple_of(3);
                let both_mod3 =
                    opener.orig_len.is_multiple_of(3) && closer.orig_len.is_multiple_of(3);
                if both_can && sum_is_mod3 && !both_mod3 {
                    k_cursor = links.prev(k);
                    continue;
                }
            }
            opener_pos = Some(k);
            break;
        }

        if let Some(opener_idx) = opener_pos {
            let opener = delims[opener_idx];
            let closer = delims[closer_idx];
            // Strikethrough always consumes 2; emphasis takes 2 when both
            // sides are ≥ 2 (strong), else 1 (emph).
            let strong = opener.len >= 2 && closer.len >= 2;
            let n = if closer.kind == b'~' || strong { 2 } else { 1 };

            // Depth guard (darkmatter#208). Wrapping these children produces a
            // node one level deeper than the deepest child. If that would push
            // the inline tree past MAX_INLINE_NESTING_DEPTH, refuse the pairing
            // and leave the closer's delimiter run as literal text — exactly
            // the "no opener found" fallback below. This bounds the recursion
            // depth of every consumer that later walks the tree (serde,
            // marmot-uniffi conversions, coalesce_text_runs), none of which can
            // then be driven into a stack-overflow abort. The probe is an
            // iterative, early-pruning O(cap) walk, so it neither overflows nor
            // costs anything on ordinary input.
            if arena.nesting_depth_at_least_between(
                opener.out_pos,
                closer.out_pos,
                MAX_INLINE_NESTING_DEPTH,
            ) {
                openers_bottom.insert(key, closer_idx);
                let after_closer = links.next(closer_idx);
                if !closer.can_open {
                    unlink_delim(delims, &mut links, closer_idx);
                }
                closer_cursor = after_closer;
                continue;
            }

            let children = arena.detach_between(opener.out_pos, closer.out_pos);
            let opener_empty = arena.trim_run_text(opener.out_pos, n, /*from_right*/ true);
            let closer_empty = arena.trim_run_text(closer.out_pos, n, /*from_right*/ false);
            let wrapped = match closer.kind {
                b'~' => Inline::Strikethrough(children),
                _ if strong => Inline::Strong(children),
                _ => Inline::Emph(children),
            };

            if opener_empty {
                let prev_node = arena.nodes[opener.out_pos].prev;
                let next_node = arena.nodes[opener.out_pos].next;
                arena.unlink(opener.out_pos);
                arena.insert_between(prev_node, next_node, wrapped);
            } else {
                let next_node = arena.nodes[opener.out_pos].next;
                arena.insert_between(Some(opener.out_pos), next_node, wrapped);
            }
            if closer_empty {
                arena.unlink(closer.out_pos);
            }

            delims[opener_idx].len -= n;
            delims[closer_idx].len -= n;
            let drop_opener = delims[opener_idx].len == 0;
            let drop_closer = delims[closer_idx].len == 0;
            let after_closer = links.next(closer_idx);

            unlink_delims_between(delims, &mut links, opener_idx, closer_idx);
            let resume = if !drop_opener {
                Some(opener_idx)
            } else if !drop_closer {
                Some(closer_idx)
            } else {
                after_closer
            };
            if drop_opener {
                unlink_delim(delims, &mut links, opener_idx);
            }
            if drop_closer {
                unlink_delim(delims, &mut links, closer_idx);
            }

            closer_cursor = resume;
            continue;
        } else {
            // No opener found.
            openers_bottom.insert(key, closer_idx);
            let after_closer = links.next(closer_idx);
            if !closer.can_open {
                // Drop this closer (it can't be an opener for later closers),
                // but keep its text node in `out` as literal.
                unlink_delim(delims, &mut links, closer_idx);
            }
            closer_cursor = after_closer;
        }
    }

    let (items, node_positions) = arena.into_items();
    out.extend(items);
    for d in delims.iter_mut().skip(stack_bottom).filter(|d| d.active) {
        if let Some(Some(pos)) = node_positions.get(d.out_pos) {
            d.out_pos = arena_start + *pos;
        } else {
            d.active = false;
        }
    }
}

struct InlineNode {
    item: Inline,
    prev: Option<usize>,
    next: Option<usize>,
    alive: bool,
}

struct InlineArena {
    nodes: Vec<InlineNode>,
    head: Option<usize>,
    tail: Option<usize>,
}

impl InlineArena {
    fn from_items(items: Vec<Inline>) -> Self {
        let len = items.len();
        let nodes = items
            .into_iter()
            .enumerate()
            .map(|(idx, item)| InlineNode {
                item,
                prev: idx.checked_sub(1),
                next: (idx + 1 < len).then_some(idx + 1),
                alive: true,
            })
            .collect();
        Self {
            nodes,
            head: (len > 0).then_some(0),
            tail: (len > 0).then_some(len - 1),
        }
    }

    fn detach_between(&mut self, before: usize, after: usize) -> Vec<Inline> {
        let mut children = Vec::new();
        let mut cursor = self.nodes[before].next;
        while let Some(idx) = cursor {
            if idx == after {
                break;
            }
            let next = self.nodes[idx].next;
            self.unlink(idx);
            children.push(std::mem::replace(
                &mut self.nodes[idx].item,
                Inline::Text(String::new()),
            ));
            cursor = next;
        }
        children
    }

    fn trim_run_text(&mut self, pos: usize, n: usize, from_right: bool) -> bool {
        if let Inline::Text(s) = &mut self.nodes[pos].item {
            if from_right {
                for _ in 0..n {
                    s.pop();
                }
            } else {
                let byte_end = s.char_indices().nth(n).map(|(i, _)| i).unwrap_or(s.len());
                s.drain(..byte_end);
            }
            s.is_empty()
        } else {
            false
        }
    }

    fn nesting_depth_at_least_between(&self, before: usize, after: usize, cap: usize) -> bool {
        if cap == 0 {
            return true;
        }
        let mut cursor = self.nodes[before].next;
        while let Some(idx) = cursor {
            if idx == after {
                break;
            }
            let node = &self.nodes[idx];
            cursor = node.next;
            if !node.alive {
                continue;
            }
            if cap == 1 {
                return true;
            }
            let Some(children) = inline_children(&node.item) else {
                continue;
            };
            if depth_from_children_at_least(children, 2, cap) {
                return true;
            }
        }
        false
    }

    fn unlink(&mut self, idx: usize) {
        if !self.nodes[idx].alive {
            return;
        }
        let prev = self.nodes[idx].prev;
        let next = self.nodes[idx].next;
        if let Some(prev) = prev {
            self.nodes[prev].next = next;
        } else {
            self.head = next;
        }
        if let Some(next) = next {
            self.nodes[next].prev = prev;
        } else {
            self.tail = prev;
        }
        self.nodes[idx].prev = None;
        self.nodes[idx].next = None;
        self.nodes[idx].alive = false;
    }

    fn insert_between(&mut self, prev: Option<usize>, next: Option<usize>, item: Inline) -> usize {
        let idx = self.nodes.len();
        self.nodes.push(InlineNode {
            item,
            prev,
            next,
            alive: true,
        });
        if let Some(prev) = prev {
            self.nodes[prev].next = Some(idx);
        } else {
            self.head = Some(idx);
        }
        if let Some(next) = next {
            self.nodes[next].prev = Some(idx);
        } else {
            self.tail = Some(idx);
        }
        idx
    }

    fn into_items(mut self) -> (Vec<Inline>, Vec<Option<usize>>) {
        let mut items = Vec::new();
        let mut node_positions = vec![None; self.nodes.len()];
        let mut cursor = self.head;
        while let Some(idx) = cursor {
            cursor = self.nodes[idx].next;
            if !self.nodes[idx].alive {
                continue;
            }
            node_positions[idx] = Some(items.len());
            items.push(std::mem::replace(
                &mut self.nodes[idx].item,
                Inline::Text(String::new()),
            ));
        }
        (items, node_positions)
    }
}

fn depth_from_children_at_least(items: &[Inline], depth: usize, cap: usize) -> bool {
    if depth >= cap {
        return !items.is_empty();
    }

    let mut stack: Vec<(&[Inline], usize, usize)> = vec![(items, 0, depth)];
    while let Some(&mut (slice, ref mut idx, depth)) = stack.last_mut() {
        if *idx >= slice.len() {
            stack.pop();
            continue;
        }
        let item = &slice[*idx];
        *idx += 1;
        if depth >= cap {
            return true;
        }
        if let Some(children) = inline_children(item) {
            if depth + 1 >= cap {
                return true;
            }
            stack.push((children, 0, depth + 1));
        }
    }
    false
}

struct DelimLinks {
    stack_bottom: usize,
    prev: Vec<Option<usize>>,
    next: Vec<Option<usize>>,
}

impl DelimLinks {
    fn new(stack_bottom: usize, delims_len: usize) -> Self {
        let window_len = delims_len.saturating_sub(stack_bottom);
        Self {
            stack_bottom,
            prev: vec![None; window_len],
            next: vec![None; window_len],
        }
    }

    fn slot(&self, idx: usize) -> usize {
        debug_assert!(idx >= self.stack_bottom);
        idx - self.stack_bottom
    }

    fn prev(&self, idx: usize) -> Option<usize> {
        self.prev[self.slot(idx)]
    }

    fn set_prev(&mut self, idx: usize, value: Option<usize>) {
        let slot = self.slot(idx);
        self.prev[slot] = value;
    }

    fn next(&self, idx: usize) -> Option<usize> {
        self.next[self.slot(idx)]
    }

    fn set_next(&mut self, idx: usize, value: Option<usize>) {
        let slot = self.slot(idx);
        self.next[slot] = value;
    }
}

fn unlink_delims_between(
    delims: &mut [BracketDelim],
    links: &mut DelimLinks,
    opener_idx: usize,
    closer_idx: usize,
) {
    let mut cursor = links.next(opener_idx);
    while let Some(idx) = cursor {
        if idx == closer_idx {
            break;
        }
        cursor = links.next(idx);
        unlink_delim(delims, links, idx);
    }
}

fn unlink_delim(delims: &mut [BracketDelim], links: &mut DelimLinks, idx: usize) {
    if !delims[idx].active {
        return;
    }
    let prev_idx = links.prev(idx);
    let next_idx = links.next(idx);
    if let Some(prev_idx) = prev_idx {
        links.set_next(prev_idx, next_idx);
    }
    if let Some(next_idx) = next_idx {
        links.set_prev(next_idx, prev_idx);
    }
    links.set_prev(idx, None);
    links.set_next(idx, None);
    delims[idx].active = false;
}

fn is_run(k: u8) -> bool {
    matches!(k, b'*' | b'_' | b'~')
}

fn utf8_char_len(first_byte: u8) -> usize {
    if first_byte < 0xC0 {
        // ASCII or stray continuation byte: advance 1.
        1
    } else if first_byte < 0xE0 {
        2
    } else if first_byte < 0xF0 {
        3
    } else {
        4
    }
}
