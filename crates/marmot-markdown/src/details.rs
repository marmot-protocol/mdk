//! Bounded `<details>` / `<summary>` tag grammar.
//!
//! Recognition is a block-oriented extension over original source, not HTML
//! recovery. Callers charge work through [`Work`] so tests can assert a
//! linear scan bound.

use std::cell::Cell;

/// Inclusive byte length from `<` through `>` for a structural tag.
pub(crate) const MAX_DETAILS_TAG_BYTES: usize = 4096;
/// Original-source prefix eligible for disclosure recognition per parse.
pub(crate) const MAX_DETAILS_SCAN_BYTES: usize = 65536;

thread_local! {
    static WORK: Cell<usize> = const { Cell::new(0) };
}

/// Monotonic recognition-work counter for tests.
pub(crate) struct Work;

impl Work {
    pub(crate) fn reset() {
        WORK.with(|c| c.set(0));
    }

    #[cfg(test)]
    pub(crate) fn get() -> usize {
        WORK.with(Cell::get)
    }

    fn charge(n: usize) {
        WORK.with(|c| c.set(c.get().saturating_add(n)));
    }
}

/// UTF-8-safe prefix of `input` in which complete details candidates may be
/// recognized. The bound is inclusive of index `window - 1`.
pub(crate) fn recognition_window(input: &str) -> usize {
    if input.len() <= MAX_DETAILS_SCAN_BYTES {
        return input.len();
    }
    let mut end = MAX_DETAILS_SCAN_BYTES;
    while end > 0 && !input.is_char_boundary(end) {
        end -= 1;
    }
    end
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DetailsOpen {
    pub open: bool,
    /// Byte index after `>` in the supplied line.
    pub tag_end: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DetailsClose {
    /// Byte index after `>` in the supplied line.
    pub tag_end: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SummaryLine {
    NotSummary,
    /// `<summary ...>inner</summary>` on one logical line.
    Complete {
        inner: String,
    },
    /// Opening tag present; closer is not on this line.
    OpenOnly {
        after_open: String,
    },
    /// Closing tag present; opener is not on this line.
    CloseOnly {
        before_close: String,
    },
    Malformed,
}

/// After container prefixes have been stripped, try to read a details opener
/// that occupies the rest of the logical line.
pub(crate) fn parse_details_opener_line(line: &str) -> Option<DetailsOpen> {
    Work::charge(1);
    let (body, start) = trim_line_ws(line);
    if !starts_with_open_angle(body) {
        return None;
    }
    let parsed = parse_open_tag(body.as_bytes(), b"details")?;
    if parsed.self_closing {
        return None;
    }
    if !is_only_ws(&body.as_bytes()[parsed.tag_end..]) {
        return None;
    }
    Some(DetailsOpen {
        open: parsed.has_open_attr,
        tag_end: start + parsed.tag_end,
    })
}

/// After container prefixes have been stripped, try to read a details closer
/// that occupies the rest of the logical line.
pub(crate) fn parse_details_closer_line(line: &str) -> Option<DetailsClose> {
    Work::charge(1);
    let (body, start) = trim_line_ws(line);
    if !starts_with_open_angle(body) {
        return None;
    }
    let tag_end = parse_close_tag(body.as_bytes(), b"details")?;
    if !is_only_ws(&body.as_bytes()[tag_end..]) {
        return None;
    }
    Some(DetailsClose {
        tag_end: start + tag_end,
    })
}

/// Classify a candidate first-child summary line (container prefixes already
/// stripped). Leading/trailing horizontal whitespace around the whole line is
/// allowed; anything else before the opener or after the closer is malformed.
pub(crate) fn parse_summary_line(line: &str) -> SummaryLine {
    Work::charge(1);
    let (body, _) = trim_line_ws(line);
    if !starts_with_open_angle(body) {
        if let Some(inner) = parse_summary_close_only(line) {
            return SummaryLine::CloseOnly {
                before_close: inner,
            };
        }
        if looks_like_summary_close(body) {
            return SummaryLine::Malformed;
        }
        return SummaryLine::NotSummary;
    }

    let Some(open) = parse_open_tag(body.as_bytes(), b"summary") else {
        return if look_like_summary_open(body) {
            SummaryLine::Malformed
        } else {
            SummaryLine::NotSummary
        };
    };
    if open.self_closing {
        return SummaryLine::Malformed;
    }

    let after = &body[open.tag_end..];
    match find_summary_close(after) {
        CloseSeek::Found { rel_start, tag_end } => {
            if !is_only_ws(&after.as_bytes()[tag_end..]) {
                return SummaryLine::Malformed;
            }
            SummaryLine::Complete {
                inner: after[..rel_start].to_string(),
            }
        }
        CloseSeek::ProtectedOrAbsent => SummaryLine::OpenOnly {
            after_open: after.to_string(),
        },
        CloseSeek::Malformed => SummaryLine::Malformed,
    }
}

fn look_like_summary_open(body: &str) -> bool {
    let bytes = body.as_bytes();
    bytes.first() == Some(&b'<') && match_name(&bytes[1..], b"summary").is_some()
}

fn looks_like_summary_close(body: &str) -> bool {
    let bytes = body.as_bytes();
    bytes.len() >= 2
        && bytes[0] == b'<'
        && bytes[1] == b'/'
        && match_name(&bytes[2..], b"summary").is_some()
}

#[derive(Debug)]
struct ParsedOpenTag {
    tag_end: usize,
    has_open_attr: bool,
    self_closing: bool,
}

fn parse_open_tag(bytes: &[u8], name: &[u8]) -> Option<ParsedOpenTag> {
    if bytes.first() != Some(&b'<') {
        return None;
    }
    let after_lt = 1;
    if bytes.get(after_lt) == Some(&b'/') {
        return None;
    }
    let name_end = match_name(&bytes[after_lt..], name)?;
    let mut i = after_lt + name_end;
    if !tag_name_boundary(bytes.get(i).copied()) {
        return None;
    }

    let mut has_open_attr = false;
    let mut self_closing = false;
    loop {
        if i > MAX_DETAILS_TAG_BYTES {
            return None;
        }
        Work::charge(1);
        i = skip_ascii_ws(bytes, i);
        if i >= bytes.len() {
            return None;
        }
        if i + 1 > MAX_DETAILS_TAG_BYTES {
            return None;
        }
        match bytes[i] {
            b'>' => {
                let tag_end = i + 1;
                if tag_end > MAX_DETAILS_TAG_BYTES {
                    return None;
                }
                return Some(ParsedOpenTag {
                    tag_end,
                    has_open_attr,
                    self_closing,
                });
            }
            b'/' => {
                self_closing = true;
                i += 1;
                i = skip_ascii_ws(bytes, i);
                if bytes.get(i) != Some(&b'>') {
                    return None;
                }
                let tag_end = i + 1;
                if tag_end > MAX_DETAILS_TAG_BYTES {
                    return None;
                }
                return Some(ParsedOpenTag {
                    tag_end,
                    has_open_attr,
                    self_closing,
                });
            }
            _ => {
                let (attr_end, is_open) = parse_attribute(bytes, i)?;
                if attr_end > MAX_DETAILS_TAG_BYTES {
                    return None;
                }
                if is_open {
                    has_open_attr = true;
                }
                i = attr_end;
            }
        }
    }
}

fn parse_close_tag(bytes: &[u8], name: &[u8]) -> Option<usize> {
    if bytes.len() < 2 || bytes[0] != b'<' || bytes[1] != b'/' {
        return None;
    }
    let name_end = match_name(&bytes[2..], name)?;
    let mut i = 2 + name_end;
    if !tag_name_boundary(bytes.get(i).copied()) {
        return None;
    }
    i = skip_ascii_ws(bytes, i);
    if bytes.get(i) != Some(&b'>') {
        return None;
    }
    let tag_end = i + 1;
    if tag_end > MAX_DETAILS_TAG_BYTES {
        return None;
    }
    Work::charge(tag_end);
    Some(tag_end)
}

fn parse_attribute(bytes: &[u8], start: usize) -> Option<(usize, bool)> {
    if start >= bytes.len() || !is_attr_name_start(bytes[start]) {
        return None;
    }
    let mut i = start + 1;
    while i < bytes.len() && is_attr_name_continue(bytes[i]) {
        i += 1;
    }
    let name = &bytes[start..i];
    let is_open = name.eq_ignore_ascii_case(b"open");
    i = skip_ascii_ws(bytes, i);
    if bytes.get(i) != Some(&b'=') {
        return Some((i, is_open));
    }
    i += 1;
    i = skip_ascii_ws(bytes, i);
    if i >= bytes.len() {
        return None;
    }
    match bytes[i] {
        b'"' | b'\'' => {
            let quote = bytes[i];
            i += 1;
            while i < bytes.len() && bytes[i] != quote {
                Work::charge(1);
                i += 1;
                if i - start + 1 > MAX_DETAILS_TAG_BYTES {
                    return None;
                }
            }
            if i >= bytes.len() {
                return None;
            }
            i += 1;
            Some((i, is_open))
        }
        b'>' | b'/' => None,
        _ => {
            let val_start = i;
            while i < bytes.len() && !matches!(bytes[i], b' ' | b'\t' | b'>' | b'/') {
                Work::charge(1);
                i += 1;
                if i - start + 1 > MAX_DETAILS_TAG_BYTES {
                    return None;
                }
            }
            if i == val_start {
                return None;
            }
            Some((i, is_open))
        }
    }
}

enum CloseSeek {
    Found { rel_start: usize, tag_end: usize },
    ProtectedOrAbsent,
    Malformed,
}

/// Find `</summary>` in `after`, skipping markdown code spans. A closer
/// inside a code span is content, not a terminator.
fn find_summary_close(after: &str) -> CloseSeek {
    let bytes = after.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        Work::charge(1);
        if bytes[i] == b'`' {
            match skip_code_span(bytes, i) {
                Some(end) => i = end,
                None => i += 1,
            }
            continue;
        }
        if bytes[i] == b'<'
            && bytes.get(i + 1) == Some(&b'/')
            && let Some(name_end) = match_name(&bytes[i + 2..], b"summary")
        {
            let mut j = i + 2 + name_end;
            if tag_name_boundary(bytes.get(j).copied()) {
                j = skip_ascii_ws(bytes, j);
                if bytes.get(j) == Some(&b'>') {
                    let tag_end = j + 1 - i;
                    if tag_end > MAX_DETAILS_TAG_BYTES {
                        return CloseSeek::Malformed;
                    }
                    return CloseSeek::Found {
                        rel_start: i,
                        tag_end: j + 1,
                    };
                }
                return CloseSeek::Malformed;
            }
        }
        i += 1;
    }
    CloseSeek::ProtectedOrAbsent
}

fn skip_code_span(bytes: &[u8], start: usize) -> Option<usize> {
    let mut ticks = 0;
    while start + ticks < bytes.len() && bytes[start + ticks] == b'`' {
        ticks += 1;
    }
    if ticks == 0 {
        return None;
    }
    let mut i = start + ticks;
    while i < bytes.len() {
        if bytes[i] == b'`' {
            let mut run = 0;
            while i + run < bytes.len() && bytes[i + run] == b'`' {
                run += 1;
            }
            if run == ticks {
                return Some(i + run);
            }
            i += run;
        } else {
            i += 1;
        }
    }
    None
}

fn match_name(bytes: &[u8], name: &[u8]) -> Option<usize> {
    if bytes.len() < name.len() {
        return None;
    }
    if !bytes[..name.len()].eq_ignore_ascii_case(name) {
        return None;
    }
    Some(name.len())
}

fn tag_name_boundary(b: Option<u8>) -> bool {
    match b {
        None => true,
        Some(b) => !b.is_ascii_alphanumeric(),
    }
}

fn is_attr_name_start(b: u8) -> bool {
    b.is_ascii_alphabetic()
}

fn is_attr_name_continue(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b':'
}

fn skip_ascii_ws(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
        i += 1;
    }
    i
}

fn is_only_ws(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == b' ' || b == b'\t')
}

fn starts_with_open_angle(s: &str) -> bool {
    s.as_bytes().first() == Some(&b'<')
}

fn trim_line_ws(line: &str) -> (&str, usize) {
    let bytes = line.as_bytes();
    let mut start = 0;
    let mut end = bytes.len();
    while start < end && (bytes[start] == b' ' || bytes[start] == b'\t') {
        start += 1;
    }
    while end > start && (bytes[end - 1] == b' ' || bytes[end - 1] == b'\t') {
        end -= 1;
    }
    (&line[start..end], start)
}

/// True when `inner` is empty or only horizontal whitespace.
pub(crate) fn summary_inner_is_empty(inner: &str) -> bool {
    inner.bytes().all(|b| b == b' ' || b == b'\t')
}

/// Second line of a two-line summary: optional content then `</summary>`.
pub(crate) fn parse_summary_close_only(line: &str) -> Option<String> {
    Work::charge(1);
    let (body, _) = trim_line_ws(line);
    if starts_with_open_angle(body) && look_like_summary_open(body) {
        return None;
    }
    match find_summary_close(body) {
        CloseSeek::Found { rel_start, tag_end } if is_only_ws(&body.as_bytes()[tag_end..]) => {
            Some(body[..rel_start].to_string())
        }
        CloseSeek::Malformed => None,
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opener_basic_and_open_attr() {
        Work::reset();
        let a = parse_details_opener_line("  <details>  ").unwrap();
        assert!(!a.open);
        let b = parse_details_opener_line("<DETAILS open>").unwrap();
        assert!(b.open);
        let c = parse_details_opener_line(r#"<details open="false">"#).unwrap();
        assert!(c.open);
        let d = parse_details_opener_line("<details opened>").unwrap();
        assert!(!d.open);
        let e = parse_details_opener_line(r#"<details data-open="1" class="open">"#).unwrap();
        assert!(!e.open);
        assert!(parse_details_opener_line("<detailsx>").is_none());
        assert!(parse_details_opener_line("<details/>").is_none());
        assert!(parse_details_opener_line("<details> trailing").is_none());
        assert!(parse_details_opener_line("<details><summary>x</summary></details>").is_none());
    }

    #[test]
    fn opener_quoted_gt_and_false_prefix() {
        assert!(parse_details_opener_line(r#"<details title="a>b">"#).is_some());
        assert!(!parse_details_opener_line("<details openx>").unwrap().open);
        assert!(
            !parse_details_opener_line(r#"<details foo='open'>"#)
                .unwrap()
                .open
        );
    }

    #[test]
    fn closer_rejects_attributes() {
        assert!(parse_details_closer_line("  </details>  ").is_some());
        assert!(parse_details_closer_line("</DETAILS>").is_some());
        assert!(parse_details_closer_line("</details foo>").is_none());
        assert!(parse_details_closer_line("</detailsx>").is_none());
    }

    #[test]
    fn summary_oneline_and_code_span() {
        assert_eq!(
            parse_summary_line("<summary>Tap</summary>"),
            SummaryLine::Complete {
                inner: "Tap".into()
            }
        );
        assert_eq!(
            parse_summary_line("<summary>`</summary>` more</summary>"),
            SummaryLine::Complete {
                inner: "`</summary>` more".into()
            }
        );
        assert_eq!(
            parse_summary_line("<summary>"),
            SummaryLine::OpenOnly {
                after_open: String::new()
            }
        );
        assert!(matches!(
            parse_summary_line("<summary foo=>"),
            SummaryLine::Malformed
        ));
        assert_eq!(parse_summary_line("hello"), SummaryLine::NotSummary);
    }

    #[test]
    fn tag_cap_is_inclusive() {
        let pad = "x".repeat(MAX_DETAILS_TAG_BYTES - "<details class=''>".len());
        let exact = format!("<details class='{pad}'>");
        assert_eq!(exact.len(), MAX_DETAILS_TAG_BYTES);
        assert!(parse_details_opener_line(&exact).is_some());
        let over = format!("<details class='{pad}y'>");
        assert!(over.len() > MAX_DETAILS_TAG_BYTES);
        assert!(parse_details_opener_line(&over).is_none());
    }

    #[test]
    fn window_stops_on_utf8_boundary() {
        let mut s = "a".repeat(MAX_DETAILS_SCAN_BYTES - 1);
        s.push('é');
        s.push_str("more");
        let w = recognition_window(&s);
        assert!(w <= MAX_DETAILS_SCAN_BYTES);
        assert!(s.is_char_boundary(w));
        assert_eq!(w, MAX_DETAILS_SCAN_BYTES - 1);
    }
}
