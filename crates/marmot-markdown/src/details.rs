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

    fn charge_bytes(n: usize) {
        Self::charge(n);
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
    Malformed,
}

/// Result of scanning one additional nonblank line of an already-open summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SummaryContinue {
    Complete { inner: String },
    StillOpen,
    Malformed,
}

#[derive(Debug, Clone)]
struct DeferredCloser {
    rel_start: usize,
    tag_end: usize,
    trailing_ws_only: bool,
}

/// Incremental summary closer / code-span state. Each new line is scanned
/// once; unmatched backtick runs stay pending until a later match or the
/// candidate ends, so a closer is not committed before a later matching run.
#[derive(Debug, Clone, Default)]
pub(crate) struct SummaryCollector {
    inner: String,
    unmatched: Vec<(usize, usize)>,
    deferred_closers: Vec<DeferredCloser>,
}

impl SummaryCollector {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn from_after_open(after_open: &str) -> Self {
        let mut collector = Self::new();
        let _ = collector.push_segment(after_open, usize::MAX, true);
        collector
    }

    pub(crate) fn inner(&self) -> &str {
        &self.inner
    }

    pub(crate) fn has_unmatched_openers(&self) -> bool {
        !self.unmatched.is_empty()
    }

    pub(crate) fn push_line(&mut self, next_line: &str, max_bytes: usize) -> SummaryContinue {
        Work::charge(1);
        let (next, _) = trim_leading_ws(next_line);
        if starts_with_open_angle(next) && look_like_summary_open(next) {
            return SummaryContinue::Malformed;
        }
        self.push_segment(next, max_bytes, false)
    }

    /// Resolve unmatched backtick runs as literal and take the first
    /// unprotected closer, returning leftover lines after that closer.
    pub(crate) fn finalize(&self) -> Option<(String, Vec<String>)> {
        let closer = self
            .deferred_closers
            .iter()
            .find(|closer| closer.trailing_ws_only)?;
        if closer.rel_start > self.inner.len() || closer.tag_end > self.inner.len() {
            return None;
        }
        let inner = self.inner[..inner_end(closer.rel_start, &self.inner)].to_string();
        Some((inner, leftover_lines(&self.inner, closer.tag_end)))
    }

    fn push_segment(&mut self, text: &str, max_bytes: usize, first: bool) -> SummaryContinue {
        let take = floor_char_boundary(text, text.len().min(max_bytes));
        let sliced = &text[..take];
        let join = !first && !self.inner.is_empty();
        let from = if join {
            self.inner.len() + 1
        } else {
            self.inner.len()
        };
        Work::charge_bytes(sliced.len() + usize::from(join));
        if join {
            self.inner.push('\n');
        }
        self.inner.push_str(sliced);
        match self.scan_from(from) {
            CloseSeek::Found { rel_start, tag_end } => {
                if !trailing_ws_only(&self.inner, tag_end) {
                    return SummaryContinue::Malformed;
                }
                SummaryContinue::Complete {
                    inner: self.inner[..inner_end(rel_start, &self.inner)].to_string(),
                }
            }
            CloseSeek::ProtectedOrAbsent => SummaryContinue::StillOpen,
            CloseSeek::Malformed => SummaryContinue::Malformed,
        }
    }

    fn scan_from(&mut self, from: usize) -> CloseSeek {
        let bytes = self.inner.as_bytes();
        let limit = bytes.len();
        let mut i = from;
        while i < limit {
            Work::charge(1);
            if bytes[i] == b'`' {
                let run_end = skip_backtick_run(bytes, i, limit);
                let run_len = run_end - i;
                if let Some(opener_start) = take_unmatched(&mut self.unmatched, run_len) {
                    self.unmatched
                        .retain(|(pos, _)| *pos <= opener_start || *pos >= i);
                    self.deferred_closers
                        .retain(|closer| closer.rel_start <= opener_start || closer.rel_start >= i);
                    i = run_end;
                } else {
                    self.unmatched.push((i, run_len));
                    i = run_end;
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
                        let tag_end = j + 1;
                        if tag_end - i > MAX_DETAILS_TAG_BYTES {
                            return CloseSeek::Malformed;
                        }
                        let unmatched_before = self.unmatched.iter().any(|(pos, _)| *pos < i);
                        if unmatched_before {
                            self.deferred_closers.push(DeferredCloser {
                                rel_start: i,
                                tag_end,
                                trailing_ws_only: trailing_ws_only_until_eol(bytes, tag_end),
                            });
                            i = tag_end;
                            continue;
                        }
                        return CloseSeek::Found {
                            rel_start: i,
                            tag_end,
                        };
                    }
                    return CloseSeek::Malformed;
                }
            }
            i += 1;
        }
        CloseSeek::ProtectedOrAbsent
    }
}

fn take_unmatched(unmatched: &mut Vec<(usize, usize)>, run_len: usize) -> Option<usize> {
    let idx = unmatched.iter().position(|(_, len)| *len == run_len)?;
    Some(unmatched.remove(idx).0)
}

fn inner_end(rel_start: usize, inner: &str) -> usize {
    if rel_start > 0 && inner.as_bytes()[rel_start - 1] == b'\n' {
        rel_start - 1
    } else {
        rel_start
    }
}

fn leftover_lines(inner: &str, tag_end: usize) -> Vec<String> {
    if tag_end >= inner.len() {
        return Vec::new();
    }
    let after = &inner[tag_end..];
    let mut lines = Vec::new();
    for (idx, line) in after.split('\n').enumerate() {
        if idx == 0 {
            continue;
        }
        lines.push(line.to_string());
    }
    lines
}

fn trailing_ws_only(text: &str, tag_end: usize) -> bool {
    trailing_ws_only_until_eol(text.as_bytes(), tag_end)
}

fn trailing_ws_only_until_eol(bytes: &[u8], mut i: usize) -> bool {
    while i < bytes.len() && bytes[i] != b'\n' && bytes[i] != b'\r' {
        if bytes[i] != b' ' && bytes[i] != b'\t' {
            return false;
        }
        i += 1;
    }
    true
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
///
/// First-nonblank classification does not search for a closer-only line: a
/// body line of backticks must not pay summary-close work.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn parse_summary_line(line: &str) -> SummaryLine {
    parse_summary_line_bounded(line, usize::MAX)
}

pub(crate) fn parse_summary_line_bounded(line: &str, max_bytes: usize) -> SummaryLine {
    Work::charge(1);
    let (body, _) = trim_leading_ws(line);
    if !starts_with_open_angle(body) {
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
    let budget = max_bytes.saturating_sub(open.tag_end);
    let mut collector = SummaryCollector::new();
    match collector.push_segment(after, budget, true) {
        SummaryContinue::Complete { inner } => SummaryLine::Complete { inner },
        SummaryContinue::StillOpen => SummaryLine::OpenOnly {
            after_open: collector.inner().to_string(),
        },
        SummaryContinue::Malformed => SummaryLine::Malformed,
    }
}

/// Continue an open `<summary>` across the next consecutive nonblank line,
/// keeping code-span matching in the accumulated inner source.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn continue_summary(accumulated: &str, next_line: &str) -> SummaryContinue {
    continue_summary_bounded(accumulated, next_line, usize::MAX)
}

pub(crate) fn continue_summary_bounded(
    accumulated: &str,
    next_line: &str,
    max_bytes: usize,
) -> SummaryContinue {
    let mut collector = SummaryCollector::from_after_open(accumulated);
    collector.push_line(next_line, max_bytes)
}

fn look_like_summary_open(body: &str) -> bool {
    let bytes = body.as_bytes();
    bytes.first() == Some(&b'<') && match_name(&bytes[1..], b"summary").is_some()
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

fn skip_backtick_run(bytes: &[u8], start: usize, limit: usize) -> usize {
    let mut end = start;
    while end < limit && bytes[end] == b'`' {
        Work::charge_bytes(1);
        end += 1;
    }
    end
}

fn floor_char_boundary(s: &str, mut end: usize) -> usize {
    if end >= s.len() {
        return s.len();
    }
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    end
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
        Work::charge_bytes(1);
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

fn trim_leading_ws(line: &str) -> (&str, usize) {
    let bytes = line.as_bytes();
    let mut start = 0;
    while start < bytes.len() && (bytes[start] == b' ' || bytes[start] == b'\t') {
        start += 1;
    }
    (&line[start..], start)
}

/// True when `inner` is empty or only whitespace (including newlines).
pub(crate) fn summary_inner_is_empty(inner: &str) -> bool {
    inner
        .bytes()
        .all(|b| b == b' ' || b == b'\t' || b == b'\n' || b == b'\r')
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
        assert_eq!(parse_summary_line(&"`".repeat(64)), SummaryLine::NotSummary);
    }

    #[test]
    fn continue_summary_spans_lines_and_code() {
        assert_eq!(
            continue_summary("", "More **information**"),
            SummaryContinue::StillOpen
        );
        assert_eq!(
            continue_summary("More **information**", "</summary>"),
            SummaryContinue::Complete {
                inner: "More **information**".into()
            }
        );
        assert_eq!(
            continue_summary("use `literal", "</summary>` here</summary>"),
            SummaryContinue::Complete {
                inner: "use `literal\n</summary>` here".into()
            }
        );
        let mut collector = SummaryCollector::from_after_open("`one");
        assert!(matches!(
            collector.push_line("</summary>", usize::MAX),
            SummaryContinue::StillOpen
        ));
        assert!(collector.has_unmatched_openers());
        assert!(matches!(
            collector.push_line("</details>", usize::MAX),
            SummaryContinue::StillOpen
        ));
        assert!(matches!(
            collector.push_line("two`", usize::MAX),
            SummaryContinue::StillOpen
        ));
        assert!(!collector.has_unmatched_openers());
        assert_eq!(
            collector.push_line("</summary>", usize::MAX),
            SummaryContinue::Complete {
                inner: "`one\n</summary>\n</details>\ntwo`".into()
            }
        );
    }

    #[test]
    fn bounded_summary_never_copies_unbounded_suffix() {
        Work::reset();
        let huge = format!("<summary>{}", "z".repeat(1_000_000));
        let classified = parse_summary_line_bounded(&huge, 16);
        assert!(matches!(classified, SummaryLine::OpenOnly { .. }));
        let work = Work::get();
        assert!(
            work < 8_192,
            "a 16-byte budget must not copy a 1MB suffix, work={work}"
        );
    }

    #[test]
    fn unmatched_backtick_close_search_is_linear() {
        let mut prev = 0usize;
        for n in [2_000usize, 4_000, 8_000, 16_000] {
            Work::reset();
            let line = "`".repeat(n);
            let _ = continue_summary("after", &line);
            let work = Work::get();
            assert!(
                work <= n * 8 + 256,
                "close search must stay linear, n={n} work={work}"
            );
            if prev > 0 {
                assert!(
                    work <= prev.saturating_mul(3),
                    "work must not jump quadratically, prev={prev} work={work}"
                );
            }
            prev = work;
        }
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
