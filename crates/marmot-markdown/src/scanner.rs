//! Byte-level scanning helpers shared by both passes.
//!
//! Strictly hand-coded ASCII predicates and line slicing; no regex, no
//! `once_cell`, no allocation outside what callers explicitly request.

/// Iterator over the input split into logical lines, with `\r\n` and bare
/// `\r` normalized to `\n`. Each yielded `&str` excludes the line ending.
///
/// The iterator yields one item per line; if the input ends without a
/// trailing newline, the final partial line is still yielded.
#[allow(dead_code)]
pub(crate) fn lines(input: &str) -> impl Iterator<Item = &str> {
    lines_with_offsets(input).map(|(line, _)| line)
}

/// Yield `(line, start_byte_offset)` over original source, matching [`lines`].
pub(crate) fn lines_with_offsets(input: &str) -> LinesWithOffsets<'_> {
    LinesWithOffsets { input, pos: 0 }
}

pub(crate) struct LinesWithOffsets<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> Iterator for LinesWithOffsets<'a> {
    type Item = (&'a str, usize);

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.input.len() {
            return None;
        }
        let start = self.pos;
        let bytes = self.input.as_bytes();
        let mut i = start;
        while i < bytes.len() {
            match bytes[i] {
                b'\n' => {
                    let line = &self.input[start..i];
                    self.pos = i + 1;
                    return Some((line, start));
                }
                b'\r' => {
                    let line = &self.input[start..i];
                    let mut step = 1;
                    if i + 1 < bytes.len() && bytes[i + 1] == b'\n' {
                        step = 2;
                    }
                    self.pos = i + step;
                    return Some((line, start));
                }
                _ => i += 1,
            }
        }
        let line = &self.input[start..];
        self.pos = self.input.len();
        Some((line, start))
    }
}

/// Measure leading indentation as (column count, byte offset).
///
/// Tabs advance to the next multiple of 4 columns. Stops at the first byte
/// that is neither space nor tab.
pub(crate) fn measure_indent(line: &[u8]) -> (usize, usize) {
    let mut col = 0;
    let mut off = 0;
    while off < line.len() {
        match line[off] {
            b' ' => {
                col += 1;
                off += 1;
            }
            b'\t' => {
                col += 4 - (col % 4);
                off += 1;
            }
            _ => break,
        }
    }
    (col, off)
}

/// True if every byte of `line` is ASCII space or tab (or empty).
pub(crate) fn is_blank(line: &[u8]) -> bool {
    line.iter().all(|&b| b == b' ' || b == b'\t')
}

/// Skip spaces/tabs, optionally one newline, then spaces/tabs again.
pub(crate) fn skip_ws_and_one_newline(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && (b[i] == b' ' || b[i] == b'\t') {
        i += 1;
    }
    if i < b.len() && b[i] == b'\n' {
        i += 1;
        while i < b.len() && (b[i] == b' ' || b[i] == b'\t') {
            i += 1;
        }
    }
    i
}

/// True if `b` is a CommonMark ASCII-punctuation byte (`!`..=`~` excluding
/// letters and digits) — the escapable set per the spec.
pub(crate) fn is_ascii_punct(b: u8) -> bool {
    matches!(b, b'!'..=b'/' | b':'..=b'@' | b'['..=b'`' | b'{'..=b'~')
}
