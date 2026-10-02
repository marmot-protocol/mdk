/// Splits a reply into UTF-8-safe chunks no larger than `max_bytes`.
pub(crate) fn split_reply_chunks(text: &str, max_bytes: usize) -> Vec<&str> {
    ReplyChunks::new(text, max_bytes).collect()
}

/// Counts reply chunks, stopping once the count exceeds `limit`.
///
/// Returns at most `limit + 1`, so an oversized reply is rejected without
/// materializing its chunk list.
pub(crate) fn count_reply_chunks(text: &str, max_bytes: usize, limit: usize) -> usize {
    ReplyChunks::new(text, max_bytes)
        .take(limit.saturating_add(1))
        .count()
}

struct ReplyChunks<'a> {
    text: &'a str,
    max_bytes: usize,
    start: usize,
    emitted: bool,
}

impl<'a> ReplyChunks<'a> {
    fn new(text: &'a str, max_bytes: usize) -> Self {
        assert!(max_bytes >= 4, "max_bytes must fit any UTF-8 scalar value");
        Self {
            text,
            max_bytes,
            start: 0,
            emitted: false,
        }
    }
}

impl<'a> Iterator for ReplyChunks<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<&'a str> {
        let text = self.text;
        if text.len() <= self.max_bytes {
            // Short replies, including the empty reply, are exactly one chunk.
            return (!std::mem::replace(&mut self.emitted, true)).then_some(text);
        }
        let start = self.start;
        if start >= text.len() {
            return None;
        }
        let hard_end = floor_char_boundary(text, (start + self.max_bytes).min(text.len()));
        if hard_end >= text.len() {
            self.start = text.len();
            return Some(&text[start..]);
        }
        let window = &text[start..hard_end];
        let split_end = preferred_split(window).unwrap_or(window.len());
        let end = if split_end == 0 {
            hard_end
        } else {
            start + split_end
        };
        self.start = end;
        Some(&text[start..end])
    }
}

fn preferred_split(window: &str) -> Option<usize> {
    for delimiter in ["\n\n", "\n", " "] {
        if let Some(index) = window.rfind(delimiter) {
            let end = index + delimiter.len();
            if end > 0 {
                return Some(end);
            }
        }
    }
    None
}

fn floor_char_boundary(text: &str, mut index: usize) -> usize {
    while index > 0 && !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_text_returns_one_chunk() {
        assert_eq!(split_reply_chunks("hello", 30_000), vec!["hello"]);
    }

    #[test]
    fn exact_boundary_ascii_stays_single_chunk() {
        let text = "a".repeat(30_000);
        let chunks = split_reply_chunks(&text, 30_000);
        assert_eq!(chunks, vec![text.as_str()]);
    }

    #[test]
    fn chunks_ascii_by_byte_count() {
        let chunks = split_reply_chunks("abcdefghij", 4);
        assert_eq!(chunks, vec!["abcd", "efgh", "ij"]);
        assert!(chunks.iter().all(|chunk| chunk.len() <= 4));
    }

    #[test]
    fn chunks_multibyte_utf8_without_splitting_codepoints() {
        let text = "aあbいc";
        let chunks = split_reply_chunks(text, 4);
        assert_eq!(chunks, vec!["aあ", "bい", "c"]);
        assert!(chunks.iter().all(|chunk| chunk.len() <= 4));
    }

    #[test]
    fn chunks_long_string_without_whitespace() {
        let text = "x".repeat(30_005);
        let chunks = split_reply_chunks(&text, 30_000);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].len(), 30_000);
        assert_eq!(chunks[1].len(), 5);
    }

    #[test]
    fn prefers_double_newline_then_newline_then_space() {
        assert_eq!(
            split_reply_chunks("aaa\n\nbbb ccc", 9),
            vec!["aaa\n\n", "bbb ccc"]
        );
        assert_eq!(
            split_reply_chunks("aaa\nbbb ccc", 8),
            vec!["aaa\n", "bbb ccc"]
        );
        assert_eq!(
            split_reply_chunks("aaa bbb ccc", 8),
            vec!["aaa bbb ", "ccc"]
        );
    }

    #[test]
    fn bounded_count_matches_split_and_stops_after_limit_plus_one() {
        for (text, max) in [
            ("", 4),
            ("hello", 30_000),
            ("abcdefghij", 4),
            ("aあbいc", 4),
            ("aaa\n\nbbb ccc", 9),
        ] {
            let chunks = split_reply_chunks(text, max).len();
            assert_eq!(count_reply_chunks(text, max, usize::MAX), chunks);
            assert_eq!(count_reply_chunks(text, max, chunks), chunks);
        }
        let text = "x".repeat(4 * 1_000);
        assert_eq!(split_reply_chunks(&text, 4).len(), 1_000);
        assert_eq!(count_reply_chunks(&text, 4, 3), 4);
        assert_eq!(count_reply_chunks(&text, 4, 0), 1);
    }

    #[test]
    fn chunks_stay_under_30kb_default() {
        let text = format!("{}\n\n{}", "a".repeat(40_000), "b".repeat(25_000));
        let chunks = split_reply_chunks(&text, 30_000);
        assert!(chunks.iter().all(|chunk| chunk.len() <= 30_000));
        assert_eq!(chunks.concat(), text);
    }
}
