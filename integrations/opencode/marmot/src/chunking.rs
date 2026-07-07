pub(crate) fn split_reply_chunks(text: &str, max_bytes: usize) -> Vec<&str> {
    assert!(max_bytes >= 4, "max_bytes must fit any UTF-8 scalar value");
    if text.len() <= max_bytes {
        return vec![text];
    }

    let mut chunks = Vec::new();
    let mut start = 0;
    while start < text.len() {
        let hard_end = floor_char_boundary(text, (start + max_bytes).min(text.len()));
        if hard_end >= text.len() {
            chunks.push(&text[start..]);
            break;
        }

        let window = &text[start..hard_end];
        let split_end = preferred_split(window).unwrap_or(window.len());
        let end = start + split_end;
        if end == start {
            chunks.push(&text[start..hard_end]);
            start = hard_end;
        } else {
            chunks.push(&text[start..end]);
            start = end;
        }
    }
    chunks
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
    fn chunks_stay_under_30kb_default() {
        let text = format!("{}\n\n{}", "a".repeat(40_000), "b".repeat(25_000));
        let chunks = split_reply_chunks(&text, 30_000);
        assert!(chunks.iter().all(|chunk| chunk.len() <= 30_000));
        assert_eq!(chunks.concat(), text);
    }
}
