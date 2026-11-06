//! Text search normalization, shared by chat-list search and user directory
//! search: trim surrounding whitespace, lowercase by Unicode rules, then match
//! as a literal substring. Accent and compatibility folding are deliberately
//! absent; adding them is a format change to `chat_list_rows.search_text`.

/// Normalize a search query or one searchable value: trim, then Unicode
/// lowercase. A query that is empty after this matches nothing.
pub fn normalize_search_text(text: &str) -> String {
    text.trim().to_lowercase()
}

/// Joins fields in `chat_list_rows.search_text`. It is a control character,
/// and fields never contain one, so a query can only match inside one field.
pub(crate) const FIELD_SEPARATOR: char = '\u{1f}';

/// The stored search column for a chat: each field cleaned for display
/// (controls become spaces, bidi formatting marks are dropped), normalized,
/// then joined by [`FIELD_SEPARATOR`]. Empty and repeated fields are dropped.
pub(crate) fn chat_search_text<'a>(fields: impl IntoIterator<Item = &'a str>) -> String {
    let mut seen: Vec<String> = Vec::new();
    for field in fields {
        let cleaned: String = field
            .chars()
            .filter(|c| !is_bidi_format(*c))
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect();
        let normalized = normalize_search_text(&cleaned);
        if !normalized.is_empty() && !seen.contains(&normalized) {
            seen.push(normalized);
        }
    }
    let mut text = String::new();
    for (index, field) in seen.iter().enumerate() {
        if index > 0 {
            text.push(FIELD_SEPARATOR);
        }
        text.push_str(field);
    }
    text
}

// The marks `marmot_app`'s title cleaning drops, so a stored title and the
// group name it came from normalize alike.
fn is_bidi_format(c: char) -> bool {
    matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}
