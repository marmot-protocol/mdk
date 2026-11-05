//! Conservative, offline inference of scheme-less web destinations.

use std::sync::OnceLock;

use crate::{Inline, classify_link_destination};
use unicode_script::{Script, UnicodeScript};

const ROOTS: &str = include_str!("iana-tlds.txt");
static ROOT_LABELS: OnceLock<Vec<&'static str>> = OnceLock::new();

/// Only these ambiguous file endings override IANA membership. This is display
/// policy, not a statement about whether the corresponding domains exist.
const FILE_ENDINGS: &[&str] = &[
    "java", "md", "mov", "pdf", "pl", "py", "rs", "sh", "so", "zip",
];

/// Necessary raw-source condition shared with explicit-label precedence handling.
pub(crate) fn has_host_separator(text: &str) -> bool {
    text.as_bytes().contains(&b'.')
}

/// Check raw token boundaries without treating a script transition as a new host.
pub(crate) fn eligible_start(raw: &str, i: usize) -> bool {
    let bytes = raw.as_bytes();
    let first = bytes[i];
    if first.is_ascii() {
        if !first.is_ascii_alphanumeric() {
            return false;
        }
        if i == 0 {
            return true;
        }
        let prev = bytes[i - 1];
        if prev.is_ascii() {
            return prev.is_ascii_whitespace()
                || matches!(
                    prev,
                    b'(' | b'[' | b'"' | b'\'' | b',' | b';' | b'!' | b'*' | b'_' | b'~'
                );
        }
    } else if !raw[i..].chars().next().is_some_and(char::is_alphanumeric) {
        return false;
    }
    i == 0
        || raw[..i].chars().next_back().is_some_and(|prev| {
            prev.is_whitespace()
                || matches!(
                    prev,
                    '(' | '[' | '"' | '\'' | ',' | ';' | '!' | '*' | '_' | '~'
                )
                || unicode_boundary(prev)
        })
}

/// Common prose punctuation is a boundary, never an IDNA-mapped host separator.
pub(crate) fn unicode_boundary(c: char) -> bool {
    matches!(
        c,
        '。' | '．'
            | '｡'
            | '，'
            | '、'
            | '；'
            | '：'
            | '！'
            | '？'
            | '“'
            | '”'
            | '‘'
            | '’'
            | '«'
            | '»'
            | '‹'
            | '›'
            | '「'
            | '」'
            | '『'
            | '』'
            | '【'
            | '】'
            | '〈'
            | '〉'
            | '《'
            | '》'
            | '（'
            | '）'
    )
}

/// Return both the inferred link and the attempted token's end. The caller
/// never retries a suffix of a rejected token (email, path, scheme, bad host).
pub(crate) fn scan(raw: &str, start: usize) -> (Option<(Inline, usize)>, usize) {
    let mut end = start;
    let mut suffix = false;
    let mut host_dot = false;
    for (offset, c) in raw[start..].char_indices() {
        if c.is_whitespace()
            || matches!(c, '<' | '>' | '`' | '"' | '[' | ']')
            || (!suffix && unicode_boundary(c))
            || (!suffix && c == '\'')
            || (!suffix && matches!(c, '(' | ',' | ';' | '*' | '~'))
        {
            break;
        }
        host_dot |= !suffix && c == '.';
        suffix |= matches!(c, '/' | '?' | '#');
        end = start + offset + c.len_utf8();
    }
    let attempted_end = end;
    if !host_dot {
        return (None, attempted_end);
    }
    end = crate::inline::trim_trailing_punct(raw.as_bytes(), start, end, true);
    let text = &raw[start..end];
    let inferred = infer(text).map(|dest| {
        let classification = classify_link_destination(&dest);
        (
            Inline::Link {
                dest,
                title: None,
                children: vec![Inline::Text(text.to_owned())],
                classification,
            },
            end,
        )
    });
    (inferred, attempted_end)
}

/// Validate one whole candidate and supply an ASCII-host HTTPS destination.
fn infer(text: &str) -> Option<String> {
    // Never silently drop or interpret controls/formatting as part of a host or
    // target. In particular UTS46 maps some default-ignorables away.
    if text.contains('\\') || text.chars().any(unsafe_character) {
        return None;
    }
    let authority_end = text.find(['/', '?', '#']).unwrap_or(text.len());
    let authority = &text[..authority_end];
    if authority.len() > 1024 || !has_host_separator(authority) || authority.contains(['@', '%']) {
        return None;
    }
    let (host, port) = match authority.split_once(':') {
        Some((host, port)) => {
            if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            port.parse::<u16>().ok()?;
            (host, Some(port))
        }
        None => (authority, None),
    };
    // Scheme-bearing URLs, www URLs and Nostr entities keep their existing
    // recognizers and contracts. Private-key-looking values stay inert.
    let lower = host.to_ascii_lowercase();
    if lower.starts_with("www.") || reserved_nostr_host(&lower) {
        return None;
    }
    let ascii = idna::domain_to_ascii_strict(host).ok()?;
    // Compatibility mappings can turn fullwidth/mixed prefixes into ASCII.
    // Apply the privacy/precedence guard to the actual destination as well.
    if reserved_nostr_host(&ascii) {
        return None;
    }
    if !host.is_ascii() {
        // Inspect the validated canonical Unicode label as well: compatibility
        // digits and mathematical letters can map into ASCII during IDNA.
        let (normalized, status) = idna::domain_to_unicode(&ascii);
        status.ok()?;
        if ambiguous_host_labels(&normalized) {
            return None;
        }
    }
    let (_, root) = ascii.rsplit_once('.')?;
    if root.is_empty() || FILE_ENDINGS.contains(&root) {
        return None;
    }
    let roots = ROOT_LABELS.get_or_init(|| ROOTS.lines().filter(|s| !s.starts_with('#')).collect());
    if roots
        .binary_search(&root.to_ascii_uppercase().as_str())
        .is_err()
    {
        return None;
    }
    let mut dest = format!("https://{ascii}");
    if let Some(port) = port {
        dest.push(':');
        dest.push_str(port);
    }
    dest.push_str(&text[authority_end..]);
    Some(dest)
}

/// Refuse ambiguous glued prose without guessing a different host suffix.
fn ambiguous_host_labels(host: &str) -> bool {
    host.split('.').any(|label| {
        if label.is_ascii() {
            return false;
        }
        let mut latin_or_digit = false;
        let mut unspaced = false;
        for c in label.chars() {
            latin_or_digit |= c.is_ascii_digit() || c.script() == Script::Latin;
            if !c.is_ascii() {
                unspaced |= matches!(
                    c.script(),
                    Script::Han | Script::Hiragana | Script::Katakana | Script::Thai
                );
            }
        }
        latin_or_digit && unspaced
    })
}

/// Reserved Nostr-looking prefixes must remain inert even after IDNA mapping.
fn reserved_nostr_host(host: &str) -> bool {
    ["nsec1", "ncryptsec1", "npub1"]
        .iter()
        .any(|prefix| host.starts_with(prefix))
}

/// Controls and Default_Ignorable characters must not disappear during IDNA.
fn unsafe_character(c: char) -> bool {
    c.is_control()
        || matches!(c as u32,
            0x00ad | 0x034f | 0x061c | 0x115f | 0x1160 | 0x17b4 | 0x17b5 |
            0x180b..=0x180f | 0x200b..=0x200f | 0x202a..=0x202e |
            0x2060..=0x206f | 0x3164 | 0xfe00..=0xfe0f | 0xfeff | 0xffa0 |
            0xfff0..=0xfff8 | 0x1bca0..=0x1bca3 | 0x1d173..=0x1d17a |
            0xe0000..=0xe0fff)
}

#[cfg(test)]
mod tests {
    use super::ROOTS;

    /// Binary lookup requires the bundled data to remain sorted, unique and valid.
    #[test]
    fn embedded_root_snapshot_satisfies_lookup_invariants() {
        let mut lines = ROOTS.lines();
        let header = lines.next().expect("root data needs provenance");
        assert!(header.starts_with("# Version ") && header.contains("Last Updated"));
        let roots: Vec<_> = lines.collect();
        assert!(!roots.is_empty());
        assert!(
            roots.windows(2).all(|pair| pair[0] < pair[1]),
            "binary lookup requires sorted unique roots"
        );
        for root in roots {
            assert!((1..=63).contains(&root.len()));
            assert!(root.as_bytes()[0].is_ascii_uppercase());
            assert!(root.as_bytes()[root.len() - 1].is_ascii_alphanumeric());
            assert!(
                root.bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-')
            );
        }
    }
}
