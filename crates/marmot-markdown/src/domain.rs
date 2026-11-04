//! Conservative, offline inference of scheme-less web destinations.

use std::sync::OnceLock;

use crate::{Inline, LinkDestinationKind, classify_link_destination};

const ROOTS: &str = include_str!("iana-tlds.txt");
static ROOT_LABELS: OnceLock<Vec<&'static str>> = OnceLock::new();

/// Only these ambiguous file endings override IANA membership. This is display
/// policy, not a statement about whether the corresponding domains exist.
const FILE_ENDINGS: &[&str] = &[
    "java", "md", "mov", "pdf", "pl", "py", "rs", "sh", "so", "zip",
];

/// Necessary raw-source condition shared with explicit-label precedence handling.
pub(crate) fn has_host_separator(text: &str) -> bool {
    text.contains(['.', '。', '．', '｡'])
}

pub(crate) fn eligible_start(raw: &str, i: usize) -> bool {
    let Some(c) = raw[i..].chars().next() else {
        return false;
    };
    if !c.is_alphanumeric() {
        return false;
    }
    i == 0
        || raw[..i].chars().next_back().is_some_and(|prev| {
            prev.is_whitespace()
                || matches!(
                    prev,
                    '(' | '[' | '"' | '\'' | ',' | ';' | '!' | '*' | '_' | '~'
                )
        })
}

/// Return both the inferred link and the attempted token's end. The caller
/// never retries a suffix of a rejected token (email, path, scheme, bad host).
pub(crate) fn scan(raw: &str, start: usize) -> (Option<(Inline, usize)>, usize) {
    let mut end = start;
    let mut suffix = false;
    for (offset, c) in raw[start..].char_indices() {
        if c.is_whitespace()
            || matches!(c, '<' | '>' | '`' | '"' | '\'' | '[' | ']')
            || (!suffix && matches!(c, '(' | ',' | ';' | '*' | '~'))
        {
            break;
        }
        suffix |= matches!(c, '/' | '?' | '#');
        end = start + offset + c.len_utf8();
    }
    let attempted_end = end;
    end = crate::inline::trim_trailing_punct(raw.as_bytes(), start, end);
    let text = &raw[start..end];
    let inferred = infer(text).and_then(|dest| {
        let classification = classify_link_destination(&dest);
        (classification == LinkDestinationKind::Web).then(|| {
            (
                Inline::Link {
                    dest,
                    title: None,
                    children: vec![Inline::Text(text.to_owned())],
                    classification,
                },
                end,
            )
        })
    });
    (inferred, attempted_end)
}

fn infer(text: &str) -> Option<String> {
    // Never silently drop or interpret controls/formatting as part of a host or
    // target. In particular UTS46 maps some default-ignorables away.
    if text.contains('\\') || text.chars().any(unsafe_character) {
        return None;
    }
    let authority_end = text.find(['/', '?', '#']).unwrap_or(text.len());
    let authority = &text[..authority_end];
    if authority.len() > 1024
        || !has_host_separator(authority)
        || authority.contains(['@', '\\', '%'])
    {
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

fn reserved_nostr_host(host: &str) -> bool {
    ["nsec1", "ncryptsec1", "npub1"]
        .iter()
        .any(|prefix| host.starts_with(prefix))
}

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
