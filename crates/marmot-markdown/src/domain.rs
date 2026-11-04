//! Conservative, offline inference of scheme-less web destinations.

use std::sync::OnceLock;

use crate::{Inline, LinkDestinationKind};

const ROOTS: &str = include_str!("iana-tlds.txt");
static ROOT_LABELS: OnceLock<Vec<&'static str>> = OnceLock::new();

/// Only these ambiguous file endings override IANA membership. This is display
/// policy, not a statement about whether the corresponding domains exist.
const FILE_ENDINGS: &[&str] = &["md", "pdf", "zip"];

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
    let inferred = infer(text).map(|dest| {
        (
            Inline::Link {
                dest,
                title: None,
                children: vec![Inline::Text(text.to_owned())],
                classification: LinkDestinationKind::Web,
            },
            end,
        )
    });
    (inferred, attempted_end)
}

fn infer(text: &str) -> Option<String> {
    // Never silently drop or interpret controls/formatting as part of a host or
    // target. In particular UTS46 maps some default-ignorables away.
    if text.chars().any(unsafe_character) {
        return None;
    }
    let authority_end = text.find(['/', '?', '#']).unwrap_or(text.len());
    let authority = &text[..authority_end];
    if authority.len() > 1024
        || !authority.contains(['.', '。', '．', '｡'])
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
    if lower.starts_with("www.")
        || lower.starts_with("nsec1")
        || lower.starts_with("ncryptsec1")
        || lower.starts_with("npub1")
    {
        return None;
    }
    let ascii = idna::domain_to_ascii_strict(host).ok()?;
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

fn unsafe_character(c: char) -> bool {
    c.is_control()
        || matches!(c as u32,
            0x00ad | 0x034f | 0x061c | 0x115f | 0x1160 | 0x17b4 | 0x17b5 |
            0x180b..=0x180f | 0x200b..=0x200f | 0x202a..=0x202e |
            0x2060..=0x206f | 0x3164 | 0xfe00..=0xfe0f | 0xfeff | 0xffa0 |
            0xfff0..=0xfff8 | 0x1bca0..=0x1bca3 | 0x1d173..=0x1d17a |
            0xe0000..=0xe0fff)
}
