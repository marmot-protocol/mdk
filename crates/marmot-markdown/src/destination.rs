//! Classification for untrusted Markdown link destinations.

use crate::{AutolinkKind, LinkDestinationKind, nostr};

/// Classify an untrusted link destination without rewriting or removing it.
///
/// The result is descriptive input to renderer policy, not permission to open
/// or fetch the destination. In particular, clients should keep
/// [`LinkDestinationKind::Dangerous`] and [`LinkDestinationKind::Sensitive`]
/// non-actionable unless their own policy explicitly says otherwise.
pub fn classify_link_destination(destination: &str) -> LinkDestinationKind {
    let destination = destination.trim();
    if is_sensitive_nostr_value(destination) {
        return LinkDestinationKind::Sensitive;
    }
    if is_public_nostr_value(destination) {
        return LinkDestinationKind::Nostr;
    }

    let Some((scheme, body)) = split_scheme(destination) else {
        return LinkDestinationKind::Relative;
    };
    if matches_ignore_ascii_case(scheme, &["javascript", "data", "vbscript", "file"]) {
        return LinkDestinationKind::Dangerous;
    }
    if scheme.eq_ignore_ascii_case("nostr") || scheme_ends_with_nostr(scheme) {
        let body = body.trim_start_matches('/');
        return if is_sensitive_nostr_value(body) {
            LinkDestinationKind::Sensitive
        } else if is_public_nostr_value(body) {
            LinkDestinationKind::Nostr
        } else {
            LinkDestinationKind::Unknown
        };
    }
    if matches_ignore_ascii_case(scheme, &["http", "https"]) {
        LinkDestinationKind::Web
    } else if matches_ignore_ascii_case(scheme, &["mailto", "tel"]) {
        LinkDestinationKind::Contact
    } else if matches_ignore_ascii_case(scheme, &["marmot", "whitenoise", "whitenoise-staging"]) {
        LinkDestinationKind::App
    } else {
        LinkDestinationKind::Unknown
    }
}

pub(crate) fn classify_autolink_destination(
    destination: &str,
    kind: AutolinkKind,
) -> LinkDestinationKind {
    match kind {
        AutolinkKind::Email => LinkDestinationKind::Contact,
        AutolinkKind::Uri => classify_link_destination(destination),
    }
}

fn split_scheme(destination: &str) -> Option<(&str, &str)> {
    let colon = destination.find(':')?;
    let scheme = &destination[..colon];
    if scheme.is_empty()
        || !scheme.as_bytes()[0].is_ascii_alphabetic()
        || !scheme
            .as_bytes()
            .iter()
            .skip(1)
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
    {
        return None;
    }
    Some((scheme, &destination[colon + 1..]))
}

fn matches_ignore_ascii_case(value: &str, candidates: &[&str]) -> bool {
    candidates
        .iter()
        .any(|candidate| value.eq_ignore_ascii_case(candidate))
}

fn scheme_ends_with_nostr(scheme: &str) -> bool {
    scheme
        .get(scheme.len().saturating_sub("+nostr".len())..)
        .is_some_and(|suffix| suffix.eq_ignore_ascii_case("+nostr"))
}

fn is_sensitive_nostr_value(value: &str) -> bool {
    ["nsec1", "ncryptsec1"].iter().any(|prefix| {
        value
            .get(..prefix.len())
            .is_some_and(|candidate| candidate.eq_ignore_ascii_case(prefix))
    })
}

fn is_public_nostr_value(value: &str) -> bool {
    matches!(
        nostr::classify_bech32(value.as_bytes(), 0),
        Some((_, end)) if end == value.len()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_renderer_relevant_destination_categories() {
        let public_nostr = "npub1qqqqqq";
        for (destination, expected) in [
            ("https://example.com", LinkDestinationKind::Web),
            ("mailto:a@example.com", LinkDestinationKind::Contact),
            ("marmot://group/abc", LinkDestinationKind::App),
            (public_nostr, LinkDestinationKind::Nostr),
            ("nostr:npub1qqqqqq", LinkDestinationKind::Nostr),
            ("/relative/path", LinkDestinationKind::Relative),
            ("custom:payload", LinkDestinationKind::Unknown),
            ("javascript:alert(1)", LinkDestinationKind::Dangerous),
            ("nsec1qqqqqq", LinkDestinationKind::Sensitive),
            ("nostr:ncryptsec1qqqqqq", LinkDestinationKind::Sensitive),
            ("web+nostr:nsec1qqqqqq", LinkDestinationKind::Sensitive),
        ] {
            assert_eq!(
                classify_link_destination(destination),
                expected,
                "unexpected classification for {destination}"
            );
        }
    }

    #[test]
    fn dangerous_schemes_are_ascii_case_insensitive() {
        for destination in [
            "JavaScript:alert(1)",
            "DATA:text/html,x",
            "VbScript:msgbox(1)",
            "FILE:///etc/passwd",
        ] {
            assert_eq!(
                classify_link_destination(destination),
                LinkDestinationKind::Dangerous
            );
        }
    }
}
