use marmot_markdown::{LinkDestinationKind, classify_link_destination};

#[test]
fn classifies_renderer_relevant_destination_categories() {
    for (destination, expected) in [
        ("https://example.com", LinkDestinationKind::Web),
        ("mailto:a@example.com", LinkDestinationKind::Contact),
        ("marmot://group/abc", LinkDestinationKind::App),
        ("npub1qqqqqq", LinkDestinationKind::Nostr),
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
            "{destination}"
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
