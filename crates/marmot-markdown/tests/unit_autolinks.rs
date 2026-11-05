use marmot_markdown::{AutolinkKind, Inline, LinkDestinationKind, NostrHrp};

mod common;
use common::{parse_inlines, t};

fn uri(url: &str) -> Inline {
    Inline::Autolink {
        url: url.to_string(),
        kind: AutolinkKind::Uri,
        classification: marmot_markdown::classify_link_destination(url),
    }
}
fn email(addr: &str) -> Inline {
    Inline::Autolink {
        url: addr.to_string(),
        kind: AutolinkKind::Email,
        classification: LinkDestinationKind::Contact,
    }
}
fn www(url: &str) -> Inline {
    Inline::Autolink {
        url: url.to_string(),
        kind: AutolinkKind::Www,
        classification: LinkDestinationKind::Web,
    }
}

// HTML is NOT parsed: tag-like sequences are literal text in both the
// block pass (no HTML blocks) and the inline pass (no raw-HTML inline).
// Only autolinks — `<scheme:body>` and `<email@host>` — get structured
// treatment.

// ----- URI autolinks ----------------------------------------------------

#[test]
fn autolink_https() {
    assert_eq!(
        parse_inlines("x <https://example.com/path?q=1>"),
        vec![t("x "), uri("https://example.com/path?q=1")]
    );
}

#[test]
fn autolink_http() {
    assert_eq!(
        parse_inlines("x <http://x>"),
        vec![t("x "), uri("http://x")]
    );
}

#[test]
fn autolink_with_surrounding_text() {
    assert_eq!(
        parse_inlines("see <http://x> please"),
        vec![t("see "), uri("http://x"), t(" please")]
    );
}

#[test]
fn autolink_scheme_too_short_rejected() {
    // Single-letter scheme is invalid; falls through to literal text.
    assert_eq!(parse_inlines("x <a:b>"), vec![t("x <a:b>")]);
}

#[test]
fn autolink_with_space_rejected() {
    assert_eq!(parse_inlines("x <http://x y>"), vec![t("x <http://x y>")]);
}

// ----- Email autolinks --------------------------------------------------

#[test]
fn email_simple() {
    assert_eq!(
        parse_inlines("x <a@b.com>"),
        vec![t("x "), email("a@b.com")]
    );
}

#[test]
fn email_complex_local() {
    assert_eq!(
        parse_inlines("x <foo.bar+baz@example.co.uk>"),
        vec![t("x "), email("foo.bar+baz@example.co.uk")]
    );
}

// ----- HTML-as-text -----------------------------------------------------

#[test]
fn html_open_tag_is_text() {
    assert_eq!(parse_inlines("x <span>"), vec![t("x <span>")]);
}

#[test]
fn html_close_tag_is_text() {
    assert_eq!(parse_inlines("x </span>"), vec![t("x </span>")]);
}

#[test]
fn html_self_closing_is_text() {
    assert_eq!(parse_inlines("x <br/>"), vec![t("x <br/>")]);
}

#[test]
fn html_with_attributes_is_text() {
    assert_eq!(
        parse_inlines("x <a href=\"y\">"),
        vec![t("x <a href=\"y\">")]
    );
}

#[test]
fn html_comment_is_text() {
    assert_eq!(parse_inlines("x <!-- hi -->"), vec![t("x <!-- hi -->")]);
}

#[test]
fn lt_with_no_following_match_is_text() {
    assert_eq!(parse_inlines("a < b"), vec![t("a < b")]);
}

// ----- Priority --------------------------------------------------------

#[test]
fn nostr_inside_uri_autolink_stays_text() {
    // The autolink wins; nostr scheme bytes inside `<...>` are part of the
    // URL, not a separate NostrUri token.
    let s = "x <nostr:nevent1qzqzqzqzqzqzqzqzqzqzqzqzqzqzqzqzqzqzqz>";
    assert_eq!(parse_inlines(s), vec![t("x "), uri(&s[3..s.len() - 1])]);
}

#[test]
fn sensitive_uri_autolinks_are_preserved_and_classified() {
    for input in ["x <nostr:nsec1qqqqqq>", "x <web+nostr:nsec1qqqqqq>"] {
        let url = &input[3..input.len() - 1];
        assert_eq!(
            parse_inlines(input),
            vec![
                t("x "),
                Inline::Autolink {
                    url: url.to_owned(),
                    kind: AutolinkKind::Uri,
                    classification: LinkDestinationKind::Sensitive,
                },
            ]
        );
    }
}

#[test]
fn dangerous_uri_autolinks_are_preserved_and_classified() {
    for input in [
        "<javascript:alert(1)>",
        "<data:text/plain,payload>",
        "<vbscript:msgbox(1)>",
        "<file:///etc/passwd>",
    ] {
        let parsed = parse_inlines(input);
        let [
            Inline::Autolink {
                url,
                classification,
                ..
            },
        ] = parsed.as_slice()
        else {
            panic!("expected a classified autolink for {input}");
        };
        assert_eq!(url, &input[1..input.len() - 1]);
        assert_eq!(*classification, LinkDestinationKind::Dangerous);
    }
}

// ----- Bare URLs (GFM-style extended autolinks) ------------------------

#[test]
fn bare_www() {
    assert_eq!(
        parse_inlines("www.example.com/path"),
        vec![www("www.example.com/path")]
    );
}

#[test]
fn bare_www_strips_trailing_period() {
    assert_eq!(
        parse_inlines("See www.example.com/path."),
        vec![t("See "), www("www.example.com/path"), t(".")]
    );
}

#[test]
fn bare_https() {
    assert_eq!(
        parse_inlines("see https://example.com/path?q=1 ok"),
        vec![t("see "), uri("https://example.com/path?q=1"), t(" ok"),]
    );
}

#[test]
fn bare_http() {
    assert_eq!(
        parse_inlines("http://example.com"),
        vec![uri("http://example.com")]
    );
}

#[test]
fn bare_mailto() {
    assert_eq!(
        parse_inlines("ping mailto:foo@bar.com please"),
        vec![t("ping "), uri("mailto:foo@bar.com"), t(" please")]
    );
}

#[test]
fn bare_tel() {
    assert_eq!(
        parse_inlines("call tel:+15551234567 now"),
        vec![t("call "), uri("tel:+15551234567"), t(" now")]
    );
}

#[test]
fn bare_marmot() {
    assert_eq!(
        parse_inlines("open marmot://profile/npub1abc"),
        vec![t("open "), uri("marmot://profile/npub1abc")]
    );
}

#[test]
fn bare_whitenoise() {
    assert_eq!(
        parse_inlines("open whitenoise://group/abc"),
        vec![t("open "), uri("whitenoise://group/abc")]
    );
}

#[test]
fn bare_whitenoise_staging() {
    assert_eq!(
        parse_inlines("open whitenoise-staging://group/abc"),
        vec![t("open "), uri("whitenoise-staging://group/abc")]
    );
}

#[test]
fn whitenoise_opaque_form_stays_text() {
    // Only the authority form (`whitenoise://`) is recognized as a URL.
    // Opaque `whitenoise:foo` (no `//`) is not a known shape and stays literal.
    assert_eq!(parse_inlines("whitenoise:foo"), vec![t("whitenoise:foo")]);
}

#[test]
fn marmot_opaque_form_stays_text() {
    assert_eq!(parse_inlines("marmot:foo"), vec![t("marmot:foo")]);
}

#[test]
fn bare_url_strips_trailing_period() {
    assert_eq!(
        parse_inlines("Visit https://example.com."),
        vec![t("Visit "), uri("https://example.com"), t(".")]
    );
}

#[test]
fn bare_url_strips_trailing_punct_cluster() {
    assert_eq!(
        parse_inlines("really?! https://example.com?!"),
        vec![t("really?! "), uri("https://example.com"), t("?!")]
    );
}

#[test]
fn bare_url_paren_balanced_kept() {
    // Wikipedia-style: the URL contains `(` so the trailing `)` is part of it.
    let s = "see https://en.wikipedia.org/wiki/Foo_(bar) ok";
    assert_eq!(
        parse_inlines(s),
        vec![
            t("see "),
            uri("https://en.wikipedia.org/wiki/Foo_(bar)"),
            t(" ok"),
        ]
    );
}

#[test]
fn bare_url_paren_unbalanced_stripped() {
    // Parenthesized prose: trailing `)` belongs to the sentence, not the URL.
    assert_eq!(
        parse_inlines("(see https://example.com)"),
        vec![t("(see "), uri("https://example.com"), t(")")]
    );
}

#[test]
fn bare_url_inside_emphasis() {
    // The closing `*` must not be absorbed into the URL.
    assert_eq!(
        parse_inlines("*https://example.com*"),
        vec![Inline::Emph(vec![uri("https://example.com")])]
    );
}

#[test]
fn word_internal_https_rejected() {
    // "xhttps://" must not become a URL; the `h` is mid-word.
    assert_eq!(
        parse_inlines("xhttps://example.com"),
        vec![t("xhttps://example.com")]
    );
}

#[test]
fn bare_url_at_start_of_line() {
    assert_eq!(
        parse_inlines("https://example.com is the site"),
        vec![uri("https://example.com"), t(" is the site")]
    );
}

#[test]
fn multiple_bare_urls() {
    assert_eq!(
        parse_inlines("a https://x.com b mailto:y@z.io c"),
        vec![
            t("a "),
            uri("https://x.com"),
            t(" b "),
            uri("mailto:y@z.io"),
            t(" c"),
        ]
    );
}

#[test]
fn non_url_h_t_m_w_bytes_stay_text() {
    // Stress the bulk-scan tripwire: lots of h/m/t/w in prose with no URL.
    let s = "the warmth of his methods matters with whitespace";
    assert_eq!(parse_inlines(s), vec![t(s)]);
}

#[test]
fn malformed_scheme_falls_through_to_text() {
    // "http:/x" — single slash, not a recognized prefix; stays literal.
    assert_eq!(parse_inlines("http:/x"), vec![t("http:/x")]);
}

#[test]
fn bare_nostr_uri_still_structured() {
    // Bare `nostr:` URIs go through the existing NostrUri path, not the new
    // generic bare-URL autolink — `nostr:` is NOT in the bare-URL scheme list.
    let s = "x nostr:nevent1qzqzqzqzqzqzqzqzqzqzqzqzqzqzqzqzqzqzqz";
    let inlines = parse_inlines(s);
    assert_eq!(inlines.len(), 2);
    assert_eq!(inlines[0], t("x "));
    match &inlines[1] {
        Inline::NostrUri(e) => assert_eq!(e.hrp, NostrHrp::Nevent),
        other => panic!("expected NostrUri, got {other:?}"),
    }
}

#[test]
fn malformed_bare_nostr_stays_text() {
    // Per the documented design: `nostr:` without valid bech32 does NOT fall
    // back to a generic bare-URL autolink — it stays literal.
    assert_eq!(parse_inlines("nostr:foo"), vec![t("nostr:foo")]);
}

/// Delegated roots beyond common extensions must retain a distinct label and target.
#[test]
fn schemeless_domain_has_https_destination_and_original_label() {
    for source in ["example.network", "example.chat", "example.photography"] {
        let inlines = parse_inlines(source);
        assert!(
            matches!(inlines.as_slice(), [Inline::Link { dest, children, classification: LinkDestinationKind::Web, .. }]
                if dest == &format!("https://{source}") && children == &vec![t(source)]),
            "expected typed HTTPS destination and authored label for {source}: {inlines:?}"
        );
    }
}

fn domain_link(label: &str, dest: &str) -> Inline {
    Inline::Link {
        dest: dest.into(),
        title: None,
        children: vec![t(label)],
        classification: LinkDestinationKind::Web,
    }
}

/// Valid suffix bytes must survive inference without changing the destination path.
#[test]
fn schemeless_domain_preserves_label_and_url_components() {
    for (source, expected) in [
        (
            "ExAmPlE.CHAT:8443/a_(b)?q=1&x=2#part",
            "https://example.chat:8443/a_(b)?q=1&x=2#part",
        ),
        (
            "example.chat/search?q=a,b",
            "https://example.chat/search?q=a,b",
        ),
        ("example.chat/a;b", "https://example.chat/a;b"),
        ("example.chat/a~b", "https://example.chat/a~b"),
        (
            "example.chat/search?q=a*b",
            "https://example.chat/search?q=a*b",
        ),
        ("2nd-site.network", "https://2nd-site.network"),
        ("example.photography", "https://example.photography"),
    ] {
        assert_eq!(parse_inlines(source), vec![domain_link(source, expected)]);
    }
    assert_eq!(
        parse_inlines("See (example.chat)."),
        vec![
            t("See ("),
            domain_link("example.chat", "https://example.chat"),
            t(").")
        ]
    );
    assert_eq!(
        parse_inlines("*example.chat*"),
        vec![Inline::Emph(vec![domain_link(
            "example.chat",
            "https://example.chat"
        )])]
    );
}

/// Filename policy and malformed tokens must not acquire rescued URL suffixes.
#[test]
fn schemeless_domain_file_endings_and_invalid_contexts_remain_inert() {
    for source in [
        "report.pdf",
        "README.md",
        "archive.zip",
        "ARCHIVE.ZIP",
        "clip.mov",
        "main.rs",
        "script.py",
        "setup.sh",
        "parser.pl",
        "Model.java",
        "library.so",
        "notes.md/path",
        "photo.jpg",
        "config.json",
        "app.js",
        "example.notarealtld",
        "3.14",
        "1.2.3",
        "bad_label.example.chat",
        "-bad.example.chat",
        "bad-.chat",
        "a..example.chat",
        "user@example.chat",
        "user:pass@example.chat",
        "custom:example.chat",
        "javascript:example.chat",
        "./example.chat",
        "../example.chat",
        "/example.chat",
        "dir/example.chat",
        "C:\\example.chat",
        "example.chat:70000",
        "example.chat:abc",
        "xn--.chat",
        "nsec1qqqqqq.chat",
        "ncryptsec1qqqqqq.chat",
        "ｎｓｅｃ１qqqqqq.chat",
        "nｓec1qqqqqq.chat",
        "ｎｃｒｙｐｔｓｅｃ１qqqqqq.chat",
        "ｎｐｕｂ１qqqqqq.chat",
    ] {
        assert_eq!(parse_inlines(source), vec![t(source)], "{source}");
    }
}

/// Explicit Markdown syntax owns its labels and code before fuzzy recognition.
#[test]
fn schemeless_domain_does_not_override_authored_links_code_or_escapes() {
    let expected = vec![domain_link("example.chat", "https://other.example")];
    for label in [
        "example.chat",
        "example。chat",
        "example．chat",
        "example｡chat",
        "bücher.de",
    ] {
        assert_eq!(
            parse_inlines(&format!("[{label}](https://other.example)")),
            vec![domain_link(label, "https://other.example")]
        );
    }
    assert_eq!(
        parse_inlines("[example.chat][target]\n\n[target]: https://other.example"),
        expected
    );
    for source in ["`example.chat`", "example\\.chat", "example&#46;chat"] {
        let expected = if source.starts_with('`') {
            Inline::Code("example.chat".into())
        } else {
            t("example.chat")
        };
        assert_eq!(parse_inlines(source), vec![expected], "{source}");
    }
    assert_eq!(
        parse_inlines("[example.chat]"),
        vec![
            t("["),
            domain_link("example.chat", "https://example.chat"),
            t("]")
        ]
    );
    assert_eq!(
        parse_inlines("![example.chat](image.png)"),
        vec![Inline::Image {
            dest: "image.png".into(),
            title: None,
            alt: vec![t("example.chat")],
            classification: LinkDestinationKind::Relative
        }]
    );
    assert_eq!(
        parse_inlines("https://example.zip"),
        vec![uri("https://example.zip")]
    );
    assert_eq!(
        parse_inlines("www.example.zip"),
        vec![www("www.example.zip")]
    );
}

/// Canonical targets must reveal IDNs while the visible label remains authored text.
#[test]
fn schemeless_domain_idna_exposes_actual_host_without_rewriting_the_label() {
    for (source, dest) in [
        ("еxample.chat", "https://xn--xample-2of.chat"), // Cyrillic e, not Latin e.
        ("bücher.de", "https://xn--bcher-kva.de"),
        ("пример.рф", "https://xn--e1afmkfd.xn--p1ai"),
        ("例子.中国", "https://xn--fsqu00a.xn--fiqs8s"),
        ("ｅxample.chat", "https://example.chat"),
    ] {
        assert_eq!(parse_inlines(source), vec![domain_link(source, dest)]);
    }
    for source in [
        "ex\u{200b}ample.chat",
        "ex\u{00ad}ample.chat",
        "ex\u{202e}ample.chat",
        "example.chat/\u{2066}hidden",
    ] {
        assert_eq!(parse_inlines(source), vec![t(source)], "{source:?}");
    }
}

/// Overlong host rejection must retain bounded progress through the whole token.
#[test]
fn schemeless_domain_rejects_whole_overlong_tokens_without_suffix_rescue() {
    for source in [
        format!("{}.example.chat", "a".repeat(64)),
        format!("{}example.chat", "a.".repeat(10000)),
    ] {
        assert_eq!(parse_inlines(&source), vec![t(&source)]);
    }
}

/// A URL scanner must not consume the backslash that protects a Markdown delimiter.
#[test]
fn schemeless_domain_backslashes_preserve_markdown_escape_precedence() {
    for suffix in ["/", "?q=", "#"] {
        for escaped in ['`', '[', ']', '<', '>', '\"', '\\', '\''] {
            let source = format!("example.chat{suffix}\\{escaped}x");
            let expected = format!("example.chat{suffix}{escaped}x");
            assert_eq!(parse_inlines(&source), vec![t(&expected)], "{source:?}");
        }
    }
    assert_eq!(
        parse_inlines(r"example.chat/\`x`"),
        vec![t("example.chat/`x`")]
    );
    assert_eq!(
        parse_inlines(r"example.chat/\[x](https://other.example)"),
        vec![t("example.chat/[x]("), uri("https://other.example"), t(")")]
    );
    assert_eq!(
        parse_inlines(r"[example.chat/\](https://other.example)"),
        vec![t("[example.chat/]("), uri("https://other.example"), t(")")]
    );
}

/// Suffix data follows opaque URL semantics, including entity and math-looking bytes.
#[test]
fn schemeless_domain_url_suffixes_keep_entities_and_math_literal() {
    for source in ["example.chat/?a=1&amp;b=2", "example.chat/$x$"] {
        assert_eq!(
            parse_inlines(source),
            vec![domain_link(source, &format!("https://{source}"))]
        );
        let qualified = format!("https://{source}");
        assert_eq!(parse_inlines(&qualified), vec![uri(&qualified)]);
    }
}

/// Rebuilding a label must preserve the bracket neighbors used by the rule of three.
#[test]
fn schemeless_domain_label_reparse_preserves_bracket_flanking() {
    for label in ["**.a.b*", "*.a.b**", "**.example.chat*", "*.example.chat**"] {
        for source in [
            format!("[{label}](x)"),
            format!("![{label}](x)"),
            format!("[{label}][ref]\n\n[ref]: x"),
            format!("![{label}][ref]\n\n[ref]: x"),
        ] {
            let inlines = parse_inlines(&source);
            let children = match &inlines[..] {
                [Inline::Link { children, .. }] => children,
                [Inline::Image { alt, .. }] => alt,
                other => panic!("unexpected tree for {source:?}: {other:?}"),
            };
            assert_eq!(children, &vec![t(label)], "{source:?}");
        }
    }
}

/// Unspaced prose and ideographic sentence stops must not synthesize a new hostname.
#[test]
fn schemeless_domains_do_not_absorb_unspaced_prose_or_sentence_stops() {
    for source in [
        "请访问example.chat",
        "詳しくはexample.com",
        "ไปที่example.com",
        "谢谢。我爱你",
        "ありがとう。みんな",
        "收到。公司",
        "good。It",
    ] {
        assert_eq!(parse_inlines(source), vec![t(source)], "{source:?}");
    }
    assert_eq!(
        parse_inlines("访问www.example.com"),
        vec![t("访问"), www("www.example.com")]
    );
    assert_eq!(
        parse_inlines("foo。bar.com"),
        vec![t("foo。"), domain_link("bar.com", "https://bar.com")]
    );
}

/// Internal path apostrophes differ from quotation marks surrounding the whole token.
#[test]
fn schemeless_domains_keep_internal_apostrophes_and_surrounding_punctuation() {
    for label in [
        "example.chat/O'Reilly",
        "example.chat/?q=O'Reilly",
        "example.chat/#O'Reilly",
    ] {
        assert_eq!(
            parse_inlines(label),
            vec![domain_link(label, &format!("https://{label}"))]
        );
        let quoted = format!("'{label}'");
        assert_eq!(
            parse_inlines(&quoted),
            vec![
                t("'"),
                domain_link(label, &format!("https://{label}")),
                t("'")
            ]
        );
    }
    for (left, right) in [
        ("“", "”"),
        ("‘", "’"),
        ("「", "」"),
        ("【", "】"),
        ("（", "）"),
        ("", "，"),
        ("", "。"),
        ("", "’s"),
    ] {
        let source = format!("{left}example.chat{right}");
        let mut expected = Vec::new();
        if !left.is_empty() {
            expected.push(t(left));
        }
        expected.push(domain_link("example.chat", "https://example.chat"));
        expected.push(t(right));
        assert_eq!(parse_inlines(&source), expected, "{source:?}");
    }
}

/// Capitalization must preserve explicit www intent even on excluded or unknown roots.
#[test]
fn schemeless_domains_accept_capitalized_www_without_changing_lowercase_www() {
    for label in [
        "Www.example.com",
        "WWW.EXAMPLE.COM",
        "Www.example.zip",
        "WWW.example.invalid",
    ] {
        assert_eq!(parse_inlines(label), vec![www(label)]);
    }
    assert_eq!(
        parse_inlines("www.example.com"),
        vec![www("www.example.com")]
    );
}

/// Finite filename exclusions cannot classify every domain-shaped word or file.
#[test]
fn schemeless_domains_document_finite_filename_and_typo_tradeoffs() {
    for label in [
        "main.cc",
        "main.tf",
        "proguard-rules.pro",
        "gradle.properties",
        "Android.mk",
        "Xcode.app",
        "Done.Now",
        "Ok.No",
    ] {
        assert_eq!(
            parse_inlines(label),
            vec![domain_link(
                label,
                &format!("https://{}", label.to_ascii_lowercase())
            )],
            "{label:?}"
        );
    }
    for label in [
        "docs.rs",
        "allegro.pl",
        "notion.so",
        "brew.sh",
        "document.pdf",
        "README.md",
        "archive.zip",
        "访问ｅｘａｍｐｌｅ.chat",
        "访问bücher.de",
        "访问１.com",
        "访问𝕒.com",
    ] {
        assert_eq!(parse_inlines(label), vec![t(label)], "{label:?}");
    }
    assert_eq!(
        parse_inlines("Date.now()"),
        vec![domain_link("Date.now", "https://date.now"), t("()")]
    );
}

/// Suffix punctuation remains data, and long terminal quote clusters trim in one pass.
#[test]
fn schemeless_domains_preserve_internal_unicode_suffix_punctuation() {
    for label in [
        "example.chat/你好，世界",
        "example.chat/?q=甲：乙",
        "example.chat/“quoted”/path",
    ] {
        assert_eq!(
            parse_inlines(label),
            vec![domain_link(label, &format!("https://{label}"))]
        );
    }
    let suffix = "',".repeat(32_000);
    let source = format!("example.chat/path{suffix}");
    assert_eq!(
        parse_inlines(&source),
        vec![
            domain_link("example.chat/path", "https://example.chat/path"),
            t(&suffix)
        ]
    );
}

/// A prior sentence-like label must not bypass the guard on a later host label.
#[test]
fn schemeless_domains_guard_all_labels() {
    for text in ["好的.请访问example.com", "收到.见example.com"] {
        assert_eq!(parse_inlines(text), vec![t(text)]);
    }
}

/// Fullwidth parentheses in a suffix follow the same balance rule as ASCII ones.
#[test]
fn schemeless_domains_balance_fullwidth_path_parens() {
    let label = "example.chat/甲（乙）";
    assert_eq!(
        parse_inlines(label),
        vec![domain_link(label, &format!("https://{label}"))]
    );
    assert_eq!(
        parse_inlines(&format!("（{label}）")),
        vec![
            t("（"),
            domain_link(label, &format!("https://{label}")),
            t("）")
        ]
    );
}
