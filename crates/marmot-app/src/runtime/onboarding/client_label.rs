//! Display sanitizing for the self-reported `client` label on another
//! installation's KeyPackage record.
//!
//! The label is peer-controlled public data: whoever signed the record chose
//! it, and nothing proves which app published it. It is only display text.
use unicode_segmentation::UnicodeSegmentation;

/// The most grapheme clusters a label keeps.
const MAX_CLIENT_LABEL_GRAPHEMES: usize = 64;
/// The most bytes a label keeps. One cluster can absorb any number of
/// combining marks or joiners, so the cluster count alone bounds nothing.
const MAX_CLIENT_LABEL_BYTES: usize = 1024;
/// The most scalars one cluster may hold: room for the longest emoji ZWJ
/// and tag sequences, but not a cluster stacked with marks.
const MAX_CLIENT_LABEL_CLUSTER_SCALARS: usize = 16;
/// The most scalars read from the tag, well past what the bounds above can
/// keep, so cleaning a relay-sized value costs no more than a short one.
const MAX_CLIENT_LABEL_SCAN_SCALARS: usize = 4096;
/// The black flag that emoji tag sequences (subdivision flags) start from.
const TAG_SEQUENCE_BASE: char = '\u{1F3F4}';

/// The record's first `client` tag value, made safe to display as plain text:
/// control and invisible formatting characters removed, whitespace runs
/// collapsed to one space, and the result cut at the first whole grapheme
/// cluster that would pass [`MAX_CLIENT_LABEL_GRAPHEMES`] clusters,
/// [`MAX_CLIENT_LABEL_BYTES`] bytes or [`MAX_CLIENT_LABEL_CLUSTER_SCALARS`]
/// scalars in one cluster. `None` when nothing displayable remains.
pub(super) fn client_label(raw: &str) -> Option<String> {
    let mut cleaned = String::new();
    let scanned: String = raw.chars().take(MAX_CLIENT_LABEL_SCAN_SCALARS).collect();
    for word in scanned
        .split(char::is_whitespace)
        .map(|word| word.chars().filter(|c| displayable(*c)).collect::<String>())
        .filter(|word| word.chars().any(visible))
    {
        if !cleaned.is_empty() {
            cleaned.push(' ');
        }
        cleaned.push_str(&word);
    }
    let mut label = String::new();
    for cluster in cleaned.graphemes(true).take(MAX_CLIENT_LABEL_GRAPHEMES) {
        // Tag characters outside a flag sequence are invisible padding.
        let cluster: String = if cluster.starts_with(TAG_SEQUENCE_BASE) {
            cluster.to_owned()
        } else {
            cluster.chars().filter(|c| !is_tag(*c)).collect()
        };
        if cluster.chars().count() > MAX_CLIENT_LABEL_CLUSTER_SCALARS
            || label.len() + cluster.len() > MAX_CLIENT_LABEL_BYTES
        {
            break;
        }
        label.push_str(&cluster);
    }
    // The cut can leave only a word's leading modifiers; drop words left
    // with nothing visible, as before the cut.
    let label = label
        .split(' ')
        .filter(|word| word.chars().any(visible))
        .collect::<Vec<_>>()
        .join(" ");
    (!label.is_empty()).then_some(label)
}

fn is_tag(c: char) -> bool {
    matches!(c, '\u{E0000}'..='\u{E007F}')
}

/// Unicode's `Default_Ignorable_Code_Point` property (DerivedCoreProperties):
/// characters that render as nothing unless a font or script gives them a
/// job. Unassigned code points in these ranges are included, as the property
/// reserves them for future invisible characters.
fn default_ignorable(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{034F}'
            | '\u{061C}'
            | '\u{115F}'..='\u{1160}'
            | '\u{17B4}'..='\u{17B5}'
            | '\u{180B}'..='\u{180F}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{206F}'
            | '\u{3164}'
            | '\u{FE00}'..='\u{FE0F}'
            | '\u{FEFF}'
            | '\u{FFA0}'
            | '\u{FFF0}'..='\u{FFF8}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0000}'..='\u{E0FFF}'
    )
}

/// The default-ignorable characters a label keeps because they change how a
/// visible neighbour renders: joiners and non-joiners (emoji sequences and
/// several scripts), variation selectors (emoji or text presentation, CJK
/// variants) and emoji tag characters (subdivision flags; removed outside a
/// flag later).
fn modifier(c: char) -> bool {
    matches!(
        c,
        '\u{200C}'
            | '\u{200D}'
            | '\u{FE00}'..='\u{FE0F}'
            | '\u{E0020}'..='\u{E007F}'
            | '\u{E0100}'..='\u{E01EF}'
    )
}

/// Whether a character draws anything on its own. A word with no such
/// character would read as a blank app name.
fn visible(c: char) -> bool {
    !default_ignorable(c)
}

/// Rejects control characters, default-ignorable characters other than
/// [`modifier`]s, and the two format-control blocks the property's derivation
/// leaves out (interlinear annotation and Egyptian hieroglyph format controls),
/// which draw nothing in a label either. That covers the bidirectional
/// controls, which can reorder the surrounding host text, and invisible
/// fillers that would make two labels look identical.
fn displayable(c: char) -> bool {
    !c.is_control()
        && !matches!(c, '\u{FFF9}'..='\u{FFFB}' | '\u{13430}'..='\u{1343F}')
        && (!default_ignorable(c) || modifier(c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_label_keeps_only_bounded_displayable_text() {
        for (raw, expected) in [
            ("Example Chat", Some("Example Chat")),
            ("  Example \t\n Chat \u{2028} ", Some("Example Chat")),
            // Reordering, control and invisible characters are removed; they
            // never become word breaks.
            ("Example\u{202E}Chat\u{2066}", Some("ExampleChat")),
            (
                "Exa\u{0000}mple\u{200B} \u{FEFF}Chat\u{007F}",
                Some("Example Chat"),
            ),
            ("e\u{0301}x", Some("e\u{0301}x")),
            ("", None),
            (" \u{202E}\u{200F} \n\u{0007}", None),
            // Modifiers with nothing to modify are not a label, nor a word.
            ("\u{200D}", None),
            ("\u{200C}\u{FE0F} \u{E0067}", None),
            ("Chat \u{200D}", Some("Chat")),
            // Every default-ignorable character counts, not a hand-picked few:
            // grapheme joiner, Hangul fillers, Mongolian selectors, shorthand
            // and musical format controls.
            ("\u{034F}", None),
            ("\u{3164}\u{FFA0} \u{115F}\u{1160}", None),
            ("\u{180F} \u{1BCA0} \u{1D173}", None),
            ("Chat\u{3164}\u{034F}\u{180B}\u{17B4}", Some("Chat")),
            ("\u{13430}\u{1343F} \u{FFF9}", None),
            ("Chat\u{1343F}", Some("Chat")),
            // Variation selectors stay with what they modify.
            ("\u{2764}\u{FE0F}", Some("\u{2764}\u{FE0F}")),
        ] {
            assert_eq!(client_label(raw).as_deref(), expected, "{raw:?}");
        }
    }

    #[test]
    fn client_label_bounds_whole_grapheme_clusters() {
        assert_eq!(
            client_label(&"a".repeat(1000)).unwrap(),
            "a".repeat(MAX_CLIENT_LABEL_GRAPHEMES)
        );
        // A cut that lands on a space leaves no trailing whitespace.
        let words = format!("{} tail", "a".repeat(MAX_CLIENT_LABEL_GRAPHEMES - 1));
        assert_eq!(
            client_label(&words).unwrap(),
            "a".repeat(MAX_CLIENT_LABEL_GRAPHEMES - 1)
        );
        // A family emoji is one 25-byte cluster of seven scalars joined by
        // ZWJ; the byte bound stops before a cluster it cannot fit whole.
        let family = "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}\u{200D}\u{1F466}";
        assert_eq!(
            client_label(&family.repeat(100)).unwrap(),
            family.repeat(MAX_CLIENT_LABEL_BYTES / family.len())
        );
        // A subdivision flag keeps its tag characters.
        let flag = "\u{1F3F4}\u{E0067}\u{E0062}\u{E0065}\u{E006E}\u{E0067}\u{E007F}";
        assert_eq!(client_label(flag).as_deref(), Some(flag));
    }

    #[test]
    fn client_label_cuts_clusters_stacked_with_marks_or_joiners() {
        // Grapheme rules never break before a combining mark or a joiner, so
        // these are single clusters of any length.
        for stack in ["\u{0301}", "\u{200D}"] {
            assert_eq!(client_label(&format!("a{}", stack.repeat(50_000))), None);
            assert_eq!(
                client_label(&format!("Chat a{}", stack.repeat(50_000))).as_deref(),
                Some("Chat")
            );
        }
        // A cut inside a word must not leave only its invisible modifiers.
        let stacked = format!("\u{200D}a{}", "\u{0301}".repeat(17));
        assert_eq!(client_label(&stacked), None);
        assert_eq!(
            client_label(&format!("Chat {stacked}")).as_deref(),
            Some("Chat")
        );
        // Invisible tag characters cannot pad a name outside a flag.
        assert_eq!(
            client_label("Chat\u{E0020}\u{E0068}\u{E0001}").as_deref(),
            Some("Chat")
        );
    }
}
