//! Terminal-safe rendering for untrusted human-facing CLI text.
//!
//! Shared by TUI render sites and non-JSON CLI/daemon writers. Machine-readable
//! `--json` and IPC serialization stay lossless.

use unicode_properties::{GeneralCategory, UnicodeGeneralCategory};

pub(crate) fn terminal_safe_text(value: &str) -> String {
    value.chars().filter(|ch| is_terminal_safe(*ch)).collect()
}

/// Sanitize freshly serialized JSON for a human-facing dump.
///
/// Split on trusted layout LFs, sanitize each line, and rejoin with LF. JSON
/// encoding already escapes embedded C0/newlines, so only formatter-owned
/// newlines survive. Never apply this to `--json` or IPC serialization, and
/// never sanitize a cloned JSON object's keys.
pub(crate) fn terminal_safe_json_display(serialized: &str) -> String {
    serialized
        .split('\n')
        .map(terminal_safe_text)
        .collect::<Vec<_>>()
        .join("\n")
}

/// Decide whether a single `char` may be rendered in untrusted terminal text
/// (message bodies, sender names, chat labels, stream previews).
///
/// This replaces the earlier hardcoded BiDi/zero-width denylist (see #201 /
/// PR #459) with a width-aware whitelist, as #201 anticipated. The denylist
/// inevitably drifted: a residual class of invisible / format characters
/// (SOFT HYPHEN, the invisible math operators, language-tag characters, the
/// interlinear-annotation controls, the Hangul fillers, BRAILLE PATTERN BLANK,
/// ...) still flowed through and enabled the same homograph / hidden-content
/// spoofing. See #473.
///
/// Policy:
/// - Drop every C0/C1 control (`char::is_control()`), preserving the prior
///   behavior of stripping ANSI/OSC escapes, newlines, and tabs.
/// - Drop the entire Unicode `Cf` (Format) general category. This subsumes
///   every BiDi override, zero-width joiner/space, word joiner, invisible
///   operator (U+2061–U+2064), deprecated shaping control (U+206A–U+206F),
///   interlinear-annotation control (U+FFF9–U+FFFB), SOFT HYPHEN, MONGOLIAN
///   VOWEL SEPARATOR, the musical-beam formatter, the BOM, and the language
///   tag / tag characters (U+E0001, U+E0020–U+E007F) — now and for any future
///   `Cf` additions, so the guard no longer drifts as Unicode evolves.
/// - Drop a small, explicit set of invisible glyphs that render blank but are
///   *not* `Cf` (so a category-only rule would miss them) and cannot be
///   distinguished from legitimate text by category alone: the Hangul fillers
///   (category `Lo`, alongside real CJK) and BRAILLE PATTERN BLANK (category
///   `So`, alongside real emoji).
///
/// Legitimate zero-width characters are intentionally kept: combining marks
/// (categories `Mn`/`Mc`/`Me`, e.g. accents, the Devanagari virama, Arabic
/// vowel marks, and emoji variation selectors) render as part of a visible base
/// glyph and must not be stripped, or accented/Indic/Arabic/emoji text would be
/// mangled. They are excluded from the `Cf` and explicit-filler rules above.
fn is_terminal_safe(ch: char) -> bool {
    if ch.is_control() {
        return false;
    }
    if matches!(ch.general_category(), GeneralCategory::Format) {
        return false;
    }
    !is_invisible_non_format_glyph(ch)
}

/// Invisible glyphs that are not Unicode `Cf` and therefore are not caught by
/// the general-category rule, yet render as a blank cell and can be used for
/// the same name/label spoofing. Enumerated explicitly because their categories
/// (`Lo`, `So`) also contain legitimate, visible text (CJK, emoji).
fn is_invisible_non_format_glyph(ch: char) -> bool {
    matches!(
        ch,
        // Hangul fillers (category Lo) — render invisible.
        '\u{115f}' | '\u{1160}' | '\u{3164}' | '\u{ffa0}'
        // BRAILLE PATTERN BLANK (category So) — renders as a blank cell.
            | '\u{2800}'
    )
}

#[cfg(test)]
mod tests {
    use super::{terminal_safe_json_display, terminal_safe_text};

    #[test]
    fn terminal_safe_text_strips_osc_and_csi_sequences() {
        assert_eq!(
            terminal_safe_text("pre\u{1b}]52;c;YXR0YWNr\u{7}post"),
            "pre]52;c;YXR0YWNrpost"
        );
        assert_eq!(
            terminal_safe_text("\u{1b}]8;;https://evil.example\u{7}click"),
            "]8;;https://evil.exampleclick"
        );
        assert_eq!(
            terminal_safe_text("\u{1b}]8;;https://evil.example\u{1b}\\click"),
            "]8;;https://evil.example\\click"
        );
        assert_eq!(terminal_safe_text("hi\u{1b}[2Jbob"), "hi[2Jbob");
        assert_eq!(terminal_safe_text("\u{1b}[Hforged"), "[Hforged");
        assert_eq!(terminal_safe_text("part\u{9b}31mial\u{7}"), "part31mial");
    }

    #[test]
    fn terminal_safe_text_strips_c0_c1_and_del() {
        let mut input = String::new();
        let mut expected = String::new();
        for byte in 0u8..=0x1f {
            input.push(char::from(byte));
            input.push('x');
            expected.push('x');
        }
        input.push('\u{7f}');
        input.push('y');
        expected.push('y');
        for code in 0x80u32..=0x9f {
            input.push(char::from_u32(code).expect("C1 scalar"));
            input.push('z');
            expected.push('z');
        }
        assert_eq!(terminal_safe_text(&input), expected);
    }

    #[test]
    fn terminal_safe_text_strips_bidi_and_zero_width_format_characters() {
        assert_eq!(
            terminal_safe_text(
                "safe\u{202a}name\u{202b}\u{202c}\u{202d}\u{202e}\u{2066}\u{2067}\u{2068}\u{2069}\u{200b}\u{200c}\u{200d}\u{200e}\u{200f}\u{feff}done",
            ),
            "safenamedone"
        );
    }

    #[test]
    fn terminal_safe_text_strips_residual_invisible_and_format_spoofing_characters() {
        let format_class_cf: &[(char, &str)] = &[
            ('\u{00ad}', "SOFT HYPHEN"),
            ('\u{2061}', "FUNCTION APPLICATION"),
            ('\u{2062}', "INVISIBLE TIMES"),
            ('\u{2063}', "INVISIBLE SEPARATOR"),
            ('\u{2064}', "INVISIBLE PLUS"),
            ('\u{206a}', "INHIBIT SYMMETRIC SWAPPING"),
            ('\u{206f}', "NOMINAL DIGIT SHAPES"),
            ('\u{fff9}', "INTERLINEAR ANNOTATION ANCHOR"),
            ('\u{fffa}', "INTERLINEAR ANNOTATION SEPARATOR"),
            ('\u{fffb}', "INTERLINEAR ANNOTATION TERMINATOR"),
            ('\u{180e}', "MONGOLIAN VOWEL SEPARATOR"),
            ('\u{1d173}', "MUSICAL SYMBOL BEGIN BEAM"),
            ('\u{061c}', "ARABIC LETTER MARK"),
            ('\u{e0001}', "LANGUAGE TAG"),
            ('\u{e0020}', "TAG SPACE"),
            ('\u{e007e}', "TAG TILDE"),
            ('\u{e007f}', "CANCEL TAG"),
        ];
        let invisible_non_cf: &[(char, &str)] = &[
            ('\u{115f}', "HANGUL CHOSEONG FILLER"),
            ('\u{1160}', "HANGUL JUNGSEONG FILLER"),
            ('\u{3164}', "HANGUL FILLER"),
            ('\u{ffa0}', "HALFWIDTH HANGUL FILLER"),
            ('\u{2800}', "BRAILLE PATTERN BLANK"),
        ];

        for (ch, name) in format_class_cf.iter().chain(invisible_non_cf) {
            let input = format!("a{ch}b");
            assert_eq!(
                terminal_safe_text(&input),
                "ab",
                "expected {name} (U+{:04X}) to be stripped",
                *ch as u32
            );
        }
    }

    #[test]
    fn terminal_safe_text_preserves_legitimate_visible_and_combining_text() {
        let preserved = [
            "plain ascii",
            "中文 日本語 한국어",
            "café",
            "cafe\u{0301}",
            "नमस्ते",
            "سَلَام",
            "❤\u{fe0f}",
            "emoji 😀 ok",
            "a b\u{00a0}c",
        ];
        for sample in preserved {
            assert_eq!(
                terminal_safe_text(sample),
                sample,
                "expected {sample:?} to pass through unchanged"
            );
        }
        assert_eq!(
            terminal_safe_text("with\ttab-was-control"),
            "withtab-was-control"
        );
    }

    #[test]
    fn terminal_safe_text_empty_and_control_only_are_blank() {
        assert_eq!(terminal_safe_text(""), "");
        assert_eq!(terminal_safe_text("\u{1b}\u{7}\u{9b}\n\t\u{202e}"), "");
        // CSI parameters are printable leftovers after the introducer is dropped.
        assert_eq!(terminal_safe_text("\u{1b}[2J"), "[2J");
    }

    #[test]
    fn terminal_safe_text_is_idempotent() {
        let input = "safe\u{1b}]52;c;YXR0YWNr\u{7}name\u{202e}中文";
        let once = terminal_safe_text(input);
        assert_eq!(terminal_safe_text(&once), once);
        assert_eq!(once, "safe]52;c;YXR0YWNrname中文");
    }

    #[test]
    fn terminal_safe_json_display_preserves_layout_and_printable_escapes() {
        let value = serde_json::json!({
            "name": "a\u{1b}b\u{202e}c",
            "nested": { "ok": true }
        });
        let serialized =
            serde_json::to_string_pretty(&value).expect("pretty JSON serialization cannot fail");
        let displayed = terminal_safe_json_display(&serialized);
        assert!(displayed.contains('\n'));
        assert!(displayed.contains("\\u001b") || displayed.contains("\\u001B"));
        assert!(!displayed.contains('\u{1b}'));
        assert!(!displayed.contains('\u{202e}'));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&serialized).expect("serialized JSON"),
            value
        );
        assert_eq!(
            displayed,
            "{\n  \"name\": \"a\\u001bbc\",\n  \"nested\": {\n    \"ok\": true\n  }\n}"
        );
    }

    #[test]
    fn terminal_safe_json_display_strips_raw_controls_from_serialized_lines() {
        let hostile = "{\n  \"name\": \"ok\"\u{9b}\u{202e}\u{2800}\n}";
        assert_eq!(
            terminal_safe_json_display(hostile),
            "{\n  \"name\": \"ok\"\n}"
        );
    }
}
