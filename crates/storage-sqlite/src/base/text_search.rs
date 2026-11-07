//! The text search rule shared by chat-list search, message search, timeline
//! search and user directory search: trim surrounding whitespace, lowercase by
//! Unicode rules, then match as a literal substring. Account connections
//! register it as an SQL function so queries on either side can use it.

/// Normalize a search query or one searchable value: trim, then Unicode
/// lowercase. A query that is empty after this matches nothing.
pub fn normalize_search_text(text: &str) -> String {
    text.trim().to_lowercase()
}

/// SQL name of [`text_contains`]: `marmot_search_contains(haystack, needle)`
/// is 1 when the Unicode-lowercased haystack contains `needle`, which the
/// caller has already normalized. Registered on every account connection.
pub(crate) const SQL_CONTAINS_FUNCTION: &str = "marmot_search_contains";

/// Whether `haystack`, lowercased by Unicode rules, contains `needle` as a
/// literal substring. `needle` is already normalized ([`normalize_search_text`]);
/// an empty needle matches nothing. Trimming the haystack is unnecessary: a
/// trimmed needle starts and ends with non-whitespace.
pub(crate) fn text_contains(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    if haystack.is_ascii() {
        // Lowercasing ASCII yields ASCII, which cannot contain a non-ASCII needle.
        return needle.is_ascii()
            && haystack
                .as_bytes()
                .windows(needle.len())
                .any(|window| window.eq_ignore_ascii_case(needle.as_bytes()));
    }
    // Non-ASCII can lowercase to ASCII (KELVIN SIGN to `k`), so fold it all.
    haystack.to_lowercase().contains(needle)
}

/// Register [`SQL_CONTAINS_FUNCTION`] on `conn`. A non-text haystack (NULL,
/// or a scrubbed `zeroblob`) or one that is not UTF-8 matches nothing.
pub(crate) fn register_search_functions(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    use rusqlite::functions::FunctionFlags;
    use rusqlite::types::ValueRef;
    conn.create_scalar_function(
        SQL_CONTAINS_FUNCTION,
        2,
        FunctionFlags::SQLITE_UTF8
            | FunctionFlags::SQLITE_DETERMINISTIC
            | FunctionFlags::SQLITE_INNOCUOUS,
        |ctx| {
            let (ValueRef::Text(haystack), ValueRef::Text(needle)) =
                (ctx.get_raw(0), ctx.get_raw(1))
            else {
                return Ok(false);
            };
            Ok(
                match (std::str::from_utf8(haystack), std::str::from_utf8(needle)) {
                    (Ok(haystack), Ok(needle)) => text_contains(haystack, needle),
                    _ => false,
                },
            )
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_contains_lowercases_the_haystack_by_unicode_rules() {
        for (haystack, query, expected) in [
            ("Hello There", "hello", true),
            ("ÉCOLE du soir", "école", true),
            ("École", "ÉCOLE", true),
            // KELVIN SIGN lowercases to ASCII `k`.
            ("\u{212a}elvin", "kelvin", true),
            ("50% complete", "50%", true),
            ("500 complete", "50%", false),
            ("a_b", "a_b", true),
            ("axb", "a_b", false),
            ("plain ascii", "é", false),
            ("anything", "   ", false),
        ] {
            assert_eq!(
                text_contains(haystack, &normalize_search_text(query)),
                expected,
                "{haystack:?} contains {query:?}"
            );
        }
    }

    #[test]
    fn the_sql_function_matches_only_text() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        register_search_functions(&conn).unwrap();
        let contains = |haystack: &str| -> bool {
            conn.query_row(
                &format!("SELECT {SQL_CONTAINS_FUNCTION}({haystack}, 'école')"),
                [],
                |row| row.get(0),
            )
            .unwrap()
        };
        assert!(contains("'Une ÉCOLE'"));
        assert!(!contains("NULL"));
        assert!(!contains("zeroblob(8)"));
        assert!(!contains("CAST('école' AS BLOB)"));
    }
}
