//! The text search rule shared by chat-list search, message search, timeline
//! search and user directory search: trim surrounding whitespace, lowercase by
//! Unicode rules, then match as a literal substring. Account and shared
//! connections register SQL functions for literal matching and directory rank.

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

fn text_search_rank(haystack: &str, needle: &str) -> u8 {
    if needle.is_empty() {
        return 3;
    }
    let (position, len) = if haystack.is_ascii() {
        if !needle.is_ascii() {
            return 3;
        }
        (
            haystack
                .as_bytes()
                .windows(needle.len())
                .position(|window| window.eq_ignore_ascii_case(needle.as_bytes())),
            haystack.len(),
        )
    } else {
        let lowercase = haystack.to_lowercase();
        (lowercase.find(needle), lowercase.len())
    };
    match position {
        Some(0) if len == needle.len() => 0,
        Some(0) => 1,
        Some(_) => 2,
        None => 3,
    }
}

/// Register literal substring matching and directory match quality on `conn`.
/// Non-text or invalid UTF-8 values match nothing. Rank is exact (0), prefix
/// (1), contains (2), or nonmatch (3), without trimming the haystack.
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
    )?;
    conn.create_scalar_function(
        "marmot_search_rank",
        2,
        FunctionFlags::SQLITE_UTF8
            | FunctionFlags::SQLITE_DETERMINISTIC
            | FunctionFlags::SQLITE_INNOCUOUS,
        |ctx| {
            let (ValueRef::Text(haystack), ValueRef::Text(needle)) =
                (ctx.get_raw(0), ctx.get_raw(1))
            else {
                return Ok(3_u8);
            };
            Ok(
                match (std::str::from_utf8(haystack), std::str::from_utf8(needle)) {
                    (Ok(haystack), Ok(needle)) => text_search_rank(haystack, needle),
                    _ => 3,
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

    #[test]
    fn directory_sql_rank_preserves_literal_unicode_match_quality() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        register_search_functions(&conn).unwrap();
        for (haystack, needle, expected) in [
            ("ALICE", "alice", 0),
            ("ALICE Smith", "alice", 1),
            (" Alice ", "alice", 2),
            ("ÉCOLE", "école", 0),
            ("ÉCOLE du soir", "école", 1),
            ("une ÉCOLE", "école", 2),
            ("\u{212a}elvin", "kelvin", 0),
            ("İ", "i\u{307}", 0),
            ("Straße", "strasse", 3),
            ("50%_done", "%_", 2),
            ("500xdone", "%_", 3),
            ("plain ascii", "é", 3),
            ("anything", "", 3),
            ("short", "longer needle", 3),
        ] {
            let rank: u8 = conn
                .query_row(
                    "SELECT marmot_search_rank(?1, ?2)",
                    [haystack, needle],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(rank, expected, "{haystack:?} against {needle:?}");
        }
        for haystack in [
            "NULL",
            "zeroblob(8)",
            "CAST('alice' AS BLOB)",
            "CAST(x'ff' AS TEXT)",
        ] {
            let rank: u8 = conn
                .query_row(
                    &format!("SELECT marmot_search_rank({haystack}, 'alice')"),
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(rank, 3, "{haystack}");
        }
    }
}
