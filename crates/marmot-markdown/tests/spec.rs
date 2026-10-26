//! Literal HTML and code escaping through the test renderer.
//! Parser structure is covered directly by the unit and golden suites.

use marmot_markdown::parse;

mod common;
use common::render::render;

fn check(md: &str, expected: &str) {
    let got = render(&parse(md));
    assert_eq!(got, expected, "input: {md:?}");
}

#[test]
fn inline_code_escapes_lt() {
    check("`x<y`", "<p><code>x&lt;y</code></p>\n");
}

#[test]
fn html_is_literal_text() {
    // HTML is NOT parsed; tags are escaped just like any other text.
    check("<div>hi</div>", "<p>&lt;div&gt;hi&lt;/div&gt;</p>\n");
    check(
        "see <span>x</span>",
        "<p>see &lt;span&gt;x&lt;/span&gt;</p>\n",
    );
}
