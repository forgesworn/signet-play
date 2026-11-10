//! `sanitizeWireText` — the one sanitiser on this wire (R-6). Strip control
//! and bidi/invisible characters, trim, then cap by CODE POINT. Asserted
//! against `vectors/sanitise.json`.

/// The character class upstream strips (escapes, never literals):
/// U+0000-001F, U+007F-009F, U+200B-200F, U+2028-202E, U+2066-2069.
fn is_stripped(c: char) -> bool {
    matches!(c,
        '\u{0000}'..='\u{001f}'
        | '\u{007f}'..='\u{009f}'
        | '\u{200b}'..='\u{200f}'
        | '\u{2028}'..='\u{202e}'
        | '\u{2066}'..='\u{2069}')
}

/// ECMAScript `String.prototype.trim` whitespace: Unicode `White_Space`
/// (which is what `char::is_whitespace` tests) plus U+FEFF, which JS also
/// trims. U+0085 differs between the two but is already stripped above.
fn is_js_trim(c: char) -> bool {
    c.is_whitespace() || c == '\u{feff}'
}

pub fn sanitize_wire_text(raw: &str, max_len: usize) -> String {
    let stripped: String = raw.chars().filter(|c| !is_stripped(*c)).collect();
    stripped.trim_matches(is_js_trim).chars().take(max_len).collect()
}

/// Over a JSON value: a non-string is missing data and becomes `""`.
pub fn sanitize_json_text(raw: Option<&serde_json::Value>, max_len: usize) -> String {
    match raw.and_then(serde_json::Value::as_str) {
        Some(s) => sanitize_wire_text(s, max_len),
        None => String::new(),
    }
}
